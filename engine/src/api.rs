//! Clash API: тот набор ручек, которым приложение управляет ядром.
//!
//! HTTP/1.1 написан руками: запросы короткие и только от своих, тянуть ради них
//! веб-сервер в бинарь незачем.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::engine::Context;

const MAX_REQUEST: usize = 64 * 1024;
const IDLE: Duration = Duration::from_secs(60);

pub async fn serve(listen: String, secret: String, ctx: Arc<Context>) -> std::io::Result<()> {
    let listener = TcpListener::bind(&listen).await?;
    crate::info!("clash-api", "слушаю {listen}");
    let secret = Arc::new(secret);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { continue };
            let (ctx, secret) = (ctx.clone(), secret.clone());
            tokio::spawn(async move {
                let _ = stream.set_nodelay(true);
                let _ = session(stream, ctx, secret).await;
            });
        }
    });
    Ok(())
}

struct Request {
    method: String,
    path: String,
    query: HashMap<String, String>,
    authorized: bool,
    body: Vec<u8>,
    keep_alive: bool,
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Запрос из буфера или `None`, если он ещё не пришёл целиком.
fn parse(buf: &[u8], secret: &str) -> Option<(Request, usize)> {
    let head_end = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&buf[..head_end]).ok()?;
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split_whitespace();
    let method = first.next()?.to_string();
    let target = first.next()?;
    let version_1_0 = first.next() == Some("HTTP/1.0");

    let (mut length, mut authorized, mut keep_alive) = (0usize, secret.is_empty(), !version_1_0);
    for line in lines {
        let Some((name, value)) = line.split_once(':') else { continue };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            length = value.parse().unwrap_or(0);
        } else if name.eq_ignore_ascii_case("authorization") {
            authorized = value.strip_prefix("Bearer ").is_some_and(|token| token.trim() == secret) || secret.is_empty();
        } else if name.eq_ignore_ascii_case("connection") {
            keep_alive = !value.eq_ignore_ascii_case("close");
        }
    }
    let total = head_end + 4 + length;
    if buf.len() < total {
        return None;
    }

    let (path, query_text) = target.split_once('?').unwrap_or((target, ""));
    let query = query_text
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(k, v)| (percent_decode(k), percent_decode(v)))
        .collect();
    Some((
        Request {
            method,
            path: path.to_string(),
            query,
            authorized,
            body: buf[head_end + 4..total].to_vec(),
            keep_alive,
        },
        total,
    ))
}

async fn session(mut stream: TcpStream, ctx: Arc<Context>, secret: Arc<String>) -> std::io::Result<()> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    loop {
        while let Some((request, used)) = parse(&buf, &secret) {
            buf.drain(..used);
            let keep_alive = request.keep_alive;
            let (status, body) = if request.authorized {
                route(&request, &ctx).await
            } else {
                (401, json!({ "message": "Unauthorized" }))
            };
            let text = if body.is_null() { String::new() } else { body.to_string() };
            let head = format!(
                "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n",
                reason(status),
                text.len(),
                if keep_alive { "keep-alive" } else { "close" },
            );
            stream.write_all(head.as_bytes()).await?;
            stream.write_all(text.as_bytes()).await?;
            if !keep_alive {
                return Ok(());
            }
        }
        if buf.len() > MAX_REQUEST {
            return Ok(());
        }
        let mut chunk = [0u8; 2048];
        let n = match tokio::time::timeout(IDLE, stream.read(&mut chunk)).await {
            Ok(result) => result?,
            Err(_) => return Ok(()),
        };
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        408 => "Request Timeout",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "OK",
    }
}

fn proxy_json(ctx: &Context, tag: &str) -> Option<Value> {
    let outbound = ctx.outbounds.get(tag)?;
    let mut value = json!({ "name": outbound.tag(), "type": outbound.kind(), "udp": true, "history": [] });
    let members = outbound.members();
    if !members.is_empty() {
        value["all"] = json!(members);
        value["now"] = json!(outbound.member());
    }
    Some(value)
}

async fn route(req: &Request, ctx: &Arc<Context>) -> (u16, Value) {
    let segments: Vec<String> = req.path.split('/').filter(|s| !s.is_empty()).map(percent_decode).collect();
    let parts: Vec<&str> = segments.iter().map(String::as_str).collect();
    match (req.method.as_str(), parts.as_slice()) {
        ("GET", ["version"]) => (200, json!({ "version": crate::VERSION_LINE, "meta": false, "premium": false })),
        ("GET", ["connections"]) => (200, ctx.tracker.snapshot()),
        // Для опроса раз в секунду: те же счётчики без списка соединений.
        ("GET", ["traffic", "total"]) => (200, ctx.tracker.totals()),
        ("DELETE", ["connections"]) => {
            ctx.tracker.close_all();
            (204, Value::Null)
        }
        ("DELETE", ["connections", id]) => match id.parse().map(|id| ctx.tracker.close(id)) {
            Ok(true) => (204, Value::Null),
            _ => (404, json!({ "message": "нет такого соединения" })),
        },
        ("GET", ["configs"]) => (200, json!({ "mode": *ctx.mode.read(), "mode-list": ["Rule", "Global", "Direct"] })),
        ("PATCH", ["configs"]) => {
            let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            if let Some(mode) = body["mode"].as_str() {
                *ctx.mode.write() = mode.to_string();
                crate::info!("clash-api", "режим {mode}");
            }
            (204, Value::Null)
        }
        ("GET", ["proxies"]) => {
            let proxies: serde_json::Map<String, Value> = ctx
                .outbounds
                .order
                .iter()
                .filter_map(|tag| proxy_json(ctx, tag).map(|v| (tag.clone(), v)))
                .collect();
            (200, json!({ "proxies": proxies }))
        }
        ("GET", ["proxies", tag]) => match proxy_json(ctx, tag) {
            Some(value) => (200, value),
            None => (404, json!({ "message": "нет такого исходящего" })),
        },
        ("PUT", ["proxies", group]) => {
            let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            let Some(member) = body["name"].as_str() else {
                return (400, json!({ "message": "нет поля name" }));
            };
            let Some(outbound) = ctx.outbounds.get(group) else {
                return (404, json!({ "message": "нет такой группы" }));
            };
            match outbound.select(member) {
                Ok(()) => {
                    crate::debug!("clash-api", "{group} → {member}");
                    (204, Value::Null)
                }
                Err(message) => (400, json!({ "message": message })),
            }
        }
        ("GET", ["proxies", tag, "delay"]) => {
            let url = req.query.get("url").map(String::as_str).unwrap_or("https://www.gstatic.com/generate_204");
            let timeout = req.query.get("timeout").and_then(|t| t.parse().ok()).unwrap_or(5000);
            match crate::probe::delay(ctx, tag, url, timeout).await {
                Ok(delay) => (200, json!({ "delay": delay })),
                Err(e) => {
                    crate::debug!("probe", "{tag}: {e}");
                    (504, json!({ "message": e.to_string() }))
                }
            }
        }
        _ => (404, json!({ "message": "нет такого адреса" })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_request_waits_for_the_body() {
        let full = b"PUT /proxies/proxy HTTP/1.1\r\nAuthorization: Bearer s\r\nContent-Length: 4\r\n\r\nabcd";
        assert!(parse(&full[..full.len() - 1], "s").is_none());
        let (req, used) = parse(full, "s").unwrap();
        assert_eq!(used, full.len());
        assert_eq!(req.body, b"abcd");
        assert!(req.authorized);
        assert!(req.keep_alive);
    }

    #[test]
    fn wrong_or_missing_token_is_not_authorized() {
        assert!(!parse(b"GET /version HTTP/1.1\r\n\r\n", "s").unwrap().0.authorized);
        let bad = b"GET /version HTTP/1.1\r\nAuthorization: Bearer nope\r\n\r\n";
        assert!(!parse(bad, "s").unwrap().0.authorized);
        assert!(parse(b"GET /version HTTP/1.1\r\n\r\n", "").unwrap().0.authorized);
    }

    #[test]
    fn tags_and_urls_are_decoded() {
        assert_eq!(percent_decode("0-Tokyo%20JP"), "0-Tokyo JP");
        assert_eq!(percent_decode("%D0%9C"), "М");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
        assert_eq!(percent_decode("https%3A%2F%2Fa%2Fb"), "https://a/b");
    }
}
