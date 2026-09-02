//! Thin client over the Clash-compatible control API that sing-box exposes.
//!
//! Everything the UI does while connected — switching node, measuring latency,
//! reading counters, flipping Rule/Global/Direct — goes through here instead of
//! restarting the core.

use std::time::Duration;

use serde::Deserialize;
use serde_json::json;

use crate::error::{AppError, Result};

#[derive(Clone)]
pub struct ClashApi {
    base: String,
    secret: String,
    http: reqwest::Client,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Totals {
    pub download: u64,
    pub upload: u64,
    pub connections: usize,
}

#[derive(Deserialize)]
struct ConnectionsResponse {
    #[serde(default, rename = "downloadTotal")]
    download_total: u64,
    #[serde(default, rename = "uploadTotal")]
    upload_total: u64,
    #[serde(default)]
    connections: Option<Vec<serde_json::Value>>,
}

#[derive(Deserialize)]
struct DelayResponse {
    #[serde(default)]
    delay: u32,
    #[serde(default)]
    message: String,
}

impl ClashApi {
    pub fn new(port: u16, secret: &str) -> Self {
        Self {
            base: format!("http://127.0.0.1:{port}"),
            secret: secret.to_string(),
            http: crate::net::http_builder()
                .timeout(Duration::from_secs(15))
                // The controller is on loopback; a system proxy must not intercept it.
                .no_proxy()
                .build()
                .unwrap_or_default(),
        }
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.http
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(&self.secret)
    }

    pub async fn version(&self) -> Result<String> {
        let value: serde_json::Value = self
            .request(reqwest::Method::GET, "/version")
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(value["version"].as_str().unwrap_or_default().to_string())
    }

    /// Poll until the control plane answers, i.e. the core finished booting.
    ///
    /// Подключение ждёт панель иначе — `await_control_plane` смотрит ещё и на
    /// живость самого ядра; этот простой вариант остался интеграционным тестам.
    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn wait_ready(&self, timeout: Duration) -> Result<()> {
        let deadline = std::time::Instant::now() + timeout;
        let mut last: Option<String> = None;
        while std::time::Instant::now() < deadline {
            match self.version().await {
                Ok(_) => return Ok(()),
                Err(e) => last = Some(e.to_string()),
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        Err(AppError::msg(format!(
            "ядро не ответило за {} с{}",
            timeout.as_secs(),
            last.map(|e| format!(": {e}")).unwrap_or_default()
        )))
    }

    /// Cumulative byte counters since the core started. The caller turns these
    /// into a rate by differencing consecutive samples.
    pub async fn totals(&self) -> Result<Totals> {
        let body: ConnectionsResponse = self
            .request(reqwest::Method::GET, "/connections")
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(Totals {
            download: body.download_total,
            upload: body.upload_total,
            connections: body.connections.map(|c| c.len()).unwrap_or(0),
        })
    }

    /// Measure a single outbound. `Ok(None)` means the node answered but failed
    /// the probe, which the UI shows as "недоступен" rather than an error toast.
    pub async fn delay(&self, tag: &str, url: &str, timeout_ms: u32) -> Result<Option<u32>> {
        let encoded = urlencode(tag);
        let response = self
            .request(
                reqwest::Method::GET,
                &format!("/proxies/{encoded}/delay?timeout={timeout_ms}&url={}", urlencode(url)),
            )
            // Give the HTTP call more room than the probe itself, so a slow node
            // reports as slow instead of as a transport error.
            .timeout(Duration::from_millis(u64::from(timeout_ms) + 5_000))
            .send()
            .await?;

        if !response.status().is_success() {
            return Ok(None);
        }
        let body: DelayResponse = response.json().await?;
        if !body.message.is_empty() || body.delay == 0 {
            return Ok(None);
        }
        Ok(Some(body.delay))
    }

    /// Point a selector group at one of its members.
    pub async fn select(&self, group: &str, member: &str) -> Result<()> {
        let response = self
            .request(reqwest::Method::PUT, &format!("/proxies/{}", urlencode(group)))
            .json(&json!({ "name": member }))
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(AppError::msg(format!(
                "ядро отклонило смену сервера ({})",
                response.status()
            )));
        }
        Ok(())
    }

    /// `Rule` | `Global` | `Direct` — matched by the `clash_mode` route rules.
    pub async fn set_mode(&self, mode: &str) -> Result<()> {
        let response = self
            .request(reqwest::Method::PATCH, "/configs")
            .json(&json!({ "mode": mode }))
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(AppError::msg(format!(
                "не удалось переключить режим ({})",
                response.status()
            )));
        }
        Ok(())
    }

    pub async fn close_connections(&self) -> Result<()> {
        self.request(reqwest::Method::DELETE, "/connections")
            .send()
            .await?;
        Ok(())
    }

    /// Закрыть соединения, идущие через `tag` — любое звено цепочки (`chains`
    /// в ответе панели: от исходящего до узла). Точечнее, чем `DELETE
    /// /connections`: прямые соединения — локальная сеть, обход — остаются, и
    /// сеть ядро не сбрасывает.
    pub async fn close_via(&self, tag: &str) -> Result<usize> {
        let body: ConnectionsResponse = self
            .request(reqwest::Method::GET, "/connections")
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let ids = ids_via(&body.connections.unwrap_or_default(), tag);
        for id in &ids {
            let _ = self
                .request(reqwest::Method::DELETE, &format!("/connections/{}", urlencode(id)))
                .send()
                .await;
        }
        Ok(ids.len())
    }
}

/// Идентификаторы соединений, в чьей цепочке исходящих есть `tag`.
fn ids_via(connections: &[serde_json::Value], tag: &str) -> Vec<String> {
    connections
        .iter()
        .filter(|conn| {
            conn["chains"]
                .as_array()
                .is_some_and(|chain| chain.iter().any(|hop| hop == tag))
        })
        .filter_map(|conn| conn["id"].as_str().map(str::to_string))
        .collect()
}

/// Percent-encode a path/query segment. Proxy tags carry spaces and non-ASCII
/// names, both of which would otherwise corrupt the request line.
fn urlencode(value: &str) -> String {
    const UNRESERVED: &[u8] = b"-_.~";
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || UNRESERVED.contains(byte) {
            out.push(*byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_tags_that_would_break_the_request_line() {
        assert_eq!(urlencode("0-Tokyo JP"), "0-Tokyo%20JP");
        assert_eq!(urlencode("Москва"), "%D0%9C%D0%BE%D1%81%D0%BA%D0%B2%D0%B0");
        assert_eq!(urlencode("a/b?c=d"), "a%2Fb%3Fc%3Dd");
        assert_eq!(urlencode("plain-tag_1.0~x"), "plain-tag_1.0~x");
    }

    #[test]
    fn only_connections_routed_through_the_tag_are_picked() {
        // Цепочка — от узла к группе: у прокси-соединения это [узел, proxy],
        // у прямого — [direct]. Закрывать надо первые и не трогать вторые.
        let connections = vec![
            json!({ "id": "one", "chains": ["0-Tokyo", "proxy"] }),
            json!({ "id": "two", "chains": ["direct"] }),
            json!({ "id": "three", "chains": ["1-Berlin", "proxy"] }),
            json!({ "id": "four" }),
        ];
        assert_eq!(ids_via(&connections, "proxy"), vec!["one", "three"]);
        assert_eq!(ids_via(&connections, "0-Tokyo"), vec!["one"]);
        assert!(ids_via(&connections, "auto").is_empty());
    }
}
