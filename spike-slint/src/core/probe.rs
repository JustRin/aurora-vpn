//! Замер задержки на «тёплом» соединении.
//!
//! `/proxies/<tag>/delay` у sing-box открывает новое соединение через узел и
//! меряет всё подряд: TCP до сервера, рукопожатие REALITY/TLS, и только потом
//! сам запрос. Это два-три круга до сервера вместо одного, поэтому число выходит
//! вдвое-втрое больше настоящего пинга — того, что показывают speedtest и
//! Hiddify. Здесь узел спрашивают так же, как это сделает приложение: соединение
//! открывается, прогревается первым запросом, а в зачёт идёт второй — по уже
//! готовому каналу, то есть ровно один круг «клиент → сервер → цель».
//!
//! Дорога к узлу — отдельный SOCKS-вход на loopback с именем пользователя, равным
//! тегу узла, и правилами маршрута «этот пользователь → этот узел». Вход есть
//! только у sing-box: Aura мерит сама (engine/src/probe.rs).

use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Тег входа в конфиге ядра.
pub const PROBE_IN: &str = "probe-in";

/// Как достучаться до замерочного входа. Пароль случайный на каждый запуск ядра:
/// порт на loopback, но воспользоваться чужим узлом через него не должен никто.
#[derive(Debug, Clone)]
pub struct ProbeAccess {
    pub port: u16,
    pub password: String,
}

impl ProbeAccess {
    pub fn new(port: u16) -> Self {
        Self { port, password: uuid::Uuid::new_v4().to_string() }
    }
}

/// Чем кончился замер.
#[derive(Debug, PartialEq, Eq)]
pub enum Probe {
    /// Задержка по тёплому соединению, мс.
    Ms(u32),
    /// Узел не отвечает (или ответил ошибкой сервера).
    Dead,
    /// Померить так нельзя — вход недоступен, адрес не http, ответ без длины.
    /// Остаётся прежний замер через панель ядра.
    Unavailable,
}

/// Теги, под которые заводится пользователь: имя SOCKS не длиннее 255 байт.
fn usable(tag: &str) -> bool {
    !tag.is_empty() && tag.len() <= 255
}

/// Дописать в конфиг вход и по правилу на каждый узел. Правила идут первыми:
/// трафик замера не должен ни обнюхиваться, ни попадать под режимы и правила
/// пользователя — только к своему узлу.
pub fn install(config: &mut Value, tags: &[String], access: &ProbeAccess) {
    let tags: Vec<&String> = tags.iter().filter(|t| usable(t)).collect();
    if tags.is_empty() {
        return;
    }
    let users: Vec<Value> = tags
        .iter()
        .map(|tag| json!({ "username": tag, "password": access.password }))
        .collect();
    if let Some(inbounds) = config.get_mut("inbounds").and_then(Value::as_array_mut) {
        inbounds.push(json!({
            "type": "socks",
            "tag": PROBE_IN,
            "listen": "127.0.0.1",
            "listen_port": access.port,
            "users": users
        }));
    }
    if let Some(rules) = config.pointer_mut("/route/rules").and_then(Value::as_array_mut) {
        let mut mine: Vec<Value> = tags
            .iter()
            .map(|tag| json!({ "inbound": [PROBE_IN], "auth_user": [tag], "outbound": tag }))
            .collect();
        mine.append(rules);
        *rules = mine;
    }
}

struct Target {
    host: String,
    port: u16,
    path: String,
}

fn parse(url: &str) -> Option<Target> {
    let url = url::Url::parse(url).ok()?;
    if url.scheme() != "http" {
        return None;
    }
    let mut path = url.path().to_string();
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    Some(Target {
        host: url.host_str()?.to_string(),
        port: url.port().unwrap_or(80),
        path,
    })
}

/// Ошибка внутри замера: узел плох или замер невозможен.
enum Fail {
    Dead,
    Unavailable,
}

type Step<T> = Result<T, Fail>;

async fn read_exact(stream: &mut TcpStream, buf: &mut [u8], on_eof: Fail) -> Step<()> {
    match stream.read_exact(buf).await {
        Ok(_) => Ok(()),
        Err(_) => Err(on_eof),
    }
}

/// Рукопожатие SOCKS5 с логином и CONNECT. Всё до CONNECT — наш собственный
/// вход: если он не отвечает, это не вина узла (`Unavailable`). Сам CONNECT
/// проходит через узел, и его провал — это уже `Dead`.
async fn connect(access: &ProbeAccess, tag: &str, target: &Target) -> Step<TcpStream> {
    // Свой вход на loopback отвечает мгновенно; молчание — значит, входа нет
    // (Windows на закрытом порту отказывает лишь через пару секунд).
    let mut stream = tokio::time::timeout(
        Duration::from_millis(500),
        TcpStream::connect(("127.0.0.1", access.port)),
    )
    .await
    .map_err(|_| Fail::Unavailable)?
    .map_err(|_| Fail::Unavailable)?;
    let _ = stream.set_nodelay(true);

    stream.write_all(&[0x05, 0x01, 0x02]).await.map_err(|_| Fail::Unavailable)?;
    let mut method = [0u8; 2];
    read_exact(&mut stream, &mut method, Fail::Unavailable).await?;
    if method != [0x05, 0x02] {
        return Err(Fail::Unavailable);
    }

    let mut auth = vec![0x01, tag.len() as u8];
    auth.extend_from_slice(tag.as_bytes());
    auth.push(access.password.len() as u8);
    auth.extend_from_slice(access.password.as_bytes());
    stream.write_all(&auth).await.map_err(|_| Fail::Unavailable)?;
    let mut verdict = [0u8; 2];
    read_exact(&mut stream, &mut verdict, Fail::Unavailable).await?;
    if verdict != [0x01, 0x00] {
        return Err(Fail::Unavailable);
    }

    let host = target.host.as_bytes();
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host);
    request.extend_from_slice(&target.port.to_be_bytes());
    stream.write_all(&request).await.map_err(|_| Fail::Dead)?;

    let mut head = [0u8; 4];
    read_exact(&mut stream, &mut head, Fail::Dead).await?;
    if head[1] != 0x00 {
        return Err(Fail::Dead);
    }
    let rest = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            read_exact(&mut stream, &mut len, Fail::Dead).await?;
            len[0] as usize
        }
        _ => return Err(Fail::Dead),
    };
    let mut skip = vec![0u8; rest + 2];
    read_exact(&mut stream, &mut skip, Fail::Dead).await?;
    Ok(stream)
}

/// Один запрос по открытому соединению: пишем GET, читаем ответ целиком, чтобы
/// соединение осталось пригодным для следующего.
async fn exchange(stream: &mut TcpStream, target: &Target) -> Step<()> {
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n",
        target.path, target.host
    );
    stream.write_all(request.as_bytes()).await.map_err(|_| Fail::Dead)?;

    let mut buf: Vec<u8> = Vec::with_capacity(512);
    let mut chunk = [0u8; 1024];
    let head_end = loop {
        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        if buf.len() > 16 * 1024 {
            return Err(Fail::Unavailable);
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return Err(Fail::Dead),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };

    let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or(Fail::Dead)?;
    if status >= 500 {
        return Err(Fail::Dead);
    }

    // Сколько тела ждать, чтобы следующий запрос не наткнулся на остаток этого.
    let length = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse::<usize>().ok());
    let body = match (status, length) {
        (204 | 304, _) => 0,
        (_, Some(n)) => n,
        // Ни длины, ни «нет тела»: где ответ кончается — неизвестно.
        _ => return Err(Fail::Unavailable),
    };
    let mut have = buf.len() - head_end;
    while have < body {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return Err(Fail::Dead),
            Ok(n) => have += n,
        }
    }
    Ok(())
}

/// Задержка узла по тёплому соединению. `timeout_ms` — на весь замер, с
/// прогревом: холодному соединению через дальний узел нужно время.
pub async fn warm_delay(access: &ProbeAccess, tag: &str, url: &str, timeout_ms: u32) -> Probe {
    let Some(target) = parse(url) else {
        return Probe::Unavailable;
    };
    if !usable(tag) {
        return Probe::Unavailable;
    }
    let work = async {
        let mut stream = connect(access, tag, &target).await?;
        // Прогрев: соединение с узлом, его рукопожатия и первый запрос — всё это
        // в число не входит.
        exchange(&mut stream, &target).await?;
        let started = Instant::now();
        exchange(&mut stream, &target).await?;
        Ok::<u32, Fail>(started.elapsed().as_millis().max(1) as u32)
    };
    match tokio::time::timeout(Duration::from_millis(u64::from(timeout_ms)), work).await {
        Ok(Ok(ms)) => Probe::Ms(ms),
        Ok(Err(Fail::Unavailable)) => Probe::Unavailable,
        Ok(Err(Fail::Dead)) | Err(_) => Probe::Dead,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_go_first_and_each_node_gets_its_own_user() {
        let mut config = json!({
            "inbounds": [{ "type": "mixed", "tag": "mixed-in" }],
            "route": { "rules": [{ "action": "sniff" }] }
        });
        let access = ProbeAccess::new(40000);
        install(&mut config, &["a".into(), "b".into()], &access);

        let inbounds = config["inbounds"].as_array().unwrap();
        assert_eq!(inbounds.len(), 2);
        assert_eq!(inbounds[1]["tag"], PROBE_IN);
        assert_eq!(inbounds[1]["listen"], "127.0.0.1");
        assert_eq!(inbounds[1]["users"].as_array().unwrap().len(), 2);

        let rules = config["route"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0]["auth_user"][0], "a");
        assert_eq!(rules[0]["outbound"], "a");
        assert_eq!(rules[1]["auth_user"][0], "b");
        assert_eq!(rules[2]["action"], "sniff");
    }

    #[test]
    fn nothing_is_added_without_usable_tags() {
        let mut config = json!({ "inbounds": [], "route": { "rules": [] } });
        install(&mut config, &[], &ProbeAccess::new(1));
        assert!(config["inbounds"].as_array().unwrap().is_empty());
        assert!(config["route"]["rules"].as_array().unwrap().is_empty());
    }

    #[test]
    fn only_plain_http_is_probed_warm() {
        let ok = parse("http://www.gstatic.com/generate_204").unwrap();
        assert_eq!((ok.host.as_str(), ok.port, ok.path.as_str()), ("www.gstatic.com", 80, "/generate_204"));
        let q = parse("http://example.com:8080/x?a=1").unwrap();
        assert_eq!((q.port, q.path.as_str()), (8080, "/x?a=1"));
        assert!(parse("https://www.gstatic.com/generate_204").is_none());
        assert!(parse("nonsense").is_none());
    }

    /// Крошечный SOCKS5-сервер с логином: проверяет, что клиент говорит по
    /// протоколу, и что в зачёт идёт именно второй запрос.
    async fn fake_socks(delay_second: Duration) -> (u16, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut hello = [0u8; 3];
            s.read_exact(&mut hello).await.unwrap();
            s.write_all(&[0x05, 0x02]).await.unwrap();
            let mut head = [0u8; 2];
            s.read_exact(&mut head).await.unwrap();
            let mut user = vec![0u8; head[1] as usize + 1];
            s.read_exact(&mut user).await.unwrap();
            let mut pass = vec![0u8; *user.last().unwrap() as usize];
            s.read_exact(&mut pass).await.unwrap();
            s.write_all(&[0x01, 0x00]).await.unwrap();
            let mut req = [0u8; 5];
            s.read_exact(&mut req).await.unwrap();
            let mut tail = vec![0u8; req[4] as usize + 2];
            s.read_exact(&mut tail).await.unwrap();
            s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await.unwrap();
            let mut buf = [0u8; 1024];
            for round in 0..2 {
                let mut got = Vec::new();
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = s.read(&mut buf).await.unwrap();
                    got.extend_from_slice(&buf[..n]);
                }
                if round == 1 {
                    tokio::time::sleep(delay_second).await;
                } else {
                    // Прогрев нарочно медленный: он в число входить не должен.
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
                s.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await.unwrap();
            }
        });
        (port, task)
    }

    #[tokio::test]
    async fn only_the_second_request_counts() {
        let (port, server) = fake_socks(Duration::from_millis(40)).await;
        let access = ProbeAccess { port, password: "p".into() };
        let got = warm_delay(&access, "node", "http://www.gstatic.com/generate_204", 5000).await;
        server.await.unwrap();
        match got {
            Probe::Ms(ms) => assert!((35..250).contains(&ms), "ms = {ms}"),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn a_closed_port_means_unavailable_not_dead() {
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let access = ProbeAccess { port, password: "p".into() };
        assert_eq!(
            warm_delay(&access, "node", "http://www.gstatic.com/generate_204", 1000).await,
            Probe::Unavailable
        );
    }
}
