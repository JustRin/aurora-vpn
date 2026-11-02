//! Клиент и сервер Veil в одном процессе, без TLS: проверяется сам протокол.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use aura_veil::addr::{Addr, Host};
use aura_veil::client::BoxIo;
use aura_veil::codec::KIND_DATA;
use aura_veil::server::{Server, ServerConfig, UserConf};
use aura_veil::{Client, ClientConfig, Connector, CMD_TCP, CMD_UDP};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const PATH: &str = "/api/v1/sync/test";

async fn start_server() -> SocketAddr {
    start_server_with(|_| {}).await
}

async fn start_server_with(tweak: impl FnOnce(&mut ServerConfig)) -> SocketAddr {
    // Свободный порт: занимаем и отпускаем.
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    let mut cfg = ServerConfig {
        listen: addr.to_string(),
        path: PATH.to_string(),
        users: vec![UserConf { name: "alice".into(), password: "correct horse".into() }],
        allow_private: true,
        access_log: true,
        ru_cidr_file: String::new(),
        ..ServerConfig::default()
    };
    tweak(&mut cfg);
    tokio::spawn(Server::new(cfg, None).run());
    for _ in 0..50 {
        if TcpStream::connect(addr).await.is_ok() {
            return addr;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("сервер не поднялся");
}

fn client(server: SocketAddr, password: &str) -> Client {
    let connector: Connector = Arc::new(move || {
        Box::pin(async move {
            let tcp = TcpStream::connect(server).await?;
            Ok(Box::new(tcp) as BoxIo)
        })
    });
    Client::new(ClientConfig { host: "example.com".into(), path: PATH.into(), password: password.into() }, connector)
}

fn socks(addr: SocketAddr) -> Vec<u8> {
    let mut out = Vec::new();
    Addr { host: Host::Ip(addr.ip()), port: addr.port() }.write(&mut out);
    out
}

async fn tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_roundtrip_many_streams() {
    let server = start_server().await;
    let echo = tcp_echo().await;
    let client = Arc::new(client(server, "correct horse"));

    // 5 МБ через один поток: проверка окон h2 и порядка записей.
    let mut stream = client.open(CMD_TCP, &socks(echo)).await.unwrap();
    let payload: Vec<u8> = (0..5 * 1024 * 1024).map(|i| (i * 31 % 251) as u8).collect();
    let (mut r, mut w) = tokio::io::split(&mut stream);
    let send = payload.clone();
    let writer = async move {
        w.write_all(&send).await.unwrap();
        w.shutdown().await.unwrap();
    };
    let reader = async move {
        let mut got = Vec::new();
        r.read_to_end(&mut got).await.unwrap();
        got
    };
    let (_, got) = tokio::join!(writer, reader);
    assert_eq!(got.len(), payload.len());
    assert!(got == payload, "данные испорчены");

    // Много параллельных потоков в одном соединении.
    let mut tasks = Vec::new();
    for i in 0..150u32 {
        let client = client.clone();
        tasks.push(tokio::spawn(async move {
            let mut s = client.open(CMD_TCP, &socks(echo)).await.unwrap();
            let msg = format!("поток {i}").repeat(50);
            s.write_all(msg.as_bytes()).await.unwrap();
            s.shutdown().await.unwrap();
            let mut back = String::new();
            s.read_to_string(&mut back).await.unwrap();
            assert_eq!(back, msg);
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_roundtrip() {
    let server = start_server().await;
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let (n, from) = echo.recv_from(&mut buf).await.unwrap();
            echo.send_to(&buf[..n], from).await.unwrap();
        }
    });
    let client = client(server, "correct horse");
    let (mut rx, mut tx) = client.open(CMD_UDP, &socks(echo_addr)).await.unwrap().into_split();
    for i in 0..20u8 {
        let mut frame = socks(echo_addr);
        frame.extend_from_slice(&[i; 1200]);
        tx.send(KIND_DATA, &frame, true).await.unwrap();
        let (kind, data) = tokio::time::timeout(Duration::from_secs(5), rx.record()).await.unwrap().unwrap().unwrap();
        assert_eq!(kind, KIND_DATA);
        let (from, used) = Addr::read(&data).unwrap();
        assert_eq!(from, Addr { host: Host::Ip(echo_addr.ip()), port: echo_addr.port() });
        assert_eq!(&data[used..], &[i; 1200][..]);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_password_gets_404() {
    let server = start_server().await;
    let echo = tcp_echo().await;
    let client = client(server, "wrong");
    let mut s = client.open(CMD_TCP, &socks(echo)).await.unwrap();
    let _ = s.write_all(b"ping").await;
    let mut buf = [0u8; 4];
    let err = s.read(&mut buf).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
}

/// Посторонний, знающий путь, но без жетона, получает тот же 404, что и на
/// любой другой адрес; GET сайта тоже 404 (сайт отдаёт фронт, не мы).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probes_see_plain_404() {
    let server = start_server().await;
    let tcp = TcpStream::connect(server).await.unwrap();
    let (mut send, conn) = h2::client::handshake(tcp).await.unwrap();
    tokio::spawn(conn);
    for (method, path) in [("POST", PATH), ("GET", PATH), ("GET", "/")] {
        let req = http::Request::builder().method(method).uri(format!("https://example.com{path}")).body(()).unwrap();
        let (resp, _) = send.send_request(req, true).unwrap();
        assert_eq!(resp.await.unwrap().status(), 404, "{method} {path}");
    }
}

/// Российский домен и адрес из списка сетей РФ наружу не выходят: поток
/// обрывается, до цели дело не доходит.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn russian_targets_are_cut() {
    let echo = tcp_echo().await;
    let cidr = std::env::temp_dir().join(format!("veil-ru-{}.txt", std::process::id()));
    std::fs::write(&cidr, "127.0.0.0/8\n").unwrap();
    let cidr_path = cidr.to_string_lossy().into_owned();
    let server = start_server_with(move |cfg| cfg.ru_cidr_file = cidr_path).await;
    let client = client(server, "correct horse");

    let mut domain = Vec::new();
    Addr { host: Host::Domain("api.vk.ru".into()), port: 443 }.write(&mut domain);
    for target in [domain, socks(echo)] {
        let mut s = client.open(CMD_TCP, &target).await.unwrap();
        let _ = s.write_all(b"ping").await;
        let mut buf = [0u8; 4];
        let got = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await.unwrap();
        assert!(matches!(got, Err(_) | Ok(0)), "поток должен оборваться, а пришло {got:?}");
    }
    let _ = std::fs::remove_file(cidr);

    // С выключенной защитой тот же адрес открывается.
    let server = start_server_with(|cfg| cfg.block_ru = false).await;
    let mut s = client_for(server).open(CMD_TCP, &socks(echo)).await.unwrap();
    s.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
}

fn client_for(server: SocketAddr) -> Client {
    client(server, "correct horse")
}

/// Часы клиента сбиты на два месяца, как у эмулятора или телефона с не тем
/// поясом: время сервера берётся из `Date` ответа на загрузку страницы.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn skewed_client_clock_is_corrected_by_the_date_header() {
    let server = start_server().await;
    let echo = tcp_echo().await;
    let client = client(server, "correct horse");
    client.skew_clock_for_test(-60 * 86_400);
    let mut s = client.open(CMD_TCP, &socks(echo)).await.unwrap();
    s.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
}

/// Поддельная панель 3x-ui: подписка по subId из `alive`, иначе 404.
async fn fake_panel(alive: Arc<std::sync::Mutex<Vec<String>>>) -> SocketAddr {
    use base64::Engine;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            let alive = alive.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = head.split_whitespace().nth(1).unwrap_or("").to_string();
                let id = path.trim_start_matches("/subs/").to_string();
                let reply = if alive.lock().unwrap().contains(&id) {
                    let body = base64::engine::general_purpose::STANDARD.encode(format!("vless://u@h:1#{id}\n"));
                    format!(
                        "HTTP/1.1 200 OK\r\nSubscription-Userinfo: upload=1; download=2; total=0; expire=0\r\nProfile-Update-Interval: 12\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    )
                } else {
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string()
                };
                let _ = s.write_all(reply.as_bytes()).await;
            });
        }
    });
    addr
}

async fn h2_get(server: SocketAddr, path: &str, agent: &str) -> (u16, http::HeaderMap, Vec<u8>) {
    let tcp = TcpStream::connect(server).await.unwrap();
    let (send, conn) = h2::client::handshake(tcp).await.unwrap();
    tokio::spawn(conn);
    let mut send = send.ready().await.unwrap();
    let req = http::Request::builder()
        .uri(format!("https://example.com{path}"))
        .header("user-agent", agent)
        .body(())
        .unwrap();
    let (resp, _) = send.send_request(req, true).unwrap();
    let resp = resp.await.unwrap();
    let (parts, mut body) = resp.into_parts();
    let mut data = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.unwrap();
        let _ = body.flow_control().release_capacity(chunk.len());
        data.extend_from_slice(&chunk);
    }
    (parts.status.as_u16(), parts.headers, data)
}

/// Подписка 3x-ui приходит с Veil в конце; пароль из неё пускает в туннель,
/// а после отключения клиента в панели — уже нет.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn panel_subscription_carries_veil_and_revokes_it() {
    use base64::Engine;
    let alive = Arc::new(std::sync::Mutex::new(vec!["friend1".to_string()]));
    let panel = fake_panel(alive.clone()).await;
    let state = std::env::temp_dir().join(format!("veil-subs-{}.json", std::process::id()));
    let _ = std::fs::remove_file(&state);
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    let cfg = ServerConfig {
        listen: addr.to_string(),
        path: PATH.to_string(),
        allow_private: true,
        ru_cidr_file: String::new(),
        subscription: Some(aura_veil::subs::SubConfig {
            upstream: format!("http://{panel}/subs/"),
            secret: "0123456789abcdef-secret".into(),
            host: "example.com".into(),
            state_file: state.to_string_lossy().into_owned(),
            ..Default::default()
        }),
        ..ServerConfig::default()
    };
    let server = Server::new(cfg, None);
    tokio::spawn(server.clone().run());
    for _ in 0..50 {
        if TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Стороннему клиенту — подписка панели без изменений.
    let (status, _, body) = h2_get(addr, "/subs/friend1", "Happ/3.0").await;
    assert_eq!(status, 200);
    let plain = String::from_utf8(base64::engine::general_purpose::STANDARD.decode(&body).unwrap()).unwrap();
    assert!(!plain.contains("veil://"), "{plain}");

    let (status, headers, body) = h2_get(addr, "/subs/friend1", "Aurora-VPN/0.1 (sing-box)").await;
    assert_eq!(status, 200);
    assert!(headers.get("subscription-userinfo").is_some(), "заголовки панели сохранены");
    let plain = String::from_utf8(base64::engine::general_purpose::STANDARD.decode(&body).unwrap()).unwrap();
    let veil_link = plain.lines().find(|l| l.starts_with("veil://")).expect("ссылка Veil в подписке");
    assert!(plain.starts_with("vless://"), "ссылки панели на месте");
    let password = veil_link.trim_start_matches("veil://").split('@').next().unwrap().to_string();
    assert!(veil_link.contains("path=%2Fapi%2Fv1%2Fsync%2Ftest"), "{veil_link}");

    assert_eq!(h2_get(addr, "/subs/stranger", "Aurora-VPN/0.1").await.0, 404);
    assert_eq!(h2_get(addr, "/subs/..%2Fetc", "Aurora-VPN/0.1").await.0, 404);

    // Пароль из подписки открывает туннель.
    let echo = tcp_echo().await;
    let mut s = client(addr, &password).open(CMD_TCP, &socks(echo)).await.unwrap();
    s.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");

    // Клиента отключили в панели — сверка снимает доступ.
    alive.lock().unwrap().clear();
    server.check_subs().await;
    let mut s = client(addr, &password).open(CMD_TCP, &socks(echo)).await.unwrap();
    let _ = s.write_all(b"ping").await;
    let err = s.read(&mut buf).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
    let _ = std::fs::remove_file(&state);
}
