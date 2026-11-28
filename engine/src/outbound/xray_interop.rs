//! Сквозные интеграционные тесты совместимости `aura-engine` с настоящим бинарником Xray-core.
//!
//! Помечены `#[ignore]`, потому что требуют локальных loopback-сокетов и наличия
//! `src-tauri/binaries/xray-x86_64-pc-windows-msvc.exe` (вне сетевой песочницы).
//! Запуск: `cargo test --manifest-path engine/Cargo.toml xray_interop -- --ignored --nocapture`

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::common::Target;
use crate::config::{OutboundOpts, TlsOpts, TransportOpts};
use crate::outbound::{masque::Masque, vless::Vless, Outbound};

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn xray_exe() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("..").join("src-tauri").join("binaries").join("xray-x86_64-pc-windows-msvc.exe")
}

fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn generate_tls_cert() -> Value {
    let out = Command::new(xray_exe())
        .args(["tls", "cert", "--domain=localhost", "--name=localhost"])
        .output()
        .expect("xray tls cert");
    assert!(out.status.success(), "xray tls cert failed: {}", String::from_utf8_lossy(&out.stderr));
    let v: Value = serde_json::from_slice(&out.stdout).expect("parse cert json");
    json!({
        "certificate": v["certificate"],
        "key": v["key"],
    })
}

fn generate_vlessenc() -> (String, String, String, String) {
    let out = Command::new(xray_exe()).arg("vlessenc").output().expect("xray vlessenc");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    let mut decs = Vec::new();
    let mut encs = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("\"decryption\": \"") {
            if let Some(val) = rest.strip_suffix('"') {
                decs.push(val.to_string());
            }
        } else if let Some(rest) = trimmed.strip_prefix("\"encryption\": \"") {
            if let Some(val) = rest.strip_suffix('"') {
                encs.push(val.to_string());
            }
        }
    }
    assert!(decs.len() >= 2 && encs.len() >= 2, "unexpected vlessenc output:\n{text}");
    (decs[0].clone(), encs[0].clone(), decs[1].clone(), encs[1].clone())
}

fn spawn_xray(name: &str, cfg: &Value) -> (ChildGuard, PathBuf) {
    let path = std::env::temp_dir().join(format!("aura-xray-interop-{name}-{}.json", std::process::id()));
    std::fs::write(&path, serde_json::to_vec_pretty(cfg).unwrap()).unwrap();
    let child = Command::new(xray_exe())
        .args(["run", "-c"])
        .arg(&path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn xray");
    (ChildGuard(child), path)
}

async fn start_echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

async fn wait_tcp_ready(port: u16) {
    for _ in 0..40 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("xray did not open tcp port {port}");
}

#[tokio::test]
#[ignore]
async fn real_xray_vless_encryption_mlkem768_random_1rtt_and_0rtt() {
    let echo_port = start_echo_server().await;
    let xray_port = free_tcp_port();
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let (_x_dec, _x_enc, mlkem_dec, mlkem_enc) = generate_vlessenc();
    // Проверяем самый сложный вариант: ML-KEM-768 + режим `random` + 0-RTT!
    let dec = mlkem_dec.replacen(".native.", ".random.", 1);
    let enc = mlkem_enc.replacen(".native.", ".random.", 1);

    let cfg = json!({
        "log": { "loglevel": "warning" },
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": xray_port,
            "protocol": "vless",
            "settings": {
                "clients": [{ "id": uuid }],
                "decryption": dec
            },
            "streamSettings": { "network": "tcp" }
        }],
        "outbounds": [{ "protocol": "freedom" }]
    });
    let (_guard, cfg_path) = spawn_xray("vlessenc", &cfg);
    wait_tcp_ready(xray_port).await;

    let outbound = Vless::new(&OutboundOpts {
        kind: "vless".into(),
        tag: "v".into(),
        server: "127.0.0.1".into(),
        server_port: xray_port,
        uuid: uuid.into(),
        encryption: enc,
        ..Default::default()
    })
    .unwrap();

    // 1) Первое соединение (1-RTT, получает тикет).
    let target = Target::new("127.0.0.1", echo_port);
    let mut s1 = outbound.dial(&target).await.expect("1-RTT dial");
    s1.write_all(b"hello-mlkem768-1rtt").await.unwrap();
    s1.flush().await.unwrap();
    let mut buf = [0u8; 19];
    s1.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello-mlkem768-1rtt");
    drop(s1);

    // 2) Второе соединение (0-RTT по кэшированному тикету).
    let mut s2 = outbound.dial(&target).await.expect("0-RTT dial");
    s2.write_all(b"hello-mlkem768-0rtt").await.unwrap();
    s2.flush().await.unwrap();
    let mut buf2 = [0u8; 19];
    s2.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, b"hello-mlkem768-0rtt");

    let _ = std::fs::remove_file(cfg_path);
}

#[tokio::test]
#[ignore]
async fn real_xray_xhttp_h2_packet_up_and_stream_one() {
    let echo_port = start_echo_server().await;
    let xray_port = free_tcp_port();
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let cert = generate_tls_cert();

    let cfg = json!({
        "log": { "loglevel": "warning" },
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": xray_port,
            "protocol": "vless",
            "settings": {
                "clients": [{ "id": uuid }],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [cert],
                    "alpn": ["h2"]
                },
                "xhttpSettings": {
                    "path": "/xhttp-test",
                    "host": "localhost"
                }
            }
        }],
        "outbounds": [{ "protocol": "freedom" }]
    });
    let (_guard, cfg_path) = spawn_xray("xhttp", &cfg);
    wait_tcp_ready(xray_port).await;

    for mode in ["packet-up", "stream-one", "stream-up"] {
        let outbound = Vless::new(&OutboundOpts {
            kind: "vless".into(),
            tag: "xh".into(),
            server: "127.0.0.1".into(),
            server_port: xray_port,
            uuid: uuid.into(),
            tls: Some(TlsOpts {
                enabled: true,
                server_name: "localhost".into(),
                insecure: true,
                alpn: vec!["h2".into()],
                ..Default::default()
            }),
            transport: Some(TransportOpts {
                kind: "xhttp".into(),
                path: "/xhttp-test".into(),
                host: json!("localhost"),
                mode: mode.into(),
                ..Default::default()
            }),
            ..Default::default()
        })
        .unwrap();

        let target = Target::new("127.0.0.1", echo_port);
        let mut s = outbound.dial(&target).await.unwrap_or_else(|e| panic!("xhttp {mode}: {e}"));
        let msg = format!("hello-xhttp-{mode}!");
        s.write_all(msg.as_bytes()).await.unwrap();
        s.flush().await.unwrap();
        let mut reply = vec![0u8; msg.len()];
        s.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, msg.as_bytes(), "xhttp {mode}");
    }

    let _ = std::fs::remove_file(cfg_path);
}

#[tokio::test]
#[ignore]
async fn real_xray_masque_h3_and_h2_connect_ip() {
    let cert = generate_tls_cert();
    let probe_cfg = json!({
        "log": { "loglevel": "warning" },
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": free_udp_port(),
            "protocol": "masque",
            "settings": { "clients": [{ "email": "a@b", "pass": "p" }], "address": ["10.99.0.1/24"] },
            "streamSettings": {
                "network": "masque",
                "security": "tls",
                "tlsSettings": { "certificates": [cert.clone()], "alpn": ["h3"] }
            }
        }],
        "outbounds": [{ "protocol": "freedom" }]
    });
    let probe_path = std::env::temp_dir().join(format!("aura-masque-probe-{}.json", std::process::id()));
    std::fs::write(&probe_path, serde_json::to_vec(&probe_cfg).unwrap()).unwrap();
    let check = Command::new(xray_exe()).args(["run", "-test", "-c"]).arg(&probe_path).output().unwrap();
    let _ = std::fs::remove_file(&probe_path);
    if !check.status.success() {
        eprintln!(
            "skipping live Xray MASQUE interop: bundled xray.exe does not yet support MASQUE ({})",
            String::from_utf8_lossy(&check.stderr).trim()
        );
        return;
    }

    let echo_port = start_echo_server().await;

    // 1) HTTP/3 DATAGRAM
    let h3_port = free_udp_port();
    let cfg_h3 = json!({
        "log": { "loglevel": "warning" },
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": h3_port,
            "protocol": "masque",
            "settings": {
                "clients": [{ "email": "alice@test", "pass": "pw123" }],
                "address": ["10.99.0.1/24"]
            },
            "streamSettings": {
                "network": "masque",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [cert.clone()],
                    "alpn": ["h3"]
                },
                "masqueSettings": {
                    "path": "/.well-known/masque/ip/*/*/"
                }
            }
        }],
        "outbounds": [{ "protocol": "freedom" }]
    });
    let (_g3, p3) = spawn_xray("masque-h3", &cfg_h3);
    tokio::time::sleep(Duration::from_millis(500)).await;

    let m_h3 = Masque::new(&OutboundOpts {
        kind: "masque".into(),
        tag: "m3".into(),
        server: "127.0.0.1".into(),
        server_port: h3_port,
        username: "alice@test".into(),
        password: "pw123".into(),
        tls: Some(TlsOpts {
            enabled: true,
            server_name: "localhost".into(),
            insecure: true,
            alpn: vec!["h3".into()],
            ..Default::default()
        }),
        ..Default::default()
    })
    .unwrap();

    let target = Target::new("127.0.0.1", echo_port);
    let mut s3 = m_h3.dial(&target).await.expect("masque h3 dial");
    s3.write_all(b"hello-masque-h3!").await.unwrap();
    let mut r3 = [0u8; 16];
    s3.read_exact(&mut r3).await.unwrap();
    assert_eq!(&r3, b"hello-masque-h3!");
    drop(s3);
    drop(_g3);
    let _ = std::fs::remove_file(p3);

    // 2) HTTP/2 Capsules
    let h2_port = free_tcp_port();
    let cfg_h2 = json!({
        "log": { "loglevel": "warning" },
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": h2_port,
            "protocol": "masque",
            "settings": {
                "clients": [{ "email": "bob@test", "pass": "pw456" }],
                "address": ["10.98.0.1/24"]
            },
            "streamSettings": {
                "network": "masque",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [cert],
                    "alpn": ["h2"]
                },
                "masqueSettings": {
                    "path": "/.well-known/masque/ip/*/*/"
                }
            }
        }],
        "outbounds": [{ "protocol": "freedom" }]
    });
    let (_g2, p2) = spawn_xray("masque-h2", &cfg_h2);
    wait_tcp_ready(h2_port).await;

    let m_h2 = Masque::new(&OutboundOpts {
        kind: "masque".into(),
        tag: "m2".into(),
        server: "127.0.0.1".into(),
        server_port: h2_port,
        username: "bob@test".into(),
        password: "pw456".into(),
        tls: Some(TlsOpts {
            enabled: true,
            server_name: "localhost".into(),
            insecure: true,
            alpn: vec!["h2".into()],
            ..Default::default()
        }),
        ..Default::default()
    })
    .unwrap();

    let mut s2 = m_h2.dial(&target).await.expect("masque h2 dial");
    s2.write_all(b"hello-masque-h2!").await.unwrap();
    let mut r2 = [0u8; 16];
    s2.read_exact(&mut r2).await.unwrap();
    assert_eq!(&r2, b"hello-masque-h2!");
    drop(s2);
    drop(_g2);
    let _ = std::fs::remove_file(p2);
}
