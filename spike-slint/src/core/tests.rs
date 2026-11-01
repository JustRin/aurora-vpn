//! End-to-end exercise of the core pipeline against the real sing-box binary:
//! generate a document, validate it, spawn the process, drive its control API,
//! then tear it down.
//!
//! Deliberately uses system-proxy mode with a loopback listener, so the test
//! never creates a virtual adapter or touches system-wide settings.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use std::collections::{HashMap, HashSet};

use crate::core::clash::ClashApi;
use crate::core::config::{self, BuildInput, TAG_AUTO, TAG_PROXY};
use crate::core::process::{CoreSupervisor, Engine};
use crate::model::{Protocol, Security, ServerNode};
use crate::settings::{Settings, SplitConfig, TunnelMode};

/// Ports well outside the app's defaults, so a running instance cannot clash.
const CLASH_PORT: u16 = 19_191;
const MIXED_PORT: u16 = 12_080;

/// These fixtures never exercise the Xray hand-off; they cover sing-box on its own.
fn no_xray() -> HashMap<String, u16> {
    HashMap::new()
}

/// No geo data cached, so the generator drops those rules — which keeps these
/// tests off the network entirely.
fn no_sets() -> HashSet<String> {
    HashSet::new()
}

fn core_binary() -> Option<PathBuf> {
    let triple = env!("TARGET_TRIPLE");
    let name = if cfg!(windows) {
        format!("sing-box-{triple}.exe")
    } else {
        format!("sing-box-{triple}")
    };
    // Обе папки, как в app::locate_binary. Своей у спайка нет: fetch-core.mjs
    // кладёт ядро в src-tauri/binaries — и на машине разработчика, и в CI, —
    // так что без второго варианта эти проверки молча пропускались везде.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    [root.join("binaries"), root.join("../src-tauri/binaries")]
        .into_iter()
        .map(|dir| dir.join(&name))
        .find(|path| path.is_file())
}

fn xray_binary() -> Option<PathBuf> {
    let triple = env!("TARGET_TRIPLE");
    let name = if cfg!(windows) {
        format!("xray-{triple}.exe")
    } else {
        format!("xray-{triple}")
    };
    // Те же две папки, что у core_binary.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    [root.join("binaries"), root.join("../src-tauri/binaries")]
        .into_iter()
        .map(|dir| dir.join(&name))
        .find(|path| path.is_file())
}

fn sample_nodes() -> Vec<ServerNode> {
    // The endpoints are never dialled: sing-box connects lazily, so an
    // unreachable server still exercises the full start-up path.
    vec![
        ServerNode {
            id: "n1".into(),
            name: "Проверка REALITY".into(),
            protocol: Protocol::Vless,
            address: "192.0.2.10".into(),
            port: 443,
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
            security: Security::Reality,
            public_key: "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0".into(),
            short_id: "0123abcd".into(),
            fingerprint: "chrome".into(),
            sni: "www.microsoft.com".into(),
            flow: "xtls-rprx-vision".into(),
            ..Default::default()
        },
        ServerNode {
            id: "n2".into(),
            name: "Проверка WebSocket".into(),
            protocol: Protocol::Vless,
            address: "192.0.2.11".into(),
            port: 8443,
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
            security: Security::Tls,
            network: crate::model::Network::Ws,
            path: "/ray?ed=2048".into(),
            host: "cdn.example.com".into(),
            ..Default::default()
        },
    ]
}

#[tokio::test(flavor = "multi_thread")]
async fn core_starts_from_a_generated_config_and_answers_its_control_api() {
    let Some(exe) = core_binary() else {
        eprintln!("пропуск: бинарник sing-box не найден (запустите npm run fetch-core)");
        return;
    };

    let work = std::env::temp_dir().join("aurora-core-lifecycle");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();

    let nodes = sample_nodes();
    let settings = Settings {
        // No TUN: this must run unprivileged and leave the machine untouched.
        tunnel_mode: TunnelMode::SystemProxy,
        clash_port: CLASH_PORT,
        mixed_port: MIXED_PORT,
        ..Default::default()
    };
    let split = SplitConfig::default();

    let built = config::build(&BuildInput {
        nodes: &nodes,
        active_id: "n2",
        settings: &settings,
        split: &split,
        clash_secret: "test-secret",
        cache_path: &work.join("cache.db"),
        xray_ports: &no_xray(),
        xray_exe: None,
        rule_sets: &no_sets(),
        rule_set_dir: &work.join("rulesets"),
        warp_chain: None,
    })
    .expect("конфигурация должна собираться");

    let config_path = work.join("config.json");
    std::fs::write(&config_path, serde_json::to_vec_pretty(&built.json).unwrap()).unwrap();

    let mut core = CoreSupervisor::new(Engine::SingBox, exe, work.clone());

    // The generated document must satisfy the real parser, not just our tests.
    core.check_config(&config_path)
        .expect("sing-box должен принять сгенерированный конфиг");

    // Keep the output: if the control plane never answers, the core's own log
    // is the only thing that explains why.
    let captured: Arc<parking_lot::Mutex<Vec<String>>> = Arc::default();
    let sink = Arc::clone(&captured);
    core.start(&config_path, move |line| {
        sink.lock().push(format!("[{}] {}", line.level, line.text));
    })
    .expect("ядро должно запуститься");

    let api = ClashApi::new(CLASH_PORT, "test-secret");
    let ready = api.wait_ready(Duration::from_secs(20)).await;

    // Collect everything before asserting, so a failure still stops the core.
    let totals = if ready.is_ok() { api.totals().await.ok() } else { None };
    let selected = if ready.is_ok() {
        Some(api.select(TAG_PROXY, TAG_AUTO).await)
    } else {
        None
    };
    let mode = if ready.is_ok() {
        Some(api.set_mode("Global").await)
    } else {
        None
    };

    core.stop();

    let log = captured.lock().join("\n");
    if let Err(e) = &ready {
        panic!("панель управления ядра не ответила: {e}\n--- журнал ядра ---\n{log}");
    }
    assert!(!log.is_empty(), "ядро должно писать в журнал");

    let totals = totals.expect("счётчики должны читаться");
    assert_eq!(totals.connections, 0, "свежий процесс не имеет соединений");

    selected.unwrap().expect("селектор должен переключаться на auto");
    mode.unwrap().expect("режим маршрутизации должен переключаться");

    let _ = std::fs::remove_dir_all(&work);
}

/// Ядро, которого приложение не запускало, — сирота. Тот самый случай, из-за
/// которого подключение падало на «initialize cache-file: timeout»: находится,
/// снимается и запись за собой убирает.
///
/// Запуск идёт мимо `CoreSupervisor` — так процесс не попадает в список своих
/// и выглядит ровно как ядро, пережившее прошлый сеанс.
#[test]
fn a_core_we_did_not_start_is_found_and_killed() {
    use crate::core::process::{find_orphan, kill_orphan, Killed};

    let Some(exe) = core_binary() else {
        eprintln!("пропуск: бинарник sing-box не найден");
        return;
    };

    let work = std::env::temp_dir().join("aurora-core-stray");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();

    // Ни входов, ни панели управления: ядру достаточно подняться и держать
    // файл кэша — именно эту блокировку и не может забрать второе ядро.
    let config_path = work.join("stray.json");
    std::fs::write(
        &config_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "log": { "level": "error" },
            "experimental": {
                "cache_file": { "enabled": true, "path": work.join("cache.db") }
            },
            "outbounds": [ { "type": "direct", "tag": "direct" } ]
        }))
        .unwrap(),
    )
    .unwrap();

    let mut stray = std::process::Command::new(&exe)
        .args(["run".as_ref(), "-c".as_ref(), config_path.as_os_str()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("постороннее ядро должно запуститься");
    let pid = stray.id();

    let pid_file = work.join("core.pid");
    std::fs::write(&pid_file, pid.to_string()).unwrap();

    let found = find_orphan(&pid_file, &exe).expect("ядро от прошлого сеанса должно находиться");
    assert_eq!(found.pid, pid, "найтись должно именно оно");

    assert_eq!(
        kill_orphan(&found, &pid_file),
        Killed::Gone,
        "своё же ядро должно сниматься"
    );
    let _ = stray.wait();
    assert!(
        !pid_file.exists(),
        "запись убирается только после подтверждённого ухода — и здесь он подтверждён"
    );
    assert!(
        find_orphan(&pid_file, &exe).map(|f| f.pid) != Some(pid),
        "снятое ядро больше не находится"
    );

    let _ = std::fs::remove_dir_all(&work);
}

/// Своё живое ядро сиротой не считается. Замер задержки поднимает второй
/// sing-box из того же файла, и без этого приложение предлагало бы снять
/// собственную работу, а «Да» её бы и оборвало.
#[tokio::test(flavor = "multi_thread")]
async fn a_running_core_of_ours_is_never_reported_as_an_orphan() {
    let Some(exe) = core_binary() else {
        eprintln!("пропуск: бинарник sing-box не найден");
        return;
    };

    let work = std::env::temp_dir().join("aurora-core-orphan");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();

    let settings = Settings {
        tunnel_mode: TunnelMode::SystemProxy,
        // Свои порты: проверки идут параллельно, и занятый сосед уронил бы обе.
        clash_port: CLASH_PORT + 2,
        mixed_port: MIXED_PORT + 2,
        ..Default::default()
    };
    let built = config::build(&BuildInput {
        nodes: &sample_nodes(),
        active_id: "n2",
        settings: &settings,
        split: &SplitConfig::default(),
        clash_secret: "test-secret",
        cache_path: &work.join("cache.db"),
        xray_ports: &no_xray(),
        xray_exe: None,
        rule_sets: &no_sets(),
        rule_set_dir: &work.join("rulesets"),
        warp_chain: None,
    })
    .expect("конфигурация должна собираться");

    let config_path = work.join("config.json");
    std::fs::write(&config_path, serde_json::to_vec_pretty(&built.json).unwrap()).unwrap();

    let mut core = CoreSupervisor::new(Engine::SingBox, exe.clone(), work.clone());
    let pid = core.start(&config_path, |_| {}).expect("ядро должно запуститься");

    // Запись на месте, процесс жив — и всё равно не сирота: номер в списке своих.
    let pid_file = work.join("core.pid");
    std::fs::write(&pid_file, pid.to_string()).unwrap();
    let seen = crate::core::process::find_orphan(&pid_file, &exe).map(|found| found.pid);
    assert_ne!(seen, Some(pid), "живое ядро приложения — не сирота");

    core.stop();

    // Ядро ушло — и запись о нём больше ничего не сторожит.
    crate::core::process::forget_dead_pid(&pid_file, &exe);
    assert!(
        !pid_file.exists(),
        "запись о завершённом ядре должна убираться"
    );

    let _ = std::fs::remove_dir_all(&work);
}

#[tokio::test(flavor = "multi_thread")]
async fn split_tunnel_config_with_process_rules_is_accepted_by_the_core() {
    let Some(exe) = core_binary() else {
        eprintln!("пропуск: бинарник sing-box не найден");
        return;
    };

    let work = std::env::temp_dir().join("aurora-core-split");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();

    let split = SplitConfig {
        mode: crate::settings::SplitMode::Include,
        apps: vec![
            crate::settings::AppRule {
                id: "a".into(),
                name: "chrome.exe".into(),
                path: String::new(),
                enabled: true,
            },
            crate::settings::AppRule {
                id: "b".into(),
                name: "game.exe".into(),
                path: r"C:\Games\game.exe".into(),
                enabled: true,
            },
        ],
        direct_domains: vec!["gosuslugi.ru".into()],
        proxy_domains: vec!["youtube.com".into()],
        direct_ips: vec!["10.0.0.0/8".into()],
        bypass_ru: true,
        block_ads: true,
        ..Default::default()
    };

    let settings = Settings {
        // Rule sets referenced from a TUN config are the heaviest variant to
        // validate, and this is the mode split tunnelling actually runs in.
        clash_port: CLASH_PORT + 1,
        mixed_port: MIXED_PORT + 1,
        fake_ip: true,
        ..Default::default()
    };

    let built = config::build(&BuildInput {
        nodes: &sample_nodes(),
        active_id: "n1",
        settings: &settings,
        split: &split,
        clash_secret: "s",
        cache_path: &work.join("cache.db"),
        xray_ports: &no_xray(),
        xray_exe: None,
        rule_sets: &no_sets(),
        rule_set_dir: &work.join("rulesets"),
        warp_chain: None,
    })
    .expect("конфигурация должна собираться");

    let config_path = work.join("config.json");
    std::fs::write(&config_path, serde_json::to_vec_pretty(&built.json).unwrap()).unwrap();

    let mut core = CoreSupervisor::new(Engine::SingBox, exe, work.clone());
    core.check_config(&config_path)
        .expect("правила по процессам и гео-наборы должны приниматься ядром");

    // `check` only parses. Start the same shape without the remote rule sets —
    // keeping the test off the network — so the fake-ip and per-process DNS
    // rules are exercised by the code path that actually rejected a bad detour.
    let offline_split = SplitConfig {
        bypass_ru: false,
        block_ads: false,
        ..split
    };
    // Creating the virtual adapter needs administrator rights, which a test run
    // must not assume; the routing and DNS rules under test are identical in
    // both tunnel modes.
    let offline_settings = Settings {
        tunnel_mode: TunnelMode::SystemProxy,
        ..settings.clone()
    };
    let offline = config::build(&BuildInput {
        nodes: &sample_nodes(),
        active_id: "n1",
        settings: &offline_settings,
        split: &offline_split,
        clash_secret: "s",
        cache_path: &work.join("cache.db"),
        xray_ports: &no_xray(),
        xray_exe: None,
        rule_sets: &no_sets(),
        rule_set_dir: &work.join("rulesets"),
        warp_chain: None,
    })
    .expect("конфигурация должна собираться");

    let offline_path = work.join("offline.json");
    std::fs::write(&offline_path, serde_json::to_vec_pretty(&offline.json).unwrap()).unwrap();

    let captured: Arc<parking_lot::Mutex<Vec<String>>> = Arc::default();
    let sink = Arc::clone(&captured);
    core.start(&offline_path, move |line| {
        sink.lock().push(format!("[{}] {}", line.level, line.text));
    })
    .expect("ядро должно запуститься");

    let api = ClashApi::new(settings.clash_port, "s");
    let ready = api.wait_ready(Duration::from_secs(20)).await;
    core.stop();

    if let Err(e) = ready {
        panic!(
            "ядро не поднялось со split-правилами и fake-ip: {e}\n--- журнал ядра ---\n{}",
            captured.lock().join("\n")
        );
    }

    let _ = std::fs::remove_dir_all(&work);
}

/// The AmneziaWG fields only the sing-box-lx build reads, straight from an
/// imported 3x-ui `.conf`: the parser's output must be what the real core
/// accepts, ranges and 3.x keys included. The peer is a refused loopback port
/// for the same reason as in the WARP test above.
#[tokio::test(flavor = "multi_thread")]
async fn an_imported_amneziawg_conf_is_accepted_by_the_lx_core() {
    let Some(exe) = core_binary() else {
        eprintln!("пропуск: бинарник sing-box не найден (запустите npm run fetch-core)");
        return;
    };
    let work = std::env::temp_dir().join("aurora-core-awg");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();

    let mut core = CoreSupervisor::new(Engine::SingBox, exe, work.clone());
    let version = core.version().unwrap_or_default();
    if !version.contains("-lx") {
        eprintln!("пропуск: ядро «{version}» — не sing-box-lx, AmneziaWG ему не по силам");
        return;
    }

    let conf = "[Interface]
PrivateKey = YPxqmCyjmwV8MU2IZ4dSAlhmDHW/+9M2uXn9fq6Kb3c=
Address = 10.8.1.2/32
MTU = 1376
Jc = 4
Jmin = 65
Jmax = 220
S1 = 87
S2 = 44
S3 = 21
S4 = 12
H1 = 463065432
H2 = 912345678
H3 = 1345678901-1345679901
H4 = 1987654321
I1 = <r 148>
HeaderProtectionKey = 8Iu83eHDA3fMKKSGaEsVW9Ycd2lYYzc0MYlk1jJTvE4=
ContentPaddingAddition = 17-49
RekeyAfterTime = 111-139
RekeyTimeout = 4-7
RejectAfterTime = 187-251
KeepaliveTimeout = 9-14
MaxHandshakeAttempts = 19-36
RandomTrailers = on
DisableCookies = on

# awg-test
[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
PresharedKey = FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 127.0.0.1:1
PersistentKeepalive = 15-25
";
    let report = crate::link::parse_subscription(conf);
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    let nodes = report.nodes;
    assert_eq!(nodes[0].protocol, Protocol::Amneziawg);

    let settings = Settings {
        tunnel_mode: TunnelMode::SystemProxy,
        clash_port: CLASH_PORT + 3,
        mixed_port: MIXED_PORT + 3,
        ..Default::default()
    };
    let split = SplitConfig::default();
    let built = config::build(&BuildInput {
        nodes: &nodes,
        active_id: &nodes[0].id,
        settings: &settings,
        split: &split,
        clash_secret: "s",
        cache_path: &work.join("cache.db"),
        xray_ports: &no_xray(),
        xray_exe: None,
        rule_sets: &no_sets(),
        rule_set_dir: &work.join("rulesets"),
        warp_chain: None,
    })
    .expect("конфигурация с AmneziaWG должна собираться");

    let config_path = work.join("awg.json");
    std::fs::write(&config_path, serde_json::to_vec_pretty(&built.json).unwrap()).unwrap();
    core.check_config(&config_path)
        .expect("sing-box-lx должен принять endpoint AmneziaWG 3.1");

    // `check` only parses; the device itself validates the obfuscation set
    // (overlapping headers, a header key with short padding) when it is built.
    let captured: Arc<parking_lot::Mutex<Vec<String>>> = Arc::default();
    let sink = Arc::clone(&captured);
    core.start(&config_path, move |line| {
        sink.lock().push(format!("[{}] {}", line.level, line.text));
    })
    .expect("ядро должно запуститься");
    let api = ClashApi::new(settings.clash_port, "s");
    let ready = api.wait_ready(Duration::from_secs(20)).await;
    core.stop();

    if let Err(e) = ready {
        panic!(
            "ядро не поднялось с AmneziaWG: {e}\n--- журнал ядра ---\n{}",
            captured.lock().join("\n")
        );
    }
    let _ = std::fs::remove_dir_all(&work);
}

/// A MASQUE outbound as 3x-ui puts it into a JSON subscription, imported and
/// re-rendered for the second engine: the real Xray parser has the last word
/// on the transport and TLS shape.
#[test]
fn an_imported_masque_outbound_is_accepted_by_xray() {
    let Some(exe) = xray_binary() else {
        eprintln!("пропуск: бинарник Xray не найден (запустите npm run fetch-core)");
        return;
    };
    let work = std::env::temp_dir().join("aurora-xray-masque");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();

    let body = serde_json::json!([{
        "remarks": "masque-test",
        "outbounds": [{
            "protocol": "masque",
            "tag": "proxy",
            "settings": { "address": "192.0.2.12", "port": 8443 },
            "streamSettings": {
                "network": "masque",
                "security": "tls",
                "tlsSettings": { "serverName": "masque.example.test", "alpn": ["h2"] },
                "masqueSettings": {
                    "path": "/.well-known/masque/ip/*/*/",
                    "user": "ivy@example.test",
                    "pass": "pw-ivy"
                }
            }
        }]
    }])
    .to_string();
    let report = crate::link::parse_subscription(&body);
    assert!(report.errors.is_empty(), "{:?}", report.errors);

    let built = crate::core::xray::build(&report.nodes, 24_150, "warning")
        .unwrap()
        .expect("MASQUE всегда уходит в Xray");
    let config_path = work.join("xray.json");
    std::fs::write(&config_path, serde_json::to_vec_pretty(&built.json).unwrap()).unwrap();

    let core = CoreSupervisor::new(Engine::Xray, exe, work.clone());
    // «Xray 26.10.21 (Xray, Penetrates Everything.) …»
    let version = core.version().unwrap_or_default();
    let release: Vec<u32> = version
        .split_whitespace()
        .nth(1)
        .unwrap_or("")
        .split('.')
        .filter_map(|part| part.parse().ok())
        .collect();
    // MASQUE появился в Xray v26.10.10; старый бинарник честно не знает протокола.
    if release < vec![26, 10, 10] {
        eprintln!("пропуск: «{version}» старше v26.10.10 — MASQUE ему неизвестен");
        return;
    }
    let result = core.check_config(&config_path);
    let _ = std::fs::remove_dir_all(&work);
    result.expect("Xray должен принять MASQUE из JSON-подписки");
}

/// Сервера из публичного списка отсеиваются по тексту ошибки Xray, поэтому её
/// формат проверяется на настоящем бинарнике: новая версия не должна молча
/// вернуть нас к «один плохой сервер лишает связи все остальные».
#[test]
fn xray_names_the_outbound_it_refuses() {
    let Some(exe) = xray_binary() else {
        eprintln!("пропуск: бинарник Xray не найден (запустите npm run fetch-core)");
        return;
    };
    let work = std::env::temp_dir().join("aurora-xray-rejected");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();

    let node = |id: &str, public_key: &str| ServerNode {
        id: id.into(),
        protocol: Protocol::Vless,
        network: crate::model::Network::Xhttp,
        security: Security::Reality,
        address: "192.0.2.14".into(),
        port: 443,
        uuid: "9deed72d-8f4a-42f8-8c22-ee0d5f6ed6c2".into(),
        sni: "www.example.test".into(),
        public_key: public_key.into(),
        ..Default::default()
    };
    let good = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let nodes = vec![node("good", good), node("bad", "не-ключ")];

    let built = crate::core::xray::build(&nodes, 24_150, "warning")
        .unwrap()
        .unwrap();
    let config_path = work.join("xray.json");
    std::fs::write(&config_path, serde_json::to_vec_pretty(&built.json).unwrap()).unwrap();

    let core = CoreSupervisor::new(Engine::Xray, exe, work.clone());
    let refused = core.check_config(&config_path).unwrap_err().to_string();

    let kept = vec![nodes[0].clone()];
    let rebuilt = crate::core::xray::build(&kept, 24_150, "warning")
        .unwrap()
        .unwrap();
    std::fs::write(&config_path, serde_json::to_vec_pretty(&rebuilt.json).unwrap()).unwrap();
    let retried = core.check_config(&config_path);
    let _ = std::fs::remove_dir_all(&work);

    assert_eq!(built.rejected_node(&refused), Some("bad"), "{refused}");
    retried.expect("без отвергнутого узла Xray должен принять остальные");
}

/// Встроенный движок через тот же супервизор: документ от настоящего генератора,
/// управление по Clash API, журнал через обратный вызов, повторный запуск в том же
/// процессе — ровно то, что делает переподключение. TUN здесь нет: нужны права.
#[tokio::test(flavor = "multi_thread")]
async fn the_embedded_engine_restarts_inside_the_process() {
    const CLASH: u16 = 19_291;
    const MIXED: u16 = 12_180;

    let work = std::env::temp_dir().join("aurora-embedded-lifecycle");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();

    let nodes = sample_nodes();
    let settings = Settings {
        tunnel_mode: TunnelMode::SystemProxy,
        clash_port: CLASH,
        mixed_port: MIXED,
        ..Default::default()
    };
    let split = SplitConfig::default();
    let built = config::build(&BuildInput {
        nodes: &nodes,
        active_id: "n2",
        settings: &settings,
        split: &split,
        clash_secret: "test-secret",
        cache_path: &work.join("cache.db"),
        xray_ports: &no_xray(),
        xray_exe: None,
        rule_sets: &no_sets(),
        rule_set_dir: &work.join("rulesets"),
        warp_chain: None,
    })
    .expect("конфигурация должна собираться");
    let config_path = work.join("config.json");
    std::fs::write(&config_path, serde_json::to_vec_pretty(&built.json).unwrap()).unwrap();

    // Файл sing-box супервизору для этого ядра не нужен.
    let mut core = CoreSupervisor::new(Engine::SingBox, PathBuf::from("нет-такого-файла"), work.clone());
    core.use_engine(Engine::Aura, None);
    assert!(core.version().unwrap().starts_with("aura-engine"));
    core.check_config(&config_path).expect("движок должен принять сгенерированный конфиг");

    let captured: Arc<parking_lot::Mutex<Vec<String>>> = Arc::default();
    for round in 0..2 {
        let sink = Arc::clone(&captured);
        let pid = core
            .start(&config_path, move |line| sink.lock().push(line.text))
            .expect("движок должен запуститься");
        assert_eq!(pid, std::process::id(), "движок живёт в этом процессе");
        assert!(core.is_running());

        let api = ClashApi::new(CLASH, "test-secret");
        let ready = api.wait_ready(Duration::from_secs(5)).await;
        let selected = api.select(TAG_PROXY, "1-Проверка WebSocket").await;
        let moved = api.set_mode("Global").await;
        let totals = api.totals().await;
        core.stop();

        ready.unwrap_or_else(|e| panic!("круг {round}: {e}"));
        selected.expect("селектор должен переключаться");
        moved.expect("режим должен переключаться");
        assert_eq!(totals.expect("счётчики").connections, 0);
        assert!(!core.is_running());
    }
    assert!(captured.lock().iter().any(|line| line.contains("aura-engine")), "журнал дошёл до приложения");

    // Возврат на sing-box: подпись версии следует за выбором сразу, без подключения.
    core.use_engine(Engine::SingBox, None);
    assert!(!core.version().unwrap_or_default().starts_with("aura-engine"));
    let _ = std::fs::remove_dir_all(&work);
}
