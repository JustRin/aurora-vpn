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
