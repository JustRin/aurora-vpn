//! aura-engine — сетевой движок Aurora VPN.
//!
//! Живёт внутри процесса приложения: [`start`] поднимает его, [`Engine::stop`]
//! останавливает, и то и другое можно повторять сколько угодно раз за сеанс. Управление
//! — как у sing-box, через Clash API, поэтому балансировщику всё равно, какое ядро
//! работает. Бинарник `aura-engine` — та же библиотека с командной строкой: для стенда
//! и ручной проверки, приложению он не нужен.

#[macro_use]
mod log;

mod api;
mod common;
mod config;
mod dns;
mod engine;
mod inbound;
mod outbound;
mod probe;
mod procinfo;
mod router;
mod ruleset;
mod sniff;
mod tls;
mod tracker;
mod transport;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Once};
use std::time::Duration;

pub use log::LogSink;

pub const VERSION_LINE: &str = concat!("aura-engine version ", env!("CARGO_PKG_VERSION"));

/// Рабочих потоков столько, сколько реально нужно перекачке, а не по числу ядер:
/// на 24-ядерной машине sing-box держит три с лишним десятка потоков впустую.
const MAX_WORKERS: usize = 4;
const SHUTDOWN_WAIT: Duration = Duration::from_secs(2);

/// Движок один на процесс: адаптер, порты и DNS у него общесистемные.
static ACTIVE: AtomicBool = AtomicBool::new(false);

pub struct Options {
    pub config: PathBuf,
    /// Где лежит wintun.dll; `None` — рядом с исполняемым файлом.
    pub wintun: Option<PathBuf>,
    /// Куда писать журнал; `None` — в stdout.
    pub log: Option<LogSink>,
}

pub struct Engine {
    runtime: Option<tokio::runtime::Runtime>,
    tun: Option<inbound::tun::TunHandle>,
}

/// Проверить конфиг без запуска. `Ok` несёт узлы, ставшие заглушками: документ из-за
/// них не отвергается, но знать о них стоит.
pub fn check(path: &Path) -> Result<Vec<(String, String)>, String> {
    let cfg = config::load(path)?;
    engine::build(&cfg).map(|(_, skipped)| skipped)
}

/// Паника в разборе чужих байтов остаётся внутри задачи соединения — но в журнал
/// попасть обязана, иначе соединение просто молча исчезнет.
fn log_panics() {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            error!("panic", "{info}");
            previous(info);
        }));
    });
}

pub fn start(options: Options) -> Result<Engine, String> {
    if ACTIVE.swap(true, Ordering::AcqRel) {
        return Err("ядро уже запущено".to_string());
    }
    let result = start_inner(options);
    if result.is_err() {
        cleanup();
    }
    result
}

fn start_inner(options: Options) -> Result<Engine, String> {
    log::set_sink(options.log.clone());
    log_panics();

    let cfg = config::load(&options.config)?;
    if !cfg.log.level.is_empty() {
        log::set_level(&cfg.log.level);
    }

    let workers = std::thread::available_parallelism().map_or(2, |n| n.get()).clamp(2, MAX_WORKERS);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .max_blocking_threads(8)
        .thread_name("aura-worker")
        .thread_keep_alive(Duration::from_secs(10))
        .enable_all()
        .build()
        .map_err(|e| format!("рантайм: {e}"))?;

    // Отдельный поток: приложение зовёт нас из своего рантайма, а block_on внутри
    // чужого рантайма запрещён.
    let wintun = options.wintun.clone();
    let booted = std::thread::scope(|scope| {
        scope
            .spawn(|| runtime.block_on(boot(cfg, wintun)))
            .join()
            .unwrap_or_else(|_| Err("паника при запуске ядра".to_string()))
    });
    match booted {
        Ok(tun) => {
            info!("main", "{VERSION_LINE} запущен");
            Ok(Engine { runtime: Some(runtime), tun })
        }
        Err(e) => {
            shutdown_runtime(runtime);
            Err(e)
        }
    }
}

async fn boot(cfg: config::Config, wintun: Option<PathBuf>) -> Result<Option<inbound::tun::TunHandle>, String> {
    let (ctx, skipped) = engine::build(&cfg)?;
    for (tag, reason) in &skipped {
        warn!("outbound", "{tag}: {reason}");
    }
    engine::install(ctx.clone());

    if !cfg.experimental.clash_api.external_controller.is_empty() {
        let api = &cfg.experimental.clash_api;
        api::serve(api.external_controller.clone(), api.secret.clone(), ctx.clone())
            .await
            .map_err(|e| format!("clash-api {}: {e}", api.external_controller))?;
    }

    let mut tun = None;
    for inbound in &cfg.inbounds {
        match inbound.kind.as_str() {
            "mixed" | "socks" | "http" => {
                inbound::mixed::serve(inbound, ctx.clone())
                    .await
                    .map_err(|e| format!("{} :{}: {e}", inbound.kind, inbound.listen_port))?;
            }
            "tun" => {
                let handle = inbound::tun::start(inbound, ctx.clone(), cfg.route.auto_detect_interface, wintun.as_deref())
                    .await
                    .map_err(|e| format!("tun: {e}"))?;
                tun = Some(handle);
            }
            other => warn!("inbound", "вход {other} не поддержан, пропускаю"),
        }
    }
    Ok(tun)
}

fn shutdown_runtime(runtime: tokio::runtime::Runtime) {
    // Опять отдельный поток: останавливать рантайм из async-кода тоже запрещено.
    let _ = std::thread::spawn(move || runtime.shutdown_timeout(SHUTDOWN_WAIT)).join();
}

fn cleanup() {
    engine::clear();
    common::set_bypass_interface(0, 0);
    log::set_sink(None);
    ACTIVE.store(false, Ordering::Release);
}

impl Engine {
    /// Жив ли движок. Панику рабочих задач рантайм переживает сам, а вот поток чтения
    /// TUN один: без него туннель мёртв, хотя процесс цел.
    pub fn is_alive(&self) -> bool {
        self.tun.as_ref().is_none_or(inbound::tun::TunHandle::is_alive)
    }

    /// Остановить и дождаться: на выходе порты свободны, а адаптера нет в системе.
    pub fn stop(self) {}

    fn shutdown(&mut self) {
        // Порядок важен: разбудить поток чтения, снять задачи, и только потом отдать
        // адаптер — пока на него есть ссылки, система его не удалит.
        let mut tun = self.tun.take();
        if let Some(tun) = tun.as_mut() {
            tun.shutdown();
        }
        if let Some(runtime) = self.runtime.take() {
            shutdown_runtime(runtime);
            drop(tun);
            cleanup();
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Для командной строки и тестов: совпадает ли запрос с набором правил.
pub fn rule_set_matches(file: &Path, queries: &[String]) -> Result<Vec<bool>, String> {
    let set = ruleset::RuleSet::load(file).map_err(|e| format!("{}: {e}", file.display()))?;
    Ok(queries
        .iter()
        .map(|query| match query.parse::<std::net::IpAddr>() {
            Ok(ip) => set.matches(None, Some(ip)),
            Err(_) => set.matches(Some(query), None),
        })
        .collect())
}

/// Журнал в виде функции `(уровень, текст)`.
pub fn log_sink(f: impl Fn(&str, &str) + Send + Sync + 'static) -> LogSink {
    Arc::new(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Движок один на процесс, а тесты идут параллельно.
    static SERIAL: parking_lot::Mutex<()> = parking_lot::const_mutex(());

    fn config_file(dir: &Path, api_port: u16, mixed_port: u16) -> PathBuf {
        let path = dir.join(format!("cfg-{api_port}.json"));
        let body = serde_json::json!({
            "log": {"level": "info"},
            "dns": {"servers": [{"type": "udp", "tag": "d", "server": "127.0.0.1"}], "final": "d"},
            "inbounds": [{"type": "mixed", "tag": "m", "listen": "127.0.0.1", "listen_port": mixed_port}],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": "direct"},
            "experimental": {"clash_api": {"external_controller": format!("127.0.0.1:{api_port}"), "secret": "s"}},
        });
        std::fs::write(&path, body.to_string()).unwrap();
        path
    }

    /// В одном процессе: ядро запускается, не пускает второе, отпускает порты при
    /// остановке и запускается снова — ровно то, что делает переподключение.
    #[test]
    fn restarts_in_one_process_and_frees_its_ports() {
        let _serial = SERIAL.lock();
        let dir = std::env::temp_dir().join(format!("aura-lib-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = config_file(&dir, 39191, 39192);
        let options = || Options { config: cfg.clone(), wintun: None, log: Some(log_sink(|_, _| {})) };

        for _ in 0..3 {
            let engine = start(options()).expect("запуск");
            assert!(engine.is_alive());
            std::net::TcpStream::connect("127.0.0.1:39191").expect("Clash API слушает");
            std::net::TcpStream::connect("127.0.0.1:39192").expect("mixed слушает");
            assert!(start(options()).is_err(), "второе ядро в процессе");
            // Переподключение ждёт этой остановки, пока пользователь смотрит на экран.
            let stopping = std::time::Instant::now();
            engine.stop();
            assert!(stopping.elapsed() < Duration::from_secs(1), "{:?}", stopping.elapsed());
            assert!(std::net::TcpStream::connect("127.0.0.1:39192").is_err(), "порт освобождён");
        }

        // Неудачный запуск не оставляет процесс в состоянии «уже запущено».
        let missing = Options { config: dir.join("нет.json"), wintun: None, log: None };
        assert!(start(missing).is_err());
        let engine = start(options()).expect("запуск после ошибки");
        engine.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Запуск из async-кода: так его зовёт приложение.
    #[test]
    fn starts_and_stops_from_inside_another_runtime() {
        let _serial = SERIAL.lock();
        let dir = std::env::temp_dir().join(format!("aura-lib-test2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = config_file(&dir, 39193, 39194);
        let host = tokio::runtime::Builder::new_multi_thread().worker_threads(1).build().unwrap();
        host.block_on(async {
            let options = Options { config: cfg.clone(), wintun: None, log: Some(log_sink(|_, _| {})) };
            start(options).expect("запуск").stop();
        });
        let _ = std::fs::remove_dir_all(&dir);
    }
}
