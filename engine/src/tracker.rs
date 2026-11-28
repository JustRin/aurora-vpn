//! Учёт соединений и трафика: то, что читает `/connections` Clash API.
//!
//! Счётчики — на атомиках: запись в них идёт на каждый кусок данных, а сериализация
//! списка нужна только когда приложение спрашивает.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use fnv::FnvHashMap;
use parking_lot::Mutex;
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;

use crate::metrics::NetMetrics;
use crate::router::Meta;

pub struct ConnInfo {
    pub id: u64,
    pub network: &'static str,
    pub source: Option<SocketAddr>,
    pub dest_host: String,
    pub dest_ip: Option<IpAddr>,
    pub dest_port: u16,
    pub process: String,
    pub chains: Vec<String>,
    pub is_proxy: bool,
    pub rule: String,
    pub start: u64,
    pub up: AtomicU64,
    pub down: AtomicU64,
    pub cancel: Notify,
}

#[derive(Default, Clone)]
struct ClosedApp {
    down: u64,
    up: u64,
    proxy_down: u64,
    proxy_up: u64,
    total_conns: u64,
    errors: u64,
}

#[derive(Default)]
struct State {
    conns: FnvHashMap<u64, Arc<ConnInfo>>,
    /// Суммы уже закрытых соединений по пути процесса: короткие HTTP-запросы не теряются
    /// между тиками опроса.
    closed_apps: HashMap<String, ClosedApp>,
}

#[derive(Default)]
pub struct Tracker {
    next_id: AtomicU64,
    state: Mutex<State>,
    pub up_total: AtomicU64,
    pub down_total: AtomicU64,
    pub proxy_up_total: AtomicU64,
    pub proxy_down_total: AtomicU64,
    pub direct_up_total: AtomicU64,
    pub direct_down_total: AtomicU64,
    pub metrics: Arc<NetMetrics>,
}

pub struct ConnGuard {
    tracker: Arc<Tracker>,
    pub info: Arc<ConnInfo>,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        let down = self.info.down.load(Ordering::Relaxed);
        let up = self.info.up.load(Ordering::Relaxed);
        let mut state = self.tracker.state.lock();
        state.conns.remove(&self.info.id);
        let entry = state.closed_apps.entry(self.info.process.clone()).or_default();
        entry.down = entry.down.saturating_add(down);
        entry.up = entry.up.saturating_add(up);
        if self.info.is_proxy {
            entry.proxy_down = entry.proxy_down.saturating_add(down);
            entry.proxy_up = entry.proxy_up.saturating_add(up);
        }
        entry.total_conns = entry.total_conns.saturating_add(1);
    }
}

pub fn is_proxy_chains(chains: &[String]) -> bool {
    !matches!(chains.first().map(String::as_str), None | Some("direct") | Some("block"))
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// RFC 3339 в UTC: так `start` отдаёт Clash API.
fn rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let rem = secs % 86_400;
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem / 60 % 60, rem % 60)
}

impl Tracker {
    pub fn open(self: &Arc<Self>, meta: &Meta, chains: Vec<String>, rule: String) -> ConnGuard {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let (dest_host, dest_ip, dest_port) = match &meta.destination {
            Some(t) => (
                t.domain().map(str::to_string).or_else(|| meta.domain.clone()).unwrap_or_default(),
                t.ip(),
                t.port,
            ),
            None => (String::new(), None, 0),
        };
        let process = meta.process.as_ref().and_then(Option::as_ref).map(|p| p.path.clone()).unwrap_or_default();
        let is_proxy = is_proxy_chains(&chains);
        let info = Arc::new(ConnInfo {
            id,
            network: meta.network,
            source: meta.source,
            dest_host,
            dest_ip,
            dest_port,
            process,
            chains,
            is_proxy,
            rule,
            start: now_secs(),
            up: AtomicU64::new(0),
            down: AtomicU64::new(0),
            cancel: Notify::new(),
        });
        self.state.lock().conns.insert(id, info.clone());
        ConnGuard { tracker: self.clone(), info }
    }

    #[inline]
    pub fn add_down(&self, info: &ConnInfo, n: u64) {
        if n == 0 {
            return;
        }
        info.down.fetch_add(n, Ordering::Relaxed);
        self.down_total.fetch_add(n, Ordering::Relaxed);
        if info.is_proxy {
            self.proxy_down_total.fetch_add(n, Ordering::Relaxed);
        } else {
            self.direct_down_total.fetch_add(n, Ordering::Relaxed);
        }
    }

    #[inline]
    pub fn add_up(&self, info: &ConnInfo, n: u64) {
        if n == 0 {
            return;
        }
        info.up.fetch_add(n, Ordering::Relaxed);
        self.up_total.fetch_add(n, Ordering::Relaxed);
        if info.is_proxy {
            self.proxy_up_total.fetch_add(n, Ordering::Relaxed);
        } else {
            self.direct_up_total.fetch_add(n, Ordering::Relaxed);
        }
    }

    pub fn record_dial_fail(&self, process: &str) {
        self.metrics.dial_fail.fetch_add(1, Ordering::Relaxed);
        let mut state = self.state.lock();
        let entry = state.closed_apps.entry(process.to_string()).or_default();
        entry.errors = entry.errors.saturating_add(1);
    }

    pub fn record_relay_error(&self, process: &str) {
        self.metrics.relay_errors.fetch_add(1, Ordering::Relaxed);
        let mut state = self.state.lock();
        let entry = state.closed_apps.entry(process.to_string()).or_default();
        entry.errors = entry.errors.saturating_add(1);
    }

    pub fn snapshot(&self) -> Value {
        // Снимаем ссылки под замком, а JSON собираем уже без него, чтобы
        // опрос `/connections` не задерживал открытие и закрытие соединений.
        let snapshot: Vec<Arc<ConnInfo>> = self.state.lock().conns.values().cloned().collect();
        let list: Vec<Value> = snapshot
            .iter()
            .map(|c| {
                let (src_ip, src_port) = c.source.map(|s| (s.ip().to_string(), s.port())).unwrap_or_default();
                let dest_ip = c.dest_ip.map(|ip| ip.to_string()).unwrap_or_default();
                json!({
                    "id": c.id.to_string(),
                    "metadata": {
                        "network": c.network,
                        "type": "tun",
                        "sourceIP": src_ip,
                        "sourcePort": src_port.to_string(),
                        "destinationIP": dest_ip,
                        "destinationPort": c.dest_port.to_string(),
                        "host": c.dest_host,
                        "processPath": c.process,
                        "dnsMode": "normal",
                    },
                    "upload": c.up.load(Ordering::Relaxed),
                    "download": c.down.load(Ordering::Relaxed),
                    "start": rfc3339(c.start),
                    "chains": c.chains,
                    "rule": c.rule,
                    "rulePayload": "",
                })
            })
            .collect();
        json!({
            "downloadTotal": self.down_total.load(Ordering::Relaxed),
            "uploadTotal": self.up_total.load(Ordering::Relaxed),
            "connections": list,
            "memory": 0,
        })
    }

    /// Счётчики без списка: для опроса раз в секунду большего не нужно.
    pub fn totals(&self) -> Value {
        json!({
            "downloadTotal": self.down_total.load(Ordering::Relaxed),
            "uploadTotal": self.up_total.load(Ordering::Relaxed),
            "connectionsCount": self.state.lock().conns.len(),
        })
    }

    /// Полная монотонная телеметрия для расширенной статистики: итоги, транспортные
    /// счётчики потерь/ретрансмитов и накопленный трафик каждого приложения (включая
    /// уже закрывшиеся соединения).
    pub fn telemetry(&self) -> Value {
        struct AppAccum {
            down: u64,
            up: u64,
            proxy_down: u64,
            proxy_up: u64,
            active_conns: u32,
            total_conns: u64,
            errors: u64,
        }

        let (apps, active_total) = {
            let state = self.state.lock();
            let mut apps: HashMap<String, AppAccum> = HashMap::with_capacity(state.closed_apps.len() + 8);
            for (path, closed) in &state.closed_apps {
                apps.insert(
                    path.clone(),
                    AppAccum {
                        down: closed.down,
                        up: closed.up,
                        proxy_down: closed.proxy_down,
                        proxy_up: closed.proxy_up,
                        active_conns: 0,
                        total_conns: closed.total_conns,
                        errors: closed.errors,
                    },
                );
            }
            for c in state.conns.values() {
                let down = c.down.load(Ordering::Relaxed);
                let up = c.up.load(Ordering::Relaxed);
                let entry = apps.entry(c.process.clone()).or_insert(AppAccum {
                    down: 0,
                    up: 0,
                    proxy_down: 0,
                    proxy_up: 0,
                    active_conns: 0,
                    total_conns: 0,
                    errors: 0,
                });
                entry.down = entry.down.saturating_add(down);
                entry.up = entry.up.saturating_add(up);
                if c.is_proxy {
                    entry.proxy_down = entry.proxy_down.saturating_add(down);
                    entry.proxy_up = entry.proxy_up.saturating_add(up);
                }
                entry.active_conns = entry.active_conns.saturating_add(1);
                entry.total_conns = entry.total_conns.saturating_add(1);
            }
            (apps, state.conns.len())
        };

        let apps_json: Vec<Value> = apps
            .into_iter()
            .filter(|(_, a)| a.down > 0 || a.up > 0 || a.active_conns > 0 || a.errors > 0)
            .map(|(path, a)| {
                json!({
                    "path": path,
                    "down": a.down,
                    "up": a.up,
                    "proxyDown": a.proxy_down,
                    "proxyUp": a.proxy_up,
                    "activeConns": a.active_conns,
                    "totalConns": a.total_conns,
                    "errors": a.errors,
                })
            })
            .collect();

        json!({
            "downloadTotal": self.down_total.load(Ordering::Relaxed),
            "uploadTotal": self.up_total.load(Ordering::Relaxed),
            "proxyDownloadTotal": self.proxy_down_total.load(Ordering::Relaxed),
            "proxyUploadTotal": self.proxy_up_total.load(Ordering::Relaxed),
            "directDownloadTotal": self.direct_down_total.load(Ordering::Relaxed),
            "directUploadTotal": self.direct_up_total.load(Ordering::Relaxed),
            "connectionsCount": active_total,
            "network": self.metrics.snapshot(),
            "apps": apps_json,
        })
    }

    pub fn close_all(&self) {
        for conn in self.state.lock().conns.values() {
            conn.cancel.notify_one();
        }
    }

    pub fn close(&self, id: u64) -> bool {
        match self.state.lock().conns.get(&id) {
            Some(conn) => {
                conn.cancel.notify_one();
                true
            }
            None => false,
        }
    }
}

/// Поток со счётчиками. `read` — с точки зрения удалённой стороны: прочитанное у
/// неё — это download клиента.
pub struct Counted<S> {
    pub inner: S,
    pub tracker: Arc<Tracker>,
    pub info: Arc<ConnInfo>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        let n = (buf.filled().len() - before) as u64;
        if n > 0 {
            self.tracker.add_down(&self.info, n);
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = polled {
            self.tracker.add_up(&self.info, n as u64);
        }
        polled
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_793_491_200), "2026-11-01T00:00:00Z");
    }

    #[test]
    fn closing_forgets_the_connection() {
        let tracker = Arc::new(Tracker::default());
        let guard = tracker.open(&Meta::default(), vec!["direct".into()], String::new());
        let snap = tracker.snapshot();
        assert_eq!(snap["connections"].as_array().unwrap().len(), 1);
        assert_eq!(snap["connections"][0]["chains"][0], "direct");
        drop(guard);
        assert_eq!(tracker.snapshot()["connections"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn telemetry_preserves_closed_app_traffic_and_proxy_split() {
        let tracker = Arc::new(Tracker::default());
        let meta = Meta {
            network: "tcp",
            process: Some(Some(crate::procinfo::Process {
                name_lower: "chrome.exe".into(),
                path_lower: r"c:\chrome.exe".into(),
                path: r"C:\chrome.exe".into(),
            })),
            ..Default::default()
        };
        let g1 = tracker.open(&meta, vec!["node-1".into(), "proxy".into()], "final".into());
        tracker.add_down(&g1.info, 1000);
        tracker.add_up(&g1.info, 250);
        drop(g1);

        let g2 = tracker.open(&meta, vec!["direct".into()], "rule#1".into());
        tracker.add_down(&g2.info, 400);
        tracker.add_up(&g2.info, 100);
        tracker.record_dial_fail(r"C:\chrome.exe");

        let t = tracker.telemetry();
        assert_eq!(t["downloadTotal"], 1400);
        assert_eq!(t["uploadTotal"], 350);
        assert_eq!(t["proxyDownloadTotal"], 1000);
        assert_eq!(t["directDownloadTotal"], 400);
        assert_eq!(t["connectionsCount"], 1);
        assert_eq!(t["network"]["dialFail"], 1);

        let apps = t["apps"].as_array().unwrap();
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0]["path"], r"C:\chrome.exe");
        assert_eq!(apps[0]["down"], 1400);
        assert_eq!(apps[0]["up"], 350);
        assert_eq!(apps[0]["proxyDown"], 1000);
        assert_eq!(apps[0]["proxyUp"], 250);
        assert_eq!(apps[0]["activeConns"], 1);
        assert_eq!(apps[0]["totalConns"], 2);
        assert_eq!(apps[0]["errors"], 1);
    }
}
