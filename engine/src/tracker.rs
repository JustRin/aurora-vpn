//! Учёт соединений и трафика: то, что читает `/connections` Clash API.
//!
//! Счётчики — на атомиках: запись в них идёт на каждый кусок данных, а сериализация
//! списка нужна только когда приложение спрашивает.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;

use crate::router::Meta;

pub struct ConnInfo {
    pub id: u64,
    pub meta: Value,
    pub chains: Vec<String>,
    pub rule: String,
    pub start: u64,
    pub up: AtomicU64,
    pub down: AtomicU64,
    pub cancel: Notify,
}

#[derive(Default)]
pub struct Tracker {
    next_id: AtomicU64,
    conns: Mutex<HashMap<u64, Arc<ConnInfo>>>,
    pub up_total: AtomicU64,
    pub down_total: AtomicU64,
}

pub struct ConnGuard {
    tracker: Arc<Tracker>,
    pub info: Arc<ConnInfo>,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.tracker.conns.lock().remove(&self.info.id);
    }
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
                t.ip().map(|ip| ip.to_string()).unwrap_or_default(),
                t.port,
            ),
            None => (String::new(), String::new(), 0),
        };
        let (src_ip, src_port) = meta.source.map(|s| (s.ip().to_string(), s.port())).unwrap_or_default();
        let process = meta.process.as_ref().and_then(Option::as_ref).map(|p| p.path.clone()).unwrap_or_default();
        let info = Arc::new(ConnInfo {
            id,
            meta: json!({
                "network": meta.network,
                "type": "tun",
                "sourceIP": src_ip,
                "sourcePort": src_port.to_string(),
                "destinationIP": dest_ip,
                "destinationPort": dest_port.to_string(),
                "host": dest_host,
                "processPath": process,
                "dnsMode": "normal",
            }),
            chains,
            rule,
            start: now_secs(),
            up: AtomicU64::new(0),
            down: AtomicU64::new(0),
            cancel: Notify::new(),
        });
        self.conns.lock().insert(id, info.clone());
        ConnGuard { tracker: self.clone(), info }
    }

    pub fn snapshot(&self) -> Value {
        let conns = self.conns.lock();
        let list: Vec<Value> = conns
            .values()
            .map(|c| {
                json!({
                    "id": c.id.to_string(),
                    "metadata": c.meta,
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
            "connectionsCount": self.conns.lock().len(),
        })
    }

    pub fn close_all(&self) {
        for conn in self.conns.lock().values() {
            conn.cancel.notify_one();
        }
    }

    pub fn close(&self, id: u64) -> bool {
        match self.conns.lock().get(&id) {
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
            self.info.down.fetch_add(n, Ordering::Relaxed);
            self.tracker.down_total.fetch_add(n, Ordering::Relaxed);
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = polled {
            self.info.up.fetch_add(n as u64, Ordering::Relaxed);
            self.tracker.up_total.fetch_add(n as u64, Ordering::Relaxed);
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
}
