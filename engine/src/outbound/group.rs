//! `selector` и `urltest`.
//!
//! urltest у sing-box обходит всех участников каждые три минуты — у пользователя с
//! сотней узлов это постоянный фон из дозвонов. Здесь группа мерит только пока ею
//! действительно пользуются: балансировщик приложения ведёт трафик через селектор
//! на конкретный узел, и обычно urltest молчит совсем.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use parking_lot::RwLock;

use super::Outbound;
use crate::common::{other, BoxStream, Target};
use crate::config::{seconds, OutboundOpts};

pub struct Selector {
    tag: String,
    members: Vec<String>,
    current: RwLock<String>,
}

impl Selector {
    pub fn new(o: &OutboundOpts) -> Self {
        let current = if o.default.is_empty() {
            o.outbounds.first().cloned().unwrap_or_default()
        } else {
            o.default.clone()
        };
        Self { tag: o.tag.clone(), members: o.outbounds.clone(), current: RwLock::new(current) }
    }
}

#[async_trait]
impl Outbound for Selector {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "selector"
    }
    async fn dial(&self, _: &Target) -> io::Result<BoxStream> {
        Err(other("группа не дозванивается сама"))
    }
    fn member(&self) -> Option<String> {
        Some(self.current.read().clone())
    }
    fn members(&self) -> Vec<String> {
        self.members.clone()
    }
    fn select(&self, member: &str) -> Result<(), String> {
        if !self.members.iter().any(|m| m == member) {
            return Err(format!("в группе {} нет {member}", self.tag));
        }
        *self.current.write() = member.to_string();
        Ok(())
    }
}

struct UrlTestState {
    members: Vec<String>,
    url: String,
    interval: Duration,
    idle: Duration,
    tolerance: u32,
    best: RwLock<Option<(String, u32)>>,
    last_used: AtomicU64,
    running: AtomicBool,
    started: Instant,
}

pub struct UrlTest {
    tag: String,
    state: Arc<UrlTestState>,
}

impl UrlTest {
    pub fn new(o: &OutboundOpts) -> Self {
        Self {
            tag: o.tag.clone(),
            state: Arc::new(UrlTestState {
                members: o.outbounds.clone(),
                url: if o.url.is_empty() { "https://www.gstatic.com/generate_204".to_string() } else { o.url.clone() },
                interval: Duration::from_secs(seconds(&o.interval, 180).max(30)),
                idle: Duration::from_secs(seconds(&o.idle_timeout, 1800)),
                tolerance: o.tolerance,
                best: RwLock::new(None),
                last_used: AtomicU64::new(0),
                running: AtomicBool::new(false),
                started: Instant::now(),
            }),
        }
    }
}

impl UrlTestState {
    fn elapsed(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    fn touch(self: &Arc<Self>) {
        self.last_used.store(self.elapsed(), Ordering::Relaxed);
        if self.running.swap(true, Ordering::AcqRel) {
            return;
        }
        let this = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                this.round().await;
                tokio::time::sleep(this.interval).await;
                let idle_for = this.elapsed().saturating_sub(this.last_used.load(Ordering::Relaxed));
                if idle_for > this.idle.as_secs() {
                    this.running.store(false, Ordering::Release);
                    return;
                }
            }
        });
    }

    async fn round(&self) {
        let Some(ctx) = crate::engine::try_global() else { return };
        let mut best: Option<(String, u32)> = None;
        // Кусками: замер на сотню узлов одновременно — это сотня рукопожатий разом.
        for chunk in self.members.chunks(8) {
            let tasks: Vec<_> = chunk
                .iter()
                .map(|tag| {
                    let (ctx, tag, url) = (ctx.clone(), tag.clone(), self.url.clone());
                    tokio::spawn(async move {
                        let delay = crate::probe::delay(&ctx, &tag, &url, 5000).await;
                        (tag, delay)
                    })
                })
                .collect();
            for task in tasks {
                if let Ok((tag, Ok(ms))) = task.await {
                    if best.as_ref().is_none_or(|(_, b)| ms < *b) {
                        best = Some((tag, ms));
                    }
                }
            }
        }
        let mut slot = self.best.write();
        let keep = match (&*slot, &best) {
            (Some((_, old)), Some((_, new))) => *old <= new + self.tolerance,
            _ => false,
        };
        if !keep && best.is_some() {
            *slot = best;
        }
    }
}

#[async_trait]
impl Outbound for UrlTest {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "urltest"
    }
    async fn dial(&self, _: &Target) -> io::Result<BoxStream> {
        Err(other("группа не дозванивается сама"))
    }
    fn member(&self) -> Option<String> {
        self.state.touch();
        self.state
            .best
            .read()
            .as_ref()
            .map(|(tag, _)| tag.clone())
            .or_else(|| self.state.members.first().cloned())
    }
    fn members(&self) -> Vec<String> {
        self.state.members.clone()
    }
}
