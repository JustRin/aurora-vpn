//! Сборка всего вместе и путь соединения: правила → исходящий → перекачка.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use crate::common::{BoxStream, PacketConn, Target};
use crate::config::Config;
use crate::dns::Dns;
use crate::outbound::Outbounds;
use crate::router::{load_rule_sets, Action, Decision, DnsRules, Meta, Router};
use crate::sniff;
use crate::tracker::{ConnGuard, Counted, Tracker};

/// Хватает на hello и на заголовок HTTP. Клиент, молчащий дольше, — протокол, где
/// первым говорит сервер: ждать его дальше значит заставлять ждать пользователя.
const SNIFF_BYTES: usize = 2048;
const SNIFF_TIMEOUT: Duration = Duration::from_millis(200);
/// Буфер перекачки на направление: память на соединение прямо зависит от него.
const RELAY_BUF: usize = 16 * 1024;
const FIRST_DATA_BYTES: usize = 4096;
const FIRST_DATA_WAIT: Duration = Duration::from_millis(20);

pub struct Context {
    pub outbounds: Outbounds,
    pub router: Router,
    pub dns: Arc<Dns>,
    pub tracker: Arc<Tracker>,
    pub mode: Arc<RwLock<String>>,
}

/// Текущий контекст: движок перезапускается в одном процессе, поэтому не OnceLock.
static GLOBAL: RwLock<Option<Arc<Context>>> = parking_lot::const_rwlock(None);

pub fn try_global() -> Option<Arc<Context>> {
    GLOBAL.read().clone()
}

/// Строит контекст. Предупреждения о заглушках идут отдельным списком: `check` их
/// показывает, но конфиг из-за них не отвергает.
pub fn build(cfg: &Config) -> Result<(Arc<Context>, Vec<(String, String)>), String> {
    let (outbounds, skipped) = Outbounds::build(&cfg.outbounds, &cfg.endpoints);

    let default_mode = &cfg.experimental.clash_api.default_mode;
    let mode = Arc::new(RwLock::new(if default_mode.is_empty() { "Rule".to_string() } else { default_mode.clone() }));

    let sets: HashMap<_, _> = load_rule_sets(&cfg.route);
    let router = Router::new(&cfg.route, &sets, mode.clone());
    let dns_rules = DnsRules::new(&cfg.dns.rules, &sets, mode.clone());

    // У sing-box это либо тег, либо объект с полем `server`.
    let resolver = match &cfg.route.default_domain_resolver {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Object(o) => o.get("server").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
        _ => String::new(),
    };
    let dns = Arc::new(Dns::new(&cfg.dns, &resolver, dns_rules)?);

    Ok((
        Arc::new(Context { outbounds, router, dns, tracker: Arc::new(Tracker::default()), mode }),
        skipped,
    ))
}

pub fn install(ctx: Arc<Context>) {
    crate::dns::set_global(Some(ctx.dns.clone()));
    *GLOBAL.write() = Some(ctx);
}

pub fn clear() {
    crate::dns::set_global(None);
    *GLOBAL.write() = None;
}

/// Подсмотреть начало потока. Прочитанное остаётся в `prefix` и уйдёт на сервер.
pub async fn sniff_stream<R: AsyncRead + Unpin>(stream: &mut R, meta: &mut Meta, prefix: &mut Vec<u8>) {
    let mut buf = vec![0u8; SNIFF_BYTES];
    let Ok(Ok(n)) = tokio::time::timeout(SNIFF_TIMEOUT, stream.read(&mut buf)).await else {
        return;
    };
    buf.truncate(n);
    let found = sniff::tls(&buf).or_else(|| sniff::http(&buf));
    if let Some(found) = found {
        meta.protocol = Some(found.protocol);
        if meta.domain.is_none() {
            meta.domain = found.domain;
        }
    }
    *prefix = buf;
}

pub fn sniff_packet(data: &[u8], meta: &mut Meta) {
    let port = meta.destination.as_ref().map_or(0, |d| d.port);
    let found = if port == 53 {
        sniff::dns(data)
    } else {
        sniff::quic(data).or_else(|| sniff::dns(data).filter(|_| port == 5353))
    };
    if let Some(found) = found {
        meta.protocol = Some(found.protocol);
        if meta.domain.is_none() {
            meta.domain = found.domain;
        }
    }
}

impl Context {
    /// `resolve`: подставить адрес для IP-правил, сам адрес назначения не трогая —
    /// имя должно дойти до прокси именем.
    async fn resolve_step(&self, meta: &mut Meta) {
        let Some(domain) = meta.destination.as_ref().and_then(Target::domain).map(str::to_string) else {
            return;
        };
        if let Ok(addrs) = crate::dns::resolve_direct(&domain, 0).await {
            if let Some(addr) = addrs.first() {
                meta.resolved_ip = Some(addr.ip());
            }
        }
    }

    /// TCP целиком: правила, дозвон, перекачка. `prefix` — уже прочитанное.
    pub async fn handle_tcp(self: Arc<Self>, mut client: BoxStream, mut meta: Meta, need_sniff: bool) {
        let mut prefix = Vec::new();
        let mut from = 0;
        let mut sniffed = false;

        let (tag, rule) = loop {
            match self.router.next(&mut meta, from).await {
                Decision::Final(tag) => break (tag, "final".to_string()),
                Decision::Step(action, next) => {
                    from = next;
                    match action {
                        Action::Sniff => {
                            if need_sniff && !sniffed {
                                sniffed = true;
                                sniff_stream(&mut client, &mut meta, &mut prefix).await;
                            }
                        }
                        Action::Resolve => self.resolve_step(&mut meta).await,
                        Action::Route(tag) => break (tag, format!("rule#{next}")),
                        Action::Reject => {
                            crate::debug!("router", "{}: отклонено правилом", show(&meta));
                            return;
                        }
                        Action::HijackDns => {
                            self.dns_over_tcp(client, meta, prefix).await;
                            return;
                        }
                    }
                }
            }
        };

        let Some((leaf, chains)) = self.outbounds.leaf(&tag) else {
            crate::warn!("router", "исходящего {tag} нет в конфиге");
            return;
        };
        let target = self.dial_target(&meta);
        let Some(target) = target else {
            crate::debug!("router", "нет адреса назначения");
            return;
        };

        let guard = self.tracker.open(&meta, chains, rule);
        crate::debug!("router", "tcp {target} → {tag}");
        match leaf.dial(&target).await {
            Ok(remote) => relay(client, remote, prefix, guard, self.tracker.clone()).await,
            Err(e) => crate::debug!("outbound", "{target} через {tag}: {e}"),
        }
    }

    /// Куда дозваниваться: fakeip разворачивается в имя, обычный IP остаётся IP.
    pub fn dial_target(&self, meta: &Meta) -> Option<Target> {
        let dest = meta.destination.as_ref()?;
        if let Some(ip) = dest.ip() {
            if let Some(name) = self.dns.fake_lookup(ip) {
                return Some(Target::new(&name, dest.port));
            }
        }
        Some(dest.clone())
    }

    async fn dns_over_tcp(&self, mut client: BoxStream, mut meta: Meta, prefix: Vec<u8>) {
        let mut pending = prefix;
        loop {
            while pending.len() < 2 {
                let mut chunk = [0u8; 2048];
                match client.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => pending.extend_from_slice(&chunk[..n]),
                }
            }
            let len = usize::from(pending[0]) << 8 | usize::from(pending[1]);
            while pending.len() < 2 + len {
                let mut chunk = [0u8; 2048];
                match client.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => pending.extend_from_slice(&chunk[..n]),
                }
            }
            let reply = self.dns.handle_query(&pending[2..2 + len], &mut meta).await;
            pending.drain(..2 + len);
            let mut frame = Vec::with_capacity(reply.len() + 2);
            frame.extend_from_slice(&(reply.len() as u16).to_be_bytes());
            frame.extend_from_slice(&reply);
            if client.write_all(&frame).await.is_err() {
                return;
            }
        }
    }
}

pub fn show(meta: &Meta) -> String {
    meta.destination.as_ref().map(ToString::to_string).unwrap_or_default()
}

pub async fn relay(mut client: BoxStream, remote: BoxStream, mut prefix: Vec<u8>, guard: ConnGuard, tracker: Arc<Tracker>) {
    // Заголовок протокола должен уйти одним куском с первыми данными: короткий пакет
    // с одним заголовком легко распознать по длине. Обычно данные уже лежат в сокете —
    // пока шёл дозвон, клиент успел их отправить. Ждём только тех, кто молчит: это
    // протоколы, где первым говорит сервер.
    if prefix.is_empty() {
        let mut first = vec![0u8; FIRST_DATA_BYTES];
        match tokio::time::timeout(FIRST_DATA_WAIT, client.read(&mut first)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return,
            Ok(Ok(n)) => {
                first.truncate(n);
                prefix = first;
            }
            Err(_) => {}
        }
    }
    let mut remote = Counted { inner: remote, tracker, info: guard.info.clone() };
    if !prefix.is_empty() {
        // Без flush сброс произошёл бы только после следующих данных клиента.
        if remote.write_all(&prefix).await.is_err() || remote.flush().await.is_err() {
            return;
        }
    }
    // Иначе эти килобайты пролежат мёртвым грузом всю жизнь соединения.
    drop(prefix);
    let copy = tokio::io::copy_bidirectional_with_sizes(&mut client, &mut remote, RELAY_BUF, RELAY_BUF);
    tokio::select! {
        result = copy => {
            if let Err(e) = result {
                if !is_churn(&e) {
                    crate::debug!("relay", "{e}");
                }
            }
        }
        _ = guard.info.cancel.notified() => {}
    }
}

/// Обычное завершение: вкладку закрыли, сервер оборвал простаивающее соединение.
fn is_churn(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted | io::ErrorKind::BrokenPipe | io::ErrorKind::UnexpectedEof
    )
}

pub struct UdpRoute {
    pub conn: Arc<dyn PacketConn>,
    pub guard: ConnGuard,
}

impl Context {
    /// Открыть UDP-сессию по первому пакету.
    pub async fn open_udp(&self, first: &[u8], meta: &mut Meta) -> UdpOpen {
        sniff_packet(first, meta);
        let mut from = 0;
        let (tag, rule) = loop {
            match self.router.next(meta, from).await {
                Decision::Final(tag) => break (tag, "final".to_string()),
                Decision::Step(action, next) => {
                    from = next;
                    match action {
                        Action::Sniff => {} // уже подсмотрели
                        Action::Resolve => self.resolve_step(meta).await,
                        Action::Route(tag) => break (tag, format!("rule#{next}")),
                        Action::Reject => return UdpOpen::Reject,
                        Action::HijackDns => return UdpOpen::Dns,
                    }
                }
            }
        };
        let Some((leaf, chains)) = self.outbounds.leaf(&tag) else {
            return UdpOpen::Reject;
        };
        let Some(target) = self.dial_target(meta) else {
            return UdpOpen::Reject;
        };
        match leaf.dial_udp(&target).await {
            Ok(conn) => {
                let guard = self.tracker.open(meta, chains, rule);
                UdpOpen::Session(UdpRoute { conn: Arc::from(conn), guard })
            }
            Err(e) => {
                crate::debug!("outbound", "udp {target} через {tag}: {e}");
                UdpOpen::Reject
            }
        }
    }
}

pub enum UdpOpen {
    Session(UdpRoute),
    Dns,
    Reject,
}
