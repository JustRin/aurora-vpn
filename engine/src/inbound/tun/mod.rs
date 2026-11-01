//! TUN: общая часть для всех платформ.
//!
//! - TCP не покидает ядро ОС: пакеты только переписываются (см. `nat`), а данные
//!   приходят на обычный сокет слушателя. Пользовательского TCP-стека нет вовсе —
//!   это и есть главная экономия против gVisor в sing-box;
//! - UDP разбирается здесь же: одна сессия на пару адресов, ответы собираются вручную.
//!
//! От платформы нужно только устройство ([`Device`]) и настройка маршрутов. Сейчас
//! реализована одна — Windows (`windows`); на остальных `start` честно отказывает, и
//! там по-прежнему работают sing-box и libbox.

#![cfg_attr(not(windows), allow(dead_code))]

mod nat;
pub mod packet;
#[cfg(windows)]
mod windows;

use std::any::Any;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::common::{BoxStream, Target};
use crate::config::InboundOpts;
use crate::engine::{Context, UdpOpen};
use crate::router::Meta;

use nat::Nat;
use packet::{Parsed, PROTO_TCP, PROTO_UDP, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN};

const UDP_IDLE: Duration = Duration::from_secs(60);
const UDP_QUEUE: usize = 1024;
const SESSION_QUEUE: usize = 64;

/// Виртуальный адаптер платформы. Вызовы идут на каждый пакет, поэтому и приём, и
/// отправка работают прямо с буфером устройства, без лишних копий.
pub trait Device: Send + Sync + 'static {
    /// Дождаться пакета и отдать его в `handle`. `Ok(false)` — устройство закрывают.
    fn recv(&self, handle: &mut dyn FnMut(&[u8])) -> io::Result<bool>;
    /// Заполнить и отправить пакет. Нет места — пакет теряется: TCP перепошлёт сам,
    /// а для UDP это штатно.
    fn send(&self, len: u16, fill: &mut dyn FnMut(&mut [u8]) -> bool);
    /// Разбудить заблокированный `recv`.
    fn shutdown(&self);
}

pub struct Pair<T> {
    pub tun: T,
    pub server: T,
    pub bits: u8,
}

pub fn parse_addresses(list: &[String]) -> (Option<Pair<Ipv4Addr>>, Option<Pair<Ipv6Addr>>) {
    let (mut v4, mut v6) = (None, None);
    for item in list {
        let Some((ip, bits)) = item.split_once('/') else { continue };
        let Ok(bits) = bits.parse::<u8>() else { continue };
        match ip.parse::<IpAddr>() {
            Ok(IpAddr::V4(tun)) => {
                v4 = Some(Pair { tun, server: Ipv4Addr::from(u32::from(tun) + 1), bits });
            }
            Ok(IpAddr::V6(tun)) => {
                v6 = Some(Pair { tun, server: Ipv6Addr::from(u128::from(tun) + 1), bits });
            }
            Err(_) => {}
        }
    }
    (v4, v6)
}

/// Запущенный TUN. Закрытие идёт в два шага: сперва `shutdown`, потом — когда рантайм
/// движка остановлен и задачи отпустили устройство — сброс: система убирает адаптер
/// вместе с маршрутами только после этого.
pub struct TunHandle {
    device: Arc<dyn Device>,
    reader: Option<JoinHandle<()>>,
    /// Что живёт вместе с адаптером на этой платформе (на Windows — фильтры WFP).
    _platform: Box<dyn Any + Send + Sync>,
}

impl TunHandle {
    pub fn is_alive(&self) -> bool {
        self.reader.as_ref().is_some_and(|reader| !reader.is_finished())
    }

    pub fn shutdown(&mut self) {
        self.device.shutdown();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

impl Drop for TunHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(windows)]
pub async fn start(
    opts: &InboundOpts,
    ctx: Arc<Context>,
    auto_detect: bool,
    wintun: Option<&Path>,
) -> Result<TunHandle, String> {
    windows::start(opts, ctx, auto_detect, wintun).await
}

#[cfg(not(windows))]
pub async fn start(_: &InboundOpts, _: Arc<Context>, _: bool, _: Option<&Path>) -> Result<TunHandle, String> {
    Err("TUN на этой платформе пока не реализован".to_string())
}

/// Точки туннеля для одного семейства адресов.
#[derive(Clone, Copy)]
struct Endpoints {
    tun: IpAddr,
    server: IpAddr,
}

#[derive(Clone)]
struct Shared {
    device: Arc<dyn Device>,
    nat: Arc<Nat>,
    v4: Option<Endpoints>,
    v6: Option<Endpoints>,
    listen_v4: u16,
    listen_v6: u16,
    clock: Arc<AtomicU64>,
    udp: mpsc::Sender<UdpMsg>,
}

struct UdpMsg {
    src: SocketAddr,
    dst: SocketAddr,
    data: Vec<u8>,
}

/// Запустить стек поверх готового устройства: адрес на адаптере уже стоит.
pub(crate) async fn run(
    device: Arc<dyn Device>,
    v4: Option<&Pair<Ipv4Addr>>,
    v6: Option<&Pair<Ipv6Addr>>,
    ctx: Arc<Context>,
    platform: Box<dyn Any + Send + Sync>,
) -> Result<TunHandle, String> {
    let bind = |ip: IpAddr| async move {
        // Адрес появляется не сразу: система проверяет его на дубликаты.
        let mut last = None;
        for _ in 0..50 {
            match TcpListener::bind(SocketAddr::new(ip, 0)).await {
                Ok(listener) => return Ok(listener),
                Err(e) => last = Some(e),
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err(format!("слушатель {ip}: {}", last.map(|e| e.to_string()).unwrap_or_default()))
    };

    let (mut listen_v4, mut listen_v6) = (0, 0);
    let nat = Arc::new(Nat::default());
    let clock = Arc::new(AtomicU64::new(0));
    let (udp_tx, udp_rx) = mpsc::channel(UDP_QUEUE);

    let endpoints_v4 = v4.map(|p| Endpoints { tun: p.tun.into(), server: p.server.into() });
    let endpoints_v6 = v6.map(|p| Endpoints { tun: p.tun.into(), server: p.server.into() });

    if let Some(ep) = endpoints_v4 {
        let listener = bind(ep.tun).await?;
        listen_v4 = listener.local_addr().map_err(|e| e.to_string())?.port();
        spawn_accept(listener, nat.clone(), ctx.clone());
    }
    if let Some(ep) = endpoints_v6 {
        let listener = bind(ep.tun).await?;
        listen_v6 = listener.local_addr().map_err(|e| e.to_string())?.port();
        spawn_accept(listener, nat.clone(), ctx.clone());
    }

    let shared = Shared {
        device: device.clone(),
        nat: nat.clone(),
        v4: endpoints_v4,
        v6: endpoints_v6,
        listen_v4,
        listen_v6,
        clock: clock.clone(),
        udp: udp_tx,
    };

    let reader = {
        let shared = shared.clone();
        std::thread::Builder::new()
            .name("aura-tun".to_string())
            .spawn(move || read_loop(shared))
            .map_err(|e| e.to_string())?
    };
    tokio::spawn(udp_dispatch(udp_rx, shared, ctx));
    tokio::spawn(housekeeping(nat, clock));

    crate::info!("tun", "стек поднят, TCP на порту {listen_v4}");
    Ok(TunHandle { device, reader: Some(reader), _platform: platform })
}

fn spawn_accept(listener: TcpListener, nat: Arc<Nat>, ctx: Arc<Context>) {
    tokio::spawn(async move {
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    crate::debug!("tun", "accept: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            let Some(flow) = nat.by_port(peer.port()) else {
                crate::debug!("tun", "соединение от неизвестного порта {}", peer.port());
                continue;
            };
            let ctx = ctx.clone();
            tokio::spawn(async move {
                let _ = stream.set_nodelay(true);
                let target = Target::from_addr(SocketAddr::new(flow.dst, flow.dport));
                let meta = Meta {
                    network: "tcp",
                    source: Some(SocketAddr::new(flow.src, flow.sport)),
                    destination: Some(target),
                    ..Default::default()
                };
                let client: BoxStream = Box::new(stream);
                ctx.handle_tcp(client, meta, true).await;
            });
        }
    });
}

/// Чтение из устройства. Отдельный поток: приём блокирующий, а этот код не должен
/// делить рабочие потоки рантайма с шифрованием.
fn read_loop(shared: Shared) {
    let device = shared.device.clone();
    let mut handle = |bytes: &[u8]| {
        let Some(parsed) = packet::parse(bytes) else { return };
        if parsed.proto == PROTO_TCP {
            handle_tcp_packet(&shared, bytes, &parsed);
        } else if parsed.proto == PROTO_UDP {
            handle_udp_packet(&shared, bytes, &parsed);
        }
    };
    loop {
        match device.recv(&mut handle) {
            Ok(true) => {}
            Ok(false) => return,
            Err(e) => {
                crate::error!("tun", "чтение: {e}");
                return;
            }
        }
    }
}

fn endpoints(shared: &Shared, parsed: &Parsed) -> Option<(Endpoints, u16)> {
    if parsed.src.is_ipv4() {
        shared.v4.map(|ep| (ep, shared.listen_v4))
    } else {
        shared.v6.map(|ep| (ep, shared.listen_v6))
    }
}

fn write_back(shared: &Shared, bytes: &[u8], parsed: &Parsed, src: IpAddr, sport: u16, dst: IpAddr, dport: u16) {
    shared.device.send(bytes.len() as u16, &mut |buf| {
        buf.copy_from_slice(bytes);
        packet::rewrite_tcp(buf, parsed, src, sport, dst, dport)
    });
}

fn handle_tcp_packet(shared: &Shared, bytes: &[u8], parsed: &Parsed) {
    let Some((ep, listen)) = endpoints(shared, parsed) else { return };
    let now = shared.clock.load(Ordering::Relaxed);
    let flags = packet::tcp_flags(bytes, parsed);

    // Ответ ядра со слушателя: развернуть обратно к приложению.
    if parsed.src == ep.tun && parsed.sport == listen && parsed.dst == ep.server {
        let Some(flow) = shared.nat.by_port(parsed.dport) else { return };
        flow.touch(now);
        if flags & (TCP_FIN | TCP_RST) != 0 {
            flow.mark_closing();
        }
        write_back(shared, bytes, parsed, flow.dst, flow.dport, flow.src, flow.sport);
        return;
    }

    let key = (parsed.src, parsed.sport, parsed.dst, parsed.dport);
    let is_syn = flags & TCP_SYN != 0 && flags & TCP_ACK == 0;
    let flow = match shared.nat.lookup(&key) {
        Some(flow) if !(is_syn && flow.is_closing()) => flow,
        _ if is_syn => match shared.nat.create(key, now) {
            Some(flow) => flow,
            None => return,
        },
        // Не SYN без записи в таблице: поток забыт, ядро приложения узнает об этом
        // по молчанию; создавать запись под чужой сегмент нельзя.
        _ => return,
    };
    flow.touch(now);
    if flags & (TCP_FIN | TCP_RST) != 0 {
        flow.mark_closing();
    }
    write_back(shared, bytes, parsed, ep.server, flow.nat_port, ep.tun, listen);
}

fn handle_udp_packet(shared: &Shared, bytes: &[u8], parsed: &Parsed) {
    // Широковещание и мультикаст в туннеле не живут.
    let local_only = match parsed.dst {
        IpAddr::V4(ip) => ip.is_multicast() || ip.is_broadcast(),
        IpAddr::V6(ip) => ip.is_multicast(),
    };
    if local_only {
        return;
    }
    let Some(data) = bytes.get(parsed.l4 + 8..parsed.total) else { return };
    let msg = UdpMsg {
        src: SocketAddr::new(parsed.src, parsed.sport),
        dst: SocketAddr::new(parsed.dst, parsed.dport),
        data: data.to_vec(),
    };
    // Очередь полна — пакет теряется: для UDP это штатно, ждать нельзя.
    let _ = shared.udp.try_send(msg);
}

fn send_udp(device: &Arc<dyn Device>, src: SocketAddr, dst: SocketAddr, payload: &[u8]) {
    if src.is_ipv4() != dst.is_ipv4() {
        return;
    }
    let len = packet::udp_packet_len(src.ip(), payload.len());
    if len > usize::from(u16::MAX) {
        return;
    }
    device.send(len as u16, &mut |buf| {
        packet::write_udp(buf, src.ip(), src.port(), dst.ip(), dst.port(), payload);
        true
    });
}

type UdpKey = (SocketAddr, SocketAddr);

async fn udp_dispatch(mut rx: mpsc::Receiver<UdpMsg>, shared: Shared, ctx: Arc<Context>) {
    let mut sessions: HashMap<UdpKey, mpsc::Sender<Vec<u8>>> = HashMap::new();
    let (done_tx, mut done_rx) = mpsc::unbounded_channel::<UdpKey>();
    loop {
        tokio::select! {
            Some(key) = done_rx.recv() => {
                sessions.remove(&key);
            }
            msg = rx.recv() => {
                let Some(msg) = msg else { return };
                let key = (msg.src, msg.dst);
                if let Some(tx) = sessions.get(&key) {
                    if !tx.is_closed() {
                        let _ = tx.try_send(msg.data);
                        continue;
                    }
                }
                let (tx, session_rx) = mpsc::channel(SESSION_QUEUE);
                sessions.insert(key, tx);
                tokio::spawn(udp_session(key, msg.data, session_rx, shared.device.clone(), ctx.clone(), done_tx.clone()));
            }
        }
    }
}

async fn udp_session(
    key: UdpKey,
    first: Vec<u8>,
    mut rx: mpsc::Receiver<Vec<u8>>,
    device: Arc<dyn Device>,
    ctx: Arc<Context>,
    done: mpsc::UnboundedSender<UdpKey>,
) {
    let (src, dst) = key;
    let target = Target::from_addr(dst);
    let mut meta = Meta {
        network: "udp",
        source: Some(src),
        destination: Some(target.clone()),
        ..Default::default()
    };

    match ctx.open_udp(&first, &mut meta).await {
        UdpOpen::Reject => {}
        UdpOpen::Dns => {
            let reply = ctx.dns.handle_query(&first, &mut meta).await;
            send_udp(&device, dst, src, &reply);
            // Тот же клиентский порт может спросить ещё: ждём недолго.
            while let Ok(Some(query)) = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
                let reply = ctx.dns.handle_query(&query, &mut meta).await;
                send_udp(&device, dst, src, &reply);
            }
        }
        UdpOpen::Session(route) => {
            let conn = route.conn;
            let _guard = route.guard;
            let info = _guard.info.clone();
            let tracker = ctx.tracker.clone();
            let dial_target = ctx.dial_target(&meta).unwrap_or(target);
            let _ = conn.send(&first, &dial_target).await;
            info.up.fetch_add(first.len() as u64, Ordering::Relaxed);
            tracker.up_total.fetch_add(first.len() as u64, Ordering::Relaxed);

            let mut last_seen = Instant::now();
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                tokio::select! {
                    data = rx.recv() => {
                        let Some(data) = data else { break };
                        last_seen = Instant::now();
                        info.up.fetch_add(data.len() as u64, Ordering::Relaxed);
                        tracker.up_total.fetch_add(data.len() as u64, Ordering::Relaxed);
                        if conn.send(&data, &dial_target).await.is_err() {
                            break;
                        }
                    }
                    received = conn.recv(&mut buf) => {
                        let Ok((n, from)) = received else { break };
                        last_seen = Instant::now();
                        info.down.fetch_add(n as u64, Ordering::Relaxed);
                        tracker.down_total.fetch_add(n as u64, Ordering::Relaxed);
                        // Адрес ответа — тот, на который писали: иначе приложение
                        // отбросит «чужой» пакет. Для полноконусного NAT берём from.
                        let reply_src = match from.ip() {
                            Some(ip) if ip.is_ipv4() == src.is_ipv4() && !ip.is_unspecified() => SocketAddr::new(ip, from.port),
                            _ => dst,
                        };
                        send_udp(&device, reply_src, src, &buf[..n]);
                    }
                    _ = tokio::time::sleep_until((last_seen + UDP_IDLE).into()) => break,
                    _ = info.cancel.notified() => break,
                }
            }
        }
    }
    let _ = done.send(key);
}

async fn housekeeping(nat: Arc<Nat>, clock: Arc<AtomicU64>) {
    let started = Instant::now();
    let mut seconds_since_sweep = 0u64;
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        clock.store(started.elapsed().as_secs(), Ordering::Relaxed);
        seconds_since_sweep += 1;
        if seconds_since_sweep >= 30 {
            seconds_since_sweep = 0;
            let removed = nat.sweep(clock.load(Ordering::Relaxed));
            if removed > 0 {
                crate::trace!("tun", "NAT: убрано {removed}, осталось {}", nat.len());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    #[test]
    fn server_address_follows_the_tun_address() {
        let (v4, v6) = parse_addresses(&["172.19.0.1/30".to_string(), "fdfe:dcba:9876::1/126".to_string()]);
        let v4 = v4.unwrap();
        assert_eq!(v4.server, Ipv4Addr::new(172, 19, 0, 2));
        assert_eq!(v4.bits, 30);
        assert_eq!(v6.unwrap().server, "fdfe:dcba:9876::2".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn bad_addresses_are_skipped() {
        let (v4, v6) = parse_addresses(&["nonsense".to_string(), "1.2.3.4".to_string(), "x/30".to_string()]);
        assert!(v4.is_none() && v6.is_none());
    }

    /// Устройство-заглушка: то, что стек отправил, складывается в список.
    #[derive(Default)]
    struct Fake {
        sent: Mutex<Vec<Vec<u8>>>,
    }

    impl Device for Fake {
        fn recv(&self, _: &mut dyn FnMut(&[u8])) -> io::Result<bool> {
            Ok(false)
        }
        fn send(&self, len: u16, fill: &mut dyn FnMut(&mut [u8]) -> bool) {
            let mut buf = vec![0u8; usize::from(len)];
            if fill(&mut buf) {
                self.sent.lock().push(buf);
            }
        }
        fn shutdown(&self) {}
    }

    fn syn(src: &str, sport: u16, dst: &str, dport: u16, flags: u8) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&40u16.to_be_bytes());
        p[9] = PROTO_TCP;
        let (s, d): (Ipv4Addr, Ipv4Addr) = (src.parse().unwrap(), dst.parse().unwrap());
        p[12..16].copy_from_slice(&s.octets());
        p[16..20].copy_from_slice(&d.octets());
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p[32] = 0x50;
        p[33] = flags;
        p
    }

    fn shared_with(device: Arc<dyn Device>) -> Shared {
        Shared {
            device,
            nat: Arc::new(Nat::default()),
            v4: Some(Endpoints { tun: "172.19.0.1".parse().unwrap(), server: "172.19.0.2".parse().unwrap() }),
            v6: None,
            listen_v4: 40000,
            listen_v6: 0,
            clock: Arc::new(AtomicU64::new(0)),
            udp: mpsc::channel(1).0,
        }
    }

    #[test]
    fn a_connection_goes_through_the_nat_and_back() {
        let fake = Arc::new(Fake::default());
        let shared = shared_with(fake.clone());

        // Приложение → сайт: разворачивается к слушателю.
        let out = syn("172.19.0.1", 50000, "1.2.3.4", 443, TCP_SYN);
        handle_tcp_packet(&shared, &out, &packet::parse(&out).unwrap());
        let rewritten = fake.sent.lock().pop().unwrap();
        let there = packet::parse(&rewritten).unwrap();
        assert_eq!(there.dst, "172.19.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(there.dport, 40000);
        assert_eq!(there.src, "172.19.0.2".parse::<IpAddr>().unwrap());
        let nat_port = there.sport;

        // Ответ ядра со слушателя: приложение должно увидеть сайт.
        let back = syn("172.19.0.1", 40000, "172.19.0.2", nat_port, TCP_SYN | TCP_ACK);
        handle_tcp_packet(&shared, &back, &packet::parse(&back).unwrap());
        let reply = fake.sent.lock().pop().unwrap();
        let seen = packet::parse(&reply).unwrap();
        assert_eq!((seen.src, seen.sport), ("1.2.3.4".parse::<IpAddr>().unwrap(), 443));
        assert_eq!((seen.dst, seen.dport), ("172.19.0.1".parse::<IpAddr>().unwrap(), 50000));
    }

    #[test]
    fn a_stray_segment_does_not_create_a_flow() {
        let fake = Arc::new(Fake::default());
        let shared = shared_with(fake.clone());
        let stray = syn("172.19.0.1", 50000, "1.2.3.4", 443, TCP_ACK);
        handle_tcp_packet(&shared, &stray, &packet::parse(&stray).unwrap());
        assert!(fake.sent.lock().is_empty());
        assert_eq!(shared.nat.len(), 0);
    }
}
