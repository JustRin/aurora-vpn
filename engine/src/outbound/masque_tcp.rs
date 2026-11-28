//! Лёгкий клиентский TCP/UDP стек поверх сырых IP-пакетов для туннеля MASQUE (CONNECT-IP).
//!
//! Поддерживает IPv4 и IPv6, TCP-рукопожатие с MSS и Window Scale,
//! переупорядочивание сегментов (out-of-order reassembly), fast retransmit
//! по 3 дублирующим ACK, таймер RTO (Jacobson/Karels), корректное закрытие
//! FIN/RST и UDP-сессии с демультиплексированием по локальному порту.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex as SyncMutex;
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

use crate::common::{other, BoxStream};
use crate::inbound::tun::packet::{
    self, PROTO_TCP, PROTO_UDP, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN,
};

const TCP_PSH: u8 = 0x08;
const LOCAL_WSCALE: u8 = 6; // масштаб ×64 → окно до ~4 МБ
const APP_BUF_SIZE: usize = 256 * 1024;
const MAX_OOO_SEGMENTS: usize = 256;
const MIN_RTO: Duration = Duration::from_millis(150);
const MAX_RTO: Duration = Duration::from_secs(8);
const MAX_RETRIES: u32 = 8;

type TcpFlowKey = (u16, IpAddr, u16);

#[derive(Debug)]
struct TcpSegment {
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    mss: Option<u16>,
    wscale: Option<u8>,
    payload: Vec<u8>,
}

/// Уровень L3→L4 одного живого CONNECT-IP туннеля.
pub struct IpStack {
    pub local_v4: Option<Ipv4Addr>,
    pub local_v6: Option<Ipv6Addr>,
    pub mtu: usize,
    tx_ip: mpsc::Sender<Vec<u8>>,
    tcp_flows: Arc<SyncMutex<HashMap<TcpFlowKey, mpsc::UnboundedSender<TcpSegment>>>>,
    udp_flows: Arc<SyncMutex<HashMap<u16, mpsc::Sender<(SocketAddr, Vec<u8>)>>>>,
    next_port: AtomicU16,
}

impl IpStack {
    pub fn new(
        local_v4: Option<Ipv4Addr>,
        local_v6: Option<Ipv6Addr>,
        mtu: usize,
        tx_ip: mpsc::Sender<Vec<u8>>,
    ) -> Arc<Self> {
        let start_port = rand::thread_rng().gen_range(20_000u16..55_000u16);
        Arc::new(Self {
            local_v4,
            local_v6,
            mtu: mtu.clamp(1280, 1460),
            tx_ip,
            tcp_flows: Arc::new(SyncMutex::new(HashMap::new())),
            udp_flows: Arc::new(SyncMutex::new(HashMap::new())),
            next_port: AtomicU16::new(start_port),
        })
    }

    pub fn local_ip_for(&self, remote: IpAddr) -> Option<IpAddr> {
        match remote {
            IpAddr::V4(_) => self.local_v4.map(IpAddr::V4),
            IpAddr::V6(_) => self.local_v6.map(IpAddr::V6),
        }
    }

    fn alloc_port(&self) -> u16 {
        loop {
            let p = self.next_port.fetch_add(1, Ordering::Relaxed);
            let p = if p < 10_000 { 10_000 + (p % 50_000) } else { p };
            if !self.udp_flows.lock().contains_key(&p) {
                return p;
            }
        }
    }

    /// Обработать входящий сырой IP-пакет из CONNECT-IP туннеля.
    pub fn ingest(&self, pkt: &[u8]) {
        let Some(parsed) = packet::parse(pkt) else { return };
        if parsed.proto == PROTO_UDP {
            let Some(payload) = pkt.get(parsed.l4 + 8..parsed.total) else { return };
            let tx = self.udp_flows.lock().get(&parsed.dport).cloned();
            if let Some(tx) = tx {
                let _ = tx.try_send((SocketAddr::new(parsed.src, parsed.sport), payload.to_vec()));
            }
            return;
        }
        if parsed.proto == PROTO_TCP {
            let Some(seg) = parse_tcp_segment(pkt, &parsed) else { return };
            let key = (parsed.dport, parsed.src, parsed.sport);
            let tx = self.tcp_flows.lock().get(&key).cloned();
            if let Some(tx) = tx {
                let _ = tx.send(seg);
            } else if seg.flags & TCP_RST == 0 {
                // Вежливый RST на неожиданный сегмент закрытого потока.
                let rst_seq = if seg.flags & TCP_ACK != 0 { seg.ack } else { 0 };
                let rst = build_tcp_packet(
                    parsed.dst,
                    parsed.dport,
                    parsed.src,
                    parsed.sport,
                    rst_seq,
                    seg.seq.wrapping_add(seg.payload.len() as u32),
                    TCP_RST | TCP_ACK,
                    0,
                    &[],
                    &[],
                );
                let _ = self.tx_ip.try_send(rst);
            }
        }
    }

    /// Открыть исходящее TCP-соединение через стек туннеля.
    pub async fn dial_tcp(self: &Arc<Self>, remote: SocketAddr) -> io::Result<BoxStream> {
        let local_ip = self
            .local_ip_for(remote.ip())
            .ok_or_else(|| other(format!("masque: туннель не получил адрес семейства {}", remote.ip())))?;
        let local_port = self.alloc_port();
        let key = (local_port, remote.ip(), remote.port());
        let (seg_tx, seg_rx) = mpsc::unbounded_channel();
        self.tcp_flows.lock().insert(key, seg_tx);

        let (app_io, stack_io) = tokio::io::duplex(APP_BUF_SIZE);
        let (ready_tx, ready_rx) = oneshot::channel::<io::Result<()>>();
        let stack = self.clone();
        tokio::spawn(async move {
            run_tcp_conn(stack, key, local_ip, stack_io, seg_rx, ready_tx).await;
        });

        match tokio::time::timeout(crate::common::DIAL_TIMEOUT, ready_rx).await {
            Ok(Ok(Ok(()))) => Ok(Box::new(app_io)),
            Ok(Ok(Err(e))) => Err(e),
            Ok(Err(_)) => Err(other("masque: TCP-соединение прервано")),
            Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "masque: таймаут TCP SYN")),
        }
    }

    /// Зарегистрировать UDP-сокет поверх стека туннеля.
    pub fn open_udp(self: &Arc<Self>) -> MasqueUdpHandle {
        let port = self.alloc_port();
        let (tx, rx) = mpsc::channel(256);
        self.udp_flows.lock().insert(port, tx);
        MasqueUdpHandle { stack: self.clone(), local_port: port, rx: tokio::sync::Mutex::new(rx) }
    }

    pub async fn send_udp_raw(&self, local_port: u16, remote: SocketAddr, payload: &[u8]) -> io::Result<()> {
        let local_ip = self
            .local_ip_for(remote.ip())
            .ok_or_else(|| other(format!("masque: нет адреса для {}", remote.ip())))?;
        let len = packet::udp_packet_len(local_ip, payload.len());
        let mut pkt = vec![0u8; len];
        packet::write_udp(&mut pkt, local_ip, local_port, remote.ip(), remote.port(), payload);
        self.tx_ip
            .send(pkt)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "masque: туннель закрыт"))
    }
}

pub struct MasqueUdpHandle {
    stack: Arc<IpStack>,
    pub local_port: u16,
    rx: tokio::sync::Mutex<mpsc::Receiver<(SocketAddr, Vec<u8>)>>,
}

impl MasqueUdpHandle {
    pub async fn send(&self, remote: SocketAddr, payload: &[u8]) -> io::Result<()> {
        self.stack.send_udp_raw(self.local_port, remote, payload).await
    }

    pub async fn recv(&self) -> io::Result<(SocketAddr, Vec<u8>)> {
        self.rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "masque: UDP закрыт"))
    }
}

impl Drop for MasqueUdpHandle {
    fn drop(&mut self) {
        self.stack.udp_flows.lock().remove(&self.local_port);
    }
}

// ------------------------------------------------------------------ TCP конечный автомат

struct SentSeg {
    seq: u32,
    flags: u8,
    data: Vec<u8>,
    sent_at: Instant,
    retransmits: u32,
}

impl SentSeg {
    fn seq_len(&self) -> u32 {
        let mut n = self.data.len() as u32;
        if self.flags & TCP_SYN != 0 {
            n += 1;
        }
        if self.flags & TCP_FIN != 0 {
            n += 1;
        }
        n
    }

    fn end_seq(&self) -> u32 {
        self.seq.wrapping_add(self.seq_len())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TcpState {
    SynSent,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    LastAck,
    Closed,
}

fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

fn seq_le(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) <= 0
}

async fn run_tcp_conn(
    stack: Arc<IpStack>,
    key: TcpFlowKey,
    local_ip: IpAddr,
    io: tokio::io::DuplexStream,
    mut seg_rx: mpsc::UnboundedReceiver<TcpSegment>,
    ready_tx: oneshot::Sender<io::Result<()>>,
) {
    let (local_port, remote_ip, remote_port) = key;
    let ip_hdr = if local_ip.is_ipv4() { 20 } else { 40 };
    let local_mss = stack.mtu.saturating_sub(ip_hdr + 20).max(536) as u16;
    let iss: u32 = rand::thread_rng().gen();

    let mut state = TcpState::SynSent;
    let mut snd_una = iss;
    let mut rcv_nxt: u32 = 0;
    let mut peer_mss: usize = local_mss as usize;
    let mut peer_wscale: u8 = 0;
    let mut peer_wnd: usize = 65535;
    let mut cwnd: usize = (local_mss as usize) * 10;
    let mut ssthresh: usize = 65535 * 4;
    let mut dup_acks: u32 = 0;

    let mut srtt_ms: f64 = 0.0;
    let mut rttvar_ms: f64 = 0.0;
    let mut rto = Duration::from_millis(500);

    let mut unacked: VecDeque<SentSeg> = VecDeque::new();
    let mut send_buf: VecDeque<u8> = VecDeque::new();
    let mut ooo: BTreeMap<i32, Vec<u8>> = BTreeMap::new();
    let mut peer_fin_seq: Option<u32> = None;
    let mut app_eof = false;
    let mut fin_sent = false;
    let mut ack_needed = false;
    let mut unacked_rx_segs: u32 = 0;
    let mut ready_tx = Some(ready_tx);

    // Опции SYN: MSS (4 байта) + NOP + WScale (3 байта) = 8 байт.
    let syn_opts = [
        2,
        4,
        (local_mss >> 8) as u8,
        local_mss as u8,
        1,
        3,
        3,
        LOCAL_WSCALE,
    ];
    let rcv_wnd_raw = ((APP_BUF_SIZE >> LOCAL_WSCALE).min(u16::MAX as usize)) as u16;

    // Отправка SYN.
    let syn_pkt = build_tcp_packet(
        local_ip,
        local_port,
        remote_ip,
        remote_port,
        iss,
        0,
        TCP_SYN,
        rcv_wnd_raw,
        &syn_opts,
        &[],
    );
    if stack.tx_ip.send(syn_pkt).await.is_err() {
        if let Some(tx) = ready_tx.take() {
            let _ = tx.send(Err(other("masque: туннель закрыт")));
        }
        stack.tcp_flows.lock().remove(&key);
        return;
    }
    let mut snd_nxt = iss.wrapping_add(1);
    unacked.push_back(SentSeg {
        seq: iss,
        flags: TCP_SYN,
        data: Vec::new(),
        sent_at: Instant::now(),
        retransmits: 0,
    });

    let (mut app_r, mut app_w) = tokio::io::split(io);
    let mut read_chunk = vec![0u8; 16 * 1024];
    let mut app_write_queue: VecDeque<u8> = VecDeque::new();
    let mut tick = tokio::time::interval(Duration::from_millis(25));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    'main: loop {
        if state == TcpState::Closed {
            break;
        }

        // Отправляем новые сегменты из send_buf, пока позволяет окно.
        if matches!(state, TcpState::Established | TcpState::CloseWait) {
            let in_flight = snd_nxt.wrapping_sub(snd_una) as usize;
            let eff_wnd = peer_wnd.min(cwnd).max(peer_mss);
            let mut room = eff_wnd.saturating_sub(in_flight);
            while room > 0 && !send_buf.is_empty() {
                let take = send_buf.len().min(peer_mss).min(room);
                let data: Vec<u8> = send_buf.drain(..take).collect();
                let seq = snd_nxt;
                let flags = TCP_ACK | if send_buf.is_empty() { TCP_PSH } else { 0 };
                let rwnd = advertised_window(&app_write_queue);
                let pkt = build_tcp_packet(
                    local_ip,
                    local_port,
                    remote_ip,
                    remote_port,
                    seq,
                    rcv_nxt,
                    flags,
                    rwnd,
                    &[],
                    &data,
                );
                if stack.tx_ip.try_send(pkt).is_err() {
                    // Очередь переполнена: перепошлём на следующем тике RTO.
                    break;
                }
                snd_nxt = snd_nxt.wrapping_add(data.len() as u32);
                room = room.saturating_sub(data.len());
                ack_needed = false;
                unacked_rx_segs = 0;
                unacked.push_back(SentSeg {
                    seq,
                    flags,
                    data,
                    sent_at: Instant::now(),
                    retransmits: 0,
                });
            }
            if app_eof && send_buf.is_empty() && !fin_sent {
                fin_sent = true;
                let seq = snd_nxt;
                let rwnd = advertised_window(&app_write_queue);
                let pkt = build_tcp_packet(
                    local_ip,
                    local_port,
                    remote_ip,
                    remote_port,
                    seq,
                    rcv_nxt,
                    TCP_FIN | TCP_ACK,
                    rwnd,
                    &[],
                    &[],
                );
                let _ = stack.tx_ip.try_send(pkt);
                snd_nxt = snd_nxt.wrapping_add(1);
                ack_needed = false;
                unacked.push_back(SentSeg {
                    seq,
                    flags: TCP_FIN | TCP_ACK,
                    data: Vec::new(),
                    sent_at: Instant::now(),
                    retransmits: 0,
                });
                state = if state == TcpState::CloseWait { TcpState::LastAck } else { TcpState::FinWait1 };
            }
        }

        // Сбрасываем накопленные входящие данные в app_w (не блокируя цикл).
        let mut drained_to_app = false;
        while !app_write_queue.is_empty() {
            let (first, _) = app_write_queue.as_slices();
            let to_write = first.to_vec();
            match tokio::time::timeout(Duration::from_millis(5), app_w.write(&to_write)).await {
                Ok(Ok(0)) | Ok(Err(_)) => {
                    break 'main;
                }
                Ok(Ok(n)) => {
                    app_write_queue.drain(..n);
                    drained_to_app = true;
                }
                Err(_) => break,
            }
        }
        if drained_to_app && matches!(state, TcpState::CloseWait | TcpState::Closed) && app_write_queue.is_empty() {
            let _ = app_w.shutdown().await;
        }

        // Немедленный ACK каждые 2 принятых сегмента.
        if ack_needed && unacked_rx_segs >= 2 {
            send_pure_ack(&stack, local_ip, local_port, remote_ip, remote_port, snd_nxt, rcv_nxt, &app_write_queue);
            ack_needed = false;
            unacked_rx_segs = 0;
        }

        let can_read_app = matches!(state, TcpState::Established | TcpState::CloseWait)
            && !app_eof
            && send_buf.len() < APP_BUF_SIZE;

        tokio::select! {
            seg = seg_rx.recv() => {
                let Some(seg) = seg else { break };
                if seg.flags & TCP_RST != 0 {
                    if let Some(tx) = ready_tx.take() {
                        let _ = tx.send(Err(io::Error::new(io::ErrorKind::ConnectionRefused, "masque: TCP RST")));
                    }
                    break;
                }

                if state == TcpState::SynSent {
                    if (seg.flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK) && seg.ack == snd_nxt {
                        snd_una = seg.ack;
                        unacked.clear();
                        rcv_nxt = seg.seq.wrapping_add(1);
                        if let Some(m) = seg.mss {
                            peer_mss = (m as usize).min(local_mss as usize).max(536);
                        }
                        peer_wscale = seg.wscale.unwrap_or(0).min(14);
                        peer_wnd = (seg.window as usize) << peer_wscale;
                        state = TcpState::Established;
                        send_pure_ack(&stack, local_ip, local_port, remote_ip, remote_port, snd_nxt, rcv_nxt, &app_write_queue);
                        if let Some(tx) = ready_tx.take() {
                            let _ = tx.send(Ok(()));
                        }
                    }
                    continue;
                }

                // Обработка ACK.
                if seg.flags & TCP_ACK != 0 {
                    peer_wnd = (seg.window as usize) << peer_wscale;
                    if seq_lt(snd_una, seg.ack) && seq_le(seg.ack, snd_nxt) {
                        let acked_bytes = seg.ack.wrapping_sub(snd_una) as usize;
                        snd_una = seg.ack;
                        dup_acks = 0;
                        // Обновляем SRTT по незаретрансмиченному сегменту.
                        let mut sample_rtt = None;
                        while let Some(front) = unacked.front() {
                            if seq_le(front.end_seq(), snd_una) {
                                let s = unacked.pop_front().unwrap();
                                if s.retransmits == 0 {
                                    sample_rtt = Some(s.sent_at.elapsed().as_secs_f64() * 1000.0);
                                }
                            } else {
                                break;
                            }
                        }
                        if let Some(rtt) = sample_rtt {
                            if srtt_ms == 0.0 {
                                srtt_ms = rtt;
                                rttvar_ms = rtt / 2.0;
                            } else {
                                rttvar_ms = 0.75 * rttvar_ms + 0.25 * (srtt_ms - rtt).abs();
                                srtt_ms = 0.875 * srtt_ms + 0.125 * rtt;
                            }
                            let rto_ms = (srtt_ms + 4.0 * rttvar_ms).clamp(MIN_RTO.as_millis() as f64, MAX_RTO.as_millis() as f64);
                            rto = Duration::from_millis(rto_ms as u64);
                        }
                        // Slow start / AIMD.
                        if cwnd < ssthresh {
                            cwnd = (cwnd + acked_bytes).min(2 * 1024 * 1024);
                        } else {
                            let inc = (peer_mss * acked_bytes) / cwnd.max(1);
                            cwnd = (cwnd + inc.max(1)).min(2 * 1024 * 1024);
                        }
                        if state == TcpState::FinWait1 && snd_una == snd_nxt {
                            state = TcpState::FinWait2;
                        } else if state == TcpState::LastAck && snd_una == snd_nxt {
                            break;
                        }
                    } else if seg.ack == snd_una && seg.payload.is_empty() && !unacked.is_empty() {
                        dup_acks += 1;
                        if dup_acks == 3 {
                            ssthresh = (cwnd / 2).max(peer_mss * 2);
                            cwnd = ssthresh;
                            if let Some(front) = unacked.front_mut() {
                                retransmit_seg(&stack, local_ip, local_port, remote_ip, remote_port, front, rcv_nxt, &app_write_queue);
                            }
                        }
                    }
                }

                // Обработка полезных данных (in-order + out-of-order reassembly).
                let has_fin = seg.flags & TCP_FIN != 0;
                let payload_len = seg.payload.len() as u32;
                if !seg.payload.is_empty() {
                    let rel = seg.seq.wrapping_sub(rcv_nxt) as i32;
                    if rel == 0 {
                        app_write_queue.extend(&seg.payload);
                        rcv_nxt = rcv_nxt.wrapping_add(payload_len);
                        ack_needed = true;
                        unacked_rx_segs += 1;
                    } else if rel < 0 {
                        // Частичное перекрытие с уже принятыми байтами.
                        let skip = (-rel) as usize;
                        if skip < seg.payload.len() {
                            app_write_queue.extend(&seg.payload[skip..]);
                            rcv_nxt = rcv_nxt.wrapping_add((seg.payload.len() - skip) as u32);
                        }
                        // Немедленный ACK на дублирующий сегмент.
                        send_pure_ack(&stack, local_ip, local_port, remote_ip, remote_port, snd_nxt, rcv_nxt, &app_write_queue);
                        ack_needed = false;
                        unacked_rx_segs = 0;
                    } else if ooo.len() < MAX_OOO_SEGMENTS {
                        // Переупорядоченный сегмент из будущего — складываем и шлём dup-ACK.
                        ooo.entry(seg.seq as i32).or_insert(seg.payload);
                        send_pure_ack(&stack, local_ip, local_port, remote_ip, remote_port, snd_nxt, rcv_nxt, &app_write_queue);
                        ack_needed = false;
                        unacked_rx_segs = 0;
                    }

                    // Сборка из буфера переупорядочивания.
                    loop {
                        let next_key = ooo
                            .keys()
                            .copied()
                            .find(|&k| ((k as u32).wrapping_sub(rcv_nxt) as i32) <= 0);
                        let Some(k) = next_key else { break };
                        let data = ooo.remove(&k).unwrap();
                        let rel = (k as u32).wrapping_sub(rcv_nxt) as i32;
                        let skip = (-rel).max(0) as usize;
                        if skip < data.len() {
                            app_write_queue.extend(&data[skip..]);
                            rcv_nxt = rcv_nxt.wrapping_add((data.len() - skip) as u32);
                        }
                    }
                }

                if has_fin {
                    let fin_pos = seg.seq.wrapping_add(payload_len);
                    peer_fin_seq = Some(fin_pos);
                }
                if let Some(fin_pos) = peer_fin_seq {
                    if fin_pos == rcv_nxt {
                        peer_fin_seq = None;
                        rcv_nxt = rcv_nxt.wrapping_add(1);
                        send_pure_ack(&stack, local_ip, local_port, remote_ip, remote_port, snd_nxt, rcv_nxt, &app_write_queue);
                        ack_needed = false;
                        if app_write_queue.is_empty() {
                            let _ = app_w.shutdown().await;
                        }
                        state = match state {
                            TcpState::Established => TcpState::CloseWait,
                            TcpState::FinWait1 | TcpState::FinWait2 => TcpState::Closed,
                            other => other,
                        };
                    }
                }
            }

            read_res = app_r.read(&mut read_chunk), if can_read_app => {
                match read_res {
                    Ok(0) | Err(_) => {
                        app_eof = true;
                    }
                    Ok(n) => {
                        send_buf.extend(&read_chunk[..n]);
                    }
                }
            }

            _ = tick.tick() => {
                if ack_needed {
                    send_pure_ack(&stack, local_ip, local_port, remote_ip, remote_port, snd_nxt, rcv_nxt, &app_write_queue);
                    ack_needed = false;
                    unacked_rx_segs = 0;
                }
                if let Some(front) = unacked.front_mut() {
                    let backoff = rto.mul_f64(1.0_f64.max((1u32 << front.retransmits.min(5)) as f64)).min(MAX_RTO);
                    if front.sent_at.elapsed() >= backoff {
                        if front.retransmits >= MAX_RETRIES {
                            if let Some(tx) = ready_tx.take() {
                                let _ = tx.send(Err(io::Error::new(io::ErrorKind::TimedOut, "masque: TCP таймаут ретрансмиссии")));
                            }
                            break;
                        }
                        ssthresh = (cwnd / 2).max(peer_mss * 2);
                        cwnd = peer_mss * 2;
                        if front.flags & TCP_SYN != 0 {
                            front.retransmits += 1;
                            front.sent_at = Instant::now();
                            let pkt = build_tcp_packet(
                                local_ip, local_port, remote_ip, remote_port,
                                front.seq, 0, TCP_SYN, rcv_wnd_raw, &syn_opts, &[],
                            );
                            let _ = stack.tx_ip.try_send(pkt);
                        } else {
                            retransmit_seg(&stack, local_ip, local_port, remote_ip, remote_port, front, rcv_nxt, &app_write_queue);
                        }
                    }
                }
            }
        }
    }

    stack.tcp_flows.lock().remove(&key);
}

fn advertised_window(app_write_queue: &VecDeque<u8>) -> u16 {
    let free = APP_BUF_SIZE.saturating_sub(app_write_queue.len());
    ((free >> LOCAL_WSCALE).min(u16::MAX as usize)) as u16
}

fn send_pure_ack(
    stack: &IpStack,
    local_ip: IpAddr,
    local_port: u16,
    remote_ip: IpAddr,
    remote_port: u16,
    snd_nxt: u32,
    rcv_nxt: u32,
    app_write_queue: &VecDeque<u8>,
) {
    let pkt = build_tcp_packet(
        local_ip,
        local_port,
        remote_ip,
        remote_port,
        snd_nxt,
        rcv_nxt,
        TCP_ACK,
        advertised_window(app_write_queue),
        &[],
        &[],
    );
    let _ = stack.tx_ip.try_send(pkt);
}

fn retransmit_seg(
    stack: &IpStack,
    local_ip: IpAddr,
    local_port: u16,
    remote_ip: IpAddr,
    remote_port: u16,
    seg: &mut SentSeg,
    rcv_nxt: u32,
    app_write_queue: &VecDeque<u8>,
) {
    seg.retransmits += 1;
    seg.sent_at = Instant::now();
    let pkt = build_tcp_packet(
        local_ip,
        local_port,
        remote_ip,
        remote_port,
        seg.seq,
        rcv_nxt,
        seg.flags,
        advertised_window(app_write_queue),
        &[],
        &seg.data,
    );
    let _ = stack.tx_ip.try_send(pkt);
}

// ------------------------------------------------------------------ разбор и сборка IP+TCP

fn sum_words(data: &[u8], mut acc: u32) -> u32 {
    let mut chunks = data.chunks_exact(2);
    for pair in &mut chunks {
        acc += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    if let [last] = chunks.remainder() {
        acc += u32::from(*last) << 8;
    }
    acc
}

fn fold(mut acc: u32) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    acc as u16
}

fn parse_tcp_segment(pkt: &[u8], parsed: &packet::Parsed) -> Option<TcpSegment> {
    let l4 = parsed.l4;
    if parsed.total < l4 + 20 {
        return None;
    }
    let hdr_len = usize::from(pkt[l4 + 12] >> 4) * 4;
    if hdr_len < 20 || l4 + hdr_len > parsed.total {
        return None;
    }
    let seq = u32::from_be_bytes([pkt[l4 + 4], pkt[l4 + 5], pkt[l4 + 6], pkt[l4 + 7]]);
    let ack = u32::from_be_bytes([pkt[l4 + 8], pkt[l4 + 9], pkt[l4 + 10], pkt[l4 + 11]]);
    let flags = pkt[l4 + 13];
    let window = u16::from_be_bytes([pkt[l4 + 14], pkt[l4 + 15]]);

    let mut mss = None;
    let mut wscale = None;
    let opts = &pkt[l4 + 20..l4 + hdr_len];
    let mut i = 0;
    while i < opts.len() {
        match opts[i] {
            0 => break,
            1 => i += 1,
            kind => {
                let Some(&len) = opts.get(i + 1) else { break };
                let len = usize::from(len);
                if len < 2 || i + len > opts.len() {
                    break;
                }
                if kind == 2 && len == 4 {
                    mss = Some(u16::from_be_bytes([opts[i + 2], opts[i + 3]]));
                } else if kind == 3 && len == 3 {
                    wscale = Some(opts[i + 2]);
                }
                i += len;
            }
        }
    }

    Some(TcpSegment {
        seq,
        ack,
        flags,
        window,
        mss,
        wscale,
        payload: pkt[l4 + hdr_len..parsed.total].to_vec(),
    })
}

#[allow(clippy::too_many_arguments)]
pub fn build_tcp_packet(
    src: IpAddr,
    sport: u16,
    dst: IpAddr,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    options: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let opt_pad = (4 - (options.len() % 4)) % 4;
    let tcp_hdr_len = 20 + options.len() + opt_pad;
    let tcp_len = tcp_hdr_len + payload.len();
    let ip_hdr_len = if src.is_ipv4() { 20 } else { 40 };
    let total = ip_hdr_len + tcp_len;
    let mut out = vec![0u8; total];

    let l4 = match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            out[0] = 0x45;
            out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            out[6..8].copy_from_slice(&[0x40, 0]); // DF
            out[8] = 64;
            out[9] = PROTO_TCP;
            out[12..16].copy_from_slice(&s.octets());
            out[16..20].copy_from_slice(&d.octets());
            let check = !fold(sum_words(&out[..20], 0));
            out[10..12].copy_from_slice(&check.to_be_bytes());
            20
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            out[0] = 0x60;
            out[4..6].copy_from_slice(&(tcp_len as u16).to_be_bytes());
            out[6] = PROTO_TCP;
            out[7] = 64;
            out[8..24].copy_from_slice(&s.octets());
            out[24..40].copy_from_slice(&d.octets());
            40
        }
        _ => return Vec::new(),
    };

    out[l4..l4 + 2].copy_from_slice(&sport.to_be_bytes());
    out[l4 + 2..l4 + 4].copy_from_slice(&dport.to_be_bytes());
    out[l4 + 4..l4 + 8].copy_from_slice(&seq.to_be_bytes());
    out[l4 + 8..l4 + 12].copy_from_slice(&ack.to_be_bytes());
    out[l4 + 12] = ((tcp_hdr_len / 4) as u8) << 4;
    out[l4 + 13] = flags;
    out[l4 + 14..l4 + 16].copy_from_slice(&window.to_be_bytes());
    out[l4 + 20..l4 + 20 + options.len()].copy_from_slice(options);
    out[l4 + tcp_hdr_len..].copy_from_slice(payload);

    let mut acc = u32::from(PROTO_TCP) + tcp_len as u32;
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            acc = sum_words(&s.octets(), acc);
            acc = sum_words(&d.octets(), acc);
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            acc = sum_words(&s.octets(), acc);
            acc = sum_words(&d.octets(), acc);
        }
        _ => {}
    }
    acc = sum_words(&out[l4..], acc);
    let check = !fold(acc);
    out[l4 + 16..l4 + 18].copy_from_slice(&check.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_packet_checksum_and_options_roundtrip() {
        let src: IpAddr = "10.0.0.2".parse().unwrap();
        let dst: IpAddr = "1.1.1.1".parse().unwrap();
        let opts = [2, 4, 0x04, 0xc4, 1, 3, 3, 6];
        let pkt = build_tcp_packet(src, 42000, dst, 443, 1000, 0, TCP_SYN, 1024, &opts, b"hi");
        let parsed = packet::parse(&pkt).unwrap();
        assert_eq!(parsed.proto, PROTO_TCP);
        assert_eq!((parsed.sport, parsed.dport), (42000, 443));
        // Проверка IPv4 контрольной суммы.
        assert_eq!(fold(sum_words(&pkt[..20], 0)), 0xffff);
        // Проверка TCP контрольной суммы.
        let mut acc = u32::from(PROTO_TCP) + (pkt.len() - 20) as u32;
        acc = sum_words(&pkt[12..20], acc);
        acc = sum_words(&pkt[20..], acc);
        assert_eq!(fold(acc), 0xffff);

        let seg = parse_tcp_segment(&pkt, &parsed).unwrap();
        assert_eq!(seg.seq, 1000);
        assert_eq!(seg.mss, Some(0x04c4));
        assert_eq!(seg.wscale, Some(6));
        assert_eq!(seg.payload, b"hi");
    }

    #[tokio::test]
    async fn tcp_client_handshake_reordering_and_data_transfer() {
        let (tx_ip, mut rx_ip) = mpsc::channel::<Vec<u8>>(64);
        let stack = IpStack::new(Some(Ipv4Addr::new(10, 0, 0, 2)), None, 1280, tx_ip);
        let remote: SocketAddr = "93.184.216.34:80".parse().unwrap();

        let stack_srv = stack.clone();
        let peer_task = tokio::spawn(async move {
            // 1) Принять SYN.
            let syn_pkt = rx_ip.recv().await.unwrap();
            let parsed = packet::parse(&syn_pkt).unwrap();
            let syn = parse_tcp_segment(&syn_pkt, &parsed).unwrap();
            assert_eq!(syn.flags, TCP_SYN);
            let client_port = parsed.sport;
            let client_seq = syn.seq.wrapping_add(1);
            let srv_iss = 50_000u32;

            // 2) Ответить SYN+ACK.
            let syn_ack = build_tcp_packet(
                remote.ip(),
                remote.port(),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                client_port,
                srv_iss,
                client_seq,
                TCP_SYN | TCP_ACK,
                65535,
                &[2, 4, 0x04, 0xb0],
                &[],
            );
            stack_srv.ingest(&syn_ack);

            // 3) Принять ACK, затем данные клиента.
            let mut client_data = Vec::new();
            let mut next_client_seq = client_seq;
            while client_data.len() < 11 {
                let pkt = rx_ip.recv().await.unwrap();
                let p = packet::parse(&pkt).unwrap();
                let s = parse_tcp_segment(&pkt, &p).unwrap();
                if !s.payload.is_empty() && s.seq == next_client_seq {
                    client_data.extend_from_slice(&s.payload);
                    next_client_seq = next_client_seq.wrapping_add(s.payload.len() as u32);
                }
            }
            assert_eq!(client_data, b"hello world");

            // 4) Отправить ответ двумя сегментами В ОБРАТНОМ ПОРЯДКЕ (out-of-order!) + FIN.
            let srv_seq = srv_iss.wrapping_add(1);
            let seg2 = build_tcp_packet(
                remote.ip(),
                remote.port(),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                client_port,
                srv_seq + 5,
                next_client_seq,
                TCP_ACK | TCP_FIN,
                65535,
                &[],
                b" MASQUE!",
            );
            let seg1 = build_tcp_packet(
                remote.ip(),
                remote.port(),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                client_port,
                srv_seq,
                next_client_seq,
                TCP_ACK,
                65535,
                &[],
                b"HELLO",
            );
            stack_srv.ingest(&seg2);
            stack_srv.ingest(&seg1);
        });

        let mut stream = stack.dial_tcp(remote).await.unwrap();
        stream.write_all(b"hello world").await.unwrap();
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).await.unwrap();
        assert_eq!(resp, b"HELLO MASQUE!");
        peer_task.await.unwrap();
    }
}
