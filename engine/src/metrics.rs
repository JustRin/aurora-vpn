//! Транспортная телеметрия движка: потери пакетов, ретрансмиты TCP/QUIC,
//! сбросы TUN/UDP и ошибки дозвона.
//!
//! Счётчики на горячем пути — только `AtomicU64` с `Relaxed`: никакой блокировки
//! на каждый пакет.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
#[cfg(windows)]
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

#[cfg(windows)]
const TCP_INFO_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Default)]
pub struct NetMetrics {
    pub tun_rx_packets: AtomicU64,
    pub tun_tx_packets: AtomicU64,
    pub tun_dropped: AtomicU64,
    pub udp_dropped: AtomicU64,
    pub tcp_bytes_out: AtomicU64,
    pub tcp_bytes_in: AtomicU64,
    pub tcp_bytes_retrans: AtomicU64,
    pub tcp_retrans_events: AtomicU64,
    pub tcp_rtt_us_sum: AtomicU64,
    pub tcp_rtt_samples: AtomicU64,
    pub quic_packets_sent: AtomicU64,
    pub quic_packets_lost: AtomicU64,
    pub dial_ok: AtomicU64,
    pub dial_fail: AtomicU64,
    pub relay_errors: AtomicU64,
}

impl NetMetrics {
    pub fn snapshot(&self) -> Value {
        json!({
            "tunRxPackets": self.tun_rx_packets.load(Ordering::Relaxed),
            "tunTxPackets": self.tun_tx_packets.load(Ordering::Relaxed),
            "tunDropped": self.tun_dropped.load(Ordering::Relaxed),
            "udpDropped": self.udp_dropped.load(Ordering::Relaxed),
            "tcpBytesOut": self.tcp_bytes_out.load(Ordering::Relaxed),
            "tcpBytesIn": self.tcp_bytes_in.load(Ordering::Relaxed),
            "tcpBytesRetrans": self.tcp_bytes_retrans.load(Ordering::Relaxed),
            "tcpRetransEvents": self.tcp_retrans_events.load(Ordering::Relaxed),
            "tcpRttUsSum": self.tcp_rtt_us_sum.load(Ordering::Relaxed),
            "tcpRttSamples": self.tcp_rtt_samples.load(Ordering::Relaxed),
            "quicPacketsSent": self.quic_packets_sent.load(Ordering::Relaxed),
            "quicPacketsLost": self.quic_packets_lost.load(Ordering::Relaxed),
            "dialOk": self.dial_ok.load(Ordering::Relaxed),
            "dialFail": self.dial_fail.load(Ordering::Relaxed),
            "relayErrors": self.relay_errors.load(Ordering::Relaxed),
        })
    }
}

/// Исходящий TCP-сокет до VPN-сервера со снятием `SIO_TCP_INFO` на Windows.
/// На других платформах — прозрачная обёртка без накладных расходов.
pub struct TrackedTcpStream {
    inner: TcpStream,
    #[cfg_attr(not(windows), allow(dead_code))]
    metrics: Option<Arc<NetMetrics>>,
    #[cfg(windows)]
    last_poll: Instant,
    #[cfg(windows)]
    prev_bytes_out: u64,
    #[cfg(windows)]
    prev_bytes_in: u64,
    #[cfg(windows)]
    prev_bytes_retrans: u32,
    #[cfg(windows)]
    prev_retrans_events: u64,
}

impl TrackedTcpStream {
    pub fn new(inner: TcpStream) -> Self {
        let metrics = crate::engine::try_global().map(|ctx| ctx.tracker.metrics.clone());
        Self {
            inner,
            metrics,
            #[cfg(windows)]
            last_poll: Instant::now(),
            #[cfg(windows)]
            prev_bytes_out: 0,
            #[cfg(windows)]
            prev_bytes_in: 0,
            #[cfg(windows)]
            prev_bytes_retrans: 0,
            #[cfg(windows)]
            prev_retrans_events: 0,
        }
    }

    #[cfg(windows)]
    fn maybe_sample(&mut self) {
        if self.metrics.is_some() && self.last_poll.elapsed() >= TCP_INFO_INTERVAL {
            self.last_poll = Instant::now();
            self.sample_now();
        }
    }

    #[cfg(windows)]
    fn sample_now(&mut self) {
        let Some(metrics) = &self.metrics else { return };
        let Some(info) = query_tcp_info(&self.inner) else { return };

        let d_out = info.BytesOut.saturating_sub(self.prev_bytes_out);
        let d_in = info.BytesIn.saturating_sub(self.prev_bytes_in);
        let d_ret = u64::from(info.BytesRetrans.wrapping_sub(self.prev_bytes_retrans));
        let events = u64::from(info.FastRetrans)
            + u64::from(info.TimeoutEpisodes)
            + u64::from(info.SynRetrans);
        let d_ev = events.saturating_sub(self.prev_retrans_events);

        self.prev_bytes_out = info.BytesOut;
        self.prev_bytes_in = info.BytesIn;
        self.prev_bytes_retrans = info.BytesRetrans;
        self.prev_retrans_events = events;

        if d_out > 0 {
            metrics.tcp_bytes_out.fetch_add(d_out, Ordering::Relaxed);
        }
        if d_in > 0 {
            metrics.tcp_bytes_in.fetch_add(d_in, Ordering::Relaxed);
        }
        if d_ret > 0 {
            metrics.tcp_bytes_retrans.fetch_add(d_ret, Ordering::Relaxed);
        }
        if d_ev > 0 {
            metrics.tcp_retrans_events.fetch_add(d_ev, Ordering::Relaxed);
        }
        if info.RttUs > 0 && info.RttUs < 30_000_000 {
            metrics.tcp_rtt_us_sum.fetch_add(u64::from(info.RttUs), Ordering::Relaxed);
            metrics.tcp_rtt_samples.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(windows)]
impl Drop for TrackedTcpStream {
    fn drop(&mut self) {
        self.sample_now();
    }
}

impl AsyncRead for TrackedTcpStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        #[cfg(windows)]
        if matches!(res, Poll::Ready(Ok(()))) {
            self.maybe_sample();
        }
        res
    }
}

impl AsyncWrite for TrackedTcpStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let res = Pin::new(&mut self.inner).poll_write(cx, data);
        #[cfg(windows)]
        if matches!(res, Poll::Ready(Ok(_))) {
            self.maybe_sample();
        }
        res
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(windows)]
fn query_tcp_info(stream: &TcpStream) -> Option<windows_sys::Win32::Networking::WinSock::TCP_INFO_v0> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{WSAIoctl, SIO_TCP_INFO, TCP_INFO_v0};

    let raw = stream.as_raw_socket() as usize;
    let version: u32 = 0;
    let mut info: TCP_INFO_v0 = unsafe { std::mem::zeroed() };
    let mut returned: u32 = 0;
    let rc = unsafe {
        WSAIoctl(
            raw,
            SIO_TCP_INFO,
            &version as *const u32 as *const core::ffi::c_void,
            std::mem::size_of::<u32>() as u32,
            &mut info as *mut TCP_INFO_v0 as *mut core::ffi::c_void,
            std::mem::size_of::<TCP_INFO_v0>() as u32,
            &mut returned,
            std::ptr::null_mut(),
            None,
        )
    };
    (rc == 0 && returned as usize >= std::mem::size_of::<TCP_INFO_v0>()).then_some(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_contains_all_metric_keys() {
        let m = NetMetrics::default();
        m.tcp_bytes_out.store(1000, Ordering::Relaxed);
        m.tcp_bytes_retrans.store(25, Ordering::Relaxed);
        m.quic_packets_sent.store(500, Ordering::Relaxed);
        m.quic_packets_lost.store(3, Ordering::Relaxed);
        m.dial_ok.store(10, Ordering::Relaxed);
        m.dial_fail.store(2, Ordering::Relaxed);
        let snap = m.snapshot();
        assert_eq!(snap["tcpBytesOut"], 1000);
        assert_eq!(snap["tcpBytesRetrans"], 25);
        assert_eq!(snap["quicPacketsSent"], 500);
        assert_eq!(snap["quicPacketsLost"], 3);
        assert_eq!(snap["dialOk"], 10);
        assert_eq!(snap["dialFail"], 2);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn tcp_info_works_on_loopback_socket() {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (_server, _) = accept.await.unwrap();
        client.write_all(b"hello world").await.unwrap();
        let info = query_tcp_info(&client).expect("SIO_TCP_INFO");
        assert!(info.Mss > 0);
    }
}
