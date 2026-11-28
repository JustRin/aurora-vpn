//! Транспорт XHTTP (SplitHTTP), совместимый с Xray-core.
//!
//! Поддерживает режимы `stream-one`, `stream-up`, `packet-up` и `auto`
//! поверх HTTP/2 (мультиплексированный пул соединений), HTTP/3 (QUIC) и HTTP/1.1.
//! По умолчанию добавляет `Referer` с `x_padding` (100..=1000 символов `X`)
//! и заголовок `Content-Type: application/grpc` для потоковых POST-запросов,
//! чтобы обратные прокси (nginx/Caddy/Cloudflare) не буферизовали тело.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes};
use h2::client::{ResponseFuture, SendRequest};
use http::{Method, Request, StatusCode};
use parking_lot::Mutex as SyncMutex;
use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, Mutex, Notify};

use crate::common::{invalid, other, udp_std_socket, BoxStream};
use crate::tls::{rustls_config, TlsConfig};

const USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36";

/// Максимальный размер одного POST-пакета в режиме `packet-up` (как в Xray: 1 МБ).
const MAX_UPLOAD_SIZE: usize = 1_000_000;
/// Минимальный интервал между последовательными POST в `packet-up` (Xray: 30 мс).
const MIN_POST_INTERVAL: Duration = Duration::from_millis(30);
/// Порог обратного давления буфера отправки `packet-up`.
const UPLOAD_BUF_LIMIT: usize = 2 * 1024 * 1024;
/// Потоков на одно HTTP/2-соединение до открытия следующего.
const H2_STREAMS_PER_CONN: usize = 64;
/// Размер чанка при отправке данных в H2/H3.
const WRITE_CHUNK: usize = 16 * 1024;

#[derive(Clone, Debug)]
pub struct XhttpOptions {
    pub path: String,
    pub host: String,
    pub headers: Vec<(String, String)>,
    pub mode: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpVersion {
    H1,
    H2,
    H3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XhttpMode {
    StreamOne,
    StreamUp,
    PacketUp,
}

/// Разделяет путь на нормализованный префикс со слешами по краям и строку запроса.
pub fn normalize_path(raw: &str) -> (String, String) {
    let (base, query) = match raw.split_once('?') {
        Some((b, q)) => (b, q.to_string()),
        None => (raw, String::new()),
    };
    let mut path = if base.is_empty() { "/".to_string() } else { base.to_string() };
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    if !path.ends_with('/') {
        path.push('/');
    }
    (path, query)
}

pub fn decide_http_version(tls: Option<&TlsConfig>) -> HttpVersion {
    let Some(tls) = tls else {
        return HttpVersion::H1;
    };
    if tls.reality.is_some() {
        return HttpVersion::H2;
    }
    if tls.alpn.len() == 1 {
        if tls.alpn[0].eq_ignore_ascii_case("http/1.1") {
            return HttpVersion::H1;
        }
        if tls.alpn[0].eq_ignore_ascii_case("h3") {
            return HttpVersion::H3;
        }
    }
    HttpVersion::H2
}

pub fn decide_mode(mode: &str, tls: Option<&TlsConfig>, version: HttpVersion) -> XhttpMode {
    match mode.trim().to_ascii_lowercase().as_str() {
        "stream-one" => XhttpMode::StreamOne,
        "stream-up" => XhttpMode::StreamUp,
        "packet-up" => XhttpMode::PacketUp,
        _ => {
            if tls.is_some_and(|t| t.reality.is_some()) && version != HttpVersion::H1 {
                XhttpMode::StreamOne
            } else {
                XhttpMode::PacketUp
            }
        }
    }
}

/// Случайный UUIDv4 для идентификатора сессии XHTTP в URL.
fn new_session_id() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

fn xpadding_referer(scheme: &str, authority: &str, path: &str, query: &str) -> String {
    let len = rand::thread_rng().gen_range(100..=1000);
    let mut s = String::with_capacity(scheme.len() + 3 + authority.len() + path.len() + query.len() + 16 + len);
    s.push_str(scheme);
    s.push_str("://");
    s.push_str(authority);
    s.push_str(path);
    if query.is_empty() {
        s.push_str("?x_padding=");
    } else {
        s.push('?');
        s.push_str(query);
        s.push_str("&x_padding=");
    }
    for _ in 0..len {
        s.push('X');
    }
    s
}

fn request_path(base_path: &str, suffix: &str, query: &str) -> String {
    let mut out = String::with_capacity(base_path.len() + suffix.len() + query.len() + 1);
    out.push_str(base_path);
    out.push_str(suffix);
    if !query.is_empty() {
        out.push('?');
        out.push_str(query);
    }
    out
}

fn format_authority(host: &str, port: u16, is_tls: bool) -> String {
    let trimmed = host.trim();
    if trimmed.contains(':') && !trimmed.starts_with('[') && trimmed.parse::<std::net::Ipv6Addr>().is_ok() {
        if (is_tls && port == 443) || (!is_tls && port == 80) {
            return format!("[{trimmed}]");
        }
        return format!("[{trimmed}]:{port}");
    }
    // Если порт уже задан явно (например `example.com:8443`), не дублируем.
    if trimmed.rsplit_once(':').is_some_and(|(h, p)| !h.contains(':') && p.parse::<u16>().is_ok()) {
        return trimmed.to_string();
    }
    if (is_tls && port == 443) || (!is_tls && port == 80) {
        trimmed.to_string()
    } else {
        format!("{trimmed}:{port}")
    }
}

// ------------------------------------------------------------------ состояние пула

struct PooledH2 {
    send: SendRequest<Bytes>,
    dead: Arc<AtomicBool>,
    streams: Arc<AtomicUsize>,
    gen: u64,
}

impl PooledH2 {
    fn usable(&self, gen: u64) -> bool {
        !self.dead.load(Ordering::Relaxed) && self.gen == gen
    }
}

struct PooledH3 {
    send: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    conn: quinn::Connection,
    gen: u64,
    _endpoint: quinn::Endpoint,
}

impl PooledH3 {
    fn usable(&self, gen: u64) -> bool {
        self.conn.close_reason().is_none() && self.gen == gen
    }
}

#[derive(Clone)]
pub struct XhttpState {
    pub options: Arc<XhttpOptions>,
    h2_pool: Arc<Mutex<Vec<PooledH2>>>,
    h3_pool: Arc<Mutex<Option<PooledH3>>>,
}

impl XhttpState {
    pub fn new(options: XhttpOptions) -> Self {
        Self {
            options: Arc::new(options),
            h2_pool: Arc::new(Mutex::new(Vec::new())),
            h3_pool: Arc::new(Mutex::new(None)),
        }
    }

    pub fn authority(&self, server: &str, port: u16, tls: Option<&TlsConfig>) -> String {
        let host = if !self.options.host.is_empty() {
            self.options.host.split(',').next().unwrap_or("").trim()
        } else if let Some(t) = tls.filter(|t| !t.sni.is_empty()) {
            t.sni.as_str()
        } else {
            server
        };
        format_authority(host, port, tls.is_some())
    }
}

pub type DialBaseFn = Arc<dyn Fn() -> Pin<Box<dyn Future<Output = io::Result<BoxStream>> + Send>> + Send + Sync>;

/// Открыть поток XHTTP поверх базового коннектора (TCP/TLS/REALITY) или QUIC (для H3).
pub async fn connect(
    state: &XhttpState,
    server: &str,
    port: u16,
    tls: Option<&TlsConfig>,
    dial_base: DialBaseFn,
) -> io::Result<BoxStream> {
    let version = decide_http_version(tls);
    let mode = decide_mode(&state.options.mode, tls, version);
    let authority = state.authority(server, port, tls);
    let (base_path, query) = normalize_path(&state.options.path);

    match version {
        HttpVersion::H2 => {
            connect_h2(state, mode, &authority, &base_path, &query, dial_base).await
        }
        HttpVersion::H3 => {
            let tls = tls.ok_or_else(|| other("xhttp: HTTP/3 требует TLS"))?;
            connect_h3(state, mode, server, port, tls, &authority, &base_path, &query).await
        }
        HttpVersion::H1 => {
            connect_h1(state, mode, tls.is_some(), &authority, &base_path, &query, dial_base).await
        }
    }
}

// ------------------------------------------------------------------ HTTP/2

fn build_h2_request(
    method: Method,
    scheme: &str,
    authority: &str,
    full_path: &str,
    referer: &str,
    content_type: Option<&str>,
    custom_headers: &[(String, String)],
) -> io::Result<Request<()>> {
    let uri = format!("{scheme}://{authority}{full_path}");
    let mut b = Request::builder().method(method).uri(&uri);
    let mut has_ua = false;
    let mut has_referer = false;
    let mut has_ct = false;
    for (k, v) in custom_headers {
        let lower = k.to_ascii_lowercase();
        if matches!(lower.as_str(), "host" | "connection" | "transfer-encoding" | "upgrade" | "keep-alive") {
            continue;
        }
        if lower == "user-agent" {
            has_ua = true;
        } else if lower == "referer" {
            has_referer = true;
        } else if lower == "content-type" {
            has_ct = true;
        }
        b = b.header(k.as_str(), v.as_str());
    }
    if !has_ua {
        b = b.header("user-agent", USER_AGENT);
    }
    if !has_referer {
        b = b.header("referer", referer);
    }
    if !has_ct {
        if let Some(ct) = content_type {
            b = b.header("content-type", ct);
        }
    }
    b.body(()).map_err(|e| invalid(format!("xhttp: неверный запрос: {e}")))
}

async fn get_h2_conn(
    pool: &Mutex<Vec<PooledH2>>,
    dial_base: &DialBaseFn,
) -> io::Result<(SendRequest<Bytes>, Arc<AtomicBool>, Arc<AtomicUsize>)> {
    let gen = crate::common::network_generation();
    let mut guard = pool.lock().await;
    guard.retain(|c| c.usable(gen));
    if let Some(c) = guard.iter().find(|c| c.streams.load(Ordering::Relaxed) < H2_STREAMS_PER_CONN) {
        return Ok((c.send.clone(), c.dead.clone(), c.streams.clone()));
    }
    let io = dial_base().await?;
    let (send, conn) = h2::client::Builder::new()
        .header_table_size(65536)
        .enable_push(false)
        .initial_window_size(4 * 1024 * 1024)
        .initial_connection_window_size(10 * 1024 * 1024)
        .max_frame_size(16384)
        .handshake::<_, Bytes>(io)
        .await
        .map_err(|e| other(format!("xhttp: рукопожатие HTTP/2: {e}")))?;
    let dead = Arc::new(AtomicBool::new(false));
    let flag = dead.clone();
    tokio::spawn(async move {
        let _ = conn.await;
        flag.store(true, Ordering::Relaxed);
    });
    let streams = Arc::new(AtomicUsize::new(0));
    guard.push(PooledH2 { send: send.clone(), dead: dead.clone(), streams: streams.clone(), gen });
    Ok((send, dead, streams))
}

async fn connect_h2(
    state: &XhttpState,
    mode: XhttpMode,
    authority: &str,
    base_path: &str,
    query: &str,
    dial_base: DialBaseFn,
) -> io::Result<BoxStream> {
    let mut last_err = None;
    for _ in 0..2 {
        let (send, dead, streams) = get_h2_conn(&state.h2_pool, &dial_base).await?;
        let res = open_h2_mode(send, streams, mode, authority, base_path, query, &state.options.headers).await;
        match res {
            Ok(s) => return Ok(s),
            Err(e) => {
                dead.store(true, Ordering::Relaxed);
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| other("xhttp: не удалось открыть поток HTTP/2")))
}

async fn open_h2_mode(
    send: SendRequest<Bytes>,
    streams: Arc<AtomicUsize>,
    mode: XhttpMode,
    authority: &str,
    base_path: &str,
    query: &str,
    headers: &[(String, String)],
) -> io::Result<BoxStream> {
    match mode {
        XhttpMode::StreamOne => {
            let mut ready = send.clone().ready().await.map_err(h2_err)?;
            let full_path = request_path(base_path, "", query);
            let referer = xpadding_referer("https", authority, base_path, query);
            let req = build_h2_request(
                Method::POST,
                "https",
                authority,
                &full_path,
                &referer,
                Some("application/grpc"),
                headers,
            )?;
            let (resp, tx) = ready.send_request(req, false).map_err(h2_err)?;
            let guard = StreamGuard::new(&streams);
            Ok(Box::new(H2BidiStream::new(resp, tx, guard)))
        }
        XhttpMode::StreamUp => {
            let sid = new_session_id();
            let path_with_sid = format!("{base_path}{sid}");
            let full_path = request_path(base_path, &sid, query);

            let mut ready_get = send.clone().ready().await.map_err(h2_err)?;
            let get_ref = xpadding_referer("https", authority, &path_with_sid, query);
            let get_req = build_h2_request(Method::GET, "https", authority, &full_path, &get_ref, None, headers)?;
            let (resp, _) = ready_get.send_request(get_req, true).map_err(h2_err)?;

            let mut ready_post = send.clone().ready().await.map_err(h2_err)?;
            let post_ref = xpadding_referer("https", authority, &path_with_sid, query);
            let post_req = build_h2_request(
                Method::POST,
                "https",
                authority,
                &full_path,
                &post_ref,
                Some("application/grpc"),
                headers,
            )?;
            let (post_resp, tx) = ready_post.send_request(post_req, false).map_err(h2_err)?;
            // Ответ на POST дренируем в фоне, чтобы сервер спокойно закрыл поток.
            tokio::spawn(async move {
                if let Ok(r) = post_resp.await {
                    let mut body = r.into_body();
                    while let Some(Ok(chunk)) = body.data().await {
                        let _ = body.flow_control().release_capacity(chunk.len());
                    }
                }
            });
            let guard = StreamGuard::new(&streams);
            Ok(Box::new(H2BidiStream::new(resp, tx, guard)))
        }
        XhttpMode::PacketUp => {
            let sid = new_session_id();
            let path_with_sid = format!("{base_path}{sid}");
            let get_full_path = request_path(base_path, &sid, query);
            let get_ref = xpadding_referer("https", authority, &path_with_sid, query);

            let mut ready_get = send.clone().ready().await.map_err(h2_err)?;
            let get_req = build_h2_request(Method::GET, "https", authority, &get_full_path, &get_ref, None, headers)?;
            let (resp, _) = ready_get.send_request(get_req, true).map_err(h2_err)?;
            let guard = StreamGuard::new(&streams);

            let up_shared = Arc::new(UploadShared::new());
            let up_worker = up_shared.clone();
            let authority_s = authority.to_string();
            let base_path_s = base_path.to_string();
            let query_s = query.to_string();
            let headers_v = headers.to_vec();
            tokio::spawn(async move {
                h2_packet_up_loop(send, up_worker, authority_s, base_path_s, sid, query_s, headers_v).await;
            });

            Ok(Box::new(PacketUpStream {
                recv: H2Recv::new(resp, guard),
                upload: PacketUpWriter::new(up_shared),
            }))
        }
    }
}

async fn h2_packet_up_loop(
    send: SendRequest<Bytes>,
    shared: Arc<UploadShared>,
    authority: String,
    base_path: String,
    sid: String,
    query: String,
    headers: Vec<(String, String)>,
) {
    let mut seq: u64 = 0;
    let mut last_post = Instant::now() - MIN_POST_INTERVAL;
    loop {
        let chunk = match shared.take_chunk(MAX_UPLOAD_SIZE).await {
            Some(c) => c,
            None => return,
        };
        let elapsed = last_post.elapsed();
        if elapsed < MIN_POST_INTERVAL {
            tokio::time::sleep(MIN_POST_INTERVAL - elapsed).await;
        }
        last_post = Instant::now();

        let suffix = format!("{sid}/{seq}");
        let path_for_ref = format!("{base_path}{suffix}");
        let full_path = request_path(&base_path, &suffix, &query);
        let referer = xpadding_referer("https", &authority, &path_for_ref, &query);
        let req = match build_h2_request(Method::POST, "https", &authority, &full_path, &referer, None, &headers) {
            Ok(r) => r,
            Err(e) => {
                shared.set_error(e);
                return;
            }
        };
        let mut ready = match send.clone().ready().await {
            Ok(s) => s,
            Err(e) => {
                shared.set_error(h2_err(e));
                return;
            }
        };
        let (resp_fut, mut tx) = match ready.send_request(req, false) {
            Ok(pair) => pair,
            Err(e) => {
                shared.set_error(h2_err(e));
                return;
            }
        };
        if let Err(e) = h2_send_all(&mut tx, chunk).await {
            shared.set_error(e);
            return;
        }
        match resp_fut.await {
            Ok(resp) => {
                if !resp.status().is_success() {
                    shared.set_error(other(format!("xhttp: POST seq={seq} вернул {}", resp.status())));
                    return;
                }
                let mut body = resp.into_body();
                while let Some(Ok(b)) = body.data().await {
                    let _ = body.flow_control().release_capacity(b.len());
                }
            }
            Err(e) => {
                shared.set_error(h2_err(e));
                return;
            }
        }
        seq += 1;
    }
}

async fn h2_send_all(tx: &mut h2::SendStream<Bytes>, mut data: Bytes) -> io::Result<()> {
    if data.is_empty() {
        tx.send_data(Bytes::new(), true).map_err(h2_err)?;
        return Ok(());
    }
    while !data.is_empty() {
        let want = data.len().min(WRITE_CHUNK);
        tx.reserve_capacity(want);
        let cap = std::future::poll_fn(|cx| tx.poll_capacity(cx))
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "xhttp: поток закрыт"))?
            .map_err(h2_err)?;
        let n = cap.min(data.len());
        let part = data.split_to(n);
        let eos = data.is_empty();
        tx.send_data(part, eos).map_err(h2_err)?;
    }
    Ok(())
}

fn h2_err(e: h2::Error) -> io::Error {
    let msg = format!("xhttp h2: {e}");
    if let Some(io) = e.into_io() {
        return io;
    }
    io::Error::new(io::ErrorKind::BrokenPipe, msg)
}

struct StreamGuard(Arc<AtomicUsize>);

impl StreamGuard {
    fn new(counter: &Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self(counter.clone())
    }
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

enum H2RecvState {
    Waiting(ResponseFuture),
    Streaming(h2::RecvStream),
    Done,
}

struct H2Recv {
    state: H2RecvState,
    buf: Bytes,
    _guard: StreamGuard,
}

impl H2Recv {
    fn new(fut: ResponseFuture, guard: StreamGuard) -> Self {
        Self { state: H2RecvState::Waiting(fut), buf: Bytes::new(), _guard: guard }
    }

    fn poll_read_inner(&mut self, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        loop {
            if !self.buf.is_empty() {
                let n = out.remaining().min(self.buf.len());
                out.put_slice(&self.buf[..n]);
                self.buf.advance(n);
                return Poll::Ready(Ok(()));
            }
            match &mut self.state {
                H2RecvState::Waiting(fut) => {
                    let resp = match ready!(Pin::new(fut).poll(cx)) {
                        Ok(r) => r,
                        Err(e) => {
                            self.state = H2RecvState::Done;
                            return Poll::Ready(Err(h2_err(e)));
                        }
                    };
                    if !resp.status().is_success() {
                        self.state = H2RecvState::Done;
                        return Poll::Ready(Err(other(format!("xhttp: сервер ответил {}", resp.status()))));
                    }
                    self.state = H2RecvState::Streaming(resp.into_body());
                }
                H2RecvState::Streaming(body) => match ready!(body.poll_data(cx)) {
                    Some(Ok(chunk)) => {
                        if chunk.is_empty() {
                            continue;
                        }
                        let _ = body.flow_control().release_capacity(chunk.len());
                        self.buf = chunk;
                    }
                    Some(Err(e)) => {
                        self.state = H2RecvState::Done;
                        return Poll::Ready(Err(h2_err(e)));
                    }
                    None => {
                        self.state = H2RecvState::Done;
                        return Poll::Ready(Ok(()));
                    }
                },
                H2RecvState::Done => return Poll::Ready(Ok(())),
            }
        }
    }
}

struct H2BidiStream {
    recv: H2Recv,
    tx: h2::SendStream<Bytes>,
    closed: bool,
}

impl H2BidiStream {
    fn new(resp: ResponseFuture, tx: h2::SendStream<Bytes>, guard: StreamGuard) -> Self {
        Self { recv: H2Recv::new(resp, guard), tx, closed: false }
    }
}

impl AsyncRead for H2BidiStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.recv.poll_read_inner(cx, buf)
    }
}

impl AsyncWrite for H2BidiStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let want = data.len().min(WRITE_CHUNK);
        self.tx.reserve_capacity(want);
        match ready!(self.tx.poll_capacity(cx)) {
            Some(Ok(cap)) => {
                let n = cap.min(data.len());
                self.tx
                    .send_data(Bytes::copy_from_slice(&data[..n]), false)
                    .map_err(h2_err)?;
                Poll::Ready(Ok(n))
            }
            Some(Err(e)) => Poll::Ready(Err(h2_err(e))),
            None => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "xhttp: поток закрыт"))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.closed {
            self.closed = true;
            let _ = self.tx.send_data(Bytes::new(), true);
        }
        Poll::Ready(Ok(()))
    }
}

// ------------------------------------------------------------------ PacketUp буфер

struct UploadInner {
    queue: VecDeque<u8>,
    closed: bool,
    error: Option<io::Error>,
}

struct UploadShared {
    inner: SyncMutex<UploadInner>,
    data_ready: Notify,
    space_ready: Notify,
}

impl UploadShared {
    fn new() -> Self {
        Self {
            inner: SyncMutex::new(UploadInner { queue: VecDeque::new(), closed: false, error: None }),
            data_ready: Notify::new(),
            space_ready: Notify::new(),
        }
    }

    fn set_error(&self, err: io::Error) {
        let mut g = self.inner.lock();
        if g.error.is_none() {
            g.error = Some(err);
        }
        g.closed = true;
        self.space_ready.notify_waiters();
        self.data_ready.notify_waiters();
    }

    async fn take_chunk(&self, max_len: usize) -> Option<Bytes> {
        loop {
            let notified = self.data_ready.notified();
            {
                let mut g = self.inner.lock();
                if g.error.is_some() {
                    return None;
                }
                if !g.queue.is_empty() {
                    let n = g.queue.len().min(max_len);
                    let mut out = Vec::with_capacity(n);
                    let (a, b) = g.queue.as_slices();
                    let take_a = a.len().min(n);
                    out.extend_from_slice(&a[..take_a]);
                    if take_a < n {
                        out.extend_from_slice(&b[..n - take_a]);
                    }
                    g.queue.drain(..n);
                    self.space_ready.notify_waiters();
                    return Some(Bytes::from(out));
                }
                if g.closed {
                    return None;
                }
            }
            notified.await;
        }
    }
}

struct PacketUpWriter {
    shared: Arc<UploadShared>,
    waiting: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

impl PacketUpWriter {
    fn new(shared: Arc<UploadShared>) -> Self {
        Self { shared, waiting: None }
    }
}

impl Drop for PacketUpWriter {
    fn drop(&mut self) {
        self.shared.inner.lock().closed = true;
        self.shared.data_ready.notify_waiters();
    }
}

impl AsyncWrite for PacketUpWriter {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            {
                let mut g = self.shared.inner.lock();
                if let Some(e) = g.error.as_ref() {
                    return Poll::Ready(Err(io::Error::new(e.kind(), e.to_string())));
                }
                if g.closed {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "xhttp: запись закрыта")));
                }
                if g.queue.len() < UPLOAD_BUF_LIMIT {
                    let room = UPLOAD_BUF_LIMIT - g.queue.len();
                    let n = data.len().min(room);
                    g.queue.extend(&data[..n]);
                    drop(g);
                    self.waiting = None;
                    self.shared.data_ready.notify_one();
                    return Poll::Ready(Ok(n));
                }
            }
            if self.waiting.is_none() {
                let s = self.shared.clone();
                self.waiting = Some(Box::pin(async move { s.space_ready.notified().await }));
            }
            let fut = self.waiting.as_mut().unwrap();
            ready!(fut.as_mut().poll(cx));
            self.waiting = None;
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let g = self.shared.inner.lock();
        if let Some(e) = g.error.as_ref() {
            return Poll::Ready(Err(io::Error::new(e.kind(), e.to_string())));
        }
        self.shared.data_ready.notify_one();
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut g = self.shared.inner.lock();
        g.closed = true;
        drop(g);
        self.shared.data_ready.notify_waiters();
        Poll::Ready(Ok(()))
    }
}

struct PacketUpStream<R> {
    recv: R,
    upload: PacketUpWriter,
}

impl AsyncRead for PacketUpStream<H2Recv> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.recv.poll_read_inner(cx, buf)
    }
}

impl<R: Unpin> AsyncWrite for PacketUpStream<R> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.upload).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.upload).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.upload).poll_shutdown(cx)
    }
}

// ------------------------------------------------------------------ HTTP/3

async fn get_h3_conn(
    pool: &Mutex<Option<PooledH3>>,
    server: &str,
    port: u16,
    tls: &TlsConfig,
) -> io::Result<h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>> {
    let gen = crate::common::network_generation();
    let mut guard = pool.lock().await;
    if let Some(live) = guard.as_ref() {
        if live.usable(gen) {
            return Ok(live.send.clone());
        }
        live.conn.close(0u32.into(), b"");
    }

    let addrs = crate::dns::resolve_server(server, port).await?;
    if addrs.is_empty() {
        return Err(other(format!("xhttp h3: нет адреса для {server}")));
    }
    let mut rtls = rustls_config(tls.insecure, &["h3".to_string()]).map_err(io::Error::other)?;
    rtls.enable_early_data = false;
    let crypto = Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(rtls).map_err(io::Error::other)?);
    let sni = tls.sni.clone();

    let (endpoint, conn) = crate::common::race(addrs, move |addr: SocketAddr| {
        let crypto = crypto.clone();
        let sni = sni.clone();
        async move {
            let socket = udp_std_socket(addr.is_ipv6())?;
            let mut client = quinn::ClientConfig::new(crypto);
            let mut transport = quinn::TransportConfig::default();
            transport
                .max_idle_timeout(Some(Duration::from_secs(30).try_into().map_err(io::Error::other)?))
                .keep_alive_interval(Some(Duration::from_secs(10)))
                .stream_receive_window(quinn::VarInt::from_u32(4 * 1024 * 1024))
                .receive_window(quinn::VarInt::from_u32(10 * 1024 * 1024));
            client.transport_config(Arc::new(transport));
            let runtime = quinn::default_runtime().ok_or_else(|| other("xhttp h3: нет рантайма"))?;
            let endpoint = quinn::Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)?;
            let conn = tokio::time::timeout(
                crate::common::DIAL_TIMEOUT,
                endpoint.connect_with(client, addr, &sni).map_err(io::Error::other)?,
            )
            .await
            .map_err(|_| other("xhttp h3: таймаут QUIC"))?
            .map_err(io::Error::other)?;
            Ok((endpoint, conn))
        }
    })
    .await?;

    let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(conn.clone()))
        .await
        .map_err(|e| other(format!("xhttp h3: {e}")))?;
    tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    *guard = Some(PooledH3 { send: send.clone(), conn, gen, _endpoint: endpoint });
    Ok(send)
}

async fn connect_h3(
    state: &XhttpState,
    mode: XhttpMode,
    server: &str,
    port: u16,
    tls: &TlsConfig,
    authority: &str,
    base_path: &str,
    query: &str,
) -> io::Result<BoxStream> {
    let mut send = get_h3_conn(&state.h3_pool, server, port, tls).await?;
    let headers = state.options.headers.clone();
    let (rx_tx, rx_rx) = mpsc::channel::<io::Result<Bytes>>(64);

    match mode {
        XhttpMode::StreamOne => {
            let full_path = request_path(base_path, "", query);
            let referer = xpadding_referer("https", authority, base_path, query);
            let req = build_h2_request(
                Method::POST,
                "https",
                authority,
                &full_path,
                &referer,
                Some("application/grpc"),
                &headers,
            )?;
            let stream = send.send_request(req).await.map_err(|e| other(format!("xhttp h3: {e}")))?;
            let (mut h3_tx, mut h3_rx) = stream.split();
            let (tx_tx, mut tx_rx) = mpsc::channel::<Bytes>(64);
            tokio::spawn(async move {
                while let Some(data) = tx_rx.recv().await {
                    if h3_tx.send_data(data).await.is_err() {
                        break;
                    }
                }
                let _ = h3_tx.finish().await;
            });
            tokio::spawn(async move {
                match h3_rx.recv_response().await {
                    Ok(resp) if resp.status().is_success() => {
                        while let Ok(Some(mut chunk)) = h3_rx.recv_data().await {
                            let bytes = chunk.copy_to_bytes(chunk.remaining());
                            if !bytes.is_empty() && rx_tx.send(Ok(bytes)).await.is_err() {
                                return;
                            }
                        }
                    }
                    Ok(resp) => {
                        let _ = rx_tx.send(Err(other(format!("xhttp h3: статус {}", resp.status())))).await;
                    }
                    Err(e) => {
                        let _ = rx_tx.send(Err(other(format!("xhttp h3: {e}")))).await;
                    }
                }
            });
            Ok(Box::new(ChannelStream::new(rx_rx, tx_tx)))
        }
        XhttpMode::StreamUp => {
            let sid = new_session_id();
            let path_with_sid = format!("{base_path}{sid}");
            let full_path = request_path(base_path, &sid, query);

            let get_req = build_h2_request(
                Method::GET,
                "https",
                authority,
                &full_path,
                &xpadding_referer("https", authority, &path_with_sid, query),
                None,
                &headers,
            )?;
            let mut get_stream = send.send_request(get_req).await.map_err(|e| other(format!("xhttp h3: {e}")))?;
            let _ = get_stream.finish().await;

            let post_req = build_h2_request(
                Method::POST,
                "https",
                authority,
                &full_path,
                &xpadding_referer("https", authority, &path_with_sid, query),
                Some("application/grpc"),
                &headers,
            )?;
            let post_stream = send.send_request(post_req).await.map_err(|e| other(format!("xhttp h3: {e}")))?;
            let (mut post_tx, mut post_rx) = post_stream.split();
            let (tx_tx, mut tx_rx) = mpsc::channel::<Bytes>(64);
            tokio::spawn(async move {
                while let Some(data) = tx_rx.recv().await {
                    if post_tx.send_data(data).await.is_err() {
                        break;
                    }
                }
                let _ = post_tx.finish().await;
                let _ = post_rx.recv_response().await;
            });
            tokio::spawn(async move {
                match get_stream.recv_response().await {
                    Ok(resp) if resp.status().is_success() => {
                        while let Ok(Some(mut chunk)) = get_stream.recv_data().await {
                            let bytes = chunk.copy_to_bytes(chunk.remaining());
                            if !bytes.is_empty() && rx_tx.send(Ok(bytes)).await.is_err() {
                                return;
                            }
                        }
                    }
                    Ok(resp) => {
                        let _ = rx_tx.send(Err(other(format!("xhttp h3: статус {}", resp.status())))).await;
                    }
                    Err(e) => {
                        let _ = rx_tx.send(Err(other(format!("xhttp h3: {e}")))).await;
                    }
                }
            });
            Ok(Box::new(ChannelStream::new(rx_rx, tx_tx)))
        }
        XhttpMode::PacketUp => {
            let sid = new_session_id();
            let path_with_sid = format!("{base_path}{sid}");
            let get_full_path = request_path(base_path, &sid, query);
            let get_req = build_h2_request(
                Method::GET,
                "https",
                authority,
                &get_full_path,
                &xpadding_referer("https", authority, &path_with_sid, query),
                None,
                &headers,
            )?;
            let mut get_stream = send.send_request(get_req).await.map_err(|e| other(format!("xhttp h3: {e}")))?;
            let _ = get_stream.finish().await;
            tokio::spawn(async move {
                match get_stream.recv_response().await {
                    Ok(resp) if resp.status().is_success() => {
                        while let Ok(Some(mut chunk)) = get_stream.recv_data().await {
                            let bytes = chunk.copy_to_bytes(chunk.remaining());
                            if !bytes.is_empty() && rx_tx.send(Ok(bytes)).await.is_err() {
                                return;
                            }
                        }
                    }
                    Ok(resp) => {
                        let _ = rx_tx.send(Err(other(format!("xhttp h3: статус {}", resp.status())))).await;
                    }
                    Err(e) => {
                        let _ = rx_tx.send(Err(other(format!("xhttp h3: {e}")))).await;
                    }
                }
            });

            let up_shared = Arc::new(UploadShared::new());
            let up_worker = up_shared.clone();
            let authority_s = authority.to_string();
            let base_path_s = base_path.to_string();
            let query_s = query.to_string();
            tokio::spawn(async move {
                let mut seq = 0u64;
                let mut last_post = Instant::now() - MIN_POST_INTERVAL;
                while let Some(chunk) = up_worker.take_chunk(MAX_UPLOAD_SIZE).await {
                    let elapsed = last_post.elapsed();
                    if elapsed < MIN_POST_INTERVAL {
                        tokio::time::sleep(MIN_POST_INTERVAL - elapsed).await;
                    }
                    last_post = Instant::now();
                    let suffix = format!("{sid}/{seq}");
                    let ref_path = format!("{base_path_s}{suffix}");
                    let full_path = request_path(&base_path_s, &suffix, &query_s);
                    let req = match build_h2_request(
                        Method::POST,
                        "https",
                        &authority_s,
                        &full_path,
                        &xpadding_referer("https", &authority_s, &ref_path, &query_s),
                        None,
                        &headers,
                    ) {
                        Ok(r) => r,
                        Err(e) => {
                            up_worker.set_error(e);
                            return;
                        }
                    };
                    let mut st = match send.send_request(req).await {
                        Ok(s) => s,
                        Err(e) => {
                            up_worker.set_error(other(format!("xhttp h3 POST: {e}")));
                            return;
                        }
                    };
                    if let Err(e) = st.send_data(chunk).await {
                        up_worker.set_error(other(format!("xhttp h3 send: {e}")));
                        return;
                    }
                    if let Err(e) = st.finish().await {
                        up_worker.set_error(other(format!("xhttp h3 finish: {e}")));
                        return;
                    }
                    match st.recv_response().await {
                        Ok(resp) if resp.status().is_success() => {
                            while let Ok(Some(_)) = st.recv_data().await {}
                        }
                        Ok(resp) => {
                            up_worker.set_error(other(format!("xhttp h3 POST: статус {}", resp.status())));
                            return;
                        }
                        Err(e) => {
                            up_worker.set_error(other(format!("xhttp h3 resp: {e}")));
                            return;
                        }
                    }
                    seq += 1;
                }
            });

            Ok(Box::new(ChannelPacketUpStream {
                recv: ChannelRecv { rx: rx_rx, buf: Bytes::new(), done: false },
                upload: PacketUpWriter::new(up_shared),
            }))
        }
    }
}

struct ChannelRecv {
    rx: mpsc::Receiver<io::Result<Bytes>>,
    buf: Bytes,
    done: bool,
}

impl ChannelRecv {
    fn poll_read_inner(&mut self, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        loop {
            if !self.buf.is_empty() {
                let n = out.remaining().min(self.buf.len());
                out.put_slice(&self.buf[..n]);
                self.buf.advance(n);
                return Poll::Ready(Ok(()));
            }
            if self.done {
                return Poll::Ready(Ok(()));
            }
            match ready!(self.rx.poll_recv(cx)) {
                Some(Ok(b)) => self.buf = b,
                Some(Err(e)) => {
                    self.done = true;
                    return Poll::Ready(Err(e));
                }
                None => {
                    self.done = true;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

struct ChannelStream {
    recv: ChannelRecv,
    tx: Option<mpsc::Sender<Bytes>>,
    sending: Option<Pin<Box<dyn Future<Output = Result<(), mpsc::error::SendError<Bytes>>> + Send>>>,
    pending_len: usize,
}

impl ChannelStream {
    fn new(rx: mpsc::Receiver<io::Result<Bytes>>, tx: mpsc::Sender<Bytes>) -> Self {
        Self { recv: ChannelRecv { rx, buf: Bytes::new(), done: false }, tx: Some(tx), sending: None, pending_len: 0 }
    }
}

impl AsyncRead for ChannelStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.recv.poll_read_inner(cx, buf)
    }
}

impl AsyncWrite for ChannelStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        if let Some(fut) = self.sending.as_mut() {
            let res = ready!(fut.as_mut().poll(cx));
            self.sending = None;
            let len = self.pending_len;
            self.pending_len = 0;
            return match res {
                Ok(()) => Poll::Ready(Ok(len)),
                Err(_) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "xhttp: запись закрыта"))),
            };
        }
        let Some(tx) = self.tx.clone() else {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "xhttp: запись закрыта")));
        };
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = data.len().min(WRITE_CHUNK);
        let bytes = Bytes::copy_from_slice(&data[..n]);
        match tx.try_send(bytes) {
            Ok(()) => Poll::Ready(Ok(n)),
            Err(mpsc::error::TrySendError::Full(bytes)) => {
                self.pending_len = n;
                self.sending = Some(Box::pin(async move { tx.send(bytes).await }));
                self.poll_write(cx, data)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "xhttp: запись закрыта")))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.tx = None;
        Poll::Ready(Ok(()))
    }
}

struct ChannelPacketUpStream {
    recv: ChannelRecv,
    upload: PacketUpWriter,
}

impl AsyncRead for ChannelPacketUpStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.recv.poll_read_inner(cx, buf)
    }
}

impl AsyncWrite for ChannelPacketUpStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.upload).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.upload).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.upload).poll_shutdown(cx)
    }
}

// ------------------------------------------------------------------ HTTP/1.1

fn format_h1_request(
    method: &str,
    full_path: &str,
    authority: &str,
    referer: &str,
    extra: &[(&str, &str)],
    custom: &[(String, String)],
) -> Vec<u8> {
    let mut out = format!("{method} {full_path} HTTP/1.1\r\nHost: {authority}\r\n");
    let mut has_ua = false;
    let mut has_referer = false;
    for (k, v) in custom {
        let lower = k.to_ascii_lowercase();
        if matches!(lower.as_str(), "host" | "content-length" | "transfer-encoding") {
            continue;
        }
        if lower == "user-agent" {
            has_ua = true;
        } else if lower == "referer" {
            has_referer = true;
        }
        out.push_str(k);
        out.push_str(": ");
        out.push_str(v);
        out.push_str("\r\n");
    }
    if !has_ua {
        out.push_str(&format!("User-Agent: {USER_AGENT}\r\n"));
    }
    if !has_referer {
        out.push_str(&format!("Referer: {referer}\r\n"));
    }
    for (k, v) in extra {
        out.push_str(k);
        out.push_str(": ");
        out.push_str(v);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out.into_bytes()
}

struct H1ResponseHead {
    status: u16,
    chunked: bool,
    content_length: Option<usize>,
    leftover: Vec<u8>,
}

async fn read_h1_response_head<R: AsyncRead + Unpin>(io: &mut R) -> io::Result<H1ResponseHead> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    let head_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 16 * 1024 {
            return Err(invalid("xhttp h1: заголовок ответа слишком велик"));
        }
        let n = io.read(&mut tmp).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "xhttp h1: обрыв до ответа"));
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = std::str::from_utf8(&buf[..head_end]).map_err(|_| invalid("xhttp h1: не UTF-8"))?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or_else(|| invalid("xhttp h1: пустой ответ"))?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| invalid("xhttp h1: неверный статус"))?;
    let mut chunked = false;
    let mut content_length = None;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked") {
                chunked = true;
            } else if k.eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().ok();
            }
        }
    }
    Ok(H1ResponseHead { status, chunked, content_length, leftover: buf[head_end..].to_vec() })
}

async fn pump_h1_body<R: AsyncRead + Unpin>(
    mut io: R,
    head: H1ResponseHead,
    tx: mpsc::Sender<io::Result<Bytes>>,
) {
    let mut buf = head.leftover;
    if !head.chunked {
        let mut remaining = head.content_length;
        if !buf.is_empty() {
            let take = remaining.map(|r| r.min(buf.len())).unwrap_or(buf.len());
            if let Some(r) = remaining.as_mut() {
                *r -= take;
            }
            if tx.send(Ok(Bytes::copy_from_slice(&buf[..take]))).await.is_err() {
                return;
            }
        }
        let mut tmp = vec![0u8; 16 * 1024];
        loop {
            if remaining == Some(0) {
                return;
            }
            let max = remaining.map(|r| r.min(tmp.len())).unwrap_or(tmp.len());
            match io.read(&mut tmp[..max]).await {
                Ok(0) => return,
                Ok(n) => {
                    if let Some(r) = remaining.as_mut() {
                        *r -= n;
                    }
                    if tx.send(Ok(Bytes::copy_from_slice(&tmp[..n]))).await.is_err() {
                        return;
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                    return;
                }
            }
        }
    }

    // Декодирование Transfer-Encoding: chunked.
    let mut tmp = [0u8; 8192];
    loop {
        let line_end = loop {
            if let Some(pos) = buf.windows(2).position(|w| w == b"\r\n") {
                break pos;
            }
            match io.read(&mut tmp).await {
                Ok(0) => return,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                    return;
                }
            }
        };
        let size_str = std::str::from_utf8(&buf[..line_end]).unwrap_or("").split(';').next().unwrap_or("").trim();
        let Ok(chunk_len) = usize::from_str_radix(size_str, 16) else {
            let _ = tx.send(Err(invalid("xhttp h1: неверный размер чанка"))).await;
            return;
        };
        buf.drain(..line_end + 2);
        if chunk_len == 0 {
            return;
        }
        let need = chunk_len + 2;
        while buf.len() < need {
            match io.read(&mut tmp).await {
                Ok(0) => return,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                    return;
                }
            }
        }
        let payload = Bytes::copy_from_slice(&buf[..chunk_len]);
        buf.drain(..need);
        if tx.send(Ok(payload)).await.is_err() {
            return;
        }
    }
}

async fn connect_h1(
    state: &XhttpState,
    mode: XhttpMode,
    is_tls: bool,
    authority: &str,
    base_path: &str,
    query: &str,
    dial_base: DialBaseFn,
) -> io::Result<BoxStream> {
    let scheme = if is_tls { "https" } else { "http" };
    let headers = state.options.headers.clone();
    let (rx_tx, rx_rx) = mpsc::channel::<io::Result<Bytes>>(64);

    match mode {
        XhttpMode::StreamOne => {
            let mut io = dial_base().await?;
            let full_path = request_path(base_path, "", query);
            let referer = xpadding_referer(scheme, authority, base_path, query);
            let req = format_h1_request(
                "POST",
                &full_path,
                authority,
                &referer,
                &[("Transfer-Encoding", "chunked"), ("Content-Type", "application/grpc")],
                &headers,
            );
            io.write_all(&req).await?;
            let (mut r, mut w) = tokio::io::split(io);
            let (tx_tx, mut tx_rx) = mpsc::channel::<Bytes>(64);
            tokio::spawn(async move {
                while let Some(chunk) = tx_rx.recv().await {
                    if chunk.is_empty() {
                        continue;
                    }
                    let hdr = format!("{:x}\r\n", chunk.len());
                    if w.write_all(hdr.as_bytes()).await.is_err()
                        || w.write_all(&chunk).await.is_err()
                        || w.write_all(b"\r\n").await.is_err()
                    {
                        return;
                    }
                }
                let _ = w.write_all(b"0\r\n\r\n").await;
                let _ = w.flush().await;
            });
            tokio::spawn(async move {
                match read_h1_response_head(&mut r).await {
                    Ok(head) if StatusCode::from_u16(head.status).is_ok_and(|s| s.is_success()) => {
                        pump_h1_body(r, head, rx_tx).await;
                    }
                    Ok(head) => {
                        let _ = rx_tx.send(Err(other(format!("xhttp h1: статус {}", head.status)))).await;
                    }
                    Err(e) => {
                        let _ = rx_tx.send(Err(e)).await;
                    }
                }
            });
            Ok(Box::new(ChannelStream::new(rx_rx, tx_tx)))
        }
        XhttpMode::PacketUp | XhttpMode::StreamUp => {
            let sid = new_session_id();
            let path_with_sid = format!("{base_path}{sid}");
            let get_full_path = request_path(base_path, &sid, query);
            let mut get_io = dial_base().await?;
            let get_req = format_h1_request(
                "GET",
                &get_full_path,
                authority,
                &xpadding_referer(scheme, authority, &path_with_sid, query),
                &[("Connection", "keep-alive")],
                &headers,
            );
            get_io.write_all(&get_req).await?;
            tokio::spawn(async move {
                match read_h1_response_head(&mut get_io).await {
                    Ok(head) if StatusCode::from_u16(head.status).is_ok_and(|s| s.is_success()) => {
                        pump_h1_body(get_io, head, rx_tx).await;
                    }
                    Ok(head) => {
                        let _ = rx_tx.send(Err(other(format!("xhttp h1 GET: статус {}", head.status)))).await;
                    }
                    Err(e) => {
                        let _ = rx_tx.send(Err(e)).await;
                    }
                }
            });

            let up_shared = Arc::new(UploadShared::new());
            let up_worker = up_shared.clone();
            let authority_s = authority.to_string();
            let base_path_s = base_path.to_string();
            let query_s = query.to_string();
            let scheme_s = scheme.to_string();
            tokio::spawn(async move {
                let mut seq = 0u64;
                let mut last_post = Instant::now() - MIN_POST_INTERVAL;
                let mut post_io: Option<BoxStream> = None;
                while let Some(chunk) = up_worker.take_chunk(MAX_UPLOAD_SIZE).await {
                    let elapsed = last_post.elapsed();
                    if elapsed < MIN_POST_INTERVAL {
                        tokio::time::sleep(MIN_POST_INTERVAL - elapsed).await;
                    }
                    last_post = Instant::now();
                    let suffix = format!("{sid}/{seq}");
                    let ref_path = format!("{base_path_s}{suffix}");
                    let full_path = request_path(&base_path_s, &suffix, &query_s);
                    let len_str = chunk.len().to_string();
                    let req = format_h1_request(
                        "POST",
                        &full_path,
                        &authority_s,
                        &xpadding_referer(&scheme_s, &authority_s, &ref_path, &query_s),
                        &[("Content-Length", &len_str), ("Connection", "keep-alive")],
                        &headers,
                    );
                    let mut sent_ok = false;
                    for attempt in 0..2 {
                        let mut io = match post_io.take() {
                            Some(io) if attempt == 0 => io,
                            _ => match dial_base().await {
                                Ok(io) => io,
                                Err(e) => {
                                    up_worker.set_error(e);
                                    return;
                                }
                            },
                        };
                        if io.write_all(&req).await.is_ok()
                            && io.write_all(&chunk).await.is_ok()
                            && io.flush().await.is_ok()
                        {
                            if let Ok(head) = read_h1_response_head(&mut io).await {
                                if StatusCode::from_u16(head.status).is_ok_and(|s| s.is_success()) {
                                    // Дренируем тело, если оно непустое.
                                    let mut skip_left = head.content_length.unwrap_or(0).saturating_sub(head.leftover.len());
                                    let mut discard = [0u8; 1024];
                                    while skip_left > 0 {
                                        let m = skip_left.min(discard.len());
                                        match io.read(&mut discard[..m]).await {
                                            Ok(0) | Err(_) => break,
                                            Ok(n) => skip_left -= n,
                                        }
                                    }
                                    if !head.chunked && skip_left == 0 {
                                        post_io = Some(io);
                                    }
                                    sent_ok = true;
                                    break;
                                } else {
                                    up_worker.set_error(other(format!("xhttp h1 POST: статус {}", head.status)));
                                    return;
                                }
                            }
                        }
                    }
                    if !sent_ok {
                        up_worker.set_error(other("xhttp h1 POST: ошибка отправки"));
                        return;
                    }
                    seq += 1;
                }
            });

            Ok(Box::new(ChannelPacketUpStream {
                recv: ChannelRecv { rx: rx_rx, buf: Bytes::new(), done: false },
                upload: PacketUpWriter::new(up_shared),
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::RealityConfig;

    #[test]
    fn path_normalization_adds_slashes_and_preserves_query() {
        assert_eq!(normalize_path(""), ("/".into(), String::new()));
        assert_eq!(normalize_path("xhttp"), ("/xhttp/".into(), String::new()));
        assert_eq!(normalize_path("/split/path?foo=1"), ("/split/path/".into(), "foo=1".into()));
        assert_eq!(normalize_path("/a/"), ("/a/".into(), String::new()));
    }

    #[test]
    fn mode_and_version_selection_matches_xray() {
        assert_eq!(decide_http_version(None), HttpVersion::H1);

        let tls_default = TlsConfig { sni: "a.test".into(), alpn: vec![], insecure: false, fingerprint: String::new(), reality: None, pq_advertise: false };
        assert_eq!(decide_http_version(Some(&tls_default)), HttpVersion::H2);
        assert_eq!(decide_mode("auto", Some(&tls_default), HttpVersion::H2), XhttpMode::PacketUp);

        let tls_h1 = TlsConfig { alpn: vec!["http/1.1".into()], ..tls_default.clone() };
        assert_eq!(decide_http_version(Some(&tls_h1)), HttpVersion::H1);

        let tls_h3 = TlsConfig { alpn: vec!["h3".into()], ..tls_default.clone() };
        assert_eq!(decide_http_version(Some(&tls_h3)), HttpVersion::H3);

        let reality = TlsConfig {
            reality: Some(RealityConfig { public_key: [1; 32], short_id: [0; 8], post_quantum: Default::default() }),
            ..tls_default
        };
        assert_eq!(decide_http_version(Some(&reality)), HttpVersion::H2);
        assert_eq!(decide_mode("", Some(&reality), HttpVersion::H2), XhttpMode::StreamOne);
        assert_eq!(decide_mode("packet-up", Some(&reality), HttpVersion::H2), XhttpMode::PacketUp);
    }

    #[test]
    fn xpadding_referer_contains_100_to_1000_x_chars() {
        let r = xpadding_referer("https", "example.com", "/x/", "");
        assert!(r.starts_with("https://example.com/x/?x_padding="));
        let pad = r.split("x_padding=").nth(1).unwrap();
        assert!((100..=1000).contains(&pad.len()));
        assert!(pad.bytes().all(|b| b == b'X'));

        let r2 = xpadding_referer("https", "example.com", "/x/", "k=v");
        assert!(r2.starts_with("https://example.com/x/?k=v&x_padding="));
    }

    #[tokio::test]
    async fn h2_stream_one_bidirectional_echo() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            let mut h2_srv = h2::server::handshake(server_io).await.unwrap();
            let mut handlers = Vec::new();
            while let Some(res) = h2_srv.accept().await {
                let (req, mut respond) = res.unwrap();
                assert_eq!(req.method(), Method::POST);
                assert_eq!(req.uri().path(), "/api/");
                assert_eq!(req.headers().get("content-type").unwrap(), "application/grpc");
                assert!(req.headers().get("referer").unwrap().to_str().unwrap().contains("x_padding=XXXX"));

                handlers.push(tokio::spawn(async move {
                    let mut recv = req.into_body();
                    let resp = http::Response::builder().status(200).body(()).unwrap();
                    let mut send = respond.send_response(resp, false).unwrap();

                    while let Some(Ok(chunk)) = recv.data().await {
                        let _ = recv.flow_control().release_capacity(chunk.len());
                        send.send_data(chunk, false).unwrap();
                    }
                    send.send_data(Bytes::new(), true).unwrap();
                }));
            }
            for h in handlers {
                h.await.unwrap();
            }
        });

        let state = XhttpState::new(XhttpOptions {
            path: "/api".into(),
            host: "example.test".into(),
            headers: vec![],
            mode: "stream-one".into(),
        });
        let io_slot = Arc::new(Mutex::new(Some(Box::new(client_io) as BoxStream)));
        let dial: DialBaseFn = Arc::new(move || {
            let slot = io_slot.clone();
            Box::pin(async move { slot.lock().await.take().ok_or_else(|| other("used")) })
        });

        let mut stream = connect_h2(&state, XhttpMode::StreamOne, "example.test", "/api/", "", dial)
            .await
            .unwrap();
        stream.write_all(b"hello xhttp stream-one!").await.unwrap();
        stream.shutdown().await.unwrap();

        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"hello xhttp stream-one!");
        drop(stream);
        drop(state);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn h2_packet_up_get_and_sequenced_posts() {
        let (client_io, server_io) = tokio::io::duplex(128 * 1024);
        let server_task = tokio::spawn(async move {
            let mut h2_srv = h2::server::handshake(server_io).await.unwrap();
            let (tx, rx) = mpsc::channel::<Bytes>(16);
            let mut tx_opt = Some(tx);
            let mut rx_opt = Some(rx);

            let mut seen_get = false;
            let mut seen_post_0 = false;
            let mut handlers = Vec::new();
            while let Some(Ok((req, mut respond))) = h2_srv.accept().await {
                if req.method() == Method::GET {
                    seen_get = true;
                    let resp = http::Response::builder().status(200).body(()).unwrap();
                    let mut send = respond.send_response(resp, false).unwrap();
                    let mut rx_local = rx_opt.take().unwrap();
                    handlers.push(tokio::spawn(async move {
                        while let Some(data) = rx_local.recv().await {
                            send.send_data(data, false).unwrap();
                        }
                        send.send_data(Bytes::new(), true).unwrap();
                    }));
                } else if req.method() == Method::POST {
                    let path = req.uri().path().to_string();
                    if path.ends_with("/0") {
                        seen_post_0 = true;
                    }
                    let mut recv = req.into_body();
                    let tx_c = tx_opt.take();
                    handlers.push(tokio::spawn(async move {
                        let mut acc = Vec::new();
                        while let Some(Ok(chunk)) = recv.data().await {
                            let _ = recv.flow_control().release_capacity(chunk.len());
                            acc.extend_from_slice(&chunk);
                        }
                        if let Some(tx_c) = tx_c {
                            let _ = tx_c.send(Bytes::from(acc)).await;
                        }
                        let resp = http::Response::builder().status(200).body(()).unwrap();
                        let _ = respond.send_response(resp, true);
                    }));
                }
            }
            for h in handlers {
                let _ = h.await;
            }
            assert!(seen_get && seen_post_0);
        });

        let state = XhttpState::new(XhttpOptions {
            path: "/x".into(),
            host: "cdn.test".into(),
            headers: vec![],
            mode: "packet-up".into(),
        });
        let io_slot = Arc::new(Mutex::new(Some(Box::new(client_io) as BoxStream)));
        let dial: DialBaseFn = Arc::new(move || {
            let slot = io_slot.clone();
            Box::pin(async move { slot.lock().await.take().ok_or_else(|| other("used")) })
        });

        let mut stream = connect_h2(&state, XhttpMode::PacketUp, "cdn.test", "/x/", "", dial)
            .await
            .unwrap();
        stream.write_all(b"packet-up payload 12345").await.unwrap();
        stream.shutdown().await.unwrap();

        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"packet-up payload 12345");
        drop(stream);
        drop(state);
        server_task.await.unwrap();
    }
}
