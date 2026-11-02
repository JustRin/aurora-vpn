//! Клиент: соединения h2 к сайту и потоки туннеля внутри них.
//!
//! TLS здесь не делается: соединение даёт `Connector` (в Aurora — движок со
//! своим ClientHello под Chrome). От него требуется одно: ALPN h2.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use h2::client::SendRequest;
use http::{Method, Request};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

use crate::codec::KIND_HEADER;
use crate::coalesce::Coalesce;
use crate::crypto::{now, UserKey};
use crate::stream::{h2_error, RecvHalf, SendHalf, Source, StreamGuard, VeilStream};
use crate::COOKIE;

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Io for T {}
pub type BoxIo = Box<dyn Io>;
pub type Connector = Arc<dyn Fn() -> Pin<Box<dyn Future<Output = io::Result<BoxIo>> + Send>> + Send + Sync>;

/// Фронт и логи сайта видят обычный Chrome под Windows.
/// Client Hints, которые Chrome шлёт на каждый запрос по HTTPS; версия та же,
/// что в User-Agent.
const SEC_CH_UA: &str = r#""Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99""#;

const USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36";

/// Сколько живёт одно соединение. Вкладку тоже не держат открытой сутками, а
/// многочасовая сессия с ровным потоком — главный поведенческий признак туннеля.
const LIFETIME_SECS: std::ops::Range<u64> = 4 * 60..12 * 60;
/// Больше потоков — новое соединение: у nginx предел 128 на соединение, у
/// Caddy 250, и ждать, пока чужой поток освободит место, нельзя.
const STREAMS_PER_CONN: usize = 100;

#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// Домен сайта: `:authority`, Origin и Referer. Тот же, что в SNI.
    pub host: String,
    pub path: String,
    pub password: String,
}

struct Conn {
    send: SendRequest<Bytes>,
    born: Instant,
    lifetime: Duration,
    dead: Arc<AtomicBool>,
    streams: Arc<AtomicUsize>,
}

impl Conn {
    fn usable(&self) -> bool {
        !self.dead.load(Ordering::Relaxed) && self.born.elapsed() < self.lifetime
    }
}

pub struct Client {
    cfg: ClientConfig,
    key: UserKey,
    connector: Connector,
    pool: Mutex<Vec<Conn>>,
    /// Часы сервера минус наши, секунды. Жетон живёт ±5 минут, а у телефонов
    /// бывают сбитые часы и не тот часовой пояс; время сервера берём из
    /// заголовка `Date` ответа на загрузку страницы — его шлёт любой сайт.
    clock_offset: AtomicI64,
}

impl Client {
    pub fn new(mut cfg: ClientConfig, connector: Connector) -> Self {
        if !cfg.path.starts_with('/') {
            cfg.path.insert(0, '/');
        }
        let key = UserKey::new(&cfg.password);
        Self { cfg, key, connector, pool: Mutex::new(Vec::new()), clock_offset: AtomicI64::new(0) }
    }

    /// Открыть поток туннеля. `addr` — цель в формате SOCKS5, `cmd` —
    /// [`crate::CMD_TCP`] или [`crate::CMD_UDP`]. Ответа сервера не ждёт:
    /// данные можно писать сразу, ошибка придёт при чтении.
    pub async fn open(&self, cmd: u8, addr: &[u8]) -> io::Result<VeilStream> {
        let mut header = Vec::with_capacity(1 + addr.len());
        header.push(cmd);
        header.extend_from_slice(addr);
        // Вторая попытка — на свежем соединении: старое могли тихо закрыть
        // фронт по простою или сеть.
        let mut last = None;
        for _ in 0..2 {
            let (send, dead, streams) = self.conn().await?;
            match self.request(send, &header, &streams).await {
                Ok(stream) => return Ok(stream),
                Err(e) => {
                    dead.store(true, Ordering::Relaxed);
                    last = Some(e);
                }
            }
        }
        Err(last.unwrap_or_else(|| io::Error::other("veil: не удалось открыть поток")))
    }

    /// Для тестов: как будто наши часы сбиты на `offset` секунд.
    #[doc(hidden)]
    pub fn skew_clock_for_test(&self, offset: i64) {
        self.clock_offset.store(offset, Ordering::Relaxed);
    }

    async fn conn(&self) -> io::Result<(SendRequest<Bytes>, Arc<AtomicBool>, Arc<AtomicUsize>)> {
        // Замок держится и на время дозвона: одновременные запросы ждут одно
        // новое соединение, а не открывают по своему, как браузер не стал бы.
        let mut pool = self.pool.lock().await;
        pool.retain(Conn::usable);
        if let Some(c) = pool.iter().find(|c| c.streams.load(Ordering::Relaxed) < STREAMS_PER_CONN) {
            return Ok((c.send.clone(), c.dead.clone(), c.streams.clone()));
        }
        let io = (self.connector)().await?;
        let (send, connection) = h2::client::Builder::new()
            // SETTINGS и окна как у Chrome.
            .header_table_size(65536)
            .enable_push(false)
            .initial_window_size(6 * 1024 * 1024)
            .initial_connection_window_size(15 * 1024 * 1024)
            .max_header_list_size(256 * 1024)
            .handshake::<_, Bytes>(Coalesce::new(io))
            .await
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("veil: сайт не согласился на HTTP/2 ({e}) — на 443 должен стоять Caddy или nginx с h2"),
                )
            })?;
        let dead = Arc::new(AtomicBool::new(false));
        let flag = dead.clone();
        tokio::spawn(async move {
            let _ = connection.await;
            flag.store(true, Ordering::Relaxed);
        });
        self.warmup(send.clone()).await;
        let lifetime = Duration::from_secs(rand::thread_rng().gen_range(LIFETIME_SECS));
        let streams = Arc::new(AtomicUsize::new(0));
        pool.push(Conn { send: send.clone(), born: Instant::now(), lifetime, dead: dead.clone(), streams: streams.clone() });
        Ok((send, dead, streams))
    }

    fn request_builder(&self, method: Method, path: &str) -> http::request::Builder {
        Request::builder()
            .method(method)
            .uri(format!("https://{}{}", self.cfg.host, path))
            .header("sec-ch-ua", SEC_CH_UA)
            .header("sec-ch-ua-mobile", "?0")
            .header("sec-ch-ua-platform", "\"Windows\"")
            .header("user-agent", USER_AGENT)
            .header("accept-language", "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7")
    }

    /// Новое соединение начинается, как у браузера, с загрузки страницы сайта.
    /// Заголовки ответа ждём — из них берётся время сервера для жетона; тело
    /// читаем и выбрасываем в фоне.
    async fn warmup(&self, send: SendRequest<Bytes>) {
        let request = self
            .request_builder(Method::GET, "/")
            .header("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
            .header("accept-encoding", "gzip, deflate, br, zstd")
            .header("sec-fetch-site", "none")
            .header("sec-fetch-mode", "navigate")
            .header("sec-fetch-dest", "document")
            .header("upgrade-insecure-requests", "1")
            .header("priority", "u=0, i")
            .body(());
        let Ok(request) = request else { return };
        let Ok(mut send) = send.ready().await else { return };
        let Ok((response, _)) = send.send_request(request, true) else { return };
        let Ok(Ok(response)) = tokio::time::timeout(Duration::from_secs(5), response).await else { return };
        let server_time = response.headers().get("date").and_then(|v| v.to_str().ok()).and_then(parse_http_date);
        if let Some(server) = server_time {
            self.clock_offset.store(server as i64 - now() as i64, Ordering::Relaxed);
        }
        tokio::spawn(async move {
            let mut body = response.into_body();
            while let Some(Ok(chunk)) = body.data().await {
                let _ = body.flow_control().release_capacity(chunk.len());
            }
        });
    }

    async fn request(&self, send: SendRequest<Bytes>, header: &[u8], streams: &Arc<AtomicUsize>) -> io::Result<VeilStream> {
        let mut send = send.ready().await.map_err(h2_error)?;
        let ts = now() as i64 + self.clock_offset.load(Ordering::Relaxed);
        let (nonce, token) = self.key.token_at(ts.max(0) as u64);
        // Без accept-encoding: фронт с `encode gzip` иначе станет сжимать поток
        // туннеля и копить его в буфере.
        let request = self
            .request_builder(Method::POST, &self.cfg.path)
            .header("content-type", "application/octet-stream")
            .header("accept", "*/*")
            .header("origin", format!("https://{}", self.cfg.host))
            .header("referer", format!("https://{}/", self.cfg.host))
            .header("sec-fetch-site", "same-origin")
            .header("sec-fetch-mode", "cors")
            .header("sec-fetch-dest", "empty")
            .header("priority", "u=1, i")
            .header("cookie", format!("{COOKIE}={token}"))
            .body(())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("veil: запрос: {e}")))?;
        let (response, stream) = send.send_request(request, false).map_err(h2_error)?;
        let (up, down) = self.key.stream_keys(&nonce);
        let mut tx = SendHalf::new(stream, &up);
        // Сервер мог уже ответить 404 и закрыть поток — тогда настоящую причину
        // покажет чтение ответа, а соединение мёртвым не считаем.
        let _ = tx.send_now(KIND_HEADER, header);
        let rx = RecvHalf::new(Source::Response(response), &down).guarded(StreamGuard::new(streams));
        Ok(VeilStream::new(rx, tx))
    }
}

/// `Mon, 02 Nov 2026 17:49:31 GMT` (RFC 9110, IMF-fixdate) → секунды Unix.
fn parse_http_date(text: &str) -> Option<u64> {
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let mut parts = text.split_whitespace().skip(1);
    let day: i64 = parts.next()?.parse().ok()?;
    let name = parts.next()?;
    let month = MONTHS.iter().position(|m| *m == name)? as i64 + 1;
    let year: i64 = parts.next()?.parse().ok()?;
    let mut clock = parts.next()?.split(':').map(|p| p.parse::<i64>().ok());
    let (h, m, s) = (clock.next()??, clock.next()??, clock.next()??);
    // Дни от 1970-01-01 по гражданскому календарю (алгоритм Говарда Хиннанта).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + h * 3600 + m * 60 + s).ok()
}

#[cfg(test)]
mod tests {
    use super::parse_http_date;

    #[test]
    fn http_dates() {
        assert_eq!(parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(parse_http_date("Mon, 02 Nov 2026 17:49:31 GMT"), Some(1_793_641_771));
        assert_eq!(parse_http_date("Tue, 29 Feb 2028 12:00:00 GMT"), Some(1_835_438_400));
        assert_eq!(parse_http_date("мусор"), None);
        assert_eq!(parse_http_date("Mon, 02 Foo 2026 17:49:31 GMT"), None);
    }
}
