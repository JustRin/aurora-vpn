//! Поток туннеля поверх потока h2: тело запроса везёт записи в одну сторону,
//! тело ответа — в другую. Половины живут раздельно, чтобы UDP мог читать и
//! писать одновременно.

use std::future::{poll_fn, Future};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use bytes::{Buf, Bytes, BytesMut};
use h2::{Reason, RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::codec::{Opener, Sealer, KIND_DATA, MAX_CHUNK, OVERHEAD};

pub(crate) fn h2_error(e: h2::Error) -> io::Error {
    if e.is_io() {
        if let Some(e) = e.into_io() {
            return e;
        }
        return io::Error::new(io::ErrorKind::ConnectionReset, "veil: обрыв соединения");
    }
    io::Error::new(io::ErrorKind::ConnectionReset, format!("veil: h2: {e}"))
}

pub struct SendHalf {
    send: SendStream<Bytes>,
    sealer: Sealer,
    finished: bool,
}

impl SendHalf {
    pub(crate) fn new(send: SendStream<Bytes>, key: &[u8; 32]) -> Self {
        Self { send, sealer: Sealer::new(key), finished: false }
    }

    /// Запись без ожидания окна: для маленького заголовка, лишнее h2 придержит сам.
    pub(crate) fn send_now(&mut self, kind: u8, data: &[u8]) -> io::Result<()> {
        let mut out = BytesMut::with_capacity(data.len() + OVERHEAD + 1500);
        self.sealer.seal(kind, data, &mut out);
        self.send.send_data(out.freeze(), false).map_err(h2_error)
    }

    /// Отправить начало `data` одной записью; вернёт, сколько байт взято.
    /// `whole` — не резать (датаграмма UDP уходит целиком).
    pub fn poll_send(&mut self, cx: &mut Context<'_>, kind: u8, data: &[u8], whole: bool) -> Poll<io::Result<usize>> {
        if self.finished {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let want = if whole { data.len() } else { data.len().min(MAX_CHUNK) };
        self.send.reserve_capacity(want + OVERHEAD);
        // Как в hyper: poll_capacity будит только при росте окна, поэтому сперва
        // смотрим, нет ли места уже сейчас.
        let mut cap = self.send.capacity();
        while cap == 0 {
            cap = match ready!(self.send.poll_capacity(cx)) {
                Some(Ok(n)) => n,
                Some(Err(e)) => return Poll::Ready(Err(h2_error(e))),
                None => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            };
        }
        // Окно почти закрыто — всё равно шлём не меньше килобайта: лучше h2
        // придержит хвост, чем поток рассыплется на крошечные записи.
        let take = if whole { want } else { want.min(cap.max(1024)) };
        let mut out = BytesMut::with_capacity(take + OVERHEAD + 64);
        self.sealer.seal(kind, &data[..take], &mut out);
        self.send.send_data(out.freeze(), false).map_err(h2_error)?;
        Poll::Ready(Ok(take))
    }

    pub async fn send(&mut self, kind: u8, data: &[u8], whole: bool) -> io::Result<usize> {
        poll_fn(|cx| self.poll_send(cx, kind, data, whole)).await
    }

    /// Закрыть свою сторону (END_STREAM). Чтение продолжается.
    pub fn finish(&mut self) -> io::Result<()> {
        if !self.finished {
            self.finished = true;
            self.send.send_data(Bytes::new(), true).map_err(h2_error)?;
        }
        Ok(())
    }

    /// Оборвать поток целиком.
    pub fn reset(&mut self) {
        self.finished = true;
        self.send.send_reset(Reason::CANCEL);
    }
}

pub(crate) enum Source {
    Response(h2::client::ResponseFuture),
    Body(RecvStream),
    Done,
}

/// Счётчик живых потоков соединения: клиент по нему решает, не пора ли
/// открыть ещё одно. Уменьшается, когда поток отпущен.
pub(crate) struct StreamGuard(pub(crate) Arc<AtomicUsize>);

impl StreamGuard {
    pub(crate) fn new(counter: &Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self(counter.clone())
    }
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

pub struct RecvHalf {
    source: Source,
    opener: Opener,
    _guard: Option<StreamGuard>,
}

impl RecvHalf {
    pub(crate) fn new(source: Source, key: &[u8; 32]) -> Self {
        Self { source, opener: Opener::new(key), _guard: None }
    }

    pub(crate) fn guarded(mut self, guard: StreamGuard) -> Self {
        self._guard = Some(guard);
        self
    }

    /// Следующая запись: тип и данные. `None` — собеседник закрыл свою сторону.
    pub fn poll_record(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<(u8, Bytes)>>> {
        loop {
            if let Some(record) = self.opener.next()? {
                return Poll::Ready(Ok(Some(record)));
            }
            match &mut self.source {
                Source::Response(response) => {
                    let response = ready!(Pin::new(response).poll(cx)).map_err(h2_error)?;
                    if response.status() != http::StatusCode::OK {
                        self.source = Source::Done;
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            format!(
                                "veil: сервер ответил {} — неверный пароль или путь, либо фронт не пропускает путь к veil-server",
                                response.status()
                            ),
                        )));
                    }
                    self.source = Source::Body(response.into_body());
                }
                Source::Body(body) => match ready!(body.poll_data(cx)) {
                    Some(Ok(chunk)) => {
                        let _ = body.flow_control().release_capacity(chunk.len());
                        self.opener.push(&chunk);
                    }
                    Some(Err(e)) if e.reason() == Some(Reason::NO_ERROR) => self.source = Source::Done,
                    Some(Err(e)) => {
                        self.source = Source::Done;
                        return Poll::Ready(Err(h2_error(e)));
                    }
                    None => self.source = Source::Done,
                },
                Source::Done => {
                    if self.opener.has_partial() {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    return Poll::Ready(Ok(None));
                }
            }
        }
    }

    pub async fn record(&mut self) -> io::Result<Option<(u8, Bytes)>> {
        poll_fn(|cx| self.poll_record(cx)).await
    }
}

/// Обе половины вместе — обычный поток байтов для TCP.
pub struct VeilStream {
    rx: RecvHalf,
    tx: SendHalf,
    pending: Bytes,
}

impl VeilStream {
    pub(crate) fn new(rx: RecvHalf, tx: SendHalf) -> Self {
        Self { rx, tx, pending: Bytes::new() }
    }

    pub fn into_split(self) -> (RecvHalf, SendHalf) {
        (self.rx, self.tx)
    }
}

impl AsyncRead for VeilStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while this.pending.is_empty() {
            match ready!(this.rx.poll_record(cx))? {
                Some((KIND_DATA, data)) => this.pending = data,
                // Неизвестные типы пропускаем: место для расширений протокола.
                Some(_) => {}
                None => return Poll::Ready(Ok(())),
            }
        }
        let n = buf.remaining().min(this.pending.len());
        buf.put_slice(&this.pending[..n]);
        this.pending.advance(n);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for VeilStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        self.get_mut().tx.poll_send(cx, KIND_DATA, data, false)
    }

    /// Кадры отправляет задача соединения h2, ждать здесь нечего.
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.get_mut().tx.finish())
    }
}
