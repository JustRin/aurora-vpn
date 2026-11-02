//! Склейка записи до flush. h2 без векторного ввода-вывода пишет кадр
//! кусками по 1 КБ, и каждый кусок становился отдельной TLS-записью: снаружи
//! это ровная череда записей по 1041 байт — признак, которого у браузера нет.
//! Здесь всё, что h2 пишет до flush, уходит одной записью до 16 КБ.
//!
//! Одно исключение — начало соединения. Chrome шлёт предисловие h2 с SETTINGS и
//! WINDOW_UPDATE отдельной записью (≈87 Б), а первый запрос — следующей. Если
//! склеить их, первая запись клиента выйдет в несколько раз крупнее, чем у
//! браузера, и это видно по размерам записей снаружи.

use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Больше открытого текста TLS-запись не берёт.
const LIMIT: usize = 16 * 1024;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const FRAME_SETTINGS: u8 = 0x4;
const FRAME_WINDOW_UPDATE: u8 = 0x8;

pub struct Coalesce<T> {
    io: T,
    buf: Vec<u8>,
    pos: usize,
    /// Граница записи внутри `buf`; 0 — нет.
    cut: usize,
    /// Первый flush ещё впереди: в нём ищется конец предисловия.
    opening: bool,
}

impl<T> Coalesce<T> {
    pub fn new(io: T) -> Self {
        Self { io, buf: Vec::with_capacity(LIMIT), pos: 0, cut: 0, opening: true }
    }
}

/// Где кончаются предисловие и служебные кадры и начинается первый запрос.
fn opening_cut(buf: &[u8]) -> usize {
    if !buf.starts_with(PREFACE) {
        return 0;
    }
    let mut off = PREFACE.len();
    while off + 9 <= buf.len() {
        let len = u32::from_be_bytes([0, buf[off], buf[off + 1], buf[off + 2]]) as usize;
        if !matches!(buf[off + 3], FRAME_SETTINGS | FRAME_WINDOW_UPDATE) {
            return off;
        }
        off += 9 + len;
    }
    0
}

impl<T: AsyncWrite + Unpin> Coalesce<T> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.pos < self.buf.len() {
            // Каждый вызов внизу — одна TLS-запись.
            let end = if self.cut > self.pos { self.cut } else { self.buf.len() };
            let n = ready!(Pin::new(&mut self.io).poll_write(cx, &self.buf[self.pos..end]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.pos += n;
        }
        self.buf.clear();
        self.pos = 0;
        self.cut = 0;
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Coalesce<T> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Coalesce<T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        self.poll_write_vectored(cx, &[IoSlice::new(data)])
    }

    fn poll_write_vectored(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[IoSlice<'_>]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.buf.len() >= LIMIT {
            ready!(this.poll_drain(cx))?;
        }
        let mut taken = 0;
        for slice in bufs {
            let room = LIMIT - this.buf.len();
            if room == 0 {
                break;
            }
            let n = slice.len().min(room);
            this.buf.extend_from_slice(&slice[..n]);
            taken += n;
            if n < slice.len() {
                break;
            }
        }
        Poll::Ready(Ok(taken))
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.opening && !self.buf.is_empty() {
            self.opening = false;
            self.cut = opening_cut(&self.buf);
        }
        ready!(self.poll_drain(cx))?;
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_drain(cx))?;
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// Запоминает границы вызовов poll_write — то есть будущих TLS-записей.
    #[derive(Default)]
    struct Records(Vec<Vec<u8>>);

    impl AsyncWrite for Records {
        fn poll_write(mut self: Pin<&mut Self>, _: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
            self.0.push(data.to_vec());
            Poll::Ready(Ok(data.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncRead for Records {
        fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, _: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn frame(kind: u8, len: usize) -> Vec<u8> {
        let mut f = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, 0, 0, 0, 0, 0];
        f.resize(9 + len, 7);
        f
    }

    #[tokio::test]
    async fn preface_and_first_request_are_separate_records() {
        let mut w = Coalesce::new(Records::default());
        let mut opening = PREFACE.to_vec();
        opening.extend(frame(FRAME_SETTINGS, 24));
        opening.extend(frame(FRAME_WINDOW_UPDATE, 4));
        let headers = frame(0x1, 300);
        w.write_all(&[opening.clone(), headers.clone()].concat()).await.unwrap();
        w.flush().await.unwrap();
        // Дальше склейка как обычно: два кадра — одна запись.
        w.write_all(&[frame(0x1, 200), frame(0x0, 1000)].concat()).await.unwrap();
        w.flush().await.unwrap();
        let records = &w.io.0;
        assert_eq!(records.len(), 3);
        assert_eq!(records[0], opening);
        assert_eq!(records[1], headers);
        assert_eq!(records[2].len(), 9 + 200 + 9 + 1000);
    }
}
