//! Клиент WebSocket (RFC 6455) и HTTP Upgrade поверх произвольного потока.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use base64::Engine;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::common::{invalid, BoxStream};

#[derive(Clone, Debug)]
pub struct WsOptions {
    pub path: String,
    pub host: String,
    pub headers: Vec<(String, String)>,
}

const MAX_HEADERS: usize = 16 * 1024;
const RBUF: usize = 16 * 1024;
const MAX_FRAME: usize = 16 * 1024;

pub async fn connect(mut io: BoxStream, opts: &WsOptions, server: &str, upgrade_only: bool) -> io::Result<BoxStream> {
    let host = if opts.host.is_empty() { server } else { &opts.host };
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let key = base64::engine::general_purpose::STANDARD.encode(nonce);

    let mut request = format!(
        "GET {} HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n",
        opts.path
    );
    if !upgrade_only {
        request.push_str(&format!("Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"));
    }
    if !opts.headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("user-agent")) {
        request.push_str(
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n",
        );
    }
    for (name, value) in &opts.headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    io.write_all(request.as_bytes()).await?;
    io.flush().await?;

    let mut buf = vec![0u8; RBUF];
    let mut filled = 0;
    let end = loop {
        if filled >= MAX_HEADERS {
            return Err(invalid("ws: ответ сервера слишком длинный"));
        }
        let n = io.read(&mut buf[filled..]).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "ws: сервер закрыл соединение до ответа"));
        }
        filled += n;
        if let Some(pos) = buf[..filled].windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
    };
    let status = String::from_utf8_lossy(&buf[..end.min(64)]);
    if status.split_whitespace().nth(1) != Some("101") {
        let line = status.lines().next().unwrap_or("").to_string();
        return Err(invalid(format!("ws: сервер ответил «{line}»")));
    }

    if upgrade_only {
        return Ok(Box::new(Prefilled { io, buf, pos: end, end: filled }));
    }
    Ok(Box::new(WsStream {
        io,
        rbuf: buf,
        rpos: end,
        rend: filled,
        remaining: 0,
        control: None,
        wbuf: Vec::new(),
        wpos: 0,
        closed: false,
    }))
}

/// Поток после HTTP Upgrade: сначала то, что пришло вместе с ответом.
struct Prefilled {
    io: BoxStream,
    buf: Vec<u8>,
    pos: usize,
    end: usize,
}

impl AsyncRead for Prefilled {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.pos < self.end {
            let n = out.remaining().min(self.end - self.pos);
            let pos = self.pos;
            out.put_slice(&self.buf[pos..pos + n]);
            self.pos += n;
            if self.pos == self.end {
                self.buf = Vec::new();
                self.pos = 0;
                self.end = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.io).poll_read(cx, out)
    }
}

impl AsyncWrite for Prefilled {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// Управляющий кадр в процессе чтения.
struct Control {
    opcode: u8,
    need: usize,
    data: Vec<u8>,
}

struct WsStream {
    io: BoxStream,
    rbuf: Vec<u8>,
    rpos: usize,
    rend: usize,
    /// Сколько байт текущего кадра данных ещё не прочитано.
    remaining: u64,
    control: Option<Control>,
    wbuf: Vec<u8>,
    wpos: usize,
    closed: bool,
}

/// Заголовок кадра из начала `data`: `(fin, opcode, длина, размер заголовка)`.
fn parse_frame_header(data: &[u8]) -> Result<Option<(u8, u64, usize)>, io::Error> {
    if data.len() < 2 {
        return Ok(None);
    }
    let opcode = data[0] & 0x0f;
    if data[1] & 0x80 != 0 {
        return Err(invalid("ws: сервер прислал маскированный кадр"));
    }
    match data[1] & 0x7f {
        126 => {
            if data.len() < 4 {
                return Ok(None);
            }
            Ok(Some((opcode, u64::from(u16::from_be_bytes([data[2], data[3]])), 4)))
        }
        127 => {
            if data.len() < 10 {
                return Ok(None);
            }
            let mut len = [0u8; 8];
            len.copy_from_slice(&data[2..10]);
            Ok(Some((opcode, u64::from_be_bytes(len), 10)))
        }
        short => Ok(Some((opcode, u64::from(short), 2))),
    }
}

fn encode_frame(opcode: u8, payload: &[u8], out: &mut Vec<u8>) {
    let mut mask = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut mask);
    out.reserve(payload.len() + 14);
    out.push(0x80 | opcode);
    match payload.len() {
        n if n < 126 => out.push(0x80 | n as u8),
        n if n <= 0xffff => {
            out.push(0x80 | 126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            out.push(0x80 | 127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    out.extend_from_slice(&mask);
    let start = out.len();
    out.extend_from_slice(payload);
    for (i, byte) in out[start..].iter_mut().enumerate() {
        *byte ^= mask[i & 3];
    }
}

impl WsStream {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.wpos < self.wbuf.len() {
            let n = ready!(Pin::new(&mut self.io).poll_write(cx, &self.wbuf[self.wpos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.wpos += n;
        }
        self.wbuf.clear();
        self.wpos = 0;
        Poll::Ready(Ok(()))
    }

    fn poll_fill(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        if self.rpos > 0 {
            self.rbuf.copy_within(self.rpos..self.rend, 0);
            self.rend -= self.rpos;
            self.rpos = 0;
        }
        let rend = self.rend;
        let mut read = ReadBuf::new(&mut self.rbuf[rend..]);
        ready!(Pin::new(&mut self.io).poll_read(cx, &mut read))?;
        let n = read.filled().len();
        self.rend += n;
        Poll::Ready(Ok(n))
    }
}

impl AsyncRead for WsStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if this.closed {
                return Poll::Ready(Ok(()));
            }
            // Управляющий кадр дочитываем целиком: он не длиннее 125 байт.
            if let Some(ctl) = &mut this.control {
                let have = (this.rend - this.rpos).min(ctl.need);
                ctl.data.extend_from_slice(&this.rbuf[this.rpos..this.rpos + have]);
                this.rpos += have;
                ctl.need -= have;
                if ctl.need > 0 {
                    if ready!(this.poll_fill(cx))? == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    continue;
                }
                let ctl = this.control.take().unwrap();
                match ctl.opcode {
                    9 => encode_frame(10, &ctl.data, &mut this.wbuf),
                    8 => {
                        this.closed = true;
                        return Poll::Ready(Ok(()));
                    }
                    _ => {}
                }
                if let Poll::Ready(Err(e)) = this.poll_drain(cx) {
                    return Poll::Ready(Err(e));
                }
                continue;
            }

            if this.remaining > 0 {
                let avail = this.rend - this.rpos;
                if avail > 0 {
                    let n = (avail as u64).min(this.remaining).min(out.remaining() as u64) as usize;
                    out.put_slice(&this.rbuf[this.rpos..this.rpos + n]);
                    this.rpos += n;
                    this.remaining -= n as u64;
                    return Poll::Ready(Ok(()));
                }
                // Длинный кадр читаем сразу в буфер получателя, минуя свой.
                let before = out.filled().len();
                let limit = (out.remaining() as u64).min(this.remaining) as usize;
                let mut sub = ReadBuf::new(out.initialize_unfilled_to(limit));
                ready!(Pin::new(&mut this.io).poll_read(cx, &mut sub))?;
                let n = sub.filled().len();
                out.set_filled(before + n);
                this.remaining -= n as u64;
                return Poll::Ready(Ok(()));
            }

            match parse_frame_header(&this.rbuf[this.rpos..this.rend])? {
                None => {
                    if ready!(this.poll_fill(cx))? == 0 {
                        return Poll::Ready(Ok(()));
                    }
                }
                Some((opcode, len, head)) => {
                    this.rpos += head;
                    match opcode {
                        0 | 1 | 2 => this.remaining = len,
                        8 | 9 | 10 => {
                            if len > 125 {
                                return Poll::Ready(Err(invalid("ws: длинный управляющий кадр")));
                            }
                            this.control = Some(Control { opcode, need: len as usize, data: Vec::with_capacity(len as usize) });
                        }
                        other => return Poll::Ready(Err(invalid(format!("ws: кадр типа {other}")))),
                    }
                }
            }
        }
    }
}

impl AsyncWrite for WsStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        ready!(this.poll_drain(cx))?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = data.len().min(MAX_FRAME);
        encode_frame(2, &data[..n], &mut this.wbuf);
        if let Poll::Ready(Err(e)) = this.poll_drain(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_are_masked_and_sized() {
        let mut out = Vec::new();
        encode_frame(2, &[0u8; 300], &mut out);
        assert_eq!(out[0], 0x82);
        assert_eq!(out[1], 0x80 | 126);
        assert_eq!(u16::from_be_bytes([out[2], out[3]]), 300);
        assert_eq!(out.len(), 4 + 4 + 300);
    }

    #[test]
    fn frame_headers_wait_for_all_their_bytes() {
        assert!(parse_frame_header(&[0x82]).unwrap().is_none());
        assert!(parse_frame_header(&[0x82, 126, 0]).unwrap().is_none());
        assert_eq!(parse_frame_header(&[0x82, 5]).unwrap(), Some((2, 5, 2)));
        assert_eq!(parse_frame_header(&[0x82, 126, 1, 0]).unwrap(), Some((2, 256, 4)));
        assert!(parse_frame_header(&[0x82, 0x85]).is_err());
    }
}
