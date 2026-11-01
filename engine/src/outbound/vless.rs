//! VLESS и его поток xtls-rprx-vision.
//!
//! Vision прячет TLS-в-TLS набивкой первых записей, а когда внутри установился
//! TLS 1.3 — отключает внешнее шифрование: данные и так зашифрованы, и шифровать их
//! второй раз незачем. Это тот самый режим, из-за которого VLESS+Vision дешевле
//! остальных протоколов на процессоре.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use async_trait::async_trait;
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::xudp::XudpConn;
use super::Outbound;
use crate::common::{invalid, parse_uuid, BoxStream, PacketConn, Target};
use crate::config::OutboundOpts;
use crate::tls::Tls13Stream;
use crate::transport::{EarlyWrite, Upstream};

const CMD_TCP: u8 = 1;
const CMD_MUX: u8 = 3;
const FLOW_VISION: &str = "xtls-rprx-vision";

pub struct Vless {
    tag: String,
    uuid: [u8; 16],
    vision: bool,
    upstream: Upstream,
}

impl Vless {
    pub fn new(o: &OutboundOpts) -> Result<Self, String> {
        let uuid = parse_uuid(&o.uuid).ok_or("vless: неверный uuid")?;
        let vision = match o.flow.as_str() {
            "" => false,
            FLOW_VISION | "xtls-rprx-vision-udp443" => true,
            other => return Err(format!("vless: flow {other} не поддержан")),
        };
        Ok(Self { tag: o.tag.clone(), uuid, vision, upstream: Upstream::from_opts(o)? })
    }

    fn header(&self, cmd: u8, target: Option<&Target>) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.push(0);
        out.extend_from_slice(&self.uuid);
        if self.vision {
            out.push(FLOW_VISION.len() as u8 + 2);
            out.push(0x0a); // protobuf: поле 1, строка
            out.push(FLOW_VISION.len() as u8);
            out.extend_from_slice(FLOW_VISION.as_bytes());
        } else {
            out.push(0);
        }
        out.push(cmd);
        if let Some(target) = target {
            target.write_vless(&mut out);
        }
        out
    }

    async fn open(&self, cmd: u8, target: Option<&Target>) -> io::Result<BoxStream> {
        let header = self.header(cmd, target);
        if self.vision {
            let tls = self.upstream.open_tls13().await?;
            Ok(Box::new(VisionStream::new(tls, header, self.uuid)))
        } else {
            let stream = self.upstream.open().await?;
            Ok(Box::new(VlessResponse::new(EarlyWrite::new(stream, header))))
        }
    }
}

#[async_trait]
impl Outbound for Vless {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "vless"
    }

    async fn dial(&self, target: &Target) -> io::Result<BoxStream> {
        self.open(CMD_TCP, Some(target)).await
    }

    async fn dial_udp(&self, _target: &Target) -> io::Result<Box<dyn PacketConn>> {
        Ok(Box::new(XudpConn::new(self.open(CMD_MUX, None).await?)))
    }
}

/// Пропуск заголовка ответа: версия, длина дополнений, дополнения.
#[derive(Default)]
struct ResponseSkip {
    /// 0 — ждём версию, 1 — длину, 2 — пропускаем `skip`, 3 — готово.
    state: u8,
    skip: u8,
}

impl ResponseSkip {
    /// Вернуть, сколько байт из начала `data` принадлежит заголовку.
    fn consume(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut i = 0;
        while i < data.len() && self.state != 3 {
            match self.state {
                0 => {
                    if data[i] != 0 {
                        return Err(invalid(format!("vless: версия ответа {}", data[i])));
                    }
                    self.state = 1;
                    i += 1;
                }
                1 => {
                    self.skip = data[i];
                    self.state = if self.skip == 0 { 3 } else { 2 };
                    i += 1;
                }
                _ => {
                    let n = (self.skip as usize).min(data.len() - i);
                    self.skip -= n as u8;
                    i += n;
                    if self.skip == 0 {
                        self.state = 3;
                    }
                }
            }
        }
        Ok(i)
    }

    fn done(&self) -> bool {
        self.state == 3
    }
}

struct VlessResponse<S> {
    io: S,
    skip: ResponseSkip,
}

impl<S> VlessResponse<S> {
    fn new(io: S) -> Self {
        Self { io, skip: ResponseSkip::default() }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for VlessResponse<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.skip.done() {
            return Pin::new(&mut this.io).poll_read(cx, buf);
        }
        loop {
            let before = buf.filled().len();
            ready!(Pin::new(&mut this.io).poll_read(cx, buf))?;
            let after = buf.filled().len();
            if after == before {
                return Poll::Ready(Ok(())); // EOF
            }
            let used = this.skip.consume(&buf.filled()[before..after])?;
            if used > 0 {
                buf.filled_mut().copy_within(before + used..after, before);
                buf.set_filled(after - used);
            }
            if buf.filled().len() > before {
                return Poll::Ready(Ok(()));
            }
            if this.skip.done() {
                return Pin::new(&mut this.io).poll_read(cx, buf);
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VlessResponse<S> {
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

// ------------------------------------------------------------------ Vision

const CHUNK: usize = 8192;
const CMD_CONTINUE: u8 = 0;
const CMD_END: u8 = 1;
const CMD_DIRECT: u8 = 2;
const TLS_APP_DATA: [u8; 3] = [0x17, 0x03, 0x03];
const TLS13_SUPPORTED_VERSIONS: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];

/// Определение TLS внутри туннеля: и на чтении, и на записи.
#[derive(Debug)]
struct Filter {
    remaining_packets: i32,
    is_tls: bool,
    is_tls12_or_above: bool,
    remaining_server_hello: i32,
    cipher: u16,
    enable_xtls: bool,
}

impl Filter {
    fn new() -> Self {
        Self {
            remaining_packets: 8,
            is_tls: false,
            is_tls12_or_above: false,
            remaining_server_hello: 0,
            cipher: 0,
            enable_xtls: false,
        }
    }

    fn observe(&mut self, data: &[u8]) {
        if self.remaining_packets <= 0 {
            return;
        }
        self.remaining_packets -= 1;
        if data.len() > 6 {
            if data[..3] == [22, 3, 3] {
                self.is_tls = true;
                if data[5] == 2 {
                    self.remaining_server_hello = (i32::from(data[3]) << 8 | i32::from(data[4])) + 5;
                    self.is_tls12_or_above = true;
                    if data.len() >= 79 && self.remaining_server_hello >= 79 {
                        let sid = data[43] as usize;
                        if let Some(c) = data.get(43 + sid + 1..43 + sid + 3) {
                            self.cipher = u16::from(c[0]) << 8 | u16::from(c[1]);
                        }
                    }
                }
            } else if data[..2] == [0x16, 0x03] && data[5] == 1 {
                self.is_tls = true;
            }
        }
        if self.remaining_server_hello > 0 {
            let end = (self.remaining_server_hello as usize).min(data.len());
            self.remaining_server_hello -= end as i32;
            if data[..end].windows(6).any(|w| w == TLS13_SUPPORTED_VERSIONS) {
                // Все шифры TLS 1.3, кроме CCM_8: его длина записи выдаёт клиента.
                self.enable_xtls = matches!(self.cipher, 0x1301 | 0x1302 | 0x1303 | 0x1304);
                self.remaining_packets = 0;
            } else if self.remaining_server_hello == 0 {
                self.remaining_packets = 0;
            }
        }
    }
}

fn pad_into(out: &mut Vec<u8>, uuid: Option<&[u8; 16]>, command: u8, data: &[u8], long: bool) {
    let mut rng = rand::thread_rng();
    let padding = if data.len() < 900 && long {
        rng.gen_range(0..500) + 900 - data.len()
    } else {
        rng.gen_range(0..256)
    };
    if let Some(uuid) = uuid {
        out.extend_from_slice(uuid);
    }
    out.push(command);
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(&(padding as u16).to_be_bytes());
    out.extend_from_slice(data);
    out.resize(out.len() + padding, 0);
}

/// Разбор набивки при чтении.
struct Unpad {
    uuid: [u8; 16],
    remaining_content: i32,
    remaining_padding: i32,
    command: u8,
    /// Заголовок может лечь на границу записи.
    partial: [u8; 5],
    partial_len: usize,
}

impl Unpad {
    fn new(uuid: [u8; 16]) -> Self {
        Self { uuid, remaining_content: -1, remaining_padding: -1, command: 0, partial: [0; 5], partial_len: 0 }
    }

    /// Дописать в `out` полезные данные из `data`.
    fn feed(&mut self, data: &[u8], out: &mut Vec<u8>) {
        let mut i = 0;
        if self.remaining_content == -1 && self.remaining_padding == -1 {
            if data.len() >= 21 && data[..16] == self.uuid {
                i = 16;
                self.remaining_content = 0;
                self.remaining_padding = 0;
                self.command = 0;
            } else {
                out.extend_from_slice(data);
                return;
            }
        }
        while i < data.len() {
            if self.remaining_content <= 0 && self.remaining_padding <= 0 {
                if self.command == CMD_END {
                    out.extend_from_slice(&data[i..]);
                    return;
                }
                let take = (5 - self.partial_len).min(data.len() - i);
                self.partial[self.partial_len..self.partial_len + take].copy_from_slice(&data[i..i + take]);
                self.partial_len += take;
                i += take;
                if self.partial_len == 5 {
                    let h = self.partial;
                    self.command = h[0];
                    self.remaining_content = i32::from(h[1]) << 8 | i32::from(h[2]);
                    self.remaining_padding = i32::from(h[3]) << 8 | i32::from(h[4]);
                    self.partial_len = 0;
                }
            } else if self.remaining_content > 0 {
                let n = (self.remaining_content as usize).min(data.len() - i);
                out.extend_from_slice(&data[i..i + n]);
                self.remaining_content -= n as i32;
                i += n;
            } else {
                let n = (self.remaining_padding as usize).min(data.len() - i);
                self.remaining_padding -= n as i32;
                i += n;
            }
        }
    }

    fn block_finished(&self) -> bool {
        self.remaining_content == 0 && self.remaining_padding == 0 && self.partial_len == 0
    }
}

pub struct VisionStream {
    tls: Tls13Stream,
    /// Заголовок VLESS: уходит с первой записью.
    header: Option<Vec<u8>>,
    uuid: [u8; 16],
    response: ResponseSkip,
    write_uuid: bool,
    filter: Filter,

    is_padding: bool,
    direct_write: bool,
    /// Запечатать через TLS до переключения на сырой сокет.
    out: Vec<u8>,
    out_pos: usize,
    /// После набивки: хвост, который идёт уже мимо TLS.
    raw_tail: Vec<u8>,
    raw_pos: usize,

    within_padding: bool,
    unpad: Unpad,
    direct_read: bool,
    chunk: Vec<u8>,
    ready: Vec<u8>,
    ready_pos: usize,
    filtered_upto: usize,
}

impl VisionStream {
    pub fn new(tls: Tls13Stream, header: Vec<u8>, uuid: [u8; 16]) -> Self {
        Self {
            tls,
            header: Some(header),
            uuid,
            response: ResponseSkip::default(),
            write_uuid: true,
            filter: Filter::new(),
            is_padding: true,
            direct_write: false,
            out: Vec::new(),
            out_pos: 0,
            raw_tail: Vec::new(),
            raw_pos: 0,
            within_padding: true,
            unpad: Unpad::new(uuid),
            direct_read: false,
            chunk: vec![0u8; CHUNK],
            ready: Vec::new(),
            ready_pos: 0,
            filtered_upto: 0,
        }
    }

    /// Слить очередь записи: сперва через TLS, затем хвост мимо него.
    fn poll_flush_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.out_pos < self.out.len() {
            let n = ready!(Pin::new(&mut self.tls).poll_write(cx, &self.out[self.out_pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.out_pos += n;
        }
        if !self.out.is_empty() {
            ready!(Pin::new(&mut self.tls).poll_flush(cx))?;
            self.out.clear();
            self.out_pos = 0;
            if self.direct_write {
                self.tls.set_direct_write();
            }
        }
        while self.raw_pos < self.raw_tail.len() {
            let n = ready!(Pin::new(&mut self.tls).poll_write(cx, &self.raw_tail[self.raw_pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.raw_pos += n;
        }
        if !self.raw_tail.is_empty() {
            self.raw_tail = Vec::new();
            self.raw_pos = 0;
        }
        Poll::Ready(Ok(()))
    }

    fn uuid_once(&mut self) -> Option<[u8; 16]> {
        if self.write_uuid {
            self.write_uuid = false;
            Some(self.uuid)
        } else {
            None
        }
    }

    /// Обернуть данные набивкой и решить, не пора ли переходить на прямой режим.
    fn pad_write(&mut self, data: &[u8]) {
        let parts: [&[u8]; 2] = if data.len() >= CHUNK - 21 {
            let mut at = data.windows(3).rposition(|w| w == TLS_APP_DATA).unwrap_or(0);
            if at == 0 {
                at = CHUNK / 2;
            }
            [&data[..at], &data[at..]]
        } else {
            [data, &[]]
        };

        let long = self.filter.is_tls;
        for (i, part) in parts.iter().enumerate() {
            if part.is_empty() && i > 0 {
                continue;
            }
            if self.filter.is_tls && part.len() > 6 && part[..3] == TLS_APP_DATA {
                let command = if self.filter.enable_xtls { CMD_DIRECT } else { CMD_END };
                self.is_padding = false;
                let uuid = self.uuid_once();
                pad_into(&mut self.out, uuid.as_ref(), command, part, true);
                if self.filter.enable_xtls {
                    self.direct_write = true;
                    // Всё, что осталось от этого куска, идёт уже мимо TLS.
                    if let Some(rest) = parts.get(i + 1) {
                        self.raw_tail.extend_from_slice(rest);
                    }
                } else if let Some(rest) = parts.get(i + 1) {
                    self.out.extend_from_slice(rest);
                }
                return;
            }
            if !self.filter.is_tls12_or_above && self.filter.remaining_packets <= 1 {
                self.is_padding = false;
                let uuid = self.uuid_once();
                pad_into(&mut self.out, uuid.as_ref(), CMD_END, part, long);
                if let Some(rest) = parts.get(i + 1) {
                    self.out.extend_from_slice(rest);
                }
                return;
            }
            let uuid = self.uuid_once();
            pad_into(&mut self.out, uuid.as_ref(), CMD_CONTINUE, part, long);
        }
    }
}

impl AsyncRead for VisionStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if this.ready_pos < this.ready.len() {
                let n = buf.remaining().min(this.ready.len() - this.ready_pos);
                buf.put_slice(&this.ready[this.ready_pos..this.ready_pos + n]);
                this.ready_pos += n;
                if this.ready_pos == this.ready.len() {
                    this.ready.clear();
                    this.ready_pos = 0;
                    this.filtered_upto = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if this.direct_read {
                return Pin::new(&mut this.tls).poll_read(cx, buf);
            }

            // Заголовок запроса обязан уйти, прежде чем мы станем ждать ответа.
            if this.header.is_some() {
                let header = this.header.take().unwrap();
                this.out.extend_from_slice(&header);
            }
            if let Poll::Ready(Err(e)) = this.poll_flush_out(cx) {
                return Poll::Ready(Err(e));
            }

            let mut chunk = std::mem::take(&mut this.chunk);
            let polled = {
                let mut read = ReadBuf::new(&mut chunk);
                match Pin::new(&mut this.tls).poll_read(cx, &mut read) {
                    Poll::Ready(Ok(())) => Poll::Ready(Ok(read.filled().len())),
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => Poll::Pending,
                }
            };
            let n = match polled {
                Poll::Pending => {
                    this.chunk = chunk;
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => {
                    this.chunk = chunk;
                    return Poll::Ready(Err(e));
                }
                Poll::Ready(Ok(n)) => n,
            };
            if n == 0 {
                this.chunk = chunk;
                return Poll::Ready(Ok(()));
            }

            let mut data = &chunk[..n];
            let used = match this.response.consume(data) {
                Ok(used) => used,
                Err(e) => {
                    this.chunk = chunk;
                    return Poll::Ready(Err(e));
                }
            };
            data = &data[used..];
            if data.is_empty() {
                this.chunk = chunk;
                continue;
            }

            if this.within_padding || this.filter.remaining_packets > 0 {
                let start = this.ready.len();
                this.unpad.feed(data, &mut this.ready);
                let finished = this.unpad.block_finished();
                if finished {
                    match this.unpad.command {
                        CMD_END => {
                            this.within_padding = false;
                            this.unpad.remaining_content = -1;
                            this.unpad.remaining_padding = -1;
                        }
                        CMD_DIRECT => {
                            this.within_padding = false;
                            this.direct_read = true;
                            let rest = this.tls.set_direct_read();
                            this.ready.extend_from_slice(&rest);
                        }
                        CMD_CONTINUE => this.within_padding = true,
                        other => {
                            this.chunk = chunk;
                            return Poll::Ready(Err(invalid(format!("vision: команда {other}"))));
                        }
                    }
                } else if this.unpad.remaining_content > 0 || this.unpad.remaining_padding > 0 || this.unpad.partial_len > 0 {
                    this.within_padding = true;
                } else {
                    this.within_padding = false;
                }
                if this.filter.remaining_packets > 0 && this.ready.len() > start {
                    let observed = this.ready[start..].to_vec();
                    this.filter.observe(&observed);
                }
            } else {
                this.ready.extend_from_slice(data);
            }
            this.chunk = chunk;
        }
    }
}

impl AsyncWrite for VisionStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        ready!(this.poll_flush_out(cx))?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if !this.is_padding {
            if this.filter.remaining_packets > 0 {
                this.filter.observe(data);
            }
            return Pin::new(&mut this.tls).poll_write(cx, data);
        }

        // Части после набивки лягут в запись не длиннее 16 КБ.
        let data = &data[..data.len().min(CHUNK * 2 - 64)];
        if this.filter.remaining_packets > 0 {
            this.filter.observe(data);
        }
        if let Some(header) = this.header.take() {
            this.out.extend_from_slice(&header);
        }
        this.pad_write(data);
        if let Poll::Ready(Err(e)) = this.poll_flush_out(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.poll_flush_out(cx))?;
        Pin::new(&mut this.tls).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.poll_flush_out(cx))?;
        Pin::new(&mut this.tls).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_header_may_arrive_in_pieces() {
        let mut skip = ResponseSkip::default();
        assert_eq!(skip.consume(&[0]).unwrap(), 1);
        assert!(!skip.done());
        assert_eq!(skip.consume(&[2, 9]).unwrap(), 2);
        assert!(!skip.done());
        assert_eq!(skip.consume(&[9, 7, 7]).unwrap(), 1);
        assert!(skip.done());
    }

    #[test]
    fn response_with_wrong_version_is_an_error_not_a_panic() {
        assert!(ResponseSkip::default().consume(&[9, 0]).is_err());
    }

    #[test]
    fn padding_roundtrip_including_a_split_header() {
        let uuid = [7u8; 16];
        let mut frame = Vec::new();
        pad_into(&mut frame, Some(&uuid), CMD_CONTINUE, b"hello", true);
        pad_into(&mut frame, None, CMD_END, b"world", false);
        frame.extend_from_slice(b"tail");

        // Рубим поток на все возможные пары кусков.
        for cut in 21..frame.len() {
            let mut unpad = Unpad::new(uuid);
            let mut out = Vec::new();
            unpad.feed(&frame[..cut], &mut out);
            unpad.feed(&frame[cut..], &mut out);
            assert_eq!(out, b"helloworldtail", "разрез на {cut}");
        }
    }

    #[test]
    fn traffic_without_the_uuid_is_passed_through() {
        let mut unpad = Unpad::new([7u8; 16]);
        let mut out = Vec::new();
        unpad.feed(&[1u8; 40], &mut out);
        assert_eq!(out, [1u8; 40]);
    }

    #[test]
    fn filter_recognises_tls13_server_hello() {
        let mut filter = Filter::new();
        let mut hello = vec![22, 3, 3, 0, 90, 2];
        hello.resize(43, 0);
        hello.push(32); // session id
        hello.extend_from_slice(&[0u8; 32]);
        hello.extend_from_slice(&[0x13, 0x01, 0]);
        hello.extend_from_slice(&[0, 6]);
        hello.extend_from_slice(&TLS13_SUPPORTED_VERSIONS);
        filter.observe(&hello);
        assert!(filter.is_tls && filter.enable_xtls);
        assert_eq!(filter.remaining_packets, 0);
    }

    #[test]
    fn filter_stops_counting_on_plain_traffic() {
        let mut filter = Filter::new();
        for _ in 0..20 {
            filter.observe(b"GET / HTTP/1.1\r\n\r\n");
        }
        assert!(!filter.is_tls);
        assert_eq!(filter.remaining_packets, 0);
    }

    #[test]
    fn header_format() {
        let o = OutboundOpts {
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
            flow: FLOW_VISION.into(),
            server: "s".into(),
            server_port: 1,
            ..Default::default()
        };
        let v = Vless::new(&o).unwrap();
        let h = v.header(CMD_TCP, Some(&Target::new("1.2.3.4", 443)));
        assert_eq!(h[0], 0);
        assert_eq!(h[17] as usize, FLOW_VISION.len() + 2);
        assert_eq!(h[18], 0x0a);
        assert_eq!(h[19] as usize, FLOW_VISION.len());
        let at = 20 + FLOW_VISION.len();
        assert_eq!(h[at], CMD_TCP);
        assert_eq!(&h[at + 1..at + 3], &443u16.to_be_bytes());
        assert_eq!(h[at + 3], 1);
    }
}
