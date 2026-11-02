//! Veil — свой туннель Aurora: снаружи Chrome на обычном сайте по HTTP/2.
//! Протокол целиком в крейте `aura-veil`, здесь только TLS и адреса.

use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use aura_veil::client::BoxIo;
use aura_veil::codec::{KIND_DATA, MAX_RECORD_DATA};
use aura_veil::{Client, ClientConfig, Connector, RecvHalf, SendHalf, CMD_TCP, CMD_UDP};
use tokio::sync::Mutex;

use super::Outbound;
use crate::common::{invalid, BoxStream, PacketConn, Target};
use crate::config::OutboundOpts;
use crate::transport::{tls_config, Transport, Upstream};

pub struct Veil {
    tag: String,
    client: Client,
}

impl Veil {
    pub fn new(o: &OutboundOpts) -> Result<Self, String> {
        if o.password.is_empty() {
            return Err("veil: нет пароля".to_string());
        }
        // Без TLS это голый h2c: такой поток выдал бы себя первым же байтом.
        let opts = o.tls.as_ref().filter(|t| t.enabled).ok_or("veil: нужен tls")?;
        let mut tls = tls_config(opts, &o.server, &["h2", "http/1.1"])?;
        if tls.reality.is_some() {
            return Err("veil: REALITY не нужен — у сайта должен быть свой настоящий сертификат".to_string());
        }
        if !tls.alpn.iter().any(|a| a == "h2") {
            tls.alpn.insert(0, "h2".to_string());
        }
        // Сервер свой (Caddy на Go): PQ-группа без ключа не вызовет HRR.
        tls.pq_advertise = true;
        let path = if o.path.is_empty() {
            o.transport.as_ref().map(|t| t.path.clone()).unwrap_or_default()
        } else {
            o.path.clone()
        };
        if path.is_empty() {
            return Err("veil: нет path".to_string());
        }
        let cfg = ClientConfig { host: tls.sni.clone(), path, password: o.password.clone() };
        let port = if o.server_port == 0 { 443 } else { o.server_port };
        let upstream = Arc::new(Upstream {
            server: o.server.clone(),
            port,
            tls: Some(tls),
            transport: Transport::Tcp,
            pq_rejected: Default::default(),
        });
        let connector: Connector = Arc::new(move || {
            let upstream = upstream.clone();
            Box::pin(async move { Ok(Box::new(upstream.open().await?) as BoxIo) })
        });
        Ok(Self { tag: o.tag.clone(), client: Client::new(cfg, connector) })
    }
}

#[async_trait]
impl Outbound for Veil {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn kind(&self) -> &'static str {
        "veil"
    }

    async fn dial(&self, target: &Target) -> io::Result<BoxStream> {
        let mut addr = Vec::with_capacity(32);
        target.write_socks(&mut addr);
        Ok(Box::new(self.client.open(CMD_TCP, &addr).await?))
    }

    async fn dial_udp(&self, target: &Target) -> io::Result<Box<dyn PacketConn>> {
        let mut addr = Vec::with_capacity(32);
        target.write_socks(&mut addr);
        let (rx, tx) = self.client.open(CMD_UDP, &addr).await?.into_split();
        Ok(Box::new(VeilPacket { rx: Mutex::new(rx), tx: Mutex::new(tx) }))
    }
}

/// UDP: одна запись — одна датаграмма с адресом SOCKS5 впереди.
struct VeilPacket {
    rx: Mutex<RecvHalf>,
    tx: Mutex<SendHalf>,
}

#[async_trait]
impl PacketConn for VeilPacket {
    async fn send(&self, data: &[u8], to: &Target) -> io::Result<()> {
        let mut frame = Vec::with_capacity(data.len() + 32);
        to.write_socks(&mut frame);
        frame.extend_from_slice(data);
        if frame.len() > MAX_RECORD_DATA {
            return Err(invalid("veil: датаграмма больше предела записи"));
        }
        self.tx.lock().await.send(KIND_DATA, &frame, true).await.map(|_| ())
    }

    async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, Target)> {
        let mut rx = self.rx.lock().await;
        loop {
            match rx.record().await? {
                Some((KIND_DATA, data)) => {
                    let (from, used) = Target::read_socks(&data).ok_or_else(|| invalid("veil: адрес датаграммы"))?;
                    let payload = &data[used..];
                    if payload.len() > buf.len() {
                        return Err(invalid("veil: пакет больше буфера"));
                    }
                    buf[..payload.len()].copy_from_slice(payload);
                    return Ok((payload.len(), from));
                }
                Some(_) => continue,
                None => return Err(io::ErrorKind::UnexpectedEof.into()),
            }
        }
    }
}
