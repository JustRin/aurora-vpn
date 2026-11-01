//! TLS для исходящих соединений.
//!
//! Основной путь — свой клиент TLS 1.3 (`stream`): только так можно управлять
//! ClientHello побайтно и получить сырой сокет для Vision. rustls подхватывает
//! серверы, знающие лишь TLS 1.2, ценой отпечатка: у него он свой.

pub mod hello;
pub mod stream;

use std::fmt;
use std::io;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

use crate::common::{invalid, BoxStream};
pub use stream::{handshake, Tls13Stream};

#[derive(Clone)]
pub struct RealityConfig {
    pub public_key: [u8; 32],
    pub short_id: [u8; 8],
    /// Сервер уже отверг короткий hello — дальше все соединения узла идут с
    /// ключом ML-KEM. Один флаг на узел, как `postQuantum` в патче aurora.2.
    pub post_quantum: Arc<AtomicBool>,
}

#[derive(Clone)]
pub struct TlsConfig {
    pub sni: String,
    pub alpn: Vec<String>,
    pub insecure: bool,
    pub fingerprint: String,
    pub reality: Option<RealityConfig>,
}

/// Исходы рукопожатия, которые лечатся новым дозвоном.
#[derive(Debug)]
pub enum Retry {
    /// REALITY-сервер не признал нас и отдал соединение своей маске.
    RealityWantsPostQuantum,
    /// Сервер ответил без TLS 1.3 — нужен rustls.
    NeedTls12,
}

impl fmt::Display for Retry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Retry::RealityWantsPostQuantum => f.write_str("reality: сервер отверг короткий hello"),
            Retry::NeedTls12 => f.write_str("сервер не поддерживает TLS 1.3"),
        }
    }
}

impl std::error::Error for Retry {}

pub fn retry_reason(err: &io::Error) -> Option<&Retry> {
    err.get_ref().and_then(|e| e.downcast_ref::<Retry>())
}

#[derive(Debug)]
struct AnyCert(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Конфиг rustls: для QUIC и серверов на TLS 1.2.
pub fn rustls_config(insecure: bool, alpn: &[String]) -> Result<rustls::ClientConfig, rustls::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?;
    let mut config = if insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCert(provider)))
            .with_no_client_auth()
    } else {
        let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    config.alpn_protocols = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
    Ok(config)
}

pub async fn connect_rustls(io: BoxStream, cfg: &TlsConfig) -> io::Result<BoxStream> {
    let config = rustls_config(cfg.insecure, &cfg.alpn).map_err(io::Error::other)?;
    let name = ServerName::try_from(cfg.sni.clone()).map_err(|e| invalid(format!("имя сервера: {e}")))?;
    let stream = tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, io).await?;
    Ok(Box::new(stream))
}
