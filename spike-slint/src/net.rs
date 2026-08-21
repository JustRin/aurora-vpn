//! One place to construct HTTP clients, because the TLS story differs per
//! platform. Desktop uses reqwest's default backend (rustls with the platform
//! certificate verifier). Android cannot: the platform verifier needs a Java
//! companion class plus an initialized android context, neither of which the
//! Tauri runtime provides — so the client carries its own webpki root store
//! over the `ring` provider instead.

/// A ready client with default settings. Callers needing timeouts or headers
/// start from [`http_builder`].
pub fn http_client() -> reqwest::Client {
    http_builder()
        .build()
        .expect("HTTP-клиент не собрался — это ошибка сборки, а не окружения")
}

#[cfg(not(target_os = "android"))]
pub fn http_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
}

#[cfg(target_os = "android")]
pub fn http_builder() -> reqwest::ClientBuilder {
    use std::sync::Arc;

    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("ring поддерживает все протоколы по умолчанию")
    .with_root_certificates(roots)
    .with_no_client_auth();

    reqwest::Client::builder().use_preconfigured_tls(config)
}
