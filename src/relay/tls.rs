//! Self-signed TLS helpers. tunnelx never talks to a public CA — the server
//! generates its own key pair (`tunnelx gencert`), and the client either pins
//! that exact certificate (`tls_ca_cert`, recommended) or, for quick testing,
//! disables verification entirely (`tls_insecure = true`).

use std::path::Path;
use std::sync::{Arc, Once};

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};

static INSTALL_CRYPTO_PROVIDER: Once = Once::new();

/// rustls 0.23 requires a process-wide default crypto provider to be installed
/// before any ClientConfig/ServerConfig is built. Call this once before using
/// anything else in this module.
pub fn ensure_crypto_provider() {
    INSTALL_CRYPTO_PROVIDER.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Generates a self-signed certificate + private key valid for `hostname`,
/// writing PEM files to `cert_path` / `key_path`.
pub fn generate_self_signed(hostname: &str, cert_path: &Path, key_path: &Path) -> Result<()> {
    ensure_crypto_provider();
    let cert_key = rcgen::generate_simple_self_signed(vec![hostname.to_string()])
        .context("failed to generate self-signed certificate")?;
    std::fs::write(cert_path, cert_key.cert.pem())
        .with_context(|| format!("failed to write {}", cert_path.display()))?;
    std::fs::write(key_path, cert_key.key_pair.serialize_pem())
        .with_context(|| format!("failed to write {}", key_path.display()))?;
    Ok(())
}

pub fn build_acceptor(cert_path: &Path, key_path: &Path) -> Result<TlsAcceptor> {
    ensure_crypto_provider();
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("failed to build TLS server config")?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// `ca_cert_path`: pin the server's exact self-signed cert (recommended).
/// If `None` and `insecure` is true, skip verification entirely (testing only).
pub fn build_connector(ca_cert_path: Option<&Path>, insecure: bool) -> Result<TlsConnector> {
    ensure_crypto_provider();
    let config = if let Some(path) = ca_cert_path {
        let mut roots = RootCertStore::empty();
        for cert in load_certs(path)? {
            roots.add(cert).context("failed to add pinned certificate to trust store")?;
        }
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    } else if insecure {
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
            .with_no_client_auth()
    } else {
        anyhow::bail!(
            "tls transport requires either tls_ca_cert (pin the server's certificate) or tls_insecure = true"
        );
    };

    Ok(TlsConnector::from(Arc::new(config)))
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let data = std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    rustls_pemfile::certs(&mut data.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("failed to parse certificate(s) in {}", path.display()))
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let data = std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    rustls_pemfile::private_key(&mut data.as_slice())
        .with_context(|| format!("failed to parse private key in {}", path.display()))?
        .with_context(|| format!("no private key found in {}", path.display()))
}

#[derive(Debug)]
struct AcceptAnyCert;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
