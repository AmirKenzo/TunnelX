//! Self-signed TLS helpers. tunnelx never talks to a public CA — the server
//! generates its own key pair (`tunnelx gencert`), and the client either pins
//! that exact certificate (`tls_ca_cert`, recommended) or, for quick testing,
//! disables verification entirely (`tls_insecure = true`).

use std::path::Path;
use std::sync::{Arc, Once};

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};

static INSTALL_CRYPTO_PROVIDER: Once = Once::new();

/// Ordinary browser HTTPS traffic almost always negotiates ALPN; a TLS client
/// that offers none is itself an anomaly some DPI heuristics flag. Advertise
/// the same protocol list on both ends purely for handshake appearance — we
/// don't run HTTP over this connection, so whatever gets negotiated has no
/// effect on the tunnel itself.
fn alpn_protocols() -> Vec<Vec<u8>> {
    vec![b"h2".to_vec(), b"http/1.1".to_vec()]
}

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

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("failed to build TLS server config")?;
    config.alpn_protocols = alpn_protocols();

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// `ca_cert_path`: pin the server's exact self-signed cert (recommended).
/// If `None` and `insecure` is true, skip verification entirely (testing only).
pub fn build_connector(ca_cert_path: Option<&Path>, insecure: bool) -> Result<TlsConnector> {
    ensure_crypto_provider();
    let mut config = if let Some(path) = ca_cert_path {
        let pinned = load_certs(path)?
            .into_iter()
            .next()
            .context("no certificate found in tls_ca_cert file")?;
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedCertVerifier::new(pinned)))
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
    config.alpn_protocols = alpn_protocols();

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

/// Verifies the server's certificate is byte-for-byte the one pinned via
/// `tls_ca_cert`, instead of doing hostname/SAN validation against a CA chain.
/// This is the correct model for a pinned self-signed cert: we don't care what
/// hostname/IP is embedded in it (the server is usually dialed by bare IP,
/// which the cert has no SAN for), only that it's the exact cert we expect.
/// Signature verification still runs normally so a stolen public cert alone
/// can't be replayed without the matching private key.
#[derive(Debug)]
struct PinnedCertVerifier {
    pinned: CertificateDer<'static>,
    supported_algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl PinnedCertVerifier {
    fn new(pinned: CertificateDer<'static>) -> Self {
        Self {
            pinned,
            supported_algs: rustls::crypto::ring::default_provider().signature_verification_algorithms,
        }
    }
}

impl rustls::client::danger::ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.pinned.as_ref() {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "server certificate does not match the pinned tls_ca_cert".to_string(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
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
