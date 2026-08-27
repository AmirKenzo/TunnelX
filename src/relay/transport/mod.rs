mod tcp;
mod ws;

use std::path::PathBuf;
use std::pin::Pin;

use anyhow::{bail, Context, Result};
use rustls::pki_types::ServerName;
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::relay::tls as tls_util;

/// A connected byte stream, regardless of which transport produced it.
pub type BoxedStream = Pin<Box<dyn AsyncRead2Write>>;

pub trait AsyncRead2Write: AsyncRead + AsyncWrite + Send {}
impl<T: AsyncRead + AsyncWrite + Send> AsyncRead2Write for T {}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Tcp,
    Tls,
    Ws,
    Wss,
}

impl Kind {
    pub fn is_tls(self) -> bool {
        matches!(self, Kind::Tls | Kind::Wss)
    }
}

/// Server-side TLS settings, required when `Kind::is_tls()`.
#[derive(Debug, Clone)]
pub struct TlsServerOpts {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// Client-side TLS settings, required when `Kind::is_tls()`.
#[derive(Debug, Clone, Default)]
pub struct TlsClientOpts {
    pub ca_cert: Option<PathBuf>,
    pub insecure: bool,
}

pub struct Listener {
    kind: Kind,
    tcp: tokio::net::TcpListener,
    tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
}

pub async fn bind(kind: Kind, addr: &str, tls: Option<&TlsServerOpts>) -> Result<Listener> {
    let tcp = tokio::net::TcpListener::bind(addr).await?;
    let tls_acceptor = if kind.is_tls() {
        let opts = tls.ok_or_else(|| anyhow::anyhow!("transport {kind:?} requires tls_cert/tls_key"))?;
        Some(tls_util::build_acceptor(&opts.cert, &opts.key)?)
    } else {
        None
    };
    Ok(Listener { kind, tcp, tls_acceptor })
}

impl Listener {
    pub async fn accept(&self) -> Result<(BoxedStream, std::net::SocketAddr)> {
        let (stream, peer) = self.tcp.accept().await?;
        stream.set_nodelay(true).ok();

        let stream: BoxedStream = match self.kind {
            Kind::Tcp => Box::pin(stream),
            Kind::Tls => {
                let acceptor = self.tls_acceptor.as_ref().expect("tls acceptor set for Kind::Tls");
                Box::pin(acceptor.accept(stream).await?)
            }
            Kind::Ws => Box::pin(ws::accept(stream).await?),
            Kind::Wss => {
                let acceptor = self.tls_acceptor.as_ref().expect("tls acceptor set for Kind::Wss");
                let tls_stream = acceptor.accept(stream).await?;
                Box::pin(ws::accept(tls_stream).await?)
            }
        };

        Ok((stream, peer))
    }
}

pub async fn dial(kind: Kind, addr: &str, tls: &TlsClientOpts) -> Result<BoxedStream> {
    match kind {
        Kind::Tcp => Ok(Box::pin(tcp::dial(addr).await?)),
        Kind::Tls => Ok(Box::pin(dial_tls(addr, tls).await?)),
        Kind::Ws => {
            let stream = tcp::dial(addr).await?;
            Ok(Box::pin(ws::connect(stream, addr).await?))
        }
        Kind::Wss => {
            let stream = dial_tls(addr, tls).await?;
            Ok(Box::pin(ws::connect(stream, addr).await?))
        }
    }
}

async fn dial_tls(
    addr: &str,
    tls: &TlsClientOpts,
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let connector = tls_util::build_connector(tls.ca_cert.as_deref(), tls.insecure)?;
    let tcp = tcp::dial(addr).await?;
    let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr);
    let server_name = ServerName::try_from(host.to_string())
        .with_context(|| format!("invalid server name '{host}' for TLS"))?;
    Ok(connector.connect(server_name, tcp).await?)
}

pub fn parse_kind(s: &str) -> Result<Kind> {
    match s.to_lowercase().as_str() {
        "tcp" => Ok(Kind::Tcp),
        "tls" => Ok(Kind::Tls),
        "ws" => Ok(Kind::Ws),
        "wss" => Ok(Kind::Wss),
        other => bail!("unknown transport '{other}' (expected one of: tcp, tls, ws, wss)"),
    }
}
