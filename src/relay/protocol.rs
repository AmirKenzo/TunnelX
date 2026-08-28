//! Wire format for the relay client<->server connections.
//!
//! Every physical connection starts with a fixed 8-byte version handshake
//! (`write_handshake`/`read_and_check_handshake`, checked before anything
//! else), then a `u32` little-endian length prefix + bincode-encoded
//! `Message` for `Auth`/`Register`. From there on the connection is handed to
//! `relay::mux::MuxSession`: a small pool of these physical connections per
//! tunnel carries many multiplexed logical streams, so opening a new proxied
//! connection is "open a mux stream" rather than "open a new physical
//! connection." `ForwardConn` is the first length-prefixed message on a
//! forward tunnel's data stream; `Ping`/`Pong` are the only messages ever
//! seen on a session's dedicated control stream.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_FRAME_BYTES: u32 = 1024 * 1024;

/// Arbitrary 4 bytes identifying a tunnelx handshake (spells "TNLX" in ASCII
/// when read as bytes), so a stray non-tunnelx peer or a wildly incompatible
/// old binary fails immediately with a clear error instead of a confusing
/// bincode decode failure somewhere downstream.
const PROTOCOL_MAGIC: u32 = 0x544e_4c58;
/// Bumped whenever the wire format changes in an incompatible way. Bumped to
/// 2 for the yamux multiplexing rewrite (removed `NewConnection`/`DataConn`,
/// renamed `RegisterReverse` to `Register`).
const PROTOCOL_VERSION: u32 = 2;

#[derive(Debug, Serialize, Deserialize)]
pub enum Message {
    /// First length-prefixed message on every physical connection (after the
    /// version handshake).
    Auth { token: String },
    AuthOk,
    AuthFail { reason: String },

    /// Sent by the client to register a physical connection into a tunnel's
    /// session pool — used by both forward and reverse tunnels.
    Register { name: String },
    RegisterOk,
    RegisterFail { reason: String },

    /// First message on a forward tunnel's data stream: proxy this stream to
    /// `target`, provided the server's config allows it for forward tunnel `name`.
    ForwardConn { name: String, target: String },

    Ping { ts_millis: u64 },
    Pong { ts_millis: u64 },
}

/// Written by both sides at the start of every new physical connection,
/// before `Auth`. Not bincode-framed like `Message` deliberately: it must be
/// decodable even by a peer running a wire-incompatible version.
pub async fn write_handshake<W: AsyncWrite + Unpin>(w: &mut W) -> Result<()> {
    let mut buf = [0u8; 8];
    buf[0..4].copy_from_slice(&PROTOCOL_MAGIC.to_le_bytes());
    buf[4..8].copy_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_and_check_handshake<R: AsyncRead + Unpin>(r: &mut R) -> Result<()> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf).await.context(
        "failed to read protocol handshake (peer closed early, wrong port, or an incompatible tunnelx binary)",
    )?;
    let magic = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    let version = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    if magic != PROTOCOL_MAGIC {
        bail!("not a tunnelx peer (bad protocol magic 0x{magic:08x})");
    }
    if version != PROTOCOL_VERSION {
        bail!(
            "protocol version mismatch: local={PROTOCOL_VERSION}, peer={version} — rebuild and restart both client and server together"
        );
    }
    Ok(())
}

pub async fn write_msg<W: AsyncWrite + Unpin>(w: &mut W, msg: &Message) -> Result<()> {
    let bytes = bincode::serialize(msg).context("failed to encode message")?;
    if bytes.len() as u64 > MAX_FRAME_BYTES as u64 {
        bail!("message too large: {} bytes", bytes.len());
    }
    w.write_all(&(bytes.len() as u32).to_le_bytes()).await?;
    w.write_all(&bytes).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_msg<R: AsyncRead + Unpin>(r: &mut R) -> Result<Message> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME_BYTES {
        bail!("incoming frame too large: {len} bytes");
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf).await?;
    bincode::deserialize(&buf).context("failed to decode message")
}
