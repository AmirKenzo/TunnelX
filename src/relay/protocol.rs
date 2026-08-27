//! Wire format for the relay client<->server control/data connections.
//!
//! Every message is a `u32` little-endian length prefix followed by that many
//! bytes of bincode-encoded `Message`. Kept deliberately flat (no multiplexing
//! layer): a forward tunnel opens one physical connection per proxied
//! connection; a reverse tunnel keeps one long-lived control connection per
//! tunnel plus one short-lived data connection per proxied connection.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_FRAME_BYTES: u32 = 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub enum Message {
    /// First message on every connection (control or data).
    Auth { token: String },
    AuthOk,
    AuthFail { reason: String },

    /// Sent by the client to open a persistent control connection for a reverse tunnel.
    RegisterReverse { name: String },
    RegisterOk,
    RegisterFail { reason: String },

    /// Server -> client on a reverse tunnel's control connection: a public
    /// connection arrived, please open a data connection for it.
    NewConnection { conn_id: u64 },
    /// Client -> server on a brand new connection: this is the data connection
    /// for `conn_id` requested above.
    DataConn { conn_id: u64 },

    /// Client -> server on a brand new connection: proxy this connection to
    /// `target`, provided the server's config allows it for forward tunnel `name`.
    ForwardConn { name: String, target: String },

    Ping { ts_millis: u64 },
    Pong { ts_millis: u64 },
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
