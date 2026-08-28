//! Adapts a `WebSocketStream<S>` into `AsyncRead + AsyncWrite` so the rest of
//! the relay code (protocol framing, byte piping) doesn't need to know it's
//! talking over WebSocket frames instead of a raw stream.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::{Context as _, Result};
use bytes::{Buf, BytesMut};
use futures_util::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{accept_async, client_async, WebSocketStream};

pub struct WsIo<S> {
    inner: WebSocketStream<S>,
    read_buf: BytesMut,
}

impl<S> WsIo<S> {
    fn new(inner: WebSocketStream<S>) -> Self {
        Self { inner, read_buf: BytesMut::new() }
    }
}

pub async fn accept<S>(stream: S) -> Result<WsIo<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let ws = accept_async(stream).await.context("websocket handshake (accept) failed")?;
    Ok(WsIo::new(ws))
}

pub async fn connect<S>(stream: S, addr: &str) -> Result<WsIo<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let url = format!("ws://{addr}/tunnelx");
    let (ws, _resp) = client_async(url, stream).await.context("websocket handshake (connect) failed")?;
    Ok(WsIo::new(ws))
}

impl<S> AsyncRead for WsIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        loop {
            if !self.read_buf.is_empty() {
                let n = std::cmp::min(buf.remaining(), self.read_buf.len());
                buf.put_slice(&self.read_buf[..n]);
                self.read_buf.advance(n);
                return Poll::Ready(Ok(()));
            }

            match Pin::new(&mut self.inner).poll_next(cx) {
                Poll::Ready(Some(Ok(msg))) => {
                    if msg.is_binary() || msg.is_text() {
                        self.read_buf = BytesMut::from(msg.into_data().as_slice());
                        continue;
                    }
                    if msg.is_close() {
                        return Poll::Ready(Ok(()));
                    }
                    // Ping/Pong/Frame: tungstenite handles the protocol-level
                    // reply internally; nothing for us to forward as data.
                    continue;
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> AsyncWrite for WsIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                let msg = Message::binary(buf.to_vec());
                match Pin::new(&mut self.inner).start_send(msg) {
                    Ok(()) => Poll::Ready(Ok(buf.len())),
                    Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Deliberately does NOT send a WebSocket Close frame here.
        //
        // A WS Close is a whole-connection teardown, not a half-close like
        // TCP's shutdown(SHUT_WR): once sent (or once tungstenite auto-echoes
        // a peer's Close), any further data send on this connection fails
        // with "Sending after closing is not allowed". `copy_bidirectional`
        // calls `shutdown()` on one direction as soon as its read side hits
        // EOF, which used to trigger exactly that — a still-active peer
        // direction sharing this same socket would get its in-flight data
        // silently dropped and the whole proxied connection aborted.
        //
        // Since the yamux multiplexing layer was introduced, `WsIo` is only
        // ever the transport underneath a `relay::mux::MuxSession` — nothing
        // calls `copy_bidirectional` directly on it anymore (that now only
        // ever runs on individual `yamux::Stream`s, which have their own
        // real per-stream half-close). So this no-op should rarely if ever
        // actually fire in practice; it's kept as cheap, correct-regardless-
        // of-caller insurance. The underlying TCP/TLS socket is still torn
        // down for real when `WsIo` (and the `yamux::Connection` above it) is
        // dropped once the session ends.
        Poll::Ready(Ok(()))
    }
}
