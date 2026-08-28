//! Multiplexes many logical byte streams over one already-connected,
//! already-authenticated physical connection, using `yamux`. This is what
//! lets opening a new proxied connection become "open a stream on an
//! already-live session" instead of a brand new TCP+TLS+WS handshake.
//!
//! `yamux::Connection` is deliberately low-level (as of yamux 0.12, its
//! `Control` convenience handle was removed): `poll_new_outbound` and
//! `poll_next_inbound` both take `&mut self`, and `poll_next_inbound` must be
//! polled continuously for the connection to make *any* progress at all
//! (flushing writes, processing incoming frames), not just to accept new
//! inbound streams. `MuxSession` exists to let arbitrary other tasks open
//! outbound streams and accept inbound ones without needing to touch the
//! `Connection` directly: a single spawned driver task owns it exclusively
//! and services requests from everyone else through channels.

use std::future::poll_fn;
use std::task::Poll;

use anyhow::{anyhow, Result};
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::{debug, warn};

use crate::relay::transport::BoxedStream;

/// Bounds on the internal request/inbound queues. Independent of yamux's own
/// `max_num_streams` (which bounds concurrently *open* streams, default 512)
/// — these just bound how many open-requests/accepted-but-unclaimed streams
/// may be queued up inside this process before a caller backs off.
const OPEN_QUEUE_CAPACITY: usize = 128;
const INBOUND_QUEUE_CAPACITY: usize = 128;

/// A tokio-compatible handle to one multiplexed logical stream — usable
/// directly as either side of `tokio::io::copy_bidirectional`, exactly like
/// the raw `BoxedStream` was before multiplexing.
pub type MuxStream = Compat<yamux::Stream>;

type OpenReply = oneshot::Sender<Result<yamux::Stream>>;

/// One physical connection, multiplexed via yamux. Backed by a single driver
/// task that is the sole owner of the underlying `yamux::Connection`; this
/// handle only ever talks to that task through channels.
///
/// Always shared via `Arc<MuxSession>` — deliberately not `Clone` itself, so
/// there is exactly one `open_tx` sender in existence per session, which
/// makes "every handle dropped" detectable for free as "the driver's request
/// channel closed" (see `is_closed`), with no extra shutdown signal needed.
pub struct MuxSession {
    open_tx: mpsc::Sender<OpenReply>,
    inbound_rx: AsyncMutex<mpsc::Receiver<yamux::Stream>>,
}

impl MuxSession {
    /// Wraps an already-connected, already-authenticated physical connection
    /// in a yamux session and spawns the task that drives it. `mode` reflects
    /// which end *dialed* this physical connection (`Client` if we dialed
    /// out, `Server` if we accepted it) — unrelated to whether the tunnel
    /// itself is configured as `forward` or `reverse`.
    pub fn new(io: BoxedStream, mode: yamux::Mode) -> Self {
        let connection = yamux::Connection::new(io.compat(), yamux::Config::default(), mode);

        let (open_tx, open_rx) = mpsc::channel(OPEN_QUEUE_CAPACITY);
        let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_QUEUE_CAPACITY);

        tokio::spawn(drive(connection, open_rx, inbound_tx));

        Self { open_tx, inbound_rx: AsyncMutex::new(inbound_rx) }
    }

    /// Opens a new outbound logical stream. May be called concurrently from
    /// many tasks against the same `Arc<MuxSession>`.
    pub async fn open_stream(&self) -> Result<MuxStream> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.open_tx.send(reply_tx).await.map_err(|_| anyhow!("mux session driver has exited"))?;
        let stream = match reply_rx.await {
            Ok(result) => result?,
            Err(_) => return Err(anyhow!("mux session driver dropped the open-stream request")),
        };
        Ok(stream.compat())
    }

    /// Accepts the next inbound logical stream opened by the peer. Returns
    /// `None` once the physical connection is closed/errored — no more
    /// inbound streams will ever arrive. Intended to be driven by exactly one
    /// long-running "accept loop" task per session; the mutex around the
    /// receiver is for interior-mutability convenience, not concurrent
    /// fan-out (a stream handed to one caller can't also go to another).
    pub async fn accept_stream(&self) -> Option<MuxStream> {
        let mut rx = self.inbound_rx.lock().await;
        rx.recv().await.map(FuturesAsyncReadCompatExt::compat)
    }

    /// True once the driver task has exited (physical connection dead). Pool
    /// management code can use this to skip a session without first waiting
    /// for an `open_stream()` call against it to fail.
    pub fn is_closed(&self) -> bool {
        self.open_tx.is_closed()
    }
}

enum DriverStep {
    Opened(OpenReply, Result<yamux::Stream, yamux::ConnectionError>),
    Inbound(Option<Result<yamux::Stream, yamux::ConnectionError>>),
    NoMoreHandles,
}

async fn drive(
    mut connection: yamux::Connection<Compat<BoxedStream>>,
    mut open_rx: mpsc::Receiver<OpenReply>,
    inbound_tx: mpsc::Sender<yamux::Stream>,
) {
    // At most one outbound-open request is "in flight" against the
    // connection at a time; further requests queue up in `open_rx` (bounded,
    // see OPEN_QUEUE_CAPACITY) until this one resolves. This slot exists so
    // that once a request has been pulled off `open_rx` it's never lost on a
    // `Poll::Pending` from `poll_new_outbound`.
    let mut in_flight_open: Option<OpenReply> = None;

    loop {
        let step = poll_fn(|cx| {
            if in_flight_open.is_none() {
                match open_rx.poll_recv(cx) {
                    Poll::Ready(Some(reply)) => in_flight_open = Some(reply),
                    Poll::Ready(None) => return Poll::Ready(DriverStep::NoMoreHandles),
                    Poll::Pending => {}
                }
            }
            if in_flight_open.is_some() {
                if let Poll::Ready(res) = connection.poll_new_outbound(cx) {
                    let reply = in_flight_open.take().expect("checked is_some above");
                    return Poll::Ready(DriverStep::Opened(reply, res));
                }
            }
            connection.poll_next_inbound(cx).map(DriverStep::Inbound)
        })
        .await;

        match step {
            DriverStep::Opened(reply, res) => {
                let _ = reply.send(res.map_err(|e| anyhow!("failed to open outbound mux stream: {e}")));
            }
            DriverStep::Inbound(Some(Ok(stream))) => {
                // If the bounded channel is full because nobody is currently
                // calling accept_stream(), this backpressures poll_next_inbound
                // too (fine: yamux buffers at the protocol level up to its own
                // limits) rather than dropping the stream.
                let _ = inbound_tx.send(stream).await;
            }
            DriverStep::Inbound(Some(Err(e))) => {
                warn!(error = %e, "yamux connection error, tearing down session");
                break;
            }
            DriverStep::Inbound(None) => {
                debug!("yamux connection closed");
                break;
            }
            DriverStep::NoMoreHandles => break,
        }
    }

    // Fail anything still waiting so callers get an error instead of hanging.
    if let Some(reply) = in_flight_open.take() {
        let _ = reply.send(Err(anyhow!("mux session closed")));
    }
    while let Ok(reply) = open_rx.try_recv() {
        let _ = reply.send(Err(anyhow!("mux session closed")));
    }
    // Dropping `connection` here closes the physical BoxedStream. Dropping
    // `inbound_tx` (end of fn) wakes any in-progress accept_stream() with None.
}
