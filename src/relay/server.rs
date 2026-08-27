use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tracing::{error, info, warn};

use crate::config::{ServerConfig, ServerTunnel};
use crate::relay::protocol::{read_msg, write_msg, Message};
use crate::relay::transport::{self, BoxedStream, TlsServerOpts};
use crate::util::LogThrottle;

const PENDING_CONN_TIMEOUT: Duration = Duration::from_secs(10);
const ACCEPT_ERROR_LOG_WINDOW: Duration = Duration::from_secs(5);
const ACCEPT_ERROR_RETRY_DELAY: Duration = Duration::from_millis(50);

struct State {
    config: ServerConfig,
    /// tunnel name -> channel to push messages (mainly `NewConnection`) to that
    /// tunnel's currently-registered control connection writer task.
    reverse_controls: Mutex<HashMap<String, mpsc::UnboundedSender<Message>>>,
    /// conn_id -> the public TcpStream (plus its peer addr, captured at accept
    /// time since it can't be reliably read back off the socket later) waiting
    /// to be paired with a data connection.
    pending: Mutex<HashMap<u64, (TcpStream, std::net::SocketAddr)>>,
    next_conn_id: AtomicU64,
}

pub async fn run(config: ServerConfig) -> Result<()> {
    let tls_opts = if config.transport.is_tls() {
        Some(TlsServerOpts {
            cert: config.tls_cert.clone().expect("validated"),
            key: config.tls_key.clone().expect("validated"),
        })
    } else {
        None
    };

    let listen_addr = config.listen.clone();
    let transport_kind = config.transport;

    let state = Arc::new(State {
        reverse_controls: Mutex::new(HashMap::new()),
        pending: Mutex::new(HashMap::new()),
        next_conn_id: AtomicU64::new(1),
        config,
    });

    for tunnel in &state.config.tunnels {
        if let ServerTunnel::Reverse { name, remote_listen } = tunnel {
            spawn_public_listener(state.clone(), name.clone(), remote_listen.clone());
        }
    }

    let listener = transport::bind(transport_kind, &listen_addr, tls_opts.as_ref())
        .await
        .with_context(|| format!("failed to bind control listener on {listen_addr}"))?;

    info!(listen = %listen_addr, transport = ?transport_kind, "relay server listening");

    let mut accept_error_throttle = LogThrottle::new(ACCEPT_ERROR_LOG_WINDOW);
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                if let Some(suppressed) = accept_error_throttle.allow() {
                    error!(error = %e, suppressed, "accept failed");
                }
                tokio::time::sleep(ACCEPT_ERROR_RETRY_DELAY).await;
                continue;
            }
        };
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(state, stream, peer).await {
                warn!(peer = %peer, error = %e, "connection handling failed");
            }
        });
    }
}

fn spawn_public_listener(state: Arc<State>, name: String, remote_listen: String) {
    tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(&remote_listen).await {
            Ok(l) => l,
            Err(e) => {
                error!(name = %name, listen = %remote_listen, error = %e, "failed to bind reverse tunnel public listener");
                return;
            }
        };
        info!(name = %name, listen = %remote_listen, "reverse tunnel public listener up");

        let mut accept_error_throttle = LogThrottle::new(ACCEPT_ERROR_LOG_WINDOW);
        let mut no_client_throttle = LogThrottle::new(ACCEPT_ERROR_LOG_WINDOW);
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(p) => p,
                Err(e) => {
                    if let Some(suppressed) = accept_error_throttle.allow() {
                        error!(name = %name, error = %e, suppressed, "accept failed on public listener");
                    }
                    tokio::time::sleep(ACCEPT_ERROR_RETRY_DELAY).await;
                    continue;
                }
            };
            stream.set_nodelay(true).ok();

            let control = state.reverse_controls.lock().await.get(&name).cloned();
            let Some(control) = control else {
                if let Some(suppressed) = no_client_throttle.allow() {
                    warn!(name = %name, peer = %peer, suppressed, "no client connected for reverse tunnel, dropping connection(s)");
                }
                continue;
            };

            let conn_id = state.next_conn_id.fetch_add(1, Ordering::Relaxed);
            state.pending.lock().await.insert(conn_id, (stream, peer));

            if control.send(Message::NewConnection { conn_id }).is_err() {
                state.pending.lock().await.remove(&conn_id);
                warn!(name = %name, peer = %peer, "control connection gone, dropping connection");
                continue;
            }

            let state = state.clone();
            tokio::spawn(async move {
                tokio::time::sleep(PENDING_CONN_TIMEOUT).await;
                if state.pending.lock().await.remove(&conn_id).is_some() {
                    warn!(conn_id, "timed out waiting for client to open data connection");
                }
            });
        }
    });
}

async fn handle_connection(state: Arc<State>, mut stream: BoxedStream, peer: std::net::SocketAddr) -> Result<()> {
    match read_msg(&mut stream).await? {
        Message::Auth { token } if token == state.config.token => {
            write_msg(&mut stream, &Message::AuthOk).await?;
        }
        Message::Auth { .. } => {
            write_msg(&mut stream, &Message::AuthFail { reason: "invalid token".into() }).await?;
            return Ok(());
        }
        other => {
            warn!(peer = %peer, message = ?other, "expected auth as first message");
            return Ok(());
        }
    }

    match read_msg(&mut stream).await? {
        Message::RegisterReverse { name } => handle_register_reverse(state, stream, peer, name).await,
        Message::ForwardConn { name, target } => handle_forward_conn(state, stream, peer, name, target).await,
        Message::DataConn { conn_id } => handle_data_conn(state, stream, conn_id).await,
        other => {
            warn!(peer = %peer, message = ?other, "unexpected message after auth");
            Ok(())
        }
    }
}

async fn handle_register_reverse(
    state: Arc<State>,
    stream: BoxedStream,
    peer: std::net::SocketAddr,
    name: String,
) -> Result<()> {
    let is_reverse = state
        .config
        .tunnels
        .iter()
        .any(|t| matches!(t, ServerTunnel::Reverse { name: n, .. } if n == &name));

    let (mut read_half, mut write_half) = tokio::io::split(stream);

    if !is_reverse {
        write_msg(&mut write_half, &Message::RegisterFail { reason: format!("unknown reverse tunnel '{name}'") }).await?;
        return Ok(());
    }

    write_msg(&mut write_half, &Message::RegisterOk).await?;
    info!(name = %name, peer = %peer, "reverse tunnel client connected");

    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
    state.reverse_controls.lock().await.insert(name.clone(), tx.clone());

    let writer_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if write_msg(&mut write_half, &msg).await.is_err() {
                break;
            }
        }
    });

    loop {
        match read_msg(&mut read_half).await {
            Ok(Message::Ping { ts_millis }) => {
                if tx.send(Message::Pong { ts_millis }).is_err() {
                    break;
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }

    writer_task.abort();
    // Only remove the registry entry if it's still ours (a newer reconnect may
    // have already replaced it).
    let mut controls = state.reverse_controls.lock().await;
    if let Some(current) = controls.get(&name) {
        if current.same_channel(&tx) {
            controls.remove(&name);
        }
    }
    info!(name = %name, peer = %peer, "reverse tunnel client disconnected");
    Ok(())
}

async fn handle_forward_conn(
    state: Arc<State>,
    mut stream: BoxedStream,
    peer: std::net::SocketAddr,
    name: String,
    target: String,
) -> Result<()> {
    let rule = state.config.tunnels.iter().find_map(|t| match t {
        ServerTunnel::Forward { name: n, allowed_targets } if n == &name => Some(allowed_targets.clone()),
        _ => None,
    });

    let Some(allowed_targets) = rule else {
        warn!(name = %name, peer = %peer, "forward request for unknown tunnel name");
        return Ok(());
    };

    if !allowed_targets.is_empty() && !allowed_targets.iter().any(|t| t == &target) {
        warn!(name = %name, peer = %peer, target = %target, "forward target not in allowed_targets, rejecting");
        return Ok(());
    }

    let mut outbound = match TcpStream::connect(&target).await {
        Ok(s) => s,
        Err(e) => {
            warn!(name = %name, peer = %peer, target = %target, error = %e, "dial failed");
            return Ok(());
        }
    };
    outbound.set_nodelay(true).ok();

    info!(name = %name, peer = %peer, target = %target, "forward connection open");
    let started = Instant::now();
    let result = copy_bidirectional(&mut stream, &mut outbound).await;
    log_close(&name, peer, started, result);
    Ok(())
}

async fn handle_data_conn(state: Arc<State>, mut stream: BoxedStream, conn_id: u64) -> Result<()> {
    let Some((mut public_stream, peer)) = state.pending.lock().await.remove(&conn_id) else {
        warn!(conn_id, "data connection for unknown or expired conn_id");
        return Ok(());
    };

    let started = Instant::now();
    let result = copy_bidirectional(&mut stream, &mut public_stream).await;
    log_close("reverse", peer, started, result);
    Ok(())
}

fn log_close(
    name: &str,
    peer: std::net::SocketAddr,
    started: Instant,
    result: std::io::Result<(u64, u64)>,
) {
    let elapsed = started.elapsed();
    match result {
        Ok((tx, rx)) => info!(
            name = %name, peer = %peer, sent = tx, received = rx,
            duration_ms = elapsed.as_millis(), "connection closed"
        ),
        Err(e) => warn!(
            name = %name, peer = %peer, duration_ms = elapsed.as_millis(), error = %e,
            "connection closed with error"
        ),
    }
}
