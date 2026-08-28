use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use rand::Rng;
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Notify};
use tracing::{error, info, warn};

use crate::config::{ServerConfig, ServerTunnel};
use crate::relay::mux::{MuxSession, MuxStream};
use crate::relay::protocol::{self, read_msg, write_msg, Message};
use crate::relay::transport::{self, BoxedStream, TlsServerOpts};
use crate::util::{constant_time_eq, LogThrottle};

const ACCEPT_ERROR_LOG_WINDOW: Duration = Duration::from_secs(5);
const ACCEPT_ERROR_RETRY_DELAY: Duration = Duration::from_millis(50);
/// Client sends a keepalive Ping every 20s (see relay::client::KEEPALIVE_INTERVAL);
/// if nothing at all arrives on a session's control stream for this long it's
/// treated as dead and evicted, so new connections fail fast instead of hanging
/// on a registration that will never answer.
const CONTROL_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

struct State {
    config: ServerConfig,
    /// tunnel name -> pool of registered multiplexed sessions. Used
    /// symmetrically by both directions: a reverse tunnel opens streams on
    /// these to push public connections out to the client; a forward tunnel
    /// accepts streams the client opens on these, each carrying a `ForwardConn`.
    pools: Mutex<HashMap<String, Vec<Arc<MuxSession>>>>,
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

    let state = Arc::new(State { pools: Mutex::new(HashMap::new()), config });

    for tunnel in &state.config.tunnels {
        match tunnel {
            ServerTunnel::Reverse { name, remote_listen } => {
                spawn_public_listener(state.clone(), name.clone(), remote_listen.clone());
            }
            ServerTunnel::Forward { name, allowed_targets } if allowed_targets.is_empty() => {
                warn!(
                    name = %name,
                    "forward tunnel has no allowed_targets configured: anyone holding the token can reach any destination through this server"
                );
            }
            ServerTunnel::Forward { .. } => {}
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

/// Picks a live session at random from `name`'s pool, pruning dead ones along
/// the way. Used both to push a reverse stream out and to hand a forward
/// tunnel's inbound accept loop a session to watch (indirectly, via the pool
/// itself in `handle_register`).
async fn pick_session(state: &State, name: &str) -> Option<Arc<MuxSession>> {
    let mut pools = state.pools.lock().await;
    let sessions = pools.get_mut(name)?;
    sessions.retain(|s| !s.is_closed());
    if sessions.is_empty() {
        return None;
    }
    let idx = rand::thread_rng().gen_range(0..sessions.len());
    Some(sessions[idx].clone())
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
        let mut no_session_throttle = LogThrottle::new(ACCEPT_ERROR_LOG_WINDOW);
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

            let Some(session) = pick_session(&state, &name).await else {
                if let Some(suppressed) = no_session_throttle.allow() {
                    warn!(name = %name, peer = %peer, suppressed, "no client session registered for reverse tunnel, dropping connection(s)");
                }
                continue;
            };

            let name = name.clone();
            tokio::spawn(async move {
                let mut mux_stream = match session.open_stream().await {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(name = %name, peer = %peer, error = %e, "failed to open mux stream for reverse connection");
                        return;
                    }
                };
                let started = Instant::now();
                let mut public_stream = stream;
                let result = copy_bidirectional(&mut mux_stream, &mut public_stream).await;
                log_close(&name, peer, started, result);
            });
        }
    });
}

async fn handle_connection(state: Arc<State>, mut stream: BoxedStream, peer: SocketAddr) -> Result<()> {
    protocol::write_handshake(&mut stream).await?;
    protocol::read_and_check_handshake(&mut stream).await?;

    match read_msg(&mut stream).await? {
        Message::Auth { token } if constant_time_eq(&token, &state.config.token) => {
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
        Message::Register { name } => handle_register(state, stream, peer, name).await,
        other => {
            warn!(peer = %peer, message = ?other, "unexpected message after auth");
            Ok(())
        }
    }
}

/// Registers one physical connection into `name`'s session pool (used by
/// both forward and reverse tunnels), then dispatches every stream the peer
/// opens on it until the session is evicted (peer disconnected, errored, or
/// its control stream went idle).
async fn handle_register(state: Arc<State>, mut stream: BoxedStream, peer: SocketAddr, name: String) -> Result<()> {
    let known = state.config.tunnels.iter().any(|t| t.name() == name);
    if !known {
        write_msg(&mut stream, &Message::RegisterFail { reason: format!("unknown tunnel '{name}'") }).await?;
        return Ok(());
    }

    {
        let pools = state.pools.lock().await;
        let current = pools.get(&name).map(|sessions| sessions.len()).unwrap_or(0);
        if current >= state.config.max_sessions_per_tunnel {
            drop(pools);
            write_msg(
                &mut stream,
                &Message::RegisterFail {
                    reason: format!(
                        "too many sessions already registered for tunnel '{name}' (max {})",
                        state.config.max_sessions_per_tunnel
                    ),
                },
            )
            .await?;
            return Ok(());
        }
    }

    write_msg(&mut stream, &Message::RegisterOk).await?;
    info!(name = %name, peer = %peer, "tunnel session registered");

    let session = Arc::new(MuxSession::new(stream, yamux::Mode::Server));
    state.pools.lock().await.entry(name.clone()).or_default().push(session.clone());

    let idle_signal = Arc::new(Notify::new());

    loop {
        tokio::select! {
            maybe_stream = session.accept_stream() => match maybe_stream {
                Some(mux_stream) => {
                    let state = state.clone();
                    let name = name.clone();
                    let idle_signal = idle_signal.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_inbound_stream(state, name, peer, mux_stream, idle_signal).await {
                            warn!(peer = %peer, error = %e, "inbound mux stream handling failed");
                        }
                    });
                }
                None => break,
            },
            _ = idle_signal.notified() => {
                warn!(name = %name, peer = %peer, "session control stream idle/dead, evicting");
                break;
            }
        }
    }

    let mut pools = state.pools.lock().await;
    if let Some(pool) = pools.get_mut(&name) {
        pool.retain(|s| !Arc::ptr_eq(s, &session));
        if pool.is_empty() {
            pools.remove(&name);
        }
    }
    info!(name = %name, peer = %peer, "tunnel session disconnected");
    Ok(())
}

/// Every stream a registered session's peer opens lands here first: it's
/// either that session's one dedicated control/ping stream, or (for a
/// forward tunnel) a fresh `ForwardConn` data stream.
async fn handle_inbound_stream(
    state: Arc<State>,
    name: String,
    peer: SocketAddr,
    mut stream: MuxStream,
    idle_signal: Arc<Notify>,
) -> Result<()> {
    match read_msg(&mut stream).await? {
        Message::Ping { ts_millis } => handle_control_stream(name, peer, stream, ts_millis, idle_signal).await,
        Message::ForwardConn { name: fwd_name, target } => handle_forward_conn(state, peer, fwd_name, target, stream).await,
        other => {
            warn!(peer = %peer, message = ?other, "unexpected first message on mux stream");
            Ok(())
        }
    }
}

async fn handle_control_stream(
    name: String,
    peer: SocketAddr,
    mut stream: MuxStream,
    first_ts_millis: u64,
    idle_signal: Arc<Notify>,
) -> Result<()> {
    write_msg(&mut stream, &Message::Pong { ts_millis: first_ts_millis }).await?;
    loop {
        match tokio::time::timeout(CONTROL_IDLE_TIMEOUT, read_msg(&mut stream)).await {
            Ok(Ok(Message::Ping { ts_millis })) => {
                write_msg(&mut stream, &Message::Pong { ts_millis }).await?;
            }
            Ok(Ok(_)) => {}
            Ok(Err(_)) => break,
            Err(_elapsed) => {
                warn!(name = %name, peer = %peer, "control stream idle, treating session as dead");
                break;
            }
        }
    }
    idle_signal.notify_one();
    Ok(())
}

async fn handle_forward_conn(
    state: Arc<State>,
    peer: SocketAddr,
    name: String,
    target: String,
    mut stream: MuxStream,
) -> Result<()> {
    let rule = state.config.tunnels.iter().find_map(|t| match t {
        ServerTunnel::Forward { name: n, allowed_targets } if n == &name => Some(allowed_targets.clone()),
        _ => None,
    });

    let Some(allowed_targets) = rule else {
        warn!(name = %name, peer = %peer, "forward request for unknown/non-forward tunnel name");
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

fn log_close(name: &str, peer: SocketAddr, started: Instant, result: std::io::Result<(u64, u64)>) {
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
