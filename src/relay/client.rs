use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use rand::Rng;
use tokio::io::copy_bidirectional;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::config::{ClientConfig, ClientTunnel};
use crate::relay::mux::{MuxSession, MuxStream};
use crate::relay::protocol::{self, read_msg, write_msg, Message};
use crate::relay::transport::{self, TlsClientOpts};
use crate::util::LogThrottle;

const ACCEPT_ERROR_LOG_WINDOW: Duration = Duration::from_secs(5);
const ACCEPT_ERROR_RETRY_DELAY: Duration = Duration::from_millis(50);

const RECONNECT_BACKOFF: [Duration; 5] = [
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(5),
    Duration::from_secs(10),
];

pub async fn run(config: ClientConfig) -> Result<()> {
    let tls_opts = Arc::new(TlsClientOpts { ca_cert: config.tls_ca_cert.clone(), insecure: config.tls_insecure });
    let config = Arc::new(config);

    let mut tasks = Vec::new();
    for tunnel in config.tunnels.clone() {
        let config = config.clone();
        let tls_opts = tls_opts.clone();
        tasks.push(tokio::spawn(async move {
            match tunnel {
                ClientTunnel::Forward { name, local_listen, remote_target } => {
                    if let Err(e) = run_forward(config, tls_opts, name.clone(), local_listen, remote_target).await {
                        error!(name = %name, error = %e, "forward tunnel stopped");
                    }
                }
                ClientTunnel::Reverse { name, local_target } => {
                    run_reverse_with_backoff(config, tls_opts, name, local_target).await;
                }
            }
        }));
    }

    for t in tasks {
        let _ = t.await;
    }
    Ok(())
}

const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);
/// Jitter applied to each keepalive delay (+/-), so pings don't go out on an
/// exact, perfectly periodic 20.000s cadence that's trivial to fingerprint
/// from traffic timing alone.
const KEEPALIVE_JITTER: Duration = Duration::from_secs(4);
const PING_TIMEOUT: Duration = Duration::from_secs(5);
/// If no pong has been seen for this long, the session's control stream is
/// treated as dead even though reads/writes on it haven't errored (e.g.
/// traffic silently black-holed instead of RST/FIN'd) so we reconnect instead
/// of waiting indefinitely for a link that will never come back.
const PONG_TIMEOUT: Duration = Duration::from_secs(45);

fn next_keepalive_delay() -> Duration {
    let jitter_ms = rand::thread_rng().gen_range(0..=KEEPALIVE_JITTER.as_millis() as u64 * 2);
    (KEEPALIVE_INTERVAL - KEEPALIVE_JITTER) + Duration::from_millis(jitter_ms)
}

fn now_millis() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

async fn authenticate<S>(stream: &mut S, token: &str) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    write_msg(stream, &Message::Auth { token: token.to_string() }).await?;
    match read_msg(stream).await? {
        Message::AuthOk => Ok(()),
        Message::AuthFail { reason } => bail!("authentication rejected by server: {reason}"),
        other => bail!("unexpected response to auth: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// shared: a pool of multiplexed physical sessions per tunnel. Opening a new
// proxied connection means picking a live session and opening a stream on it
// instead of dialing a brand new physical connection.
// ---------------------------------------------------------------------------

type SessionPool = Arc<Mutex<Vec<Arc<MuxSession>>>>;

async fn pick_session(pool: &SessionPool) -> Option<Arc<MuxSession>> {
    let mut sessions = pool.lock().await;
    sessions.retain(|s| !s.is_closed());
    if sessions.is_empty() {
        return None;
    }
    let idx = rand::thread_rng().gen_range(0..sessions.len());
    Some(sessions[idx].clone())
}

/// Dials, version-checks, authenticates, and registers one physical
/// connection, then wraps it as a multiplexed session. Used to establish
/// every pooled session for both forward and reverse tunnels.
async fn establish_pooled_session(config: &ClientConfig, tls: &TlsClientOpts, name: &str) -> Result<MuxSession> {
    let mut stream = transport::dial(config.transport, &config.server, tls)
        .await
        .context("failed to connect to server")?;
    protocol::write_handshake(&mut stream).await?;
    protocol::read_and_check_handshake(&mut stream).await?;
    authenticate(&mut stream, &config.token).await?;

    write_msg(&mut stream, &Message::Register { name: name.to_string() }).await?;
    match read_msg(&mut stream).await? {
        Message::RegisterOk => {}
        Message::RegisterFail { reason } => bail!("server rejected registration: {reason}"),
        other => bail!("unexpected response to register: {other:?}"),
    }

    Ok(MuxSession::new(stream, yamux::Mode::Client))
}

/// Opens this session's one dedicated control stream, verifies it round-trips,
/// then keeps pinging it on a jittered interval for the life of the session —
/// the same liveness contract every pooled session (forward or reverse) needs.
async fn run_ping_stream(session: &MuxSession, name: &str) -> Result<()> {
    let ping_stream = session.open_stream().await.context("failed to open control/ping stream")?;
    let (mut read_half, mut write_half) = tokio::io::split(ping_stream);

    // Verify the control stream actually round-trips before declaring the
    // session up, rather than just trusting that RegisterOk means it's healthy.
    let verify_ts = now_millis();
    write_msg(&mut write_half, &Message::Ping { ts_millis: verify_ts }).await?;
    match tokio::time::timeout(PING_TIMEOUT, read_msg(&mut read_half)).await {
        Ok(Ok(Message::Pong { ts_millis })) => {
            info!(name = %name, rtt_ms = now_millis().saturating_sub(ts_millis), "pooled session control stream verified");
        }
        Ok(Ok(other)) => bail!("expected pong to verify control stream, got {other:?}"),
        Ok(Err(e)) => return Err(e),
        Err(_) => bail!("no response to initial ping, control stream appears unhealthy"),
    }

    let mut last_pong = Instant::now();
    loop {
        let keepalive = tokio::time::sleep(next_keepalive_delay());
        tokio::select! {
            msg = read_msg(&mut read_half) => {
                match msg? {
                    Message::Pong { ts_millis } => {
                        last_pong = Instant::now();
                        tracing::debug!(name = %name, rtt_ms = now_millis().saturating_sub(ts_millis), "keepalive pong received");
                    }
                    other => warn!(name = %name, message = ?other, "unexpected message on control stream"),
                }
            }
            _ = keepalive => {
                if last_pong.elapsed() > PONG_TIMEOUT {
                    bail!("no pong received in over {:?}, session appears dead", PONG_TIMEOUT);
                }
                write_msg(&mut write_half, &Message::Ping { ts_millis: now_millis() }).await?;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// forward tunnels: listen locally, keep a pool of pre-authenticated sessions
// to the server, open a mux stream on one per accepted local connection.
// ---------------------------------------------------------------------------

async fn run_forward(
    config: Arc<ClientConfig>,
    tls: Arc<TlsClientOpts>,
    name: String,
    local_listen: String,
    remote_target: String,
) -> Result<()> {
    let listener = TcpListener::bind(&local_listen)
        .await
        .with_context(|| format!("tunnel '{name}': failed to bind {local_listen}"))?;

    info!(name = %name, listen = %local_listen, server = %config.server, remote_target = %remote_target, "forward tunnel listening");

    let pool: SessionPool = Arc::new(Mutex::new(Vec::new()));
    for _ in 0..config.mux_connections {
        tokio::spawn(run_forward_session_with_backoff(config.clone(), tls.clone(), name.clone(), pool.clone()));
    }

    let mut accept_error_throttle = LogThrottle::new(ACCEPT_ERROR_LOG_WINDOW);
    loop {
        let (inbound, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                if let Some(suppressed) = accept_error_throttle.allow() {
                    error!(name = %name, error = %e, suppressed, "accept failed");
                }
                tokio::time::sleep(ACCEPT_ERROR_RETRY_DELAY).await;
                continue;
            }
        };
        inbound.set_nodelay(true).ok();

        let pool = pool.clone();
        let name = name.clone();
        let remote_target = remote_target.clone();

        tokio::spawn(async move {
            let started = Instant::now();
            match handle_forward_conn(inbound, &pool, &name, &remote_target).await {
                Ok((tx, rx)) => info!(
                    name = %name, peer = %peer, sent = tx, received = rx,
                    duration_ms = started.elapsed().as_millis(), "forward connection closed"
                ),
                Err(e) => warn!(name = %name, peer = %peer, error = %e, "forward connection failed"),
            }
        });
    }
}

async fn handle_forward_conn(
    mut inbound: tokio::net::TcpStream,
    pool: &SessionPool,
    name: &str,
    remote_target: &str,
) -> Result<(u64, u64)> {
    let session = pick_session(pool).await.context("no healthy pooled session available for this tunnel")?;
    let mut stream = session.open_stream().await.context("failed to open mux stream")?;
    write_msg(&mut stream, &Message::ForwardConn { name: name.to_string(), target: remote_target.to_string() }).await?;

    let (tx, rx) = copy_bidirectional(&mut inbound, &mut stream).await?;
    Ok((tx, rx))
}

async fn run_forward_session_with_backoff(config: Arc<ClientConfig>, tls: Arc<TlsClientOpts>, name: String, pool: SessionPool) {
    let mut attempt = 0usize;
    loop {
        let result = run_forward_session_once(&config, &tls, &name, &pool).await;
        match result {
            Ok(()) => attempt = 0,
            Err(e) => warn!(name = %name, error = %e, "pooled forward session lost"),
        }

        let delay = RECONNECT_BACKOFF[attempt.min(RECONNECT_BACKOFF.len() - 1)];
        attempt += 1;
        info!(name = %name, delay_ms = delay.as_millis(), "reconnecting pooled forward session");
        tokio::time::sleep(delay).await;
    }
}

async fn run_forward_session_once(config: &ClientConfig, tls: &TlsClientOpts, name: &str, pool: &SessionPool) -> Result<()> {
    let session = Arc::new(establish_pooled_session(config, tls, name).await?);
    pool.lock().await.push(session.clone());
    let result = run_ping_stream(&session, name).await;
    // Forceful, immediate teardown -- not just removing our clone from the
    // pool -- so the physical socket doesn't linger open for however long a
    // concurrent handle_forward_conn() that already grabbed this session is
    // still relaying traffic through it.
    session.close();
    pool.lock().await.retain(|s| !Arc::ptr_eq(s, &session));
    result
}

// ---------------------------------------------------------------------------
// reverse tunnels: keep a pool of pre-authenticated, pre-registered sessions;
// on each stream the server opens against one, proxy it to local_target.
// ---------------------------------------------------------------------------

async fn run_reverse_with_backoff(config: Arc<ClientConfig>, tls: Arc<TlsClientOpts>, name: String, local_target: String) {
    let pool: SessionPool = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::new();
    for _ in 0..config.mux_connections {
        handles.push(tokio::spawn(run_reverse_session_with_backoff(
            config.clone(),
            tls.clone(),
            name.clone(),
            local_target.clone(),
            pool.clone(),
        )));
    }
    for h in handles {
        let _ = h.await;
    }
}

async fn run_reverse_session_with_backoff(
    config: Arc<ClientConfig>,
    tls: Arc<TlsClientOpts>,
    name: String,
    local_target: String,
    pool: SessionPool,
) {
    let mut attempt = 0usize;
    loop {
        match run_reverse_session_once(&config, &tls, &name, &local_target, &pool).await {
            Ok(()) => attempt = 0,
            Err(e) => warn!(name = %name, error = %e, "pooled reverse session lost"),
        }

        let delay = RECONNECT_BACKOFF[attempt.min(RECONNECT_BACKOFF.len() - 1)];
        attempt += 1;
        info!(name = %name, delay_ms = delay.as_millis(), "reconnecting pooled reverse session");
        tokio::time::sleep(delay).await;
    }
}

async fn run_reverse_session_once(
    config: &ClientConfig,
    tls: &TlsClientOpts,
    name: &str,
    local_target: &str,
    pool: &SessionPool,
) -> Result<()> {
    let session = Arc::new(establish_pooled_session(config, tls, name).await?);
    pool.lock().await.push(session.clone());
    info!(
        name = %name, server = %config.server, local_target = %local_target,
        "pooled reverse session registered, waiting for connections"
    );

    let result = tokio::select! {
        r = run_ping_stream(&session, name) => r,
        r = accept_reverse_connections(&session, name, local_target) => r,
    };

    // See the matching comment in run_forward_session_once: forceful,
    // immediate teardown so an in-flight reverse data stream elsewhere can't
    // keep this physical socket open indefinitely after we've declared the
    // session dead.
    session.close();
    pool.lock().await.retain(|s| !Arc::ptr_eq(s, &session));
    result
}

async fn accept_reverse_connections(session: &MuxSession, name: &str, local_target: &str) -> Result<()> {
    loop {
        let mux_stream = session.accept_stream().await.ok_or_else(|| anyhow!("mux session closed"))?;
        let name = name.to_string();
        let local_target = local_target.to_string();
        tokio::spawn(async move {
            if let Err(e) = handle_reverse_data_stream(mux_stream, &local_target).await {
                warn!(name = %name, error = %e, "reverse data stream failed");
            }
        });
    }
}

async fn handle_reverse_data_stream(mut mux_stream: MuxStream, local_target: &str) -> Result<()> {
    let mut local = tokio::net::TcpStream::connect(local_target)
        .await
        .with_context(|| format!("failed to dial local target {local_target}"))?;
    local.set_nodelay(true).ok();

    copy_bidirectional(&mut mux_stream, &mut local).await?;
    Ok(())
}
