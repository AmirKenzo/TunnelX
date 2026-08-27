use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use tokio::io::copy_bidirectional;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use crate::config::{ClientConfig, ClientTunnel};
use crate::relay::protocol::{read_msg, write_msg, Message};
use crate::relay::transport::{self, TlsClientOpts};

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
                    if let Err(e) = run_forward(&config, &tls_opts, &name, &local_listen, &remote_target).await {
                        error!(name = %name, error = %e, "forward tunnel stopped");
                    }
                }
                ClientTunnel::Reverse { name, local_target } => {
                    run_reverse_with_backoff(&config, &tls_opts, name, local_target).await;
                }
            }
        }));
    }

    for t in tasks {
        let _ = t.await;
    }
    Ok(())
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
// forward tunnels: listen locally, dial the server once per connection.
// ---------------------------------------------------------------------------

async fn run_forward(
    config: &ClientConfig,
    tls: &TlsClientOpts,
    name: &str,
    local_listen: &str,
    remote_target: &str,
) -> Result<()> {
    let listener = TcpListener::bind(local_listen)
        .await
        .with_context(|| format!("tunnel '{name}': failed to bind {local_listen}"))?;

    info!(name = %name, listen = %local_listen, server = %config.server, remote_target = %remote_target, "forward tunnel listening");

    loop {
        let (inbound, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                error!(name = %name, error = %e, "accept failed");
                continue;
            }
        };
        inbound.set_nodelay(true).ok();

        let name = name.to_string();
        let remote_target = remote_target.to_string();
        let server_addr = config.server.clone();
        let transport_kind = config.transport;
        let token = config.token.clone();
        let tls = tls.clone();

        tokio::spawn(async move {
            let started = Instant::now();
            match handle_forward_conn(inbound, &server_addr, transport_kind, &tls, &token, &name, &remote_target).await
            {
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
    server_addr: &str,
    transport_kind: transport::Kind,
    tls: &TlsClientOpts,
    token: &str,
    name: &str,
    remote_target: &str,
) -> Result<(u64, u64)> {
    let mut stream = transport::dial(transport_kind, server_addr, tls)
        .await
        .context("failed to connect to server")?;
    authenticate(&mut stream, token).await?;
    write_msg(&mut stream, &Message::ForwardConn { name: name.to_string(), target: remote_target.to_string() }).await?;

    let (tx, rx) = copy_bidirectional(&mut inbound, &mut stream).await?;
    Ok((tx, rx))
}

// ---------------------------------------------------------------------------
// reverse tunnels: keep one persistent control connection registered with the
// server; on each `NewConnection` push, open a fresh data connection back.
// ---------------------------------------------------------------------------

async fn run_reverse_with_backoff(config: &ClientConfig, tls: &TlsClientOpts, name: String, local_target: String) {
    let mut attempt = 0usize;
    loop {
        match run_reverse_once(config, tls, &name, &local_target).await {
            Ok(()) => attempt = 0, // clean shutdown (shouldn't normally happen), reset backoff
            Err(e) => warn!(name = %name, error = %e, "reverse tunnel control connection lost"),
        }

        let delay = RECONNECT_BACKOFF[attempt.min(RECONNECT_BACKOFF.len() - 1)];
        attempt += 1;
        info!(name = %name, delay_ms = delay.as_millis(), "reconnecting reverse tunnel");
        tokio::time::sleep(delay).await;
    }
}

async fn run_reverse_once(config: &ClientConfig, tls: &TlsClientOpts, name: &str, local_target: &str) -> Result<()> {
    let mut stream = transport::dial(config.transport, &config.server, tls)
        .await
        .context("failed to connect to server")?;
    authenticate(&mut stream, &config.token).await?;

    write_msg(&mut stream, &Message::RegisterReverse { name: name.to_string() }).await?;
    match read_msg(&mut stream).await? {
        Message::RegisterOk => {}
        Message::RegisterFail { reason } => bail!("server rejected reverse tunnel registration: {reason}"),
        other => bail!("unexpected response to register: {other:?}"),
    }

    info!(name = %name, server = %config.server, local_target = %local_target, "reverse tunnel registered, waiting for connections");

    loop {
        match read_msg(&mut stream).await? {
            Message::NewConnection { conn_id } => {
                let name = name.to_string();
                let local_target = local_target.to_string();
                let server_addr = config.server.clone();
                let transport_kind = config.transport;
                let token = config.token.clone();
                let tls = tls.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_new_connection(conn_id, &server_addr, transport_kind, &tls, &token, &local_target).await
                    {
                        warn!(name = %name, conn_id, error = %e, "reverse data connection failed");
                    }
                });
            }
            Message::Ping { ts_millis } => {
                write_msg(&mut stream, &Message::Pong { ts_millis }).await?;
            }
            other => warn!(name = %name, message = ?other, "unexpected message on reverse control connection"),
        }
    }
}

async fn handle_new_connection(
    conn_id: u64,
    server_addr: &str,
    transport_kind: transport::Kind,
    tls: &TlsClientOpts,
    token: &str,
    local_target: &str,
) -> Result<()> {
    let mut data_stream = transport::dial(transport_kind, server_addr, tls)
        .await
        .context("failed to open data connection")?;
    authenticate(&mut data_stream, token).await?;
    write_msg(&mut data_stream, &Message::DataConn { conn_id }).await?;

    let mut local = tokio::net::TcpStream::connect(local_target)
        .await
        .with_context(|| format!("failed to dial local target {local_target}"))?;
    local.set_nodelay(true).ok();

    copy_bidirectional(&mut data_stream, &mut local).await?;
    Ok(())
}
