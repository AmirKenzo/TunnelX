use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::config::ForwardRule;
use crate::util::LogThrottle;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_ERROR_LOG_WINDOW: Duration = Duration::from_secs(5);
const ACCEPT_ERROR_RETRY_DELAY: Duration = Duration::from_millis(50);

pub type Registry = Arc<RwLock<HashMap<String, ForwardRule>>>;

/// Binds `listen` once and runs forever, forwarding each connection to the
/// current `target` for `name` (read live from `registry` on every accept,
/// so changing just the target in the config doesn't require rebinding).
pub async fn run(name: String, listen: String, registry: Registry) -> Result<()> {
    let listener = TcpListener::bind(&listen)
        .await
        .with_context(|| format!("forward '{name}': failed to bind {listen}"))?;

    info!(name = %name, listen = %listen, "listening");

    let mut accept_error_throttle = LogThrottle::new(ACCEPT_ERROR_LOG_WINDOW);
    loop {
        let (inbound, peer_addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                if let Some(suppressed) = accept_error_throttle.allow() {
                    error!(name = %name, error = %e, suppressed, "accept failed");
                }
                tokio::time::sleep(ACCEPT_ERROR_RETRY_DELAY).await;
                continue;
            }
        };

        let name = name.clone();
        let registry = registry.clone();
        tokio::spawn(async move {
            let target = match registry.read().await.get(&name).map(|r| r.target.clone()) {
                Some(target) => target,
                None => return, // rule was removed by a reload just as we accepted
            };
            handle_connection(name, target, inbound, peer_addr).await;
        });
    }
}

async fn handle_connection(
    name: String,
    target: String,
    mut inbound: TcpStream,
    peer_addr: std::net::SocketAddr,
) {
    let _ = inbound.set_nodelay(true);

    let outbound = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&target)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            warn!(name = %name, peer = %peer_addr, target = %target, error = %e, "dial failed");
            return;
        }
        Err(_) => {
            warn!(name = %name, peer = %peer_addr, target = %target, "dial timed out");
            return;
        }
    };
    let _ = outbound.set_nodelay(true);

    info!(name = %name, peer = %peer_addr, target = %target, "connection open");
    let started = Instant::now();

    let mut outbound = outbound;
    let result = copy_bidirectional(&mut inbound, &mut outbound).await;

    let elapsed = started.elapsed();
    match result {
        Ok((tx, rx)) => {
            info!(
                name = %name,
                peer = %peer_addr,
                sent = tx,
                received = rx,
                duration_ms = elapsed.as_millis(),
                "connection closed"
            );
        }
        Err(e) => {
            warn!(
                name = %name,
                peer = %peer_addr,
                duration_ms = elapsed.as_millis(),
                error = %e,
                "connection closed with error"
            );
        }
    }
}
