use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use rand::seq::SliceRandom;
use socket2::{SockRef, TcpKeepalive};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::config::ForwardRule;
use crate::util::LogThrottle;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const SNI_READ_TIMEOUT: Duration = Duration::from_secs(5);
const DROP_LOG_WINDOW: Duration = Duration::from_secs(5);
const MAX_CLIENT_HELLO_RECORD: usize = 16384 + 2048;
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const COPY_BUF_SIZE: usize = 8 * 1024;
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
    let drop_throttle = Arc::new(Mutex::new(LogThrottle::new(DROP_LOG_WINDOW)));
    let active = Arc::new(AtomicUsize::new(0));
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
        let drop_throttle = drop_throttle.clone();
        let guard = ActiveGuard::new(active.clone());
        tokio::spawn(async move {
            let guard = guard;
            let rule = match registry.read().await.get(&name).cloned() {
                Some(rule) => rule,
                None => return, // rule was removed by a reload just as we accepted
            };
            if rule.max_connections > 0 && guard.count > rule.max_connections {
                log_dropped(&drop_throttle, &name, peer_addr, None, "connection limit reached");
                return;
            }
            handle_connection(name, rule, inbound, peer_addr, drop_throttle).await;
        });
    }
}

struct ActiveGuard {
    counter: Arc<AtomicUsize>,
    count: usize,
}

impl ActiveGuard {
    fn new(counter: Arc<AtomicUsize>) -> Self {
        let count = counter.fetch_add(1, Ordering::Relaxed) + 1;
        Self { counter, count }
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
    }
}

async fn handle_connection(
    name: String,
    rule: ForwardRule,
    mut inbound: TcpStream,
    peer_addr: std::net::SocketAddr,
    drop_throttle: Arc<Mutex<LogThrottle>>,
) {
    let _ = inbound.set_nodelay(true);
    set_keepalive(&inbound, rule.keepalive_secs);

    let mut sni: Option<String> = None;
    let mut consumed: Vec<u8> = Vec::new();
    if !rule.allowed_sni.is_empty() {
        let reason = match tokio::time::timeout(SNI_READ_TIMEOUT, read_client_hello(&mut inbound)).await {
            Ok(Ok(record)) => match parse_sni(&record) {
                Some(host) if rule.allowed_sni.iter().any(|p| sni_matches(&host, p)) => {
                    sni = Some(host);
                    consumed = record;
                    None
                }
                Some(host) => {
                    sni = Some(host);
                    Some("sni not allowed".to_string())
                }
                None => Some("no sni in client hello".to_string()),
            },
            Ok(Err(e)) => Some(format!("client hello read failed: {e}")),
            Err(_) => Some("client hello read timed out".to_string()),
        };
        if let Some(reason) = reason {
            log_dropped(&drop_throttle, &name, peer_addr, sni.as_deref(), &reason);
            return;
        }
    }

    let pool = rule.target_pool();
    let target = match pool.as_slice() {
        [only] => only.clone(),
        _ => match pool.choose(&mut rand::thread_rng()) {
            Some(target) => target.clone(),
            None => {
                warn!(name = %name, peer = %peer_addr, "no target configured");
                return;
            }
        },
    };

    let local_addr = inbound.local_addr().ok();
    let source = match rule.source_ip.as_deref() {
        None => None,
        Some("inbound") => local_addr.map(|a| a.ip()),
        Some(ip) => ip.parse().ok(),
    };

    let outbound = match tokio::time::timeout(CONNECT_TIMEOUT, dial(&target, source)).await {
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
    set_keepalive(&outbound, rule.keepalive_secs);

    info!(
        name = %name,
        peer = %peer_addr,
        local = local_addr.map(tracing::field::display),
        source = source.map(tracing::field::display),
        target = %target,
        sni = sni.as_deref(),
        "connection open"
    );
    let started = Instant::now();

    let mut outbound = outbound;
    let sent = AtomicU64::new(consumed.len() as u64);
    let received = AtomicU64::new(0);
    let idle_timeout = Duration::from_secs(rule.idle_timeout_secs);
    let result = match outbound.write_all(&consumed).await {
        Ok(()) => relay(&mut inbound, &mut outbound, idle_timeout, &sent, &received).await,
        Err(e) => Err(e),
    };

    let elapsed = started.elapsed();
    let (tx, rx) = (sent.load(Ordering::Relaxed), received.load(Ordering::Relaxed));
    match result {
        Ok(idle) => {
            info!(
                name = %name,
                peer = %peer_addr,
                target = %target,
                sni = sni.as_deref(),
                sent = tx,
                received = rx,
                duration_ms = elapsed.as_millis(),
                idle_timeout = idle,
                "connection closed"
            );
        }
        Err(e) => {
            warn!(
                name = %name,
                peer = %peer_addr,
                target = %target,
                sni = sni.as_deref(),
                sent = tx,
                received = rx,
                duration_ms = elapsed.as_millis(),
                error = %e,
                "connection closed with error"
            );
        }
    }
}

async fn dial(target: &str, source: Option<IpAddr>) -> io::Result<TcpStream> {
    let target: SocketAddr = target
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let source = match source {
        Some(ip) if ip.is_ipv4() == target.is_ipv4() => ip,
        _ => return TcpStream::connect(target).await,
    };
    let socket = if target.is_ipv4() { TcpSocket::new_v4()? } else { TcpSocket::new_v6()? };
    socket.bind(SocketAddr::new(source, 0))?;
    socket.connect(target).await
}

fn log_dropped(
    throttle: &Mutex<LogThrottle>,
    name: &str,
    peer_addr: std::net::SocketAddr,
    sni: Option<&str>,
    reason: &str,
) {
    let allowed = throttle.lock().map(|mut t| t.allow()).unwrap_or(Some(0));
    if let Some(suppressed) = allowed {
        warn!(name = %name, peer = %peer_addr, sni, reason = %reason, suppressed, "connection dropped");
    }
}

fn set_keepalive(stream: &TcpStream, secs: u64) {
    if secs == 0 {
        return;
    }
    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(secs))
        .with_interval(KEEPALIVE_INTERVAL);
    let _ = SockRef::from(stream).set_tcp_keepalive(&keepalive);
}

/// Returns `Ok(true)` when the connection was closed by `idle_timeout`.
async fn relay(
    inbound: &mut TcpStream,
    outbound: &mut TcpStream,
    idle_timeout: Duration,
    sent: &AtomicU64,
    received: &AtomicU64,
) -> io::Result<bool> {
    let started = Instant::now();
    let last_activity = AtomicU64::new(0);
    let (mut inbound_read, mut inbound_write) = inbound.split();
    let (mut outbound_read, mut outbound_write) = outbound.split();
    let copy = async {
        tokio::try_join!(
            copy_half(&mut inbound_read, &mut outbound_write, sent, &last_activity, started),
            copy_half(&mut outbound_read, &mut inbound_write, received, &last_activity, started),
        )
        .map(|_| false)
    };

    if idle_timeout.is_zero() {
        return copy.await;
    }
    tokio::select! {
        result = copy => result,
        _ = idle_watch(started, &last_activity, idle_timeout) => Ok(true),
    }
}

async fn copy_half<R, W>(
    reader: &mut R,
    writer: &mut W,
    total: &AtomicU64,
    last_activity: &AtomicU64,
    started: Instant,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; COPY_BUF_SIZE];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            return writer.shutdown().await;
        }
        writer.write_all(&buf[..n]).await?;
        total.fetch_add(n as u64, Ordering::Relaxed);
        last_activity.store(started.elapsed().as_millis() as u64, Ordering::Relaxed);
    }
}

async fn idle_watch(started: Instant, last_activity: &AtomicU64, idle_timeout: Duration) {
    loop {
        let deadline = started + Duration::from_millis(last_activity.load(Ordering::Relaxed)) + idle_timeout;
        if Instant::now() >= deadline {
            return;
        }
        tokio::time::sleep_until(deadline.into()).await;
    }
}

async fn read_client_hello(inbound: &mut TcpStream) -> Result<Vec<u8>> {
    let mut record = vec![0u8; 5];
    inbound.read_exact(&mut record).await?;
    if record[0] != 0x16 {
        return Ok(record);
    }
    let len = u16::from_be_bytes([record[3], record[4]]) as usize;
    if len == 0 || 5 + len > MAX_CLIENT_HELLO_RECORD {
        bail!("tls record length {len} out of range");
    }
    record.resize(5 + len, 0);
    inbound.read_exact(&mut record[5..]).await?;
    Ok(record)
}

fn take<'a>(buf: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if buf.len() < n {
        return None;
    }
    let (head, tail) = buf.split_at(n);
    *buf = tail;
    Some(head)
}

fn take_u8(buf: &mut &[u8]) -> Option<usize> {
    take(buf, 1).map(|b| b[0] as usize)
}

fn take_u16(buf: &mut &[u8]) -> Option<usize> {
    take(buf, 2).map(|b| u16::from_be_bytes([b[0], b[1]]) as usize)
}

fn parse_sni(record: &[u8]) -> Option<String> {
    let mut buf = record;

    let header = take(&mut buf, 5)?;
    if header[0] != 0x16 {
        return None;
    }
    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut body = take(&mut buf, record_len)?;

    let hs = take(&mut body, 4)?;
    if hs[0] != 0x01 {
        return None;
    }
    let hs_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | hs[3] as usize;
    let mut hello = take(&mut body, hs_len)?;

    take(&mut hello, 2)?;
    take(&mut hello, 32)?;
    let session_id_len = take_u8(&mut hello)?;
    take(&mut hello, session_id_len)?;
    let cipher_suites_len = take_u16(&mut hello)?;
    take(&mut hello, cipher_suites_len)?;
    let compression_len = take_u8(&mut hello)?;
    take(&mut hello, compression_len)?;

    let extensions_len = take_u16(&mut hello)?;
    let mut extensions = take(&mut hello, extensions_len)?;
    while !extensions.is_empty() {
        let ext_type = take_u16(&mut extensions)?;
        let ext_len = take_u16(&mut extensions)?;
        let mut ext = take(&mut extensions, ext_len)?;
        if ext_type != 0x0000 {
            continue;
        }

        let list_len = take_u16(&mut ext)?;
        let mut list = take(&mut ext, list_len)?;
        while !list.is_empty() {
            let name_type = take_u8(&mut list)?;
            let name_len = take_u16(&mut list)?;
            let name = take(&mut list, name_len)?;
            if name_type == 0 {
                return std::str::from_utf8(name)
                    .ok()
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);
            }
        }
        return None;
    }
    None
}

fn sni_matches(host: &str, pattern: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    let pattern = pattern.strip_suffix('.').unwrap_or(pattern).to_ascii_lowercase();
    match pattern.strip_prefix("*.") {
        Some(suffix) => host
            .strip_suffix(suffix)
            .and_then(|rest| rest.strip_suffix('.'))
            .is_some_and(|label| !label.is_empty() && !label.contains('.')),
        None => host == pattern,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT_HELLO_EXAMPLE_COM: &str = "16030100ca010000c60303295b4dd0547a7710277b86872a9e634876979941de30f2652afa38d28565527f000036c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009c0130033009d009c003d003c0035002f01000067ff0100010000000010000e00000b6578616d706c652e636f6d000b000403000102000a000c000a001d0017001e001800190016000000170000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602";

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn parse_sni_real_client_hello() {
        assert_eq!(parse_sni(&hex(CLIENT_HELLO_EXAMPLE_COM)).as_deref(), Some("example.com"));
    }

    #[test]
    fn parse_sni_truncated() {
        let record = hex(CLIENT_HELLO_EXAMPLE_COM);
        for len in [0, 4, 5, 40, 120, record.len() - 1] {
            assert_eq!(parse_sni(&record[..len]), None, "len {len}");
        }
    }

    #[test]
    fn parse_sni_non_handshake() {
        let mut record = hex(CLIENT_HELLO_EXAMPLE_COM);
        record[0] = 0x17;
        assert_eq!(parse_sni(&record), None);
        assert_eq!(parse_sni(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), None);
    }

    #[test]
    fn sni_exact() {
        assert!(sni_matches("example.com", "example.com"));
        assert!(!sni_matches("other.com", "example.com"));
        assert!(!sni_matches("a.example.com", "example.com"));
    }

    #[test]
    fn sni_wildcard_single_label() {
        assert!(sni_matches("a.sni.ir", "*.sni.ir"));
        assert!(!sni_matches("sni.ir", "*.sni.ir"));
        assert!(!sni_matches("a.b.sni.ir", "*.sni.ir"));
        assert!(!sni_matches(".sni.ir", "*.sni.ir"));
        assert!(!sni_matches("asni.ir", "*.sni.ir"));
    }

    #[test]
    fn sni_case_and_trailing_dot() {
        assert!(sni_matches("Example.COM", "example.com"));
        assert!(sni_matches("A.Sni.Ir", "*.SNI.ir"));
        assert!(sni_matches("example.com.", "example.com"));
        assert!(sni_matches("a.sni.ir.", "*.sni.ir"));
    }

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    #[tokio::test]
    async fn relay_copies_both_ways_until_close() {
        let (mut client, mut inbound) = tcp_pair().await;
        let (mut outbound, mut backend) = tcp_pair().await;
        let (sent, received) = (AtomicU64::new(0), AtomicU64::new(0));

        let peers = async {
            client.write_all(b"ping").await.unwrap();
            client.shutdown().await.unwrap();
            let mut buf = Vec::new();
            backend.read_to_end(&mut buf).await.unwrap();
            assert_eq!(buf, b"ping");
            backend.write_all(b"pong!").await.unwrap();
            backend.shutdown().await.unwrap();
            let mut buf = Vec::new();
            client.read_to_end(&mut buf).await.unwrap();
            assert_eq!(buf, b"pong!");
        };
        let relayed = relay(&mut inbound, &mut outbound, Duration::from_secs(5), &sent, &received);
        let (result, ()) = tokio::join!(relayed, peers);

        assert!(!result.unwrap());
        assert_eq!((sent.load(Ordering::Relaxed), received.load(Ordering::Relaxed)), (4, 5));
    }

    #[tokio::test]
    async fn relay_closes_idle_connection() {
        let (_client, mut inbound) = tcp_pair().await;
        let (mut outbound, _backend) = tcp_pair().await;
        let (sent, received) = (AtomicU64::new(0), AtomicU64::new(0));

        let started = Instant::now();
        let result = relay(&mut inbound, &mut outbound, Duration::from_millis(200), &sent, &received).await;

        assert!(result.unwrap());
        assert!(started.elapsed() >= Duration::from_millis(200));
    }

    #[test]
    fn active_guard_counts_and_releases() {
        let counter = Arc::new(AtomicUsize::new(0));
        let first = ActiveGuard::new(counter.clone());
        let second = ActiveGuard::new(counter.clone());
        assert_eq!((first.count, second.count), (1, 2));
        drop(first);
        assert_eq!(ActiveGuard::new(counter.clone()).count, 2);
        drop(second);
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn dial_binds_requested_source_ip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap().to_string();

        let _plain = dial(&target, None).await.unwrap();
        let (_, peer) = listener.accept().await.unwrap();
        assert_eq!(peer.ip().to_string(), "127.0.0.1");

        let _bound = dial(&target, Some("127.0.0.2".parse().unwrap())).await.unwrap();
        let (_, peer) = listener.accept().await.unwrap();
        assert_eq!(peer.ip().to_string(), "127.0.0.2");

        let _mismatch = dial(&target, Some("::1".parse().unwrap())).await.unwrap();
        let (_, peer) = listener.accept().await.unwrap();
        assert!(peer.ip().is_ipv4());
    }
}
