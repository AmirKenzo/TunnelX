use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use rand::seq::SliceRandom;
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::config::ForwardRule;
use crate::util::LogThrottle;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const SNI_READ_TIMEOUT: Duration = Duration::from_secs(5);
const SNI_DROP_LOG_WINDOW: Duration = Duration::from_secs(5);
const MAX_CLIENT_HELLO_RECORD: usize = 16384 + 2048;
const ACCEPT_ERROR_LOG_WINDOW: Duration = Duration::from_secs(5);
const ACCEPT_ERROR_RETRY_DELAY: Duration = Duration::from_millis(50);

pub type Registry = Arc<RwLock<HashMap<String, ForwardRule>>>;

pub async fn run(name: String, listen: String, registry: Registry) -> Result<()> {
    let listener = TcpListener::bind(&listen)
        .await
        .with_context(|| format!("forward '{name}': failed to bind {listen}"))?;

    info!(name = %name, listen = %listen, "listening");

    let mut accept_error_throttle = LogThrottle::new(ACCEPT_ERROR_LOG_WINDOW);
    let sni_drop_throttle = Arc::new(Mutex::new(LogThrottle::new(SNI_DROP_LOG_WINDOW)));
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
        let sni_drop_throttle = sni_drop_throttle.clone();
        tokio::spawn(async move {
            let rule = match registry.read().await.get(&name).cloned() {
                Some(rule) => rule,
                None => return, // rule was removed by a reload just as we accepted
            };
            handle_connection(name, rule, inbound, peer_addr, sni_drop_throttle).await;
        });
    }
}

async fn handle_connection(
    name: String,
    rule: ForwardRule,
    mut inbound: TcpStream,
    peer_addr: std::net::SocketAddr,
    sni_drop_throttle: Arc<Mutex<LogThrottle>>,
) {
    let _ = inbound.set_nodelay(true);

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
            let allowed = sni_drop_throttle.lock().map(|mut t| t.allow()).unwrap_or(Some(0));
            if let Some(suppressed) = allowed {
                warn!(name = %name, peer = %peer_addr, sni = sni.as_deref(), reason = %reason, suppressed, "connection dropped");
            }
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

    info!(name = %name, peer = %peer_addr, target = %target, sni = sni.as_deref(), "connection open");
    let started = Instant::now();

    let mut outbound = outbound;
    let result = match outbound.write_all(&consumed).await {
        Ok(()) => copy_bidirectional(&mut inbound, &mut outbound)
            .await
            .map(|(tx, rx)| (tx + consumed.len() as u64, rx)),
        Err(e) => Err(e),
    };

    let elapsed = started.elapsed();
    match result {
        Ok((tx, rx)) => {
            info!(
                name = %name,
                peer = %peer_addr,
                target = %target,
                sni = sni.as_deref(),
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
                target = %target,
                sni = sni.as_deref(),
                duration_ms = elapsed.as_millis(),
                error = %e,
                "connection closed with error"
            );
        }
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
        assert!(sni_matches("nativeplus.ir", "nativeplus.ir"));
        assert!(!sni_matches("other.ir", "nativeplus.ir"));
        assert!(!sni_matches("a.nativeplus.ir", "nativeplus.ir"));
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
        assert!(sni_matches("NativePlus.IR", "nativeplus.ir"));
        assert!(sni_matches("A.Sni.Ir", "*.SNI.ir"));
        assert!(sni_matches("nativeplus.ir.", "nativeplus.ir"));
        assert!(sni_matches("a.sni.ir.", "*.sni.ir"));
    }
}
