use std::time::{Duration, Instant};

/// Compares two secrets without short-circuiting on the first differing byte,
/// so response time doesn't leak how many leading bytes of a guess were
/// correct (a network attacker who can measure timing precisely enough could
/// otherwise brute-force the auth token one byte at a time against `==`).
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Collapses a burst of identical/frequent errors (e.g. a tight accept-error
/// loop, or a flood of bad handshakes) into one log line per time window
/// instead of one line per occurrence.
pub struct LogThrottle {
    window: Duration,
    last_logged: Option<Instant>,
    suppressed: u64,
}

impl LogThrottle {
    pub fn new(window: Duration) -> Self {
        Self { window, last_logged: None, suppressed: 0 }
    }

    /// Call once per event. Returns `Some(suppressed_count)` when this call
    /// should actually be logged (count of events skipped since the last log,
    /// 0 the first time); returns `None` when it should be silently skipped.
    pub fn allow(&mut self) -> Option<u64> {
        let now = Instant::now();
        match self.last_logged {
            Some(last) if now.duration_since(last) < self.window => {
                self.suppressed += 1;
                None
            }
            _ => {
                let suppressed = self.suppressed;
                self.suppressed = 0;
                self.last_logged = Some(now);
                Some(suppressed)
            }
        }
    }
}
