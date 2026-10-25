use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::relay::transport::Kind as TransportKind;

fn default_log_level() -> String {
    "info".to_string()
}

fn default_mux_connections() -> usize {
    4
}

fn default_max_sessions_per_tunnel() -> usize {
    8
}

fn default_idle_timeout_secs() -> u64 {
    300
}

fn default_keepalive_secs() -> u64 {
    60
}

fn default_max_connections() -> usize {
    100_000
}

/// Top-level config. `mode` decides which of the three shapes below applies;
/// it's optional and defaults to "direct" so existing direct-mode config
/// files (no `mode` key) keep working unchanged.
#[derive(Debug)]
pub enum Config {
    Direct(DirectConfig),
    Client(ClientConfig),
    Server(ServerConfig),
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file: {}", path.display()))?;
        Self::parse(&raw)
    }

    pub fn parse(raw: &str) -> Result<Self> {
        let value: toml::Value = toml::from_str(raw).context("failed to parse config file")?;
        let mode = value
            .get("mode")
            .and_then(|v| v.as_str())
            .unwrap_or("direct")
            .to_string();
        // Round-trip through a string rather than deserializing `Value` directly:
        // avoids depending on exactly which Deserializer impls this toml version
        // provides for its own Value type.
        let normalized = toml::to_string(&value).context("failed to normalize config for parsing")?;

        let config = match mode.as_str() {
            "direct" => {
                let c: DirectConfig = toml::from_str(&normalized).context("failed to parse direct-mode config")?;
                c.validate()?;
                Config::Direct(c)
            }
            "client" => {
                let c: ClientConfig = toml::from_str(&normalized).context("failed to parse client-mode config")?;
                c.validate()?;
                Config::Client(c)
            }
            "server" => {
                let c: ServerConfig = toml::from_str(&normalized).context("failed to parse server-mode config")?;
                c.validate()?;
                Config::Server(c)
            }
            other => bail!("unknown mode '{other}' (expected one of: direct, client, server)"),
        };

        Ok(config)
    }

    pub fn log_level(&self) -> &str {
        match self {
            Config::Direct(c) => &c.log_level,
            Config::Client(c) => &c.log_level,
            Config::Server(c) => &c.log_level,
        }
    }
}

// ---------------------------------------------------------------------------
// direct mode (unchanged since v1): plain TCP forwarder, no remote agent.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct DirectConfig {
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(rename = "forward")]
    pub forwards: Vec<ForwardRule>,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct ForwardRule {
    pub name: String,
    pub listen: String,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub allowed_sni: Vec<String>,
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    #[serde(default = "default_keepalive_secs")]
    pub keepalive_secs: u64,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
}

impl ForwardRule {
    pub fn target_pool(&self) -> Vec<String> {
        match &self.target {
            Some(target) => vec![target.clone()],
            None => self.targets.clone(),
        }
    }
}

impl DirectConfig {
    /// Rules keyed by name, for diffing against a previous config on reload.
    pub fn by_name(self) -> std::collections::HashMap<String, ForwardRule> {
        self.forwards.into_iter().map(|r| (r.name.clone(), r)).collect()
    }

    fn validate(&self) -> Result<()> {
        validate_log_level(&self.log_level)?;

        if self.forwards.is_empty() {
            bail!("config must contain at least one [[forward]] entry");
        }

        let mut seen_listen = HashSet::new();
        let mut seen_name = HashSet::new();
        for rule in &self.forwards {
            rule.listen.parse::<std::net::SocketAddr>().with_context(|| {
                format!("forward '{}': invalid listen address '{}'", rule.name, rule.listen)
            })?;
            match (&rule.target, rule.targets.is_empty()) {
                (Some(_), false) => {
                    bail!("forward '{}': set either 'target' or 'targets', not both", rule.name)
                }
                (None, true) => bail!("forward '{}': must set 'target' or a non-empty 'targets'", rule.name),
                _ => {}
            }
            for target in rule.target_pool() {
                target.parse::<std::net::SocketAddr>().with_context(|| {
                    format!("forward '{}': invalid target address '{}'", rule.name, target)
                })?;
            }
            for pattern in &rule.allowed_sni {
                let valid = match pattern.strip_prefix("*.") {
                    Some(suffix) => !suffix.is_empty() && !suffix.contains('*'),
                    None => !pattern.is_empty() && !pattern.contains('*'),
                };
                if !valid {
                    bail!("forward '{}': invalid allowed_sni pattern '{}'", rule.name, pattern);
                }
            }
            if !seen_listen.insert(rule.listen.clone()) {
                bail!("duplicate listen address '{}' in config", rule.listen);
            }
            if !seen_name.insert(rule.name.clone()) {
                bail!("duplicate forward name '{}' in config", rule.name);
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// client mode: connects out to a tunnelx server, runs forward and/or reverse
// tunnels over tcp/tls/ws/wss.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
pub struct ClientConfig {
    #[serde(default = "default_log_level")]
    pub log_level: String,
    pub server: String,
    pub transport: TransportKind,
    pub token: String,
    pub tls_ca_cert: Option<PathBuf>,
    #[serde(default)]
    pub tls_insecure: bool,
    /// How many physical connections to keep open per tunnel, each carrying
    /// many multiplexed logical streams. More than 1 limits how much traffic
    /// a single degraded/black-holed physical link or a single TCP-level
    /// head-of-line-blocking event can affect at once; there's little
    /// latency argument for a large pool since multiplexing already removes
    /// the per-connection handshake cost.
    #[serde(default = "default_mux_connections")]
    pub mux_connections: usize,
    #[serde(rename = "tunnel")]
    pub tunnels: Vec<ClientTunnel>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "direction", rename_all = "lowercase")]
pub enum ClientTunnel {
    Forward {
        name: String,
        local_listen: String,
        remote_target: String,
    },
    Reverse {
        name: String,
        local_target: String,
    },
}

impl ClientTunnel {
    pub fn name(&self) -> &str {
        match self {
            ClientTunnel::Forward { name, .. } => name,
            ClientTunnel::Reverse { name, .. } => name,
        }
    }
}

impl ClientConfig {
    fn validate(&self) -> Result<()> {
        validate_log_level(&self.log_level)?;

        if self.transport.is_tls() && self.tls_ca_cert.is_none() && !self.tls_insecure {
            bail!("transport {:?} requires tls_ca_cert (pin the server's cert) or tls_insecure = true", self.transport);
        }

        if self.mux_connections == 0 {
            bail!("mux_connections must be at least 1");
        }

        if self.tunnels.is_empty() {
            bail!("config must contain at least one [[tunnel]] entry");
        }

        let mut seen_name = HashSet::new();
        let mut seen_listen = HashSet::new();
        for t in &self.tunnels {
            if !seen_name.insert(t.name().to_string()) {
                bail!("duplicate tunnel name '{}' in config", t.name());
            }
            if let ClientTunnel::Forward { local_listen, .. } = t {
                local_listen.parse::<std::net::SocketAddr>().with_context(|| {
                    format!("tunnel '{}': invalid local_listen address '{}'", t.name(), local_listen)
                })?;
                if !seen_listen.insert(local_listen.clone()) {
                    bail!("duplicate local_listen address '{}' in config", local_listen);
                }
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// server mode: the relay agent, meant to run on the foreign-side box.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    #[serde(default = "default_log_level")]
    pub log_level: String,
    pub listen: String,
    pub transport: TransportKind,
    pub token: String,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    /// Caps how many physical sessions the server will register per tunnel
    /// name, so a misbehaving or duplicated client can't grow this
    /// unboundedly. Defaults to twice the client's default `mux_connections`
    /// pool size, leaving headroom for one full extra generation of sessions
    /// to overlap during a client-side reconnect without hitting the cap.
    #[serde(default = "default_max_sessions_per_tunnel")]
    pub max_sessions_per_tunnel: usize,
    #[serde(rename = "tunnel")]
    pub tunnels: Vec<ServerTunnel>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "direction", rename_all = "lowercase")]
pub enum ServerTunnel {
    Forward {
        name: String,
        #[serde(default)]
        allowed_targets: Vec<String>,
    },
    Reverse {
        name: String,
        remote_listen: String,
    },
}

impl ServerTunnel {
    pub fn name(&self) -> &str {
        match self {
            ServerTunnel::Forward { name, .. } => name,
            ServerTunnel::Reverse { name, .. } => name,
        }
    }
}

impl ServerConfig {
    fn validate(&self) -> Result<()> {
        validate_log_level(&self.log_level)?;

        if self.transport.is_tls() && (self.tls_cert.is_none() || self.tls_key.is_none()) {
            bail!("transport {:?} requires tls_cert and tls_key", self.transport);
        }

        if self.max_sessions_per_tunnel == 0 {
            bail!("max_sessions_per_tunnel must be at least 1");
        }

        if self.tunnels.is_empty() {
            bail!("config must contain at least one [[tunnel]] entry");
        }

        let mut seen_name = HashSet::new();
        let mut seen_listen = HashSet::new();
        for t in &self.tunnels {
            if !seen_name.insert(t.name().to_string()) {
                bail!("duplicate tunnel name '{}' in config", t.name());
            }
            if let ServerTunnel::Reverse { remote_listen, .. } = t {
                remote_listen.parse::<std::net::SocketAddr>().with_context(|| {
                    format!("tunnel '{}': invalid remote_listen address '{}'", t.name(), remote_listen)
                })?;
                if !seen_listen.insert(remote_listen.clone()) {
                    bail!("duplicate remote_listen address '{}' in config", remote_listen);
                }
            }
            if let ServerTunnel::Forward { allowed_targets, .. } = t {
                for target in allowed_targets {
                    target.parse::<std::net::SocketAddr>().with_context(|| {
                        format!("tunnel '{}': invalid allowed_targets entry '{}'", t.name(), target)
                    })?;
                }
            }
        }

        Ok(())
    }
}

fn validate_log_level(level: &str) -> Result<()> {
    const VALID_LEVELS: [&str; 6] = ["off", "error", "warn", "info", "debug", "trace"];
    if !VALID_LEVELS.contains(&level.to_lowercase().as_str()) {
        bail!("invalid log_level '{level}' (expected one of: {})", VALID_LEVELS.join(", "));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_direct(raw: &str) -> Result<DirectConfig> {
        match Config::parse(raw)? {
            Config::Direct(c) => Ok(c),
            _ => bail!("expected direct config"),
        }
    }

    #[test]
    fn plain_target_rule_ok() {
        let c = parse_direct("[[forward]]\nname = \"ssh\"\nlisten = \"0.0.0.0:2222\"\ntarget = \"1.2.3.4:22\"\n").unwrap();
        assert_eq!(c.forwards[0].target_pool(), vec!["1.2.3.4:22".to_string()]);
        assert!(c.forwards[0].allowed_sni.is_empty());
    }

    #[test]
    fn connection_settings_defaults_and_overrides() {
        let c = parse_direct("[[forward]]\nname = \"ssh\"\nlisten = \"0.0.0.0:2222\"\ntarget = \"1.2.3.4:22\"\n").unwrap();
        let rule = &c.forwards[0];
        assert_eq!((rule.idle_timeout_secs, rule.keepalive_secs, rule.max_connections), (300, 60, 100_000));

        let c = parse_direct(
            "[[forward]]\nname = \"ssh\"\nlisten = \"0.0.0.0:2222\"\ntarget = \"1.2.3.4:22\"\nidle_timeout_secs = 0\nkeepalive_secs = 30\nmax_connections = 10\n",
        )
        .unwrap();
        let rule = &c.forwards[0];
        assert_eq!((rule.idle_timeout_secs, rule.keepalive_secs, rule.max_connections), (0, 30, 10));
    }

    #[test]
    fn targets_only_ok() {
        let c = parse_direct(
            "[[forward]]\nname = \"cf\"\nlisten = \"0.0.0.0:3256\"\nallowed_sni = [\"a.ir\", \"*.sni.ir\"]\ntargets = [\"1.1.1.1:443\", \"1.0.0.1:443\"]\n",
        )
        .unwrap();
        assert_eq!(c.forwards[0].target_pool().len(), 2);
    }

    #[test]
    fn both_target_and_targets_rejected() {
        let err = parse_direct(
            "[[forward]]\nname = \"cf\"\nlisten = \"0.0.0.0:3256\"\ntarget = \"1.1.1.1:443\"\ntargets = [\"1.0.0.1:443\"]\n",
        )
        .unwrap_err();
        assert!(err.to_string().contains("not both"), "{err}");
    }

    #[test]
    fn neither_target_nor_targets_rejected() {
        assert!(parse_direct("[[forward]]\nname = \"cf\"\nlisten = \"0.0.0.0:3256\"\n").is_err());
        assert!(parse_direct("[[forward]]\nname = \"cf\"\nlisten = \"0.0.0.0:3256\"\ntargets = []\n").is_err());
    }

    #[test]
    fn invalid_pool_entry_rejected() {
        assert!(parse_direct(
            "[[forward]]\nname = \"cf\"\nlisten = \"0.0.0.0:3256\"\ntargets = [\"1.1.1.1:443\", \"nope\"]\n"
        )
        .is_err());
    }

    #[test]
    fn bad_sni_pattern_rejected() {
        for pattern in ["", "*.", "*", "a.*.ir"] {
            let raw = format!(
                "[[forward]]\nname = \"cf\"\nlisten = \"0.0.0.0:3256\"\ntarget = \"1.1.1.1:443\"\nallowed_sni = [\"{pattern}\"]\n"
            );
            assert!(parse_direct(&raw).is_err(), "pattern {pattern:?} should be rejected");
        }
    }
}
