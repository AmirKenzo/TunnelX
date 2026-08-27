use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::relay::transport::Kind as TransportKind;

fn default_log_level() -> String {
    "info".to_string()
}

fn default_mode() -> String {
    "direct".to_string()
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
    pub target: String,
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
            rule.target.parse::<std::net::SocketAddr>().with_context(|| {
                format!("forward '{}': invalid target address '{}'", rule.name, rule.target)
            })?;
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
