use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

fn default_log_level() -> String {
    "info".to_string()
}

#[derive(Debug, Deserialize)]
pub struct Config {
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

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file: {}", path.display()))?;
        let config: Config = toml::from_str(&raw).context("failed to parse config file")?;
        config.validate()?;
        Ok(config)
    }

    /// Rules keyed by name, for diffing against a previous config on reload.
    pub fn by_name(self) -> HashMap<String, ForwardRule> {
        self.forwards.into_iter().map(|r| (r.name.clone(), r)).collect()
    }

    fn validate(&self) -> Result<()> {
        const VALID_LEVELS: [&str; 6] = ["off", "error", "warn", "info", "debug", "trace"];
        if !VALID_LEVELS.contains(&self.log_level.to_lowercase().as_str()) {
            bail!(
                "invalid log_level '{}' (expected one of: {})",
                self.log_level,
                VALID_LEVELS.join(", ")
            );
        }

        if self.forwards.is_empty() {
            bail!("config must contain at least one [[forward]] entry");
        }

        let mut seen_listen = HashSet::new();
        let mut seen_name = HashSet::new();
        for rule in &self.forwards {
            rule.listen
                .parse::<std::net::SocketAddr>()
                .with_context(|| {
                    format!("forward '{}': invalid listen address '{}'", rule.name, rule.listen)
                })?;
            rule.target
                .parse::<std::net::SocketAddr>()
                .with_context(|| {
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
