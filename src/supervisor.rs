use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};

use crate::config::{Config, ForwardRule};
use crate::forward::{self, Registry};
use crate::logging;

const RELOAD_POLL_INTERVAL: Duration = Duration::from_secs(2);

struct ActiveRule {
    handle: JoinHandle<()>,
}

/// Runs all forward rules and watches the config file for changes, hot-reloading
/// added/removed/changed rules without restarting the whole process. A rule whose
/// `listen` address didn't change keeps its listener socket bound (no dropped
/// connections mid-reload); only `target` is updated live. A changed `listen`
/// (or a removed/added rule) rebinds just that one listener.
pub async fn run(config_path: PathBuf, initial: Config, log_handle: logging::Handle) {
    let mut current_log_level = initial.log_level.clone();
    let registry: Registry = Arc::new(RwLock::new(initial.by_name()));
    let mut active: HashMap<String, ActiveRule> = HashMap::new();
    let mut last_modified = file_modified(&config_path);

    for rule in registry.read().await.values().cloned().collect::<Vec<_>>() {
        spawn_rule(&mut active, &registry, rule);
    }

    let mut ticker = interval(RELOAD_POLL_INTERVAL);
    loop {
        ticker.tick().await;

        let modified = file_modified(&config_path);
        if modified == last_modified {
            continue;
        }
        last_modified = modified;

        let new_config = match Config::load(&config_path) {
            Ok(c) => c,
            Err(e) => {
                error!(error = %e, "config reload failed, keeping previous config");
                continue;
            }
        };

        if new_config.log_level != current_log_level {
            match logging::set_level(&log_handle, &new_config.log_level) {
                Ok(()) => {
                    info!(old = %current_log_level, new = %new_config.log_level, "log level updated");
                    current_log_level = new_config.log_level.clone();
                }
                Err(e) => error!(error = %e, "failed to apply new log level, keeping previous"),
            }
        }

        reload(&mut active, &registry, new_config).await;
    }
}

async fn reload(active: &mut HashMap<String, ActiveRule>, registry: &Registry, new: Config) {
    let new_rules = new.by_name();

    // Snapshot the old state, then apply the diff without holding the lock
    // across the loop (spawn_rule/abort don't need it held).
    let old_rules = registry.read().await.clone();

    let removed: Vec<String> = old_rules
        .keys()
        .filter(|name| !new_rules.contains_key(*name))
        .cloned()
        .collect();
    for name in &removed {
        if let Some(rule) = active.remove(name) {
            rule.handle.abort();
        }
        info!(name = %name, "forward removed");
    }

    let mut to_spawn = Vec::new();
    for (name, rule) in &new_rules {
        match old_rules.get(name) {
            None => {
                info!(name = %name, listen = %rule.listen, target = %rule.target, "forward added");
                to_spawn.push(rule.clone());
            }
            Some(existing) if existing.listen != rule.listen => {
                if let Some(old) = active.remove(name) {
                    old.handle.abort();
                }
                info!(name = %name, old_listen = %existing.listen, new_listen = %rule.listen, "forward listen address changed, rebinding");
                to_spawn.push(rule.clone());
            }
            Some(existing) if existing.target != rule.target => {
                info!(name = %name, old_target = %existing.target, new_target = %rule.target, "forward target updated");
            }
            _ => {}
        }
    }

    {
        let mut current = registry.write().await;
        *current = new_rules;
    }

    for rule in to_spawn {
        spawn_rule(active, registry, rule);
    }
}

fn spawn_rule(active: &mut HashMap<String, ActiveRule>, registry: &Registry, rule: ForwardRule) {
    let name = rule.name.clone();
    let registry = registry.clone();
    let handle = tokio::spawn(async move {
        if let Err(e) = forward::run(rule.name.clone(), rule.listen.clone(), registry).await {
            error!(name = %rule.name, error = %e, "forward rule stopped");
        }
    });
    active.insert(name, ActiveRule { handle });
}

fn file_modified(path: &PathBuf) -> Option<SystemTime> {
    match std::fs::metadata(path).and_then(|m| m.modified()) {
        Ok(t) => Some(t),
        Err(e) => {
            warn!(path = %path.display(), error = %e, "could not stat config file for reload watch");
            None
        }
    }
}
