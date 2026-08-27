use anyhow::{Context, Result};
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::reload;
use tracing_subscriber::util::SubscriberInitExt;

pub type Handle = reload::Handle<EnvFilter, tracing_subscriber::Registry>;

/// Sets up logging with `level` (e.g. "error", "warn", "info", "debug", "trace") as
/// the default filter. `RUST_LOG`, if set, always takes precedence over the config
/// value — useful for a one-off debug run without editing the config file.
/// Returns a handle that lets the level be changed later (used for config hot-reload).
pub fn init(level: &str) -> Result<Handle> {
    let filter = build_filter(level)?;
    let (filter, handle) = reload::Layer::new(filter);

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .init();

    Ok(handle)
}

/// Applies a new log level at runtime (e.g. after a config reload). No-op if
/// `RUST_LOG` is set in the environment, since that's meant to override the config.
pub fn set_level(handle: &Handle, level: &str) -> Result<()> {
    if std::env::var_os("RUST_LOG").is_some() {
        return Ok(());
    }
    let filter = build_filter(level)?;
    handle.reload(filter).context("failed to apply new log level")?;
    // tracing caches each log callsite's enabled/disabled "interest" the first time
    // it fires; without this, callsites already marked enabled under the old filter
    // stay enabled forever regardless of what the new filter says.
    tracing::callsite::rebuild_interest_cache();
    Ok(())
}

fn build_filter(level: &str) -> Result<EnvFilter> {
    if let Ok(from_env) = std::env::var("RUST_LOG") {
        return EnvFilter::try_new(&from_env).context("invalid RUST_LOG value");
    }
    EnvFilter::try_new(level)
        .with_context(|| format!("invalid log_level '{level}' (expected one of: off, error, warn, info, debug, trace)"))
}
