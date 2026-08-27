mod config;
mod forward;
mod logging;
mod supervisor;

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use tracing::info;

use config::Config;

#[derive(Parser, Debug)]
#[command(name = "tunnelx", version, about = "Simple TCP port forwarder")]
struct Args {
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let config = Config::load(&args.config)?;
    let log_handle = logging::init(&config.log_level)?;

    info!(
        rules = config.forwards.len(),
        config = %args.config.display(),
        log_level = %config.log_level,
        "starting tunnelx (config auto-reloads on change)"
    );

    tokio::select! {
        _ = supervisor::run(args.config, config, log_handle) => {}
        _ = tokio::signal::ctrl_c() => {
            info!("shutdown signal received");
        }
    }

    Ok(())
}
