mod config;
mod direct;
mod logging;
mod relay;
mod util;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::info;

use config::Config;

#[derive(Parser, Debug)]
#[command(name = "tunnelx", version, about = "Multi-mode TCP/TLS/WS tunnel")]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate a self-signed TLS certificate + key for the tls/wss transports.
    Gencert {
        /// Hostname/identity embedded in the certificate (informational only).
        #[arg(long, default_value = "tunnelx")]
        hostname: String,
        #[arg(long, default_value = "cert.pem")]
        cert_out: PathBuf,
        #[arg(long, default_value = "key.pem")]
        key_out: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if let Some(Command::Gencert { hostname, cert_out, key_out }) = args.command {
        relay::tls::generate_self_signed(&hostname, &cert_out, &key_out)?;
        println!("wrote {} and {}", cert_out.display(), key_out.display());
        return Ok(());
    }

    let config = Config::load(&args.config)?;
    let log_handle = logging::init(config.log_level())?;

    // Printed directly to stderr, bypassing the log_level filter entirely: this
    // is the one thing you always want to see regardless of verbosity setting.
    match &config {
        Config::Direct(c) => eprintln!(
            "tunnelx v{} starting — mode=direct rules={} config={} log_level={}",
            env!("CARGO_PKG_VERSION"), c.forwards.len(), args.config.display(), c.log_level
        ),
        Config::Client(c) => eprintln!(
            "tunnelx v{} starting — mode=client server={} transport={:?} tunnels={} log_level={}",
            env!("CARGO_PKG_VERSION"), c.server, c.transport, c.tunnels.len(), c.log_level
        ),
        Config::Server(c) => eprintln!(
            "tunnelx v{} starting — mode=server listen={} transport={:?} tunnels={} log_level={}",
            env!("CARGO_PKG_VERSION"), c.listen, c.transport, c.tunnels.len(), c.log_level
        ),
    }

    match config {
        Config::Direct(direct_config) => {
            tokio::select! {
                _ = direct::supervisor::run(args.config, direct_config, log_handle) => {}
                _ = tokio::signal::ctrl_c() => info!("shutdown signal received"),
            }
        }
        Config::Client(client_config) => {
            tokio::select! {
                r = relay::client::run(client_config) => { r?; }
                _ = tokio::signal::ctrl_c() => info!("shutdown signal received"),
            }
        }
        Config::Server(server_config) => {
            tokio::select! {
                r = relay::server::run(server_config) => { r?; }
                _ = tokio::signal::ctrl_c() => info!("shutdown signal received"),
            }
        }
    }

    Ok(())
}
