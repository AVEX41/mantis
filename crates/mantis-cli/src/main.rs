//! Headless frontend for Mantis.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use mantis_core::{Scope, Store};
use mantis_proxy::{serve, Config};

#[derive(Parser)]
#[command(version, about = "Mantis security-testing toolkit")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the HTTP proxy and log traffic to a SQLite database.
    Proxy {
        /// Address to listen on.
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen: SocketAddr,
        /// Project database (created if missing).
        #[arg(long, default_value = "mantis.db")]
        db: PathBuf,
        /// TOML scope file; when given, only in-scope traffic is logged.
        #[arg(long)]
        scope: Option<PathBuf>,
        /// Allow listening on a non-loopback address (exposes the proxy to the network).
        #[arg(long)]
        allow_non_loopback: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    match Cli::parse().cmd {
        Cmd::Proxy {
            listen,
            db,
            scope,
            allow_non_loopback,
        } => {
            let scope = scope
                .map(|p| {
                    let text = std::fs::read_to_string(&p)
                        .with_context(|| format!("reading {}", p.display()))?;
                    Scope::from_toml(&text).with_context(|| format!("parsing {}", p.display()))
                })
                .transpose()?;
            let store = Store::open(&db).with_context(|| format!("opening {}", db.display()))?;
            let config = Config {
                listen,
                allow_non_loopback,
                scope,
                ..Config::default()
            };
            let proxy = serve(config, store).await?;
            let mut events = proxy.subscribe();
            tracing::info!(db = %db.display(), "logging to database; Ctrl-C to stop");
            loop {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => break,
                    Ok(s) = events.recv() => println!(
                        "#{} {} {}:{} {} -> {}",
                        s.id,
                        s.method.as_deref().unwrap_or("?"),
                        s.host,
                        s.port,
                        s.path.as_deref().unwrap_or("?"),
                        s.status.map_or("no response".to_string(), |c| c.to_string()),
                    ),
                }
            }
            proxy.shutdown().await;
            Ok(())
        }
    }
}
