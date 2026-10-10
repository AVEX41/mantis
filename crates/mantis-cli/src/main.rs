//! Headless frontend for Mantis.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use mantis_core::{Scope, Store};
use mantis_proxy::ca::Ca;
use mantis_proxy::intercept::Decision;
use mantis_proxy::{rewrite, Dir};
use mantis_proxy::{serve, Config};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

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
        /// Directory holding the local CA (default: the user data directory).
        #[arg(long)]
        ca_dir: Option<PathBuf>,
        /// TOML file of match-and-replace rules (`[[rules]]` tables).
        #[arg(long)]
        rules: Option<PathBuf>,
        /// Hold each in-scope request and ask on stdin: f = forward, d = drop.
        #[arg(long)]
        intercept: bool,
        /// Also hold responses.
        #[arg(long)]
        intercept_responses: bool,
        /// DANGEROUS: do not verify origin server certificates. For lab targets with self-signed certificates only.
        #[arg(long)]
        insecure_upstream: bool,
    },
    /// Manage the local CA used to intercept HTTPS.
    Ca {
        /// Directory holding the local CA (default: the user data directory).
        #[arg(long, global = true)]
        ca_dir: Option<PathBuf>,
        #[command(subcommand)]
        action: CaCmd,
    },
}

#[derive(Subcommand)]
enum CaCmd {
    /// Print where the CA files live.
    Path,
    /// Write the CA certificate (never the key) so it can be imported into a browser or OS.
    Export {
        /// Destination file; must not exist.
        #[arg(long)]
        out: PathBuf,
        /// Output format.
        #[arg(long, value_enum, default_value = "pem")]
        format: Format,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Pem,
    Der,
}

fn ca_dir(arg: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    match arg {
        Some(d) => Ok(d),
        None => Ca::default_dir().context("locating the CA directory"),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    match Cli::parse().cmd {
        Cmd::Ca {
            ca_dir: dir,
            action,
        } => {
            let dir = ca_dir(dir)?;
            match action {
                CaCmd::Path => println!("{}", dir.display()),
                CaCmd::Export { out, format } => {
                    let ca = Ca::load_or_create(&dir)
                        .with_context(|| format!("loading CA in {}", dir.display()))?;
                    let bytes = match format {
                        Format::Pem => ca.cert_pem().as_bytes().to_vec(),
                        Format::Der => ca.cert_der().as_ref().to_vec(),
                    };
                    let mut f = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&out)
                        .with_context(|| format!("creating {}", out.display()))?;
                    std::io::Write::write_all(&mut f, &bytes)?;
                    eprintln!(
                        "wrote CA certificate to {} (SHA-256 {})",
                        out.display(),
                        ca.fingerprint()
                    );
                }
            }
            Ok(())
        }
        Cmd::Proxy {
            listen,
            db,
            scope,
            allow_non_loopback,
            ca_dir: dir,
            rules,
            intercept,
            intercept_responses,
            insecure_upstream,
        } => {
            let rewrite = match rules {
                Some(p) => {
                    let text = std::fs::read_to_string(&p)
                        .with_context(|| format!("reading {}", p.display()))?;
                    rewrite::parse_rules(&text)
                        .with_context(|| format!("parsing {}", p.display()))?
                }
                None => Vec::new(),
            };
            let scope = scope
                .map(|p| {
                    let text = std::fs::read_to_string(&p)
                        .with_context(|| format!("reading {}", p.display()))?;
                    Scope::from_toml(&text).with_context(|| format!("parsing {}", p.display()))
                })
                .transpose()?;
            let store = Store::open(&db).with_context(|| format!("opening {}", db.display()))?;
            let dir = ca_dir(dir)?;
            let ca = Ca::load_or_create(&dir)
                .with_context(|| format!("loading CA in {}", dir.display()))?;
            tracing::info!(
                dir = %dir.display(),
                fingerprint = %ca.fingerprint(),
                "HTTPS interception enabled; import the CA with `mantis-cli ca export`"
            );
            if insecure_upstream {
                tracing::warn!("--insecure-upstream: origin certificates are NOT verified");
            }
            let config = Config {
                listen,
                allow_non_loopback,
                scope,
                ca: Some(Arc::new(ca)),
                insecure_upstream,
                rewrite,
                ..Config::default()
            };
            let proxy = serve(config, store).await?;
            let queue = proxy.intercept();
            queue.set_enabled(Dir::Request, intercept);
            queue.set_enabled(Dir::Response, intercept_responses);
            if intercept || intercept_responses {
                tokio::spawn(prompt(queue));
            }
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

/// Show raw bytes safely: control characters and non-ASCII bytes are escaped so
/// captured traffic cannot drive the terminal.
fn printable(raw: &[u8]) -> String {
    raw.iter()
        .take(4000)
        .map(|&b| match b {
            b'\n' | b'\t' | 0x20..=0x7e => (b as char).to_string(),
            b'\r' => "\\r".to_string(),
            _ => format!("\\x{b:02x}"),
        })
        .collect()
}

/// Ask on stdin what to do with each held message. If stdin closes,
/// interception is turned off so nothing stays stuck.
async fn prompt(queue: mantis_proxy::intercept::Intercept) {
    let mut held = queue.subscribe();
    let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
    loop {
        let h = match held.recv().await {
            Ok(h) => h,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(_) => return,
        };
        println!(
            "--- held {:?} #{} {}:{} ---\n{}",
            h.dir,
            h.id,
            h.host,
            h.port,
            printable(&h.raw)
        );
        let decision = loop {
            print!("[f]orward / [d]rop? ");
            let _ = tokio::io::stdout().flush().await;
            match lines.next_line().await {
                Ok(Some(l)) if l.trim().eq_ignore_ascii_case("f") => break Decision::Forward,
                Ok(Some(l)) if l.trim().eq_ignore_ascii_case("d") => break Decision::Drop,
                Ok(Some(_)) => {}
                _ => {
                    queue.set_enabled(Dir::Request, false);
                    queue.set_enabled(Dir::Response, false);
                    return;
                }
            }
        };
        queue.decide(h.id, decision);
    }
}

#[cfg(test)]
mod tests {
    use super::printable;

    #[test]
    fn terminal_escapes_in_captured_traffic_are_neutralised() {
        let shown = printable(b"GET / HTTP/1.1\r\nX: \x1b]0;pwned\x07\xff\r\n\r\n");
        assert!(!shown.contains('\x1b') && !shown.contains('\x07'));
        assert!(shown.contains("\\x1b") && shown.contains("\\xff") && shown.contains("\\r"));
    }
}
