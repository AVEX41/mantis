//! Runs the proxy on a background runtime so the UI thread never waits on it.
//!
//! The UI sends [`Cmd`]s and polls [`Event`]s; `wake` is called after each
//! event so the window repaints.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;

use mantis_core::{Scope, Store};
use mantis_proxy::ca::Ca;
use mantis_proxy::{serve, Config, ProxyHandle};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

use crate::settings::StartConfig;

/// A request from the UI.
#[derive(Debug)]
pub enum Cmd {
    /// Start the proxy.
    Start(StartConfig),
    /// Stop the proxy (open connections are dropped).
    Stop,
    /// Replace the scope of the running proxy.
    SetScope(Option<Scope>),
    /// Write the CA certificate (never the key) to `out`, creating the CA if needed.
    ExportCa {
        /// CA directory; `None` for the default.
        ca_dir: Option<PathBuf>,
        /// Destination; must not exist.
        out: PathBuf,
        /// DER instead of PEM.
        der: bool,
    },
}

/// Something that happened in the background.
#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    /// The proxy is listening.
    Started {
        /// Bound address.
        addr: SocketAddr,
        /// SHA-256 fingerprint of the CA certificate in use.
        fingerprint: String,
    },
    /// The proxy stopped.
    Stopped,
    /// At least one exchange was stored since the last [`Backend::ack_logged`].
    Logged,
    /// The CA certificate was written.
    CaExported {
        /// Where.
        path: PathBuf,
        /// Its fingerprint.
        fingerprint: String,
    },
    /// Something failed; the text is for the user.
    Error(String),
}

/// Handle to the background runtime. Dropping it stops the proxy.
pub struct Backend {
    tx: Option<UnboundedSender<Cmd>>,
    rx: Receiver<Event>,
    logged: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Backend {
    /// Start the runtime thread. `wake` runs after every event.
    pub fn spawn(wake: impl Fn() + Send + Sync + 'static) -> std::io::Result<Backend> {
        let (tx, cmd_rx) = unbounded_channel();
        let (evt_tx, rx) = mpsc::channel();
        let logged = Arc::new(AtomicBool::new(false));
        let flag = logged.clone();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("mantis-backend")
            .enable_all()
            .build()?;
        let thread = std::thread::Builder::new()
            .name("mantis-backend-main".into())
            .spawn(move || {
                rt.block_on(run(
                    cmd_rx,
                    Emit {
                        tx: evt_tx,
                        wake: Arc::new(wake),
                    },
                    flag,
                ));
            })?;
        Ok(Backend {
            tx: Some(tx),
            rx,
            logged,
            thread: Some(thread),
        })
    }

    /// Queue a command.
    pub fn send(&self, cmd: Cmd) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(cmd);
        }
    }

    /// Next event, if one is ready.
    pub fn try_recv(&self) -> Option<Event> {
        self.rx.try_recv().ok()
    }

    /// Call after handling [`Event::Logged`] so the next stored exchange raises it again.
    pub fn ack_logged(&self) {
        self.logged.store(false, Ordering::SeqCst);
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        self.tx = None; // ends the command loop, which stops the proxy
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

#[derive(Clone)]
struct Emit {
    tx: Sender<Event>,
    wake: Arc<dyn Fn() + Send + Sync>,
}

impl Emit {
    fn send(&self, e: Event) {
        if self.tx.send(e).is_ok() {
            (self.wake)();
        }
    }

    fn error(&self, msg: impl Into<String>) {
        self.send(Event::Error(msg.into()));
    }
}

async fn run(mut cmds: UnboundedReceiver<Cmd>, emit: Emit, logged: Arc<AtomicBool>) {
    let mut proxy: Option<ProxyHandle> = None;
    let mut forwarder: Option<tokio::task::JoinHandle<()>> = None;
    while let Some(cmd) = cmds.recv().await {
        match cmd {
            Cmd::Start(_) if proxy.is_some() => emit.error("the proxy is already running"),
            Cmd::Start(cfg) => match start(cfg).await {
                Ok((handle, fingerprint)) => {
                    let (mut sub, e, flag) = (handle.subscribe(), emit.clone(), logged.clone());
                    forwarder = Some(tokio::spawn(async move {
                        use tokio::sync::broadcast::error::RecvError;
                        while let Ok(_) | Err(RecvError::Lagged(_)) = sub.recv().await {
                            if !flag.swap(true, Ordering::SeqCst) {
                                e.send(Event::Logged);
                            }
                        }
                    }));
                    let addr = handle.local_addr();
                    proxy = Some(handle);
                    emit.send(Event::Started { addr, fingerprint });
                }
                Err(msg) => emit.error(msg),
            },
            Cmd::Stop => {
                if let Some(p) = proxy.take() {
                    p.shutdown().await;
                    if let Some(f) = forwarder.take() {
                        f.abort();
                    }
                }
                emit.send(Event::Stopped);
            }
            Cmd::SetScope(scope) => {
                if let Some(p) = &proxy {
                    p.set_scope(scope);
                }
            }
            Cmd::ExportCa { ca_dir, out, der } => match export_ca(ca_dir, out, der).await {
                Ok((path, fingerprint)) => emit.send(Event::CaExported { path, fingerprint }),
                Err(msg) => emit.error(msg),
            },
        }
    }
    if let Some(p) = proxy {
        p.shutdown().await;
    }
}

async fn start(cfg: StartConfig) -> Result<(ProxyHandle, String), String> {
    let StartConfig {
        db,
        listen,
        allow_non_loopback,
        insecure_upstream,
        ca_dir,
        scope,
    } = cfg;
    let store = tokio::task::spawn_blocking(move || {
        Store::open(&db).map_err(|e| format!("cannot open the project database: {e}"))
    })
    .await
    .map_err(|e| e.to_string())??;
    let ca = load_ca(ca_dir).await?;
    let fingerprint = ca.fingerprint();
    let config = Config {
        listen,
        allow_non_loopback,
        scope,
        ca: Some(Arc::new(ca)),
        insecure_upstream,
        ..Config::default()
    };
    let handle = serve(config, store)
        .await
        .map_err(|e| format!("cannot start the proxy on {listen}: {e}"))?;
    Ok((handle, fingerprint))
}

async fn load_ca(dir: Option<PathBuf>) -> Result<Ca, String> {
    tokio::task::spawn_blocking(move || {
        let dir = match dir {
            Some(d) => d,
            None => Ca::default_dir().map_err(|e| e.to_string())?,
        };
        Ca::load_or_create(&dir).map_err(|e| format!("CA in {}: {e}", dir.display()))
    })
    .await
    .map_err(|e| e.to_string())?
}

async fn export_ca(
    dir: Option<PathBuf>,
    out: PathBuf,
    der: bool,
) -> Result<(PathBuf, String), String> {
    let ca = load_ca(dir).await?;
    tokio::task::spawn_blocking(move || {
        let bytes = if der {
            ca.cert_der().as_ref().to_vec()
        } else {
            ca.cert_pem().as_bytes().to_vec()
        };
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&out)
            .map_err(|e| format!("cannot create {}: {e}", out.display()))?;
        std::io::Write::write_all(&mut f, &bytes)
            .map_err(|e| format!("cannot write {}: {e}", out.display()))?;
        Ok((out, ca.fingerprint()))
    })
    .await
    .map_err(|e| e.to_string())?
}
