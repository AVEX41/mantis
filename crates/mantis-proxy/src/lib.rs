//! Intercepting HTTP proxy: listener, request forwarding and history logging.
//!
//! Requests and responses are forwarded byte-for-byte (see `mantis_core::wire`)
//! and every exchange is stored raw. Plain HTTP only: `CONNECT` is answered
//! with 501 until HTTPS interception exists.

pub mod ca;
mod conn;
pub mod intercept;
pub mod rewrite;
mod target;
mod tls;

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use mantis_core::wire::Limits;
use mantis_core::{Exchange, Scope, Store, Summary, WsDir, WsFrame};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::{JoinHandle, JoinSet};

/// What the store writer thread is asked to do.
pub(crate) enum LogCmd {
    /// Store an exchange; send back its id if someone is waiting for it.
    Exchange {
        ex: Exchange,
        reply: Option<oneshot::Sender<i64>>,
    },
    /// Store a WebSocket frame of an already stored exchange.
    Frame(WsFrame),
}

/// A WebSocket frame that was just stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsEvent {
    /// Row id of the frame.
    pub id: i64,
    /// The exchange it belongs to.
    pub exchange_id: i64,
    /// Direction of travel.
    pub dir: WsDir,
    /// Opcode from the frame header.
    pub opcode: u8,
    /// FIN bit.
    pub fin: bool,
    /// Compressed with permessage-deflate (RSV1).
    pub compressed: bool,
    /// Real payload length.
    pub payload_len: u64,
    /// Only part of the payload was stored.
    pub truncated: bool,
}

/// Direction of a message through the proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    /// Client to origin.
    Request,
    /// Origin to client.
    Response,
}

/// Proxy settings.
#[derive(Debug, Clone)]
pub struct Config {
    /// Address to listen on.
    pub listen: SocketAddr,
    /// Permit binding a non-loopback address. Off by default: an exposed proxy
    /// would let anyone on the network send traffic through this machine.
    pub allow_non_loopback: bool,
    /// When set, only in-scope exchanges are logged. Everything is forwarded.
    pub scope: Option<Scope>,
    /// Message size limits.
    pub limits: Limits,
    /// CA used to intercept HTTPS. Without one, `CONNECT` gets a 501.
    pub ca: Option<Arc<ca::Ca>>,
    /// Skip verification of origin certificates. Off by default; meant for lab
    /// targets with self-signed certificates. Frontends must expose this
    /// same option and make its state obvious.
    pub insecure_upstream: bool,
    /// Match-and-replace rules applied to forwarded messages.
    pub rewrite: Vec<rewrite::RuleSpec>,
    /// Extra trusted roots for origin certificates, in addition to the OS store.
    pub extra_upstream_roots: Vec<rustls::pki_types::CertificateDer<'static>>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            listen: SocketAddr::from(([127, 0, 0, 1], 8080)),
            allow_non_loopback: false,
            scope: None,
            limits: Limits::default(),
            ca: None,
            insecure_upstream: false,
            rewrite: Vec::new(),
            extra_upstream_roots: Vec::new(),
        }
    }
}

/// Errors starting the proxy.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    /// Binding or socket setup failed.
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    /// A rewrite rule is invalid.
    #[error("rewrite rules: {0}")]
    Rewrite(#[from] rewrite::RewriteError),
    /// TLS setup failed.
    #[error("tls: {0}")]
    Tls(#[from] rustls::Error),
    /// A non-loopback listen address was given without opting in.
    #[error("refusing to listen on non-loopback address {0} without allow_non_loopback")]
    NonLoopback(SocketAddr),
}

/// A running proxy.
pub struct ProxyHandle {
    addr: SocketAddr,
    events: broadcast::Sender<Summary>,
    ws_events: broadcast::Sender<WsEvent>,
    stop: oneshot::Sender<()>,
    accept: JoinHandle<()>,
    writer: std::thread::JoinHandle<()>,
    intercept: intercept::Intercept,
    rewriter: rewrite::Rewriter,
    scope: Arc<RwLock<Option<Arc<Scope>>>>,
}

impl ProxyHandle {
    /// The address actually bound (useful with port 0).
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// The intercept queue (off until enabled).
    pub fn intercept(&self) -> intercept::Intercept {
        self.intercept.clone()
    }

    /// Replace the scope while running. `None` puts everything in scope.
    /// Exchanges already in flight keep the verdict they started with.
    pub fn set_scope(&self, scope: Option<Scope>) {
        *self.scope.write().unwrap_or_else(|p| p.into_inner()) = scope.map(Arc::new);
    }

    /// The match-and-replace rules; they can be replaced while running.
    pub fn rewriter(&self) -> rewrite::Rewriter {
        self.rewriter.clone()
    }

    /// Receive a [`Summary`] for each exchange as it is stored.
    pub fn subscribe(&self) -> broadcast::Receiver<Summary> {
        self.events.subscribe()
    }

    /// Receive a [`WsEvent`] for each captured WebSocket frame.
    pub fn subscribe_ws(&self) -> broadcast::Receiver<WsEvent> {
        self.ws_events.subscribe()
    }

    /// Stop accepting, drop open connections, and wait for the store writer to drain.
    pub async fn shutdown(self) {
        let _ = self.stop.send(());
        let _ = self.accept.await;
        let w = self.writer;
        let _ = tokio::task::spawn_blocking(move || w.join()).await;
    }
}

/// Bind and start the proxy. `store` moves to a dedicated writer thread so
/// SQLite never blocks the async runtime.
pub async fn serve(config: Config, store: Store) -> Result<ProxyHandle, ProxyError> {
    if !config.listen.ip().is_loopback() && !config.allow_non_loopback {
        return Err(ProxyError::NonLoopback(config.listen));
    }
    let listener = TcpListener::bind(config.listen).await?;
    let addr = listener.local_addr()?;
    let scope = Arc::new(RwLock::new(config.scope.map(Arc::new)));
    let rewriter = rewrite::Rewriter::new(config.rewrite)?;
    let intercept = intercept::Intercept::new();
    let mitm = match &config.ca {
        Some(ca) => Some(tls::Mitm {
            certs: Arc::new(tls::CertCache::new(ca.clone())),
            client: tls::client_config(config.insecure_upstream, &config.extra_upstream_roots)?,
        }),
        None => None,
    };
    let (events, _) = broadcast::channel(256);
    let (ws_events, _) = broadcast::channel(1024);
    let (log_tx, log_rx) = mpsc::channel::<LogCmd>(1024);
    let writer = std::thread::Builder::new()
        .name("mantis-store".into())
        .spawn({
            let (events, ws_events) = (events.clone(), ws_events.clone());
            move || write_loop(store, log_rx, events, ws_events)
        })?;
    let ctx = Arc::new(conn::Ctx {
        listen: addr,
        scope: scope.clone(),
        limits: config.limits,
        log: log_tx,
        mitm,
        intercept: intercept.clone(),
        rewriter: rewriter.clone(),
    });
    let (stop, mut stopped) = oneshot::channel();
    let accept = tokio::spawn(async move {
        let mut conns = JoinSet::new();
        loop {
            tokio::select! {
                _ = &mut stopped => break,
                // Reap finished connections so the set doesn't grow forever.
                Some(_) = conns.join_next(), if !conns.is_empty() => {}
                r = listener.accept() => match r {
                    Ok((stream, peer)) => {
                        tracing::debug!(%peer, "client connected");
                        conns.spawn(conn::handle(stream, ctx.clone()));
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "accept failed");
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                },
            }
        }
        conns.abort_all();
        while conns.join_next().await.is_some() {}
    });
    tracing::info!(%addr, "proxy listening");
    Ok(ProxyHandle {
        addr,
        events,
        ws_events,
        stop,
        accept,
        writer,
        intercept,
        rewriter,
        scope,
    })
}

fn write_loop(
    store: Store,
    mut rx: mpsc::Receiver<LogCmd>,
    events: broadcast::Sender<Summary>,
    ws_events: broadcast::Sender<WsEvent>,
) {
    while let Some(cmd) = rx.blocking_recv() {
        match cmd {
            LogCmd::Exchange { ex, reply } => match store.insert(&ex) {
                Ok(id) => {
                    if let Some(r) = reply {
                        let _ = r.send(id);
                    }
                    match store.summary(id) {
                        Ok(Some(s)) => {
                            let _ = events.send(s); // no subscribers is fine
                        }
                        Ok(None) => tracing::error!("inserted row vanished"),
                        Err(e) => tracing::error!(error = %e, "failed to read back exchange"),
                    }
                }
                Err(e) => tracing::error!(error = %e, "failed to store exchange"),
            },
            LogCmd::Frame(f) => match store.insert_ws_frame(&f) {
                Ok(id) => {
                    let _ = ws_events.send(WsEvent {
                        id,
                        exchange_id: f.exchange_id,
                        dir: f.dir,
                        opcode: f.opcode,
                        fin: f.fin,
                        compressed: f.compressed,
                        payload_len: f.payload_len,
                        truncated: f.truncated,
                    });
                }
                Err(e) => tracing::error!(error = %e, "failed to store websocket frame"),
            },
        }
    }
}
