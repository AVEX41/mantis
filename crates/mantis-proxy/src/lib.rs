//! Intercepting HTTP proxy: listener, request forwarding and history logging.
//!
//! Requests and responses are forwarded byte-for-byte (see `mantis_core::wire`)
//! and every exchange is stored raw. Plain HTTP only: `CONNECT` is answered
//! with 501 until HTTPS interception exists.

mod conn;
mod target;

use std::net::SocketAddr;
use std::sync::Arc;

use mantis_core::wire::Limits;
use mantis_core::{Exchange, Scope, Store, Summary};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::{JoinHandle, JoinSet};

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
}

impl Default for Config {
    fn default() -> Self {
        Config {
            listen: SocketAddr::from(([127, 0, 0, 1], 8080)),
            allow_non_loopback: false,
            scope: None,
            limits: Limits::default(),
        }
    }
}

/// Errors starting the proxy.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    /// Binding or socket setup failed.
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    /// A non-loopback listen address was given without opting in.
    #[error("refusing to listen on non-loopback address {0} without allow_non_loopback")]
    NonLoopback(SocketAddr),
}

/// A running proxy.
pub struct ProxyHandle {
    addr: SocketAddr,
    events: broadcast::Sender<Summary>,
    stop: oneshot::Sender<()>,
    accept: JoinHandle<()>,
    writer: std::thread::JoinHandle<()>,
}

impl ProxyHandle {
    /// The address actually bound (useful with port 0).
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Receive a [`Summary`] for each exchange as it is stored.
    pub fn subscribe(&self) -> broadcast::Receiver<Summary> {
        self.events.subscribe()
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
    let (events, _) = broadcast::channel(256);
    let (log_tx, log_rx) = mpsc::channel::<Exchange>(1024);
    let writer = std::thread::Builder::new()
        .name("mantis-store".into())
        .spawn({
            let events = events.clone();
            move || write_loop(store, log_rx, events)
        })?;
    let ctx = Arc::new(conn::Ctx {
        listen: addr,
        scope: config.scope,
        limits: config.limits,
        log: log_tx,
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
        stop,
        accept,
        writer,
    })
}

fn write_loop(store: Store, mut rx: mpsc::Receiver<Exchange>, events: broadcast::Sender<Summary>) {
    while let Some(ex) = rx.blocking_recv() {
        match store.insert(&ex).and_then(|id| store.summary(id)) {
            Ok(Some(s)) => {
                let _ = events.send(s); // no subscribers is fine
            }
            Ok(None) => tracing::error!("inserted row vanished"),
            Err(e) => tracing::error!(error = %e, "failed to store exchange"),
        }
    }
}
