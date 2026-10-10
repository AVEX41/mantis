//! Intercept queue: hold messages until a frontend forwards, edits or drops them.
//!
//! Frontends drive it through [`Intercept`]: turn a direction on or off, watch
//! [`Held`] events, and [`Intercept::decide`] each one. Edited bytes are
//! forwarded exactly as given.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use mantis_core::wire::Reader;
use tokio::io::AsyncRead;
use tokio::sync::{broadcast, oneshot};

use crate::Dir;

/// Stop reading from a held client once this much is buffered.
const MAX_PIPELINED: usize = 1 << 20;

/// What to do with a held message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Send it unchanged.
    Forward,
    /// Send these bytes instead, exactly as given.
    Edited(Bytes),
    /// Discard it and close the client connection without a reply.
    Drop,
}

/// A message waiting for a decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    /// Id to pass to [`Intercept::decide`].
    pub id: u64,
    /// Request or response.
    pub dir: Dir,
    /// Target host.
    pub host: String,
    /// Target port.
    pub port: u16,
    /// Whether the connection is TLS.
    pub tls: bool,
    /// The message as it would be sent.
    pub raw: Bytes,
}

struct Pending {
    held: Held,
    tx: oneshot::Sender<Decision>,
}

struct Inner {
    request_on: AtomicBool,
    response_on: AtomicBool,
    next_id: AtomicU64,
    pending: Mutex<HashMap<u64, Pending>>,
    events: broadcast::Sender<Held>,
}

/// Handle to the intercept queue. Cheap to clone.
#[derive(Clone)]
pub struct Intercept {
    inner: Arc<Inner>,
}

/// How a hold ended.
pub(crate) enum HoldOutcome {
    Decided(Decision),
    /// The client connection failed while waiting.
    ClientGone,
}

struct Guard<'a> {
    inner: &'a Inner,
    id: u64,
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        self.inner
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&self.id);
    }
}

impl Default for Intercept {
    fn default() -> Self {
        Self::new()
    }
}

impl Intercept {
    /// A queue with interception off for both directions.
    pub fn new() -> Self {
        let (events, _) = broadcast::channel(256);
        Intercept {
            inner: Arc::new(Inner {
                request_on: AtomicBool::new(false),
                response_on: AtomicBool::new(false),
                next_id: AtomicU64::new(1),
                pending: Mutex::new(HashMap::new()),
                events,
            }),
        }
    }

    fn flag(&self, dir: Dir) -> &AtomicBool {
        match dir {
            Dir::Request => &self.inner.request_on,
            Dir::Response => &self.inner.response_on,
        }
    }

    /// Whether messages in this direction are held.
    pub fn is_enabled(&self, dir: Dir) -> bool {
        self.flag(dir).load(Ordering::SeqCst)
    }

    /// Turn holding on or off. Turning it off forwards everything already held in that direction.
    pub fn set_enabled(&self, dir: Dir, on: bool) {
        self.flag(dir).store(on, Ordering::SeqCst);
        if !on {
            let ids: Vec<u64> = self
                .pending()
                .iter()
                .filter(|h| h.dir == dir)
                .map(|h| h.id)
                .collect();
            for id in ids {
                self.decide(id, Decision::Forward);
            }
        }
    }

    /// Receive each message as it is held.
    pub fn subscribe(&self) -> broadcast::Receiver<Held> {
        self.inner.events.subscribe()
    }

    /// Messages currently waiting, oldest first.
    pub fn pending(&self) -> Vec<Held> {
        let mut v: Vec<Held> = self
            .inner
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .map(|p| p.held.clone())
            .collect();
        v.sort_by_key(|h| h.id);
        v
    }

    /// Resolve a held message. Returns false if `id` is unknown (already
    /// decided, or the client went away).
    pub fn decide(&self, id: u64, decision: Decision) -> bool {
        let p = self
            .inner
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&id);
        p.is_some_and(|p| p.tx.send(decision).is_ok())
    }

    /// Hold `raw` until decided. While waiting, keep watching the client so a
    /// connection error releases the entry. A clean end of the client's
    /// stream is treated as a half-close, not a disconnect, because such
    /// clients may still be waiting for the reply.
    pub(crate) async fn hold<R: AsyncRead + Unpin>(
        &self,
        client: &mut Reader<R>,
        dir: Dir,
        host: &str,
        port: u16,
        tls: bool,
        raw: &Bytes,
    ) -> HoldOutcome {
        let id = self.inner.next_id.fetch_add(1, Ordering::SeqCst);
        let held = Held {
            id,
            dir,
            host: host.to_string(),
            port,
            tls,
            raw: raw.clone(),
        };
        let (tx, mut rx) = oneshot::channel();
        self.inner
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(
                id,
                Pending {
                    held: held.clone(),
                    tx,
                },
            );
        let _guard = Guard {
            inner: &self.inner,
            id,
        };
        let _ = self.inner.events.send(held);
        let mut reading = true;
        loop {
            tokio::select! {
                d = &mut rx => return HoldOutcome::Decided(d.unwrap_or(Decision::Forward)),
                n = client.fill_more(), if reading && client.buffered_len() < MAX_PIPELINED => match n {
                    Err(_) => return HoldOutcome::ClientGone,
                    Ok(0) => reading = false,
                    Ok(_) => {}
                },
            }
        }
    }
}
