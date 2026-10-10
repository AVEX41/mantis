//! The message model: one request/response pair as raw bytes plus metadata.

use bytes::Bytes;

/// Which tool produced an exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Captured by the intercepting proxy.
    Proxy,
    /// Sent from a replay tab.
    Replay,
    /// Sent by the fuzzer.
    Fuzz,
    /// Sent by the scanner.
    Scan,
}

impl Source {
    /// Stable name used in storage.
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Proxy => "proxy",
            Source::Replay => "replay",
            Source::Fuzz => "fuzz",
            Source::Scan => "scan",
        }
    }

    /// Inverse of [`Source::as_str`].
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "proxy" => Source::Proxy,
            "replay" => Source::Replay,
            "fuzz" => Source::Fuzz,
            "scan" => Source::Scan,
            _ => return None,
        })
    }
}

/// A request and optional response, exactly as they were on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exchange {
    /// Time of the request, unix microseconds (UTC).
    pub ts_micros: i64,
    /// Producing tool.
    pub source: Source,
    /// Target host (the connection target, not parsed from the request).
    pub host: String,
    /// Target port.
    pub port: u16,
    /// Whether the connection used TLS.
    pub tls: bool,
    /// Raw request bytes. Source of truth.
    pub request: Bytes,
    /// Raw response bytes, if one was received.
    pub response: Option<Bytes>,
}

/// An [`Exchange`] with its storage id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    /// Row id assigned by the store.
    pub id: i64,
    /// The stored exchange.
    pub exchange: Exchange,
}

/// Row summary for history lists; omits the raw bodies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    /// Row id.
    pub id: i64,
    /// Request time, unix microseconds.
    pub ts_micros: i64,
    /// Producing tool.
    pub source: Source,
    /// Target host.
    pub host: String,
    /// Target port.
    pub port: u16,
    /// Whether the connection used TLS.
    pub tls: bool,
    /// Request method, lossily decoded from the raw request.
    pub method: Option<String>,
    /// Request target, lossily decoded from the raw request.
    pub path: Option<String>,
    /// Response status code, if the response had a parseable one.
    pub status: Option<u16>,
}

/// Current time as unix microseconds (0 if the clock is before the epoch).
pub fn now_micros() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_micros()).ok())
        .unwrap_or(0)
}
