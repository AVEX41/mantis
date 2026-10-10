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
    /// The request as captured, when rewrite rules or an edit changed what
    /// was sent (`request` then holds the bytes actually sent).
    pub request_original: Option<Bytes>,
    /// The response as received, when it was changed before reaching the client.
    pub response_original: Option<Bytes>,
    /// The user dropped the request or response from the intercept queue.
    pub dropped: bool,
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
    /// Rewrite rules or an edit changed the request or response.
    pub modified: bool,
    /// The user dropped the exchange from the intercept queue.
    pub dropped: bool,
}

/// Current time as unix microseconds (0 if the clock is before the epoch).
pub fn now_micros() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_micros()).ok())
        .unwrap_or(0)
}

/// Which way a WebSocket frame travelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsDir {
    /// Client to server.
    ToServer,
    /// Server to client.
    ToClient,
}

/// One WebSocket frame belonging to an upgraded exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsFrame {
    /// The exchange (upgrade request and `101` response) it belongs to.
    pub exchange_id: i64,
    /// Time the frame was completed, unix microseconds.
    pub ts_micros: i64,
    /// Direction of travel.
    pub dir: WsDir,
    /// Opcode from the frame header.
    pub opcode: u8,
    /// FIN bit.
    pub fin: bool,
    /// RSV1 bit (compressed with permessage-deflate).
    pub compressed: bool,
    /// Real payload length, even when `raw` was cut short.
    pub payload_len: u64,
    /// `raw` holds only part of the payload.
    pub truncated: bool,
    /// The frame exactly as on the wire (header plus payload, possibly truncated).
    pub raw: Bytes,
}

/// A [`WsFrame`] with its storage id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredWsFrame {
    /// Row id.
    pub id: i64,
    /// The frame.
    pub frame: WsFrame,
}
