//! One client connection: read requests, forward them, relay and log responses.
//!
//! The same request loop serves plain HTTP and requests decrypted from an
//! intercepted `CONNECT` tunnel; only the way the upstream is reached differs.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use mantis_core::view::{Header, RequestView, ResponseView};
use mantis_core::wire::ws::{FrameScanner, DEFAULT_CAP};
use mantis_core::wire::{write_raw, Framing, Limits, Message, Reader, WireError};
use mantis_core::{now_micros, Exchange, Scope, Source, Target, Verdict, WsDir, WsFrame};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::intercept::{Decision, HoldOutcome, Intercept};
use crate::rewrite::Rewriter;
use crate::target::{connect_target, resolve, tunneled, Dest, Reject};
use crate::tls::{self, Mitm};
use crate::{Dir, LogCmd};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) struct Ctx {
    pub listen: SocketAddr,
    pub scope: Option<Scope>,
    pub limits: Limits,
    pub log: mpsc::Sender<LogCmd>,
    /// `None`: no CA configured, `CONNECT` is refused with 501.
    pub mitm: Option<Mitm>,
    pub intercept: Intercept,
    pub rewriter: Rewriter,
}

type BoxRead = Box<dyn AsyncRead + Send + Unpin>;
type BoxWrite = Box<dyn AsyncWrite + Send + Unpin>;

/// A connection to the origin.
struct Conn {
    reader: Reader<BoxRead>,
    writer: BoxWrite,
}

enum Mode<'a> {
    /// Plain HTTP from the client; a new upstream connection per request.
    Plain,
    /// Inside an intercepted tunnel to `host:port`; the upstream TLS connection is reused.
    Tls { host: &'a str, port: u16 },
}

enum Outcome {
    Done,
    /// The client asked for a tunnel; the caller decides what to do with the stream.
    Connect {
        host: String,
        port: u16,
    },
}

pub(crate) async fn handle(stream: TcpStream, ctx: Arc<Ctx>) {
    if let Err(e) = session(stream, &ctx).await {
        tracing::debug!(error = %e, "connection ended");
    }
}

async fn session(stream: TcpStream, ctx: &Ctx) -> std::io::Result<()> {
    let (cr, mut cw) = stream.into_split();
    let mut client = Reader::new(cr, ctx.limits);
    match serve_requests(&mut client, &mut cw, ctx, Mode::Plain).await? {
        Outcome::Done => Ok(()),
        Outcome::Connect { host, port } => {
            let (cr, left) = client.into_parts();
            tunnel_connect(ctx, host, port, cr, cw, left.to_vec()).await
        }
    }
}

/// Handle `CONNECT`: intercept when a CA is configured and the target may be
/// in scope, otherwise relay bytes untouched (nothing minted, nothing logged).
async fn tunnel_connect(
    ctx: &Ctx,
    host: String,
    port: u16,
    cr: OwnedReadHalf,
    mut cw: OwnedWriteHalf,
    left: Vec<u8>,
) -> std::io::Result<()> {
    let intercept = ctx
        .mitm
        .as_ref()
        .filter(|_| ctx.scope.as_ref().is_none_or(|s| s.may_match(&host, port)));
    let Some(mitm) = intercept else {
        let up =
            match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host.as_str(), port)))
                .await
            {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    return write_raw(
                        &mut cw,
                        &reply("502 Bad Gateway", &format!("connect failed: {e}\n")),
                    )
                    .await
                }
                Err(_) => {
                    return write_raw(&mut cw, &reply("502 Bad Gateway", "connect timed out\n"))
                        .await
                }
            };
        let mut stream = cr.reunite(cw).map_err(std::io::Error::other)?;
        write_raw(&mut stream, b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
        let mut up = up;
        up.write_all(&left).await?;
        tracing::debug!(%host, port, "blind tunnel (out of scope)");
        return tokio::io::copy_bidirectional(&mut stream, &mut up)
            .await
            .map(drop);
    };

    write_raw(&mut cw, b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
    if !left.is_empty() {
        return Ok(()); // the client spoke before the tunnel was open
    }
    let stream = cr.reunite(cw).map_err(std::io::Error::other)?;
    let cfg = tls::server_config(mitm.certs.clone(), &host).map_err(std::io::Error::other)?;
    let tls_stream = match TlsAcceptor::from(cfg).accept(stream).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(%host, port, error = %e, hint = handshake_hint(&e), "client TLS handshake failed");
            return Ok(());
        }
    };
    let (r, mut w) = tokio::io::split(tls_stream);
    let mut client = Reader::new(r, ctx.limits);
    let res = serve_requests(&mut client, &mut w, ctx, Mode::Tls { host: &host, port }).await;
    let _ = w.shutdown().await; // send close_notify so clients don't see a truncation
    res.map(drop)
}

/// Explain a failed client handshake in terms the user can act on.
fn handshake_hint(e: &std::io::Error) -> &'static str {
    match e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()) {
        Some(rustls::Error::NoApplicationProtocol) => {
            "the client only speaks HTTP/2, which Mantis does not support (see docs/adr/0002-http2-downgrade.md)"
        }
        _ => "is the Mantis CA trusted by the client?",
    }
}

fn reply(status: &str, body: &str) -> Vec<u8> {
    format!("HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
        .into_bytes()
}

fn read_error_reply(e: &WireError) -> Option<Vec<u8>> {
    match e {
        WireError::HeadTooLarge { .. } => Some(reply(
            "431 Request Header Fields Too Large",
            "head too large\n",
        )),
        WireError::BodyTooLarge { .. } => Some(reply("413 Content Too Large", "body too large\n")),
        WireError::BadChunk(_) => Some(reply("400 Bad Request", "bad chunked framing\n")),
        WireError::Truncated | WireError::Io(_) => None,
    }
}

fn has_token(raw: &[u8], headers: &[Header], name: &[u8], token: &[u8]) -> bool {
    headers
        .iter()
        .filter(|h| raw[h.name.clone()].eq_ignore_ascii_case(name))
        .any(|h| {
            raw[h.value.clone()]
                .split(|&b| b == b',')
                .any(|t| t.trim_ascii().eq_ignore_ascii_case(token))
        })
}

/// Does this message end the connection (`Connection: close`, or HTTP/1.0 without keep-alive)?
fn closes(raw: &[u8], headers: &[Header], version: Option<&std::ops::Range<usize>>) -> bool {
    has_token(raw, headers, b"connection", b"close")
        || (version.is_some_and(|v| &raw[v.clone()] == b"HTTP/1.0")
            && !has_token(raw, headers, b"connection", b"keep-alive"))
}

/// What to store about one exchange.
struct Record {
    ts: i64,
    request: Bytes,
    request_original: Option<Bytes>,
    response: Option<Bytes>,
    response_original: Option<Bytes>,
    dropped: bool,
}

impl Ctx {
    fn loggable(&self, d: &Dest) -> bool {
        self.scope.as_ref().is_none_or(|s| {
            matches!(
                s.check(&Target {
                    host: &d.host,
                    port: d.port,
                    path: &d.path
                }),
                Verdict::InScope(_)
            )
        })
    }

    /// Would forwarding to `host:port` send traffic back into the proxy?
    fn is_self(&self, host: &str, port: u16) -> bool {
        port == self.listen.port()
            && (host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback() || ip == self.listen.ip()))
    }

    fn exchange_for(d: &Dest, tls: bool, rec: Record) -> Exchange {
        Exchange {
            ts_micros: rec.ts,
            source: Source::Proxy,
            host: d.host.clone(),
            port: d.port,
            tls,
            request: rec.request,
            response: rec.response,
            request_original: rec.request_original,
            response_original: rec.response_original,
            dropped: rec.dropped,
        }
    }

    async fn log(&self, d: &Dest, tls: bool, rec: Record) {
        if !self.loggable(d) {
            return;
        }
        let ex = Self::exchange_for(d, tls, rec);
        if self
            .log
            .send(LogCmd::Exchange { ex, reply: None })
            .await
            .is_err()
        {
            tracing::error!("store writer is gone; exchange not logged");
        }
    }

    /// Like [`Ctx::log`], but wait for the row id (None if out of scope or not stored).
    async fn log_id(&self, d: &Dest, tls: bool, rec: Record) -> Option<i64> {
        if !self.loggable(d) {
            return None;
        }
        let (tx, rx) = oneshot::channel();
        let ex = Self::exchange_for(d, tls, rec);
        self.log
            .send(LogCmd::Exchange {
                ex,
                reply: Some(tx),
            })
            .await
            .ok()?;
        rx.await.ok()
    }
}

async fn serve_requests<R, W>(
    client: &mut Reader<R>,
    cw: &mut W,
    ctx: &Ctx,
    mode: Mode<'_>,
) -> std::io::Result<Outcome>
where
    R: AsyncRead + Send + Unpin,
    W: AsyncWrite + Send + Unpin,
{
    let tls = matches!(mode, Mode::Tls { .. });
    let mut upstream: Option<Conn> = None;
    loop {
        let msg = match client.read_request().await {
            Ok(Some(m)) => m,
            Ok(None) => return Ok(Outcome::Done),
            Err(e) => {
                if let Some(r) = read_error_reply(&e) {
                    write_raw(cw, &r).await?;
                }
                return Ok(Outcome::Done);
            }
        };
        let ts = now_micros();
        let view = RequestView::parse(&msg.raw);
        let resolved = match mode {
            Mode::Plain => resolve(&msg.raw, &view),
            Mode::Tls { host, port } => tunneled(&msg.raw, &view, host, port),
        };
        let dest = match resolved {
            Ok(d) => d,
            Err(Reject::Connect) => {
                let target = connect_target(&msg.raw, &view).filter(|_| ctx.mitm.is_some() && !tls);
                let Some((host, port)) = target else {
                    write_raw(
                        cw,
                        &reply(
                            "501 Not Implemented",
                            "CONNECT (HTTPS) is not supported here\n",
                        ),
                    )
                    .await?;
                    return Ok(Outcome::Done);
                };
                if ctx.is_self(&host, port) {
                    write_raw(
                        cw,
                        &reply("400 Bad Request", "request targets the proxy itself\n"),
                    )
                    .await?;
                    return Ok(Outcome::Done);
                }
                return Ok(Outcome::Connect { host, port });
            }
            Err(Reject::Bad) => {
                write_raw(cw, &reply("400 Bad Request", "cannot determine target\n")).await?;
                return Ok(Outcome::Done);
            }
        };
        if !tls && ctx.is_self(&dest.host, dest.port) {
            write_raw(
                cw,
                &reply("400 Bad Request", "request targets the proxy itself\n"),
            )
            .await?;
            return Ok(Outcome::Done);
        }
        let method = view.method.as_ref().map(|r| msg.raw[r.clone()].to_vec());
        let close_req = closes(&msg.raw, &view.headers, view.version.as_ref());

        // Rewrite rules, then the intercept queue. Both leave out-of-scope
        // traffic alone: it is forwarded untouched and unlogged.
        let in_scope = ctx.loggable(&dest);
        let mut request = msg.raw.clone();
        if in_scope {
            let rw = ctx.rewriter.apply(Dir::Request, &request);
            rw.warnings
                .iter()
                .for_each(|w| tracing::warn!(warning = %w, "request rewrite"));
            request = rw.raw;
        }
        if in_scope && ctx.intercept.is_enabled(Dir::Request) {
            match ctx
                .intercept
                .hold(client, Dir::Request, &dest.host, dest.port, tls, &request)
                .await
            {
                HoldOutcome::ClientGone => return Ok(Outcome::Done),
                HoldOutcome::Decided(Decision::Forward) => {}
                HoldOutcome::Decided(Decision::Edited(b)) => request = b,
                HoldOutcome::Decided(Decision::Drop) => {
                    let request_original = (request != msg.raw).then(|| msg.raw.clone());
                    let rec = Record {
                        ts,
                        request,
                        request_original,
                        response: None,
                        response_original: None,
                        dropped: true,
                    };
                    ctx.log(&dest, tls, rec).await;
                    return Ok(Outcome::Done);
                }
            }
        }
        let request_original = (request != msg.raw).then(|| msg.raw.clone());

        let resp = match obtain_response(
            ctx,
            &mut upstream,
            &dest,
            tls,
            &request,
            method.as_deref(),
            cw,
        )
        .await
        {
            Ok(r) => r,
            Err(why) => {
                tracing::warn!(host = %dest.host, port = dest.port, %why, "upstream failed");
                let rec = Record {
                    ts,
                    request,
                    request_original,
                    response: None,
                    response_original: None,
                    dropped: false,
                };
                ctx.log(&dest, tls, rec).await;
                write_raw(cw, &reply("502 Bad Gateway", &format!("{why}\n"))).await?;
                return Ok(Outcome::Done);
            }
        };

        let mut response = resp.raw.clone();
        if in_scope {
            let rw = ctx.rewriter.apply(Dir::Response, &response);
            rw.warnings
                .iter()
                .for_each(|w| tracing::warn!(warning = %w, "response rewrite"));
            response = rw.raw;
        }
        let mut dropped = false;
        if in_scope && ctx.intercept.is_enabled(Dir::Response) {
            match ctx
                .intercept
                .hold(client, Dir::Response, &dest.host, dest.port, tls, &response)
                .await
            {
                HoldOutcome::ClientGone => return Ok(Outcome::Done),
                HoldOutcome::Decided(Decision::Forward) => {}
                HoldOutcome::Decided(Decision::Edited(b)) => response = b,
                HoldOutcome::Decided(Decision::Drop) => dropped = true,
            }
        }
        let response_original = (response != resp.raw).then(|| resp.raw.clone());
        let rec = Record {
            ts,
            request,
            request_original,
            response: Some(response.clone()),
            response_original,
            dropped,
        };
        if dropped {
            ctx.log(&dest, tls, rec).await;
            return Ok(Outcome::Done);
        }
        write_raw(cw, &response).await?;
        let websocket = resp.framing == Framing::HeadOnly && is_websocket_upgrade(&response);
        // WebSocket frames are stored against the upgrade exchange, so wait for its id.
        let ws_exchange = if websocket {
            ctx.log_id(&dest, tls, rec).await
        } else {
            ctx.log(&dest, tls, rec).await;
            None
        };
        tracing::info!(host = %dest.host, port = dest.port, tls, bytes = response.len(), "exchange");

        if resp.framing == Framing::HeadOnly {
            if let Some(up) = upstream.take() {
                tunnel(client, cw, up, ws_exchange.map(|id| (&ctx.log, id))).await?;
            }
            return Ok(Outcome::Done);
        }
        let rv = ResponseView::parse(&resp.raw);
        let ends = close_req
            || resp.framing == Framing::UntilEof
            || closes(&resp.raw, &rv.headers, rv.version.as_ref());
        if ends {
            return Ok(Outcome::Done);
        }
        if !tls {
            upstream = None; // plain mode opens a fresh connection per request
        }
    }
}

async fn open_upstream(ctx: &Ctx, dest: &Dest, tls: bool) -> Result<Conn, String> {
    let tcp = match tokio::time::timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((dest.host.as_str(), dest.port)),
    )
    .await
    {
        Err(_) => return Err("connect timed out".into()),
        Ok(Err(e)) => return Err(format!("connect failed: {e}")),
        Ok(Ok(s)) => s,
    };
    let (reader, writer): (BoxRead, BoxWrite) = if tls {
        let mitm = ctx.mitm.as_ref().ok_or("TLS is not configured")?;
        let name =
            ServerName::try_from(dest.host.clone()).map_err(|e| format!("bad server name: {e}"))?;
        let connector = TlsConnector::from(mitm.client.clone());
        let stream = match tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(name, tcp)).await
        {
            Err(_) => return Err("upstream TLS handshake timed out".into()),
            Ok(Err(e)) => return Err(format!("upstream TLS handshake failed: {e}")),
            Ok(Ok(s)) => s,
        };
        let (r, w) = tokio::io::split(stream);
        (Box::new(r), Box::new(w))
    } else {
        let (r, w) = tcp.into_split();
        (Box::new(r), Box::new(w))
    };
    Ok(Conn {
        reader: Reader::new(reader, ctx.limits),
        writer,
    })
}

enum ExchangeError {
    /// The connection was dead before any response byte arrived.
    Stale,
    Other(String),
}

/// Send the request and read the final response. Interim 1xx responses
/// (except 101) are relayed to the client and skipped.
async fn exchange<W: AsyncWrite + Unpin>(
    conn: &mut Conn,
    request: &[u8],
    method: Option<&[u8]>,
    client: &mut W,
) -> Result<Message, ExchangeError> {
    write_raw(&mut conn.writer, request)
        .await
        .map_err(|_| ExchangeError::Stale)?;
    let mut relayed_interim = false;
    loop {
        let resp = match conn.reader.read_response(method).await {
            Ok(Some(r)) => r,
            Ok(None) if !relayed_interim => return Err(ExchangeError::Stale),
            Ok(None) => {
                return Err(ExchangeError::Other(
                    "upstream closed without a final response".into(),
                ))
            }
            Err(e) => return Err(ExchangeError::Other(format!("bad upstream response: {e}"))),
        };
        if matches!(ResponseView::parse(&resp.raw).status, Some(100..=199))
            && resp.framing != Framing::HeadOnly
        {
            write_raw(client, &resp.raw)
                .await
                .map_err(|e| ExchangeError::Other(format!("client write failed: {e}")))?;
            relayed_interim = true;
            continue;
        }
        return Ok(resp);
    }
}

/// Get the origin's response, reusing `upstream` when present and retrying
/// once on a fresh connection if a reused one turns out to be dead. On
/// success the connection stays in `upstream`; on failure it is cleared.
async fn obtain_response<W: AsyncWrite + Unpin>(
    ctx: &Ctx,
    upstream: &mut Option<Conn>,
    dest: &Dest,
    tls: bool,
    request: &[u8],
    method: Option<&[u8]>,
    client: &mut W,
) -> Result<Message, String> {
    let reused = upstream.is_some();
    let mut conn = match upstream.take() {
        Some(c) => c,
        None => open_upstream(ctx, dest, tls).await?,
    };
    let result = match exchange(&mut conn, request, method, client).await {
        Err(ExchangeError::Stale) if reused => {
            conn = open_upstream(ctx, dest, tls).await?;
            exchange(&mut conn, request, method, client).await
        }
        other => other,
    };
    match result {
        Ok(resp) => {
            *upstream = Some(conn);
            Ok(resp)
        }
        Err(ExchangeError::Stale) => Err("upstream closed without a response".into()),
        Err(ExchangeError::Other(why)) => Err(why),
    }
}

fn is_websocket_upgrade(response: &[u8]) -> bool {
    let v = ResponseView::parse(response);
    v.status == Some(101) && has_token(response, &v.headers, b"upgrade", b"websocket")
}

/// Stop recording WebSocket frames for one connection after this many stored bytes.
const MAX_CAPTURE_BYTES: usize = 64 << 20;
/// After one side of a tunnel ends, give the other this long to finish.
const DRAIN: Duration = Duration::from_secs(2);

/// Records the frames passing in one direction. It never touches the bytes.
struct Scan<'a> {
    log: &'a mpsc::Sender<LogCmd>,
    exchange_id: i64,
    dir: WsDir,
    scanner: FrameScanner,
    budget: &'a AtomicUsize,
    stopped: bool,
}

impl Scan<'_> {
    async fn feed(&mut self, data: &[u8]) {
        if self.stopped {
            return;
        }
        for f in self.scanner.feed(data) {
            if self.budget.fetch_add(f.raw.len(), Ordering::SeqCst) + f.raw.len()
                > MAX_CAPTURE_BYTES
            {
                tracing::warn!(
                    exchange = self.exchange_id,
                    "websocket capture limit reached; no further frames are stored"
                );
                self.stopped = true;
                return;
            }
            let frame = WsFrame {
                exchange_id: self.exchange_id,
                ts_micros: now_micros(),
                dir: self.dir,
                opcode: f.opcode,
                fin: f.fin,
                compressed: f.rsv1,
                payload_len: f.payload_len,
                truncated: f.truncated,
                raw: f.raw,
            };
            if self.log.send(LogCmd::Frame(frame)).await.is_err() {
                self.stopped = true;
                return;
            }
        }
        if self.scanner.is_lost() {
            tracing::warn!(
                exchange = self.exchange_id,
                "websocket capture lost: stream is not valid WebSocket framing (still forwarding)"
            );
            self.stopped = true;
        }
    }
}

/// Copy `r` to `w` as bytes arrive, then show them to the scanner. On end of
/// input, close the write side so the peer sees it.
async fn pump<R, W>(r: &mut R, w: &mut W, mut scan: Option<Scan<'_>>) -> std::io::Result<()>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            let _ = w.shutdown().await;
            return Ok(());
        }
        w.write_all(&buf[..n]).await?;
        w.flush().await?;
        if let Some(s) = scan.as_mut() {
            s.feed(&buf[..n]).await;
        }
    }
}

/// After a 101 the stream is no longer HTTP: copy bytes both ways. With
/// `capture` (log channel and upgrade exchange id) WebSocket frames are
/// recorded on the side; forwarding never waits for or depends on that.
async fn tunnel<R, W>(
    client: &mut Reader<R>,
    cw: &mut W,
    mut up: Conn,
    capture: Option<(&mpsc::Sender<LogCmd>, i64)>,
) -> std::io::Result<()>
where
    R: AsyncRead + Send + Unpin,
    W: AsyncWrite + Send + Unpin,
{
    let budget = AtomicUsize::new(0);
    let scan = |dir| {
        capture.map(|(log, exchange_id)| Scan {
            log,
            exchange_id,
            dir,
            scanner: FrameScanner::new(DEFAULT_CAP),
            budget: &budget,
            stopped: false,
        })
    };
    let (mut to_server, mut to_client) = (scan(WsDir::ToServer), scan(WsDir::ToClient));
    let (c_left, u_left) = (client.take_buffered(), up.reader.take_buffered());
    cw.write_all(&u_left).await?;
    up.writer.write_all(&c_left).await?;
    cw.flush().await?;
    up.writer.flush().await?;
    if let Some(s) = to_client.as_mut() {
        s.feed(&u_left).await;
    }
    if let Some(s) = to_server.as_mut() {
        s.feed(&c_left).await;
    }
    let ur = up.reader.get_mut();
    let uw = &mut up.writer;
    let cr = client.get_mut();
    let a = pump(cr, uw, to_server);
    let b = pump(ur, cw, to_client);
    tokio::pin!(a, b);
    tokio::select! {
        r = &mut a => {
            let _ = tokio::time::timeout(DRAIN, &mut b).await;
            r
        }
        r = &mut b => {
            let _ = tokio::time::timeout(DRAIN, &mut a).await;
            r
        }
    }
}

#[cfg(test)]
mod tests {
    use super::handshake_hint;

    #[test]
    fn an_h2_only_client_gets_a_specific_hint() {
        let e = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            rustls::Error::NoApplicationProtocol,
        );
        assert!(handshake_hint(&e).contains("HTTP/2"));
        let other =
            std::io::Error::new(std::io::ErrorKind::InvalidData, rustls::Error::DecryptError);
        assert!(handshake_hint(&other).contains("trusted"));
        assert!(handshake_hint(&std::io::Error::other("x")).contains("trusted"));
    }
}
