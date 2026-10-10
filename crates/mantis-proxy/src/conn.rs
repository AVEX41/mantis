//! One client connection: read requests, forward them, relay and log responses.
//!
//! The same request loop serves plain HTTP and requests decrypted from an
//! intercepted `CONNECT` tunnel; only the way the upstream is reached differs.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use mantis_core::view::{Header, RequestView, ResponseView};
use mantis_core::wire::{write_raw, Framing, Limits, Message, Reader, WireError};
use mantis_core::{now_micros, Exchange, Scope, Source, Target, Verdict};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::target::{connect_target, resolve, tunneled, Dest, Reject};
use crate::tls::{self, Mitm};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) struct Ctx {
    pub listen: SocketAddr,
    pub scope: Option<Scope>,
    pub limits: Limits,
    pub log: mpsc::Sender<Exchange>,
    /// `None`: no CA configured, `CONNECT` is refused with 501.
    pub mitm: Option<Mitm>,
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
            tracing::warn!(%host, port, error = %e, "client TLS handshake failed (is the Mantis CA trusted by the client?)");
            return Ok(());
        }
    };
    let (r, mut w) = tokio::io::split(tls_stream);
    let mut client = Reader::new(r, ctx.limits);
    let res = serve_requests(&mut client, &mut w, ctx, Mode::Tls { host: &host, port }).await;
    let _ = w.shutdown().await; // send close_notify so clients don't see a truncation
    res.map(drop)
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

    async fn log(&self, d: &Dest, tls: bool, ts: i64, request: Bytes, response: Option<Bytes>) {
        if !self.loggable(d) {
            return;
        }
        let ex = Exchange {
            ts_micros: ts,
            source: Source::Proxy,
            host: d.host.clone(),
            port: d.port,
            tls,
            request,
            response,
        };
        if self.log.send(ex).await.is_err() {
            tracing::error!("store writer is gone; exchange not logged");
        }
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

        let resp = match obtain_response(
            ctx,
            &mut upstream,
            &dest,
            tls,
            &msg.raw,
            method.as_deref(),
            cw,
        )
        .await
        {
            Ok(r) => r,
            Err(why) => {
                tracing::warn!(host = %dest.host, port = dest.port, %why, "upstream failed");
                ctx.log(&dest, tls, ts, msg.raw.clone(), None).await;
                write_raw(cw, &reply("502 Bad Gateway", &format!("{why}\n"))).await?;
                return Ok(Outcome::Done);
            }
        };
        write_raw(cw, &resp.raw).await?;
        ctx.log(&dest, tls, ts, msg.raw.clone(), Some(resp.raw.clone()))
            .await;
        tracing::info!(host = %dest.host, port = dest.port, tls, bytes = resp.raw.len(), "exchange");

        if resp.framing == Framing::HeadOnly {
            if let Some(up) = upstream.take() {
                tunnel(client, cw, up).await?;
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

/// After a 101 the stream is no longer HTTP: copy bytes both ways (not captured yet).
async fn tunnel<R, W>(client: &mut Reader<R>, cw: &mut W, mut up: Conn) -> std::io::Result<()>
where
    R: AsyncRead + Send + Unpin,
    W: AsyncWrite + Send + Unpin,
{
    let (c_left, u_left) = (client.take_buffered(), up.reader.take_buffered());
    cw.write_all(&u_left).await?;
    up.writer.write_all(&c_left).await?;
    cw.flush().await?;
    up.writer.flush().await?;
    let ur = up.reader.get_mut();
    let uw = &mut up.writer;
    let cr = client.get_mut();
    tokio::select! {
        r = tokio::io::copy(cr, uw) => r.map(drop),
        r = tokio::io::copy(ur, cw) => r.map(drop),
    }
}
