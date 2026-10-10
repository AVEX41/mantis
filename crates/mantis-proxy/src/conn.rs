//! One client connection: read requests, forward them, relay and log responses.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use mantis_core::view::{Header, RequestView, ResponseView};
use mantis_core::wire::{write_raw, Framing, Limits, Message, Reader, WireError};
use mantis_core::{now_micros, Exchange, Scope, Source, Target, Verdict};
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::target::{resolve, Dest, Reject};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) struct Ctx {
    pub listen: SocketAddr,
    pub scope: Option<Scope>,
    pub limits: Limits,
    pub log: mpsc::Sender<Exchange>,
}

pub(crate) async fn handle(stream: TcpStream, ctx: Arc<Ctx>) {
    if let Err(e) = run(stream, &ctx).await {
        tracing::debug!(error = %e, "connection ended");
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

    /// Would forwarding this request send it back into the proxy?
    fn is_self(&self, d: &Dest) -> bool {
        d.port == self.listen.port()
            && (d.host.eq_ignore_ascii_case("localhost")
                || d.host
                    .parse::<IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback() || ip == self.listen.ip()))
    }

    async fn log(&self, d: &Dest, ts: i64, request: Bytes, response: Option<Bytes>) {
        if !self.loggable(d) {
            return;
        }
        let ex = Exchange {
            ts_micros: ts,
            source: Source::Proxy,
            host: d.host.clone(),
            port: d.port,
            tls: false,
            request,
            response,
        };
        if self.log.send(ex).await.is_err() {
            tracing::error!("store writer is gone; exchange not logged");
        }
    }
}

async fn run(stream: TcpStream, ctx: &Ctx) -> std::io::Result<()> {
    let (cr, mut cw) = stream.into_split();
    let mut client = Reader::new(cr, ctx.limits);
    loop {
        let msg = match client.read_request().await {
            Ok(Some(m)) => m,
            Ok(None) => return Ok(()),
            Err(e) => {
                if let Some(r) = read_error_reply(&e) {
                    write_raw(&mut cw, &r).await?;
                }
                return Ok(());
            }
        };
        let ts = now_micros();
        let view = RequestView::parse(&msg.raw);
        let dest = match resolve(&msg.raw, &view) {
            Ok(d) => d,
            Err(Reject::Connect) => {
                return write_raw(
                    &mut cw,
                    &reply(
                        "501 Not Implemented",
                        "CONNECT (HTTPS) is not supported yet\n",
                    ),
                )
                .await;
            }
            Err(Reject::Bad) => {
                return write_raw(
                    &mut cw,
                    &reply("400 Bad Request", "cannot determine target\n"),
                )
                .await
            }
        };
        if ctx.is_self(&dest) {
            return write_raw(
                &mut cw,
                &reply("400 Bad Request", "request targets the proxy itself\n"),
            )
            .await;
        }
        let method = view.method.as_ref().map(|r| msg.raw[r.clone()].to_vec());
        let close_req = closes(&msg.raw, &view.headers, view.version.as_ref());

        let connect = tokio::time::timeout(
            CONNECT_TIMEOUT,
            TcpStream::connect((dest.host.as_str(), dest.port)),
        );
        let fetched = match connect.await {
            Err(_) => Err("connect timed out".to_string()),
            Ok(Err(e)) => Err(format!("connect failed: {e}")),
            Ok(Ok(up)) => fetch(up, &msg.raw, method.as_deref(), ctx.limits, &mut cw).await,
        };
        let (resp, up_reader, up_writer) = match fetched {
            Ok(f) => f,
            Err(why) => {
                tracing::warn!(host = %dest.host, port = dest.port, %why, "upstream failed");
                ctx.log(&dest, ts, msg.raw.clone(), None).await;
                return write_raw(&mut cw, &reply("502 Bad Gateway", &format!("{why}\n"))).await;
            }
        };
        write_raw(&mut cw, &resp.raw).await?;
        ctx.log(&dest, ts, msg.raw.clone(), Some(resp.raw.clone()))
            .await;
        tracing::info!(host = %dest.host, port = dest.port, bytes = resp.raw.len(), "exchange");

        if resp.framing == Framing::HeadOnly {
            return tunnel(client, cw, up_reader, up_writer).await;
        }
        let rv = ResponseView::parse(&resp.raw);
        if close_req
            || resp.framing == Framing::UntilEof
            || closes(&resp.raw, &rv.headers, rv.version.as_ref())
        {
            return Ok(());
        }
    }
}

type Fetched = (Message, Reader<OwnedReadHalf>, OwnedWriteHalf);

/// Send the request upstream and read the final response. Interim 1xx
/// responses (except 101) are relayed to the client and skipped.
async fn fetch(
    up: TcpStream,
    request: &[u8],
    method: Option<&[u8]>,
    limits: Limits,
    client: &mut OwnedWriteHalf,
) -> Result<Fetched, String> {
    let (ur, mut uw) = up.into_split();
    write_raw(&mut uw, request)
        .await
        .map_err(|e| format!("write failed: {e}"))?;
    let mut reader = Reader::new(ur, limits);
    loop {
        let resp = match reader.read_response(method).await {
            Ok(Some(r)) => r,
            Ok(None) => return Err("upstream closed without a response".into()),
            Err(e) => return Err(format!("bad upstream response: {e}")),
        };
        if matches!(ResponseView::parse(&resp.raw).status, Some(100..=199))
            && resp.framing != Framing::HeadOnly
        {
            write_raw(client, &resp.raw)
                .await
                .map_err(|e| format!("client write failed: {e}"))?;
            continue;
        }
        return Ok((resp, reader, uw));
    }
}

/// After a 101 the stream is no longer HTTP: copy bytes both ways (not captured yet).
async fn tunnel(
    client: Reader<OwnedReadHalf>,
    mut cw: OwnedWriteHalf,
    up: Reader<OwnedReadHalf>,
    mut uw: OwnedWriteHalf,
) -> std::io::Result<()> {
    let (mut cr, c_left) = client.into_parts();
    let (mut ur, u_left) = up.into_parts();
    cw.write_all(&u_left).await?;
    uw.write_all(&c_left).await?;
    tokio::select! {
        r = tokio::io::copy(&mut cr, &mut uw) => r.map(drop),
        r = tokio::io::copy(&mut ur, &mut cw) => r.map(drop),
    }
}
