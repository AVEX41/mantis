use std::pin::Pin;
use std::task::{Context, Poll};

use proptest::prelude::*;
use tokio::io::{AsyncRead, ReadBuf};

use super::*;

/// Yields at most `n` bytes per read, to exercise every split point.
struct Trickle {
    data: Vec<u8>,
    pos: usize,
    n: usize,
}

impl AsyncRead for Trickle {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let s = &mut *self;
        let k = s.n.min(s.data.len() - s.pos).min(buf.remaining());
        buf.put_slice(&s.data[s.pos..s.pos + k]);
        s.pos += k;
        Poll::Ready(Ok(()))
    }
}

fn reader(data: &[u8], n: usize) -> Reader<Trickle> {
    Reader::new(
        Trickle {
            data: data.to_vec(),
            pos: 0,
            n,
        },
        Limits::default(),
    )
}

fn small(data: &[u8], max_head: usize, max_body: usize) -> Reader<Trickle> {
    Reader::new(
        Trickle {
            data: data.to_vec(),
            pos: 0,
            n: 5,
        },
        Limits { max_head, max_body },
    )
}

const NONE: Framing = Framing::None;
const SPLITS: [usize; 6] = [1, 2, 3, 7, 64, 1 << 16];

async fn request_ok(raw: &[u8], framing: Framing, ambiguous: bool) {
    for n in SPLITS {
        let mut r = reader(raw, n);
        let m = r.read_request().await.unwrap().unwrap();
        assert_eq!(&m.raw[..], raw, "split {n}");
        assert_eq!((m.framing, m.ambiguous), (framing, ambiguous), "split {n}");
        assert!(r.read_request().await.unwrap().is_none());
    }
}

async fn response_ok(raw: &[u8], method: Option<&[u8]>, framing: Framing, ambiguous: bool) {
    for n in SPLITS {
        let mut r = reader(raw, n);
        let m = r.read_response(method).await.unwrap().unwrap();
        assert_eq!(&m.raw[..], raw, "split {n}");
        assert_eq!((m.framing, m.ambiguous), (framing, ambiguous), "split {n}");
    }
}

#[tokio::test]
async fn requests_round_trip_byte_for_byte() {
    use Framing::{Chunked, ContentLength};
    request_ok(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", NONE, false).await;
    request_ok(b"GET / HTTP/1.1\nHost: a\n\n", NONE, false).await; // bare LF
    request_ok(b"GET / HTTP/1.1\r\nHost: a\n\r\n", NONE, false).await; // mixed endings
    request_ok(
        b"GET / HTTP/1.1\r\nA: 1\r\nA: 2\r\na: 3\r\n\r\n",
        NONE,
        false,
    )
    .await; // duplicates
    request_ok(
        b"GET / HTTP/1.1\r\nA: 1\r\n  folded\r\n\tmore\r\n\r\n",
        NONE,
        false,
    )
    .await; // obs-fold
    request_ok(
        b"GET / HTTP/1.1\r\nnocolon\r\n: empty-name\r\nBad Name : v\r\n\r\n",
        NONE,
        false,
    )
    .await;
    request_ok(b"G\x00T \xff HTTP/9.9\r\nX: \x00\xfe\r\n\r\n", NONE, false).await; // non-UTF-8, NUL
    request_ok(
        b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc",
        ContentLength(3),
        false,
    )
    .await;
    request_ok(
        b"POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
        ContentLength(0),
        false,
    )
    .await;
    request_ok(b"POST / HTTP/1.1\r\ntransfer-ENCODING: gzip, Chunked\r\n\r\n3;e=1\r\nabc\r\n0\r\nT: 1\r\n\r\n", Chunked, false).await;
    request_ok(
        b"POST / HTTP/1.1\nTransfer-Encoding: chunked\n\n3\nabc\n0\n\n",
        Chunked,
        false,
    )
    .await; // bare LF chunks
    request_ok(
        b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        Chunked,
        false,
    )
    .await;
}

#[tokio::test]
async fn ambiguous_framing_is_reported_not_rejected() {
    use Framing::{Chunked, ContentLength};
    request_ok(
        b"POST / HTTP/1.1\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        Chunked,
        true,
    )
    .await;
    request_ok(
        b"POST / HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 5\r\n\r\nabc",
        ContentLength(3),
        true,
    )
    .await;
    request_ok(
        b"POST / HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc",
        ContentLength(3),
        false,
    )
    .await;
    request_ok(
        b"POST / HTTP/1.1\r\nContent-Length: abc\r\n\r\n",
        NONE,
        true,
    )
    .await;
    request_ok(
        b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\nContent-Length: 1\r\n\r\nx",
        ContentLength(1),
        true,
    )
    .await;
}

#[tokio::test]
async fn responses_framing() {
    use Framing::{Chunked, ContentLength, HeadOnly, UntilEof};
    response_ok(
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc",
        None,
        ContentLength(3),
        false,
    )
    .await;
    response_ok(
        b"HTTP/1.0 200 OK\r\n\r\nuntil eof \xff",
        None,
        UntilEof,
        false,
    )
    .await;
    response_ok(
        b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n",
        Some(b"HEAD"),
        NONE,
        false,
    )
    .await;
    response_ok(
        b"HTTP/1.1 204 No Content\r\nContent-Length: 10\r\n\r\n",
        None,
        NONE,
        false,
    )
    .await;
    response_ok(b"HTTP/1.1 304 Not Modified\r\n\r\n", None, NONE, false).await;
    response_ok(b"HTTP/1.1 100 Continue\r\n\r\n", None, NONE, false).await;
    response_ok(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nwiki\r\n0\r\n\r\n",
        None,
        Chunked,
        false,
    )
    .await;
    response_ok(
        b"HTTP/1.1 200 Connection established\r\n\r\n",
        Some(b"CONNECT"),
        HeadOnly,
        false,
    )
    .await;
}

#[tokio::test]
async fn upgrade_returns_head_and_keeps_tunnel_bytes() {
    let raw = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n\x81\x05hello";
    let mut r = reader(raw, 7);
    let m = r.read_response(None).await.unwrap().unwrap();
    assert_eq!(m.framing, Framing::HeadOnly);
    assert!(m.raw.ends_with(b"\r\n\r\n"));
    let (t, left) = r.into_parts();
    let rest = [&left[..], &t.data[t.pos..]].concat();
    assert_eq!(rest, b"\x81\x05hello");
}

#[tokio::test]
async fn pipelined_messages_and_clean_eof() {
    let a = b"POST /a HTTP/1.1\r\nContent-Length: 2\r\n\r\nhi".as_slice();
    let b = b"GET /b HTTP/1.1\nHost: x\n\n".as_slice();
    let both = [a, b].concat();
    for n in SPLITS {
        let mut r = reader(&both, n);
        assert_eq!(&r.read_request().await.unwrap().unwrap().raw[..], a);
        assert_eq!(&r.read_request().await.unwrap().unwrap().raw[..], b);
        assert!(r.read_request().await.unwrap().is_none());
    }
}

#[tokio::test]
async fn large_body_and_huge_header() {
    let mut raw = b"POST / HTTP/1.1\r\nContent-Length: 5242880\r\nX: ".to_vec();
    raw.extend(std::iter::repeat_n(b'v', 30_000));
    raw.extend(b"\r\n\r\n");
    raw.extend((0..5 * 1024 * 1024).map(|i| (i % 253) as u8));
    let m = reader(&raw, 8192).read_request().await.unwrap().unwrap();
    assert_eq!(&m.raw[..], &raw[..]);
}

#[tokio::test]
async fn errors() {
    assert!(matches!(
        reader(b"GET / HTTP/1.1\r\nHost:", 3).read_request().await,
        Err(WireError::Truncated)
    ));
    assert!(matches!(
        reader(b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc", 3)
            .read_request()
            .await,
        Err(WireError::Truncated)
    ));
    assert!(matches!(
        reader(
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nab",
            3
        )
        .read_request()
        .await,
        Err(WireError::Truncated)
    ));
    assert!(matches!(
        small(
            b"GET / HTTP/1.1\r\nX: aaaaaaaaaaaaaaaaaaaa\r\n\r\n",
            16,
            100
        )
        .read_request()
        .await,
        Err(WireError::HeadTooLarge { limit: 16 })
    ));
    assert!(matches!(
        small(b"POST / HTTP/1.1\r\nContent-Length: 1000\r\n\r\n", 100, 10)
            .read_request()
            .await,
        Err(WireError::BodyTooLarge { limit: 10 })
    ));
    assert!(matches!(
        small(
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
            100,
            10
        )
        .read_request()
        .await,
        Err(WireError::BadChunk(_))
    ));
    assert!(matches!(
        small(
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nabXY0\r\n\r\n",
            100,
            100
        )
        .read_request()
        .await,
        Err(WireError::BadChunk(_))
    ));
    assert!(matches!(
        small(b"HTTP/1.0 200 OK\r\n\r\n0123456789ABCDEF", 100, 8)
            .read_response(None)
            .await,
        Err(WireError::BodyTooLarge { .. })
    ));
}

#[tokio::test]
async fn writer_is_verbatim() {
    let raw = b"POST / HTTP/1.1\nContent-Length: 99\nA: 1\nA: 2\n\nshort".as_slice();
    let (mut a, b) = tokio::io::duplex(64);
    let w = tokio::spawn(async move { write_raw(&mut a, raw).await });
    let mut r = Reader::new(b, Limits::default());
    let m = r.read_request().await;
    w.await.unwrap().unwrap();
    // Content-Length lies (99 vs 5): written as-is, so the reader sees a truncated body.
    assert!(matches!(m, Err(WireError::Truncated)));
}

fn eol() -> impl Strategy<Value = &'static str> {
    prop_oneof![Just("\r\n"), Just("\n")]
}

fn message() -> impl Strategy<Value = Vec<u8>> {
    let hdr = ("[A-Za-z][A-Za-z0-9-]{0,8}", "[ -~]{0,20}", eol());
    let hdrs = proptest::collection::vec(hdr, 0..6);
    let body = proptest::collection::vec(proptest::collection::vec(any::<u8>(), 1..40), 0..5);
    (hdrs, eol(), any::<bool>(), body, eol(), eol()).prop_map(
        |(hdrs, e0, chunked, chunks, e1, e2)| {
            let mut m = format!("POST /p HTTP/1.1{e0}").into_bytes();
            for (n, v, e) in hdrs.iter().filter(|(n, ..)| {
                !n.eq_ignore_ascii_case("content-length")
                    && !n.eq_ignore_ascii_case("transfer-encoding")
            }) {
                m.extend(format!("{n}: {v}{e}").bytes());
            }
            if chunked {
                m.extend(format!("Transfer-Encoding: chunked{e1}{e1}").bytes());
                for c in &chunks {
                    m.extend(format!("{:x}{e2}", c.len()).bytes());
                    m.extend(c);
                    m.extend(e2.bytes());
                }
                m.extend(format!("0{e2}{e2}").bytes());
            } else {
                let body: Vec<u8> = chunks.concat();
                m.extend(format!("Content-Length: {}{e1}{e1}", body.len()).bytes());
                m.extend(body);
            }
            m
        },
    )
}

proptest! {
    #[test]
    fn generated_messages_round_trip(msg in message(), n in 1usize..80, tail in message()) {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        rt.block_on(async {
            let both = [msg.clone(), tail.clone()].concat();
            let mut r = reader(&both, n);
            let a = r.read_request().await.unwrap().unwrap();
            let b = r.read_request().await.unwrap().unwrap();
            prop_assert_eq!(&a.raw[..], &msg[..]);
            prop_assert_eq!(&b.raw[..], &tail[..]);
            prop_assert!(!a.ambiguous);
            Ok(())
        })?;
    }

    #[test]
    fn arbitrary_bytes_never_panic(data in proptest::collection::vec(any::<u8>(), 0..400)) {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        rt.block_on(async {
            for resp in [false, true] {
                let mut r = small(&data, 128, 128);
                let _ = if resp { r.read_response(None).await } else { r.read_request().await };
            }
        });
    }
}
