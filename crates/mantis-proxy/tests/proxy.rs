//! End-to-end tests: client -> proxy -> local origin, with the store read back.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mantis_core::wire::{write_raw, Framing, Limits, Reader};
use mantis_core::{Action, RuleSpec, Scope, Source, Store, Summary};
use mantis_proxy::{serve, Config, ProxyError, ProxyHandle};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

const T: Duration = Duration::from_secs(5);

/// A local origin that records raw requests and replies with canned responses
/// (the last one repeats).
struct Origin {
    addr: SocketAddr,
    received: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Origin {
    async fn start(replies: &'static [&'static [u8]], close_after: bool) -> Origin {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let received = Arc::new(Mutex::new(Vec::new()));
        let rec = received.clone();
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0)); // shared: the proxy opens a connection per request
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = l.accept().await else { return };
                let (rec, count) = (rec.clone(), count.clone());
                tokio::spawn(async move {
                    let (r, mut w) = s.into_split();
                    let mut r = Reader::new(r, Limits::default());
                    while let Ok(Some(m)) = r.read_request().await {
                        rec.lock().unwrap().push(m.raw.to_vec());
                        let n = count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        let reply = replies[n.min(replies.len() - 1)];
                        if write_raw(&mut w, reply).await.is_err() || close_after {
                            return;
                        }
                    }
                });
            }
        });
        Origin { addr, received }
    }

    fn requests(&self) -> Vec<Vec<u8>> {
        self.received.lock().unwrap().clone()
    }
}

struct Rig {
    proxy: ProxyHandle,
    events: broadcast::Receiver<Summary>,
    db: PathBuf,
}

impl Rig {
    async fn start(scope: Option<Scope>) -> Rig {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let db = std::env::temp_dir().join(format!(
            "mantis-proxy-test-{}-{}.db",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        let store = Store::open(&db).unwrap();
        let cfg = Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            scope,
            ..Config::default()
        };
        let proxy = serve(cfg, store).await.unwrap();
        let events = proxy.subscribe();
        Rig { proxy, events, db }
    }

    fn addr(&self) -> SocketAddr {
        self.proxy.local_addr()
    }

    async fn next_event(&mut self) -> Summary {
        tokio::time::timeout(T, self.events.recv())
            .await
            .expect("timed out waiting for a logged exchange")
            .unwrap()
    }

    fn store(&self) -> Store {
        Store::open(&self.db).unwrap()
    }

    async fn finish(self) {
        self.proxy.shutdown().await;
        for ext in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{ext}", self.db.display()));
        }
    }
}

/// Send raw requests on one connection; read one response per request.
async fn client(proxy: SocketAddr, requests: &[(&[u8], Option<&[u8]>)]) -> Vec<Vec<u8>> {
    let s = TcpStream::connect(proxy).await.unwrap();
    let (r, mut w) = s.into_split();
    let mut r = Reader::new(r, Limits::default());
    let mut out = Vec::new();
    for (req, method) in requests {
        write_raw(&mut w, req).await.unwrap();
        let m = tokio::time::timeout(T, r.read_response(*method))
            .await
            .expect("response timed out")
            .unwrap()
            .expect("proxy closed");
        out.push(m.raw.to_vec());
    }
    out
}

fn get(origin: SocketAddr, path: &str) -> Vec<u8> {
    format!("GET http://{origin}{path} HTTP/1.1\r\nHost: {origin}\r\n\r\n").into_bytes()
}

const OK5: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";

#[tokio::test]
async fn get_round_trip_is_byte_exact_and_stored() {
    let origin = Origin::start(&[OK5], false).await;
    let mut rig = Rig::start(None).await;
    let req = get(origin.addr, "/hello?x=1");
    let got = client(rig.addr(), &[(&req, None)]).await;
    assert_eq!(got[0], OK5);
    assert_eq!(origin.requests(), vec![req.clone()]);

    let ev = rig.next_event().await;
    assert_eq!(
        (ev.method.as_deref(), ev.status, ev.port, ev.tls),
        (Some("GET"), Some(200), origin.addr.port(), false)
    );
    let row = rig.store().get(ev.id).unwrap().unwrap().exchange;
    assert_eq!(&row.request[..], &req[..]);
    assert_eq!(row.response.as_deref(), Some(OK5));
    assert_eq!(
        (row.source, row.host.as_str()),
        (Source::Proxy, "127.0.0.1")
    );
    rig.finish().await;
}

#[tokio::test]
async fn malformed_request_reaches_origin_unchanged() {
    let origin = Origin::start(&[OK5], false).await;
    let mut rig = Rig::start(None).await;
    let req = format!("POST http://{}/p HTTP/1.1\nHost: x\nA: 1\r\nA: 2\nB: v\n  folded\nnocolon\nContent-Length: 3\n\nabc", origin.addr).into_bytes();
    client(rig.addr(), &[(&req, None)]).await;
    assert_eq!(origin.requests(), vec![req.clone()]);
    let ev = rig.next_event().await;
    assert_eq!(
        &rig.store().get(ev.id).unwrap().unwrap().exchange.request[..],
        &req[..]
    );
    rig.finish().await;
}

#[tokio::test]
async fn keep_alive_and_chunked_response() {
    const CHUNKED: &[u8] =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nT: 1\r\n\r\n";
    let origin = Origin::start(&[OK5, CHUNKED], false).await;
    let mut rig = Rig::start(None).await;
    let (a, b) = (get(origin.addr, "/a"), get(origin.addr, "/b"));
    let got = client(rig.addr(), &[(&a, None), (&b, None)]).await;
    assert_eq!((&got[0][..], &got[1][..]), (OK5, CHUNKED));
    let (e1, e2) = (rig.next_event().await, rig.next_event().await);
    assert_eq!(
        (e1.path.as_deref(), e2.path.as_deref()),
        (
            Some(&format!("http://{}/a", origin.addr)[..]),
            Some(&format!("http://{}/b", origin.addr)[..])
        )
    );
    rig.finish().await;
}

#[tokio::test]
async fn head_response_does_not_wait_for_a_body() {
    const HEAD_RESP: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
    let origin = Origin::start(&[HEAD_RESP], false).await;
    let rig = Rig::start(None).await;
    let req = format!(
        "HEAD http://{0}/ HTTP/1.1\r\nHost: {0}\r\n\r\n",
        origin.addr
    )
    .into_bytes();
    let got = client(rig.addr(), &[(&req, Some(b"HEAD"))]).await;
    assert_eq!(got[0], HEAD_RESP);
    rig.finish().await;
}

#[tokio::test]
async fn response_until_eof_is_relayed_then_closed() {
    const EOF_RESP: &[u8] = b"HTTP/1.0 200 OK\r\n\r\nbody until close";
    let origin = Origin::start(&[EOF_RESP], true).await;
    let rig = Rig::start(None).await;
    let mut s = TcpStream::connect(rig.addr()).await.unwrap();
    write_raw(&mut s, &get(origin.addr, "/")).await.unwrap();
    let mut all = Vec::new();
    tokio::time::timeout(T, s.read_to_end(&mut all))
        .await
        .expect("proxy did not close")
        .unwrap();
    assert_eq!(all, EOF_RESP);
    rig.finish().await;
}

#[tokio::test]
async fn unreachable_origin_gives_502_and_logs_request_only() {
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap()
    };
    let mut rig = Rig::start(None).await;
    let req = get(dead, "/");
    let got = client(rig.addr(), &[(&req, None)]).await;
    assert!(got[0].starts_with(b"HTTP/1.1 502 "));
    let ev = rig.next_event().await;
    assert_eq!(ev.status, None);
    assert!(rig
        .store()
        .get(ev.id)
        .unwrap()
        .unwrap()
        .exchange
        .response
        .is_none());
    rig.finish().await;
}

#[tokio::test]
async fn loops_connect_and_bad_requests_are_refused() {
    let rig = Rig::start(None).await;
    let me = rig.addr();
    let reply = |req: String| async move {
        let mut s = TcpStream::connect(me).await.unwrap();
        write_raw(&mut s, req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        tokio::time::timeout(T, s.read_to_end(&mut buf))
            .await
            .unwrap()
            .unwrap();
        String::from_utf8_lossy(&buf).into_owned()
    };
    assert!(
        reply(format!("GET http://{me}/ HTTP/1.1\r\nHost: {me}\r\n\r\n"))
            .await
            .starts_with("HTTP/1.1 400 ")
    );
    assert!(reply(format!(
        "GET http://localhost:{}/ HTTP/1.1\r\n\r\n",
        me.port()
    ))
    .await
    .starts_with("HTTP/1.1 400 "));
    assert!(
        reply("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".into())
            .await
            .starts_with("HTTP/1.1 501 ")
    );
    assert!(reply("GET /nohost HTTP/1.1\r\n\r\n".into())
        .await
        .starts_with("HTTP/1.1 400 "));
    rig.finish().await;
}

#[tokio::test]
async fn out_of_scope_is_forwarded_but_not_logged() {
    let (inside, outside) = (
        Origin::start(&[OK5], false).await,
        Origin::start(&[OK5], false).await,
    );
    let mut scope = Scope::new();
    scope
        .push(RuleSpec {
            action: Action::Include,
            host: "127.0.0.1".into(),
            ports: vec![inside.addr.port().to_string()],
            path: None,
        })
        .unwrap();
    let mut rig = Rig::start(Some(scope)).await;
    let got = client(
        rig.addr(),
        &[
            (&get(outside.addr, "/out"), None),
            (&get(inside.addr, "/in"), None),
        ],
    )
    .await;
    assert_eq!((&got[0][..], &got[1][..]), (OK5, OK5)); // both forwarded
    assert_eq!(outside.requests().len(), 1);
    let ev = rig.next_event().await;
    assert_eq!(ev.port, inside.addr.port());
    assert_eq!(rig.store().list(10, 0).unwrap().len(), 1);
    rig.finish().await;
}

#[tokio::test]
async fn upgrade_switches_to_a_byte_tunnel() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let (s, _) = l.accept().await.unwrap();
        let (r, mut w) = s.into_split();
        let mut r = Reader::new(r, Limits::default());
        r.read_request().await.unwrap().unwrap();
        write_raw(
            &mut w,
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\nhi-from-origin",
        )
        .await
        .unwrap();
        let (mut inner, left) = r.into_parts();
        let mut buf = left.to_vec();
        let mut tmp = [0u8; 64];
        while buf.len() < 9 {
            let n = inner.read(&mut tmp).await.unwrap();
            buf.extend(&tmp[..n]);
        }
        write_raw(&mut w, &buf).await.unwrap(); // echo
    });
    let mut rig = Rig::start(None).await;
    let s = TcpStream::connect(rig.addr()).await.unwrap();
    let (r, mut w) = s.into_split();
    write_raw(&mut w, format!("GET http://{addr}/ws HTTP/1.1\r\nHost: {addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n").as_bytes()).await.unwrap();
    let mut r = Reader::new(r, Limits::default());
    let head = tokio::time::timeout(T, r.read_response(None))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(head.framing, Framing::HeadOnly);
    write_raw(&mut w, b"ping-data").await.unwrap();
    let (mut inner, mut got) = {
        let (i, l) = r.into_parts();
        (i, l.to_vec())
    };
    let want = b"hi-from-origin".len() + b"ping-data".len();
    while got.len() < want {
        let mut tmp = [0u8; 64];
        let n = tokio::time::timeout(T, inner.read(&mut tmp))
            .await
            .expect("tunnel stalled")
            .unwrap();
        assert!(n > 0, "tunnel closed early");
        got.extend(&tmp[..n]);
    }
    assert_eq!(got, b"hi-from-originping-data");
    assert_eq!(rig.next_event().await.status, Some(101));
    rig.finish().await;
}

#[tokio::test]
async fn non_loopback_bind_is_refused_by_default() {
    let store = Store::in_memory().unwrap();
    let cfg = Config {
        listen: "0.0.0.0:0".parse().unwrap(),
        ..Config::default()
    };
    assert!(matches!(
        serve(cfg, store).await,
        Err(ProxyError::NonLoopback(_))
    ));
}
