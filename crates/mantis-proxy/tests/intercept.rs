//! Intercept queue and match-and-replace, end to end over plain HTTP.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use mantis_core::wire::{write_raw, Limits, Reader};
use mantis_core::{Action, RuleSpec as ScopeRule, Scope, Store, Summary};
use mantis_proxy::intercept::{Decision, Held, Intercept};
use mantis_proxy::rewrite::{Direction, RuleSpec, Target};
use mantis_proxy::{serve, Config, Dir, ProxyHandle};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

const T: Duration = Duration::from_secs(5);
const OK5: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello";

struct Origin {
    addr: SocketAddr,
    received: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Origin {
    async fn start(replies: &'static [&'static [u8]]) -> Origin {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let received = Arc::new(Mutex::new(Vec::new()));
        let (rec, count) = (received.clone(), Arc::new(AtomicUsize::new(0)));
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = l.accept().await else { return };
                let (rec, count) = (rec.clone(), count.clone());
                tokio::spawn(async move {
                    let (r, mut w) = s.into_split();
                    let mut r = Reader::new(r, Limits::default());
                    while let Ok(Some(m)) = r.read_request().await {
                        rec.lock().unwrap().push(m.raw.to_vec());
                        let n = count.fetch_add(1, Ordering::SeqCst);
                        if write_raw(&mut w, replies[n.min(replies.len() - 1)])
                            .await
                            .is_err()
                        {
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
    held: broadcast::Receiver<Held>,
    intercept: Intercept,
    db: PathBuf,
}

impl Rig {
    async fn start(scope: Option<Scope>, rewrite: Vec<RuleSpec>) -> Rig {
        static N: AtomicUsize = AtomicUsize::new(0);
        let db = std::env::temp_dir().join(format!(
            "mantis-intercept-test-{}-{}.db",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let cfg = Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            scope,
            rewrite,
            ..Config::default()
        };
        let proxy = serve(cfg, Store::open(&db).unwrap()).await.unwrap();
        let intercept = proxy.intercept();
        Rig {
            events: proxy.subscribe(),
            held: intercept.subscribe(),
            intercept,
            proxy,
            db,
        }
    }

    fn addr(&self) -> SocketAddr {
        self.proxy.local_addr()
    }

    async fn next_held(&mut self) -> Held {
        tokio::time::timeout(T, self.held.recv())
            .await
            .expect("nothing was held")
            .unwrap()
    }

    async fn next_event(&mut self) -> Summary {
        tokio::time::timeout(T, self.events.recv())
            .await
            .expect("nothing was logged")
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

/// Send `req` and return the response bytes, or nothing if the proxy closed the connection.
fn spawn_client(proxy: SocketAddr, req: Vec<u8>) -> JoinHandle<Vec<u8>> {
    tokio::spawn(async move {
        let s = TcpStream::connect(proxy).await.unwrap();
        let (r, mut w) = s.into_split();
        write_raw(&mut w, &req).await.unwrap();
        let mut r = Reader::new(r, Limits::default());
        match r.read_response(None).await {
            Ok(Some(m)) => m.raw.to_vec(),
            _ => Vec::new(),
        }
    })
}

async fn done(h: JoinHandle<Vec<u8>>) -> Vec<u8> {
    tokio::time::timeout(T, h)
        .await
        .expect("client timed out")
        .unwrap()
}

fn get(origin: SocketAddr, path: &str) -> Vec<u8> {
    format!("GET http://{origin}{path} HTTP/1.1\r\nHost: {origin}\r\nUser-Agent: curl/8\r\n\r\n")
        .into_bytes()
}

fn rule(
    direction: Direction,
    target: Target,
    header: Option<&str>,
    pattern: &str,
    replace: &str,
) -> RuleSpec {
    RuleSpec {
        direction,
        target,
        header: header.map(Into::into),
        pattern: pattern.into(),
        regex: false,
        replace: replace.into(),
        fix_content_length: None,
        enabled: true,
    }
}

async fn settle() {
    tokio::time::sleep(Duration::from_millis(150)).await;
}

#[tokio::test]
async fn a_held_request_waits_for_a_decision_then_goes_through_unchanged() {
    let origin = Origin::start(&[OK5]).await;
    let mut rig = Rig::start(None, vec![]).await;
    rig.intercept.set_enabled(Dir::Request, true);
    let req = get(origin.addr, "/held");
    let client = spawn_client(rig.addr(), req.clone());

    let held = rig.next_held().await;
    assert_eq!(
        (held.dir, held.port, held.tls, &held.raw[..]),
        (Dir::Request, origin.addr.port(), false, &req[..])
    );
    settle().await;
    assert!(
        origin.requests().is_empty(),
        "nothing may reach the origin before a decision"
    );
    assert_eq!(rig.intercept.pending(), vec![held.clone()]);

    assert!(rig.intercept.decide(held.id, Decision::Forward));
    assert!(
        !rig.intercept.decide(held.id, Decision::Forward),
        "a decision applies once"
    );
    assert_eq!(done(client).await, OK5);
    assert_eq!(origin.requests(), vec![req]);
    let ev = rig.next_event().await;
    assert!(!ev.modified && !ev.dropped);
    assert!(rig.intercept.pending().is_empty());
    rig.finish().await;
}

#[tokio::test]
async fn an_edited_request_is_sent_exactly_as_edited_and_the_original_is_kept() {
    let origin = Origin::start(&[OK5]).await;
    let mut rig = Rig::start(None, vec![]).await;
    rig.intercept.set_enabled(Dir::Request, true);
    let req = get(origin.addr, "/original");
    let client = spawn_client(rig.addr(), req.clone());
    let held = rig.next_held().await;
    // Deliberately odd: bare LF and a duplicate header, sent as-is.
    let edited = Bytes::from(format!(
        "POST http://{0}/edited HTTP/1.1\nHost: {0}\nContent-Length: 5\nA: 1\nA: 2\n\nshort",
        origin.addr
    ));
    rig.intercept
        .decide(held.id, Decision::Edited(edited.clone()));
    assert_eq!(done(client).await, OK5);
    assert_eq!(origin.requests(), vec![edited.to_vec()]);
    let ev = rig.next_event().await;
    assert!(ev.modified);
    let row = rig.store().get(ev.id).unwrap().unwrap().exchange;
    assert_eq!(
        (&row.request[..], row.request_original.as_deref()),
        (&edited[..], Some(&req[..]))
    );
    rig.finish().await;
}

#[tokio::test]
async fn a_dropped_request_never_reaches_the_origin_and_closes_the_connection() {
    let origin = Origin::start(&[OK5]).await;
    let mut rig = Rig::start(None, vec![]).await;
    rig.intercept.set_enabled(Dir::Request, true);
    let client = spawn_client(rig.addr(), get(origin.addr, "/drop"));
    let held = rig.next_held().await;
    rig.intercept.decide(held.id, Decision::Drop);
    assert!(done(client).await.is_empty(), "the client gets no reply");
    settle().await;
    assert!(origin.requests().is_empty());
    let ev = rig.next_event().await;
    assert!(ev.dropped && ev.status.is_none());
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
async fn turning_interception_off_releases_everything_held() {
    let origin = Origin::start(&[OK5]).await;
    let mut rig = Rig::start(None, vec![]).await;
    rig.intercept.set_enabled(Dir::Request, true);
    let client = spawn_client(rig.addr(), get(origin.addr, "/x"));
    rig.next_held().await;
    rig.intercept.set_enabled(Dir::Request, false);
    assert_eq!(done(client).await, OK5);
    assert!(rig.intercept.pending().is_empty());
    rig.finish().await;
}

#[tokio::test]
async fn responses_can_be_edited_and_dropped() {
    const SECOND: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nbye";
    let origin = Origin::start(&[OK5, SECOND]).await;
    let mut rig = Rig::start(None, vec![]).await;
    rig.intercept.set_enabled(Dir::Response, true);

    let client = spawn_client(rig.addr(), get(origin.addr, "/a"));
    let held = rig.next_held().await;
    assert_eq!((held.dir, &held.raw[..]), (Dir::Response, OK5));
    let edited = Bytes::from_static(b"HTTP/1.1 418 Teapot\r\nContent-Length: 2\r\n\r\nhi");
    rig.intercept
        .decide(held.id, Decision::Edited(edited.clone()));
    assert_eq!(done(client).await, &edited[..]);
    let ev = rig.next_event().await;
    let row = rig.store().get(ev.id).unwrap().unwrap().exchange;
    assert_eq!(
        (row.response.as_deref(), row.response_original.as_deref()),
        (Some(&edited[..]), Some(OK5))
    );
    assert_eq!(ev.status, Some(418));

    let client = spawn_client(rig.addr(), get(origin.addr, "/b"));
    let held = rig.next_held().await;
    rig.intercept.decide(held.id, Decision::Drop);
    assert!(done(client).await.is_empty());
    let ev = rig.next_event().await;
    assert!(ev.dropped);
    assert_eq!(
        rig.store()
            .get(ev.id)
            .unwrap()
            .unwrap()
            .exchange
            .response
            .as_deref(),
        Some(SECOND)
    );
    rig.finish().await;
}

#[tokio::test]
async fn out_of_scope_traffic_is_never_held_or_rewritten() {
    let origin = Origin::start(&[OK5]).await;
    let mut scope = Scope::new();
    scope
        .push(ScopeRule {
            action: Action::Include,
            host: "in-scope.example".into(),
            ports: vec![],
            path: None,
        })
        .unwrap();
    let rules = vec![rule(
        Direction::Request,
        Target::Header,
        Some("User-Agent"),
        "curl",
        "Mantis",
    )];
    let rig = Rig::start(Some(scope), rules).await;
    rig.intercept.set_enabled(Dir::Request, true);
    rig.intercept.set_enabled(Dir::Response, true);
    let req = get(origin.addr, "/free");
    assert_eq!(done(spawn_client(rig.addr(), req.clone())).await, OK5);
    assert_eq!(origin.requests(), vec![req], "forwarded untouched");
    assert!(rig.intercept.pending().is_empty());
    rig.finish().await;
}

#[tokio::test]
#[allow(deprecated)]
async fn a_client_connection_error_releases_the_held_entry() {
    let origin = Origin::start(&[OK5]).await;
    let mut rig = Rig::start(None, vec![]).await;
    rig.intercept.set_enabled(Dir::Request, true);
    let mut s = TcpStream::connect(rig.addr()).await.unwrap();
    write_raw(&mut s, &get(origin.addr, "/gone")).await.unwrap();
    rig.next_held().await;
    s.set_linger(Some(Duration::ZERO)).unwrap(); // closing now sends RST
    drop(s);
    tokio::time::timeout(T, async {
        while !rig.intercept.pending().is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("entry was not released");
    assert!(origin.requests().is_empty());
    rig.finish().await;
}

#[tokio::test]
async fn rewrite_rules_run_before_interception_and_both_versions_are_stored() {
    const RESP: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nsecret-ok";
    let origin = Origin::start(&[RESP]).await;
    let rules = vec![
        rule(
            Direction::Request,
            Target::Header,
            Some("User-Agent"),
            "curl",
            "Mantis",
        ),
        rule(
            Direction::Response,
            Target::Body,
            None,
            "secret",
            "hidden-longer",
        ),
    ];
    let mut rig = Rig::start(None, rules).await;
    rig.intercept.set_enabled(Dir::Request, true);
    let req = get(origin.addr, "/rw");
    let client = spawn_client(rig.addr(), req.clone());
    let held = rig.next_held().await;
    assert!(
        String::from_utf8_lossy(&held.raw).contains("User-Agent: Mantis/8"),
        "the queue shows the rewritten request"
    );
    rig.intercept.decide(held.id, Decision::Forward);

    let sent = String::from_utf8_lossy(&origin_wait(&origin).await).into_owned();
    assert!(sent.contains("User-Agent: Mantis/8") && !sent.contains("curl"));
    assert_eq!(
        done(client).await,
        b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\nhidden-longer-ok"
    );

    let ev = rig.next_event().await;
    assert!(ev.modified);
    let row = rig.store().get(ev.id).unwrap().unwrap().exchange;
    assert_eq!(row.request_original.as_deref(), Some(&req[..]));
    assert_eq!(row.response_original.as_deref(), Some(RESP));
    assert_eq!(
        row.response.as_deref(),
        Some(&b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\nhidden-longer-ok"[..])
    );

    // Rules can be replaced while the proxy runs.
    rig.proxy.rewriter().set_rules(vec![]).unwrap();
    rig.intercept.set_enabled(Dir::Request, false);
    assert_eq!(
        done(spawn_client(rig.addr(), get(origin.addr, "/after"))).await,
        RESP
    );
    assert!(!rig.next_event().await.modified);
    rig.finish().await;
}

async fn origin_wait(o: &Origin) -> Vec<u8> {
    tokio::time::timeout(T, async {
        loop {
            if let Some(r) = o.requests().first() {
                return r.clone();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("origin received nothing")
}

#[tokio::test]
async fn an_unmatched_client_read_is_not_confused_with_a_disconnect() {
    // A client that half-closes after sending still gets its answer once the request is forwarded.
    let origin = Origin::start(&[OK5]).await;
    let mut rig = Rig::start(None, vec![]).await;
    rig.intercept.set_enabled(Dir::Request, true);
    let mut s = TcpStream::connect(rig.addr()).await.unwrap();
    write_raw(&mut s, &get(origin.addr, "/half")).await.unwrap();
    tokio::io::AsyncWriteExt::shutdown(&mut s).await.unwrap();
    let held = rig.next_held().await;
    settle().await;
    assert_eq!(
        rig.intercept.pending().len(),
        1,
        "half-close keeps the entry"
    );
    rig.intercept.decide(held.id, Decision::Forward);
    let mut all = Vec::new();
    tokio::time::timeout(T, s.read_to_end(&mut all))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(all, OK5);
    rig.finish().await;
}
