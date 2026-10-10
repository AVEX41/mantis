//! The background runtime against a real proxy and a local origin.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use mantis_core::{Action, Filter, RuleSpec, Scope, Store};
use mantis_ui::backend::{Backend, Cmd, Event};
use mantis_ui::settings::StartConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const T: Duration = Duration::from_secs(5);

async fn origin() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf).await;
                let _ = s
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
            });
        }
    });
    addr
}

async fn next(b: &Backend) -> Event {
    let end = tokio::time::Instant::now() + T;
    loop {
        if let Some(e) = b.try_recv() {
            return e;
        }
        assert!(tokio::time::Instant::now() < end, "no event");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Next `Held` event, acknowledging any `Logged` that arrives first.
async fn next_held(b: &Backend) -> mantis_proxy::intercept::Held {
    loop {
        match next(b).await {
            Event::Held(h) => return h,
            Event::Logged => b.ack_logged(),
            other => panic!("expected Held, got {other:?}"),
        }
    }
}

async fn quiet(b: &Backend) -> bool {
    tokio::time::sleep(Duration::from_millis(300)).await;
    b.try_recv().is_none()
}

fn config(
    db: &std::path::Path,
    ca: &std::path::Path,
    listen: &str,
    scope: Option<Scope>,
) -> StartConfig {
    StartConfig {
        db: db.to_path_buf(),
        listen: listen.parse().unwrap(),
        allow_non_loopback: false,
        insecure_upstream: false,
        ca_dir: Some(ca.to_path_buf()),
        scope,
    }
}

async fn fetch(proxy: SocketAddr, origin: SocketAddr, path: &str) {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(format!("GET http://{origin}{path} HTTP/1.1\r\nHost: {origin}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut all = Vec::new();
    tokio::time::timeout(T, s.read_to_end(&mut all))
        .await
        .unwrap()
        .unwrap();
    assert!(all.starts_with(b"HTTP/1.1 200"));
}

#[tokio::test]
async fn start_log_rescope_export_stop() {
    let dir = std::env::temp_dir().join(format!("mantis-ui-backend-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (db, ca) = (dir.join("p.db"), dir.join("ca"));

    let woken = Arc::new(AtomicUsize::new(0));
    let w = woken.clone();
    let b = Backend::spawn(move || {
        w.fetch_add(1, Ordering::SeqCst);
    })
    .unwrap();
    let origin = origin().await;

    b.send(Cmd::Start(config(&db, &ca, "127.0.0.1:0", None)));
    let Event::Started { addr, fingerprint } = next(&b).await else {
        panic!("expected Started")
    };
    assert_eq!(fingerprint.matches(':').count(), 31);

    // A second start is refused and does not disturb the first.
    b.send(Cmd::Start(config(&db, &ca, "127.0.0.1:0", None)));
    assert!(matches!(next(&b).await, Event::Error(m) if m.contains("already running")));

    fetch(addr, origin, "/one").await;
    assert_eq!(next(&b).await, Event::Logged);
    let ro = Store::open_read_only(&db).unwrap();
    assert_eq!(ro.count(&Filter::default()).unwrap(), 1);

    // More traffic raises Logged only again after the UI acknowledges.
    fetch(addr, origin, "/two").await;
    assert!(quiet(&b).await, "coalesced until acknowledged");
    b.ack_logged();
    fetch(addr, origin, "/three").await;
    assert_eq!(next(&b).await, Event::Logged);
    b.ack_logged();

    // A scope that excludes the origin stops logging, without a restart.
    let mut scope = Scope::new();
    scope
        .push(RuleSpec {
            action: Action::Include,
            host: "elsewhere.example".into(),
            ports: vec![],
            path: None,
        })
        .unwrap();
    b.send(Cmd::SetScope(Some(scope)));
    tokio::time::sleep(Duration::from_millis(100)).await;
    fetch(addr, origin, "/hidden").await;
    assert!(quiet(&b).await);
    b.send(Cmd::SetScope(None));
    tokio::time::sleep(Duration::from_millis(100)).await;
    fetch(addr, origin, "/shown").await;
    assert_eq!(next(&b).await, Event::Logged);
    assert_eq!(ro.count(&Filter::default()).unwrap(), 4);

    // CA export: certificate only, never over an existing file.
    let out = dir.join("ca.pem");
    b.send(Cmd::ExportCa {
        ca_dir: Some(ca.clone()),
        out: out.clone(),
        der: false,
    });
    assert!(matches!(next(&b).await, Event::CaExported { fingerprint: f, .. } if f == fingerprint));
    let pem = std::fs::read_to_string(&out).unwrap();
    assert!(pem.contains("BEGIN CERTIFICATE") && !pem.contains("PRIVATE"));
    b.send(Cmd::ExportCa {
        ca_dir: Some(ca.clone()),
        out,
        der: false,
    });
    assert!(matches!(next(&b).await, Event::Error(_)));

    b.send(Cmd::Stop);
    assert_eq!(next(&b).await, Event::Stopped);
    assert!(
        TcpStream::connect(addr).await.is_err(),
        "no longer listening"
    );
    assert!(
        woken.load(Ordering::SeqCst) >= 8,
        "every event wakes the UI"
    );

    // It can be started again, and a bad address is reported, not fatal.
    b.send(Cmd::Start(config(&db, &ca, "127.0.0.1:0", None)));
    assert!(matches!(next(&b).await, Event::Started { .. }));
    b.send(Cmd::Stop);
    assert_eq!(next(&b).await, Event::Stopped);
    let busy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    b.send(Cmd::Start(config(
        &db,
        &ca,
        &busy.local_addr().unwrap().to_string(),
        None,
    )));
    assert!(matches!(next(&b).await, Event::Error(m) if m.contains("cannot start the proxy")));
    drop(b);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn dropping_the_backend_stops_the_proxy() {
    let dir = std::env::temp_dir().join(format!("mantis-ui-backend-drop-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let b = Backend::spawn(|| {}).unwrap();
    b.send(Cmd::Start(config(
        &dir.join("p.db"),
        &dir.join("ca"),
        "127.0.0.1:0",
        None,
    )));
    let Event::Started { addr, .. } = next(&b).await else {
        panic!()
    };
    assert!(TcpStream::connect(addr).await.is_ok());
    tokio::task::spawn_blocking(move || drop(b)).await.unwrap();
    assert!(TcpStream::connect(addr).await.is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

/// An origin that records each raw request it receives.
async fn recording_origin() -> (SocketAddr, Arc<std::sync::Mutex<Vec<Vec<u8>>>>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            let log = log.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = s.read(&mut buf).await.unwrap_or(0);
                log.lock().unwrap().push(buf[..n].to_vec());
                let _ = s
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
            });
        }
    });
    (addr, seen)
}

async fn send_in_background(proxy: SocketAddr, raw: Vec<u8>) -> tokio::task::JoinHandle<Vec<u8>> {
    tokio::spawn(async move {
        let mut s = TcpStream::connect(proxy).await.unwrap();
        s.write_all(&raw).await.unwrap();
        let mut all = Vec::new();
        let _ = tokio::time::timeout(T, s.read_to_end(&mut all)).await;
        all
    })
}

#[tokio::test]
async fn intercept_through_the_backend_edit_forward_and_drop() {
    use mantis_proxy::intercept::Decision;
    use mantis_proxy::Dir;

    let dir = std::env::temp_dir().join(format!("mantis-ui-backend-icpt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let b = Backend::spawn(|| {}).unwrap();
    let (origin, seen) = recording_origin().await;
    b.send(Cmd::Start(config(
        &dir.join("p.db"),
        &dir.join("ca"),
        "127.0.0.1:0",
        None,
    )));
    let Event::Started { addr, .. } = next(&b).await else {
        panic!()
    };
    b.send(Cmd::SetIntercept {
        dir: Dir::Request,
        on: true,
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Edit: the origin receives exactly the edited bytes.
    let req = format!("GET http://{origin}/a HTTP/1.1\r\nHost: {origin}\r\n\r\n").into_bytes();
    let client = send_in_background(addr, req.clone()).await;
    let h = next_held(&b).await;
    assert_eq!((h.dir, &h.raw[..]), (Dir::Request, &req[..]));
    assert!(
        seen.lock().unwrap().is_empty(),
        "nothing reaches the origin while held"
    );
    let edited = bytes::Bytes::from(format!(
        "GET http://{origin}/edited HTTP/1.1\nHost: x\nA: \x01\n\n"
    ));
    b.send(Cmd::Decide {
        id: h.id,
        decision: Decision::Edited(edited.clone()),
    });
    assert_eq!(next(&b).await, Event::Resolved(h.id));
    assert!(client.await.unwrap().starts_with(b"HTTP/1.1 200"));
    let got = seen.lock().unwrap().clone();
    assert_eq!(got, vec![edited.to_vec()]);
    // The proxy's Logged event for that exchange is also delivered.
    assert_eq!(next(&b).await, Event::Logged);
    b.ack_logged();

    // Drop: the client gets nothing and the origin never sees it.
    let client = send_in_background(addr, req.clone()).await;
    let h = next_held(&b).await;
    b.send(Cmd::Decide {
        id: h.id,
        decision: Decision::Drop,
    });
    assert_eq!(next(&b).await, Event::Resolved(h.id));
    assert!(client.await.unwrap().is_empty());
    assert_eq!(seen.lock().unwrap().len(), 1);

    // Turning interception off releases what is waiting.
    let client = send_in_background(addr, req).await;
    let h = next_held(&b).await;
    b.send(Cmd::SetIntercept {
        dir: Dir::Request,
        on: false,
    });
    loop {
        match next(&b).await {
            Event::Resolved(id) if id == h.id => break,
            Event::Logged => b.ack_logged(),
            other => panic!("unexpected {other:?}"),
        }
    }
    assert!(client.await.unwrap().starts_with(b"HTTP/1.1 200"));
    b.send(Cmd::Stop);
    drop(b);
    let _ = std::fs::remove_dir_all(&dir);
}
