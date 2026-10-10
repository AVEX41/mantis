//! "No UI blocking during proxying": drive the UI's per-frame work (event
//! draining, history paging) while a real proxy handles a burst of traffic,
//! and check that no single frame's worth of work is ever slow.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use mantis_core::Store;
use mantis_ui::backend::{Backend, Cmd, Event};
use mantis_ui::data;
use mantis_ui::history::HistoryModel;
use mantis_ui::settings::StartConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const REQUESTS: usize = 2000;
const WORKERS: usize = 8;
const VISIBLE_ROWS: usize = 40;

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

/// What the window does each frame, minus the drawing.
fn frame(backend: &Backend, data: &data::DataHandle, history: &mut HistoryModel) {
    for _ in 0..256 {
        match backend.try_recv() {
            Some(Event::Logged) => {
                backend.ack_logged();
                history.refresh();
            }
            Some(_) => {}
            None => break,
        }
    }
    for _ in 0..64 {
        let Some(r) = data.try_recv() else { break };
        history.apply(r);
    }
    for i in 0..VISIBLE_ROWS {
        history.row(i);
    }
    for req in history.drain_requests() {
        data.send(req);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_ui_side_stays_responsive_while_the_proxy_is_busy() {
    let dir = std::env::temp_dir().join(format!("mantis-ui-load-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("p.db");
    Store::open(&db).unwrap();
    let data = data::spawn(&db, || {}).unwrap();
    let backend = Backend::spawn(|| {}).unwrap();
    let origin = origin().await;

    backend.send(Cmd::Start(StartConfig {
        db: db.clone(),
        listen: "127.0.0.1:0".parse().unwrap(),
        allow_non_loopback: false,
        insecure_upstream: false,
        ca_dir: Some(dir.join("ca")),
        scope: None,
    }));
    let proxy = loop {
        match backend.try_recv() {
            Some(Event::Started { addr, .. }) => break addr,
            Some(Event::Error(e)) => panic!("{e}"),
            _ => tokio::time::sleep(Duration::from_millis(5)).await,
        }
    };

    // The burst: WORKERS clients, each sending its share over fresh connections.
    let load: Vec<_> = (0..WORKERS)
        .map(|w| {
            tokio::spawn(async move {
                for i in 0..REQUESTS / WORKERS {
                    let mut s = TcpStream::connect(proxy).await.unwrap();
                    let req =
                        format!("GET http://{origin}/w{w}/{i} HTTP/1.1\r\nHost: {origin}\r\n\r\n");
                    s.write_all(req.as_bytes()).await.unwrap();
                    let mut all = Vec::new();
                    s.read_to_end(&mut all).await.unwrap();
                    assert!(all.starts_with(b"HTTP/1.1 200"));
                }
            })
        })
        .collect();

    // Meanwhile, ~250 "frames" per second on a plain thread, timing the work each one does.
    let (frames, history) = tokio::task::spawn_blocking(move || {
        let mut history = HistoryModel::new();
        let mut spent = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            let t = Instant::now();
            frame(&backend, &data, &mut history);
            spent.push(t.elapsed());
            if history.total() == REQUESTS && (0..VISIBLE_ROWS).all(|i| history.row(i).is_some()) {
                break;
            }
            std::thread::sleep(Duration::from_millis(4));
        }
        backend.send(Cmd::Stop);
        (spent, history)
    })
    .await
    .unwrap();
    for l in load {
        l.await.unwrap();
    }

    let mut ms: Vec<f64> = frames.iter().map(|d| d.as_secs_f64() * 1000.0).collect();
    ms.sort_by(|a, b| a.total_cmp(b));
    let (p99, max) = (ms[(ms.len() - 1) * 99 / 100], ms[ms.len() - 1]);
    println!(
        "{} frames while {REQUESTS} requests went through: p99 {p99:.2} ms, max {max:.2} ms",
        ms.len()
    );
    assert_eq!(
        history.total(),
        REQUESTS,
        "every exchange reached the history"
    );
    assert!(
        p99 < 10.0 && max < 100.0,
        "UI-side work blocked: p99 {p99:.2} ms, max {max:.2} ms"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
