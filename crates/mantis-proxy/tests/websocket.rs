//! WebSocket capture end to end over plain HTTP: frames are built by hand.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use mantis_core::wire::{write_raw, Limits, Reader};
use mantis_core::{Action, RuleSpec, Scope, Store, WsDir};
use mantis_proxy::{serve, Config, ProxyHandle, WsEvent};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, oneshot};

const T: Duration = Duration::from_secs(10);
const UPGRADE: &[u8] =
    b"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: x\r\n\r\n";

fn frame(opcode: u8, fin: bool, mask: Option<[u8; 4]>, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![(u8::from(fin) << 7) | opcode];
    let m = if mask.is_some() { 0x80 } else { 0 };
    match payload.len() {
        n if n < 126 => v.push(m | n as u8),
        n if n <= 0xffff => {
            v.push(m | 126);
            v.extend((n as u16).to_be_bytes());
        }
        n => {
            v.push(m | 127);
            v.extend((n as u64).to_be_bytes());
        }
    }
    match mask {
        Some(k) => {
            v.extend(k);
            v.extend(payload.iter().enumerate().map(|(i, b)| b ^ k[i % 4]));
        }
        None => v.extend(payload),
    }
    v
}

/// An origin that accepts the upgrade, sends `script` in separate writes, then
/// records everything the client sends until it hangs up.
struct Origin {
    addr: SocketAddr,
    from_client: Option<oneshot::Receiver<Vec<u8>>>,
}

impl Origin {
    async fn start(status_line_and_headers: &'static [u8], script: Vec<Vec<u8>>) -> Origin {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            let (r, mut w) = s.into_split();
            let mut r = Reader::new(r, Limits::default());
            r.read_request().await.unwrap().unwrap();
            // The first server frame goes out in the same write as the 101 head.
            let mut first = status_line_and_headers.to_vec();
            let mut rest = script.into_iter();
            if let Some(c) = rest.next() {
                first.extend(c);
            }
            w.write_all(&first).await.unwrap();
            for chunk in rest {
                tokio::time::sleep(Duration::from_millis(5)).await;
                w.write_all(&chunk).await.unwrap();
            }
            let mut got = r.take_buffered().to_vec();
            let mut inner = r.into_parts().0;
            inner.read_to_end(&mut got).await.unwrap();
            let _ = tx.send(got);
        });
        Origin {
            addr,
            from_client: Some(rx),
        }
    }

    async fn client_bytes(&mut self) -> Vec<u8> {
        tokio::time::timeout(T, self.from_client.take().unwrap())
            .await
            .expect("origin never saw the client hang up")
            .unwrap()
    }
}

fn head_101(extra: &str) -> &'static [u8] {
    Box::leak(
        format!("HTTP/1.1 101 Switching Protocols\r\n{extra}")
            .into_bytes()
            .into_boxed_slice(),
    )
}

struct Rig {
    proxy: ProxyHandle,
    ws: broadcast::Receiver<WsEvent>,
    db: PathBuf,
}

impl Rig {
    async fn start(scope: Option<Scope>) -> Rig {
        static N: AtomicUsize = AtomicUsize::new(0);
        let db = std::env::temp_dir().join(format!(
            "mantis-ws-test-{}-{}.db",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let cfg = Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            scope,
            ..Config::default()
        };
        let proxy = serve(cfg, Store::open(&db).unwrap()).await.unwrap();
        Rig {
            ws: proxy.subscribe_ws(),
            proxy,
            db,
        }
    }

    fn store(&self) -> Store {
        Store::open(&self.db).unwrap()
    }

    async fn frames(&mut self, n: usize) -> Vec<WsEvent> {
        let mut v = Vec::new();
        while v.len() < n {
            v.push(
                tokio::time::timeout(T, self.ws.recv())
                    .await
                    .expect("frame event missing")
                    .unwrap(),
            );
        }
        v
    }

    async fn finish(self) {
        self.proxy.shutdown().await;
        for ext in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{ext}", self.db.display()));
        }
    }
}

/// Upgrade through the proxy, send `to_server` (in `chunk`-byte writes), read
/// `expect` bytes from the server, then hang up. Returns what the client received after the 101 head.
async fn run_client(
    proxy: SocketAddr,
    origin: SocketAddr,
    to_server: &[u8],
    chunk: usize,
    expect: usize,
) -> Vec<u8> {
    let s = TcpStream::connect(proxy).await.unwrap();
    let (r, mut w) = s.into_split();
    let req = format!("GET http://{origin}/chat HTTP/1.1\r\nHost: {origin}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: abc\r\nSec-WebSocket-Version: 13\r\n\r\n");
    write_raw(&mut w, req.as_bytes()).await.unwrap();
    let mut r = Reader::new(r, Limits::default());
    let head = tokio::time::timeout(T, r.read_response(None))
        .await
        .expect("no 101")
        .unwrap()
        .unwrap();
    assert!(head.raw.starts_with(b"HTTP/1.1 101 "));
    for c in to_server.chunks(chunk.max(1)) {
        w.write_all(c).await.unwrap();
        w.flush().await.unwrap();
    }
    let mut got = r.take_buffered().to_vec();
    let mut inner = r.into_parts().0;
    let mut buf = vec![0u8; 64 * 1024];
    while got.len() < expect {
        let n = tokio::time::timeout(T, inner.read(&mut buf))
            .await
            .expect("server bytes stalled")
            .unwrap();
        assert!(
            n > 0,
            "tunnel closed early after {} of {expect} bytes",
            got.len()
        );
        got.extend(&buf[..n]);
    }
    w.shutdown().await.unwrap();
    got
}

#[tokio::test]
async fn frames_in_both_directions_are_forwarded_exactly_and_captured() {
    let key = [0xde, 0xad, 0xbe, 0xef];
    let server: Vec<Vec<u8>> = vec![
        frame(1, true, None, b"hello"),
        frame(9, true, None, b"p"),
        frame(8, true, None, &[0x03, 0xe8]),
    ];
    let client = [
        frame(1, true, Some(key), b"world"),
        frame(8, true, Some(key), &[0x03, 0xe8]),
    ]
    .concat();
    let mut origin = Origin::start(
        head_101(std::str::from_utf8(UPGRADE).unwrap()),
        server.clone(),
    )
    .await;
    let mut rig = Rig::start(None).await;
    let expect = server.concat();
    let got = run_client(
        rig.proxy.local_addr(),
        origin.addr,
        &client,
        3,
        expect.len(),
    )
    .await;
    assert_eq!(got, expect, "client gets the server's bytes unchanged");
    assert_eq!(
        origin.client_bytes().await,
        client,
        "origin gets the client's bytes unchanged"
    );

    let evs = rig.frames(5).await;
    let id = evs[0].exchange_id;
    let store = rig.store();
    let frames = store.ws_frames(id).unwrap();
    assert_eq!(frames.len(), 5);
    let to = |d: WsDir| {
        frames
            .iter()
            .filter(|f| f.frame.dir == d)
            .map(|f| (f.frame.opcode, f.frame.raw.to_vec()))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        to(WsDir::ToClient),
        server
            .iter()
            .zip([1u8, 9, 8])
            .map(|(f, o)| (o, f.clone()))
            .collect::<Vec<_>>()
    );
    let c = to(WsDir::ToServer);
    assert_eq!((c[0].0, c[1].0), (1, 8));
    assert_eq!(
        c.iter().flat_map(|x| x.1.clone()).collect::<Vec<_>>(),
        client
    );
    // The derived view unmasks; the stored bytes stay masked.
    let masked = frames
        .iter()
        .find(|f| f.frame.dir == WsDir::ToServer && f.frame.opcode == 1)
        .unwrap();
    assert_ne!(&masked.frame.raw[masked.frame.raw.len() - 5..], b"world");
    let upgrade = store.get(id).unwrap().unwrap().exchange;
    assert!(upgrade.response.unwrap().starts_with(b"HTTP/1.1 101 "));
    rig.finish().await;
}

#[tokio::test]
async fn fragments_and_long_frames_are_captured_across_odd_read_boundaries() {
    let big: Vec<u8> = (0..70_000).map(|i| (i % 251) as u8).collect();
    let mid = vec![b'm'; 300];
    let server = vec![
        frame(1, false, None, b"He"),
        frame(0, true, None, b"llo"),
        frame(2, true, None, &mid),
        frame(2, true, None, &big),
    ];
    let mut origin = Origin::start(
        head_101(std::str::from_utf8(UPGRADE).unwrap()),
        server.clone(),
    )
    .await;
    let mut rig = Rig::start(None).await;
    let expect = server.concat();
    let got = run_client(
        rig.proxy.local_addr(),
        origin.addr,
        &frame(2, true, Some([1, 2, 3, 4]), &big),
        1000,
        expect.len(),
    )
    .await;
    assert_eq!(got, expect);
    origin.client_bytes().await;
    let evs = rig.frames(5).await;
    let lens: Vec<_> = evs
        .iter()
        .filter(|e| e.dir == WsDir::ToClient)
        .map(|e| (e.opcode, e.fin, e.payload_len))
        .collect();
    assert_eq!(
        lens,
        [
            (1, false, 2),
            (0, true, 3),
            (2, true, 300),
            (2, true, 70_000)
        ]
    );
    assert!(evs.iter().all(|e| !e.truncated));
    rig.finish().await;
}

#[tokio::test]
async fn an_oversize_frame_is_truncated_in_the_store_but_forwarded_in_full() {
    let huge: Vec<u8> = (0..1_500_000).map(|i| (i % 249) as u8).collect();
    let server = vec![frame(2, true, None, &huge), frame(1, true, None, b"after")];
    let mut origin = Origin::start(
        head_101(std::str::from_utf8(UPGRADE).unwrap()),
        server.clone(),
    )
    .await;
    let mut rig = Rig::start(None).await;
    let expect = server.concat();
    let got = run_client(rig.proxy.local_addr(), origin.addr, b"", 1, expect.len()).await;
    assert!(
        got == expect,
        "all {} bytes must arrive intact",
        expect.len()
    );
    origin.client_bytes().await;
    let evs = rig.frames(2).await;
    assert_eq!(
        (evs[0].payload_len, evs[0].truncated, evs[1].truncated),
        (1_500_000, true, false)
    );
    let stored = rig.store().ws_frames(evs[0].exchange_id).unwrap();
    assert_eq!(stored[0].frame.raw.len(), 1 + 1 + 8 + (1 << 20));
    assert_eq!(&stored[0].frame.raw[10..], &huge[..1 << 20]);
    assert_eq!(&stored[1].frame.raw[2..], b"after");
    rig.finish().await;
}

#[tokio::test]
async fn invalid_framing_stops_capture_but_not_forwarding() {
    let server = vec![
        frame(1, true, None, b"ok"),
        vec![0x03, 0x02, b'x', b'y'],
        frame(1, true, None, b"after the garbage"),
    ];
    let mut origin = Origin::start(
        head_101(std::str::from_utf8(UPGRADE).unwrap()),
        server.clone(),
    )
    .await;
    let mut rig = Rig::start(None).await;
    let expect = server.concat();
    let got = run_client(rig.proxy.local_addr(), origin.addr, b"", 1, expect.len()).await;
    assert_eq!(got, expect);
    origin.client_bytes().await;
    let evs = rig.frames(1).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        rig.store().ws_frames(evs[0].exchange_id).unwrap().len(),
        1,
        "only the frame before the garbage"
    );
    rig.finish().await;
}

#[tokio::test]
async fn a_non_websocket_upgrade_is_an_uncaptured_tunnel() {
    let server = vec![frame(1, true, None, b"looks like a frame")];
    let mut origin = Origin::start(
        head_101("Upgrade: h2c\r\nConnection: Upgrade\r\n\r\n"),
        server.clone(),
    )
    .await;
    let mut rig = Rig::start(None).await;
    let mut events = rig.proxy.subscribe();
    let got = run_client(
        rig.proxy.local_addr(),
        origin.addr,
        b"client bytes",
        4,
        server[0].len(),
    )
    .await;
    assert_eq!(got, server[0]);
    assert_eq!(origin.client_bytes().await, b"client bytes");
    let ev = tokio::time::timeout(T, events.recv())
        .await
        .expect("exchange not logged")
        .unwrap();
    assert_eq!(ev.status, Some(101));
    assert!(
        tokio::time::timeout(Duration::from_millis(300), rig.ws.recv())
            .await
            .is_err(),
        "no frames for a non-WebSocket upgrade"
    );
    rig.finish().await;
}

#[tokio::test]
async fn out_of_scope_websockets_are_relayed_but_not_captured() {
    let mut scope = Scope::new();
    scope
        .push(RuleSpec {
            action: Action::Include,
            host: "elsewhere.example".into(),
            ports: vec![],
            path: None,
        })
        .unwrap();
    let server = vec![frame(1, true, None, b"hi")];
    let mut origin = Origin::start(
        head_101(std::str::from_utf8(UPGRADE).unwrap()),
        server.clone(),
    )
    .await;
    let mut rig = Rig::start(Some(scope)).await;
    let got = run_client(
        rig.proxy.local_addr(),
        origin.addr,
        &frame(1, true, Some([1, 1, 1, 1]), b"yo"),
        100,
        server[0].len(),
    )
    .await;
    assert_eq!(got, server[0]);
    origin.client_bytes().await;
    assert!(
        tokio::time::timeout(Duration::from_millis(300), rig.ws.recv())
            .await
            .is_err()
    );
    assert!(rig.store().list(10, 0).unwrap().is_empty());
    rig.finish().await;
}
