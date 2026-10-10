//! HTTPS interception end to end: client --TLS--> proxy --TLS--> origin.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mantis_core::wire::{write_raw, Framing, Limits, Reader};
use mantis_core::{Action, RuleSpec, Scope, Store, Summary};
use mantis_proxy::ca::Ca;
use mantis_proxy::{serve, Config, ProxyHandle};
use rustls::crypto::ring;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio_rustls::client::TlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const T: Duration = Duration::from_secs(5);
const OK5: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";

#[derive(Debug)]
struct Fixed(Arc<CertifiedKey>);

impl ResolvesServerCert for Fixed {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(ring::default_provider())
}

fn client_cfg(trust: &CertificateDer<'static>, alpn: &[&[u8]]) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(trust.clone()).unwrap();
    let mut c = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    c.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(c)
}

/// A TLS origin with a certificate from its own private CA.
struct TlsOrigin {
    addr: SocketAddr,
    ca_der: CertificateDer<'static>,
    received: Arc<Mutex<Vec<Vec<u8>>>>,
    accepts: Arc<AtomicUsize>,
}

impl TlsOrigin {
    async fn start(cert_name: &str, replies: &'static [&'static [u8]]) -> TlsOrigin {
        let (ca, _) = Ca::generate().unwrap();
        let leaf = ca.leaf(cert_name).unwrap();
        let cfg = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Fixed(leaf)));
        let acceptor = TlsAcceptor::from(Arc::new(cfg));
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let (received, accepts, count) = (
            Arc::new(Mutex::new(Vec::new())),
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(0)),
        );
        let (rec, acc) = (received.clone(), accepts.clone());
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = l.accept().await else { return };
                let (acceptor, rec, acc, count) =
                    (acceptor.clone(), rec.clone(), acc.clone(), count.clone());
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(s).await else {
                        return;
                    };
                    acc.fetch_add(1, Ordering::SeqCst);
                    let (r, mut w) = tokio::io::split(tls);
                    let mut r = Reader::new(r, Limits::default());
                    while let Ok(Some(m)) = r.read_request().await {
                        rec.lock().unwrap().push(m.raw.to_vec());
                        let reply =
                            replies[count.fetch_add(1, Ordering::SeqCst).min(replies.len() - 1)];
                        if write_raw(&mut w, reply).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        TlsOrigin {
            addr,
            ca_der: ca.cert_der().clone(),
            received,
            accepts,
        }
    }

    fn requests(&self) -> Vec<Vec<u8>> {
        self.received.lock().unwrap().clone()
    }
}

struct Rig {
    proxy: ProxyHandle,
    events: broadcast::Receiver<Summary>,
    ca_der: CertificateDer<'static>,
    db: std::path::PathBuf,
}

struct Opts {
    scope: Option<Scope>,
    trust_origin: Option<CertificateDer<'static>>,
    insecure: bool,
}

impl Rig {
    async fn start(o: Opts) -> Rig {
        static N: AtomicUsize = AtomicUsize::new(0);
        let db = std::env::temp_dir().join(format!(
            "mantis-https-test-{}-{}.db",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let (ca, _) = Ca::generate().unwrap();
        let ca_der = ca.cert_der().clone();
        let cfg = Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            scope: o.scope,
            ca: Some(Arc::new(ca)),
            insecure_upstream: o.insecure,
            extra_upstream_roots: o.trust_origin.into_iter().collect(),
            ..Config::default()
        };
        let proxy = serve(cfg, Store::open(&db).unwrap()).await.unwrap();
        let events = proxy.subscribe();
        Rig {
            proxy,
            events,
            ca_der,
            db,
        }
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

type Tunnel = (
    Reader<ReadHalf<TlsStream<TcpStream>>>,
    WriteHalf<TlsStream<TcpStream>>,
    Option<Vec<u8>>,
);

/// CONNECT through the proxy, then TLS to `sni`, trusting `trust`.
async fn open_tunnel(
    proxy: SocketAddr,
    target: &str,
    sni: &str,
    trust: &CertificateDer<'static>,
) -> Result<Tunnel, String> {
    let s = TcpStream::connect(proxy).await.unwrap();
    let (r, mut w) = s.into_split();
    write_raw(
        &mut w,
        format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut r = Reader::new(r, Limits::default());
    let head = tokio::time::timeout(T, r.read_response(Some(b"CONNECT")))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(head.framing, Framing::HeadOnly);
    assert!(
        head.raw.starts_with(b"HTTP/1.1 200 "),
        "{:?}",
        String::from_utf8_lossy(&head.raw)
    );
    let (rh, left) = r.into_parts();
    assert!(left.is_empty());
    let stream = rh.reunite(w).unwrap();
    let connector = TlsConnector::from(client_cfg(trust, &[b"h2", b"http/1.1"]));
    let tls = tokio::time::timeout(
        T,
        connector.connect(ServerName::try_from(sni.to_string()).unwrap(), stream),
    )
    .await
    .unwrap()
    .map_err(|e| e.to_string())?;
    let alpn = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    let (r, w) = tokio::io::split(tls);
    Ok((Reader::new(r, Limits::default()), w, alpn))
}

async fn ask(t: &mut Tunnel, req: &[u8]) -> Vec<u8> {
    write_raw(&mut t.1, req).await.unwrap();
    tokio::time::timeout(T, t.0.read_response(None))
        .await
        .expect("response timed out")
        .unwrap()
        .expect("tunnel closed")
        .raw
        .to_vec()
}

fn get(path: &str, host: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n").into_bytes()
}

#[tokio::test]
async fn https_round_trip_is_byte_exact_and_logged_as_tls() {
    let origin = TlsOrigin::start("127.0.0.1", &[OK5]).await;
    let mut rig = Rig::start(Opts {
        scope: None,
        trust_origin: Some(origin.ca_der.clone()),
        insecure: false,
    })
    .await;
    let target = origin.addr.to_string();
    let mut t = open_tunnel(rig.proxy.local_addr(), &target, "127.0.0.1", &rig.ca_der)
        .await
        .unwrap();
    assert_eq!(
        t.2.as_deref(),
        Some(&b"http/1.1"[..]),
        "h2 must be negotiated down"
    );

    let req = get("/secret?x=1", &target);
    assert_eq!(ask(&mut t, &req).await, OK5);
    assert_eq!(origin.requests(), vec![req.clone()]);

    let ev = rig.next_event().await;
    assert_eq!(
        (
            ev.method.as_deref(),
            ev.path.as_deref(),
            ev.status,
            ev.tls,
            ev.port
        ),
        (
            Some("GET"),
            Some("/secret?x=1"),
            Some(200),
            true,
            origin.addr.port()
        )
    );
    let row = rig.store().get(ev.id).unwrap().unwrap().exchange;
    assert_eq!(
        (
            &row.request[..],
            row.response.as_deref(),
            row.host.as_str(),
            row.tls
        ),
        (&req[..], Some(OK5), "127.0.0.1", true)
    );
    rig.finish().await;
}

#[tokio::test]
async fn dns_name_targets_get_a_dns_certificate() {
    let origin = TlsOrigin::start("localhost", &[OK5]).await;
    let mut rig = Rig::start(Opts {
        scope: None,
        trust_origin: Some(origin.ca_der.clone()),
        insecure: false,
    })
    .await;
    let target = format!("localhost:{}", origin.addr.port());
    let mut t = open_tunnel(rig.proxy.local_addr(), &target, "localhost", &rig.ca_der)
        .await
        .unwrap();
    assert_eq!(ask(&mut t, &get("/", &target)).await, OK5);
    assert_eq!(rig.next_event().await.status, Some(200));
    rig.finish().await;
}

#[tokio::test]
async fn malformed_request_survives_the_tls_hop() {
    let origin = TlsOrigin::start("127.0.0.1", &[OK5]).await;
    let mut rig = Rig::start(Opts {
        scope: None,
        trust_origin: Some(origin.ca_der.clone()),
        insecure: false,
    })
    .await;
    let mut t = open_tunnel(
        rig.proxy.local_addr(),
        &origin.addr.to_string(),
        "127.0.0.1",
        &rig.ca_der,
    )
    .await
    .unwrap();
    let req = b"POST /p HTTP/1.1\nHost: x\nA: 1\r\nA: 2\nB: v\n  folded\nnocolon\nContent-Length: 3\n\nabc".to_vec();
    ask(&mut t, &req).await;
    assert_eq!(origin.requests(), vec![req.clone()]);
    let ev = rig.next_event().await;
    assert_eq!(
        &rig.store().get(ev.id).unwrap().unwrap().exchange.request[..],
        &req[..]
    );
    rig.finish().await;
}

#[tokio::test]
async fn keep_alive_reuses_one_upstream_tls_connection() {
    const SECOND: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
    let origin = TlsOrigin::start("127.0.0.1", &[OK5, SECOND]).await;
    let mut rig = Rig::start(Opts {
        scope: None,
        trust_origin: Some(origin.ca_der.clone()),
        insecure: false,
    })
    .await;
    let target = origin.addr.to_string();
    let mut t = open_tunnel(rig.proxy.local_addr(), &target, "127.0.0.1", &rig.ca_der)
        .await
        .unwrap();
    assert_eq!(ask(&mut t, &get("/a", &target)).await, OK5);
    assert_eq!(ask(&mut t, &get("/b", &target)).await, SECOND);
    assert_eq!(
        origin.accepts.load(Ordering::SeqCst),
        1,
        "one upstream handshake for the whole tunnel"
    );
    assert_eq!(rig.next_event().await.path.as_deref(), Some("/a"));
    assert_eq!(rig.next_event().await.path.as_deref(), Some("/b"));
    rig.finish().await;
}

#[tokio::test]
async fn untrusted_origin_certificate_is_a_502_and_logged_without_response() {
    let origin = TlsOrigin::start("127.0.0.1", &[OK5]).await;
    let mut rig = Rig::start(Opts {
        scope: None,
        trust_origin: None,
        insecure: false,
    })
    .await;
    let target = origin.addr.to_string();
    let mut t = open_tunnel(rig.proxy.local_addr(), &target, "127.0.0.1", &rig.ca_der)
        .await
        .unwrap();
    let resp = ask(&mut t, &get("/", &target)).await;
    assert!(
        resp.starts_with(b"HTTP/1.1 502 "),
        "{}",
        String::from_utf8_lossy(&resp)
    );
    assert!(String::from_utf8_lossy(&resp).contains("TLS handshake failed"));
    assert!(origin.requests().is_empty());
    let ev = rig.next_event().await;
    assert!(ev.tls && ev.status.is_none());
    rig.finish().await;
}

#[tokio::test]
async fn insecure_upstream_accepts_an_untrusted_origin() {
    let origin = TlsOrigin::start("127.0.0.1", &[OK5]).await;
    let mut rig = Rig::start(Opts {
        scope: None,
        trust_origin: None,
        insecure: true,
    })
    .await;
    let target = origin.addr.to_string();
    let mut t = open_tunnel(rig.proxy.local_addr(), &target, "127.0.0.1", &rig.ca_der)
        .await
        .unwrap();
    assert_eq!(ask(&mut t, &get("/", &target)).await, OK5);
    assert_eq!(rig.next_event().await.status, Some(200));
    rig.finish().await;
}

#[tokio::test]
async fn client_that_does_not_trust_the_ca_fails_cleanly() {
    let origin = TlsOrigin::start("127.0.0.1", &[OK5]).await;
    let mut rig = Rig::start(Opts {
        scope: None,
        trust_origin: Some(origin.ca_der.clone()),
        insecure: false,
    })
    .await;
    let other = Ca::generate().unwrap().0;
    let err = open_tunnel(
        rig.proxy.local_addr(),
        &origin.addr.to_string(),
        "127.0.0.1",
        other.cert_der(),
    )
    .await
    .err()
    .expect("handshake must fail");
    assert!(
        err.to_lowercase().contains("cert")
            || err.to_lowercase().contains("unknown")
            || err.to_lowercase().contains("issuer"),
        "{err}"
    );
    // The proxy is still serving.
    let mut t = open_tunnel(
        rig.proxy.local_addr(),
        &origin.addr.to_string(),
        "127.0.0.1",
        &rig.ca_der,
    )
    .await
    .unwrap();
    assert_eq!(ask(&mut t, &get("/", "x")).await, OK5);
    assert_eq!(rig.next_event().await.status, Some(200));
    rig.finish().await;
}

fn include(host: &str, ports: &[u16], path: Option<&str>) -> Scope {
    let mut s = Scope::new();
    s.push(RuleSpec {
        action: Action::Include,
        host: host.into(),
        ports: ports.iter().map(u16::to_string).collect(),
        path: path.map(Into::into),
    })
    .unwrap();
    s
}

#[tokio::test]
async fn out_of_scope_connect_is_a_blind_tunnel_with_the_real_certificate() {
    let origin = TlsOrigin::start("127.0.0.1", &[OK5]).await;
    let mut rig = Rig::start(Opts {
        scope: Some(include("somewhere-else.example", &[], None)),
        trust_origin: None,
        insecure: false,
    })
    .await;
    // The client trusts only the origin's CA: the handshake succeeds only if the
    // proxy relays the origin's own certificate instead of minting one.
    let target = origin.addr.to_string();
    let mut t = open_tunnel(rig.proxy.local_addr(), &target, "127.0.0.1", &origin.ca_der)
        .await
        .unwrap();
    assert_eq!(ask(&mut t, &get("/", &target)).await, OK5);
    drop(t);
    assert!(
        tokio::time::timeout(Duration::from_millis(300), rig.events.recv())
            .await
            .is_err(),
        "nothing may be logged"
    );
    rig.finish().await;
}

#[tokio::test]
async fn path_scope_is_applied_per_request_inside_the_tunnel() {
    let origin = TlsOrigin::start("127.0.0.1", &[OK5]).await;
    let scope = include("127.0.0.1", &[origin.addr.port()], Some("/api/.*"));
    let mut rig = Rig::start(Opts {
        scope: Some(scope),
        trust_origin: Some(origin.ca_der.clone()),
        insecure: false,
    })
    .await;
    let target = origin.addr.to_string();
    let mut t = open_tunnel(rig.proxy.local_addr(), &target, "127.0.0.1", &rig.ca_der)
        .await
        .unwrap();
    assert_eq!(ask(&mut t, &get("/static/x.js", &target)).await, OK5); // forwarded, not logged
    assert_eq!(ask(&mut t, &get("/api/users", &target)).await, OK5);
    assert_eq!(rig.next_event().await.path.as_deref(), Some("/api/users"));
    assert_eq!(rig.store().list(10, 0).unwrap().len(), 1);
    rig.finish().await;
}

#[tokio::test]
async fn connect_to_the_proxy_itself_is_refused() {
    let rig = Rig::start(Opts {
        scope: None,
        trust_origin: None,
        insecure: false,
    })
    .await;
    let me = rig.proxy.local_addr();
    let mut s = TcpStream::connect(me).await.unwrap();
    write_raw(&mut s, format!("CONNECT {me} HTTP/1.1\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut buf = Vec::new();
    tokio::time::timeout(T, s.read_to_end(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert!(buf.starts_with(b"HTTP/1.1 400 "));
    rig.finish().await;
}
