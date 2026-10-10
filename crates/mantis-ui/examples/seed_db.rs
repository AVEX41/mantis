//! Build a large project database for trying the UI:
//! `cargo run --release -p mantis-ui --example seed_db -- /tmp/big.db 100000`
//!
//! The newest row carries a 5 MB response so the viewer can be exercised too.

use anyhow::Context;
use bytes::Bytes;
use mantis_core::{Exchange, Source, Store};

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let path = args.next().context("usage: seed_db PATH [ROWS]")?;
    let rows: usize = args
        .next()
        .map(|n| n.parse())
        .transpose()?
        .unwrap_or(100_000);
    anyhow::ensure!(
        !std::path::Path::new(&path).exists(),
        "{path} already exists; refusing to add to it"
    );
    let store = Store::open(&path)?;

    let methods = ["GET", "POST", "PUT", "DELETE", "GET", "GET"];
    let statuses = [200, 200, 301, 404, 500, 204, 403];
    let t0 = 1_760_000_000_000_000_i64;
    let mut batch = Vec::with_capacity(10_000);
    for i in 0..rows {
        let (host, method, status) = (
            format!("host{}.example.test", i % 50),
            methods[i % methods.len()],
            statuses[i % statuses.len()],
        );
        let last = i + 1 == rows;
        let body: Vec<u8> = if last {
            // 5 MB of mixed text with the odd invalid byte, like the GUI spike.
            let mut b = Vec::with_capacity(5 << 20);
            let mut n = 0u64;
            while b.len() < 5 << 20 {
                b.extend_from_slice(
                    format!("line {n} needle é日本語 token={}\n", n * 7919 % 10007).as_bytes(),
                );
                if n.is_multiple_of(997) {
                    b.extend_from_slice(&[0xff, 0xfe, 0x00]);
                }
                n += 1;
            }
            b
        } else if i.is_multiple_of(1000) {
            vec![b'x'; 20_000]
        } else {
            format!("{{\"id\":{i}}}").into_bytes()
        };
        let request = format!("{method} /api/v1/items/{i}?page={} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: seed\r\nAccept: */*\r\n\r\n", i % 9);
        let mut response = format!(
            "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend(body);
        batch.push(Exchange {
            ts_micros: t0 + i as i64 * 1_000_000,
            source: Source::Proxy,
            host,
            port: if i.is_multiple_of(3) { 443 } else { 80 },
            tls: i.is_multiple_of(3),
            request: Bytes::from(request),
            response: Some(Bytes::from(response)),
            request_original: None,
            response_original: None,
            dropped: false,
        });
        if batch.len() == 10_000 || last {
            store.insert_batch(&batch)?;
            batch.clear();
        }
    }
    println!("wrote {rows} exchanges to {path}");
    Ok(())
}
