//! SQLite storage for exchanges, with numbered migrations.

use std::path::Path;

use bytes::Bytes;
use rusqlite::{params, Connection, OptionalExtension, Row};

use crate::message::{Exchange, Source, Stored, Summary};
use crate::view::{RequestView, ResponseView};

/// Migrations in order; entry `i` upgrades `user_version` from `i` to `i + 1`.
const MIGRATIONS: &[&str] = &[include_str!("../migrations/0001_init.sql")];
const LATEST: u32 = MIGRATIONS.len() as u32;

/// Storage errors.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// SQLite failed.
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// The database was written by a newer version of Mantis.
    #[error("database schema version {found} is newer than supported version {supported}")]
    NewerSchema {
        /// Version found in the file.
        found: u32,
        /// Highest version this build understands.
        supported: u32,
    },
    /// No exchange has this id.
    #[error("no exchange with id {0}")]
    NotFound(i64),
    /// A stored value could not be decoded.
    #[error("corrupt row: {0}")]
    Corrupt(&'static str),
}

/// Handle to an exchange database.
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open (creating if needed) the database at `path` and migrate it.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        Self::init(conn)
    }

    /// Open a private in-memory database (for tests and ephemeral sessions).
    pub fn in_memory() -> Result<Self, StoreError> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(mut conn: Connection) -> Result<Self, StoreError> {
        migrate(&mut conn)?;
        Ok(Store { conn })
    }

    /// Insert an exchange and return its id.
    pub fn insert(&self, ex: &Exchange) -> Result<i64, StoreError> {
        let rq = RequestView::parse(&ex.request);
        let method = rq.method.as_ref().map(|r| lossy(&ex.request[r.clone()]));
        let path = rq.target.as_ref().map(|r| lossy(&ex.request[r.clone()]));
        let status = ex
            .response
            .as_ref()
            .and_then(|r| ResponseView::parse(r).status);
        self.conn.execute(
            "INSERT INTO exchanges (ts, source, host, port, tls, method, path, status, request, response)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                ex.ts_micros,
                ex.source.as_str(),
                ex.host,
                ex.port,
                ex.tls,
                method,
                path,
                status,
                &ex.request[..],
                ex.response.as_deref()
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Attach (or replace) the response of an existing exchange.
    pub fn set_response(&self, id: i64, response: &Bytes) -> Result<(), StoreError> {
        let status = ResponseView::parse(response).status;
        let n = self.conn.execute(
            "UPDATE exchanges SET response = ?1, status = ?2 WHERE id = ?3",
            params![&response[..], status, id],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound(id));
        }
        Ok(())
    }

    /// Fetch one exchange with its raw bytes.
    pub fn get(&self, id: i64) -> Result<Option<Stored>, StoreError> {
        let row = self
            .conn
            .query_row(
                "SELECT id, ts, source, host, port, tls, request, response FROM exchanges WHERE id = ?1",
                [id],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, i64>(4)?,
                        r.get::<_, bool>(5)?,
                        r.get::<_, Vec<u8>>(6)?,
                        r.get::<_, Option<Vec<u8>>>(7)?,
                    ))
                },
            )
            .optional()?;
        row.map(|(id, ts, source, host, port, tls, request, response)| {
            Ok(Stored {
                id,
                exchange: Exchange {
                    ts_micros: ts,
                    source: Source::parse(&source).ok_or(StoreError::Corrupt("source"))?,
                    host,
                    port: u16::try_from(port).map_err(|_| StoreError::Corrupt("port"))?,
                    tls,
                    request: request.into(),
                    response: response.map(Bytes::from),
                },
            })
        })
        .transpose()
    }

    /// List summaries, newest first.
    pub fn list(&self, limit: usize, offset: usize) -> Result<Vec<Summary>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ts, source, host, port, tls, method, path, status
             FROM exchanges ORDER BY id DESC LIMIT ?1 OFFSET ?2",
        )?;
        let rows = stmt.query_map(params![limit as i64, offset as i64], summary_row)?;
        rows.map(|r| r?).collect()
    }
}

fn summary_row(r: &Row<'_>) -> rusqlite::Result<Result<Summary, StoreError>> {
    let source: String = r.get(2)?;
    let port: i64 = r.get(4)?;
    let status: Option<i64> = r.get(8)?;
    Ok((|| {
        Ok(Summary {
            id: r.get(0)?,
            ts_micros: r.get(1)?,
            source: Source::parse(&source).ok_or(StoreError::Corrupt("source"))?,
            host: r.get(3)?,
            port: u16::try_from(port).map_err(|_| StoreError::Corrupt("port"))?,
            tls: r.get(5)?,
            method: r.get(6)?,
            path: r.get(7)?,
            status: status
                .map(u16::try_from)
                .transpose()
                .map_err(|_| StoreError::Corrupt("status"))?,
        })
    })())
}

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn migrate(conn: &mut Connection) -> Result<(), StoreError> {
    let found: u32 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if found > LATEST {
        return Err(StoreError::NewerSchema {
            found,
            supported: LATEST,
        });
    }
    for (i, sql) in MIGRATIONS.iter().enumerate().skip(found as usize) {
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.pragma_update(None, "user_version", i as u32 + 1)?;
        tx.commit()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn ex(request: &[u8], response: Option<&[u8]>) -> Exchange {
        Exchange {
            ts_micros: 1_700_000_000_000_000,
            source: Source::Proxy,
            host: "example.com".into(),
            port: 8443,
            tls: true,
            request: Bytes::copy_from_slice(request),
            response: response.map(Bytes::copy_from_slice),
        }
    }

    #[test]
    fn round_trip_preserves_odd_bytes() {
        let s = Store::in_memory().unwrap();
        let rq = b"GET /\x00\xff HTTP/1.1\nA: 1\r\nA: 2\r\n\r\n\xc3(";
        let rs = b"HTTP/1.1 200 OK\r\n\r\n\x00\x00";
        let id = s.insert(&ex(rq, Some(rs))).unwrap();
        let got = s.get(id).unwrap().unwrap();
        assert_eq!(got.exchange, ex(rq, Some(rs)));
        assert!(s.get(id + 1).unwrap().is_none());
    }

    #[test]
    fn five_mb_body_round_trips() {
        let s = Store::in_memory().unwrap();
        let mut rq = b"POST / HTTP/1.1\r\n\r\n".to_vec();
        rq.extend((0..5 * 1024 * 1024).map(|i| (i % 251) as u8));
        let id = s.insert(&ex(&rq, None)).unwrap();
        assert_eq!(&s.get(id).unwrap().unwrap().exchange.request[..], &rq[..]);
    }

    #[test]
    fn set_response_updates_status_and_list() {
        let s = Store::in_memory().unwrap();
        let a = s.insert(&ex(b"GET /a HTTP/1.1\r\n\r\n", None)).unwrap();
        let b = s.insert(&ex(b"POST /b HTTP/1.1\r\n\r\n", None)).unwrap();
        s.set_response(a, &Bytes::from_static(b"HTTP/1.1 302 Found\r\n\r\n"))
            .unwrap();
        assert!(matches!(
            s.set_response(99, &Bytes::new()),
            Err(StoreError::NotFound(99))
        ));
        let l = s.list(10, 0).unwrap();
        assert_eq!(l.iter().map(|x| x.id).collect::<Vec<_>>(), [b, a]);
        assert_eq!(l[0].method.as_deref(), Some("POST"));
        assert_eq!(l[1].path.as_deref(), Some("/a"));
        assert_eq!((l[0].status, l[1].status), (None, Some(302)));
        assert_eq!(s.list(1, 1).unwrap()[0].id, a);
    }

    #[test]
    fn migrations_are_idempotent_and_versioned() {
        let dir = std::env::temp_dir().join(format!("mantis-test-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&dir);
        {
            let s = Store::open(&dir).unwrap();
            s.insert(&ex(b"GET / HTTP/1.1\r\n\r\n", None)).unwrap();
        }
        let s = Store::open(&dir).unwrap(); // reopen runs migrate again
        assert_eq!(s.list(10, 0).unwrap().len(), 1);
        let v: u32 = s
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(v, LATEST);
        s.conn
            .pragma_update(None, "user_version", LATEST + 1)
            .unwrap();
        drop(s);
        assert!(matches!(
            Store::open(&dir),
            Err(StoreError::NewerSchema { .. })
        ));
        for ext in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{ext}", dir.display()));
        }
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_round_trip(rq in proptest::collection::vec(any::<u8>(), 0..2048),
                                      rs in proptest::option::of(proptest::collection::vec(any::<u8>(), 0..2048))) {
            let s = Store::in_memory().unwrap();
            let e = ex(&rq, rs.as_deref());
            let id = s.insert(&e).unwrap();
            prop_assert_eq!(s.get(id).unwrap().unwrap().exchange, e);
        }

        #[test]
        fn views_never_panic_and_ranges_in_bounds(raw in proptest::collection::vec(
            prop_oneof![Just(b'\r'), Just(b'\n'), Just(b' '), Just(b':'), Just(b'\t'), any::<u8>()], 0..512)) {
            let n = raw.len();
            let ok = |r: &std::ops::Range<usize>| r.start <= r.end && r.end <= n;
            let q = RequestView::parse(&raw);
            let p = ResponseView::parse(&raw);
            for r in [&q.start_line, &q.body, &p.start_line, &p.body] { prop_assert!(ok(r)); }
            for r in [&q.method, &q.target, &q.version, &p.version, &p.reason].into_iter().flatten() { prop_assert!(ok(r)); }
            for h in q.headers.iter().chain(&p.headers) { prop_assert!(ok(&h.name) && ok(&h.value)); }
        }
    }
}
