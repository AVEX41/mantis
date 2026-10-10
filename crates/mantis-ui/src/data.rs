//! Background reader: the UI asks, a thread with its own read-only database
//! connection answers, so the UI thread never touches SQLite.

use std::path::Path;
use std::sync::mpsc::{self, Receiver, Sender};

use mantis_core::{Filter, Store, StoreError, Stored, Summary};

/// Rows fetched per page.
pub const PAGE: usize = 200;

/// A question for the reader.
#[derive(Debug, Clone)]
pub enum Req {
    /// How many rows match? `gen` identifies the filter generation.
    Count { gen: u64, filter: Filter },
    /// One page (ascending id order) of matching rows.
    Page {
        gen: u64,
        page: usize,
        filter: Filter,
    },
    /// The full exchange with this id.
    Get { id: i64 },
}

/// An answer from the reader.
#[derive(Debug)]
pub enum Resp {
    /// Answer to [`Req::Count`].
    Count { gen: u64, total: usize },
    /// Answer to [`Req::Page`].
    Page {
        gen: u64,
        page: usize,
        rows: Vec<Summary>,
    },
    /// Answer to [`Req::Get`]; `None` if the row does not exist.
    Exchange {
        id: i64,
        stored: Option<Box<Stored>>,
    },
    /// A request failed.
    Failed(String),
}

/// The UI's end of the reader thread. Dropping it stops the thread.
pub struct DataHandle {
    tx: Sender<Req>,
    rx: Receiver<Resp>,
}

impl DataHandle {
    /// Queue a request.
    pub fn send(&self, req: Req) {
        let _ = self.tx.send(req); // the thread only ends when we are dropped
    }

    /// Next answer, if one is ready.
    pub fn try_recv(&self) -> Option<Resp> {
        self.rx.try_recv().ok()
    }
}

/// Why a project could not be opened.
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    /// The database could not be opened or migrated.
    #[error("{0}")]
    Store(#[from] StoreError),
    /// The reader thread could not be started.
    #[error("cannot start reader thread: {0}")]
    Thread(#[from] std::io::Error),
}

/// Open `path` read-only and start answering requests. `wake` is called after
/// every answer so the UI can repaint.
pub fn spawn(path: &Path, wake: impl Fn() + Send + 'static) -> Result<DataHandle, OpenError> {
    let store = Store::open_read_only(path)?;
    let (tx, req_rx) = mpsc::channel::<Req>();
    let (resp_tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("mantis-ui-data".into())
        .spawn(move || {
            for req in req_rx {
                let resp = answer(&store, req);
                if resp_tx.send(resp).is_err() {
                    return;
                }
                wake();
            }
        })?;
    Ok(DataHandle { tx, rx })
}

fn answer(store: &Store, req: Req) -> Resp {
    let fail = |e: StoreError| Resp::Failed(e.to_string());
    match req {
        Req::Count { gen, filter } => store
            .count(&filter)
            .map(|total| Resp::Count { gen, total })
            .unwrap_or_else(fail),
        Req::Page { gen, page, filter } => store
            .list_range(page * PAGE, PAGE, &filter)
            .map(|rows| Resp::Page { gen, page, rows })
            .unwrap_or_else(fail),
        Req::Get { id } => store
            .get(id)
            .map(|s| Resp::Exchange {
                id,
                stored: s.map(Box::new),
            })
            .unwrap_or_else(fail),
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use bytes::Bytes;
    use mantis_core::{Exchange, Source};

    use super::*;

    fn db(tag: &str, rows: usize) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("mantis-ui-{tag}-{}.db", std::process::id()));
        for ext in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{ext}", path.display()));
        }
        let s = Store::open(&path).unwrap();
        let ex: Vec<_> = (0..rows)
            .map(|i| Exchange {
                ts_micros: i as i64,
                source: Source::Proxy,
                host: format!("h{}.com", i % 3),
                port: 80,
                tls: false,
                request: Bytes::from(format!("GET /{i} HTTP/1.1\r\n\r\n")),
                response: None,
                request_original: None,
                response_original: None,
                dropped: false,
            })
            .collect();
        s.insert_batch(&ex).unwrap();
        path
    }

    fn wait(h: &DataHandle) -> Resp {
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(r) = h.try_recv() {
                return r;
            }
            assert!(Instant::now() < end, "no answer");
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    #[test]
    fn answers_count_page_and_get_and_wakes_the_ui() {
        let path = db("data", 450);
        let woken = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let w = woken.clone();
        let h = spawn(&path, move || {
            w.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        })
        .unwrap();
        h.send(Req::Count {
            gen: 7,
            filter: Filter::default(),
        });
        assert!(matches!(wait(&h), Resp::Count { gen: 7, total: 450 }));
        h.send(Req::Page {
            gen: 7,
            page: 2,
            filter: Filter::default(),
        });
        match wait(&h) {
            Resp::Page {
                gen: 7,
                page: 2,
                rows,
            } => assert_eq!((rows.len(), rows[0].id, rows[49].id), (50, 401, 450)),
            other => panic!("{other:?}"),
        }
        h.send(Req::Get { id: 3 });
        match wait(&h) {
            Resp::Exchange {
                id: 3,
                stored: Some(s),
            } => assert!(s.exchange.request.starts_with(b"GET /2 ")),
            other => panic!("{other:?}"),
        }
        h.send(Req::Get { id: 999 });
        assert!(matches!(
            wait(&h),
            Resp::Exchange {
                id: 999,
                stored: None
            }
        ));
        assert_eq!(woken.load(std::sync::atomic::Ordering::SeqCst), 4);
        h.send(Req::Count {
            gen: 8,
            filter: Filter { text: "h1".into() },
        });
        assert!(matches!(wait(&h), Resp::Count { gen: 8, total: 150 }));
        drop(h);
        for ext in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{ext}", path.display()));
        }
    }

    #[test]
    fn opening_a_missing_database_fails_instead_of_creating_one() {
        let path = std::env::temp_dir().join("mantis-ui-definitely-missing.db");
        let _ = std::fs::remove_file(&path);
        assert!(spawn(&path, || {}).is_err());
        assert!(!path.exists());
    }
}
