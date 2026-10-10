//! The history table's data model: a lazily paged, filterable, newest-first view.
//!
//! Rows are stored by ascending id; display row 0 is the newest. New rows
//! therefore only touch the last page and earlier cached pages stay valid.

use std::collections::{HashMap, HashSet};

use mantis_core::{Filter, Summary};

use crate::data::{Req, Resp, PAGE};

/// Pages kept in memory; the ones farthest from the viewport go first.
const MAX_PAGES: usize = 64;

/// Paged view over the exchange table.
pub struct HistoryModel {
    filter: Filter,
    gen: u64,
    total: usize,
    pages: HashMap<usize, Vec<Summary>>,
    pending: HashSet<usize>,
    count_inflight: bool,
    outbox: Vec<Req>,
    focus_page: usize,
    selected: Option<i64>,
}

impl Default for HistoryModel {
    fn default() -> Self {
        Self::new()
    }
}

impl HistoryModel {
    /// An empty model; asks for the row count right away.
    pub fn new() -> Self {
        let mut m = HistoryModel {
            filter: Filter::default(),
            gen: 0,
            total: 0,
            pages: HashMap::new(),
            pending: HashSet::new(),
            count_inflight: false,
            outbox: Vec::new(),
            focus_page: 0,
            selected: None,
        };
        m.refresh();
        m
    }

    /// Rows matching the filter.
    pub fn total(&self) -> usize {
        self.total
    }

    /// Id of the selected row.
    pub fn selected(&self) -> Option<i64> {
        self.selected
    }

    /// Select a row by id and ask for its full contents.
    pub fn select(&mut self, id: i64) {
        self.selected = Some(id);
        self.outbox.push(Req::Get { id });
    }

    /// Change the text filter; resets the cache.
    pub fn set_filter(&mut self, text: &str) {
        if self.filter.text == text {
            return;
        }
        self.filter.text = text.to_string();
        self.gen += 1;
        self.total = 0;
        self.pages.clear();
        self.pending.clear();
        self.count_inflight = false;
        self.refresh();
    }

    /// Ask for a fresh row count (new traffic shows up through this).
    pub fn refresh(&mut self) {
        if !self.count_inflight {
            self.count_inflight = true;
            self.outbox.push(Req::Count {
                gen: self.gen,
                filter: self.filter.clone(),
            });
        }
    }

    /// Display row `i` (0 = newest). Missing pages are requested and `None` is returned meanwhile.
    pub fn row(&mut self, i: usize) -> Option<&Summary> {
        if i >= self.total {
            return None;
        }
        let asc = self.total - 1 - i;
        let page = asc / PAGE;
        self.focus_page = page;
        if !self.pages.contains_key(&page) {
            if self.pending.insert(page) {
                self.outbox.push(Req::Page {
                    gen: self.gen,
                    page,
                    filter: self.filter.clone(),
                });
            }
            return None;
        }
        self.pages.get(&page).and_then(|p| p.get(asc % PAGE))
    }

    /// Requests to forward to the reader.
    pub fn drain_requests(&mut self) -> Vec<Req> {
        std::mem::take(&mut self.outbox)
    }

    /// Take in an answer. Returns it back if it is not about the history list.
    pub fn apply(&mut self, resp: Resp) -> Option<Resp> {
        match resp {
            Resp::Count { gen, total } => {
                if gen == self.gen {
                    self.count_inflight = false;
                    if total < self.total {
                        self.pages.clear();
                        self.pending.clear();
                    } else if total > self.total {
                        // The old last page was partial; drop it and anything beyond.
                        let first_stale = self.total / PAGE;
                        self.pages.retain(|&p, _| p < first_stale);
                        self.pending.retain(|&p| p < first_stale);
                    }
                    self.total = total;
                }
                None
            }
            Resp::Page { gen, page, rows } => {
                if gen == self.gen {
                    self.pending.remove(&page);
                    self.pages.insert(page, rows);
                    self.trim();
                }
                None
            }
            other => Some(other),
        }
    }

    fn trim(&mut self) {
        while self.pages.len() > MAX_PAGES {
            let focus = self.focus_page;
            if let Some(&far) = self.pages.keys().max_by_key(|&&p| p.abs_diff(focus)) {
                self.pages.remove(&far);
            }
        }
    }

    #[cfg(test)]
    fn cached_pages(&self) -> usize {
        self.pages.len()
    }
}

#[cfg(test)]
mod tests {
    use mantis_core::Source;

    use super::*;

    fn summary(id: i64) -> Summary {
        Summary {
            id,
            ts_micros: id,
            source: Source::Proxy,
            host: "h".into(),
            port: 80,
            tls: false,
            method: Some("GET".into()),
            path: Some(format!("/{id}")),
            status: Some(200),
            modified: false,
            dropped: false,
        }
    }

    fn page_resp(gen: u64, page: usize, total: usize) -> Resp {
        let rows = (page * PAGE..((page + 1) * PAGE).min(total))
            .map(|i| summary(i as i64 + 1))
            .collect();
        Resp::Page { gen, page, rows }
    }

    /// Answer every outstanding request from an imaginary table of `total` rows.
    fn serve(m: &mut HistoryModel, total: usize) {
        for r in m.drain_requests() {
            match r {
                Req::Count { gen, .. } => assert!(m.apply(Resp::Count { gen, total }).is_none()),
                Req::Page { gen, page, .. } => {
                    assert!(m.apply(page_resp(gen, page, total)).is_none())
                }
                Req::Get { .. } => {}
            }
        }
    }

    #[test]
    fn starts_by_asking_for_a_count_and_shows_newest_first() {
        let mut m = HistoryModel::new();
        assert!(matches!(
            m.drain_requests()[..],
            [Req::Count { gen: 0, .. }]
        ));
        assert!(m.row(0).is_none());
        m.apply(Resp::Count { gen: 0, total: 450 });
        assert_eq!(m.total(), 450);
        assert!(m.row(0).is_none(), "page not loaded yet");
        assert!(matches!(
            m.drain_requests()[..],
            [Req::Page { page: 2, .. }]
        ));
        assert!(m.row(1).is_none());
        assert!(
            m.drain_requests().is_empty(),
            "no duplicate request for a pending page"
        );
        m.apply(page_resp(0, 2, 450));
        assert_eq!(m.row(0).map(|s| s.id), Some(450));
        assert_eq!(m.row(49).map(|s| s.id), Some(401));
        assert!(m.row(50).is_none(), "next page (older rows) not loaded");
        assert!(matches!(
            m.drain_requests()[..],
            [Req::Page { page: 1, .. }]
        ));
        assert!(m.row(450).is_none(), "out of range");
    }

    #[test]
    fn new_rows_only_invalidate_the_partial_last_page() {
        let mut m = HistoryModel::new();
        serve(&mut m, 450);
        for i in [0, 100, 300] {
            m.row(i);
        }
        serve(&mut m, 450);
        assert_eq!(m.cached_pages(), 3);
        m.refresh();
        serve(&mut m, 460);
        assert_eq!(
            m.cached_pages(),
            2,
            "pages 0 and 1 are full and stay; page 2 is refetched"
        );
        assert_eq!(m.row(0).map(|s| s.id), None, "page 2 is being refetched");
        serve(&mut m, 460);
        assert_eq!(m.row(0).map(|s| s.id), Some(460));
        assert_eq!(m.row(10).map(|s| s.id), Some(450));
    }

    #[test]
    fn a_new_filter_drops_the_cache_and_ignores_stale_answers() {
        let mut m = HistoryModel::new();
        serve(&mut m, 1000);
        m.row(0);
        let stale = m.drain_requests();
        m.set_filter("example");
        assert_eq!(m.total(), 0);
        for r in stale {
            if let Req::Page { gen, page, .. } = r {
                m.apply(page_resp(gen, page, 1000)); // answer for the old filter arrives late
            }
        }
        assert_eq!(m.cached_pages(), 0);
        let reqs = m.drain_requests();
        let Some(Req::Count { gen, filter }) = reqs.first() else {
            panic!("{reqs:?}")
        };
        assert_eq!((*gen, filter.text.as_str()), (1, "example"));
        m.apply(Resp::Count {
            gen: 0,
            total: 5000,
        }); // old generation
        assert_eq!(m.total(), 0);
        m.apply(Resp::Count { gen: 1, total: 7 });
        assert_eq!(m.total(), 7);
        m.set_filter("example"); // unchanged: nothing happens
        assert!(m.drain_requests().is_empty());
    }

    #[test]
    fn cache_stays_bounded_around_the_viewport() {
        let mut m = HistoryModel::new();
        serve(&mut m, 200 * 200); // 200 pages
        for page in 0..200 {
            m.row(page * PAGE); // walk through every page
            serve(&mut m, 200 * 200);
        }
        assert!(m.cached_pages() <= MAX_PAGES);
        let here = m.row(199 * PAGE).map(|s| s.id);
        assert!(here.is_some(), "the page being looked at is kept");
    }

    #[test]
    fn selecting_requests_the_full_exchange_and_other_answers_pass_through() {
        let mut m = HistoryModel::new();
        m.drain_requests();
        m.select(42);
        assert_eq!(m.selected(), Some(42));
        assert!(matches!(m.drain_requests()[..], [Req::Get { id: 42 }]));
        assert!(m
            .apply(Resp::Exchange {
                id: 42,
                stored: None
            })
            .is_some());
        assert!(m.apply(Resp::Failed("x".into())).is_some());
    }
}
