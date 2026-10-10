// Shared throwaway spike code, included by each spike via #[path].
#![allow(dead_code)]
use std::borrow::Cow;
use std::time::Instant;

pub const SIZE: usize = 5 * 1024 * 1024;
pub const FRAMES: usize = 600;

pub struct Body {
    pub bytes: Vec<u8>,
    pub line_starts: Vec<usize>,
}

pub fn gen() -> Body {
    let mut s: u64 = 0x2545F4914F6CDD1D;
    let mut next = move || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    let words = ["GET", "/api/v1/users", "Host:", "example.com", "token=", "needle", "Ünïcödé", "日本語", "application/json", "Set-Cookie:"];
    let mut bytes = Vec::with_capacity(SIZE + 256);
    let mut n = 0u64;
    while bytes.len() < SIZE {
        n += 1;
        let len = 10 + (next() % 200) as usize; // some very long lines
        let mut line = String::new();
        while line.len() < len {
            line.push_str(words[(next() % words.len() as u64) as usize]);
            line.push(' ');
        }
        bytes.extend_from_slice(line.as_bytes());
        if n % 997 == 0 {
            bytes.extend_from_slice(&[0xFF, 0xFE, 0x80, 0xC3, 0x00]); // non-UTF-8
        }
        bytes.push(b'\n');
    }
    bytes.truncate(SIZE);
    let mut line_starts = vec![0];
    line_starts.extend(bytes.iter().enumerate().filter(|(_, b)| **b == b'\n').map(|(i, _)| i + 1));
    Body { bytes, line_starts }
}

impl Body {
    pub fn lines(&self) -> usize {
        self.line_starts.len()
    }
    pub fn line(&self, i: usize) -> Cow<'_, str> {
        let a = self.line_starts[i];
        let b = self.line_starts.get(i + 1).copied().unwrap_or(self.bytes.len());
        String::from_utf8_lossy(&self.bytes[a..b.max(a)]).trim_end_matches('\n').to_string().into()
    }
    pub fn hex_rows(&self) -> usize {
        self.bytes.len().div_ceil(16)
    }
    pub fn hex_row(&self, r: usize) -> String {
        let a = r * 16;
        let c = &self.bytes[a..(a + 16).min(self.bytes.len())];
        let mut h = String::with_capacity(80);
        h.push_str(&format!("{a:08x}  "));
        for i in 0..16 {
            match c.get(i) {
                Some(b) => h.push_str(&format!("{b:02x} ")),
                None => h.push_str("   "),
            }
        }
        h.push(' ');
        h.extend(c.iter().map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' }));
        h
    }
    pub fn search(&self, q: &str) -> Vec<usize> {
        if q.is_empty() {
            return vec![];
        }
        memchr::memmem::find_iter(&self.bytes, q.as_bytes()).collect()
    }
    pub fn line_of(&self, off: usize) -> usize {
        self.line_starts.partition_point(|&s| s <= off) - 1
    }
}

pub fn rss_mb() -> f64 {
    let o = std::process::Command::new("ps").args(["-o", "rss=", "-p", &std::process::id().to_string()]).output().ok();
    o.and_then(|o| String::from_utf8(o.stdout).ok()).and_then(|s| s.trim().parse::<f64>().ok()).unwrap_or(0.0) / 1024.0
}

/// Scripted scroll benchmark: call `tick()` once per rendered frame.
pub struct Bench {
    last: Option<Instant>,
    n: usize,
    frames: Vec<Vec<f64>>,
    rss_start: f64,
    pub started: Instant,
}

impl Bench {
    pub fn new() -> Self {
        Bench { last: None, n: 0, frames: vec![vec![], vec![]], rss_start: 0.0, started: Instant::now() }
    }
    /// Returns (phase 0=text 1=hex, progress 0..1), or None when finished (report printed).
    pub fn tick(&mut self) -> Option<(usize, f64)> {
        let now = Instant::now();
        if let Some(l) = self.last {
            if self.n > 0 {
                let ph = ((self.n - 1) / FRAMES).min(1);
                self.frames[ph].push(now.duration_since(l).as_secs_f64() * 1000.0);
            }
        }
        self.last = Some(now);
        if self.n == 30 {
            self.rss_start = rss_mb();
        }
        if self.n >= 2 * FRAMES + 30 {
            self.report();
            return None;
        }
        // 30 warm-up frames at the top, then the scripted scroll.
        let i = self.n.saturating_sub(30);
        self.n += 1;
        Some(((i / FRAMES).min(1), (i % FRAMES) as f64 / FRAMES as f64))
    }
    fn report(&mut self) {
        println!("RSS after load: {:.0} MB, after scroll: {:.0} MB", self.rss_start, rss_mb());
        for (ph, name) in ["text", "hex"].iter().enumerate() {
            let mut f = self.frames[ph].clone();
            if f.is_empty() { continue; }
            f.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let p = |q: f64| f[((f.len() - 1) as f64 * q) as usize];
            println!(
                "{name}: frames={} p50={:.1}ms p95={:.1}ms p99={:.1}ms max={:.1}ms >20ms={} >33ms={}",
                f.len(), p(0.5), p(0.95), p(0.99), f[f.len() - 1],
                f.iter().filter(|&&x| x > 20.0).count(), f.iter().filter(|&&x| x > 33.0).count()
            );
        }
    }
}
