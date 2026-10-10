//! Scripted-scroll benchmark for `mantis-ui --bench`: call [`Bench::tick`] once
//! per frame; it reports frame-interval percentiles and memory at the end.

use std::time::Instant;

/// Frames per phase.
pub const FRAMES: usize = 600;
const WARMUP: usize = 30;

/// Frame timing collector for a fixed list of phases.
pub struct Bench {
    names: &'static [&'static str],
    last: Option<Instant>,
    n: usize,
    frames: Vec<Vec<f64>>,
    rss_start: f64,
    finished: bool,
}

/// Resident memory of this process in MB (0 if `ps` is unavailable).
pub fn rss_mb() -> f64 {
    std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<f64>().ok())
        .unwrap_or(0.0)
        / 1024.0
}

impl Bench {
    /// A benchmark with one phase per name.
    pub fn new(names: &'static [&'static str]) -> Self {
        Bench {
            names,
            last: None,
            n: 0,
            frames: vec![Vec::new(); names.len()],
            rss_start: 0.0,
            finished: false,
        }
    }

    /// Returns (phase, progress 0..1), or `None` once finished (the report has been printed).
    pub fn tick(&mut self) -> Option<(usize, f64)> {
        if self.finished {
            return None;
        }
        let now = Instant::now();
        let step = self.n.saturating_sub(WARMUP);
        if let (Some(last), true) = (self.last, self.n > WARMUP) {
            let phase = ((step - 1) / FRAMES).min(self.names.len() - 1);
            self.frames[phase].push(now.duration_since(last).as_secs_f64() * 1000.0);
        }
        self.last = Some(now);
        if self.n == WARMUP {
            self.rss_start = rss_mb();
        }
        if step >= FRAMES * self.names.len() {
            self.finished = true;
            self.report();
            return None;
        }
        self.n += 1;
        Some((
            (step / FRAMES).min(self.names.len() - 1),
            (step % FRAMES) as f64 / FRAMES as f64,
        ))
    }

    fn report(&self) {
        println!(
            "RSS after warm-up: {:.0} MB, at end: {:.0} MB",
            self.rss_start,
            rss_mb()
        );
        for (name, f) in self.names.iter().zip(&self.frames) {
            let mut f = f.clone();
            if f.is_empty() {
                continue;
            }
            f.sort_by(|a, b| a.total_cmp(b));
            let p = |q: f64| f[((f.len() - 1) as f64 * q) as usize];
            println!(
                "{name}: frames={} p50={:.1}ms p95={:.1}ms p99={:.1}ms max={:.1}ms >20ms={} >33ms={}",
                f.len(),
                p(0.5),
                p(0.95),
                p(0.99),
                f[f.len() - 1],
                f.iter().filter(|&&x| x > 20.0).count(),
                f.iter().filter(|&&x| x > 33.0).count()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walks_every_phase_then_finishes() {
        let mut b = Bench::new(&["a", "b"]);
        let mut seen = Vec::new();
        while let Some(s) = b.tick() {
            seen.push(s);
        }
        assert_eq!(seen.len(), WARMUP + 2 * FRAMES);
        assert_eq!(seen[0], (0, 0.0));
        assert_eq!(seen[WARMUP + FRAMES].0, 1);
        assert!(seen.iter().all(|&(p, x)| p < 2 && (0.0..1.0).contains(&x)));
        assert_eq!(b.frames.iter().map(Vec::len).sum::<usize>(), 2 * FRAMES);
    }
}
