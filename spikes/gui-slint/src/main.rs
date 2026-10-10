#[path = "../../common.rs"]
mod common;
use common::*;
use slint::{Model, ModelNotify, ModelRc, ModelTracker, SharedString};
use std::cell::RefCell;
use std::rc::Rc;

slint::include_modules!();

const ROW_H: f32 = 16.0;

struct Lazy {
    body: Rc<Body>,
    hex: bool,
    n: ModelNotify,
}

impl Model for Lazy {
    type Data = SharedString;
    fn row_count(&self) -> usize {
        if self.hex { self.body.hex_rows() } else { self.body.lines() }
    }
    fn row_data(&self, r: usize) -> Option<SharedString> {
        (r < self.row_count()).then(|| if self.hex { self.body.hex_row(r) } else { self.body.line(r).into_owned() }.into())
    }
    fn model_tracker(&self) -> &dyn ModelTracker {
        &self.n
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

struct St {
    body: Rc<Body>,
    hex: bool,
    hits: Vec<usize>,
    cur: usize,
}

fn set_hex(ui: &App, st: &mut St, hex: bool) {
    st.hex = hex;
    ui.set_rows(ModelRc::new(Lazy { body: st.body.clone(), hex, n: ModelNotify::default() }));
    ui.set_vy(0.0);
}

fn jump(ui: &App, st: &St) {
    if let Some(&off) = st.hits.get(st.cur) {
        let r = if st.hex { off / 16 } else { st.body.line_of(off) };
        ui.set_vy(-(r as f32 * ROW_H));
    }
}

fn main() {
    let bench = std::env::args().any(|a| a == "--bench");
    let ui = App::new().unwrap();
    let st = Rc::new(RefCell::new(St { body: Rc::new(gen()), hex: false, hits: vec![], cur: 0 }));
    set_hex(&ui, &mut st.borrow_mut(), false);
    {
        let (w, st) = (ui.as_weak(), st.clone());
        ui.on_hex(move |h| set_hex(&w.unwrap(), &mut st.borrow_mut(), h));
    }
    {
        let (w, st) = (ui.as_weak(), st.clone());
        ui.on_query(move |q| {
            let ui = w.unwrap();
            let mut s = st.borrow_mut();
            s.hits = s.body.search(&q);
            s.cur = 0;
            ui.set_matches(format!("{} matches", s.hits.len()).into());
            jump(&ui, &s);
        });
    }
    {
        let (w, st) = (ui.as_weak(), st.clone());
        ui.on_next(move || {
            let ui = w.unwrap();
            let mut s = st.borrow_mut();
            if !s.hits.is_empty() {
                s.cur = (s.cur + 1) % s.hits.len();
            }
            jump(&ui, &s);
        });
    }
    if bench {
        use slint::ComponentHandle;
        let (w, st) = (ui.as_weak(), st.clone());
        let mut b = Bench::new();
        ui.window()
            .set_rendering_notifier(move |state, _| {
                if !matches!(state, slint::RenderingState::AfterRendering) {
                    return;
                }
                let ui = w.unwrap();
                match b.tick() {
                    None => std::process::exit(0),
                    Some((ph, p)) => {
                        let mut s = st.borrow_mut();
                        if s.hex != (ph == 1) {
                            set_hex(&ui, &mut s, ph == 1);
                        }
                        let rows = if s.hex { s.body.hex_rows() } else { s.body.lines() };
                        ui.set_vy(-((p * rows as f64) as f32 * ROW_H));
                        ui.window().request_redraw();
                    }
                }
            })
            .unwrap();
    }
    ui.run().unwrap();
}
