#[path = "../../common.rs"]
mod common;
use common::*;
use eframe::egui;

struct App {
    body: Body,
    hex: bool,
    query: String,
    hits: Vec<usize>,
    cur: usize,
    jump: Option<usize>, // row to scroll to
    bench: Option<Bench>,
    scroll: Option<f32>,
}

impl App {
    fn ui_impl(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        if let Some(b) = &mut self.bench {
            match b.tick() {
                None => std::process::exit(0),
                Some((ph, p)) => {
                    self.hex = ph == 1;
                    let rows = if self.hex { self.body.hex_rows() } else { self.body.lines() };
                    self.scroll = Some((p * rows as f64) as f32 * 14.0);
                }
            }
            ctx.request_repaint();
        }
        egui::Panel::top("bar").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.hex, false, "Text");
                ui.selectable_value(&mut self.hex, true, "Hex");
                let r = ui.text_edit_singleline(&mut self.query);
                if r.changed() {
                    self.hits = self.body.search(&self.query);
                    self.cur = 0;
                    self.jump_to_hit();
                }
                if ui.button("Next").clicked() && !self.hits.is_empty() {
                    self.cur = (self.cur + 1) % self.hits.len();
                    self.jump_to_hit();
                }
                ui.label(format!("{} matches", self.hits.len()));
            });
        });
        egui::CentralPanel::default().show(ui, |ui| {
            let mut area = egui::ScrollArea::both().auto_shrink(false);
            if let Some(s) = self.scroll.take().or(self.jump.take().map(|r| r as f32 * 14.0)) {
                area = area.vertical_scroll_offset(s);
            }
            let total = if self.hex { self.body.hex_rows() } else { self.body.lines() };
            area.show_rows(ui, 14.0, total, |ui, range| {
                for i in range {
                    let t = if self.hex { self.body.hex_row(i) } else { self.body.line(i).into_owned() };
                    ui.add(egui::Label::new(egui::RichText::new(t).monospace()).extend());
                }
            });
        });
    }
    fn jump_to_hit(&mut self) {
        if let Some(&off) = self.hits.get(self.cur) {
            self.jump = Some(if self.hex { off / 16 } else { self.body.line_of(off) });
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _f: &mut eframe::Frame) {
        self.ui_impl(ui);
    }
}

fn main() -> eframe::Result {
    let bench = std::env::args().any(|a| a == "--bench").then(Bench::new);
    let body = gen();
    eframe::run_native(
        "spike-egui",
        eframe::NativeOptions::default(),
        Box::new(|_| Ok(Box::new(App { body, hex: false, query: String::new(), hits: vec![], cur: 0, jump: None, bench, scroll: None }))),
    )
}
