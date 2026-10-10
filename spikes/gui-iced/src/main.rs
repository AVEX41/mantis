#[path = "../../common.rs"]
mod common;
use common::*;
use iced::widget::{operation, Id, button, column, container, row, scrollable, text, text_input, Space};
use iced::{Element, Font, Length, Subscription, Task};
use std::time::Instant;

const ROW_H: f32 = 16.0;
const WINDOW: usize = 80; // rendered rows; manual virtualisation

struct App {
    body: Body,
    hex: bool,
    query: String,
    hits: Vec<usize>,
    cur: usize,
    top: usize,
    bench: Option<Bench>,
}

#[derive(Debug, Clone)]
enum Msg {
    Scrolled(scrollable::Viewport),
    Hex(bool),
    Query(String),
    Next,
    Frame(Instant),
}

fn sid() -> Id {
    Id::new("body")
}

impl App {
    fn new() -> Self {
        let bench = std::env::args().any(|a| a == "--bench").then(Bench::new);
        App { body: gen(), hex: false, query: String::new(), hits: vec![], cur: 0, top: 0, bench }
    }
    fn total(&self) -> usize {
        if self.hex { self.body.hex_rows() } else { self.body.lines() }
    }
    fn scroll_row(&mut self, r: usize) -> Task<Msg> {
        self.top = r;
        operation::scroll_to(sid(), scrollable::AbsoluteOffset { x: 0.0, y: r as f32 * ROW_H })
    }
    fn jump(&mut self) -> Task<Msg> {
        match self.hits.get(self.cur) {
            Some(&off) => {
                let r = if self.hex { off / 16 } else { self.body.line_of(off) };
                self.scroll_row(r)
            }
            None => Task::none(),
        }
    }
    fn update(&mut self, m: Msg) -> Task<Msg> {
        match m {
            Msg::Scrolled(v) => {
                self.top = (v.absolute_offset().y / ROW_H) as usize;
                Task::none()
            }
            Msg::Hex(h) => {
                self.hex = h;
                self.scroll_row(0)
            }
            Msg::Query(q) => {
                self.hits = self.body.search(&q);
                self.query = q;
                self.cur = 0;
                self.jump()
            }
            Msg::Next => {
                if !self.hits.is_empty() {
                    self.cur = (self.cur + 1) % self.hits.len();
                }
                self.jump()
            }
            Msg::Frame(_) => {
                let Some(b) = &mut self.bench else { return Task::none() };
                match b.tick() {
                    None => std::process::exit(0),
                    Some((ph, p)) => {
                        self.hex = ph == 1;
                        let rows = self.total();
                        self.scroll_row((p * rows as f64) as usize)
                    }
                }
            }
        }
    }
    fn view(&self) -> Element<'_, Msg> {
        let bar = row![
            button("Text").on_press(Msg::Hex(false)),
            button("Hex").on_press(Msg::Hex(true)),
            text_input("search", &self.query).on_input(Msg::Query),
            button("Next").on_press(Msg::Next),
            text(format!("{} matches", self.hits.len())),
        ]
        .spacing(8);
        let total = self.total();
        let a = self.top.min(total);
        let b = (a + WINDOW).min(total);
        let mut rows = column![Space::new().height(a as f32 * ROW_H)];
        for i in a..b {
            let t = if self.hex { self.body.hex_row(i) } else { self.body.line(i).into_owned() };
            rows = rows.push(container(text(t).font(Font::MONOSPACE).size(13).wrapping(text::Wrapping::None)).height(ROW_H));
        }
        rows = rows.push(Space::new().height((total - b) as f32 * ROW_H));
        column![bar, scrollable(rows).id(sid()).on_scroll(Msg::Scrolled).width(Length::Fill).height(Length::Fill)].into()
    }
    fn subscription(&self) -> Subscription<Msg> {
        if self.bench.is_some() { iced::window::frames().map(Msg::Frame) } else { Subscription::none() }
    }
}

fn main() -> iced::Result {
    iced::application(App::new, App::update, App::view).subscription(App::subscription).run()
}
