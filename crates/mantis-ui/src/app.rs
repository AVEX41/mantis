//! The egui application: thin drawing code over the models.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use bytes::Bytes;
use eframe::egui::{self, Color32, RichText};
use egui_extras::{Column, TableBuilder};
use mantis_core::view::RequestView;
use mantis_core::{Store, Stored};
use serde::{Deserialize, Serialize};

use crate::backend::{Backend, Cmd, Event};
use crate::bench::Bench;
use crate::data::{self, DataHandle, Resp};
use crate::history::HistoryModel;
use crate::intercept::InterceptModel;
use crate::scope_editor::ScopeEditor;
use crate::settings::ProxySettings;
use crate::timefmt::format_utc;
use crate::viewer::RawView;

const TABLE_ROW_H: f32 = 18.0;
const MAX_RESPONSES_PER_FRAME: usize = 64;
const REFRESH_EVERY: Duration = Duration::from_secs(1);

/// One tab of the message viewer.
struct Tab {
    name: &'static str,
    view: RawView,
}

/// The selected exchange and the viewer state around it.
struct Detail {
    title: String,
    tabs: Vec<Tab>,
    tab: usize,
    hex: bool,
    query: String,
    hits: Vec<usize>,
    cur: usize,
    /// One-shot scroll target for the viewer, in rows.
    jump: Option<usize>,
}

impl Detail {
    fn new(s: &Stored) -> Self {
        let e = &s.exchange;
        let rq = RequestView::parse(&e.request);
        let text = |r: &Option<std::ops::Range<usize>>| {
            r.as_ref()
                .map(|r| String::from_utf8_lossy(&e.request[r.clone()]).into_owned())
                .unwrap_or_default()
        };
        let status = e
            .response
            .as_ref()
            .map(|r| {
                mantis_core::view::ResponseView::parse(r)
                    .status
                    .map_or("?".to_string(), |c| c.to_string())
            })
            .unwrap_or_else(|| "no response".into());
        let scheme = if e.tls { "https" } else { "http" };
        let mut flags = String::new();
        if e.request_original.is_some() || e.response_original.is_some() {
            flags.push_str("  [modified]");
        }
        if e.dropped {
            flags.push_str("  [dropped]");
        }
        let title = format!(
            "#{}  {} {scheme}://{}:{}{}  ->  {status}{flags}",
            s.id,
            text(&rq.method),
            e.host,
            e.port,
            text(&rq.target)
        );
        let mut tabs = vec![Tab {
            name: "Request",
            view: RawView::new(e.request.clone()),
        }];
        if let Some(r) = &e.response {
            tabs.push(Tab {
                name: "Response",
                view: RawView::new(r.clone()),
            });
        }
        if let Some(r) = &e.request_original {
            tabs.push(Tab {
                name: "Request (as captured)",
                view: RawView::new(r.clone()),
            });
        }
        if let Some(r) = &e.response_original {
            tabs.push(Tab {
                name: "Response (as received)",
                view: RawView::new(r.clone()),
            });
        }
        Detail {
            title,
            tabs,
            tab: 0,
            hex: false,
            query: String::new(),
            hits: Vec::new(),
            cur: 0,
            jump: None,
        }
    }

    fn research(&mut self) {
        self.hits = self.tabs[self.tab].view.search(&self.query);
        self.cur = 0;
        self.jump_to_hit();
    }

    fn jump_to_hit(&mut self) {
        if let Some(&off) = self.hits.get(self.cur) {
            let v = &self.tabs[self.tab].view;
            self.jump = Some(if self.hex { off / 16 } else { v.row_of(off) });
        }
    }
}

/// Scripted scrolling for `--bench`.
struct BenchDrive {
    bench: Bench,
    /// Set once the 5 MB exchange is on screen.
    started: bool,
}

/// Which page the central area shows.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Page {
    History,
    Proxy,
    Scope,
    Intercept,
}

/// What the background proxy is doing, as far as the UI knows.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProxyState {
    Stopped,
    Starting,
    Running(SocketAddr),
    Stopping,
}

/// What is remembered between runs. The insecure and network-exposure
/// switches are deliberately not part of it: they start off every time.
#[derive(Default, Serialize, Deserialize)]
struct Prefs {
    project: Option<String>,
    listen: Option<String>,
    ca_dir: String,
    scope: ScopeEditor,
}

const PREFS_KEY: &str = "mantis-prefs";

/// The Mantis window.
pub struct App {
    pub(crate) path_input: String,
    pub(crate) project: Option<PathBuf>,
    data: Option<DataHandle>,
    pub(crate) history: HistoryModel,
    filter_input: String,
    pub(crate) error: Option<String>,
    pub(crate) notice: Option<String>,
    detail: Option<Detail>,
    last_refresh: Instant,
    bench: Option<BenchDrive>,
    table_scroll: Option<f32>,
    viewer_scroll: Option<f32>,
    /// Deepest history row and viewer row drawn, to confirm a `--bench` run really scrolled.
    deepest: (usize, usize),
    pub(crate) page: Page,
    pub(crate) backend: Backend,
    pub(crate) proxy: ProxyState,
    pub(crate) settings: ProxySettings,
    pub(crate) scope: ScopeEditor,
    pub(crate) scope_file: String,
    pub(crate) ca_export: String,
    pub(crate) fingerprint: Option<String>,
    /// The running proxy was started without origin certificate verification.
    pub(crate) running_insecure: bool,
    pub(crate) intercept: InterceptModel,
}

fn status_color(code: u16) -> Color32 {
    match code {
        200..=299 => Color32::from_rgb(90, 190, 110),
        300..=399 => Color32::from_rgb(110, 160, 230),
        400..=499 => Color32::from_rgb(235, 170, 70),
        _ => Color32::from_rgb(230, 100, 100),
    }
}

impl App {
    /// A window, optionally opening `path` right away (otherwise the last project).
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        path: Option<PathBuf>,
        bench: bool,
    ) -> std::io::Result<Self> {
        let ctx = &cc.egui_ctx;
        let prefs: Prefs = if bench {
            Prefs::default()
        } else {
            cc.storage
                .and_then(|s| eframe::get_value(s, PREFS_KEY))
                .unwrap_or_default()
        };
        let wake = {
            let ctx = ctx.clone();
            move || ctx.request_repaint()
        };
        let mut settings = ProxySettings::default();
        if let Some(l) = prefs.listen {
            settings.listen = l;
        }
        settings.ca_dir = prefs.ca_dir;
        let last = prefs.project.map(PathBuf::from).filter(|p| p.exists());
        let path = path.or(last);
        let mut app = App {
            path_input: path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            project: None,
            data: None,
            history: HistoryModel::new(),
            filter_input: String::new(),
            error: None,
            notice: None,
            detail: None,
            last_refresh: Instant::now(),
            bench: bench.then(|| BenchDrive {
                bench: Bench::new(&["history scroll", "viewer text", "viewer hex"]),
                started: false,
            }),
            table_scroll: None,
            viewer_scroll: None,
            deepest: (0, 0),
            page: Page::History,
            backend: Backend::spawn(wake)?,
            proxy: ProxyState::Stopped,
            settings,
            scope: prefs.scope,
            scope_file: String::new(),
            ca_export: String::new(),
            fingerprint: None,
            running_insecure: false,
            intercept: InterceptModel::default(),
        };
        if let Some(p) = path {
            app.open(ctx, &p);
        }
        Ok(app)
    }

    /// Open (creating or migrating if needed) the project database and start reading it.
    pub(crate) fn open(&mut self, ctx: &egui::Context, path: &Path) {
        let wake = {
            let ctx = ctx.clone();
            move || ctx.request_repaint()
        };
        // Opening read-write once creates and migrates; reading then goes through a read-only connection.
        let opened = (|| -> Result<DataHandle, data::OpenError> {
            Store::open(path)?;
            data::spawn(path, wake)
        })();
        match opened {
            Ok(h) => {
                self.data = Some(h);
                self.project = Some(path.to_path_buf());
                self.history = HistoryModel::new();
                self.detail = None;
                self.filter_input.clear();
                self.error = None;
            }
            Err(e) => self.error = Some(format!("cannot open {}: {e}", path.display())),
        }
    }

    /// Validate the forms and ask the backend to start the proxy.
    pub(crate) fn start_proxy(&mut self) {
        let Some(project) = self.project.clone() else {
            self.error = Some("Open or create a project first (top bar).".into());
            return;
        };
        let scope = match self.scope.compile() {
            Ok(s) => s,
            Err(_) => {
                self.error = Some("Fix the scope rules first (Scope page).".into());
                return;
            }
        };
        match self.settings.to_start(&project, scope) {
            Ok(cfg) => {
                self.running_insecure = cfg.insecure_upstream;
                self.error = None;
                self.proxy = ProxyState::Starting;
                self.backend.send(Cmd::Start(cfg));
            }
            Err(msg) => self.error = Some(msg),
        }
    }

    pub(crate) fn stop_proxy(&mut self) {
        self.proxy = ProxyState::Stopping;
        self.backend.send(Cmd::Stop);
    }

    /// Take in what the background runtime reports.
    fn pump_backend(&mut self) {
        for _ in 0..256 {
            let Some(ev) = self.backend.try_recv() else {
                break;
            };
            match ev {
                Event::Held(h) => self.intercept.on_held(h),
                Event::Resolved(id) => self.intercept.on_resolved(id),
                Event::Started { addr, fingerprint } => {
                    self.intercept.clear();
                    self.proxy = ProxyState::Running(addr);
                    self.fingerprint = Some(fingerprint);
                    self.error = None;
                }
                Event::Stopped => {
                    self.intercept.clear();
                    self.proxy = ProxyState::Stopped;
                    self.running_insecure = false;
                }
                Event::Logged => {
                    self.backend.ack_logged();
                    self.history.refresh();
                }
                Event::CaExported { path, fingerprint } => {
                    self.notice = Some(format!(
                        "CA certificate written to {} (SHA-256 {fingerprint})",
                        path.display()
                    ));
                }
                Event::Error(msg) => {
                    if self.proxy == ProxyState::Starting {
                        self.proxy = ProxyState::Stopped;
                        self.running_insecure = false;
                    }
                    self.error = Some(msg);
                }
            }
        }
    }

    /// Take in finished reads, forward new requests, and poll for new rows.
    fn pump(&mut self, ctx: &egui::Context) {
        let Some(d) = &self.data else { return };
        let mut others = Vec::new();
        for _ in 0..MAX_RESPONSES_PER_FRAME {
            let Some(r) = d.try_recv() else { break };
            if let Some(r) = self.history.apply(r) {
                others.push(r);
            }
        }
        if self.last_refresh.elapsed() >= REFRESH_EVERY {
            self.history.refresh();
            self.last_refresh = Instant::now();
        }
        ctx.request_repaint_after(REFRESH_EVERY);
        for req in self.history.drain_requests() {
            d.send(req);
        }
        for r in others {
            match r {
                Resp::Exchange {
                    id,
                    stored: Some(s),
                } if self.history.selected() == Some(id) => self.detail = Some(Detail::new(&s)),
                Resp::Failed(msg) => self.error = Some(msg),
                _ => {}
            }
        }
    }

    /// Advance the `--bench` script and close the window when it is done.
    fn drive_bench(&mut self, ctx: &egui::Context) {
        let Some(b) = self.bench.as_mut() else { return };
        ctx.request_repaint();
        if !b.started {
            // Select the newest row (the seeder makes it the 5 MB one) and wait until it is shown.
            let newest = self.history.row(0).map(|s| s.id);
            match (newest, self.history.selected(), self.detail.is_some()) {
                (Some(id), None, _) => self.history.select(id),
                (Some(_), Some(_), true) => b.started = true,
                _ => {}
            }
            return;
        }
        match b.bench.tick() {
            None => {
                println!(
                    "scrolled to history row {} of {}, viewer row {}",
                    self.deepest.0,
                    self.history.total(),
                    self.deepest.1
                );
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            Some((phase, p)) => {
                let spacing = ctx.global_style().spacing.item_spacing.y;
                if phase == 0 {
                    self.table_scroll =
                        Some((p * self.history.total() as f64) as f32 * (TABLE_ROW_H + spacing));
                } else if let Some(d) = self.detail.as_mut() {
                    d.hex = phase == 2;
                    d.tab = d.tabs.len().saturating_sub(1).min(1); // the 5 MB body is in the response
                    let rows = if d.hex {
                        d.tabs[d.tab].view.hex_rows()
                    } else {
                        d.tabs[d.tab].view.rows()
                    };
                    self.viewer_scroll = Some(
                        (p * rows as f64) as f32
                            * (ctx.global_style().text_styles[&egui::TextStyle::Monospace].size
                                + spacing
                                + 2.0),
                    );
                }
            }
        }
    }

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        egui::Panel::top("top").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label("Project");
                let idle = self.proxy == ProxyState::Stopped;
                let r = ui.add_enabled(
                    idle,
                    egui::TextEdit::singleline(&mut self.path_input)
                        .desired_width(360.0)
                        .hint_text("path/to/project.db"),
                );
                let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                let clicked = ui
                    .add_enabled(idle, egui::Button::new("Open / create"))
                    .clicked();
                if (clicked || enter) && !self.path_input.trim().is_empty() {
                    let p = PathBuf::from(self.path_input.trim());
                    self.open(&ctx, &p);
                }
                ui.separator();
                ui.label("Filter");
                if ui
                    .add(
                        egui::TextEdit::singleline(&mut self.filter_input)
                            .desired_width(220.0)
                            .hint_text("host, method, path or status"),
                    )
                    .changed()
                {
                    self.history.set_filter(&self.filter_input);
                    self.table_scroll = Some(0.0);
                }
                ui.separator();
                ui.label(format!("{} rows", self.history.total()));
            });
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.page, Page::History, "History");
                ui.selectable_value(&mut self.page, Page::Proxy, "Proxy");
                ui.selectable_value(&mut self.page, Page::Scope, "Scope");
                let held = self.intercept.entries().len();
                let label = if held > 0 {
                    format!("Intercept ({held})")
                } else {
                    "Intercept".to_string()
                };
                ui.selectable_value(&mut self.page, Page::Intercept, label);
            });
            if let Some(e) = &self.error {
                ui.colored_label(Color32::from_rgb(230, 100, 100), e);
            }
            if let Some(n) = &self.notice {
                ui.colored_label(Color32::from_rgb(110, 190, 130), n);
            }
        });
    }

    /// A red bar that stays visible whenever origin certificates are not being verified.
    fn insecure_banner(&self, ui: &mut egui::Ui) {
        if !(self.settings.insecure_upstream || self.running_insecure) {
            return;
        }
        let active = if self.running_insecure {
            " (active in the running proxy)"
        } else {
            " (takes effect when the proxy is started)"
        };
        egui::Panel::top("insecure-banner")
            .frame(egui::Frame::new().fill(Color32::from_rgb(150, 30, 30)).inner_margin(6))
            .show(ui, |ui| {
                ui.label(
                    RichText::new(format!("INSECURE: origin server certificates are NOT being verified{active}. Only use this for lab targets."))
                        .color(Color32::WHITE)
                        .strong(),
                );
            });
    }

    fn status_bar(&self, ui: &mut egui::Ui) {
        egui::Panel::bottom("status").show(ui, |ui| {
            ui.horizontal(|ui| {
                match self.proxy {
                    ProxyState::Stopped => ui.weak("Proxy stopped"),
                    ProxyState::Starting => ui.label("Proxy starting…"),
                    ProxyState::Running(a) => ui.colored_label(
                        Color32::from_rgb(90, 190, 110),
                        format!("Proxy listening on {a}"),
                    ),
                    ProxyState::Stopping => ui.label("Proxy stopping…"),
                };
                ui.separator();
                match &self.project {
                    Some(p) => ui.label(p.display().to_string()),
                    None => ui.weak("no project open"),
                };
                if self.scope.enabled {
                    ui.separator();
                    ui.label("scope on");
                }
                let held = self.intercept.entries().len();
                if held > 0 {
                    ui.separator();
                    ui.colored_label(Color32::from_rgb(235, 170, 70), format!("{held} held"));
                }
                if self.settings.allow_non_loopback {
                    ui.separator();
                    ui.colored_label(Color32::from_rgb(235, 170, 70), "network access allowed");
                }
            });
        });
    }

    fn history_table(&mut self, ui: &mut egui::Ui) {
        let total = self.history.total();
        let selected = self.history.selected();
        let mut clicked = None;
        let history = &mut self.history;
        let deepest = &mut self.deepest;
        let mut table = TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .sense(egui::Sense::click())
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::exact(64.0))
            .column(Column::exact(176.0))
            .column(Column::exact(64.0))
            .column(Column::initial(200.0).at_least(60.0))
            .column(Column::remainder().at_least(120.0))
            .column(Column::exact(56.0))
            .column(Column::exact(96.0))
            .min_scrolled_height(0.0);
        if let Some(o) = self.table_scroll.take() {
            table = table.vertical_scroll_offset(o);
        }
        table
            .header(20.0, |mut h| {
                for t in [
                    "#",
                    "Time (UTC)",
                    "Method",
                    "Host",
                    "Path",
                    "Status",
                    "Flags",
                ] {
                    h.col(|ui| {
                        ui.strong(t);
                    });
                }
            })
            .body(|body| {
                body.rows(TABLE_ROW_H, total, |mut row| {
                    let i = row.index();
                    deepest.0 = deepest.0.max(i);
                    let Some(s) = history.row(i) else {
                        row.col(|ui| {
                            ui.weak("…");
                        });
                        return;
                    };
                    row.set_selected(selected == Some(s.id));
                    row.col(|ui| {
                        ui.label(s.id.to_string());
                    });
                    row.col(|ui| {
                        ui.label(RichText::new(format_utc(s.ts_micros)).monospace());
                    });
                    row.col(|ui| {
                        ui.label(s.method.as_deref().unwrap_or("?"));
                    });
                    row.col(|ui| {
                        ui.add(egui::Label::new(format!("{}:{}", s.host, s.port)).truncate());
                    });
                    row.col(|ui| {
                        ui.add(egui::Label::new(s.path.as_deref().unwrap_or("?")).truncate());
                    });
                    row.col(|ui| match s.status {
                        Some(c) => {
                            ui.label(RichText::new(c.to_string()).color(status_color(c)));
                        }
                        None => {
                            ui.weak("-");
                        }
                    });
                    row.col(|ui| {
                        let mut f = Vec::new();
                        if s.tls {
                            f.push("tls");
                        }
                        if s.modified {
                            f.push("mod");
                        }
                        if s.dropped {
                            f.push("drop");
                        }
                        ui.weak(f.join(" "));
                    });
                    if row.response().clicked() {
                        clicked = Some(s.id);
                    }
                });
            });
        if let Some(id) = clicked {
            self.history.select(id);
        }
    }

    fn viewer(&mut self, ui: &mut egui::Ui) {
        let Some(d) = self.detail.as_mut() else {
            ui.weak("Select a row to see the raw request and response.");
            return;
        };
        ui.label(RichText::new(&d.title).strong());
        ui.horizontal(|ui| {
            let mut research = false;
            for (i, t) in d.tabs.iter().enumerate() {
                if ui.selectable_label(d.tab == i, t.name).clicked() && d.tab != i {
                    d.tab = i;
                    research = true;
                }
            }
            ui.separator();
            ui.selectable_value(&mut d.hex, false, "Text");
            ui.selectable_value(&mut d.hex, true, "Hex");
            ui.separator();
            if ui
                .add(
                    egui::TextEdit::singleline(&mut d.query)
                        .desired_width(180.0)
                        .hint_text("search"),
                )
                .changed()
            {
                research = true;
            }
            if ui.button("Next").clicked() && !d.hits.is_empty() {
                d.cur = (d.cur + 1) % d.hits.len();
                d.jump_to_hit();
            }
            if !d.query.is_empty() {
                ui.label(if d.hits.is_empty() {
                    "no matches".to_string()
                } else {
                    format!("{}/{}", d.cur + 1, d.hits.len())
                });
            }
            ui.weak(format!("{} bytes", d.tabs[d.tab].view.bytes().len()));
            if research {
                d.research();
            }
        });
        ui.separator();
        let view = &d.tabs[d.tab].view;
        let row_h = ui.text_style_height(&egui::TextStyle::Monospace);
        let step = row_h + ui.spacing().item_spacing.y;
        let rows = if d.hex { view.hex_rows() } else { view.rows() };
        let mut area = egui::ScrollArea::both()
            .id_salt("viewer")
            .auto_shrink(false);
        if let Some(o) = self
            .viewer_scroll
            .take()
            .or(d.jump.take().map(|r| r as f32 * step))
        {
            area = area.vertical_scroll_offset(o);
        }
        let deepest = &mut self.deepest;
        area.show_rows(ui, row_h, rows, |ui, range| {
            deepest.1 = deepest.1.max(range.end);
            for i in range {
                let t = if d.hex { view.hex_row(i) } else { view.row(i) };
                ui.add(egui::Label::new(RichText::new(t).monospace()).extend());
            }
        });
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.pump_backend();
        self.pump(&ctx);
        self.drive_bench(&ctx);
        self.insecure_banner(ui);
        self.top_bar(ui);
        self.status_bar(ui);
        if self.page == Page::History {
            egui::Panel::bottom("viewer")
                .resizable(true)
                .default_size(340.0)
                .show(ui, |ui| self.viewer(ui));
        }
        egui::CentralPanel::default().show(ui, |ui| match self.page {
            Page::History if self.data.is_some() => self.history_table(ui),
            Page::History => {
                ui.weak("Open a project database (or create a new one) to begin.");
            }
            Page::Proxy => self.proxy_page(ui),
            Page::Scope => self.scope_page(ui),
            Page::Intercept => self.intercept_page(ui),
        });
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        let prefs = Prefs {
            project: self.project.as_ref().map(|p| p.display().to_string()),
            listen: Some(self.settings.listen.clone()),
            ca_dir: self.settings.ca_dir.clone(),
            scope: self.scope.clone(),
        };
        eframe::set_value(storage, PREFS_KEY, &prefs);
    }
}

/// Bytes shown in the viewer for a message (kept here so tests can use it).
pub fn raw_view(bytes: Bytes) -> RawView {
    RawView::new(bytes)
}
