//! The Proxy and Scope pages.

use std::path::PathBuf;

use eframe::egui::{self, Color32, RichText};

use crate::app::{App, ProxyState};
use crate::backend::Cmd;

const WARN: Color32 = Color32::from_rgb(235, 170, 70);
const BAD: Color32 = Color32::from_rgb(230, 100, 100);

impl App {
    pub(crate) fn proxy_page(&mut self, ui: &mut egui::Ui) {
        let state = self.proxy;
        let editable = state == ProxyState::Stopped;
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.heading("Proxy");
            egui::Grid::new("proxy-form").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
                ui.label("Listen address");
                ui.add_enabled(editable, egui::TextEdit::singleline(&mut self.settings.listen).desired_width(220.0));
                ui.end_row();
                ui.label("CA directory");
                ui.add_enabled(
                    editable,
                    egui::TextEdit::singleline(&mut self.settings.ca_dir).desired_width(360.0).hint_text("default: user data directory"),
                );
                ui.end_row();
            });
            ui.add_space(6.0);
            ui.add_enabled_ui(editable, |ui| {
                ui.checkbox(&mut self.settings.allow_non_loopback, "Allow network access (listen on a non-loopback address)");
                if self.settings.allow_non_loopback {
                    ui.colored_label(WARN, "Anyone who can reach the proxy can send traffic through this machine.");
                }
                ui.checkbox(&mut self.settings.insecure_upstream, "Skip origin certificate verification (insecure)");
                if self.settings.insecure_upstream {
                    ui.colored_label(BAD, "Origin certificates will not be checked. Use only for lab targets with self-signed certificates.");
                }
            });
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                match state {
                    ProxyState::Stopped => {
                        if ui.button("Start proxy").clicked() {
                            self.start_proxy();
                        }
                    }
                    ProxyState::Running(addr) => {
                        if ui.button("Stop proxy").clicked() {
                            self.stop_proxy();
                        }
                        ui.colored_label(Color32::from_rgb(90, 190, 110), format!("listening on {addr}"));
                    }
                    ProxyState::Starting => {
                        ui.label("starting…");
                    }
                    ProxyState::Stopping => {
                        ui.label("stopping…");
                    }
                }
                if self.project.is_none() {
                    ui.colored_label(WARN, "open a project first");
                }
            });

            ui.add_space(16.0);
            ui.heading("HTTPS interception");
            ui.label("Browsers must trust the Mantis CA before HTTPS sites load through the proxy. Export the certificate (never the key) and import it into the browser or OS trust store.");
            if let Some(fp) = &self.fingerprint {
                ui.label(RichText::new(format!("SHA-256 {fp}")).monospace());
            }
            ui.horizontal(|ui| {
                ui.label("Export to");
                ui.add(egui::TextEdit::singleline(&mut self.ca_export).desired_width(360.0).hint_text("path/to/mantis-ca.pem"));
                for (label, der) in [("Export PEM", false), ("Export DER", true)] {
                    if ui.button(label).clicked() && !self.ca_export.trim().is_empty() {
                        let ca_dir = Some(self.settings.ca_dir.trim()).filter(|d| !d.is_empty()).map(PathBuf::from);
                        self.notice = None;
                        self.backend.send(Cmd::ExportCa { ca_dir, out: PathBuf::from(self.ca_export.trim()), der });
                    }
                }
            });
            ui.weak("The export refuses to overwrite an existing file.");
        });
    }

    pub(crate) fn scope_page(&mut self, ui: &mut egui::Ui) {
        let errors = self.scope.row_errors();
        let running = matches!(self.proxy, ProxyState::Running(_));
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.heading("Scope");
            ui.checkbox(&mut self.scope.enabled, "Only log, intercept and rewrite in-scope traffic");
            if !self.scope.enabled {
                ui.weak("Off: everything the proxy sees is in scope.");
            } else if self.scope.rows.is_empty() {
                ui.colored_label(WARN, "Scope is on but has no rules, so nothing is in scope. Traffic is still forwarded.");
            }
            ui.add_space(6.0);
            let mut remove = None;
            egui::Grid::new("scope-rules").num_columns(5).spacing([8.0, 6.0]).striped(true).show(ui, |ui| {
                for h in ["", "Host", "Ports", "Path regex (whole path)", ""] {
                    ui.strong(h);
                }
                ui.end_row();
                for (i, row) in self.scope.rows.iter_mut().enumerate() {
                    egui::ComboBox::from_id_salt(("action", i)).width(80.0).selected_text(if row.include { "Include" } else { "Exclude" }).show_ui(ui, |ui| {
                        ui.selectable_value(&mut row.include, true, "Include");
                        ui.selectable_value(&mut row.include, false, "Exclude");
                    });
                    ui.add(egui::TextEdit::singleline(&mut row.host).desired_width(200.0).hint_text("example.com or *.example.com"));
                    ui.add(egui::TextEdit::singleline(&mut row.ports).desired_width(110.0).hint_text("443, 8000-8100"));
                    ui.add(egui::TextEdit::singleline(&mut row.path).desired_width(220.0).hint_text("/api/.*"));
                    ui.horizontal(|ui| {
                        if ui.button("Remove").clicked() {
                            remove = Some(i);
                        }
                        if let Some(Some(e)) = errors.get(i) {
                            ui.colored_label(BAD, e);
                        }
                    });
                    ui.end_row();
                }
            });
            if let Some(i) = remove {
                self.scope.rows.remove(i);
            }
            ui.add_space(6.0);
            if ui.button("Add rule").clicked() {
                self.scope.rows.push(Default::default());
            }
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                let apply = ui.add_enabled(running, egui::Button::new("Apply to running proxy"));
                if apply.clicked() {
                    match self.scope.compile() {
                        Ok(scope) => {
                            self.backend.send(Cmd::SetScope(scope));
                            self.error = None;
                            self.notice = Some("Scope applied.".into());
                        }
                        Err(_) => self.error = Some("Fix the highlighted rules first.".into()),
                    }
                }
                ui.weak(if running { "In-flight exchanges keep the verdict they started with." } else { "Start the proxy to apply; the current rules are used at start." });
            });
            ui.add_space(14.0);
            ui.heading("File");
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.scope_file).desired_width(360.0).hint_text("path/to/scope.toml"));
                if ui.button("Load").clicked() && !self.scope_file.trim().is_empty() {
                    match std::fs::read_to_string(self.scope_file.trim()).map_err(|e| e.to_string()).and_then(|t| self.scope.load_toml(&t)) {
                        Ok(()) => {
                            self.error = None;
                            self.notice = Some("Scope loaded; review it, then apply.".into());
                        }
                        Err(e) => self.error = Some(format!("cannot load scope: {e}")),
                    }
                }
                if ui.button("Save").clicked() && !self.scope_file.trim().is_empty() {
                    let result = self.scope.to_toml().and_then(|t| std::fs::write(self.scope_file.trim(), t).map_err(|e| e.to_string()));
                    match result {
                        Ok(()) => {
                            self.error = None;
                            self.notice = Some(format!("Saved {}", self.scope_file.trim()));
                        }
                        Err(e) => self.error = Some(format!("cannot save scope: {e}")),
                    }
                }
            });
            ui.weak("Same format as `mantis-cli proxy --scope`.");
        });
    }
}
