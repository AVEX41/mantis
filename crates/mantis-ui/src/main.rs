//! Mantis desktop UI.
//!
//! Usage: `mantis-ui [PROJECT.db] [--bench]`

use std::path::PathBuf;

use eframe::egui;
use mantis_ui::app::App;

fn main() -> eframe::Result {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let bench = args.iter().any(|a| a == "--bench");
    let path = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .map(PathBuf::from);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 800.0])
            .with_title("Mantis"),
        ..Default::default()
    };
    eframe::run_native(
        "Mantis",
        options,
        Box::new(move |cc| Ok(Box::new(App::new(&cc.egui_ctx, path.clone(), bench)))),
    )
}
