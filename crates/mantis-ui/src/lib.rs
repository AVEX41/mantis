//! Mantis desktop UI: testable models plus a thin egui view layer.
//!
//! Everything that can be decided without drawing lives in the models
//! (`history`, `viewer`, `data`) so it is covered by ordinary tests.

pub mod app;
pub mod backend;
pub mod bench;
pub mod data;
pub mod history;
mod pages;
pub mod scope_editor;
pub mod settings;
pub mod timefmt;
pub mod viewer;
