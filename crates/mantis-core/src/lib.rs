//! Message model, raw wire I/O, storage, scope and events.
//!
//! Messages are stored as raw bytes; parsed views are derived and never
//! replace the raw form.

pub mod message;
pub mod store;
pub mod view;
pub mod wire;

pub use message::{now_micros, Exchange, Source, Stored, Summary};
pub use store::{Store, StoreError};
pub use view::{Header, RequestView, ResponseView};
