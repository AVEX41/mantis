//! Message model, raw wire I/O, storage, scope and events.
//!
//! Messages are stored as raw bytes; parsed views are derived and never
//! replace the raw form.

pub mod message;
pub mod scope;
pub mod store;
pub mod view;
pub mod wire;

pub use message::{now_micros, Exchange, Source, Stored, StoredWsFrame, Summary, WsDir, WsFrame};
pub use scope::{Action, RuleSpec, RunOverride, Scope, ScopeError, Target, Verdict};
pub use store::{Store, StoreError};
pub use view::{Header, RequestView, ResponseView};
