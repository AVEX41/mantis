//! Raw HTTP/1.1 reader and writer.
//!
//! The reader returns each message exactly as it appeared on the wire: it
//! decides where a message ends but never rewrites, reorders or normalises
//! anything. The writer puts caller-supplied bytes on the stream verbatim.
//! Neither goes through `hyper`.

mod read;
mod write;

#[cfg(test)]
mod tests;

pub use read::{detect_framing, Framing, Kind, Limits, Message, Reader};
pub use write::write_raw;

/// Errors from the wire reader.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    /// The underlying stream failed.
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    /// The stream ended in the middle of a message.
    #[error("stream ended mid-message")]
    Truncated,
    /// The head (start line and headers) exceeded the limit.
    #[error("message head larger than {limit} bytes")]
    HeadTooLarge {
        /// The configured limit.
        limit: usize,
    },
    /// The body exceeded the limit.
    #[error("message body larger than {limit} bytes")]
    BodyTooLarge {
        /// The configured limit.
        limit: usize,
    },
    /// Chunked framing could not be followed.
    #[error("bad chunked framing: {0}")]
    BadChunk(&'static str),
}
