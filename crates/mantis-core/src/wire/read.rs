use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};

use super::WireError;
use crate::view::{Header, RequestView, ResponseView};

/// Size limits for [`Reader`].
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Maximum bytes in the start line plus headers.
    pub max_head: usize,
    /// Maximum bytes in the body (including chunk framing and trailers).
    pub max_body: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_head: 64 * 1024,
            max_body: 128 * 1024 * 1024,
        }
    }
}

/// How the end of a message was determined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// No body.
    None,
    /// Body of exactly this many bytes.
    ContentLength(u64),
    /// Chunked; the raw bytes include chunk framing and trailers.
    Chunked,
    /// Body runs until the peer closes the stream.
    UntilEof,
    /// Only the head belongs to HTTP; the rest of the stream is a tunnel or
    /// upgraded protocol (101, or 2xx to CONNECT). Leftover bytes stay
    /// available through [`Reader::into_parts`].
    HeadOnly,
}

/// What kind of message to read.
#[derive(Debug, Clone, Copy)]
pub enum Kind<'a> {
    /// A request.
    Request,
    /// A response to a request with this method (if known).
    Response {
        /// Method of the request this answers; `HEAD` and `CONNECT` change framing.
        request_method: Option<&'a [u8]>,
    },
}

/// One message read from the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// The message exactly as received.
    pub raw: Bytes,
    /// How its end was found.
    pub framing: Framing,
    /// The headers disagreed about framing (both `Transfer-Encoding` and
    /// `Content-Length`, conflicting or invalid `Content-Length`, or an
    /// unsupported transfer coding). A fixed precedence was applied: chunked,
    /// then the first valid `Content-Length`.
    pub ambiguous: bool,
}

/// Reads successive messages from a stream, keeping unread bytes for the next.
pub struct Reader<R> {
    inner: R,
    buf: BytesMut,
    limits: Limits,
}

enum Chunk {
    Size,
    Data(usize),
    Trailers,
}

impl<R: AsyncRead + Unpin> Reader<R> {
    /// Wrap `inner`.
    pub fn new(inner: R, limits: Limits) -> Self {
        Reader {
            inner,
            buf: BytesMut::new(),
            limits,
        }
    }

    /// Number of bytes read from the stream but not yet consumed.
    pub fn buffered_len(&self) -> usize {
        self.buf.len()
    }

    /// Read more from the stream into the buffer without consuming a message
    /// (cancel-safe). Returns 0 at end of stream.
    pub async fn fill_more(&mut self) -> std::io::Result<usize> {
        self.fill().await
    }

    /// Take the bytes read from the stream but not yet consumed by a message.
    pub fn take_buffered(&mut self) -> BytesMut {
        self.buf.split()
    }

    /// Mutable access to the underlying stream (bypasses the buffer).
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Give back the stream and any bytes read but not consumed.
    pub fn into_parts(self) -> (R, BytesMut) {
        (self.inner, self.buf)
    }

    /// Read one request. `Ok(None)` means the stream ended cleanly between messages.
    pub async fn read_request(&mut self) -> Result<Option<Message>, WireError> {
        self.read_message(Kind::Request).await
    }

    /// Read one response. `Ok(None)` means the stream ended cleanly between messages.
    pub async fn read_response(
        &mut self,
        request_method: Option<&[u8]>,
    ) -> Result<Option<Message>, WireError> {
        self.read_message(Kind::Response { request_method }).await
    }

    async fn read_message(&mut self, kind: Kind<'_>) -> Result<Option<Message>, WireError> {
        let Some(head_end) = self.read_head().await? else {
            return Ok(None);
        };
        let (framing, ambiguous) = detect_framing(&self.buf[..head_end], kind);
        let max_body = self.limits.max_body;
        let total = match framing {
            Framing::None | Framing::HeadOnly => head_end,
            Framing::ContentLength(n) => {
                let n = usize::try_from(n)
                    .ok()
                    .filter(|&n| n <= max_body)
                    .ok_or(WireError::BodyTooLarge { limit: max_body })?;
                while self.buf.len() < head_end + n {
                    if self.fill().await? == 0 {
                        return Err(WireError::Truncated);
                    }
                }
                head_end + n
            }
            Framing::Chunked => self.read_chunked(head_end).await?,
            Framing::UntilEof => {
                loop {
                    if self.buf.len() - head_end > max_body {
                        return Err(WireError::BodyTooLarge { limit: max_body });
                    }
                    if self.fill().await? == 0 {
                        break;
                    }
                }
                self.buf.len()
            }
        };
        Ok(Some(Message {
            raw: self.buf.split_to(total).freeze(),
            framing,
            ambiguous,
        }))
    }

    async fn fill(&mut self) -> std::io::Result<usize> {
        self.buf.reserve(16 * 1024);
        self.inner.read_buf(&mut self.buf).await
    }

    /// Find the end of the head (same rule as the views: the first line is the
    /// start line, the next empty line ends the head). `None` = clean EOF.
    async fn read_head(&mut self) -> Result<Option<usize>, WireError> {
        let limit = self.limits.max_head;
        let (mut pos, mut first) = (0, true);
        loop {
            match find_line(&self.buf, pos) {
                Some((content_end, next)) => {
                    if next > limit {
                        return Err(WireError::HeadTooLarge { limit });
                    }
                    if !first && content_end == pos {
                        return Ok(Some(next));
                    }
                    first = false;
                    pos = next;
                }
                None => {
                    if self.buf.len() > limit {
                        return Err(WireError::HeadTooLarge { limit });
                    }
                    if self.fill().await? == 0 {
                        return if self.buf.is_empty() {
                            Ok(None)
                        } else {
                            Err(WireError::Truncated)
                        };
                    }
                }
            }
        }
    }

    /// Walk chunked framing from `head_end`; return the offset just past the trailers.
    async fn read_chunked(&mut self, head_end: usize) -> Result<usize, WireError> {
        let (max_body, max_head) = (self.limits.max_body, self.limits.max_head);
        let (mut pos, mut st, mut data_total) = (head_end, Chunk::Size, 0usize);
        loop {
            if pos - head_end > max_body {
                return Err(WireError::BodyTooLarge { limit: max_body });
            }
            let need_more = match st {
                Chunk::Size | Chunk::Trailers => match find_line(&self.buf, pos) {
                    Some((content_end, next)) => {
                        if matches!(st, Chunk::Trailers) {
                            if content_end == pos {
                                return Ok(next);
                            }
                        } else {
                            let line = &self.buf[pos..content_end];
                            let digits = line.iter().take_while(|b| b.is_ascii_hexdigit()).count();
                            if digits == 0 || digits > 16 {
                                return Err(WireError::BadChunk("chunk size"));
                            }
                            let hex = std::str::from_utf8(&line[..digits])
                                .map_err(|_| WireError::BadChunk("chunk size"))?;
                            let n = u64::from_str_radix(hex, 16)
                                .map_err(|_| WireError::BadChunk("chunk size"))?;
                            let n = usize::try_from(n)
                                .map_err(|_| WireError::BodyTooLarge { limit: max_body })?;
                            data_total = data_total
                                .checked_add(n)
                                .filter(|&t| t <= max_body)
                                .ok_or(WireError::BodyTooLarge { limit: max_body })?;
                            st = if n == 0 {
                                Chunk::Trailers
                            } else {
                                Chunk::Data(n)
                            };
                        }
                        pos = next;
                        false
                    }
                    None => {
                        if self.buf.len() - pos > max_head {
                            return Err(WireError::HeadTooLarge { limit: max_head });
                        }
                        true
                    }
                },
                Chunk::Data(n) => {
                    let t = pos + n;
                    match (self.buf.get(t), self.buf.get(t + 1)) {
                        (Some(b'\n'), _) => {
                            pos = t + 1;
                            st = Chunk::Size;
                            false
                        }
                        (Some(b'\r'), Some(b'\n')) => {
                            pos = t + 2;
                            st = Chunk::Size;
                            false
                        }
                        (Some(b'\r'), None) | (None, _) => true,
                        _ => return Err(WireError::BadChunk("chunk terminator")),
                    }
                }
            };
            if need_more && self.fill().await? == 0 {
                return Err(WireError::Truncated);
            }
        }
    }
}

/// Line starting at `pos`: (end of content excluding `\r`, start of next line).
fn find_line(buf: &[u8], pos: usize) -> Option<(usize, usize)> {
    let nl = pos + buf.get(pos..)?.iter().position(|&b| b == b'\n')?;
    let end = if nl > pos && buf[nl - 1] == b'\r' {
        nl - 1
    } else {
        nl
    };
    Some((end, nl + 1))
}

fn named(raw: &[u8], h: &Header, name: &[u8]) -> bool {
    raw[h.name.clone()].eq_ignore_ascii_case(name)
}

fn parse_len(v: &[u8]) -> Option<u64> {
    if v.is_empty() || !v.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(v).ok()?.parse().ok()
}

/// Decide how a message with this head ends. Returns (framing, ambiguous).
/// `head` may extend past the blank line; only the headers are read.
pub fn detect_framing(head: &[u8], kind: Kind<'_>) -> (Framing, bool) {
    let (headers, status) = match kind {
        Kind::Request => (RequestView::parse(head).headers, None),
        Kind::Response { .. } => {
            let v = ResponseView::parse(head);
            (v.headers, v.status)
        }
    };
    if let Kind::Response { request_method } = kind {
        match (request_method, status) {
            (_, Some(101)) | (Some(b"CONNECT"), Some(200..=299)) => {
                return (Framing::HeadOnly, false)
            }
            (Some(b"HEAD"), _) | (_, Some(100..=199 | 204 | 304)) => return (Framing::None, false),
            _ => {}
        }
    }
    let mut ambiguous = false;
    let te: Vec<&Header> = headers
        .iter()
        .filter(|h| named(head, h, b"transfer-encoding"))
        .collect();
    let chunked = te.last().is_some_and(|h| {
        head[h.value.clone()]
            .rsplit(|&b| b == b',')
            .next()
            .is_some_and(|t| t.trim_ascii().eq_ignore_ascii_case(b"chunked"))
    });
    ambiguous |= !te.is_empty() && !chunked;
    let (mut first_cl, mut saw_cl) = (None, false);
    for h in headers.iter().filter(|h| named(head, h, b"content-length")) {
        saw_cl = true;
        match (parse_len(&head[h.value.clone()]), first_cl) {
            (None, _) => ambiguous = true,
            (Some(n), None) => first_cl = Some(n),
            (Some(n), Some(f)) => ambiguous |= n != f,
        }
    }
    if chunked {
        return (Framing::Chunked, ambiguous | saw_cl);
    }
    match (first_cl, kind) {
        (Some(n), _) => (Framing::ContentLength(n), ambiguous),
        (None, Kind::Request) => (Framing::None, ambiguous),
        (None, Kind::Response { .. }) => (Framing::UntilEof, ambiguous),
    }
}
