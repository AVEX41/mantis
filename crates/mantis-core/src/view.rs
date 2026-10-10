//! Derived, lossless views over raw HTTP/1.x messages.
//!
//! A view holds only byte ranges into the raw buffer. Parsing never fails and
//! never normalises: duplicate headers, bare LF, obs-fold and garbage all
//! produce a best-effort view. The full reader/writer lives in `wire`.

use std::ops::Range;

/// One header line. Ranges index into the raw message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Bytes before the first `:` (the whole line if there is no colon).
    pub name: Range<usize>,
    /// Bytes after the colon, with surrounding spaces/tabs trimmed. Spans
    /// continuation lines when the value is obs-folded.
    pub value: Range<usize>,
    /// The line had no colon.
    pub malformed: bool,
    /// The value continues over one or more obs-fold lines.
    pub folded: bool,
}

#[derive(Debug)]
struct Head {
    start_line: Range<usize>,
    headers: Vec<Header>,
    body: Range<usize>,
    head_complete: bool,
}

/// Tolerant view of a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestView {
    /// The first line without its terminator.
    pub start_line: Range<usize>,
    /// Bytes before the first space of the start line.
    pub method: Option<Range<usize>>,
    /// Bytes between the first and last space (needs two spaces).
    pub target: Option<Range<usize>>,
    /// Bytes after the last space (needs two spaces).
    pub version: Option<Range<usize>>,
    /// Header lines in wire order, duplicates preserved.
    pub headers: Vec<Header>,
    /// Everything after the blank line (empty if the head never ended).
    pub body: Range<usize>,
    /// A blank line terminating the head was found.
    pub head_complete: bool,
}

/// Tolerant view of a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseView {
    /// The first line without its terminator.
    pub start_line: Range<usize>,
    /// Bytes before the first space.
    pub version: Option<Range<usize>>,
    /// Status code if the second token is exactly three ASCII digits.
    pub status: Option<u16>,
    /// Bytes after the status token.
    pub reason: Option<Range<usize>>,
    /// Header lines in wire order, duplicates preserved.
    pub headers: Vec<Header>,
    /// Everything after the blank line (empty if the head never ended).
    pub body: Range<usize>,
    /// A blank line terminating the head was found.
    pub head_complete: bool,
}

fn parse_head(raw: &[u8]) -> Head {
    let mut pos = 0;
    let mut start_line = 0..0;
    let mut headers: Vec<Header> = Vec::new();
    let mut first = true;
    while pos < raw.len() {
        let nl = raw[pos..].iter().position(|&b| b == b'\n');
        let next = nl.map_or(raw.len(), |i| pos + i + 1);
        let mut end = nl.map_or(raw.len(), |i| pos + i);
        if end > pos && raw[end - 1] == b'\r' {
            end -= 1;
        }
        let line = pos..end;
        if first {
            start_line = line;
            first = false;
        } else if line.is_empty() {
            return Head {
                start_line,
                headers,
                body: next..raw.len(),
                head_complete: true,
            };
        } else if matches!(raw[line.start], b' ' | b'\t') && !headers.is_empty() {
            if let Some(h) = headers.last_mut() {
                h.value.end = trim_end(raw, line.start, line.end);
                h.folded = true;
            }
        } else {
            headers.push(parse_header(raw, line));
        }
        pos = next;
    }
    Head {
        start_line,
        headers,
        body: raw.len()..raw.len(),
        head_complete: false,
    }
}

fn trim_end(raw: &[u8], start: usize, mut end: usize) -> usize {
    while end > start && matches!(raw[end - 1], b' ' | b'\t') {
        end -= 1;
    }
    end
}

fn parse_header(raw: &[u8], line: Range<usize>) -> Header {
    match raw[line.clone()].iter().position(|&b| b == b':') {
        None => Header {
            name: line.clone(),
            value: line.end..line.end,
            malformed: true,
            folded: false,
        },
        Some(i) => {
            let colon = line.start + i;
            let mut vs = colon + 1;
            while vs < line.end && matches!(raw[vs], b' ' | b'\t') {
                vs += 1;
            }
            let ve = trim_end(raw, vs, line.end);
            Header {
                name: line.start..colon,
                value: vs..ve,
                malformed: false,
                folded: false,
            }
        }
    }
}

impl RequestView {
    /// Build a view of `raw`. Never fails.
    pub fn parse(raw: &[u8]) -> Self {
        let h = parse_head(raw);
        let line = &raw[h.start_line.clone()];
        let s = h.start_line.start;
        let first = line.iter().position(|&b| b == b' ');
        let last = line.iter().rposition(|&b| b == b' ');
        let (method, target, version) = match (first, last) {
            (None, _) => (
                Some(h.start_line.clone()).filter(|r| !r.is_empty()),
                None,
                None,
            ),
            (Some(f), Some(l)) if f != l => (
                Some(s..s + f),
                Some(s + f + 1..s + l),
                Some(s + l + 1..h.start_line.end),
            ),
            (Some(f), _) => (Some(s..s + f), Some(s + f + 1..h.start_line.end), None),
        };
        RequestView {
            start_line: h.start_line,
            method,
            target,
            version,
            headers: h.headers,
            body: h.body,
            head_complete: h.head_complete,
        }
    }
}

impl ResponseView {
    /// Build a view of `raw`. Never fails.
    pub fn parse(raw: &[u8]) -> Self {
        let h = parse_head(raw);
        let line = &raw[h.start_line.clone()];
        let s = h.start_line.start;
        let (mut version, mut status, mut reason) = (None, None, None);
        if let Some(f) = line.iter().position(|&b| b == b' ') {
            version = Some(s..s + f);
            let rest = &line[f + 1..];
            let tok = rest.iter().position(|&b| b == b' ').unwrap_or(rest.len());
            if tok == 3 && rest[..3].iter().all(u8::is_ascii_digit) {
                status = Some(
                    rest[..3]
                        .iter()
                        .fold(0u16, |a, &d| a * 10 + u16::from(d - b'0')),
                );
            }
            if tok < rest.len() {
                reason = Some(s + f + 1 + tok + 1..h.start_line.end);
            }
        } else if !line.is_empty() {
            version = Some(h.start_line.clone());
        }
        ResponseView {
            start_line: h.start_line,
            version,
            status,
            reason,
            headers: h.headers,
            body: h.body,
            head_complete: h.head_complete,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s<'a>(raw: &'a [u8], r: &Option<Range<usize>>) -> Option<&'a [u8]> {
        r.as_ref().map(|r| &raw[r.clone()])
    }

    #[test]
    fn request_basic() {
        let raw = b"GET /a?b=1 HTTP/1.1\r\nHost: x\r\nX:  y \t\r\n\r\nbody";
        let v = RequestView::parse(raw);
        assert_eq!(s(raw, &v.method), Some(&b"GET"[..]));
        assert_eq!(s(raw, &v.target), Some(&b"/a?b=1"[..]));
        assert_eq!(s(raw, &v.version), Some(&b"HTTP/1.1"[..]));
        assert_eq!(&raw[v.headers[1].value.clone()], b"y");
        assert_eq!(&raw[v.body.clone()], b"body");
        assert!(v.head_complete);
    }

    #[test]
    fn duplicates_bare_lf_fold_and_malformed() {
        let raw = b"POST / HTTP/1.1\nA: 1\nA: 2\nB: x\n  y\nnocolon\n\n";
        let v = RequestView::parse(raw);
        assert_eq!(v.headers.len(), 4);
        assert_eq!(&raw[v.headers[0].value.clone()], b"1");
        assert_eq!(&raw[v.headers[1].value.clone()], b"2");
        assert!(v.headers[2].folded);
        assert_eq!(&raw[v.headers[2].value.clone()], b"x\n  y");
        assert!(v.headers[3].malformed);
        assert!(v.body.is_empty() && v.head_complete);
    }

    #[test]
    fn truncated_and_garbage() {
        let raw = b"GET /";
        let v = RequestView::parse(raw);
        assert_eq!(s(raw, &v.method), Some(&b"GET"[..]));
        assert!(v.version.is_none() && !v.head_complete);
        let g = RequestView::parse(&[0xff, 0, b'\r']);
        assert!(g.headers.is_empty());
        assert!(RequestView::parse(b"").method.is_none());
    }

    #[test]
    fn response_basic() {
        let raw = b"HTTP/1.1 404 Not Found\r\nA: b\r\n\r\nxyz";
        let v = ResponseView::parse(raw);
        assert_eq!(v.status, Some(404));
        assert_eq!(s(raw, &v.reason), Some(&b"Not Found"[..]));
        assert_eq!(&raw[v.body.clone()], b"xyz");
        assert_eq!(ResponseView::parse(b"HTTP/1.1 2000 x\r\n").status, None);
        assert_eq!(ResponseView::parse(b"HTTP/1.1 200").status, Some(200));
    }
}
