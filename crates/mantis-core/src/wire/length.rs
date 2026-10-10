//! An explicit "fix Content-Length" helper for hand-edited messages.
//!
//! Nothing in Mantis calls this implicitly: edits are sent exactly as written.
//! It exists for a frontend to offer as a deliberate action.

use super::{detect_framing, Framing, Kind};
use crate::view::RequestView;

/// Result of [`fix_content_length`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fix {
    /// The corrected message.
    Changed(Vec<u8>),
    /// `Content-Length` already matches (or there is no body and no header).
    Unchanged,
    /// The message was left alone, for this reason.
    Skipped(&'static str),
}

/// Make `Content-Length` equal the body length: replace the single header's
/// value, or add one before the blank line (in the message's own line-ending
/// style) when there is a body and no header. Chunked messages, several
/// `Content-Length` headers and unterminated heads are left alone.
pub fn fix_content_length(raw: &[u8]) -> Fix {
    let v = RequestView::parse(raw); // header and body split are the same for responses
    if !v.head_complete {
        return Fix::Skipped("no blank line ends the headers");
    }
    if detect_framing(&raw[..v.body.start], Kind::Request).0 == Framing::Chunked {
        return Fix::Skipped("the body is chunked");
    }
    let body_len = v.body.len().to_string();
    let mut cl = v
        .headers
        .iter()
        .filter(|h| raw[h.name.clone()].eq_ignore_ascii_case(b"content-length"));
    match (cl.next(), cl.next()) {
        (Some(_), Some(_)) => Fix::Skipped("there are several Content-Length headers"),
        (Some(h), None) => {
            if raw[h.value.clone()] == *body_len.as_bytes() {
                return Fix::Unchanged;
            }
            let mut out = raw[..h.value.start].to_vec();
            out.extend_from_slice(body_len.as_bytes());
            out.extend_from_slice(&raw[h.value.end..]);
            Fix::Changed(out)
        }
        (None, _) if v.body.is_empty() => Fix::Unchanged,
        (None, _) => {
            let head = &raw[..v.body.start];
            let eol: &[u8] = if head.ends_with(b"\r\n") {
                b"\r\n"
            } else {
                b"\n"
            };
            let at = head.len() - eol.len(); // start of the blank line
            let mut out = raw[..at].to_vec();
            out.extend_from_slice(b"Content-Length: ");
            out.extend_from_slice(body_len.as_bytes());
            out.extend_from_slice(eol);
            out.extend_from_slice(&raw[at..]);
            Fix::Changed(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn changed(raw: &[u8]) -> String {
        match fix_content_length(raw) {
            Fix::Changed(v) => String::from_utf8(v).unwrap(),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn replaces_a_wrong_value_and_keeps_everything_else() {
        assert_eq!(
            changed(b"POST / HTTP/1.1\r\nA: 1\r\nContent-Length: 99\r\nB: 2\r\n\r\nabc"),
            "POST / HTTP/1.1\r\nA: 1\r\nContent-Length: 3\r\nB: 2\r\n\r\nabc"
        );
        assert_eq!(
            changed(b"POST / HTTP/1.1\ncontent-length:  0 \n\nhello"),
            "POST / HTTP/1.1\ncontent-length:  5 \n\nhello"
        );
        assert_eq!(
            changed(b"POST / HTTP/1.1\r\nContent-Length: abc\r\n\r\nxy"),
            "POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\nxy"
        );
        assert_eq!(
            fix_content_length(b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc"),
            Fix::Unchanged
        );
    }

    #[test]
    fn adds_a_header_in_the_messages_own_line_ending_style() {
        assert_eq!(
            changed(b"POST / HTTP/1.1\r\nHost: x\r\n\r\nabc"),
            "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc"
        );
        assert_eq!(
            changed(b"POST / HTTP/1.1\nHost: x\n\nabc"),
            "POST / HTTP/1.1\nHost: x\nContent-Length: 3\n\nabc"
        );
        assert_eq!(
            changed(b"POST / HTTP/1.1\r\n\r\nabc"),
            "POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc"
        );
        assert_eq!(
            fix_content_length(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
            Fix::Unchanged,
            "no body, no header: nothing to do"
        );
    }

    #[test]
    fn leaves_ambiguous_or_unframed_messages_alone() {
        assert!(
            matches!(fix_content_length(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"), Fix::Skipped(m) if m.contains("chunked"))
        );
        assert!(
            matches!(fix_content_length(b"POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nabc"), Fix::Skipped(m) if m.contains("several"))
        );
        assert!(
            matches!(fix_content_length(b"POST / HTTP/1.1\r\nContent-Length: 1\r\n"), Fix::Skipped(m) if m.contains("blank line"))
        );
        assert!(matches!(fix_content_length(b""), Fix::Skipped(_)));
    }

    proptest! {
        #[test]
        fn never_panics_and_is_idempotent(raw in proptest::collection::vec(prop_oneof![Just(b'\r'), Just(b'\n'), Just(b':'), Just(b' '), any::<u8>()], 0..300)) {
            if let Fix::Changed(once) = fix_content_length(&raw) {
                prop_assert!(matches!(fix_content_length(&once), Fix::Unchanged | Fix::Skipped(_)));
            }
        }
    }
}
