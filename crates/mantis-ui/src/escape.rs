//! Lossless text form of raw bytes for the message editor.
//!
//! Line feeds are real line breaks; CR, tab and backslash are `\r`, `\t`, `\\`;
//! every other control byte, every byte that is not valid UTF-8, and
//! characters that can hide or reorder text (zero-width, bidi overrides) are
//! `\xNN` per byte. Any byte string survives `unescape(escape(b))` unchanged.

/// A malformed escape in edited text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("bad escape at character {offset}: {reason}")]
pub struct EscapeError {
    /// Character offset in the text.
    pub offset: usize,
    /// What is wrong.
    pub reason: &'static str,
}

/// Characters that are valid UTF-8 but invisible or direction-changing.
fn hidden(c: char) -> bool {
    matches!(c, '\u{00ad}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{2069}' | '\u{feff}')
}

fn push_hex(out: &mut String, b: u8) {
    out.push_str(&format!("\\x{b:02x}"));
}

fn push_valid(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push('\n'),
            c if c.is_control() || hidden(c) => {
                let mut buf = [0u8; 4];
                c.encode_utf8(&mut buf)
                    .bytes()
                    .for_each(|b| push_hex(out, b));
            }
            c => out.push(c),
        }
    }
}

/// Bytes to editable text.
pub fn escape(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    let mut rest = bytes;
    loop {
        match std::str::from_utf8(rest) {
            Ok(s) => {
                push_valid(&mut out, s);
                return out;
            }
            Err(e) => {
                let (valid, after) = rest.split_at(e.valid_up_to());
                if let Ok(s) = std::str::from_utf8(valid) {
                    push_valid(&mut out, s);
                }
                let bad = e.error_len().unwrap_or(after.len());
                after[..bad].iter().for_each(|&b| push_hex(&mut out, b));
                rest = &after[bad..];
            }
        }
    }
}

/// Edited text back to bytes. Unknown escapes are errors, so a stray backslash is never silently changed.
pub fn unescape(text: &str) -> Result<Vec<u8>, EscapeError> {
    let mut out = Vec::with_capacity(text.len());
    let mut chars = text.chars().enumerate();
    while let Some((i, c)) = chars.next() {
        if c != '\\' {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            continue;
        }
        let err = |reason| EscapeError { offset: i, reason };
        match chars.next().map(|(_, c)| c) {
            Some('\\') => out.push(b'\\'),
            Some('r') => out.push(b'\r'),
            Some('n') => out.push(b'\n'),
            Some('t') => out.push(b'\t'),
            Some('x') => {
                let hi = chars.next().and_then(|(_, c)| c.to_digit(16));
                let lo = chars.next().and_then(|(_, c)| c.to_digit(16));
                match (hi, lo) {
                    (Some(h), Some(l)) => out.push((h * 16 + l) as u8),
                    _ => return Err(err("\\x needs two hex digits")),
                }
            }
            Some(_) => return Err(err("unknown escape (use \\\\ for a backslash)")),
            None => return Err(err("text ends with a lone backslash")),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn http_messages_read_naturally_and_keep_their_exact_line_endings() {
        let raw =
            b"POST /a HTTP/1.1\r\nHost: x\nX: tab\there\r\n\r\n\xff\x00 caf\xc3\xa9 back\\slash";
        let text = escape(raw);
        assert_eq!(
            text,
            "POST /a HTTP/1.1\\r\nHost: x\nX: tab\\there\\r\n\\r\n\\xff\\x00 café back\\\\slash"
        );
        assert_eq!(unescape(&text).unwrap(), raw);
    }

    #[test]
    fn hidden_and_direction_changing_characters_are_made_visible() {
        let raw = "a\u{202e}b\u{200b}c\u{feff}\u{85}".as_bytes();
        let text = escape(raw);
        assert!(
            text.chars()
                .all(|c| !hidden(c) && !c.is_control() || c == '\n'),
            "{text:?}"
        );
        assert!(text.contains("\\xe2\\x80\\xae"));
        assert_eq!(unescape(&text).unwrap(), raw);
    }

    #[test]
    fn typed_escapes_are_accepted_and_bad_ones_rejected_with_a_position() {
        assert_eq!(
            unescape("a\\nb\\tc\\r\\x41\\x4a\\\\").unwrap(),
            b"a\nb\tc\rAJ\\"
        );
        assert_eq!(unescape("real\r\nnewline").unwrap(), b"real\r\nnewline");
        for (bad, at) in [
            ("ab\\q", 2),
            ("\\x4", 0),
            ("\\xzz", 0),
            ("x\\", 1),
            ("\\x", 0),
        ] {
            let e = unescape(bad).unwrap_err();
            assert_eq!(e.offset, at, "{bad:?}: {e}");
        }
    }

    #[test]
    fn truncated_utf8_sequences_become_byte_escapes() {
        assert_eq!(escape(b"ok\xe2\x82"), "ok\\xe2\\x82");
        assert_eq!(escape(b"\xc3"), "\\xc3");
        assert_eq!(escape(b""), "");
    }

    proptest! {
        #[test]
        fn any_bytes_round_trip(raw in proptest::collection::vec(any::<u8>(), 0..3000)) {
            let text = escape(&raw);
            prop_assert!(text.chars().all(|c| c == '\n' || !c.is_control()), "control character leaked: {text:?}");
            prop_assert_eq!(unescape(&text).unwrap(), raw);
        }

        #[test]
        fn any_text_either_decodes_or_reports_an_error(text in ".{0,200}") {
            let _ = unescape(&text);
        }
    }
}
