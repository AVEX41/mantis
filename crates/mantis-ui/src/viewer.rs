//! Text and hex views over a raw message, plus search. Display only: the
//! bytes themselves are never changed.

use bytes::Bytes;

/// Longest text row in bytes; longer lines continue on the next row so a
/// 5 MB single-line body stays viewable.
const WRAP: usize = 240;

/// A raw message prepared for virtualised display.
pub struct RawView {
    bytes: Bytes,
    /// Start offset of each text row.
    starts: Vec<usize>,
}

impl RawView {
    /// Index `bytes` into display rows (split at `\n` and every [`WRAP`] bytes).
    pub fn new(bytes: Bytes) -> Self {
        let mut starts = vec![0];
        let mut row_start = 0;
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'\n' {
                i += 1;
                row_start = i;
                starts.push(i);
            } else if i - row_start >= WRAP {
                // Don't cut a UTF-8 sequence in half when the next byte is a continuation.
                let mut cut = i;
                while cut < bytes.len() && cut - i < 3 && bytes[cut] & 0xC0 == 0x80 {
                    cut += 1;
                }
                row_start = cut;
                starts.push(cut);
                i = cut;
            } else {
                i += 1;
            }
        }
        if starts.len() > 1 && starts.last() == Some(&bytes.len()) {
            starts.pop(); // no empty row after a trailing newline
        }
        RawView { bytes, starts }
    }

    /// The underlying bytes.
    pub fn bytes(&self) -> &Bytes {
        &self.bytes
    }

    /// Number of text rows.
    pub fn rows(&self) -> usize {
        self.starts.len()
    }

    /// Text row `i`: control characters shown as escapes, invalid UTF-8 as U+FFFD.
    pub fn row(&self, i: usize) -> String {
        let a = self.starts[i];
        let b = self.starts.get(i + 1).copied().unwrap_or(self.bytes.len());
        let mut out = String::new();
        for c in String::from_utf8_lossy(&self.bytes[a..b]).chars() {
            match c {
                '\n' => {}
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("    "),
                c if c.is_control() => out.push_str(&format!("\\x{:02x}", c as u32)),
                c => out.push(c),
            }
        }
        out
    }

    /// Number of 16-byte hex rows.
    pub fn hex_rows(&self) -> usize {
        self.bytes.len().div_ceil(16)
    }

    /// Hex row `r`: offset, 16 bytes, ASCII gutter.
    pub fn hex_row(&self, r: usize) -> String {
        let a = r * 16;
        let c = &self.bytes[a..(a + 16).min(self.bytes.len())];
        let mut h = format!("{a:08x}  ");
        for i in 0..16 {
            match c.get(i) {
                Some(b) => h.push_str(&format!("{b:02x} ")),
                None => h.push_str("   "),
            }
        }
        h.push(' ');
        h.extend(c.iter().map(|&b| {
            if (0x20..0x7f).contains(&b) {
                b as char
            } else {
                '.'
            }
        }));
        h
    }

    /// Offsets of every occurrence of `needle` (empty needle: none).
    pub fn search(&self, needle: &str) -> Vec<usize> {
        if needle.is_empty() {
            return Vec::new();
        }
        memchr::memmem::find_iter(&self.bytes, needle.as_bytes()).collect()
    }

    /// Text row containing byte `offset`.
    pub fn row_of(&self, offset: usize) -> usize {
        self.starts
            .partition_point(|&s| s <= offset)
            .saturating_sub(1)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn view(b: &[u8]) -> RawView {
        RawView::new(Bytes::copy_from_slice(b))
    }

    #[test]
    fn rows_split_at_newlines_and_show_escapes() {
        let v = view(b"GET / HTTP/1.1\r\nHost:\tx\r\n\r\nbody\x00\xff");
        assert_eq!(v.rows(), 4);
        assert_eq!(v.row(0), "GET / HTTP/1.1\\r");
        assert_eq!(v.row(1), "Host:    x\\r");
        assert_eq!(v.row(2), "\\r");
        assert_eq!(v.row(3), "body\\x00\u{fffd}");
        assert_eq!(
            view(b"a\n").rows(),
            1,
            "no empty row after a trailing newline"
        );
        assert_eq!(view(b"").rows(), 1);
        assert_eq!(view(b"").row(0), "");
    }

    #[test]
    fn long_lines_are_split_without_cutting_characters() {
        let long = "é".repeat(500); // 1000 bytes, 2 bytes per char
        let v = view(long.as_bytes());
        assert!(v.rows() >= 4);
        let joined: String = (0..v.rows()).map(|i| v.row(i)).collect();
        assert_eq!(
            joined, long,
            "no replacement characters introduced by the split"
        );
        let plain = view(&vec![b'x'; 1000]);
        assert_eq!(plain.rows(), 1000usize.div_ceil(WRAP));
    }

    #[test]
    fn hex_rows_and_search() {
        let v = view(b"0123456789abcdefXYZ\x01");
        assert_eq!(v.hex_rows(), 2);
        assert!(v.hex_row(0).starts_with("00000000  30 31 32"));
        assert!(v.hex_row(0).ends_with("0123456789abcdef"));
        assert!(v.hex_row(1).starts_with("00000010  58 59 5a 01 "));
        assert!(v.hex_row(1).ends_with("XYZ."));
        assert_eq!(v.search("XY"), [16]);
        assert_eq!(v.search("zzz"), Vec::<usize>::new());
        assert!(v.search("").is_empty());
        let t = view(b"ab\ncd\nab");
        assert_eq!(
            t.search("ab")
                .iter()
                .map(|&o| t.row_of(o))
                .collect::<Vec<_>>(),
            [0, 2]
        );
    }

    proptest! {
        #[test]
        fn any_bytes_can_be_indexed_and_rendered(data in proptest::collection::vec(any::<u8>(), 0..3000)) {
            let v = view(&data);
            for i in 0..v.rows() {
                let _ = v.row(i);
            }
            for r in 0..v.hex_rows() {
                prop_assert!(v.hex_row(r).len() >= 8 + 2 + 48);
            }
            prop_assert!(v.rows() >= 1);
            if !data.is_empty() {
                prop_assert!(v.row_of(data.len() - 1) < v.rows());
            }
        }
    }
}
