//! Incremental WebSocket (RFC 6455) frame scanner.
//!
//! Feed it the bytes of one direction as they pass; it reports each complete
//! frame with its raw bytes. It never alters or delays anything: the caller
//! forwards the bytes itself. Payloads past the cap are not buffered, only counted.

use bytes::Bytes;

/// Default bytes of payload kept per frame.
pub const DEFAULT_CAP: usize = 1 << 20;

/// One frame as seen on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Opcode (0 continuation, 1 text, 2 binary, 8 close, 9 ping, 10 pong).
    pub opcode: u8,
    /// FIN bit.
    pub fin: bool,
    /// RSV1 bit (set on compressed messages with permessage-deflate).
    pub rsv1: bool,
    /// The payload is masked (client to server).
    pub masked: bool,
    /// Real payload length, even when `raw` was cut short.
    pub payload_len: u64,
    /// `raw` holds only part of the payload.
    pub truncated: bool,
    /// Header plus (up to the cap of) payload, exactly as received.
    pub raw: Bytes,
    header_len: usize,
}

impl Frame {
    /// Length of the frame header inside `raw`.
    pub fn header_len(&self) -> usize {
        self.header_len
    }

    /// The stored payload with the mask removed. Compressed payloads stay compressed.
    pub fn payload(&self) -> Vec<u8> {
        let p = &self.raw[self.header_len..];
        if !self.masked {
            return p.to_vec();
        }
        let key = &self.raw[self.header_len - 4..self.header_len];
        p.iter().enumerate().map(|(i, b)| b ^ key[i % 4]).collect()
    }
}

struct Header {
    raw: Vec<u8>,
    opcode: u8,
    fin: bool,
    rsv1: bool,
    masked: bool,
    len: u64,
}

impl Header {
    fn finish(self, payload: Vec<u8>) -> Frame {
        let header_len = self.raw.len();
        let truncated = (payload.len() as u64) < self.len;
        let mut raw = self.raw;
        raw.extend_from_slice(&payload);
        Frame {
            opcode: self.opcode,
            fin: self.fin,
            rsv1: self.rsv1,
            masked: self.masked,
            payload_len: self.len,
            truncated,
            raw: Bytes::from(raw),
            header_len,
        }
    }
}

enum State {
    Header(Vec<u8>),
    Payload {
        hdr: Header,
        stored: Vec<u8>,
        remaining: u64,
    },
}

/// Scans one direction of a WebSocket connection.
pub struct FrameScanner {
    cap: usize,
    lost: bool,
    state: State,
}

/// Bytes needed for the header whose first bytes are `h`.
fn header_len(h: &[u8]) -> usize {
    if h.len() < 2 {
        return 2;
    }
    let ext = match h[1] & 0x7f {
        126 => 2,
        127 => 8,
        _ => 0,
    };
    2 + ext + if h[1] & 0x80 != 0 { 4 } else { 0 }
}

/// Validate a complete header. `None` means the stream is not valid WebSocket.
fn parse_header(h: &[u8]) -> Option<Header> {
    let (b0, b1) = (h[0], h[1]);
    if b0 & 0x30 != 0 {
        return None; // RSV2/RSV3: no extension we know of uses them
    }
    let opcode = b0 & 0x0f;
    if !matches!(opcode, 0 | 1 | 2 | 8 | 9 | 10) {
        return None;
    }
    let len = match b1 & 0x7f {
        126 => u64::from(u16::from_be_bytes([h[2], h[3]])),
        127 => {
            let n = u64::from_be_bytes([h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9]]);
            if n >> 63 != 0 {
                return None;
            }
            n
        }
        n => u64::from(n),
    };
    let fin = b0 & 0x80 != 0;
    if opcode >= 8 && (!fin || len > 125) {
        return None; // control frames are never fragmented and are short
    }
    Some(Header {
        raw: h.to_vec(),
        opcode,
        fin,
        rsv1: b0 & 0x40 != 0,
        masked: b1 & 0x80 != 0,
        len,
    })
}

impl FrameScanner {
    /// A scanner keeping at most `cap` payload bytes per frame.
    pub fn new(cap: usize) -> Self {
        FrameScanner {
            cap,
            lost: false,
            state: State::Header(Vec::new()),
        }
    }

    /// The stream stopped looking like WebSocket; no more frames will be reported.
    pub fn is_lost(&self) -> bool {
        self.lost
    }

    /// Consume the next bytes of the stream; returns frames completed by them.
    pub fn feed(&mut self, mut data: &[u8]) -> Vec<Frame> {
        let mut out = Vec::new();
        while !data.is_empty() && !self.lost {
            match std::mem::replace(&mut self.state, State::Header(Vec::new())) {
                State::Header(mut h) => {
                    let take = header_len(&h).saturating_sub(h.len()).min(data.len());
                    h.extend_from_slice(&data[..take]);
                    data = &data[take..];
                    if h.len() < header_len(&h) {
                        self.state = State::Header(h);
                        continue;
                    }
                    match parse_header(&h) {
                        None => self.lost = true,
                        Some(hdr) if hdr.len == 0 => out.push(hdr.finish(Vec::new())),
                        Some(hdr) => {
                            let remaining = hdr.len;
                            self.state = State::Payload {
                                hdr,
                                stored: Vec::new(),
                                remaining,
                            };
                        }
                    }
                }
                State::Payload {
                    hdr,
                    mut stored,
                    remaining,
                } => {
                    let take = remaining.min(data.len() as u64) as usize;
                    let room = self.cap.saturating_sub(stored.len());
                    stored.extend_from_slice(&data[..take.min(room)]);
                    data = &data[take..];
                    let remaining = remaining - take as u64;
                    if remaining == 0 {
                        out.push(hdr.finish(stored));
                    } else {
                        self.state = State::Payload {
                            hdr,
                            stored,
                            remaining,
                        };
                    }
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Encode a frame the way a peer would.
    fn encode(opcode: u8, fin: bool, mask: Option<[u8; 4]>, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![(u8::from(fin) << 7) | opcode];
        let m = if mask.is_some() { 0x80 } else { 0 };
        match payload.len() {
            n if n < 126 => v.push(m | n as u8),
            n if n <= 0xffff => {
                v.push(m | 126);
                v.extend((n as u16).to_be_bytes());
            }
            n => {
                v.push(m | 127);
                v.extend((n as u64).to_be_bytes());
            }
        }
        match mask {
            Some(k) => {
                v.extend(k);
                v.extend(payload.iter().enumerate().map(|(i, b)| b ^ k[i % 4]));
            }
            None => v.extend(payload),
        }
        v
    }

    fn scan_chunked(data: &[u8], chunk: usize, cap: usize) -> Vec<Frame> {
        let mut s = FrameScanner::new(cap);
        data.chunks(chunk.max(1)).flat_map(|c| s.feed(c)).collect()
    }

    #[test]
    fn frames_of_every_length_class_split_at_every_boundary() {
        let k = [1, 2, 3, 4];
        for len in [0usize, 1, 125, 126, 127, 65535, 65536, 70_000] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            for (mask, op) in [(None, 1u8), (Some(k), 2u8)] {
                let wire = encode(op, true, mask, &payload);
                for chunk in [1usize, 2, 3, 7, 1000, wire.len()] {
                    if len > 1000 && chunk < 7 {
                        continue; // keep the test quick
                    }
                    let f = scan_chunked(&wire, chunk, DEFAULT_CAP);
                    assert_eq!(f.len(), 1, "len {len} chunk {chunk}");
                    assert_eq!(
                        (
                            f[0].opcode,
                            f[0].fin,
                            f[0].masked,
                            f[0].payload_len,
                            f[0].truncated
                        ),
                        (op, true, mask.is_some(), len as u64, false)
                    );
                    assert_eq!(&f[0].raw[..], &wire[..]);
                    assert_eq!(f[0].payload(), payload);
                }
            }
        }
    }

    #[test]
    fn several_frames_in_one_read_and_control_frames() {
        let mut wire = encode(1, false, None, b"hel");
        wire.extend(encode(9, true, None, b"ping"));
        wire.extend(encode(0, true, None, b"lo"));
        wire.extend(encode(8, true, Some([9, 9, 9, 9]), &[0x03, 0xe8]));
        let f = scan_chunked(&wire, wire.len(), DEFAULT_CAP);
        let seen: Vec<_> = f.iter().map(|f| (f.opcode, f.fin)).collect();
        assert_eq!(seen, [(1, false), (9, true), (0, true), (8, true)]);
        assert_eq!(f.iter().map(|f| f.raw.len()).sum::<usize>(), wire.len());
        assert_eq!(f[3].payload(), [0x03, 0xe8]);
    }

    #[test]
    fn oversize_payloads_are_counted_not_buffered_and_the_next_frame_still_parses() {
        let mut wire = encode(2, true, None, &[7u8; 50]);
        wire.extend(encode(1, true, None, b"after"));
        for chunk in [1usize, 5, 1000] {
            let f = scan_chunked(&wire, chunk, 10);
            assert_eq!(f.len(), 2);
            assert_eq!(
                (f[0].payload_len, f[0].truncated, f[0].raw.len()),
                (50, true, 2 + 10)
            );
            assert_eq!(f[0].payload(), vec![7u8; 10]);
            assert_eq!((f[1].truncated, f[1].payload()), (false, b"after".to_vec()));
        }
    }

    #[test]
    fn invalid_streams_are_declared_lost_and_stay_quiet() {
        let bad: Vec<Vec<u8>> = vec![
            encode(3, true, None, b"x"), // reserved opcode
            encode(1, true, None, b"x")
                .into_iter()
                .enumerate()
                .map(|(i, b)| if i == 0 { b | 0x20 } else { b })
                .collect(), // RSV2
            encode(9, false, None, b"x"), // fragmented ping
            encode(9, true, None, &[0u8; 126]), // long ping
            [vec![0x82, 127], (1u64 << 63).to_be_bytes().to_vec()].concat(), // top bit of 64-bit length
        ];
        for b in bad {
            let mut s = FrameScanner::new(DEFAULT_CAP);
            assert!(s.feed(&b).is_empty());
            assert!(s.is_lost(), "{b:02x?}");
            assert!(
                s.feed(&encode(1, true, None, b"ok")).is_empty(),
                "stays quiet once lost"
            );
        }
    }

    type Spec = (u8, bool, Option<[u8; 4]>, Vec<u8>);

    fn arb_frames() -> impl Strategy<Value = Vec<Spec>> {
        let one = (
            prop_oneof![Just(0u8), Just(1), Just(2)],
            any::<bool>(),
            proptest::option::of(any::<[u8; 4]>()),
            proptest::collection::vec(any::<u8>(), 0..300),
        );
        proptest::collection::vec(one, 0..6)
    }

    proptest! {
        #[test]
        fn any_chunking_of_a_valid_stream_yields_the_same_frames(frames in arb_frames(), chunk in 1usize..40) {
            let wire: Vec<u8> = frames.iter().flat_map(|(op, fin, m, p)| encode(*op, *fin, *m, p)).collect();
            let got = scan_chunked(&wire, chunk, DEFAULT_CAP);
            prop_assert_eq!(got.len(), frames.len());
            for (g, (op, fin, m, p)) in got.iter().zip(&frames) {
                prop_assert_eq!((g.opcode, g.fin, g.masked.then_some(()), g.payload()), (*op, *fin, m.map(|_| ()), p.clone()));
            }
            prop_assert_eq!(got.iter().flat_map(|f| f.raw.to_vec()).collect::<Vec<_>>(), wire);
        }

        #[test]
        fn arbitrary_bytes_never_panic_or_exceed_the_cap(data in proptest::collection::vec(any::<u8>(), 0..2000), chunk in 1usize..64, cap in 0usize..64) {
            for f in scan_chunked(&data, chunk, cap) {
                prop_assert!(f.raw.len() <= 14 + cap);
                prop_assert!(f.header_len() >= 2 && f.header_len() <= 14);
            }
        }
    }
}
