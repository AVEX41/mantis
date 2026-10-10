//! The intercept page's data model: held messages and the editor state.

use bytes::Bytes;
use mantis_core::wire::{fix_content_length, Fix};
use mantis_proxy::intercept::{Decision, Held};

use crate::escape::{escape, unescape};
use crate::viewer::RawView;

/// Messages larger than this are shown read-only (they can still be forwarded or dropped).
pub const EDIT_LIMIT: usize = 256 * 1024;

/// The message being looked at or edited.
pub struct Editor {
    /// Id of the held message.
    pub id: u64,
    /// The editable text (empty when the message is too large to edit).
    pub text: String,
    /// Text as first shown; edits are measured against it.
    pristine: String,
    original: Bytes,
    /// The message is small enough to edit.
    pub editable: bool,
    /// Read-only view of a message that is too large to edit.
    pub preview: Option<RawView>,
    /// Last problem or note for the user.
    pub status: Option<String>,
}

impl Editor {
    fn new(held: &Held) -> Self {
        let editable = held.raw.len() <= EDIT_LIMIT;
        let text = if editable {
            escape(&held.raw)
        } else {
            String::new()
        };
        Editor {
            id: held.id,
            pristine: text.clone(),
            text,
            original: held.raw.clone(),
            editable,
            preview: (!editable).then(|| RawView::new(held.raw.clone())),
            status: None,
        }
    }

    /// The text differs from what was shown.
    pub fn is_modified(&self) -> bool {
        self.editable && self.text != self.pristine
    }

    /// Size of the original message in bytes.
    pub fn original_len(&self) -> usize {
        self.original.len()
    }
}

/// Held messages, which one is selected, and the on/off switches.
#[derive(Default)]
pub struct InterceptModel {
    /// Hold requests (mirrors the proxy; reset when it restarts).
    pub hold_requests: bool,
    /// Hold responses.
    pub hold_responses: bool,
    entries: Vec<Held>,
    editor: Option<Editor>,
}

impl InterceptModel {
    /// Held messages, oldest first.
    pub fn entries(&self) -> &[Held] {
        &self.entries
    }

    /// Id of the selected message.
    pub fn selected(&self) -> Option<u64> {
        self.editor.as_ref().map(|e| e.id)
    }

    /// The editor for the selected message.
    pub fn editor_mut(&mut self) -> Option<&mut Editor> {
        self.editor.as_mut()
    }

    /// A message was held.
    pub fn on_held(&mut self, held: Held) {
        if self.entries.iter().any(|h| h.id == held.id) {
            return;
        }
        self.entries.push(held);
        if self.editor.is_none() {
            self.select_first();
        }
    }

    /// A message stopped waiting (decided, released, or its client left).
    pub fn on_resolved(&mut self, id: u64) {
        self.entries.retain(|h| h.id != id);
        if self.selected() == Some(id) {
            self.editor = None;
            self.select_first();
        }
    }

    /// Forget everything (the proxy stopped).
    pub fn clear(&mut self) {
        self.entries.clear();
        self.editor = None;
        self.hold_requests = false;
        self.hold_responses = false;
    }

    /// Show a held message in the editor.
    pub fn select(&mut self, id: u64) {
        if self.selected() == Some(id) {
            return;
        }
        self.editor = self.entries.iter().find(|h| h.id == id).map(Editor::new);
    }

    fn select_first(&mut self) {
        self.editor = self.entries.first().map(Editor::new);
    }

    fn take_selected(&mut self) -> Option<u64> {
        let id = self.selected()?;
        self.on_resolved(id);
        Some(id)
    }

    /// Forward the selected message exactly as the proxy holds it, ignoring edits.
    pub fn forward(&mut self) -> Option<(u64, Decision)> {
        self.take_selected().map(|id| (id, Decision::Forward))
    }

    /// Drop the selected message.
    pub fn drop_selected(&mut self) -> Option<(u64, Decision)> {
        self.take_selected().map(|id| (id, Decision::Drop))
    }

    /// Send the edited text, byte for byte as written (`\xNN` etc. decoded).
    /// An unchanged text is a plain forward. A malformed escape keeps the
    /// message selected and reports the problem in the editor.
    pub fn send_edited(&mut self) -> Option<(u64, Decision)> {
        let ed = self.editor.as_mut()?;
        if !ed.editable {
            ed.status = Some("this message is too large to edit".into());
            return None;
        }
        if !ed.is_modified() {
            return self.forward();
        }
        match unescape(&ed.text) {
            Ok(bytes) => {
                let id = ed.id;
                self.on_resolved(id);
                Some((id, Decision::Edited(Bytes::from(bytes))))
            }
            Err(e) => {
                ed.status = Some(e.to_string());
                None
            }
        }
    }

    /// Set `Content-Length` to the body length in the edited text (an explicit action).
    pub fn fix_content_length(&mut self) {
        let Some(ed) = self.editor.as_mut().filter(|e| e.editable) else {
            return;
        };
        let raw = match unescape(&ed.text) {
            Ok(r) => r,
            Err(e) => {
                ed.status = Some(e.to_string());
                return;
            }
        };
        ed.status = Some(match fix_content_length(&raw) {
            Fix::Changed(fixed) => {
                ed.text = escape(&fixed);
                "Content-Length updated.".into()
            }
            Fix::Unchanged => "Content-Length already matches the body.".into(),
            Fix::Skipped(why) => format!("Content-Length left alone: {why}."),
        });
    }
}

#[cfg(test)]
mod tests {
    use mantis_proxy::Dir;

    use super::*;

    fn held(id: u64, raw: &[u8]) -> Held {
        Held {
            id,
            dir: Dir::Request,
            host: "h".into(),
            port: 80,
            tls: false,
            raw: Bytes::copy_from_slice(raw),
        }
    }

    #[test]
    fn first_held_message_is_selected_and_resolved_ones_disappear() {
        let mut m = InterceptModel::default();
        m.on_held(held(1, b"GET /a HTTP/1.1\r\n\r\n"));
        m.on_held(held(2, b"GET /b HTTP/1.1\r\n\r\n"));
        m.on_held(held(2, b"duplicate event")); // ignored
        assert_eq!((m.entries().len(), m.selected()), (2, Some(1)));
        m.select(2);
        assert_eq!(m.editor_mut().unwrap().text, "GET /b HTTP/1.1\\r\n\\r\n");
        m.on_resolved(2);
        assert_eq!(
            (m.entries().len(), m.selected()),
            (1, Some(1)),
            "falls back to the oldest"
        );
        m.on_resolved(1);
        assert_eq!(m.selected(), None);
        m.on_resolved(99); // unknown: harmless
    }

    #[test]
    fn forward_ignores_edits_and_advances() {
        let mut m = InterceptModel::default();
        m.on_held(held(1, b"GET / HTTP/1.1\r\n\r\n"));
        m.on_held(held(2, b"GET /2 HTTP/1.1\r\n\r\n"));
        m.editor_mut().unwrap().text.push_str("garbage");
        assert_eq!(m.forward(), Some((1, Decision::Forward)));
        assert_eq!(m.selected(), Some(2));
        assert_eq!(m.drop_selected(), Some((2, Decision::Drop)));
        assert_eq!(
            (m.forward(), m.drop_selected(), m.send_edited()),
            (None, None, None)
        );
    }

    #[test]
    fn edited_text_is_sent_byte_for_byte() {
        let mut m = InterceptModel::default();
        m.on_held(held(7, b"GET /old HTTP/1.1\r\nHost: x\r\n\r\n"));
        let ed = m.editor_mut().unwrap();
        assert!(!ed.is_modified());
        ed.text = "GET /new HTTP/1.1\nHost: x\nA: 1\\x00\\xff\n\n".into();
        assert!(ed.is_modified());
        let (id, d) = m.send_edited().unwrap();
        assert_eq!(
            (id, d),
            (
                7,
                Decision::Edited(Bytes::from_static(
                    b"GET /new HTTP/1.1\nHost: x\nA: 1\x00\xff\n\n"
                ))
            )
        );
        assert!(m.entries().is_empty());
    }

    #[test]
    fn unchanged_text_is_a_plain_forward_and_a_bad_escape_changes_nothing() {
        let mut m = InterceptModel::default();
        m.on_held(held(1, b"GET / HTTP/1.1\r\n\r\n"));
        assert_eq!(m.send_edited(), Some((1, Decision::Forward)));
        m.on_held(held(2, b"GET / HTTP/1.1\r\n\r\n"));
        m.editor_mut().unwrap().text.push_str("\\q");
        assert_eq!(m.send_edited(), None);
        assert_eq!(m.selected(), Some(2), "still waiting");
        assert!(m
            .editor_mut()
            .unwrap()
            .status
            .as_ref()
            .unwrap()
            .contains("unknown escape"));
        assert_eq!(m.entries().len(), 1);
    }

    #[test]
    fn large_messages_are_read_only_but_can_be_forwarded() {
        let mut m = InterceptModel::default();
        let big = vec![b'a'; EDIT_LIMIT + 1];
        m.on_held(held(1, &big));
        let ed = m.editor_mut().unwrap();
        assert!(!ed.editable && ed.text.is_empty() && ed.preview.is_some());
        assert_eq!(ed.original_len(), EDIT_LIMIT + 1);
        assert_eq!(m.send_edited(), None);
        m.fix_content_length(); // no-op
        assert_eq!(m.forward(), Some((1, Decision::Forward)));
    }

    #[test]
    fn fix_content_length_edits_the_text_and_explains_itself() {
        let mut m = InterceptModel::default();
        m.on_held(held(1, b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc"));
        m.editor_mut().unwrap().text =
            "POST / HTTP/1.1\\r\nContent-Length: 3\\r\n\\r\nabcdef".into();
        m.fix_content_length();
        let ed = m.editor_mut().unwrap();
        assert_eq!(
            ed.text,
            "POST / HTTP/1.1\\r\nContent-Length: 6\\r\n\\r\nabcdef"
        );
        assert_eq!(ed.status.as_deref(), Some("Content-Length updated."));
        m.fix_content_length();
        assert!(m
            .editor_mut()
            .unwrap()
            .status
            .as_ref()
            .unwrap()
            .contains("already matches"));
        m.editor_mut().unwrap().text =
            "POST / HTTP/1.1\\r\nTransfer-Encoding: chunked\\r\n\\r\n0\\r\n\\r\n".into();
        m.fix_content_length();
        assert!(m
            .editor_mut()
            .unwrap()
            .status
            .as_ref()
            .unwrap()
            .contains("chunked"));
        m.editor_mut().unwrap().text = "bad \\q".into();
        m.fix_content_length();
        assert!(m
            .editor_mut()
            .unwrap()
            .status
            .as_ref()
            .unwrap()
            .contains("escape"));
    }

    #[test]
    fn clearing_resets_the_switches_too() {
        let mut m = InterceptModel {
            hold_requests: true,
            hold_responses: true,
            ..Default::default()
        };
        m.on_held(held(1, b"x"));
        m.clear();
        assert!(
            m.entries().is_empty()
                && m.selected().is_none()
                && !m.hold_requests
                && !m.hold_responses
        );
    }
}
