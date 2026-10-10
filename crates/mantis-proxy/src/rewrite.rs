//! Match-and-replace rules applied to raw messages before they are forwarded.
//!
//! Rules work on bytes: the request line, header values, the body, or the
//! whole message. Bodies framed with chunked transfer coding are not touched
//! (a match could straddle chunk framing and re-encoding would change bytes
//! the rule never asked about); a warning is reported instead.

use std::sync::{Arc, RwLock};

use bytes::Bytes;
use mantis_core::view::{Header, RequestView, ResponseView};
use mantis_core::wire::{detect_framing, Framing, Kind};
use regex::bytes::{NoExpand, Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

use crate::Dir;

/// Which messages a rule applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// Requests only.
    Request,
    /// Responses only.
    Response,
    /// Both.
    Both,
}

/// Which part of the message a rule rewrites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    /// The first line.
    RequestLine,
    /// The value of every header with the rule's `header` name.
    Header,
    /// Everything after the blank line.
    Body,
    /// The whole message, head and body.
    Message,
}

fn yes() -> bool {
    true
}

/// A rule as written by the user (and as saved to disk).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSpec {
    /// Requests, responses or both.
    pub direction: Direction,
    /// Part of the message to rewrite.
    pub target: Target,
    /// Header name (case-insensitive); required for, and only allowed with, `target = "header"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    /// What to look for: literal text, or a regex when `regex` is set.
    pub pattern: String,
    /// Treat `pattern` as a regular expression (`$1` expands in `replace`).
    #[serde(default)]
    pub regex: bool,
    /// Replacement text.
    pub replace: String,
    /// After a body change, shift `Content-Length` by the length difference.
    /// Default: on for body and message rules, off otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix_content_length: Option<bool>,
    /// Disabled rules are kept but skipped.
    #[serde(default = "yes")]
    pub enabled: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RulesFile {
    #[serde(default)]
    rules: Vec<RuleSpec>,
}

/// Rewrite errors.
#[derive(Debug, thiserror::Error)]
pub enum RewriteError {
    /// The pattern is empty or does not compile.
    #[error("rule {index}: invalid pattern: {reason}")]
    Pattern {
        /// Position of the rule.
        index: usize,
        /// Why.
        reason: String,
    },
    /// `header` is missing for a header rule, or given for another target.
    #[error("rule {index}: `header` is required for target \"header\" and only allowed there")]
    Header {
        /// Position of the rule.
        index: usize,
    },
    /// The rules file could not be parsed.
    #[error("rules file: {0}")]
    Parse(#[from] toml::de::Error),
}

/// Parse `[[rules]]` tables from TOML without compiling them. Unknown keys are errors.
pub fn parse_rules(s: &str) -> Result<Vec<RuleSpec>, RewriteError> {
    Ok(toml::from_str::<RulesFile>(s)?.rules)
}

struct Rule {
    spec: RuleSpec,
    re: Regex,
}

impl Rule {
    fn new(index: usize, spec: RuleSpec) -> Result<Self, RewriteError> {
        if spec.pattern.is_empty() {
            return Err(RewriteError::Pattern {
                index,
                reason: "pattern is empty".into(),
            });
        }
        let named = spec.header.as_deref().is_some_and(|h| !h.is_empty());
        if (spec.target == Target::Header) != named {
            return Err(RewriteError::Header { index });
        }
        let src = if spec.regex {
            spec.pattern.clone()
        } else {
            regex::escape(&spec.pattern)
        };
        let re = RegexBuilder::new(&src)
            .size_limit(1 << 20)
            .build()
            .map_err(|e| RewriteError::Pattern {
                index,
                reason: e.to_string(),
            })?;
        Ok(Rule { spec, re })
    }

    fn fixes_length(&self) -> bool {
        self.spec
            .fix_content_length
            .unwrap_or(matches!(self.spec.target, Target::Body | Target::Message))
    }

    fn applies(&self, dir: Dir) -> bool {
        self.spec.enabled
            && matches!(
                (self.spec.direction, dir),
                (Direction::Both, _)
                    | (Direction::Request, Dir::Request)
                    | (Direction::Response, Dir::Response)
            )
    }

    /// Replace matches inside `buf[range]`; returns the length change if anything changed.
    fn replace_in(&self, buf: &mut Vec<u8>, range: std::ops::Range<usize>) -> Option<isize> {
        let out = if self.spec.regex {
            self.re
                .replace_all(&buf[range.clone()], self.spec.replace.as_bytes())
        } else {
            self.re
                .replace_all(&buf[range.clone()], NoExpand(self.spec.replace.as_bytes()))
        };
        let std::borrow::Cow::Owned(new) = out else {
            return None;
        };
        let delta = new.len() as isize - range.len() as isize;
        buf.splice(range, new);
        Some(delta)
    }
}

/// The result of applying the rules to one message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rewritten {
    /// The message to forward.
    pub raw: Bytes,
    /// At least one rule changed it.
    pub changed: bool,
    /// Rules that could not be applied (for example chunked bodies).
    pub warnings: Vec<String>,
}

/// An ordered, replaceable set of rewrite rules. Cheap to share.
#[derive(Clone, Default)]
pub struct Rewriter {
    rules: Arc<RwLock<Arc<Vec<Rule>>>>,
}

struct Parts {
    start_line: std::ops::Range<usize>,
    headers: Vec<Header>,
    body: std::ops::Range<usize>,
    head_complete: bool,
}

fn parts(dir: Dir, raw: &[u8]) -> Parts {
    match dir {
        Dir::Request => {
            let v = RequestView::parse(raw);
            Parts {
                start_line: v.start_line,
                headers: v.headers,
                body: v.body,
                head_complete: v.head_complete,
            }
        }
        Dir::Response => {
            let v = ResponseView::parse(raw);
            Parts {
                start_line: v.start_line,
                headers: v.headers,
                body: v.body,
                head_complete: v.head_complete,
            }
        }
    }
}

fn is_chunked(dir: Dir, raw: &[u8], p: &Parts) -> bool {
    let kind = match dir {
        Dir::Request => Kind::Request,
        Dir::Response => Kind::Response {
            request_method: None,
        },
    };
    p.head_complete && detect_framing(&raw[..p.body.start], kind).0 == Framing::Chunked
}

/// Shift the single numeric `Content-Length` by `delta`. Anything else (none,
/// several, non-numeric) is left alone: a deliberately wrong header stays wrong
/// by the same amount.
fn shift_content_length(dir: Dir, buf: &mut Vec<u8>, delta: isize) {
    let p = parts(dir, buf);
    let mut cl = p
        .headers
        .iter()
        .filter(|h| buf[h.name.clone()].eq_ignore_ascii_case(b"content-length"));
    let (Some(h), None) = (cl.next(), cl.next()) else {
        return;
    };
    let range = h.value.clone();
    let Some(old) = std::str::from_utf8(&buf[range.clone()])
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
    else {
        return;
    };
    let Some(new) = old.checked_add_signed(delta as i64) else {
        return;
    };
    buf.splice(range, new.to_string().into_bytes());
}

impl Rewriter {
    /// Compile `specs` into a rewriter.
    pub fn new(specs: Vec<RuleSpec>) -> Result<Self, RewriteError> {
        let r = Rewriter::default();
        r.set_rules(specs)?;
        Ok(r)
    }

    /// Parse rules from TOML (`[[rules]]` tables). Unknown keys are errors.
    pub fn from_toml(s: &str) -> Result<Self, RewriteError> {
        Self::new(parse_rules(s)?)
    }

    /// Replace all rules atomically; on error the old rules stay.
    pub fn set_rules(&self, specs: Vec<RuleSpec>) -> Result<(), RewriteError> {
        let rules = specs
            .into_iter()
            .enumerate()
            .map(|(i, s)| Rule::new(i, s))
            .collect::<Result<Vec<_>, _>>()?;
        *self.rules.write().unwrap_or_else(|p| p.into_inner()) = Arc::new(rules);
        Ok(())
    }

    /// The current rules as written.
    pub fn specs(&self) -> Vec<RuleSpec> {
        self.snapshot().iter().map(|r| r.spec.clone()).collect()
    }

    fn snapshot(&self) -> Arc<Vec<Rule>> {
        self.rules.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Apply every matching rule, in order, to one message.
    pub fn apply(&self, dir: Dir, raw: &Bytes) -> Rewritten {
        let rules = self.snapshot();
        let mut buf: Option<Vec<u8>> = None;
        let mut warnings = Vec::new();
        for (i, rule) in rules.iter().enumerate().filter(|(_, r)| r.applies(dir)) {
            let b = buf.get_or_insert_with(|| raw.to_vec());
            let p = parts(dir, b);
            match rule.spec.target {
                Target::RequestLine => {
                    rule.replace_in(b, p.start_line);
                }
                Target::Header => {
                    let name = rule.spec.header.as_deref().unwrap_or("").as_bytes();
                    let hits: Vec<_> = p
                        .headers
                        .iter()
                        .filter(|h| b[h.name.clone()].eq_ignore_ascii_case(name))
                        .map(|h| h.value.clone())
                        .collect();
                    for range in hits.into_iter().rev() {
                        rule.replace_in(b, range); // right to left keeps earlier ranges valid
                    }
                }
                Target::Body | Target::Message => {
                    if is_chunked(dir, b, &p) {
                        warnings.push(format!("rule {i}: skipped, message body is chunked"));
                        continue;
                    }
                    if rule.spec.target == Target::Body && !p.head_complete {
                        continue;
                    }
                    let (region, body_before) = match rule.spec.target {
                        Target::Body => (p.body.clone(), p.body.len()),
                        _ => (0..b.len(), p.body.len()),
                    };
                    if rule.replace_in(b, region).is_some() && rule.fixes_length() {
                        let after = parts(dir, b);
                        let delta = after.body.len() as isize - body_before as isize;
                        if after.head_complete && delta != 0 {
                            shift_content_length(dir, b, delta);
                        }
                    }
                }
            }
        }
        match buf {
            Some(b) if b[..] != raw[..] => Rewritten {
                raw: Bytes::from(b),
                changed: true,
                warnings,
            },
            _ => Rewritten {
                raw: raw.clone(),
                changed: false,
                warnings,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn spec(
        direction: Direction,
        target: Target,
        header: Option<&str>,
        pattern: &str,
        regex: bool,
        replace: &str,
    ) -> RuleSpec {
        RuleSpec {
            direction,
            target,
            header: header.map(Into::into),
            pattern: pattern.into(),
            regex,
            replace: replace.into(),
            fix_content_length: None,
            enabled: true,
        }
    }

    fn run(rules: Vec<RuleSpec>, dir: Dir, raw: &[u8]) -> Rewritten {
        Rewriter::new(rules)
            .unwrap()
            .apply(dir, &Bytes::copy_from_slice(raw))
    }

    #[test]
    fn header_rule_rewrites_every_duplicate_case_insensitively() {
        let r = run(
            vec![spec(
                Direction::Request,
                Target::Header,
                Some("user-agent"),
                "curl",
                false,
                "Mantis",
            )],
            Dir::Request,
            b"GET / HTTP/1.1\nUser-Agent: curl/8\nUSER-AGENT: curl/9\nX: curl\n\n",
        );
        assert_eq!(
            &r.raw[..],
            b"GET / HTTP/1.1\nUser-Agent: Mantis/8\nUSER-AGENT: Mantis/9\nX: curl\n\n"
        );
        assert!(r.changed);
    }

    #[test]
    fn request_line_and_regex_captures() {
        let r = run(
            vec![spec(
                Direction::Request,
                Target::RequestLine,
                None,
                r"^GET (/\w+)",
                true,
                "POST $1",
            )],
            Dir::Request,
            b"GET /abc?x=1 HTTP/1.1\r\n\r\n",
        );
        assert_eq!(&r.raw[..], b"POST /abc?x=1 HTTP/1.1\r\n\r\n");
    }

    #[test]
    fn literal_patterns_and_replacements_are_not_interpreted() {
        let r = run(
            vec![spec(
                Direction::Request,
                Target::Body,
                None,
                "a.c$",
                false,
                "$1\\d",
            )],
            Dir::Request,
            b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\na.c$",
        );
        assert_eq!(&r.raw[r.raw.len() - 4..], b"$1\\d"); // replaced as-is
        assert!(
            !run(
                vec![spec(
                    Direction::Request,
                    Target::Body,
                    None,
                    "a.c$",
                    false,
                    "x"
                )],
                Dir::Request,
                b"POST / HTTP/1.1\r\n\r\nabcd"
            )
            .changed
        );
    }

    #[test]
    fn body_rule_shifts_content_length_by_the_difference() {
        let r = run(
            vec![spec(
                Direction::Request,
                Target::Body,
                None,
                "cat",
                false,
                "elephant",
            )],
            Dir::Request,
            b"POST / HTTP/1.1\r\nContent-Length: 7\r\n\r\ncat dog",
        );
        assert_eq!(
            &r.raw[..],
            b"POST / HTTP/1.1\r\nContent-Length: 12\r\n\r\nelephant dog"
        );
    }

    #[test]
    fn a_deliberately_wrong_content_length_stays_wrong_by_the_same_amount() {
        let r = run(
            vec![spec(
                Direction::Request,
                Target::Body,
                None,
                "cat",
                false,
                "tiger",
            )],
            Dir::Request,
            b"POST / HTTP/1.1\r\nContent-Length: 99\r\n\r\ncat",
        );
        assert_eq!(
            &r.raw[..],
            b"POST / HTTP/1.1\r\nContent-Length: 101\r\n\r\ntiger"
        );
    }

    #[test]
    fn content_length_fix_can_be_switched_off_and_does_not_apply_to_headers() {
        let mut s = spec(
            Direction::Request,
            Target::Body,
            None,
            "cat",
            false,
            "tiger",
        );
        s.fix_content_length = Some(false);
        let r = run(
            vec![s],
            Dir::Request,
            b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\ncat",
        );
        assert_eq!(
            &r.raw[..],
            b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\ntiger"
        );
        let r = run(
            vec![spec(
                Direction::Request,
                Target::Header,
                Some("X"),
                "1",
                false,
                "22",
            )],
            Dir::Request,
            b"GET / HTTP/1.1\r\nX: 1\r\nContent-Length: 0\r\n\r\n",
        );
        assert_eq!(
            &r.raw[..],
            b"GET / HTTP/1.1\r\nX: 22\r\nContent-Length: 0\r\n\r\n"
        );
    }

    #[test]
    fn chunked_bodies_are_left_alone_with_a_warning() {
        let raw = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\ncat\r\n0\r\n\r\n";
        let r = run(
            vec![spec(
                Direction::Request,
                Target::Body,
                None,
                "cat",
                false,
                "dog",
            )],
            Dir::Request,
            raw,
        );
        assert_eq!((&r.raw[..], r.changed), (&raw[..], false));
        assert_eq!(r.warnings.len(), 1);
        // Header rules still work on chunked messages.
        let r = run(
            vec![spec(
                Direction::Request,
                Target::Header,
                Some("Transfer-Encoding"),
                "chunked",
                false,
                "chunked",
            )],
            Dir::Request,
            raw,
        );
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn direction_and_enabled_are_respected() {
        let req = spec(
            Direction::Request,
            Target::Message,
            None,
            "secret",
            false,
            "XXXXXX",
        );
        let mut off = spec(
            Direction::Both,
            Target::Message,
            None,
            "secret",
            false,
            "XXXXXX",
        );
        off.enabled = false;
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecret";
        assert!(!run(vec![req.clone(), off], Dir::Response, raw).changed);
        let both = spec(
            Direction::Both,
            Target::Body,
            None,
            "secret",
            false,
            "hidden",
        );
        assert_eq!(
            &run(vec![both], Dir::Response, raw).raw[..],
            b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nhidden"
        );
    }

    #[test]
    fn rules_apply_in_order() {
        let r = run(
            vec![
                spec(
                    Direction::Request,
                    Target::Header,
                    Some("X"),
                    "a",
                    false,
                    "b",
                ),
                spec(
                    Direction::Request,
                    Target::Header,
                    Some("X"),
                    "b",
                    false,
                    "c",
                ),
            ],
            Dir::Request,
            b"GET / HTTP/1.1\r\nX: a\r\n\r\n",
        );
        assert_eq!(&r.raw[..], b"GET / HTTP/1.1\r\nX: c\r\n\r\n");
    }

    #[test]
    fn invalid_rules_are_rejected_and_old_rules_survive_a_bad_update() {
        let bad = [
            spec(Direction::Both, Target::Body, None, "", false, "x"),
            spec(Direction::Both, Target::Body, None, "(", true, "x"),
            spec(Direction::Both, Target::Header, None, "a", false, "x"),
            spec(Direction::Both, Target::Body, Some("X"), "a", false, "x"),
        ];
        for b in bad {
            assert!(Rewriter::new(vec![b]).is_err());
        }
        let rw = Rewriter::new(vec![spec(
            Direction::Both,
            Target::Body,
            None,
            "a",
            false,
            "b",
        )])
        .unwrap();
        assert!(rw
            .set_rules(vec![spec(
                Direction::Both,
                Target::Body,
                None,
                "(",
                true,
                "x"
            )])
            .is_err());
        assert_eq!(rw.specs().len(), 1);
    }

    #[test]
    fn toml_round_trip_and_strictness() {
        let text = "[[rules]]\ndirection = \"both\"\ntarget = \"header\"\nheader = \"Cookie\"\npattern = \"sid=\\\\w+\"\nregex = true\nreplace = \"sid=redacted\"\n";
        let rw = Rewriter::from_toml(text).unwrap();
        assert_eq!(rw.specs()[0].header.as_deref(), Some("Cookie"));
        assert!(rw.specs()[0].enabled);
        assert!(Rewriter::from_toml("[[rules]]\ndirection = \"both\"\ntarget = \"body\"\npattern = \"a\"\nreplace = \"b\"\nreplacee = \"typo\"\n").is_err());
        assert!(Rewriter::from_toml("").unwrap().specs().is_empty());
    }

    proptest! {
        #[test]
        fn never_panics_and_unmatched_rules_change_nothing(raw in proptest::collection::vec(any::<u8>(), 0..300)) {
            let targets = [Target::RequestLine, Target::Body, Target::Message];
            let rules: Vec<_> = targets.iter().map(|&t| spec(Direction::Both, t, None, "\u{1F980}never-present", false, "x")).collect();
            let raw = Bytes::from(raw);
            for dir in [Dir::Request, Dir::Response] {
                let out = Rewriter::new(rules.clone()).unwrap().apply(dir, &raw);
                prop_assert_eq!(&out.raw, &raw);
                prop_assert!(!out.changed);
            }
            // Active rules must not panic either, whatever the bytes.
            let active: Vec<_> = targets.iter().map(|&t| spec(Direction::Both, t, None, "a", false, "bbb")).collect();
            for dir in [Dir::Request, Dir::Response] {
                Rewriter::new(active.clone()).unwrap().apply(dir, &raw);
            }
        }
    }
}
