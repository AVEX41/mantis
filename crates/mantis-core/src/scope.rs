//! Scope model: which hosts, ports and paths tools may touch.
//!
//! Default deny: a target is in scope only if an include rule matches and no
//! exclude rule matches. Matching normalises a copy of the host and path; it
//! never alters stored message bytes.
//!
//! Limits worth knowing: paths are matched as sent (no percent-decoding), IPv4
//! and IPv6 literals match only the same address family, and an exclude on
//! `/admin` does not cover `/%61dmin`.

use std::net::IpAddr;
use std::ops::RangeInclusive;

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

/// Whether a rule adds to or removes from scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Matching targets are in scope.
    Include,
    /// Matching targets are out of scope, overriding any include.
    Exclude,
}

/// A rule as written by the user (and as saved to disk).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSpec {
    /// Include or exclude.
    pub action: Action,
    /// Exact host, IP literal, or `*.suffix` (subdomains only, not the apex).
    pub host: String,
    /// Ports as `"80"` or `"8000-8999"`. Empty means any port.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<String>,
    /// Regex that must match the whole path (query string excluded). Omit for any path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeFile {
    #[serde(default)]
    rules: Vec<RuleSpec>,
}

/// Something a tool wants to contact.
#[derive(Debug, Clone, Copy)]
pub struct Target<'a> {
    /// Host name or IP literal (brackets allowed for IPv6).
    pub host: &'a str,
    /// TCP port.
    pub port: u16,
    /// Request path, optionally with a query string.
    pub path: &'a str,
}

/// Result of checking a target against a [`Scope`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// In scope; index of the include rule that matched.
    InScope(usize),
    /// An exclude rule matched; its index.
    Excluded(usize),
    /// No include rule matched.
    OutOfScope,
}

/// Per-run decision to go beyond the configured scope. Callers must pass it
/// explicitly; it is never stored in a scope.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RunOverride {
    /// Enforce scope.
    #[default]
    None,
    /// Allow targets that match no include rule. Explicit excludes still apply.
    AllowOutOfScope,
}

/// Scope errors.
#[derive(Debug, thiserror::Error)]
pub enum ScopeError {
    /// The host pattern is empty or malformed.
    #[error("invalid host pattern {0:?}")]
    BadHost(String),
    /// A port entry is not `N` or `LO-HI` within 1..=65535.
    #[error("invalid port {0:?}")]
    BadPort(String),
    /// The path regex failed to compile (or is too large).
    #[error("invalid path pattern: {0}")]
    BadPath(#[from] regex::Error),
    /// The scope file could not be parsed.
    #[error("scope file: {0}")]
    Parse(#[from] toml::de::Error),
    /// The scope could not be serialised.
    #[error("scope serialise: {0}")]
    Serialize(#[from] toml::ser::Error),
    /// The target is outside scope and no override was given.
    #[error("target {host}:{port} refused: {verdict:?}")]
    Refused {
        /// Target host.
        host: String,
        /// Target port.
        port: u16,
        /// Why it was refused.
        verdict: Verdict,
    },
}

#[derive(Debug, Clone)]
enum HostPat {
    Name(String),
    /// Stored with the leading dot, e.g. `.example.com`.
    Suffix(String),
    Ip(IpAddr),
}

/// A compiled rule.
#[derive(Debug, Clone)]
pub struct Rule {
    spec: RuleSpec,
    host: HostPat,
    ports: Vec<RangeInclusive<u16>>,
    path: Option<Regex>,
}

fn norm_host(h: &str) -> String {
    let h = h
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(h);
    h.strip_suffix('.').unwrap_or(h).to_ascii_lowercase()
}

fn norm_path(p: &str) -> &str {
    let p = p.split(['?', '#']).next().unwrap_or("");
    if p.is_empty() {
        "/"
    } else {
        p
    }
}

fn parse_ports(entry: &str) -> Result<RangeInclusive<u16>, ScopeError> {
    let bad = || ScopeError::BadPort(entry.to_string());
    let num = |s: &str| {
        s.trim()
            .parse::<u16>()
            .ok()
            .filter(|&n| n != 0)
            .ok_or_else(bad)
    };
    match entry.split_once('-') {
        None => num(entry).map(|n| n..=n),
        Some((lo, hi)) => {
            let (lo, hi) = (num(lo)?, num(hi)?);
            if lo > hi {
                return Err(bad());
            }
            Ok(lo..=hi)
        }
    }
}

impl Rule {
    /// Compile a rule, validating host, ports and path regex.
    pub fn new(spec: RuleSpec) -> Result<Self, ScopeError> {
        let bad_host = || ScopeError::BadHost(spec.host.clone());
        let h = norm_host(spec.host.trim());
        let host = if let Some(rest) = h.strip_prefix("*.") {
            if rest.is_empty() || rest.contains('*') || rest.starts_with('.') {
                return Err(bad_host());
            }
            HostPat::Suffix(format!(".{rest}"))
        } else if h.is_empty() || h.contains('*') {
            return Err(bad_host());
        } else if let Ok(ip) = h.parse::<IpAddr>() {
            HostPat::Ip(ip)
        } else {
            HostPat::Name(h)
        };
        let ports = spec
            .ports
            .iter()
            .map(|p| parse_ports(p))
            .collect::<Result<_, _>>()?;
        let path = spec
            .path
            .as_deref()
            .map(|p| {
                // Compile alone first: a pattern like `a)|(b` would otherwise
                // escape the full-match anchoring once wrapped.
                Regex::new(p)?;
                RegexBuilder::new(&format!("^(?:{p})$"))
                    .size_limit(1 << 20)
                    .build()
            })
            .transpose()?;
        Ok(Rule {
            spec,
            host,
            ports,
            path,
        })
    }

    /// The rule as written.
    pub fn spec(&self) -> &RuleSpec {
        &self.spec
    }

    fn matches(&self, t: &Target<'_>) -> bool {
        let host = norm_host(t.host);
        let host_ok = match &self.host {
            HostPat::Name(n) => *n == host,
            HostPat::Suffix(s) => host.len() > s.len() && host.ends_with(s.as_str()),
            HostPat::Ip(ip) => host.parse::<IpAddr>().is_ok_and(|h| h == *ip),
        };
        host_ok
            && (self.ports.is_empty() || self.ports.iter().any(|r| r.contains(&t.port)))
            && self
                .path
                .as_ref()
                .is_none_or(|re| re.is_match(norm_path(t.path)))
    }
}

/// An ordered set of include/exclude rules.
#[derive(Debug, Clone, Default)]
pub struct Scope {
    rules: Vec<Rule>,
}

impl Scope {
    /// An empty scope: nothing is in scope.
    pub fn new() -> Self {
        Self::default()
    }

    /// Compile and append a rule.
    pub fn push(&mut self, spec: RuleSpec) -> Result<(), ScopeError> {
        self.rules.push(Rule::new(spec)?);
        Ok(())
    }

    /// The compiled rules in order.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Parse a scope from TOML (`[[rules]]` tables). Unknown keys are errors.
    pub fn from_toml(s: &str) -> Result<Self, ScopeError> {
        let file: ScopeFile = toml::from_str(s)?;
        let mut scope = Scope::new();
        for spec in file.rules {
            scope.push(spec)?;
        }
        Ok(scope)
    }

    /// Serialise to TOML.
    pub fn to_toml(&self) -> Result<String, ScopeError> {
        let file = ScopeFile {
            rules: self.rules.iter().map(|r| r.spec.clone()).collect(),
        };
        Ok(toml::to_string(&file)?)
    }

    /// Classify a target. Excludes win, then the first matching include.
    pub fn check(&self, t: &Target<'_>) -> Verdict {
        let hit = |a: Action| {
            self.rules
                .iter()
                .position(|r| r.spec.action == a && r.matches(t))
        };
        if let Some(i) = hit(Action::Exclude) {
            Verdict::Excluded(i)
        } else if let Some(i) = hit(Action::Include) {
            Verdict::InScope(i)
        } else {
            Verdict::OutOfScope
        }
    }

    /// Gate for active tools. Out-of-scope targets pass only with
    /// [`RunOverride::AllowOutOfScope`]; explicit excludes never do.
    pub fn authorize(&self, t: &Target<'_>, ov: RunOverride) -> Result<(), ScopeError> {
        match (self.check(t), ov) {
            (Verdict::InScope(_), _) | (Verdict::OutOfScope, RunOverride::AllowOutOfScope) => {
                Ok(())
            }
            (verdict, _) => Err(ScopeError::Refused {
                host: t.host.to_string(),
                port: t.port,
                verdict,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn rule(action: Action, host: &str, ports: &[&str], path: Option<&str>) -> RuleSpec {
        RuleSpec {
            action,
            host: host.into(),
            ports: ports.iter().map(|s| s.to_string()).collect(),
            path: path.map(Into::into),
        }
    }

    fn scope(rules: Vec<RuleSpec>) -> Scope {
        let mut s = Scope::new();
        for r in rules {
            s.push(r).unwrap();
        }
        s
    }

    fn t<'a>(host: &'a str, port: u16, path: &'a str) -> Target<'a> {
        Target { host, port, path }
    }

    #[test]
    fn empty_scope_denies_everything() {
        assert_eq!(
            Scope::new().check(&t("example.com", 80, "/")),
            Verdict::OutOfScope
        );
    }

    #[test]
    fn exact_host_case_and_trailing_dot() {
        let s = scope(vec![rule(Action::Include, "Example.COM", &[], None)]);
        assert_eq!(s.check(&t("example.com", 1, "/")), Verdict::InScope(0));
        assert_eq!(s.check(&t("EXAMPLE.com.", 1, "/")), Verdict::InScope(0));
        assert_eq!(s.check(&t("www.example.com", 1, "/")), Verdict::OutOfScope);
    }

    #[test]
    fn wildcard_matches_subdomains_not_apex_or_lookalikes() {
        let s = scope(vec![rule(Action::Include, "*.example.com", &[], None)]);
        assert_eq!(s.check(&t("a.example.com", 80, "/")), Verdict::InScope(0));
        assert_eq!(s.check(&t("a.b.example.com", 80, "/")), Verdict::InScope(0));
        for bad in [
            "example.com",
            "evil-example.com",
            "example.com.evil.net",
            ".example.com",
            "xexample.com",
            "",
        ] {
            assert_eq!(s.check(&t(bad, 80, "/")), Verdict::OutOfScope, "{bad}");
        }
    }

    #[test]
    fn ports_and_ranges() {
        let s = scope(vec![rule(Action::Include, "h", &["80", "8000-8100"], None)]);
        for (p, ok) in [
            (80, true),
            (81, false),
            (8000, true),
            (8100, true),
            (8101, false),
        ] {
            assert_eq!(
                matches!(s.check(&t("h", p, "/")), Verdict::InScope(_)),
                ok,
                "{p}"
            );
        }
    }

    #[test]
    fn path_is_full_match_without_query() {
        let s = scope(vec![rule(Action::Include, "h", &[], Some("/api/.*"))]);
        assert_eq!(s.check(&t("h", 80, "/api/users?id=1")), Verdict::InScope(0));
        assert_eq!(s.check(&t("h", 80, "/api/")), Verdict::InScope(0));
        assert_eq!(s.check(&t("h", 80, "/x/api/users")), Verdict::OutOfScope);
        assert_eq!(s.check(&t("h", 80, "/api")), Verdict::OutOfScope);
        let root = scope(vec![rule(Action::Include, "h", &[], Some("/"))]);
        assert_eq!(root.check(&t("h", 80, "")), Verdict::InScope(0));
        assert_eq!(root.check(&t("h", 80, "?q=/api")), Verdict::InScope(0));
    }

    #[test]
    fn exclude_beats_include_regardless_of_order() {
        let inc = rule(Action::Include, "*.example.com", &[], None);
        let exc = rule(Action::Exclude, "admin.example.com", &[], None);
        for rules in [vec![inc.clone(), exc.clone()], vec![exc, inc]] {
            let s = scope(rules);
            assert!(matches!(
                s.check(&t("admin.example.com", 80, "/")),
                Verdict::Excluded(_)
            ));
            assert!(matches!(
                s.check(&t("www.example.com", 80, "/")),
                Verdict::InScope(_)
            ));
        }
    }

    #[test]
    fn ip_literals() {
        let s = scope(vec![
            rule(Action::Include, "127.0.0.1", &[], None),
            rule(Action::Include, "::1", &[], None),
        ]);
        assert!(matches!(
            s.check(&t("127.0.0.1", 80, "/")),
            Verdict::InScope(_)
        ));
        assert!(matches!(s.check(&t("[::1]", 80, "/")), Verdict::InScope(_)));
        assert!(matches!(
            s.check(&t("0:0:0:0:0:0:0:1", 80, "/")),
            Verdict::InScope(_)
        ));
        assert_eq!(s.check(&t("127.0.0.2", 80, "/")), Verdict::OutOfScope);
        assert_eq!(s.check(&t("localhost", 80, "/")), Verdict::OutOfScope);
    }

    #[test]
    fn authorize_override_never_bypasses_excludes() {
        let s = scope(vec![
            rule(Action::Include, "a", &[], None),
            rule(Action::Exclude, "b", &[], None),
        ]);
        let (a, b, c) = (t("a", 80, "/"), t("b", 80, "/"), t("c", 80, "/"));
        assert!(s.authorize(&a, RunOverride::None).is_ok());
        assert!(matches!(
            s.authorize(&c, RunOverride::None),
            Err(ScopeError::Refused {
                verdict: Verdict::OutOfScope,
                ..
            })
        ));
        assert!(s.authorize(&c, RunOverride::AllowOutOfScope).is_ok());
        assert!(s.authorize(&b, RunOverride::AllowOutOfScope).is_err());
    }

    #[test]
    fn invalid_rules_are_rejected() {
        for host in ["", "*", "*.", "a*.com", "*.*.com", "*..com"] {
            assert!(
                matches!(
                    Rule::new(rule(Action::Include, host, &[], None)),
                    Err(ScopeError::BadHost(_))
                ),
                "{host}"
            );
        }
        for p in ["0", "65536", "x", "9-1", "1-", "-1", ""] {
            assert!(
                matches!(
                    Rule::new(rule(Action::Include, "h", &[p], None)),
                    Err(ScopeError::BadPort(_))
                ),
                "{p}"
            );
        }
        assert!(matches!(
            Rule::new(rule(Action::Include, "h", &[], Some("(unclosed"))),
            Err(ScopeError::BadPath(_))
        ));
        assert!(matches!(
            Rule::new(rule(Action::Include, "h", &[], Some("a{1000}{1000}{1000}"))),
            Err(ScopeError::BadPath(_))
        ));
    }

    #[test]
    fn toml_round_trip_and_strictness() {
        let s = scope(vec![
            rule(
                Action::Include,
                "*.example.com",
                &["443", "8000-8999"],
                Some("/api/.*"),
            ),
            rule(Action::Exclude, "admin.example.com", &[], None),
        ]);
        let text = s.to_toml().unwrap();
        let back = Scope::from_toml(&text).unwrap();
        let specs = |s: &Scope| {
            s.rules()
                .iter()
                .map(|r| r.spec().clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(specs(&s), specs(&back));
        // A typo must not silently widen scope.
        assert!(
            Scope::from_toml("[[rules]]\naction = \"exclude\"\nhost = \"a\"\nport = [1]\n")
                .is_err()
        );
        assert!(Scope::from_toml("[[rules]]\naction = \"allow\"\nhost = \"a\"\n").is_err());
        assert!(Scope::from_toml("").unwrap().rules().is_empty());
    }

    proptest! {
        #[test]
        fn check_never_panics(host in ".{0,40}", path in ".{0,60}", port in any::<u16>()) {
            let s = scope(vec![
                rule(Action::Include, "*.example.com", &["1-65535"], Some(".*")),
                rule(Action::Include, "::1", &[], None),
                rule(Action::Exclude, "a.example.com", &[], Some("/x.*")),
            ]);
            let _ = s.check(&t(&host, port, &path));
        }

        #[test]
        fn adding_an_exclude_never_widens_scope(
            host in prop_oneof![Just("a.example.com".to_string()), Just("b.example.com".to_string()), "[a-c.]{0,12}"],
            port in prop_oneof![Just(80u16), Just(443u16), any::<u16>()],
            path in prop_oneof![Just("/".to_string()), Just("/x/y".to_string()), "[/a-c]{0,8}"],
            ex_host in prop_oneof![Just("a.example.com"), Just("*.example.com"), Just("b")],
        ) {
            let base = vec![rule(Action::Include, "*.example.com", &[], None), rule(Action::Include, "b", &["80"], None)];
            let before = scope(base.clone()).check(&t(&host, port, &path));
            let mut more = base;
            more.push(rule(Action::Exclude, ex_host, &[], None));
            let after = scope(more).check(&t(&host, port, &path));
            if !matches!(before, Verdict::InScope(_)) {
                prop_assert!(!matches!(after, Verdict::InScope(_)));
            }
        }
    }
}
