//! The scope rule table as edited in the UI.

use mantis_core::{Action, RuleSpec, Scope};
use serde::{Deserialize, Serialize};

/// One editable rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleRow {
    /// Include (true) or exclude (false).
    pub include: bool,
    /// Host, IP, or `*.suffix`.
    pub host: String,
    /// Comma-separated ports and ranges, e.g. `80, 8000-8100`. Empty: any.
    pub ports: String,
    /// Path regex that must match the whole path. Empty: any.
    pub path: String,
}

impl Default for RuleRow {
    fn default() -> Self {
        RuleRow {
            include: true,
            host: String::new(),
            ports: String::new(),
            path: String::new(),
        }
    }
}

impl RuleRow {
    fn spec(&self) -> RuleSpec {
        RuleSpec {
            action: if self.include {
                Action::Include
            } else {
                Action::Exclude
            },
            host: self.host.trim().to_string(),
            ports: self
                .ports
                .split(',')
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(str::to_string)
                .collect(),
            path: Some(self.path.trim())
                .filter(|p| !p.is_empty())
                .map(str::to_string),
        }
    }

    fn from_spec(s: &RuleSpec) -> Self {
        RuleRow {
            include: s.action == Action::Include,
            host: s.host.clone(),
            ports: s.ports.join(", "),
            path: s.path.clone().unwrap_or_default(),
        }
    }
}

/// The rules plus whether scope is switched on.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ScopeEditor {
    /// Restrict logging, interception and rewriting to the rules. Off: everything is in scope.
    pub enabled: bool,
    /// The rules, in order.
    pub rows: Vec<RuleRow>,
}

impl ScopeEditor {
    /// Problem with each row, or `None` where it is fine.
    pub fn row_errors(&self) -> Vec<Option<String>> {
        self.rows
            .iter()
            .map(|r| Scope::new().push(r.spec()).err().map(|e| e.to_string()))
            .collect()
    }

    /// The scope to apply: `None` when switched off, an error per bad row otherwise.
    pub fn compile(&self) -> Result<Option<Scope>, Vec<(usize, String)>> {
        if !self.enabled {
            return Ok(None);
        }
        let errors: Vec<_> = self
            .row_errors()
            .into_iter()
            .enumerate()
            .filter_map(|(i, e)| e.map(|e| (i, e)))
            .collect();
        if !errors.is_empty() {
            return Err(errors);
        }
        let mut scope = Scope::new();
        for r in &self.rows {
            scope.push(r.spec()).map_err(|e| vec![(0, e.to_string())])?;
        }
        Ok(Some(scope))
    }

    /// Replace the rules from TOML and switch scope on.
    pub fn load_toml(&mut self, text: &str) -> Result<(), String> {
        let scope = Scope::from_toml(text).map_err(|e| e.to_string())?;
        self.rows = scope
            .rules()
            .iter()
            .map(|r| RuleRow::from_spec(r.spec()))
            .collect();
        self.enabled = true;
        Ok(())
    }

    /// The rules as TOML; fails while any row is invalid.
    pub fn to_toml(&self) -> Result<String, String> {
        let mut scope = Scope::new();
        for (i, r) in self.rows.iter().enumerate() {
            scope
                .push(r.spec())
                .map_err(|e| format!("rule {}: {e}", i + 1))?;
        }
        scope.to_toml().map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use mantis_core::{Target, Verdict};

    use super::*;

    fn row(include: bool, host: &str, ports: &str, path: &str) -> RuleRow {
        RuleRow {
            include,
            host: host.into(),
            ports: ports.into(),
            path: path.into(),
        }
    }

    fn verdict(s: &Scope, host: &str, port: u16, path: &str) -> Verdict {
        s.check(&Target { host, port, path })
    }

    #[test]
    fn rows_compile_into_a_working_scope() {
        let e = ScopeEditor {
            enabled: true,
            rows: vec![
                row(true, " *.example.com ", "443, 8000-8100", "/api/.*"),
                row(false, "admin.example.com", "", ""),
            ],
        };
        let s = e.compile().unwrap().unwrap();
        assert!(matches!(
            verdict(&s, "a.example.com", 8050, "/api/x"),
            Verdict::InScope(0)
        ));
        assert_eq!(
            verdict(&s, "a.example.com", 80, "/api/x"),
            Verdict::OutOfScope
        );
        assert!(matches!(
            verdict(&s, "admin.example.com", 443, "/api/x"),
            Verdict::Excluded(1)
        ));
    }

    #[test]
    fn switched_off_means_everything_and_empty_means_nothing() {
        assert!(ScopeEditor::default().compile().unwrap().is_none());
        let on_but_empty = ScopeEditor {
            enabled: true,
            rows: vec![],
        };
        let s = on_but_empty.compile().unwrap().unwrap();
        assert_eq!(verdict(&s, "anything", 80, "/"), Verdict::OutOfScope);
    }

    #[test]
    fn each_bad_row_gets_its_own_message() {
        let e = ScopeEditor {
            enabled: true,
            rows: vec![
                row(true, "ok.com", "", ""),
                row(true, "", "", ""),
                row(true, "a.com", "99999", ""),
                row(true, "b.com", "", "("),
            ],
        };
        let errs = e.row_errors();
        assert!(errs[0].is_none());
        assert!(errs[1].as_ref().unwrap().contains("host"));
        assert!(errs[2].as_ref().unwrap().contains("port"));
        assert!(errs[3].as_ref().unwrap().contains("path"));
        let Err(list) = e.compile() else {
            panic!("must not compile")
        };
        assert_eq!(list.iter().map(|x| x.0).collect::<Vec<_>>(), [1, 2, 3]);
        assert!(e.to_toml().unwrap_err().contains("rule 2"));
        // A switched-off scope ignores broken rows until it is switched on.
        assert!(ScopeEditor {
            enabled: false,
            ..e
        }
        .compile()
        .unwrap()
        .is_none());
    }

    #[test]
    fn toml_round_trip_and_typos() {
        let e = ScopeEditor {
            enabled: true,
            rows: vec![
                row(true, "a.com", "80,443", "/x"),
                row(false, "*.b.com", "", ""),
            ],
        };
        let text = e.to_toml().unwrap();
        let mut back = ScopeEditor::default();
        back.load_toml(&text).unwrap();
        assert!(back.enabled);
        assert_eq!(back.rows[0], row(true, "a.com", "80, 443", "/x"));
        assert_eq!(back.rows[1], row(false, "*.b.com", "", ""));
        let before = back.clone();
        assert!(back
            .load_toml("[[rules]]\naction = \"include\"\nhost = \"a\"\nport = [1]\n")
            .is_err());
        assert_eq!(back, before, "a failed load changes nothing");
    }
}
