//! Proxy settings as edited in the UI, validated into what the backend starts with.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use mantis_core::Scope;

/// Everything the backend needs to start the proxy.
#[derive(Debug, Clone)]
pub struct StartConfig {
    /// Project database.
    pub db: PathBuf,
    /// Address to listen on.
    pub listen: SocketAddr,
    /// Listening beyond loopback was explicitly allowed.
    pub allow_non_loopback: bool,
    /// Origin certificates are not verified.
    pub insecure_upstream: bool,
    /// CA directory; `None` for the default.
    pub ca_dir: Option<PathBuf>,
    /// Scope at start (`None`: everything).
    pub scope: Option<Scope>,
}

/// The proxy form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxySettings {
    /// `ip:port` text.
    pub listen: String,
    /// Allow a non-loopback listen address.
    pub allow_non_loopback: bool,
    /// Skip origin certificate verification. Never remembered between runs.
    pub insecure_upstream: bool,
    /// CA directory text; empty for the default.
    pub ca_dir: String,
}

impl Default for ProxySettings {
    fn default() -> Self {
        ProxySettings {
            listen: "127.0.0.1:8080".into(),
            allow_non_loopback: false,
            insecure_upstream: false,
            ca_dir: String::new(),
        }
    }
}

impl ProxySettings {
    /// Validate the form into a start configuration.
    pub fn to_start(&self, db: &Path, scope: Option<Scope>) -> Result<StartConfig, String> {
        let listen: SocketAddr = self.listen.trim().parse().map_err(|_| {
            format!(
                "listen address {:?} must look like 127.0.0.1:8080 or [::1]:8080",
                self.listen.trim()
            )
        })?;
        if !listen.ip().is_loopback() && !self.allow_non_loopback {
            return Err(format!("{listen} is not a loopback address: anyone who can reach it could send traffic through this proxy. Tick \"Allow network access\" to do it anyway"));
        }
        let ca_dir = Some(self.ca_dir.trim())
            .filter(|d| !d.is_empty())
            .map(PathBuf::from);
        Ok(StartConfig {
            db: db.to_path_buf(),
            listen,
            allow_non_loopback: self.allow_non_loopback,
            insecure_upstream: self.insecure_upstream,
            ca_dir,
            scope,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> PathBuf {
        PathBuf::from("p.db")
    }

    #[test]
    fn defaults_are_loopback_and_verifying() {
        let s = ProxySettings::default();
        let c = s.to_start(&db(), None).unwrap();
        assert_eq!(
            (
                c.listen.to_string().as_str(),
                c.allow_non_loopback,
                c.insecure_upstream,
                c.ca_dir
            ),
            ("127.0.0.1:8080", false, false, None)
        );
    }

    #[test]
    fn bad_addresses_and_exposure_are_refused_with_a_reason() {
        for bad in ["", "8080", "localhost:8080", "127.0.0.1", "1.2.3.4:99999"] {
            let e = ProxySettings {
                listen: bad.into(),
                ..Default::default()
            }
            .to_start(&db(), None)
            .unwrap_err();
            assert!(e.contains("must look like"), "{bad}: {e}");
        }
        let open = ProxySettings {
            listen: "0.0.0.0:8080".into(),
            ..Default::default()
        };
        assert!(open
            .to_start(&db(), None)
            .unwrap_err()
            .contains("not a loopback"));
        assert!(ProxySettings {
            allow_non_loopback: true,
            ..open
        }
        .to_start(&db(), None)
        .is_ok());
        assert!(ProxySettings {
            listen: " [::1]:9 ".into(),
            ..Default::default()
        }
        .to_start(&db(), None)
        .is_ok());
    }

    #[test]
    fn ca_dir_blank_means_default() {
        let s = ProxySettings {
            ca_dir: "  /tmp/ca ".into(),
            ..Default::default()
        };
        assert_eq!(
            s.to_start(&db(), None).unwrap().ca_dir,
            Some(PathBuf::from("/tmp/ca"))
        );
        assert_eq!(
            ProxySettings {
                ca_dir: "   ".into(),
                ..Default::default()
            }
            .to_start(&db(), None)
            .unwrap()
            .ca_dir,
            None
        );
    }
}
