//! Local certificate authority: generation, on-disk storage and leaf issuance.
//!
//! The CA private key lives only in `ca.key`, created with owner-only
//! permissions on Unix. It is never logged, printed or exported; `Ca`'s `Debug`
//! output shows only the certificate fingerprint.

use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

const CA_CN: &str = "Mantis Local CA";
const CA_DAYS: i64 = 3 * 365;
/// Browsers reject leaf certificates valid for more than 398 days.
const LEAF_DAYS: i64 = 365;
const CERT_FILE: &str = "ca.pem";
const KEY_FILE: &str = "ca.key";

/// CA errors.
#[derive(Debug, thiserror::Error)]
pub enum CaError {
    /// File system trouble.
    #[error("i/o on {path}: {source}")]
    Io {
        /// File involved.
        path: PathBuf,
        /// Underlying error.
        source: std::io::Error,
    },
    /// Certificate generation or parsing failed.
    #[error("certificate: {0}")]
    Cert(#[from] rcgen::Error),
    /// PEM/DER handling failed.
    #[error("pem: {0}")]
    Pem(#[from] rustls::pki_types::pem::Error),
    /// rustls rejected a key.
    #[error("tls: {0}")]
    Tls(#[from] rustls::Error),
    /// The key file can be read by other users.
    #[error("{0} is readable by group/others; run `chmod 600` on it (or delete the CA files to regenerate)")]
    KeyPermissions(PathBuf),
    /// One of the two CA files exists without the other.
    #[error("{0} exists but its counterpart is missing; refusing to overwrite. Delete both files to regenerate")]
    Incomplete(PathBuf),
    /// The requested leaf name is not usable.
    #[error("invalid host name for certificate: {0:?}")]
    BadName(String),
    /// No user data directory could be determined.
    #[error("cannot determine a user data directory; pass one explicitly")]
    NoDataDir,
}

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> CaError + '_ {
    move |source| CaError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// A local CA able to sign per-host leaf certificates.
pub struct Ca {
    issuer: Issuer<'static, KeyPair>,
    cert_pem: String,
    cert_der: CertificateDer<'static>,
}

impl std::fmt::Debug for Ca {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ca")
            .field("fingerprint", &self.fingerprint())
            .finish_non_exhaustive()
    }
}

fn ca_params() -> CertificateParams {
    let mut p = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, CA_CN);
    dn.push(DnType::OrganizationName, "Mantis");
    p.distinguished_name = dn;
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let now = OffsetDateTime::now_utc();
    p.not_before = now - Duration::days(1);
    p.not_after = now + Duration::days(CA_DAYS);
    p
}

impl Ca {
    /// Default CA directory: `<user data dir>/mantis/ca`.
    pub fn default_dir() -> Result<PathBuf, CaError> {
        dirs::data_dir()
            .map(|d| d.join("mantis").join("ca"))
            .ok_or(CaError::NoDataDir)
    }

    /// Generate a fresh CA. Returns the CA and its private key as PEM; the
    /// caller is responsible for storing the key safely.
    pub fn generate() -> Result<(Ca, String), CaError> {
        let key = KeyPair::generate()?;
        let params = ca_params();
        let cert = params.self_signed(&key)?;
        let key_pem = key.serialize_pem();
        let ca = Ca {
            cert_pem: cert.pem(),
            cert_der: cert.der().clone(),
            issuer: Issuer::new(params, key),
        };
        Ok((ca, key_pem))
    }

    /// Load the CA from `dir`, creating it (and the directory) if neither file exists.
    pub fn load_or_create(dir: &Path) -> Result<Ca, CaError> {
        let (cert_path, key_path) = (dir.join(CERT_FILE), dir.join(KEY_FILE));
        match (cert_path.exists(), key_path.exists()) {
            (true, true) => Self::load(&cert_path, &key_path),
            (false, false) => {
                create_private_dir(dir)?;
                let (ca, key_pem) = Self::generate()?;
                write_new(&key_path, key_pem.as_bytes(), true)?;
                write_new(&cert_path, ca.cert_pem.as_bytes(), false)?;
                Ok(ca)
            }
            (true, false) => Err(CaError::Incomplete(cert_path)),
            (false, true) => Err(CaError::Incomplete(key_path)),
        }
    }

    fn load(cert_path: &Path, key_path: &Path) -> Result<Ca, CaError> {
        check_key_permissions(key_path)?;
        let cert_pem = std::fs::read_to_string(cert_path).map_err(io(cert_path))?;
        let key_pem = std::fs::read_to_string(key_path).map_err(io(key_path))?;
        let key = KeyPair::from_pem(&key_pem)?;
        let cert_der = CertificateDer::from_pem_slice(cert_pem.as_bytes())?;
        // The issuer is rebuilt from the same parameters used at generation;
        // only the subject name, key usages and key matter for signing leaves.
        Ok(Ca {
            cert_pem,
            cert_der,
            issuer: Issuer::new(ca_params(), key),
        })
    }

    /// The CA certificate, PEM encoded (safe to share).
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// The CA certificate, DER encoded (safe to share).
    pub fn cert_der(&self) -> &CertificateDer<'static> {
        &self.cert_der
    }

    /// SHA-256 fingerprint of the CA certificate, as colon-separated hex.
    pub fn fingerprint(&self) -> String {
        let digest = Sha256::digest(self.cert_der.as_ref());
        digest
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }

    /// Issue a leaf certificate for a DNS name or IP literal.
    pub fn leaf(&self, name: &str) -> Result<Arc<CertifiedKey>, CaError> {
        let bad = || CaError::BadName(name.to_string());
        let san = match name.parse::<IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) if valid_dns_name(name) => SanType::DnsName(name.try_into().map_err(|_| bad())?),
            Err(_) => return Err(bad()),
        };
        let mut p = CertificateParams::default();
        p.subject_alt_names = vec![san];
        let mut dn = DistinguishedName::new();
        if name.len() <= 64 {
            dn.push(DnType::CommonName, name);
        }
        p.distinguished_name = dn;
        p.is_ca = IsCa::NoCa;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let now = OffsetDateTime::now_utc();
        p.not_before = now - Duration::days(1);
        p.not_after = now + Duration::days(LEAF_DAYS);
        let key = KeyPair::generate()?;
        let cert = p.signed_by(&key, &self.issuer)?;
        let der_key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let signer = rustls::crypto::ring::sign::any_supported_type(&der_key)?;
        Ok(Arc::new(CertifiedKey::new(
            vec![cert.der().clone()],
            signer,
        )))
    }
}

/// Letters, digits, hyphen, dot, underscore (seen in the wild); no empty labels.
fn valid_dns_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 253
        && n.split('.').all(|l| !l.is_empty() && l.len() <= 63)
        && n.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
}

fn create_private_dir(dir: &Path) -> Result<(), CaError> {
    std::fs::create_dir_all(dir).map_err(io(dir))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(io(dir))?;
    }
    Ok(())
}

/// Create `path` (failing if it exists), owner-only when `private`.
fn write_new(path: &Path, data: &[u8], private: bool) -> Result<(), CaError> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = private; // Windows: relies on the per-user profile ACL.
    let mut f = opts.open(path).map_err(io(path))?;
    f.write_all(data).map_err(io(path))
}

fn check_key_permissions(path: &Path) -> Result<(), CaError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map_err(io(path))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(CaError::KeyPermissions(path.to_path_buf()));
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::WebPkiServerVerifier;
    use rustls::pki_types::{ServerName, UnixTime};
    use rustls::RootCertStore;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("mantis-ca-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    /// Verify `leaf` for `name` against `ca` using rustls's real verifier.
    pub(crate) fn verifies(ca: &Ca, leaf: &CertifiedKey, name: &str) -> Result<(), rustls::Error> {
        let mut roots = RootCertStore::empty();
        roots.add(ca.cert_der().clone()).unwrap();
        let v = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .unwrap();
        let sn = ServerName::try_from(name.to_string()).unwrap();
        use rustls::client::danger::ServerCertVerifier;
        v.verify_server_cert(&leaf.cert[0], &[], &sn, &[], UnixTime::now())
            .map(|_| ())
    }

    #[test]
    fn create_then_reload_gives_the_same_ca() {
        let dir = tmp("reload");
        let a = Ca::load_or_create(&dir).unwrap();
        let b = Ca::load_or_create(&dir).unwrap();
        assert_eq!(a.fingerprint(), b.fingerprint());
        // A leaf issued by the reloaded CA must verify against the original certificate.
        let leaf = b.leaf("example.com").unwrap();
        verifies(&a, &leaf, "example.com").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn key_is_owner_only_and_loose_keys_are_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp("perms");
        Ca::load_or_create(&dir).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir.join(KEY_FILE)), 0o600);
        assert_eq!(mode(&dir), 0o700);
        std::fs::set_permissions(dir.join(KEY_FILE), std::fs::Permissions::from_mode(0o644))
            .unwrap();
        assert!(matches!(
            Ca::load_or_create(&dir),
            Err(CaError::KeyPermissions(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn half_present_ca_is_never_overwritten() {
        let dir = tmp("half");
        Ca::load_or_create(&dir).unwrap();
        std::fs::remove_file(dir.join(CERT_FILE)).unwrap();
        assert!(matches!(
            Ca::load_or_create(&dir),
            Err(CaError::Incomplete(_))
        ));
        assert!(dir.join(KEY_FILE).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn leaf_verifies_for_dns_and_ip_but_not_other_names() {
        let (ca, _) = Ca::generate().unwrap();
        let dns = ca.leaf("api.example.com").unwrap();
        verifies(&ca, &dns, "api.example.com").unwrap();
        assert!(verifies(&ca, &dns, "evil.com").is_err());
        let ip = ca.leaf("127.0.0.1").unwrap();
        verifies(&ca, &ip, "127.0.0.1").unwrap();
        assert!(verifies(&ca, &ip, "127.0.0.2").is_err());
        let ip6 = ca.leaf("::1").unwrap();
        verifies(&ca, &ip6, "::1").unwrap();
    }

    #[test]
    fn leaf_from_another_ca_does_not_verify() {
        let ((a, _), (b, _)) = (Ca::generate().unwrap(), Ca::generate().unwrap());
        assert!(verifies(&a, &b.leaf("x.com").unwrap(), "x.com").is_err());
    }

    #[test]
    fn bad_names_are_rejected() {
        let (ca, _) = Ca::generate().unwrap();
        for n in [
            "",
            "a b",
            "a..b",
            ".",
            "é.com",
            &"a".repeat(64),
            &format!("{}.com", "a.".repeat(130)),
        ] {
            assert!(matches!(ca.leaf(n), Err(CaError::BadName(_))), "{n:?}");
        }
    }

    #[test]
    fn ca_certificate_is_a_constrained_ca() {
        let (ca, _) = Ca::generate().unwrap();
        // BasicConstraints CA:TRUE, pathlen 0: DER contains the OID 2.5.29.19 and the INTEGER 0.
        let der = ca.cert_der().as_ref();
        let oid = [0x55, 0x1d, 0x13];
        let at = der
            .windows(3)
            .position(|w| w == oid)
            .expect("basicConstraints present");
        assert!(
            der[at..at + 16].windows(3).any(|w| w == [0x02, 0x01, 0x00]),
            "pathlen 0"
        );
    }

    #[test]
    fn debug_never_shows_key_material() {
        let (ca, key_pem) = Ca::generate().unwrap();
        let shown = format!("{ca:?}");
        assert!(!shown.contains("PRIVATE") && !shown.contains(key_pem.lines().nth(1).unwrap()));
    }
}
