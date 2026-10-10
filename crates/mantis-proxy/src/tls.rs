//! TLS plumbing: per-host leaf cache, server-side resolver, upstream client config.

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use lru::LruCache;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ring, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};

use crate::ca::{Ca, CaError};

const LEAF_CACHE_SIZE: usize = 1024;
/// HTTP/2 is not implemented yet: offering only http/1.1 makes both sides
/// negotiate down (documented downgrade).
const ALPN: &[&[u8]] = &[b"http/1.1"];

fn provider() -> Arc<CryptoProvider> {
    Arc::new(ring::default_provider())
}

/// Everything needed to intercept TLS.
pub(crate) struct Mitm {
    pub certs: Arc<CertCache>,
    pub client: Arc<ClientConfig>,
}

/// Leaf certificates by host name, bounded LRU.
pub(crate) struct CertCache {
    ca: Arc<Ca>,
    cache: Mutex<LruCache<String, Arc<CertifiedKey>>>,
}

impl std::fmt::Debug for CertCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CertCache")
    }
}

impl CertCache {
    pub fn new(ca: Arc<Ca>) -> Self {
        let cap = NonZeroUsize::new(LEAF_CACHE_SIZE).unwrap_or(NonZeroUsize::MIN);
        CertCache {
            ca,
            cache: Mutex::new(LruCache::new(cap)),
        }
    }

    pub fn get(&self, name: &str) -> Result<Arc<CertifiedKey>, CaError> {
        let key = name.to_ascii_lowercase();
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(c) = cache.get(&key) {
            return Ok(c.clone());
        }
        let leaf = self.ca.leaf(&key)?;
        cache.put(key, leaf.clone());
        Ok(leaf)
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.cache.lock().map(|c| c.len()).unwrap_or(0)
    }
}

/// Picks the leaf by SNI, falling back to the `CONNECT` host (needed for IP targets).
#[derive(Debug)]
struct Resolver {
    certs: Arc<CertCache>,
    fallback: String,
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = hello.server_name().unwrap_or(&self.fallback);
        self.certs
            .get(name)
            .map_err(|e| tracing::warn!(%name, error = %e, "cannot issue certificate"))
            .ok()
    }
}

/// Server-side TLS config for one intercepted tunnel.
pub(crate) fn server_config(
    certs: Arc<CertCache>,
    fallback: &str,
) -> Result<Arc<ServerConfig>, rustls::Error> {
    let mut cfg = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Resolver {
            certs,
            fallback: fallback.to_string(),
        }));
    cfg.alpn_protocols = ALPN.iter().map(|p| p.to_vec()).collect();
    Ok(Arc::new(cfg))
}

/// Accepts any upstream certificate (still checks handshake signatures).
/// Only used when the user opts in with `insecure_upstream`.
#[derive(Debug)]
struct NoVerify(Arc<CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Client config for connections to origins: OS trust store plus `extra_roots`,
/// or no certificate verification when `insecure` is set.
pub(crate) fn client_config(
    insecure: bool,
    extra_roots: &[CertificateDer<'static>],
) -> Result<Arc<ClientConfig>, rustls::Error> {
    let builder =
        ClientConfig::builder_with_provider(provider()).with_safe_default_protocol_versions()?;
    let mut cfg = if insecure {
        tracing::warn!("upstream certificate verification is DISABLED (insecure_upstream)");
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider())))
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        let native = rustls_native_certs::load_native_certs();
        for e in &native.errors {
            tracing::warn!(error = %e, "skipping unreadable system certificate");
        }
        let (added, _) = roots.add_parsable_certificates(native.certs);
        for c in extra_roots {
            roots.add(c.clone())?;
        }
        if added + extra_roots.len() == 0 {
            tracing::warn!(
                "no trusted roots loaded; every upstream HTTPS connection will fail verification"
            );
        }
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    cfg.alpn_protocols = ALPN.iter().map(|p| p.to_vec()).collect();
    Ok(Arc::new(cfg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_reuses_and_is_case_insensitive() {
        let (ca, _) = Ca::generate().unwrap();
        let cache = CertCache::new(Arc::new(ca));
        let a = cache.get("Example.COM").unwrap();
        let b = cache.get("example.com").unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        cache.get("other.com").unwrap();
        assert_eq!(cache.len(), 2);
        assert!(cache.get("bad name").is_err());
        assert_eq!(cache.len(), 2);
    }
}
