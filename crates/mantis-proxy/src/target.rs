//! Work out where a proxied request is going.

use mantis_core::view::{Header, RequestView};

/// Destination of a request.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Dest {
    pub host: String,
    pub port: u16,
    /// Path and query as sent, starting with `/`.
    pub path: String,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Reject {
    /// `CONNECT` (needs HTTPS interception, not built yet).
    Connect,
    /// Unusable request line or missing host.
    Bad,
}

/// Resolve the destination from an absolute-form target (`http://host/path`)
/// or, for origin-form targets, the `Host` header. The raw request is not changed.
pub(crate) fn resolve(raw: &[u8], v: &RequestView) -> Result<Dest, Reject> {
    let slice = |r: &Option<std::ops::Range<usize>>| r.as_ref().map(|r| &raw[r.clone()]);
    if slice(&v.method) == Some(b"CONNECT") {
        return Err(Reject::Connect);
    }
    let target = slice(&v.target)
        .and_then(|t| std::str::from_utf8(t).ok())
        .ok_or(Reject::Bad)?;
    slice(&v.version).ok_or(Reject::Bad)?;
    if target.len() >= 7 && target[..7].eq_ignore_ascii_case("http://") {
        let rest = &target[7..];
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = rest[..end].rsplit('@').next().unwrap_or("");
        let (host, port) = host_port(authority)?;
        let tail = &rest[end..];
        let path = if tail.starts_with('/') {
            tail.to_string()
        } else {
            format!("/{tail}")
        };
        Ok(Dest { host, port, path })
    } else if target.starts_with('/') {
        let host_hdr = first_header(raw, &v.headers, b"host")
            .and_then(|h| std::str::from_utf8(h).ok())
            .ok_or(Reject::Bad)?;
        let (host, port) = host_port(host_hdr)?;
        Ok(Dest {
            host,
            port,
            path: target.to_string(),
        })
    } else {
        Err(Reject::Bad)
    }
}

fn first_header<'a>(raw: &'a [u8], headers: &[Header], name: &[u8]) -> Option<&'a [u8]> {
    headers
        .iter()
        .find(|h| raw[h.name.clone()].eq_ignore_ascii_case(name))
        .map(|h| &raw[h.value.clone()])
}

fn host_port(s: &str) -> Result<(String, u16), Reject> {
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (h, after) = rest.split_once(']').ok_or(Reject::Bad)?;
        (h, after.strip_prefix(':'))
    } else {
        match s.split_once(':') {
            None => (s, None),
            Some((_, p)) if p.contains(':') => return Err(Reject::Bad), // bare IPv6
            Some((h, p)) => (h, Some(p)),
        }
    };
    if host.is_empty() {
        return Err(Reject::Bad);
    }
    let port = match port {
        None => 80,
        Some(p) => p
            .parse::<u16>()
            .ok()
            .filter(|&p| p != 0)
            .ok_or(Reject::Bad)?,
    };
    Ok((host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(req: &str) -> Result<Dest, Reject> {
        resolve(req.as_bytes(), &RequestView::parse(req.as_bytes()))
    }

    fn dest(host: &str, port: u16, path: &str) -> Result<Dest, Reject> {
        Ok(Dest {
            host: host.into(),
            port,
            path: path.into(),
        })
    }

    #[test]
    fn absolute_form() {
        assert_eq!(
            r("GET http://a.com/x?y=1 HTTP/1.1\r\n\r\n"),
            dest("a.com", 80, "/x?y=1")
        );
        assert_eq!(
            r("GET HTTP://a.com:8080 HTTP/1.1\r\n\r\n"),
            dest("a.com", 8080, "/")
        );
        assert_eq!(
            r("GET http://a.com?q=1 HTTP/1.1\r\n\r\n"),
            dest("a.com", 80, "/?q=1")
        );
        assert_eq!(
            r("GET http://[::1]:9000/p HTTP/1.1\r\n\r\n"),
            dest("::1", 9000, "/p")
        );
        assert_eq!(
            r("GET http://user:pw@a.com/ HTTP/1.1\r\n\r\n"),
            dest("a.com", 80, "/")
        );
        // Userinfo trick: the host is what follows the last '@'.
        assert_eq!(
            r("GET http://good.com@evil.com/ HTTP/1.1\r\n\r\n"),
            dest("evil.com", 80, "/")
        );
    }

    #[test]
    fn origin_form_uses_host_header() {
        assert_eq!(
            r("GET /p HTTP/1.1\r\nHost: a.com:81\r\n\r\n"),
            dest("a.com", 81, "/p")
        );
        assert_eq!(r("GET /p HTTP/1.1\r\n\r\n"), Err(Reject::Bad));
    }

    #[test]
    fn rejects() {
        assert_eq!(
            r("CONNECT a.com:443 HTTP/1.1\r\n\r\n"),
            Err(Reject::Connect)
        );
        for bad in [
            "GET https://a.com/ HTTP/1.1\r\n\r\n",
            "GET * HTTP/1.1\r\n\r\n",
            "GET http:///x HTTP/1.1\r\n\r\n",
            "GET http://a.com:0/ HTTP/1.1\r\n\r\n",
            "GET http://a.com:99999/ HTTP/1.1\r\n\r\n",
            "GET http://::1/ HTTP/1.1\r\n\r\n",
            "GET http://a.com/",
            "",
        ] {
            assert_eq!(r(bad), Err(Reject::Bad), "{bad:?}");
        }
    }
}
