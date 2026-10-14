//! Origin normalization, display helpers and the registrable domain (site family).

/// The site's origin as the browser reported it (`MessageSender.origin` in the extension, never a
/// value from the page). Accepted: `https://host[:port]`, and `http://` only for localhost,
/// 127.0.0.1 and [::1] (local development). Hosts must be ASCII (IDNs arrive in punycode).
pub fn normalize_origin(s: &str) -> Result<String, String> {
    if s.is_empty() || s.len() > 270 {
        return Err("origin missing or too long".into());
    }
    let lower = s.to_ascii_lowercase();
    let (scheme, rest) = lower.split_once("://").ok_or("origin has no scheme")?;
    if scheme != "https" && scheme != "http" {
        return Err(format!("{scheme}: pages are not supported"));
    }
    if rest.is_empty()
        || rest.bytes().any(|b| matches!(b, b'/' | b'?' | b'#' | b'@' | b'\\' | b'%') || b <= b' ' || b >= 0x7f)
    {
        return Err("origin must be scheme://host[:port] only".into());
    }
    let (host, port) = if rest.starts_with('[') {
        let end = rest.find(']').ok_or("bad IPv6 origin")?;
        (&rest[..=end], &rest[end + 1..])
    } else {
        match rest.find(':') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        }
    };
    if !port.is_empty() {
        let digits = port.strip_prefix(':').ok_or("bad port")?;
        if digits.is_empty()
            || digits.len() > 5
            || !digits.bytes().all(|b| b.is_ascii_digit())
            || digits.starts_with('0')
        {
            return Err("bad port".into());
        }
        if digits.parse::<u32>().map_err(|_| "bad port")? > 65535 {
            return Err("bad port".into());
        }
    }
    let local = matches!(host, "localhost" | "127.0.0.1" | "[::1]");
    if host.starts_with('[') && host != "[::1]" {
        return Err("IPv6 literal origins are not supported".into());
    }
    if !host.starts_with('[') {
        if host.is_empty() || host.len() > 253 {
            return Err("bad host".into());
        }
        for label in host.split('.') {
            if label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                return Err(format!("bad host {host:?}"));
            }
        }
    }
    if scheme == "http" && !local {
        return Err("plain http:// sites are refused; only https:// (and localhost for development)".into());
    }
    Ok(format!("{scheme}://{host}{port}"))
}

/// "app.uniswap.org" from "https://app.uniswap.org" (port kept when present).
pub fn origin_host(origin: &str) -> String {
    origin.split_once("://").map(|(_, h)| h.to_string()).unwrap_or_else(|| origin.to_string())
}
pub fn origin_is_local(origin: &str) -> bool {
    origin.starts_with("http://")
}

/// Second-level labels under which countries (and a few hosting services) hand out names, so the
/// registrable domain is one label further left ("example.co.uk", "alice.github.io"). Deliberately
/// short, not the Public Suffix List: it only groups a site's subdomains for the waiting-request
/// cap and the connection backoff, and a miss errs towards treating two sites as one family.
const TWO_LABEL_SUFFIXES: [&str; 40] = [
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "me.uk",
    "ltd.uk",
    "plc.uk",
    "net.uk",
    "com.au",
    "net.au",
    "org.au",
    "edu.au",
    "co.nz",
    "org.nz",
    "co.jp",
    "ne.jp",
    "or.jp",
    "ac.jp",
    "co.kr",
    "or.kr",
    "com.br",
    "net.br",
    "com.cn",
    "net.cn",
    "com.hk",
    "com.sg",
    "com.tw",
    "co.in",
    "co.za",
    "com.mx",
    "com.tr",
    "com.ar",
    "co.il",
    "github.io",
    "vercel.app",
    "netlify.app",
    "pages.dev",
    "web.app",
    "firebaseapp.com",
    "herokuapp.com",
];

/// Registrable domain ("eTLD+1", simplified) of a normalized origin's host: the last two labels,
/// or three under a known two-label suffix (TWO_LABEL_SUFFIXES). Local and IP-literal origins are
/// their own host. The port is ignored.
pub fn registrable_domain(origin: &str) -> String {
    let auth = origin_host(origin);
    let host = if auth.starts_with('[') {
        auth.split_once(']').map(|(h, _)| format!("{h}]")).unwrap_or(auth.clone())
    } else {
        auth.split(':').next().unwrap_or("").to_string()
    };
    if host.starts_with('[') || host.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return host;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() <= 2 {
        return host;
    }
    let last2 = labels[labels.len() - 2..].join(".");
    let keep = if TWO_LABEL_SUFFIXES.contains(&last2.as_str()) { 3 } else { 2 };
    labels[labels.len().saturating_sub(keep)..].join(".")
}

pub(super) fn valid_method(m: &str) -> bool {
    !m.is_empty() && m.len() <= 64 && m.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins() {
        assert_eq!(normalize_origin("https://app.uniswap.org").unwrap(), "https://app.uniswap.org");
        assert_eq!(normalize_origin("HTTPS://App.Uniswap.ORG").unwrap(), "https://app.uniswap.org");
        assert_eq!(normalize_origin("https://example.org:8443").unwrap(), "https://example.org:8443");
        assert_eq!(normalize_origin("http://localhost:5173").unwrap(), "http://localhost:5173");
        assert_eq!(normalize_origin("http://127.0.0.1:8080").unwrap(), "http://127.0.0.1:8080");
        assert_eq!(normalize_origin("http://[::1]:3000").unwrap(), "http://[::1]:3000");
        assert_eq!(
            normalize_origin("https://xn--uniswp-9za.org").unwrap(),
            "https://xn--uniswp-9za.org",
            "punycode passes (shown as such)"
        );
        for bad in [
            "",
            "null",
            "app.uniswap.org",
            "http://app.uniswap.org",
            "file:///etc/passwd",
            "chrome-extension://abc",
            "javascript:alert(1)",
            "https://app.uniswap.org/",
            "https://app.uniswap.org/path",
            "https://user@app.uniswap.org",
            "https://app.uniswap.org?x",
            "https://app.uniswap.org#x",
            "https://ápp.org",
            "https://app uniswap.org",
            "https://-bad.org",
            "https://a..b",
            "https://x.org:0",
            "https://x.org:65536",
            "https://x.org:08",
            "https://x.org:",
            "https://[2001:db8::1]",
            "http://localhost.evil.org",
            "https://x.org%2f",
        ] {
            assert!(normalize_origin(bad).is_err(), "{bad:?} must be refused");
        }
        assert_eq!(origin_host("https://app.uniswap.org"), "app.uniswap.org");
        assert!(origin_is_local("http://localhost:1"));
        assert!(!origin_is_local("https://localhost"));
    }

    #[test]
    fn registrable_domains() {
        for (o, d) in [
            ("https://app.uniswap.org", "uniswap.org"),
            ("https://uniswap.org", "uniswap.org"),
            ("https://a.b.c.example.com:8443", "example.com"),
            ("https://shop.example.co.uk", "example.co.uk"),
            ("https://example.co.uk", "example.co.uk"),
            ("https://alice.github.io", "alice.github.io"),
            ("https://x.alice.github.io", "alice.github.io"),
            ("http://localhost:5173", "localhost"),
            ("http://127.0.0.1:8080", "127.0.0.1"),
            ("http://[::1]:3000", "[::1]"),
            ("https://com", "com"),
        ] {
            assert_eq!(registrable_domain(o), d, "{o}");
        }
    }
}
