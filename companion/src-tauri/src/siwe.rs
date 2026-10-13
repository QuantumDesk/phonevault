//! Sign-In with Ethereum (EIP-4361) phishing check. A sign-in message names the site it logs you
//! into ("<domain> wants you to sign in with your Ethereum account:"); a page that asks you to sign
//! one for ANOTHER domain is trying to log in as you somewhere else. The companion knows which site
//! asked (the browser-reported origin, or WalletConnect Verify's origin when it says VALID) and
//! refuses a mismatch before anything reaches the phone. Without a trusted origin it only warns.
//!
//! Only what the check needs is parsed: the first line (optional `scheme://`, authority) and the
//! `URI:` line. The phone and the Mac's review parse the whole grammar separately.

const SUFFIX: &str = " wants you to sign in with your Ethereum account:";

#[derive(Debug, Clone, PartialEq)]
pub struct SignIn {
    /// Scheme written before the domain (EIP-4361 allows `https://example.com wants you …`).
    pub scheme: Option<String>,
    /// host[:port] as written, lowercase.
    pub authority: String,
    /// The `URI:` line's value, if present.
    pub uri: Option<String>,
}

/// The sign-in fields of `text`, or None when it is not an EIP-4361 message.
pub fn parse(text: &str) -> Option<SignIn> {
    let text = text.trim_start_matches(|c: char| c.is_whitespace() || c == '\u{feff}');
    let first = text.split('\n').next()?.trim_end_matches('\r');
    let head = first.strip_suffix(SUFFIX)?;
    if head.is_empty() || head.len() > 300 || head.chars().any(|c| c.is_whitespace() || c.is_control()) { return None; }
    let (scheme, authority) = match head.split_once("://") {
        Some((s, a)) => (Some(s.to_ascii_lowercase()), a),
        None => (None, head),
    };
    // userinfo is not part of the site's identity
    let authority = authority.rsplit_once('@').map(|(_, a)| a).unwrap_or(authority).to_ascii_lowercase();
    if authority.is_empty() { return None; }
    let uri = text.split('\n').map(|l| l.trim_end_matches('\r')).find_map(|l| l.strip_prefix("URI: ")).map(str::to_string);
    Some(SignIn { scheme, authority, uri })
}

/// host[:port] with the scheme's default port removed.
fn canonical_authority(authority: &str, scheme: &str) -> String {
    let a = authority.to_ascii_lowercase();
    let default = match scheme { "https" => ":443", "http" => ":80", _ => "" };
    match a.strip_suffix(default) { Some(h) if !default.is_empty() => h.to_string(), _ => a }
}

fn host_only(authority: &str) -> &str {
    if authority.starts_with('[') { return authority.split_once(']').map(|(h, _)| &authority[..=h.len()]).unwrap_or(authority); }
    authority.split(':').next().unwrap_or(authority)
}

/// (scheme, authority) of an http(s) URI; None for other schemes or junk.
fn uri_authority(uri: &str) -> Option<(String, String)> {
    let (scheme, rest) = uri.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "https" && scheme != "http" { return None; }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let auth = &rest[..end];
    let auth = auth.rsplit_once('@').map(|(_, a)| a).unwrap_or(auth);
    Some((scheme, auth.to_ascii_lowercase()))
}

#[derive(Debug, Clone, PartialEq)]
pub enum Check {
    /// Not a sign-in message.
    NotSignIn,
    /// A sign-in for the site that asked.
    Matches { domain: String },
    /// A sign-in, but no trusted origin to compare with.
    Unverified { domain: String },
    /// A sign-in for another site: refuse.
    Mismatch { domain: String, site: String },
}

/// Compare a message with the site that asked. `origin`: normalized `scheme://host[:port]`
/// (bridge::normalize_origin) when it is trusted (browser-reported, or WalletConnect Verify VALID).
pub fn check(text: &str, origin: Option<&str>) -> Check {
    let Some(s) = parse(text) else { return Check::NotSignIn };
    let domain = s.authority.clone();
    let Some(origin) = origin else { return Check::Unverified { domain } };
    let Some((o_scheme, o_auth)) = origin.split_once("://") else { return Check::Unverified { domain } };
    let site = crate::bridge::origin_host(origin);
    let mismatch = || Check::Mismatch { domain: domain.clone(), site: site.clone() };
    if let Some(sc) = &s.scheme { if sc != o_scheme { return mismatch(); } }
    // without a scheme in the message the site's scheme decides the default port
    if canonical_authority(&s.authority, s.scheme.as_deref().unwrap_or(o_scheme)) != canonical_authority(o_auth, o_scheme) { return mismatch(); }
    if let Some((_, u_auth)) = s.uri.as_deref().and_then(uri_authority) {
        if host_only(&u_auth) != host_only(o_auth) { return mismatch(); }
    }
    Check::Matches { domain }
}

/// What the site and the user are told when a sign-in is for another site.
pub fn blocked_message(site: &str, domain: &str) -> String {
    format!("Blocked: {site} asked you to sign in to {domain}. Phone Vault refuses sign-in messages for a different site than the one asking.")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(domain: &str, uri: &str) -> String {
        format!("{domain} wants you to sign in with your Ethereum account:\n0x7a3B9c1D2E4F5061728394a5B6c7D8e9F0A1B2c3\n\nSign in to the app.\n\nURI: {uri}\nVersion: 1\nChain ID: 1\nNonce: 32891756\nIssued At: 2021-09-30T16:25:24Z")
    }

    #[test]
    fn parses_the_first_line_and_uri() {
        let s = parse(&msg("app.uniswap.org", "https://app.uniswap.org/login")).unwrap();
        assert_eq!((s.scheme, s.authority.as_str(), s.uri.as_deref()), (None, "app.uniswap.org", Some("https://app.uniswap.org/login")));
        let s = parse(&msg("https://Example.com:8443", "https://example.com:8443")).unwrap();
        assert_eq!((s.scheme.as_deref(), s.authority.as_str()), (Some("https"), "example.com:8443"));
        assert!(parse("Hello world").is_none());
        assert!(parse("please sign: example.com wants you to sign in with your Ethereum account:").is_none(), "spaces in the domain");
        assert!(parse(&msg("app.uniswap.org", "x").replacen('\n', "\r\n", 1)).is_some(), "CRLF");
        assert!(parse(&format!("\u{feff}  {}", msg("a.org", "https://a.org"))).is_some(), "leading BOM/whitespace does not hide it");
    }

    #[test]
    fn matches_mismatches_and_unverified() {
        let o = Some("https://app.uniswap.org");
        assert_eq!(check("gm", o), Check::NotSignIn);
        assert_eq!(check(&msg("app.uniswap.org", "https://app.uniswap.org"), o), Check::Matches { domain: "app.uniswap.org".into() });
        assert_eq!(check(&msg("APP.UNISWAP.ORG:443", "https://app.uniswap.org/x"), o), Check::Matches { domain: "app.uniswap.org:443".into() });
        assert_eq!(check(&msg("https://app.uniswap.org", "https://app.uniswap.org"), o), Check::Matches { domain: "app.uniswap.org".into() });
        // another site, a subdomain, a parent domain, a lookalike: refused
        for d in ["opensea.io", "evil.app.uniswap.org", "uniswap.org", "app.uniswap.org.evil.com", "app.uniswap.org:8443"] {
            assert!(matches!(check(&msg(d, "https://app.uniswap.org"), o), Check::Mismatch { .. }), "{d}");
        }
        // right domain, URI on another host
        assert!(matches!(check(&msg("app.uniswap.org", "https://opensea.io/login"), o), Check::Mismatch { .. }));
        // scheme written in the message must be the site's
        assert!(matches!(check(&msg("http://app.uniswap.org", "https://app.uniswap.org"), o), Check::Mismatch { .. }));
        // non-http URIs are not compared (the domain still is)
        assert!(matches!(check(&msg("app.uniswap.org", "did:key:z6Mk"), o), Check::Matches { .. }));
        // local development page with a port
        let l = Some("http://localhost:3000");
        assert!(matches!(check(&msg("localhost:3000", "http://localhost:3000"), l), Check::Matches { .. }));
        assert!(matches!(check(&msg("localhost:3001", "http://localhost:3001"), l), Check::Mismatch { .. }));
        // no trusted origin
        assert_eq!(check(&msg("opensea.io", "https://opensea.io"), None), Check::Unverified { domain: "opensea.io".into() });
        assert_eq!(blocked_message("evil.com", "opensea.io"), "Blocked: evil.com asked you to sign in to opensea.io. Phone Vault refuses sign-in messages for a different site than the one asking.");
    }
}
