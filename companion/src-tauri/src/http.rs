//! The one place HTTP clients are built: every caller states its timeout and its redirect policy.
//! Anything whose answer is checked or shown as fact (nodes, Esplora, NFT metadata, the attestation
//! status list) uses `Policy::none()`: the server is the URL that was asked, not wherever it points.

use reqwest::blocking::{Client, ClientBuilder};
pub use reqwest::redirect::Policy;
use std::time::Duration;

/// A builder with the timeout and redirect policy set (for callers that add more, e.g. a user agent).
pub fn builder(timeout: Duration, redirects: Policy) -> ClientBuilder {
    Client::builder().timeout(timeout).redirect(redirects)
}

pub fn client(timeout: Duration, redirects: Policy) -> Result<Client, String> {
    builder(timeout, redirects).build().map_err(|e| e.to_string())
}
