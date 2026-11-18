//! Stable identities for native compiled content-blocking rule caches.

/// Maximum UTF-8 source JSON size accepted for a compiled rule list (16 MiB).
pub const MAX_CONTENT_FILTER_JSON_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const FILTER_ID_PREFIX: &str = "enzui-rules-v1-";

/// Content-addressed identity for one exact UTF-8 JSON rule source.
///
/// Identities use a versioned prefix and a lowercase SHA-256 digest. They contain
/// no page URL or browsing history. Changing source whitespace changes the identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentFilterId(String);

impl ContentFilterId {
    /// Parse a previously stored cache identity without accepting arbitrary paths.
    ///
    /// # Errors
    /// Returns [`InvalidContentFilterId`] for another namespace, length or alphabet.
    pub fn parse(value: &str) -> Result<Self, InvalidContentFilterId> {
        let Some(digest) = value.strip_prefix(FILTER_ID_PREFIX) else {
            return Err(InvalidContentFilterId);
        };
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(InvalidContentFilterId);
        }
        Ok(Self(value.to_owned()))
    }

    /// The stable, filesystem-safe native cache identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ContentFilterId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A cache identifier outside the engine's content-addressed namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidContentFilterId;
impl std::fmt::Display for InvalidContentFilterId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid native content-filter cache identifier")
    }
}
impl std::error::Error for InvalidContentFilterId {}
