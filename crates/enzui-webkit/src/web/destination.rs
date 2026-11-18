//! Destination screening for embedded web content.
//!
//! Requests are screened before DNS, resolved addresses are validated and pinned before connection, and every redirect is screened again. The strict default permits only public HTTPS destinations; this module performs no I/O.

use std::net::{IpAddr, SocketAddr};

use enzui_security::url_policy::{AddressClass, RedirectDecision, SafeUrl, UrlPolicy, UrlVerdict};

/// Why a destination was refused, naming the stage that refused it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DestinationDenial {
    /// The URL string itself was refused before any lookup (bad scheme,
    /// cleartext, embedded credential, missing host, malformed).
    Url(UrlVerdict),
    /// The destination address - an IP literal in the URL, or one the caller
    /// resolved - is not a globally-routable public address.
    Address {
        /// The class that was refused.
        class: AddressClass,
    },
    /// The host resolved to nothing at all. Fail closed: an unresolvable host
    /// is not a permitted destination.
    Unresolvable,
    /// The URL named no port and its scheme has no default (only reachable for
    /// a scheme that already failed the screen).
    NoPort,
    /// A resolver returned an address for a different port than requested.
    ResolverPortMismatch,
}

impl DestinationDenial {
    /// A short, stable tag for a log line or a metric label.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            DestinationDenial::Url(verdict) => verdict.reason(),
            DestinationDenial::Address { .. } => "destination-not-public",
            DestinationDenial::Unresolvable => "destination-unresolvable",
            DestinationDenial::NoPort => "destination-no-port",
            DestinationDenial::ResolverPortMismatch => "resolver-port-mismatch",
        }
    }
}

/// Screens requested schemes and connected addresses; [`Default`] is the strict [`Self::DEFAULT`] policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DestinationPolicy {
    /// URL-stage rules shared with the workspace URL policy.
    pub url: UrlPolicy,
}

impl DestinationPolicy {
    /// The strict default: HTTPS only, public addresses only, 5 redirect hops.
    pub const DEFAULT: DestinationPolicy = DestinationPolicy {
        url: UrlPolicy::DEFAULT,
    };

    /// Permits host-supplied local content to use HTTP and private addresses; do not use for untrusted remote content.
    #[must_use]
    pub const fn trusted_local() -> DestinationPolicy {
        DestinationPolicy {
            url: UrlPolicy {
                allow_http: true,
                allow_private_network: true,
                max_redirects: UrlPolicy::DEFAULT.max_redirects,
            },
        }
    }

    /// Permits cleartext HTTP without permitting private-network destinations.
    #[must_use]
    pub const fn allowing_cleartext(self) -> DestinationPolicy {
        DestinationPolicy {
            url: UrlPolicy {
                allow_http: true,
                allow_private_network: self.url.allow_private_network,
                max_redirects: self.url.max_redirects,
            },
        }
    }

    /// Returns whether non-public destination addresses are permitted.
    #[must_use]
    pub const fn permits_private_network(&self) -> bool {
        self.url.allow_private_network
    }

    /// Screens a URL before DNS, rejecting private IP literals immediately and requiring named hosts to pass through [`Self::pin_destination`].
    ///
    /// # Errors
    /// Returns the [`DestinationDenial`] that refused the URL.
    pub fn screen_request(&self, url: &str) -> Result<SafeUrl, DestinationDenial> {
        let safe = self.url.check_url(url).map_err(DestinationDenial::Url)?;
        if let Some(addr) = literal_host(safe.host()) {
            self.screen_address(addr)?;
        }
        Ok(safe)
    }

    /// Stage 2 on one address: the connected-address verdict.
    ///
    /// # Errors
    ///
    /// [`DestinationDenial::Address`] with the class that was refused.
    pub fn screen_address(&self, addr: IpAddr) -> Result<(), DestinationDenial> {
        if self.url.check_address(addr).is_allowed() {
            Ok(())
        } else {
            Err(DestinationDenial::Address {
                class: AddressClass::of(addr),
            })
        }
    }

    /// Validates every resolver answer and returns the first address as the pinned connection target.
    ///
    /// # Errors
    /// Returns [`DestinationDenial::Unresolvable`] for an empty answer or [`DestinationDenial::Address`] for a refused address.
    pub fn pin_destination(
        &self,
        resolved: &[SocketAddr],
    ) -> Result<SocketAddr, DestinationDenial> {
        let first = *resolved.first().ok_or(DestinationDenial::Unresolvable)?;
        for addr in resolved {
            self.screen_address(addr.ip())?;
        }
        Ok(first)
    }

    /// As [`pin_destination`](Self::pin_destination), additionally requiring
    /// every resolver answer to retain the requested port.
    pub fn pin_destination_for_port(
        &self,
        resolved: &[SocketAddr],
        port: u16,
    ) -> Result<SocketAddr, DestinationDenial> {
        if resolved.iter().any(|addr| addr.port() != port) {
            return Err(DestinationDenial::ResolverPortMismatch);
        }
        self.pin_destination(resolved)
    }

    /// Screens a 1-based redirect hop using the same pre-DNS rules as an original request.
    ///
    /// # Errors
    /// Returns the [`DestinationDenial`] that refused the hop.
    pub fn screen_redirect(
        &self,
        from: &str,
        to: &str,
        hop: u32,
    ) -> Result<SafeUrl, DestinationDenial> {
        self.redirect_decision(from, to, hop)
            .map(|decision| decision.target)
    }

    /// Judge a redirect while preserving the credential-carry decision needed
    /// by a native transport.
    pub fn redirect_decision(
        &self,
        from: &str,
        to: &str,
        hop: u32,
    ) -> Result<RedirectDecision, DestinationDenial> {
        let decision = self
            .url
            .check_redirect(from, to, hop)
            .map_err(DestinationDenial::Url)?;
        // Redirect checking does not classify addresses, so private literals must be screened again here.
        if let Some(addr) = literal_host(decision.target.host()) {
            self.screen_address(addr)?;
        }
        Ok(decision)
    }

    /// The effective port for a screened URL (explicit, else the scheme
    /// default), for building the address to resolve.
    ///
    /// # Errors
    ///
    /// [`DestinationDenial::NoPort`] when the scheme has no default port.
    pub fn effective_port(&self, safe: &SafeUrl) -> Result<u16, DestinationDenial> {
        match safe.port() {
            Some(port) => Ok(port),
            None => match safe.scheme() {
                enzui_security::url_policy::Scheme::Https => Ok(443),
                enzui_security::url_policy::Scheme::Http => Ok(80),
                enzui_security::url_policy::Scheme::Other => Err(DestinationDenial::NoPort),
            },
        }
    }
}

impl Default for DestinationPolicy {
    fn default() -> Self {
        DestinationPolicy::DEFAULT
    }
}

/// Parse a host component that is already an IP literal.
///
/// Accepts the bracketed IPv6 form as well, because a host arriving from a
/// native engine callback may still carry its brackets even though
/// [`enzui_security::url_policy`]'s own parser strips them.
#[must_use]
pub fn literal_host(host: &str) -> Option<IpAddr> {
    let trimmed = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host);
    trimmed.parse::<IpAddr>().ok()
}
