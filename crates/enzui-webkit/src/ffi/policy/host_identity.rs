use super::*;

pub(super) fn diagnostic_url(uri: &str) -> PolicyUrl {
    let mut redacted = PolicyUrl::new(uri).redacted();
    truncate_utf8(&mut redacted, CertificateLedger::URL_MAX);
    // Redaction can turn a very large query into a short string while leaving
    // its old allocation capacity behind. Re-box so diagnostics retain only
    // the bounded representation, not that hostile spare capacity.
    PolicyUrl::new(compact_string(&redacted))
}

pub(super) fn truncate_utf8(value: &mut String, max: usize) {
    if value.len() <= max {
        return;
    }
    let mut end = max;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
}

/// The one certificate-authorization host parser, shared by both
/// installers: the native `load-failed-with-tls-errors` continuation and the
/// public host-initiated pre-trust.
///
/// It answers a single question: can this string be the identity WebKit
/// compares when it looks for a per-host certificate exception? WebKit
/// compares against the request URL's host with IPv6 brackets already
/// stripped, ASCII-case-insensitively and byte-for-byte otherwise. So:
///
/// * every non-host form is refused with a named [`CertificateHostError`] -
///   empty, URL/scheme spellings, userinfo, path/query/fragment, a port,
///   unbalanced brackets, over-limit length, malformed DNS/IP shape;
/// * a bracketed IPv6 spelling is refused, because WebKit documents the bare
///   address (`::1`) and compares against the request host with its brackets
///   already stripped - use
///   `certificate_authorization_host_from_url` when the host came out of a
///   URL authority, which is where the brackets legitimately appear;
/// * alternate numeric hosts are refused. WHATWG special-host parsing treats
///   a domain whose final label "ends in a number" as IPv4 input, normalizing
///   spellings such as `127.1` and `0xffffffff` and rejecting malformed ones
///   such as `09`. Only Rust's strict canonical dotted-quad IPv4 spelling is
///   accepted here;
/// * noncanonical IPv6 is refused. WHATWG/WebKit serialize IPv6 addresses
///   in RFC 5952 compressed form using only hex pieces (never dotted IPv4
///   notation), so expanded (`0:0:0:0:0:0:0:1`), leading-zero (`0000::1`),
///   and the dotted IPv4-mapped form (`::ffff:127.0.0.1` - WHATWG canonical
///   is `::ffff:7f00:1`) would install an identity `URL::host()` never
///   produces. A dedicated WHATWG eight-hex-piece serializer
///   (`whatwg_ipv6_serializer`) is used instead of Rust's `Display` (which
///   differs for IPv4-mapped addresses). The WHATWG canonical serialization
///   must equal the input modulo ASCII case (`FE80::1` matches `fe80::1`
///   under WebKit's documented case-insensitive comparison);
/// * nothing is rewritten. A trailing DNS-root dot is preserved for DNS
///   names, because `example.com.` and `example.com` are different
///   `URL::host()` strings and WebKit does not fold them. Folding here would
///   install an exception under a name WebKit never asks for.
///
/// The equivalence fold lives in `canonicalize_authority_host` and is used
/// only as a retry-budget/ledger correlation key, never as the authorization
/// identity.
///
/// # Errors
///
/// [`CertificateHostError`] naming the first violated rule.
pub fn certificate_authorization_host(host: &str) -> Result<&str, CertificateHostError> {
    if host.is_empty() {
        return Err(CertificateHostError::Empty);
    }
    // Scanned before anything else: these bytes mean the caller passed a URL
    // (or an authority) where a host identity was required, and every one of
    // them makes equality with `URL::host()` impossible.
    if host.contains("//") || host.contains("://") {
        return Err(CertificateHostError::UrlForm);
    }
    if host.contains(['/', '\\']) || host.contains('?') || host.contains('#') {
        return Err(CertificateHostError::PathQueryOrFragment);
    }
    if host.contains('@') {
        return Err(CertificateHostError::UserInfo);
    }

    if host.contains(['[', ']']) {
        return Err(CertificateHostError::BracketedIpv6);
    }
    let host = if host.contains(':') {
        // A colon is either an unbracketed IPv6 literal (a valid identity: it
        // is what WebKit compares once it has stripped brackets) or a port.
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(CertificateHostError::Port);
        }
        host
    } else {
        host
    };

    if host.len() > MAX_CERTIFICATE_HOST_BYTES {
        return Err(CertificateHostError::TooLong);
    }

    // WebKit supplies an ASCII DNS name (IDNs already in their ASCII form) or
    // an IP literal. Admit an IPv4 spelling only when Rust's parser and
    // canonical serializer reproduce it exactly, before applying WHATWG's
    // broader special-host boundary: canonical `127.0.0.1` also "ends in a
    // number", but unlike `127.1`, `0177.0.0.1`, or `0xffffffff` it needs no
    // WebKit rewrite.
    if let Ok(address) = host.parse::<std::net::Ipv4Addr>() {
        return if address.to_string() == host {
            Ok(host)
        } else {
            Err(CertificateHostError::InvalidShape)
        };
    }
    if let Ok(address) = host.parse::<std::net::Ipv6Addr>() {
        // Same rule as IPv4: the WHATWG canonical serialization must equal the
        // input modulo ASCII case. WHATWG URL host serialization compresses
        // IPv6 addresses per RFC 5952 using only hex pieces, so
        // `0:0:0:0:0:0:0:1`, `::0:1`, leading-zero, and the dotted
        // IPv4-mapped form `::ffff:127.0.0.1` (WHATWG canonical:
        // `::ffff:7f00:1`) would install an identity `URL::host()` never
        // produces. WebKit compares case-insensitively, so `FE80::1` matches
        // `fe80::1`.
        //
        // Rust's `Ipv6Addr::Display` uses dotted notation for IPv4-mapped
        // addresses, diverging from WHATWG. This code uses a dedicated WHATWG
        // eight-hex-piece serializer from `segments()` instead.
        let canonical = whatwg_ipv6_serializer(&address);
        return if canonical.eq_ignore_ascii_case(host) {
            Ok(host)
        } else {
            Err(CertificateHostError::InvalidShape)
        };
    }
    if whatwg_domain_ends_in_number(host) {
        return Err(CertificateHostError::InvalidShape);
    }

    // Validate DNS shape before allocation; accepting an arbitrary reg-name
    // would let an installer authorize a name no request can ever carry.
    // A single trailing root dot is part of the identity, not a label.
    let dns = host.strip_suffix('.').unwrap_or(host);
    if dns.is_empty()
        || !dns.is_ascii()
        || dns.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(CertificateHostError::InvalidShape);
    }
    Ok(host)
}

/// WHATWG URL Standard IPv6 serializer: eight hex pieces, RFC 5952 `::` compression.
///
/// Rust's `Ipv6Addr::Display` uses dotted IPv4 notation for IPv4-mapped and
/// IPv4-compatible addresses (`::ffff:127.0.0.1`), while WHATWG always serializes
/// all eight 16-bit pieces as lowercase hex (`::ffff:7f00:1`). This function
/// follows the WHATWG spec exactly so the certificate-authorization parser can
/// compare against the identity WebKit's `URL::host()` produces.
///
/// <https://url.spec.whatwg.org/#concept-ipv6-serializer>
pub(super) fn whatwg_ipv6_serializer(address: &std::net::Ipv6Addr) -> String {
    let pieces = address.segments();

    // Find the start and length of the first longest run of consecutive zero
    // pieces (the compress target). Ties go to the earliest run.
    // RFC 5952 §4.2.3: `::` must not compress a single 16-bit 0 field.
    let (mut compress_start, mut compress_len): (Option<usize>, usize) = (None, 0);
    let mut run_start: Option<usize> = None;
    for (i, &piece) in pieces.iter().enumerate() {
        if piece == 0 {
            if run_start.is_none() {
                run_start = Some(i);
            }
        } else {
            if let Some(start) = run_start {
                let run_len = i - start;
                if run_len >= 2 && run_len > compress_len {
                    compress_start = Some(start);
                    compress_len = run_len;
                }
            }
            run_start = None;
        }
    }
    // Check a trailing run.
    if let Some(start) = run_start {
        let run_len = 8 - start;
        if run_len >= 2 && run_len > compress_len {
            compress_start = Some(start);
            let _ = compress_len; // only needed during the scan
        }
    }

    // Follow the WHATWG spec step by step.
    let mut output = String::with_capacity(39); // max "xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx"
    let mut ignore0 = false;
    for (i, piece) in pieces.iter().enumerate() {
        if ignore0 && *piece == 0 {
            continue;
        }
        if ignore0 {
            ignore0 = false;
        }
        if compress_start == Some(i) {
            if i == 0 {
                output.push(':');
            }
            output.push(':');
            ignore0 = true;
            continue;
        }
        use std::fmt::Write;
        let _ = write!(output, "{piece:x}");
        if i != 7 {
            output.push(':');
        }
    }
    output
}

/// Whether a potential special host crosses WHATWG's "ends in a number"
/// boundary and must therefore be interpreted as IPv4 rather than DNS.
///
/// This deliberately mirrors the boundary predicate, not the full permissive
/// IPv4 parser: after dropping one trailing root dot, the final label either
/// consists entirely of ASCII digits, or is `0x`/`0X` followed by zero or more
/// ASCII hex digits. Inputs crossing that boundary are unsafe DNS identities
/// even when the later WHATWG IPv4 parse would reject them (for example `09`,
/// too many parts, or overflow).
pub(super) fn whatwg_domain_ends_in_number(host: &str) -> bool {
    let without_root_dot = host.strip_suffix('.').unwrap_or(host);
    let last = without_root_dot.rsplit('.').next().unwrap_or_default();

    (!last.is_empty() && last.bytes().all(|byte| byte.is_ascii_digit()))
        || last
            .strip_prefix("0x")
            .or_else(|| last.strip_prefix("0X"))
            .is_some_and(|digits| digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

/// [`certificate_authorization_host`] for a host taken from a URL
/// authority, where an IPv6 literal is legitimately bracketed.
///
/// The bracket rule is WebKit's own, implemented once here: WTF's `URL::host()`
/// keeps `[` and `]` as part of the host component, and WebKit's
/// `hostForComparison` removes exactly that outer pair before looking the
/// exception up. Everything else is the shared parser's decision.
///
/// # Errors
///
/// [`CertificateHostError`] from the shared parser.
pub(super) fn certificate_authorization_host_from_url(
    host: &str,
) -> Result<&str, CertificateHostError> {
    let unbracketed = match host.strip_prefix('[') {
        Some(rest) => {
            let inner = rest
                .strip_suffix(']')
                .ok_or(CertificateHostError::BracketedIpv6)?;
            // Brackets in a URL authority mean IPv6 and nothing else; a
            // bracketed registered name is not a host WebKit can produce.
            if inner.parse::<std::net::Ipv6Addr>().is_err() {
                return Err(CertificateHostError::InvalidShape);
            }
            inner
        }
        None => host,
    };
    certificate_authorization_host(unbracketed)
}

/// The two host strings one certificate authorization needs, from one
/// validated caller identity.
///
/// * `.0` - the authorization identity: byte-for-byte what
///   [`certificate_authorization_host`] accepted (bare IPv6, trailing root dot
///   intact). This is the only string that may reach
///   `webkit_network_session_allow_tls_certificate_for_host`.
/// * `.1` - the correlation key: the canonicalized/folded form, used for
///   the retry budget and ledger correlation and nothing else.
///
/// Both are re-boxed so a retained copy carries no spare caller-controlled
/// capacity.
///
/// # Errors
///
/// [`CertificateHostError`] when the identity is not a possible `URL::host()`.
pub(crate) fn certificate_authorization_identity(
    host: &str,
) -> Result<(String, String), CertificateHostError> {
    let identity = compact_string(certificate_authorization_host(host)?);
    let mut key = identity.clone();
    canonicalize_authority_host(&mut key);
    Ok((identity, compact_string(&key)))
}

pub(super) fn certificate_host(uri: &str) -> Result<&str, NativeUriError> {
    let after_scheme = uri
        .split_once("://")
        .map(|(_, rest)| rest)
        .ok_or(NativeUriError::InvalidHost)?;
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);

    // Split the port off the URI authority, then hand the remaining host to
    // the SHARED authorization parser: the callback and the public pre-trust
    // must agree on what identity WebKit will compare, byte for byte.
    let host = if host_port.starts_with('[') {
        let (bracketed, suffix) = host_port
            .split_once(']')
            .ok_or(NativeUriError::InvalidHost)?;
        if !suffix.is_empty()
            && !suffix
                .strip_prefix(':')
                .is_some_and(|port| port.parse::<u16>().is_ok())
        {
            return Err(NativeUriError::InvalidHost);
        }
        // Keep the brackets: the shared parser strips them exactly as WebKit
        // documents, so only one place knows that rule.
        &host_port[..bracketed.len() + 1]
    } else {
        let (host, port) = host_port
            .rsplit_once(':')
            .map_or((host_port, None), |(host, port)| (host, Some(port)));
        // A URI authority must bracket an IPv6 literal, so a colon surviving
        // the port split is malformed here even though the shared parser
        // accepts an unbracketed literal as an authorization identity.
        if host.contains(':') || port.is_some_and(|port| port.parse::<u16>().is_err()) {
            return Err(NativeUriError::InvalidHost);
        }
        host
    };

    certificate_authorization_host_from_url(host).map_err(|error| match error {
        CertificateHostError::TooLong => NativeUriError::HostTooLong,
        _ => NativeUriError::InvalidHost,
    })
}

/// Canonicalize an authority host string so the retry-budget key does not
/// diverge over spellings the DNS and TLS layers already treat as equal.
///
/// This is the shared key boundary for [`CertificateLedger::admit_continuation`]
/// (after [`certificate_host`]). Two failing URIs whose hosts differ only in ASCII case,
/// a single trailing DNS-root dot, or IPv6-literal spelling all resolve to the
/// same peer and present the same certificate; without this fold a hostile
/// page could rotate case variants of one host to spend one `MAX_CONTINUATIONS`
/// budget per variant, up to `RETRY_HOSTS_MAX`, and then also refill the table
/// against unrelated legitimate hosts.
///
/// Pure ASCII, and pure text: [`certificate_host`] has already stripped IPv6
/// brackets and rejected non-ASCII registered names. WebKit supplies IDNs in
/// their ASCII form, avoiding a second Unicode equivalence class here.
pub(super) fn canonicalize_authority_host(host: &mut String) {
    // Fast path: an IP literal has one canonical text form. Do this first so
    // `[0:0:0:0:0:0:0:1]` and `[::1]` share a budget entry.
    if let Ok(addr) = host.parse::<std::net::IpAddr>() {
        *host = addr.to_string();
        return;
    }
    host.make_ascii_lowercase();
    // Strip a single trailing DNS-root dot: `example.com.` and `example.com`
    // are the same authority. A bare `.` is preserved so a hostless URI still
    // fails the empty-host check upstream.
    if host.len() > 1 && host.ends_with('.') {
        host.pop();
    }
}

pub(super) fn is_a(
    request: *mut ffi::WebKitPermissionRequest,
    ty: unsafe extern "C" fn() -> ffi::GType,
) -> bool {
    unsafe { ffi::g_type_check_instance_is_a(request.cast::<ffi::GTypeInstance>(), ty()) != 0 }
}
