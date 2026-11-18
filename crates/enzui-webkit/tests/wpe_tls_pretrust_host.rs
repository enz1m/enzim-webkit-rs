//! Native gate for the certificate-authorization host identity.
//!
//! ```text
//! cargo test -p enzui-webkit --features wpe \
//!     --test wpe_tls_pretrust_host -- --ignored --nocapture
//! ```

#[cfg(feature = "wpe")]
mod wpe_native_support;
#[cfg(feature = "wpe")]
mod wpe_tls_origin;

#[cfg(feature = "wpe")]
use enzui_webkit::ffi::runtime::{HeadlessDisplay, SessionError, WebSession};
#[cfg(feature = "wpe")]
use wpe_tls_origin::TlsRedirectOrigin;

#[cfg(feature = "wpe")]
#[test]
#[ignore = "requires the confined WPE source runtime and a loopback TLS origin fixture"]
fn wpe_certificate_pre_trust_validates_the_authorization_host_identity() {
    wpe_native_support::run(
        "wpe_certificate_pre_trust_validates_the_authorization_host_identity",
        || {
            let outcome = (|| {
                let display =
                    HeadlessDisplay::new().map_err(|e| format!("headless WPE display: {e}"))?;
                let tls = TlsRedirectOrigin::start()?;
                run(&display, &tls)
            })();
            if let Err(error) = outcome {
                panic!("certificate pre-trust host gate FAILED: {error}");
            }
            println!(
                "wpe_certificate_pre_trust_validates_the_authorization_host_identity: ALL GATES OK"
            );
        },
    );
}

/// `WebSession::allow_tls_certificate_for_host` validates the identity WebKit
/// compares, records both outcomes in the ledger, and still fails closed.
///
/// Three pieces of evidence on the real self-signed fixture:
///
/// 1. Control - `localhost:<port>` is not a WebKit request host. It must
///    return the typed [`SessionError::TlsCertificateError`], make no native
///    install and no request, and append a *denied* pre-trust record.
/// 2. Strict default denial - that same session, with no valid exception,
///    must not reach `/safe-target`: the TLS callback fires and denies. This is
///    the positive control for step 3 - a target reached without any pre-trust
///    would make step 3 vacuous.
/// 3. Positive - an identical strict session pre-trusted with the real
///    identity `localhost` reaches `/safe-target` exactly once with zero
///    TLS callbacks, and the ledger records the installation.
///
/// The pre-trust is issued *after* `install_native_policy`, because installing
/// a policy binding replaces the ledger the record lives in.
/// Bound on how long one real HTTPS load may be polled for. Generous because
/// it is only an upper bound: every wait below ends as soon as the effect it
/// waits for appears, and the assertions run afterwards either way.
#[cfg(feature = "wpe")]
const LOAD_DEADLINE: std::time::Duration = std::time::Duration::from_secs(15);

#[cfg(feature = "wpe")]
fn run(display: &HeadlessDisplay, tls: &TlsRedirectOrigin) -> Result<(), String> {
    use enzui_webkit::ffi::policy::PreTrustOutcome;

    let strict_session = |slot: u64| -> Result<WebSession, String> {
        let mut web = WebSession::new_trusted_local(display).map_err(|e| e.to_string())?;
        let mut router = enzui_webkit::web::ViewRouter::new();
        let view = router.create(slot);
        web.bind_view(&router, view).map_err(|e| e.to_string())?;
        web.install_native_policy(
            &router,
            view,
            // STRICT: `allow_insecure_certificates` stays false, so nothing but
            // a valid pre-trusted exception can complete this handshake.
            enzui_webkit::web::WebPolicy::strict(),
            |request| Some(request.id),
        )
        .map_err(|e| e.to_string())?;
        Ok(web)
    };

    // 1. Control: an authority spelling, not a host identity.
    let control = strict_session(2059)?;
    let before = tls.count("/safe-target");
    let host_port = format!("localhost:{}", tls.port());
    match control.allow_tls_certificate_for_host(tls.cert_pem(), &host_port) {
        Err(SessionError::TlsCertificateError(message)) => {
            if !message.contains("port") {
                return Err(format!("typed refusal did not name the port: {message}"));
            }
        }
        other => {
            return Err(format!(
                "pre-trusting {host_port:?} must fail with TlsCertificateError, got {:?}",
                other.map(|()| "Ok")
            ));
        }
    }
    let ledger = control
        .native_certificate_ledger()
        .ok_or("control session has no certificate ledger")?;
    let records = ledger.pre_trusts();
    if records.len() != 1
        || !matches!(records[0].outcome, PreTrustOutcome::HostDenied(_))
        || !records[0].host.is_empty()
    {
        return Err(format!(
            "refused pre-trust did not record exactly one denied ledger event: {records:?}"
        ));
    }
    if ledger.callbacks() != 0 || tls.count("/safe-target") != before {
        return Err(format!(
            "refused pre-trust performed native work: callbacks {}, target count {} -> {}",
            ledger.callbacks(),
            before,
            tls.count("/safe-target")
        ));
    }

    // 2. Strict default denial for the same session: no valid exception, so
    // the handshake must not complete and the target must not be reached.
    control
        .begin_load_uri(&tls.url("/safe-target"))
        .map_err(|e| format!("start un-pre-trusted HTTPS load: {e}"))?;
    // Poll for WebKit's own report of the refused handshake rather than
    // sleeping a fixed budget: a fixed budget that expires early would let
    // "nothing has happened yet" pass as "the load was refused".
    let deadline = std::time::Instant::now() + LOAD_DEADLINE;
    let mut denied_ledger = control
        .native_certificate_ledger()
        .ok_or("control session has no certificate ledger")?;
    while std::time::Instant::now() < deadline
        && denied_ledger.callbacks() == 0
        && denied_ledger.load_failures().is_empty()
    {
        control.pump(200);
        denied_ledger = control
            .native_certificate_ledger()
            .ok_or("control session has no certificate ledger")?;
    }
    // The origin counter is the load-bearing assertion: with no usable
    // exception nothing may reach `/safe-target`. WebKit's own report of the
    // refused handshake - the TLS failure callback, or the `load-failed`
    // diagnostic when WPE 2.52 answers there instead - is what proves the load
    // was really attempted, so "nothing happened" cannot pass as fail-closed.
    let attempted = denied_ledger.callbacks() > 0 || !denied_ledger.load_failures().is_empty();
    if tls.count("/safe-target") != before || !attempted {
        return Err(format!(
            "strict session without a valid exception was not fail-closed: target count {} -> {}, TLS callbacks {}, load failures {:?}",
            before,
            tls.count("/safe-target"),
            denied_ledger.callbacks(),
            denied_ledger.load_failures()
        ));
    }
    drop(control);

    // 3. Positive: the SAME strict configuration, pre-trusted with the real
    // identity, reaches the target once with no TLS round trip at all.
    let trusted = strict_session(2060)?;
    trusted
        .allow_tls_certificate_for_host(tls.cert_pem(), "localhost")
        .map_err(|e| format!("pre-trust the real host identity: {e}"))?;
    let installed = trusted
        .native_certificate_ledger()
        .ok_or("pre-trusted session has no certificate ledger")?
        .pre_trusts();
    if installed.len() != 1
        || installed[0].outcome != PreTrustOutcome::Installed
        || installed[0].host != "localhost"
    {
        return Err(format!(
            "successful pre-trust was not recorded in the ledger: {installed:?}"
        ));
    }
    let before_trusted = tls.count("/safe-target");
    trusted
        .begin_load_uri(&tls.url("/safe-target"))
        .map_err(|e| format!("start pre-trusted HTTPS load: {e}"))?;
    // Same reason as above, in the other direction: poll for the effect this
    // gate claims (the origin was reached) instead of hoping one fixed sleep
    // covers a real WebKit page load.
    let deadline = std::time::Instant::now() + LOAD_DEADLINE;
    while std::time::Instant::now() < deadline && tls.count("/safe-target") == before_trusted {
        trusted.pump(200);
    }
    let after_trusted = tls.count("/safe-target");
    let trusted_ledger = trusted
        .native_certificate_ledger()
        .ok_or("pre-trusted session has no certificate ledger")?;
    if after_trusted != before_trusted + 1 || trusted_ledger.callbacks() != 0 {
        return Err(format!(
            "pre-trusted strict session did not reach the target without a TLS round trip: \
             target count {before_trusted} -> {after_trusted}, TLS callbacks {}, events {:?}, \
             load failures {:?}, main responses {:?}, origin paths {:?}",
            trusted_ledger.callbacks(),
            trusted_ledger.events(),
            trusted_ledger.load_failures(),
            trusted_ledger.main_responses(),
            tls.paths()
        ));
    }

    // Every rejected spelling, on a live session: none of them may install.
    let long_host = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(62)
    );
    if long_host.len() != 254 {
        return Err("the over-limit host fixture is not 254 bytes".into());
    }
    for rejected in [
        "",
        "https://localhost/",
        // WebKit documents the bare address and strips brackets off the
        // request host before comparing, so a bracketed exception matches
        // nothing.
        "[::1]",
        long_host.as_str(),
        "localhost:44443",
        // WHATWG/WebKit special-host IPv4 spellings. Public pre-trust must
        // refuse the whole numeric boundary rather than install a normalized
        // or parser-rejected identity.
        "0",
        "127.1",
        "0177.0.0.1",
        "0xffffffff",
        "127.0.0.1.",
        "09",
        "1.2.3.4.5",
        "4294967296",
    ] {
        if !matches!(
            trusted.allow_tls_certificate_for_host(tls.cert_pem(), rejected),
            Err(SessionError::TlsCertificateError(_))
        ) {
            return Err(format!(
                "pre-trusting {rejected:?} was accepted; only a WebKit request host is an identity"
            ));
        }
    }
    // Positive control for that list: real identities are still accepted, so
    // "reject everything" cannot pass this gate.
    for accepted in ["localhost", "127.0.0.1", "::1"] {
        trusted
            .allow_tls_certificate_for_host(tls.cert_pem(), accepted)
            .map_err(|e| format!("valid host identity {accepted:?} was refused: {e}"))?;
    }
    println!(
        "tls-pretrust-gate: host:port pre-trust refused with a denied ledger record and no native \
         work; strict session without an exception failed closed; `localhost` pre-trust reached \
         /safe-target once with 0 TLS callbacks OK"
    );
    Ok(())
}
