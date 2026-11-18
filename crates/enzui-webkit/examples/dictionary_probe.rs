//! Exercise dictionary transport against an explicitly trusted local HTTPS fixture.

use enzui_webkit::ffi::profile::ProfileStore;
use enzui_webkit::ffi::runtime::{HeadlessDisplay, WebSession};
use enzui_webkit::page::{PageEvent, ScriptWorld};
use enzui_webkit::web::{DestinationPolicy, ViewRouter, WebPolicy, WebProfile};
use std::error::Error;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn evaluate(session: &WebSession, script: &str) -> Result<String, Box<dyn Error>> {
    let id = session.evaluate_script(script, &ScriptWorld::Isolated("dictionary-probe".into()))?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        session.pump(2);
        for event in session.take_page_events() {
            if let PageEvent::ScriptResult { id: found, result } = event
                && found == id
            {
                return result.map_err(|error| format!("{error:?}").into());
            }
        }
    }
    Err("script deadline".into())
}

fn session(
    display: &HeadlessDisplay,
    store: &mut ProfileStore,
    profile: &WebProfile,
    certificate: &[u8],
    slot: u64,
) -> Result<WebSession, Box<dyn Error>> {
    let mut session = WebSession::new_profiled_trusted_local(display, store, profile)?;
    let mut router = ViewRouter::new();
    let view = router.create(slot);
    session.bind_view(&router, view)?;
    session.install_native_policy(
        &router,
        view,
        WebPolicy::strict().with_destination(DestinationPolicy::trusted_local()),
        |request| Some(request.id),
    )?;
    session.allow_tls_certificate_for_host(certificate, "localhost")?;
    Ok(session)
}

fn run_case(
    session: &mut WebSession,
    origin: &str,
    output: &Path,
    name: &str,
    acquire: bool,
    expect_dictionary: bool,
) -> Result<(), Box<dyn Error>> {
    if let Err(error) = session.load(&format!("{origin}/index?case={name}"), 10_000) {
        eprintln!(
            "dictionary guard events: {:?}",
            session.destination_guard_events()
        );
        if let Some(observations) = session.native_policy_observations() {
            eprintln!(
                "dictionary fixture policy: {:?}",
                observations.iter().collect::<Vec<_>>()
            );
        }
        if let Some(ledger) = session.native_certificate_ledger() {
            eprintln!("dictionary fixture certificate grants: {:?}", ledger);
        }
        return Err(error.into());
    }
    let script = include_str!("dictionary_probe.js")
        .replace("ACQUIRE_DICTIONARY", if acquire { "true" } else { "false" })
        .replace(
            "EXPECT_DICTIONARY",
            if expect_dictionary { "true" } else { "false" },
        );
    evaluate(session, &script)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while evaluate(
        session,
        "document.getElementById('dictionary-result').dataset.done === '1'",
    )? != "true"
    {
        if Instant::now() >= deadline {
            return Err(format!("dictionary case deadline: {name}").into());
        }
        session.pump(20);
    }
    let report = evaluate(
        session,
        "JSON.parse(document.getElementById('dictionary-result').textContent)",
    )?;
    std::fs::write(output.join(format!("{name}.json")), &report)?;
    if evaluate(
        session,
        "JSON.parse(document.getElementById('dictionary-result').textContent).passed === true",
    )? != "true"
    {
        return Err(format!("{name}: {report}").into());
    }
    println!("DICTIONARY_CASE {name} {report}");
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let origin = args.next().ok_or("missing local HTTPS origin")?;
    if !origin.starts_with("https://localhost:") {
        return Err("fixture must use HTTPS localhost".into());
    }
    let mut certificate = Vec::new();
    std::fs::File::open(args.next().ok_or("missing certificate")?)?
        .take(64 * 1024 + 1)
        .read_to_end(&mut certificate)?;
    if certificate.len() > 64 * 1024 {
        return Err("certificate exceeds bound".into());
    }
    let output = PathBuf::from(args.next().ok_or("missing output")?);
    std::fs::create_dir_all(&output)?;
    let display = HeadlessDisplay::new()?;
    let mut store = ProfileStore::new(output.join("profiles"));
    let profile = WebProfile::persistent("dictionary-a");
    let mut first = session(&display, &mut store, &profile, &certificate, 1)?;
    assert!(
        WebSession::feature_defaults()?
            .iter()
            .any(|(name, enabled)| name == "CompressionDictionary" && !enabled)
    );
    run_case(&mut first, &origin, &output, "disabled", true, false)?;
    assert!(first.enable_compression_dictionary_transport());
    run_case(&mut first, &origin, &output, "enabled", true, true)?;
    let mut other = session(
        &display,
        &mut store,
        &WebProfile::persistent("dictionary-b"),
        &certificate,
        2,
    )?;
    assert!(other.enable_compression_dictionary_transport());
    run_case(&mut other, &origin, &output, "other-profile", false, false)?;
    let mut private = session(
        &display,
        &mut store,
        &WebProfile::ephemeral(),
        &certificate,
        3,
    )?;
    assert!(private.enable_compression_dictionary_transport());
    run_case(&mut private, &origin, &output, "ephemeral", true, false)?;
    println!("DICTIONARY_PROBE passed=4");
    Ok(())
}
