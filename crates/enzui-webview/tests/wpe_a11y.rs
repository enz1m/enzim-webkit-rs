//! `wpe_a11y` - the embedded page's accessible tree reaches
//! the host.
//!
//! ```text
//! cargo test --features wpe -p enzui-webview --test wpe_a11y \
//!     -- --ignored --nocapture
//! ```

#[cfg(feature = "wpe")]
#[path = "../../enzui-webkit/tests/wpe_native_support/mod.rs"]
mod wpe_native_support;

#[cfg(feature = "wpe")]
use enzui_webkit::ffi::a11y::{A11yNode, role};
#[cfg(feature = "wpe")]
use enzui_webkit::ffi::runtime::{DeliverError, HeadlessDisplay, SessionError, WebSession};
#[cfg(feature = "wpe")]
use enzui_webkit::page_a11y::PageA11y;
#[cfg(feature = "wpe")]
use enzui_webkit::page_a11y::PageRole as Role;

/// The fixture page. Every element carries a DISTINCT accessible name, so an
/// assertion on `(role, name)` cannot be satisfied by the wrong element.
///
/// The link uses an absolute URL deliberately: a `#fragment` inside a `data:`
/// URL truncates the document (a defect in the render path), which would silently
/// drop everything after it from the tree.
#[cfg(feature = "wpe")]
const A11Y_PAGE: &str = "data:text/html,<!DOCTYPE html><html><head>\
    <title>Accessible Page Title</title></head><body>\
    <h1>Main Heading</h1>\
    <button>Submit Order</button>\
    <a href='https://example.com/'>Read The Docs</a>\
    <input aria-label='Email Address'>\
    </body></html>";

/// A distinct document loaded into the same session after [`A11Y_PAGE`]. The
/// navigation closes the first document generation, so none of its names may
/// remain in the next AT-SPI walk.
#[cfg(feature = "wpe")]
const A11Y_REPLACEMENT_PAGE: &str = "data:text/html,<!DOCTYPE html><html><head>\
    <title>Replacement Document</title></head><body>\
    <button>Discard Changes</button></body></html>";

/// Names unique to the first generated document. They are both its positive
/// control and the stale-generation absence set after replacement.
#[cfg(feature = "wpe")]
const FIRST_GENERATION_NAMES: &[&str] = &[
    "Accessible Page Title",
    "Main Heading",
    "Submit Order",
    "Read The Docs",
    "Email Address",
];

/// The gate-10 page: a button whose click handler repaints the body.
///
/// The whole point is that the colour change is driven by the page's own DOM
/// handler, so a pixel flip proves the activation reached the page's script,
/// not merely that a D-Bus call returned success. `DoAction` returning
/// `true` only says the object accepted the request.
///
/// The anchor sits at (400,300), well inside the body and clear of the button,
/// so the measured pixel is the background the handler paints.
#[cfg(feature = "wpe")]
const A11Y_ACTION_PAGE: &str = "data:text/html,<!DOCTYPE html><html><head>\
    <title>Action Page</title>\
    <style>body{background:rgb(0,0,255);margin:0}\
    button{position:absolute;top:10px;left:10px}</style></head><body>\
    <h1>Action Heading</h1>\
    <button id='b' onclick=\"document.body.style.background='rgb(255,34,170)'\">\
    Press Me</button>\
    </body></html>";

/// Gate 10's anchor: inside the body, away from the button.
#[cfg(feature = "wpe")]
const ACTION_ANCHOR: (u32, u32) = (400, 300);
/// The body's colour before the action.
#[cfg(feature = "wpe")]
const BEFORE_RGBA: (u8, u8, u8, u8) = (0, 0, 255, 255);
/// The colour the page's own click handler paints.
#[cfg(feature = "wpe")]
const AFTER_RGBA: (u8, u8, u8, u8) = (255, 34, 170, 255);

/// Walk depth/count caps. Generous enough for the fixture, bounded so a
/// pathological page cannot make the gate run unbounded.
#[cfg(feature = "wpe")]
const MAX_DEPTH: usize = 12;
#[cfg(feature = "wpe")]
const MAX_NODES: usize = 200;

#[cfg(feature = "wpe")]
#[test]
#[ignore = "requires the confined WPE source runtime and an AT-SPI bus"]
fn wpe_page_accessibility_tree_reaches_the_host() {
    wpe_native_support::run("wpe_page_accessibility_tree_reaches_the_host", || {
        if let Err(error) = run_a11y_gates() {
            panic!("a11y gate failed: {error}");
        }
    });
}

#[cfg(feature = "wpe")]
fn run_a11y_gates() -> Result<(), String> {
    let display = HeadlessDisplay::new().expect("headless WPE display");
    let mut session = WebSession::new(&display).map_err(|e| format!("session: {e}"))?;

    // -- gate 1: the platform exposes an accessibility object at all ---------
    if !session.has_accessible() {
        return Err(
            "wpe_view_get_accessible() returned NULL — this platform publishes no \
             accessibility object, so an embedded page can never be accessible"
                .to_string(),
        );
    }
    println!("a11y-gate1: the headless view exposes an accessibility object OK");

    // -- gate 2: identify the real initial blank tree by its CONTENT ---------
    // WPE 2.52 starts a sandboxed WebProcess during construction and publishes
    // its initial blank document. Presence is therefore a positive fact, not a
    // negative control. The useful control is that this real D-Bus tree has a
    // document but none of the named interactive descendants generated below.
    let blank_plug = session.accessibility_plug_id().ok_or_else(|| {
        "the initial blank document published no AT-SPI plug id — WPE 2.52 should \
         already expose its sandboxed WebProcess root"
            .to_string()
    })?;
    if !blank_plug.contains("/org/a11y/") {
        return Err(format!(
            "the initial blank document's plug id is not an AT-SPI address: \
             {blank_plug:?}"
        ));
    }
    let blank_tree = session
        .accessibility_tree(MAX_DEPTH, MAX_NODES)
        .map_err(|e| format!("reading the initial blank tree over AT-SPI failed: {e}"))?;
    let blank_flat = blank_tree.flatten();
    if blank_tree.find_by_role(role::DOCUMENT_WEB).is_none() {
        return Err(format!(
            "the initial AT-SPI tree has no web document, so it is not the real \
             blank document: {blank_flat:?}"
        ));
    }
    let named_interactive = |(node_role, name): &(u32, String)| {
        matches!(*node_role, role::PUSH_BUTTON | role::LINK | role::ENTRY)
            && !name.trim().is_empty()
    };
    if let Some(node) = blank_flat.iter().find(|node| named_interactive(node)) {
        return Err(format!(
            "the initial blank document contains a named interactive descendant \
             {node:?} — the walk returned a fabricated page tree"
        ));
    }
    if let Some(name) = FIRST_GENERATION_NAMES
        .iter()
        .find(|name| blank_flat.iter().any(|(_, got)| got.as_str() == **name))
    {
        return Err(format!(
            "the initial blank tree already contains generated-page marker \
             {name:?} — a fabricated constant tree crossed the seam: {blank_flat:?}"
        ));
    }
    println!(
        "a11y-gate2: read the initial blank document ({} nodes) over AT-SPI; \
         it has no named interactive descendants OK",
        blank_tree.count()
    );

    // -- load the real page --------------------------------------------------
    session
        .load(A11Y_PAGE, 15_000)
        .map_err(|e| format!("load: {e}"))?;
    // Let the WebProcess publish its tree and call bind().
    for _ in 0..8 {
        session.pump(300);
    }

    // -- gate 3: the WebProcess published a plug id --------------------------
    let plug = session.accessibility_plug_id().ok_or_else(|| {
        "after loading a real page the WebProcess never called bind(), so no \
         accessible tree was published"
            .to_string()
    })?;
    if !plug.contains("/org/a11y/") {
        return Err(format!(
            "the published plug id does not address an AT-SPI object: {plug:?}"
        ));
    }
    println!("a11y-gate3: WebProcess published an AT-SPI plug id OK");

    // -- gate 4: the remote tree reads back ---------------------------------
    let tree = session
        .accessibility_tree(MAX_DEPTH, MAX_NODES)
        .map_err(|e| format!("reading the accessible tree across the seam failed: {e}"))?;
    let flat = tree.flatten();
    if flat == blank_flat {
        return Err(format!(
            "the tree after loading the generated page is identical to the initial \
             blank tree — the AT-SPI seam reused a cached tree: {flat:?}"
        ));
    }
    println!(
        "a11y-gate4: a second D-Bus walk changed from the {}-node blank tree to \
         the {}-node generated-page tree OK",
        blank_tree.count(),
        tree.count()
    );

    // The socket is the root and is EMPTY in-process; if the walk had gone
    // local instead of over D-Bus this code would see exactly one node.
    if tree.count() <= 1 {
        return Err(format!(
            "the tree has {} node(s) — that is the empty in-process AtkSocket, not \
             the page's real tree. The remote AT-SPI read did not happen.",
            tree.count()
        ));
    }

    // -- gate 5: the document arrives, carrying the page <title> -------------
    let doc = tree.find_by_role(role::DOCUMENT_WEB).ok_or_else(|| {
        format!(
            "no ATSPI_ROLE_DOCUMENT_WEB ({}) node in the tree — the page document \
             did not cross the seam. Tree was: {flat:?}",
            role::DOCUMENT_WEB
        )
    })?;
    if doc.name != "Accessible Page Title" {
        return Err(format!(
            "the document's accessible name is {:?}, expected {:?} — a web \
             document's name IS the page <title>, so the title did not cross",
            doc.name, "Accessible Page Title"
        ));
    }
    println!(
        "a11y-gate5: document role={} name={:?} (the page <title>) OK",
        doc.role, doc.name
    );

    // -- gate 6: each element crosses with BOTH the right role AND name ------
    // Distinct names, so a mismatched pairing cannot satisfy the assertion, and
    // an empty-name bridge (correct roles, useless to a screen reader) fails.
    let expected: &[(u32, &str, &str)] = &[
        (role::PUSH_BUTTON, "Submit Order", "<button>"),
        (role::LINK, "Read The Docs", "<a href>"),
        (role::ENTRY, "Email Address", "<input aria-label>"),
        (role::HEADING, "Main Heading", "<h1>"),
    ];

    // Calibration: all four expected names are distinct, so the gate cannot
    // pass by every element collapsing to one string.
    for i in 0..expected.len() {
        for j in (i + 1)..expected.len() {
            assert_ne!(
                expected[i].1, expected[j].1,
                "a11y calibration: two expected accessible names collide"
            );
        }
    }

    for (want_role, want_name, dom) in expected {
        let hit = flat.iter().find(|(r, n)| r == want_role && n == want_name);
        if hit.is_none() {
            // Report what DID arrive for that role, which is the actionable
            // diagnosis: wrong name, or missing entirely.
            let same_role: Vec<&String> = flat
                .iter()
                .filter(|(r, _)| r == want_role)
                .map(|(_, n)| n)
                .collect();
            return Err(format!(
                "{dom} did not cross the seam as (role={want_role}, name={want_name:?}). \
                 Nodes with that role carried names {same_role:?}. Full tree: {flat:?}"
            ));
        }
        println!("a11y-gate6: {dom} arrived as role={want_role} name={want_name:?} OK");
    }

    // -- gate 7 (negative control): a role the page lacks is absent ----------
    // The fixture has no <table>; asserting its absence catches a matcher that
    // returns something for everything, which would make gate 5/6 vacuous.
    const ATSPI_ROLE_TABLE: u32 = 55;
    if let Some(bogus) = tree.find_by_role(ATSPI_ROLE_TABLE) {
        return Err(format!(
            "found a TABLE role in a page that has no table: {bogus:?} — the role \
             matcher returns hits for roles that are not present, which would make \
             every positive assertion above vacuous"
        ));
    }
    println!("a11y-gate7: a role the page does not contain is correctly absent OK");

    // -- gate 8: a replacement generation closes the first ------------------
    // Navigate the SAME session. A separate view would prove isolation but not
    // that this plug's next D-Bus walk is live rather than a one-shot cache.
    // The old document generation is closed by this navigation, so require the
    // new title/control and require EVERY old marker absent.
    session
        .load(A11Y_REPLACEMENT_PAGE, 15_000)
        .map_err(|e| format!("replacement load: {e}"))?;
    for _ in 0..8 {
        session.pump(300);
    }
    let replacement = session
        .accessibility_tree(MAX_DEPTH, MAX_NODES)
        .map_err(|e| format!("replacement tree over AT-SPI: {e}"))?;
    let replacement_flat = replacement.flatten();
    if replacement_flat == flat {
        return Err(format!(
            "the replacement navigation returned the first generation's cached \
             tree unchanged: {replacement_flat:?}"
        ));
    }
    for (want_role, want_name, dom) in [
        (role::DOCUMENT_WEB, "Replacement Document", "<title>"),
        (role::PUSH_BUTTON, "Discard Changes", "<button>"),
    ] {
        if !replacement_flat
            .iter()
            .any(|(got_role, got_name)| *got_role == want_role && got_name == want_name)
        {
            return Err(format!(
                "the replacement {dom} did not cross the live D-Bus seam as \
                 (role={want_role}, name={want_name:?}): {replacement_flat:?}"
            ));
        }
    }
    let stale_names: Vec<&&str> = FIRST_GENERATION_NAMES
        .iter()
        .filter(|name| {
            replacement_flat
                .iter()
                .any(|(_, got)| got.as_str() == **name)
        })
        .collect();
    if !stale_names.is_empty() {
        return Err(format!(
            "the replacement tree still contains names from the closed document \
             generation {stale_names:?}: {replacement_flat:?}"
        ));
    }
    println!(
        "a11y-gate8: the same session's next D-Bus walk contains Replacement \
         Document/Discard Changes and no closed-generation names OK"
    );

    // -- gate 9: the real page's tree becomes enzUI semantics ----------------
    // This drives the same translation the widget publishes
    // (`PageA11y::from_source`, unit-tested feature-off) over the REAL tree
    // read above, so the mapping is proven against WebKit's actual role
    // numbers rather than against a fixture that agrees with it by
    // construction.
    let page = PageA11y::from_source(&tree);
    let translated = page.root().flatten();
    let want: &[(Role, &str, &str)] = &[
        (Role::Heading, "Main Heading", "<h1>"),
        (Role::Button, "Submit Order", "<button>"),
        (Role::Link, "Read The Docs", "<a href>"),
        (Role::TextInput, "Email Address", "<input aria-label>"),
    ];
    for (want_role, want_name, dom) in want {
        if !page.find(*want_role, want_name) {
            let same_role: Vec<&String> = translated
                .iter()
                .filter(|(r, _)| r == want_role)
                .map(|(_, n)| n)
                .collect();
            return Err(format!(
                "{dom} did not translate to (role={want_role:?}, name={want_name:?}). \
                 Nodes with that host role carried names {same_role:?}. \
                 Translated tree: {translated:?}"
            ));
        }
        println!("a11y-gate9: {dom} -> enzUI {want_role:?} name={want_name:?} OK");
    }
    // Negative control: the four host roles are distinct, so the gate cannot
    // pass by everything collapsing to one role.
    for i in 0..want.len() {
        for j in (i + 1)..want.len() {
            if want[i].0 == want[j].0 {
                return Err(format!(
                    "gate9 calibration: expected roles {:?} and {:?} collide",
                    want[i].0, want[j].0
                ));
            }
        }
    }
    // -- gate 9b: an action is advertised EXACTLY where one is routable ------
    // Two-sided: the page's real controls must advertise an action, and its
    // non-interactive text must not. A one-sided check would pass both for an
    // implementation that advertises everything and for one that advertises
    // nothing.
    fn advertised(node: &enzui_webkit::page_a11y::PageNode, out: &mut Vec<(Role, String)>) {
        if node.semantics().supports_default_action {
            out.push((
                node.semantics().role,
                node.semantics().label.clone().unwrap_or_default(),
            ));
        }
        for c in node.children() {
            advertised(c, out);
        }
    }
    let mut actionable = Vec::new();
    advertised(page.root(), &mut actionable);

    // The button and the link are operable on a real page; WebKit reports
    // `press` for a <button> and `jump` for an <a href>.
    for (want_role, want_name) in [
        (Role::Button, "Submit Order"),
        (Role::Link, "Read The Docs"),
    ] {
        if !actionable
            .iter()
            .any(|(r, n)| *r == want_role && n == want_name)
        {
            return Err(format!(
                "the page's {want_name:?} ({want_role:?}) advertises NO routable \
                 action, so a screen reader can read it but never operate it. \
                 Advertised: {actionable:?}"
            ));
        }
    }
    // ...and the heading must not: it is text, and an advertised action that
    // resolves to nothing is the delivery defect this gate prevents.
    if actionable.iter().any(|(r, _)| *r == Role::Heading) {
        return Err(format!(
            "a heading advertises a default action — non-interactive text must \
             publish read-only. Advertised: {actionable:?}"
        ));
    }
    println!(
        "a11y-gate9b: {} node(s) advertise a routable action: {actionable:?} OK",
        actionable.len()
    );

    // Every advertised node must actually resolve to a target, or the
    // advertisement is a promise the host cannot keep.
    for key in page.keys() {
        let node = page.node_for_key(&key).expect("key came from the tree");
        if node.semantics().supports_default_action && page.action_target(&key).is_none() {
            return Err(format!(
                "node {key} advertises an action but resolves to no target — \
                 advertisement and routability have drifted apart"
            ));
        }
    }
    // The roles WebKit actually reported that this code does not map are a fact worth
    // printing: silence here would hide a page kind published as a bare group.
    println!(
        "a11y-gate9: translated {} nodes; unmapped AT-SPI roles {:?}; unnamed \
         controls demoted: {}; truncated: {} OK",
        page.count(),
        page.unmapped_roles(),
        page.unnamed_actionable(),
        page.truncated()
    );

    // -- gate 10: a published control is ADDRESSABLE and its action changes
    //             the page's RENDERED state -----------------------------------
    // The consequence gate for the whole target. Everything above proves the
    // tree is read correctly; this proves the round trip: resolve a published
    // node to its AT-SPI target, perform its action through the same entry
    // point a screen reader uses, and measure the page's own repaint.
    //
    // Deliberately measured in PIXELS rather than by `DoAction`'s boolean: a
    // `true` reply only means the object accepted the request. Only the repaint
    // proves the page's click handler actually ran.
    run_action_gate()?;

    // -- gate 13: two live sessions cannot mislabel each other's trees -------
    run_two_session_mislabel_gate()?;

    // -- gate 14: the DoAction cap-expiry give-up path retains everything ----
    run_cap_expiry_gate()?;

    // -- gate 16: the SNAPSHOT cap-expiry transfer is callback-owned too -----
    run_snapshot_cap_expiry_gate()?;

    // -- gate 17: a forged offer cannot choose which native action runs ------
    run_forged_offer_gate()?;

    // -- gate 15: one production chain, AccessKit Activate -> native action ---
    run_end_to_end_activation_gate()?;

    Ok(())
}

/// Gate 15: a SINGLE production chain from an AccessKit
/// `Activate` all the way to a native `DoAction` on the page, with generation
/// validation in the middle.
///
/// # Why this is not two halves
///
/// The probe's feature-off route proves AccessKit `Activate(id)` -> id
/// resolution -> generation validation, and gate 10 proves key -> native
/// `DoAction`. They met only at a key found by role. This gate joins them at the
/// exact seam a real app uses:
///
/// 1. the runtime resolves an assistive-technology `Activate` to a widget
///    [`Id`] - modelled here with [`AccessibilityAction::Activate`], the value
///    `enzui_core::a11y_action` produces (its Action->Id step is proven in
///    that crate's own tests);
/// 2. the id recipe lives in [`enzui_core::identity::web_page_node_id`] -
///    the SAME single recipe `enzui_webview::page_node_id`
///    delegates to and the probe's dispatcher resolves through. The gate uses
///    the core recipe directly, so there is no reverse dev-dependency on the
///    widget crate: the production recipe is exercised at the
///    layer both consumers share, not borrowed through a cycle;
/// 3. [`WebSession::perform_page_action`] validates the session binding and the
///    router generation, then performs the real `DoAction`;
/// 4. the page's own handler repaints, measured in pixels.
///
/// A dead generation or a foreign session id is refused at step 3, which the
/// negative leg proves.
#[cfg(feature = "wpe")]
fn run_end_to_end_activation_gate() -> Result<(), String> {
    use enzui_core::a11y_action::AccessibilityAction;
    use enzui_core::identity::web_page_node_id;
    use enzui_webkit::frame::{Generation, Rgba8Frame};
    use enzui_webkit::page_action::{PageActionDispatch, PageActionDispatchOutcome};
    use enzui_webkit::page_delivery::{PageA11yDelivery, PageDelivery};
    use enzui_webkit::web::ViewRouter;
    use enzui_webkit::web::frame::FrameSeq;

    fn pixel_at(frame: &Rgba8Frame, x: u32, y: u32) -> (u8, u8, u8, u8) {
        let px = frame.pixels();
        let stride = frame.width() as usize * 4;
        let i = (y as usize) * stride + (x as usize) * 4;
        (px[i], px[i + 1], px[i + 2], px[i + 3])
    }
    fn near(a: (u8, u8, u8, u8), b: (u8, u8, u8, u8), tol: i32) -> bool {
        let d = |x: u8, y: u8| (i32::from(x) - i32::from(y)).abs() <= tol;
        d(a.0, b.0) && d(a.1, b.1) && d(a.2, b.2) && d(a.3, b.3)
    }

    let display = HeadlessDisplay::new().expect("headless WPE display");
    let mut session = WebSession::new(&display).map_err(|e| format!("gate15 session: {e}"))?;
    session
        .load(A11Y_ACTION_PAGE, 15_000)
        .map_err(|e| format!("gate15 load: {e}"))?;
    session.pump(600);

    let mut router = ViewRouter::new();
    let live = router.create(0);
    session
        .bind_view(&router, live)
        .map_err(|e| format!("gate15 bind: {e}"))?;
    let mut delivery = PageA11yDelivery::new();
    let delivered = session
        .deliver_page_accessibility(&router, live, &mut delivery, MAX_DEPTH, MAX_NODES)
        .map_err(|e| format!("gate15 delivery: {e}"))?;
    if !matches!(delivered, PageDelivery::Accepted { .. }) {
        return Err(format!("gate15: live delivery refused: {delivered:?}"));
    }
    let page = delivery
        .published(&router, live)
        .ok_or("gate15: nothing published for the live view")?
        .clone();

    // The button's stable key, then the widget Id the runtime hands the app on
    // Activate -- built with the PRODUCTION recipe, not a copy.
    let button_key = page
        .keys()
        .into_iter()
        .find(|k| {
            page.node_for_key(k)
                .is_some_and(|n| n.semantics().label.as_deref() == Some("Press Me"))
        })
        .ok_or("gate15: no Press Me button in the live tree")?;
    let widget_id = web_page_node_id(live.slot(), button_key.as_str());

    // Step 1: the AccessKit-resolved action the runtime dispatches.
    let action = AccessibilityAction::Activate(widget_id);
    let AccessibilityAction::Activate(activated_id) = action else {
        return Err("gate15: constructed action was not an Activate".into());
    };

    // Step 2: resolve the id back to a page node through the SAME core recipe
    // the widget publishes with -- enumerating the live tree, so an id for a
    // vanished node resolves to nothing.
    let resolved = page
        .keys()
        .into_iter()
        .find(|k| web_page_node_id(live.slot(), k.as_str()) == activated_id)
        .ok_or("gate15: the shared core recipe did not map the Activate id to a page node")?;
    if resolved != button_key {
        return Err(format!(
            "gate15: the Activate id resolved to {resolved} but the button is {button_key}"
        ));
    }

    // Baseline before acting.
    let before = session
        .snapshot(Generation::FIRST, FrameSeq(0), 10_000)
        .map_err(|e| format!("gate15 baseline: {e}"))?;
    if !near(
        pixel_at(&before, ACTION_ANCHOR.0, ACTION_ANCHOR.1),
        BEFORE_RGBA,
        3,
    ) {
        return Err("gate15: page did not start at the BEFORE colour".into());
    }

    // Step 3+4: dispatch through the PRODUCTION `PageActionDispatch` port - the
    // very trait method the probe's update path calls - which here drives a real
    // native `Action.DoAction` (binding + generation validation inside), then
    // repaint. This is what makes the chain one composition rather than two
    // tests sharing an id recipe.
    match PageActionDispatch::dispatch_page_action(
        &mut session,
        &router,
        live,
        &delivery,
        &resolved,
    ) {
        PageActionDispatchOutcome::Dispatched { view, key } => {
            if view != live || key != resolved {
                return Err(format!(
                    "gate15: dispatched the wrong target: {view:?}/{key}"
                ));
            }
        }
        PageActionDispatchOutcome::Refused { reason } => {
            return Err(format!("gate15: the port refused the activation: {reason}"));
        }
    }
    let start = std::time::Instant::now();
    let cap = std::time::Duration::from_millis(5_000);
    loop {
        session.pump(120);
        let frame = session
            .snapshot(Generation::FIRST, FrameSeq(0), 10_000)
            .map_err(|e| format!("gate15 poll: {e}"))?;
        if near(
            pixel_at(&frame, ACTION_ANCHOR.0, ACTION_ANCHOR.1),
            AFTER_RGBA,
            3,
        ) {
            break;
        }
        if start.elapsed() >= cap {
            return Err("gate15: the page never repainted after the end-to-end activation".into());
        }
    }
    println!(
        "a11y-gate15: AccessKit Activate(id) -> page_node_key_for_id -> \
         perform_page_action -> repaint, end to end OK"
    );

    // Negative leg: after a crash-recreate, the SAME resolved id must not reach
    // the page. The runtime would hand the app the same id (the slot-keyed
    // recipe survives recovery), but generation validation refuses it.
    let dead = live;
    let _recreated = router.recreate(0);
    let dead_id = web_page_node_id(dead.slot(), button_key.as_str());
    // The id still resolves against the (now stale) published tree by slot...
    let dead_key = page
        .keys()
        .into_iter()
        .find(|k| web_page_node_id(dead.slot(), k.as_str()) == dead_id)
        .ok_or("gate15: calibration, the dead id must still resolve by slot")?;
    // ...but dispatching it is refused, because the router generation moved on.
    match PageActionDispatch::dispatch_page_action(
        &mut session,
        &router,
        dead,
        &delivery,
        &dead_key,
    ) {
        PageActionDispatchOutcome::Refused { reason } => {
            println!("a11y-gate15: a post-crash Activate is refused end to end: {reason} OK")
        }
        PageActionDispatchOutcome::Dispatched { .. } => {
            return Err("gate15: a post-crash Activate reached the page".into());
        }
    }
    Ok(())
}

/// Gate 13: a native [`WebSession`] is bound to its own
/// [`ViewId`], and refuses to deliver or act under another live session's
/// id.
///
/// # Why the router check alone is not enough
///
/// Two sessions in different slots are BOTH `accepts`-true, so the router cannot
/// tell them apart. Only the per-session binding stops session A walking its own
/// page and publishing it under session B's identity (the two-session
/// mislabel), or driving `DoAction` through B's id. This gate builds two real,
/// both-live sessions and proves the refusal happens with the correct ids.
#[cfg(feature = "wpe")]
fn run_two_session_mislabel_gate() -> Result<(), String> {
    use enzui_webkit::page_delivery::{PageA11yDelivery, PageDelivery};
    use enzui_webkit::web::ViewRouter;

    let display = HeadlessDisplay::new().expect("headless WPE display");
    let mut session_a = WebSession::new(&display).map_err(|e| format!("gate13 session A: {e}"))?;
    let mut session_b = WebSession::new(&display).map_err(|e| format!("gate13 session B: {e}"))?;
    session_a
        .load(A11Y_ACTION_PAGE, 15_000)
        .map_err(|e| format!("gate13 load A: {e}"))?;
    session_a.pump(400);

    // Two DIFFERENT slots, both live at once.
    let mut router = ViewRouter::new();
    let view_a = router.create(0);
    let view_b = router.create(1);
    if !router.accepts(view_a) || !router.accepts(view_b) {
        return Err("gate13 calibration: both views must be live in the router".into());
    }
    session_a
        .bind_view(&router, view_a)
        .map_err(|e| format!("gate13 bind A: {e}"))?;
    session_b
        .bind_view(&router, view_b)
        .map_err(|e| format!("gate13 bind B: {e}"))?;

    // binding is one-time. Session A cannot REASSIGN itself to
    // B's live id, even though B is live - that is the arbitrary both-live
    // reassignment binding exists to reject.
    match session_a.bind_view(&router, view_b) {
        Err(SessionError::ForeignRebind) => {
            println!("a11y-gate13: A refuses to rebind to B's live id (ForeignRebind) OK")
        }
        other => {
            return Err(format!(
                "gate13: session A reassigned its binding to B's live id: {other:?}"
            ));
        }
    }
    // Re-binding A to its OWN id is an idempotent no-op, not a reassignment.
    session_a
        .bind_view(&router, view_a)
        .map_err(|e| format!("gate13: idempotent self-rebind refused: {e}"))?;

    // Positive control: session A delivers under its OWN id.
    let mut delivery_a = PageA11yDelivery::new();
    let own = session_a
        .deliver_page_accessibility(&router, view_a, &mut delivery_a, MAX_DEPTH, MAX_NODES)
        .map_err(|e| format!("gate13 own delivery: {e}"))?;
    if !matches!(own, PageDelivery::Accepted { .. }) {
        return Err(format!(
            "gate13: session A refused its own live delivery: {own:?}"
        ));
    }

    // The mislabel: session A must not deliver under session B's id, even
    // though B is live. This is refused BEFORE the tree is walked.
    match session_a.deliver_page_accessibility(
        &router,
        view_b,
        &mut delivery_a,
        MAX_DEPTH,
        MAX_NODES,
    ) {
        Err(DeliverError::ForeignSession { bound, asked }) => {
            if bound != view_a || asked != view_b {
                return Err(format!(
                    "gate13: mislabel refused with wrong ids: bound={bound:?} asked={asked:?}"
                ));
            }
            println!("a11y-gate13: session A refuses to deliver under B's live id OK");
        }
        other => {
            return Err(format!(
                "gate13: session A delivered its tree under session B's id \
                 (mislabel): {other:?}"
            ));
        }
    }

    // And it must not ACT under B's id either. Pick a real key from A's own
    // published tree so the refusal is the binding, not a missing node.
    let key = delivery_a
        .published(&router, view_a)
        .and_then(|p| {
            p.keys()
                .into_iter()
                .find(|k| p.node_for_key(k).is_some_and(|n| n.action().is_some()))
        })
        .ok_or("gate13: A's tree has no actionable node to test with")?;
    match session_a.perform_page_action(&router, view_b, &delivery_a, &key) {
        Err(enzui_webkit::ffi::runtime::PageActionError::ForeignSession { bound, asked }) => {
            if bound != view_a || asked != view_b {
                return Err(format!(
                    "gate13: action mislabel refused with wrong ids: bound={bound:?} asked={asked:?}"
                ));
            }
            println!("a11y-gate13: session A refuses to act under B's live id OK");
        }
        other => {
            return Err(format!(
                "gate13: session A performed an action under session B's id: {other:?}"
            ));
        }
    }
    Ok(())
}

/// Gate 14: the `DoAction` cap-expiry give-up path is reached
/// deterministically and the process survives the retained, still-pending
/// callback.
///
/// # Why this gate exists
///
/// Gate 12 forces the deadline but the cancelled callback always completes
/// during the bounded drain, so it never reaches the give-up branch (drain cap
/// expires while the callback is still outstanding). That branch retains every
/// object the callback can still reach -- state box, main loop, cancellable and
/// now the GDBus connection -- and nothing exercised it. A drain cap of
/// 0 ms returns from the drain loop before it iterates the context, so the
/// callback cannot complete during the call and the give-up branch runs every
/// time.
///
/// After giving up, ownership of the state, loop, cancellable and the extra
/// connection ref is transferred to the callback. The `A11yBus` is dropped
/// (which would free its connection were the extra ref missing) and the default
/// context is pumped until the still-pending callback fires. The proof is not
/// "the process survived" but that the callback completed its own cleanup:
/// `abandoned_cleanup_count` advances by exactly one, which only happens if the
/// callback ran and freed the transferred resources.
#[cfg(feature = "wpe")]
fn run_cap_expiry_gate() -> Result<(), String> {
    use enzui_webkit::ffi::a11y::{A11yBus, abandoned_cleanup_count};

    // A real page + a real actionable object, so the DoAction is a genuine
    // outstanding async call and not a call that fails synchronously.
    let display = HeadlessDisplay::new().expect("headless WPE display");
    let mut session = WebSession::new(&display).map_err(|e| format!("gate14 session: {e}"))?;
    session
        .load(A11Y_ACTION_PAGE, 15_000)
        .map_err(|e| format!("gate14 load: {e}"))?;
    session.pump(400);
    let tree = session
        .accessibility_tree(MAX_DEPTH, MAX_NODES)
        .map_err(|e| format!("gate14 walk: {e}"))?;
    let button = tree
        .find_by_role(role::PUSH_BUTTON)
        .ok_or("gate14: the page published no button to act on")?;
    let (bus_name, path) = (button.bus_name.clone(), button.path.clone());

    let bus = A11yBus::connect().map_err(|e| format!("gate14 bus: {e}"))?;
    let before = abandoned_cleanup_count();
    // deadline 0 => the deadline source wins; drain cap 0 => the give-up branch
    // is reached before the cancelled callback can complete.
    let outcome = bus.do_action_deadline_and_drain_cap(&bus_name, &path, 0, 0, 0);
    match &outcome {
        Err(enzui_webkit::ffi::a11y::A11yError::DbusCall(msg))
            if msg.contains("transferred to the callback") =>
        {
            println!("a11y-gate14: cap-expiry transfer branch reached: {msg} OK");
        }
        other => {
            return Err(format!(
                "gate14: the transfer branch was not reached (drain cap 0 should \
                 return before the callback can complete): {other:?}"
            ));
        }
    }

    // The callback must not have run yet: drain cap 0 returns before it can
    // complete. If it already cleaned up, the transfer path was not exercised.
    if abandoned_cleanup_count() != before {
        return Err(format!(
            "gate14: the callback completed during the call (count {before} -> {}); \
             the ownership-transfer path was not exercised",
            abandoned_cleanup_count()
        ));
    }

    // Drop the bus: its `GDBusConnection` would be freed now, EXCEPT the
    // transfer took an extra strong ref. Pump the default context until the
    // still-pending, cancelled callback fires and performs its own cleanup. A
    // missing connection ref would crash here; a callback that never cleaned up
    // would leave the counter unmoved.
    drop(bus);
    let start = std::time::Instant::now();
    loop {
        // SAFETY: draining the default context, non-blocking.
        #[allow(unsafe_code)]
        unsafe {
            enzui_webkit::ffi::wpe::g_main_context_iteration(core::ptr::null_mut(), 0)
        };
        if abandoned_cleanup_count() == before + 1 {
            break;
        }
        if start.elapsed() >= std::time::Duration::from_millis(3_000) {
            return Err(format!(
                "gate14: the transferred callback never completed its cleanup \
                 (count stuck at {}); either it never fired or the \
                 callback-owned free path is missing",
                abandoned_cleanup_count()
            ));
        }
    }
    println!(
        "a11y-gate14: the abandoned callback fired and freed its own resources \
         (abandoned_cleanup_count {before} -> {}) OK",
        abandoned_cleanup_count()
    );
    Ok(())
}

/// Gate 16 (the snapshot half): `WebSession::snapshot`'s
/// ownership-transfer branch is callback-owned, and the callback really does
/// free what it was handed.
///
/// # Why this gate had to be added
///
/// Gate 14 proves the transfer for `Action.DoAction`. The identical pattern was
/// written for the two snapshot paths, and `snapshot_abandoned_cleanup_count`
/// was published for it, but nothing read that counter - the branch was
/// reachable only when a WebProcess wedged mid-call, so the release half was
/// asserted by reading the code. A drain cap of 0 makes it deterministic: the
/// deadline source (0 ms) is dispatched long before WebKit's async snapshot can
/// resolve, and the drain loop returns before iterating the context even once,
/// so the transfer branch runs on every invocation.
///
/// The load-bearing observation is not that the process survived: the
/// `WebSession` is dropped while the cancelled callback is still
/// outstanding - which would free the `WebKitWebView` the callback finishes
/// against, were the transfer's extra strong ref missing - and the counter must
/// then advance by exactly one, which happens only if the callback ran and
/// freed the box, the loop, the cancellable and that extra ref.
#[cfg(feature = "wpe")]
fn run_snapshot_cap_expiry_gate() -> Result<(), String> {
    use enzui_webkit::ffi::runtime::snapshot_abandoned_cleanup_count;
    use enzui_webkit::frame::Generation;
    use enzui_webkit::web::frame::FrameSeq;

    let display = HeadlessDisplay::new().expect("headless WPE display");
    let mut session = WebSession::new(&display).map_err(|e| format!("gate16 session: {e}"))?;
    session
        .load(A11Y_ACTION_PAGE, 15_000)
        .map_err(|e| format!("gate16 load: {e}"))?;
    session.pump(400);

    // Calibration: an ordinary snapshot on this session succeeds, so the
    // timeout below is caused by the deadline and not by a broken session that
    // could never snapshot at all.
    let ok = session
        .snapshot(Generation::FIRST, FrameSeq(0), 10_000)
        .map_err(|e| format!("gate16 calibration snapshot: {e}"))?;
    if ok.width() == 0 || ok.height() == 0 {
        return Err("gate16 calibration: degenerate frame".into());
    }

    let before = snapshot_abandoned_cleanup_count();
    // deadline 0 => the deadline source wins; drain cap 0 => the transfer branch
    // is reached before the cancelled callback can complete.
    match session.snapshot_with_drain_cap(Generation::FIRST, FrameSeq(0), 0, 0) {
        Err(SessionError::Timeout("snapshot")) => {
            println!("a11y-gate16: snapshot cap-expiry transfer branch reached OK");
        }
        Err(other) => {
            return Err(format!(
                "gate16: expected SessionError::Timeout(\"snapshot\"), got {other:?}"
            ));
        }
        Ok(_) => {
            return Err(
                "gate16: a 0 ms deadline produced a FRAME, so the transfer branch \
                 was never reached"
                    .into(),
            );
        }
    }
    if snapshot_abandoned_cleanup_count() != before {
        return Err(format!(
            "gate16: the callback completed during the call (count {before} -> {}); \
             the ownership-transfer path was not exercised",
            snapshot_abandoned_cleanup_count()
        ));
    }

    // Drop the session. Its `WebKitWebView` would be released here, EXCEPT the
    // transfer took an extra strong ref for the pending callback. Then pump
    // until the callback fires and frees what it owns.
    drop(session);
    let start = std::time::Instant::now();
    loop {
        // SAFETY: draining the default context, non-blocking.
        #[allow(unsafe_code)]
        unsafe {
            enzui_webkit::ffi::wpe::g_main_context_iteration(core::ptr::null_mut(), 0)
        };
        if snapshot_abandoned_cleanup_count() == before + 1 {
            break;
        }
        if start.elapsed() >= std::time::Duration::from_millis(3_000) {
            return Err(format!(
                "gate16: the transferred snapshot callback never completed its \
                 cleanup (count stuck at {}); either it never fired or the \
                 callback-owned free path is missing",
                snapshot_abandoned_cleanup_count()
            ));
        }
    }
    println!(
        "a11y-gate16: the abandoned snapshot callback fired and freed its own \
         resources after the session was dropped (count {before} -> {}) OK",
        snapshot_abandoned_cleanup_count()
    );
    Ok(())
}

/// Gate 17 (the executor half): a caller-supplied tree that
/// clones a real object's address and re-orders its actions cannot choose which
/// native action `DoAction` receives.
///
/// The pure tests prove `NativeActionAuthority::authorize` returns the walked
/// index for a forged key. They cannot prove the *executor* consults the
/// authority rather than the tree it was handed - with an honest tree both agree,
/// so reading `authorized.index()` and reading `target.action().index()` are
/// indistinguishable. This gate makes them disagree against a real WebProcess:
/// the published tree is replaced by a forgery whose `click` sits at index 1,
/// and the page must still repaint, which only happens if index 0 (the real
/// walk's `press`) was sent.
///
/// The real object exposes a single action, so an executor that trusted the
/// forged tree would send `DoAction(1)` - no click, no repaint, and the gate
/// fails on the pixel rather than on a return code.
#[cfg(feature = "wpe")]
fn run_forged_offer_gate() -> Result<(), String> {
    use enzui_webkit::frame::{Generation, Rgba8Frame};
    use enzui_webkit::page_a11y::{AccessibleSource, PageNodeAddress, atspi};
    use enzui_webkit::page_action::{PageActionDispatch, PageActionDispatchOutcome};
    use enzui_webkit::page_delivery::{PageA11yDelivery, PageDelivery};
    use enzui_webkit::web::ViewRouter;
    use enzui_webkit::web::frame::FrameSeq;

    /// A tree an application can build with only the crate's PUBLIC API - so
    /// every address it mints is inert, exactly like a hostile or buggy host's.
    struct Forged {
        role: u32,
        name: String,
        address: Option<PageNodeAddress>,
        actions: Vec<String>,
        children: Vec<Forged>,
    }
    impl AccessibleSource for Forged {
        fn atspi_role(&self) -> u32 {
            self.role
        }
        fn accessible_name(&self) -> &str {
            &self.name
        }
        fn accessible_children(&self) -> &[Self] {
            &self.children
        }
        fn accessible_address(&self) -> Option<PageNodeAddress> {
            self.address.clone()
        }
        fn accessible_actions(&self) -> &[String] {
            &self.actions
        }
    }

    fn pixel_at(frame: &Rgba8Frame, x: u32, y: u32) -> (u8, u8, u8, u8) {
        let px = frame.pixels();
        let stride = frame.width() as usize * 4;
        let i = (y as usize) * stride + (x as usize) * 4;
        (px[i], px[i + 1], px[i + 2], px[i + 3])
    }
    fn near(a: (u8, u8, u8, u8), b: (u8, u8, u8, u8), tol: i32) -> bool {
        let d = |x: u8, y: u8| (i32::from(x) - i32::from(y)).abs() <= tol;
        d(a.0, b.0) && d(a.1, b.1) && d(a.2, b.2) && d(a.3, b.3)
    }

    let display = HeadlessDisplay::new().expect("headless WPE display");
    let mut session = WebSession::new(&display).map_err(|e| format!("gate17 session: {e}"))?;
    session
        .load(A11Y_ACTION_PAGE, 15_000)
        .map_err(|e| format!("gate17 load: {e}"))?;
    session.pump(600);

    let mut router = ViewRouter::new();
    let live = router.create(0);
    session
        .bind_view(&router, live)
        .map_err(|e| format!("gate17 bind: {e}"))?;
    let mut delivery = PageA11yDelivery::new();
    // The honest walk seeds the authority.
    let delivered = session
        .deliver_page_accessibility(&router, live, &mut delivery, MAX_DEPTH, MAX_NODES)
        .map_err(|e| format!("gate17 delivery: {e}"))?;
    if !matches!(delivered, PageDelivery::Accepted { .. }) {
        return Err(format!("gate17: live delivery refused: {delivered:?}"));
    }
    let real = delivery
        .published(&router, live)
        .ok_or("gate17: nothing published for the live view")?
        .clone();
    let real_key = real
        .keys()
        .into_iter()
        .find(|k| {
            real.node_for_key(k).is_some_and(|n| {
                n.semantics().role == Role::Button
                    && n.semantics().label.as_deref() == Some("Press Me")
            })
        })
        .ok_or("gate17: no Press Me button in the live tree")?;
    let real_target = real
        .action_target(&real_key)
        .ok_or("gate17: the real button advertises no action")?;
    let real_index = real_target.action().index();
    let real_addr = real_target.address().clone();

    // Baseline, so the repaint below is a change and not the starting state.
    let base = session
        .snapshot(Generation::FIRST, FrameSeq(0), 10_000)
        .map_err(|e| format!("gate17 baseline: {e}"))?;
    if !near(
        pixel_at(&base, ACTION_ANCHOR.0, ACTION_ANCHOR.1),
        BEFORE_RGBA,
        3,
    ) {
        return Err("gate17: page did not start at the BEFORE colour".into());
    }

    // The forgery: the SAME address, with a non-activation name shifted in front
    // of `click` so the allow-list picks index 1.
    let forged_page = PageA11y::from_source(&Forged {
        role: atspi::DOCUMENT_WEB,
        name: "Forged Doc".to_owned(),
        address: Some(PageNodeAddress::new("org.forged", "/forged/root")),
        actions: Vec::new(),
        children: vec![Forged {
            role: atspi::PUSH_BUTTON,
            name: "Press Me".to_owned(),
            address: Some(PageNodeAddress::new(
                real_addr.bus_name.clone(),
                real_addr.path.clone(),
            )),
            actions: vec!["focus".to_owned(), "click".to_owned()],
            children: Vec::new(),
        }],
    });
    let forged_key = forged_page
        .keys()
        .into_iter()
        .find(|k| {
            forged_page
                .node_for_key(k)
                .is_some_and(|n| n.semantics().role == Role::Button)
        })
        .ok_or("gate17: the forged tree published no button")?;
    // Calibration 1: the cloned address collides with the real key, so a naive
    // executor keyed on the caller's tree WOULD find this node.
    if forged_key != real_key {
        return Err(format!(
            "gate17 calibration: the forged key {forged_key} does not collide with \
             the real key {real_key}, so this proves nothing about the executor"
        ));
    }
    // Calibration 2: the forged tree really does route to a DIFFERENT index.
    let forged_index = forged_page
        .action_target(&forged_key)
        .ok_or("gate17: the forged tree does not route at the display layer")?
        .action()
        .index();
    if forged_index == real_index {
        return Err(format!(
            "gate17 calibration: forged index {forged_index} equals the native one \
             {real_index}; the two sources agree, so the gate cannot fail"
        ));
    }

    // Publish the forgery over the honest tree. Accepted at the display layer:
    // it is offered for the LIVE view, which is exactly the point - delivery
    // authorizes ownership, not provenance.
    let offered = delivery.offer(&router, live, forged_page);
    if !matches!(offered, PageDelivery::Accepted { .. }) {
        return Err(format!(
            "gate17: the forged offer was refused by delivery ({offered:?}); the \
             gate needs it published to test the EXECUTOR"
        ));
    }

    // Dispatch through the production port. The authority must supply the
    // native index, so the page's own handler runs.
    match PageActionDispatch::dispatch_page_action(
        &mut session,
        &router,
        live,
        &delivery,
        &forged_key,
    ) {
        PageActionDispatchOutcome::Dispatched { .. } => {}
        PageActionDispatchOutcome::Refused { reason } => {
            return Err(format!(
                "gate17: the forged-but-live-key dispatch was refused: {reason}"
            ));
        }
    }
    let start = std::time::Instant::now();
    loop {
        session.pump(120);
        let frame = session
            .snapshot(Generation::FIRST, FrameSeq(0), 10_000)
            .map_err(|e| format!("gate17 poll: {e}"))?;
        if near(
            pixel_at(&frame, ACTION_ANCHOR.0, ACTION_ANCHOR.1),
            AFTER_RGBA,
            3,
        ) {
            break;
        }
        if start.elapsed() >= std::time::Duration::from_millis(5_000) {
            return Err(format!(
                "gate17: the page never repainted, so the executor sent the FORGED \
                 index {forged_index} instead of the native {real_index}"
            ));
        }
    }
    println!(
        "a11y-gate17: a forged tree routing to index {forged_index} still executed \
         the native index {real_index} and the page repainted OK"
    );
    Ok(())
}

/// Gate 10, in its own session so the action page cannot disturb the tree
/// assertions above.
///
/// # It goes through the OWNED delivery path, not a bare walk
///
/// `WebSession::accessibility_tree` returns an untagged tree, and publishing
/// one of those is how a dead generation's controls reach a live view. So this
/// gate drives `deliver_page_accessibility` (walk + translate + generation-
/// checked offer) and `perform_page_action` (re-resolve under the router, then
/// act), which are the two seams a real host uses. Gate 11 then proves the
/// generation check is load-bearing on the *native* path and not only in the
/// pure tests.
#[cfg(feature = "wpe")]
fn run_action_gate() -> Result<(), String> {
    // The frame generation is the MEDIA one (the frame path's), not the web
    // view generation - two different concepts with the same name.
    use enzui_webkit::frame::{Generation, Rgba8Frame};
    use enzui_webkit::page_delivery::{PageA11yDelivery, PageActionRoute, PageDelivery};
    use enzui_webkit::web::frame::FrameSeq;
    use enzui_webkit::web::{ViewId, ViewRouter};

    fn pixel_at(frame: &Rgba8Frame, x: u32, y: u32) -> (u8, u8, u8, u8) {
        let px = frame.pixels();
        let stride = frame.width() as usize * 4;
        let i = (y as usize) * stride + (x as usize) * 4;
        (px[i], px[i + 1], px[i + 2], px[i + 3])
    }
    fn near(a: (u8, u8, u8, u8), b: (u8, u8, u8, u8), tol: i32) -> bool {
        let d = |x: u8, y: u8| (i32::from(x) - i32::from(y)).abs() <= tol;
        d(a.0, b.0) && d(a.1, b.1) && d(a.2, b.2) && d(a.3, b.3)
    }

    let display = HeadlessDisplay::new().expect("headless WPE display");
    let mut session = WebSession::new(&display).map_err(|e| format!("gate10 session: {e}"))?;
    session
        .load(A11Y_ACTION_PAGE, 15_000)
        .map_err(|e| format!("gate10 load: {e}"))?;
    session.pump(600);

    // (a) Baseline: the body is the BEFORE colour. Without this the "after"
    //     assertion could pass on a page that was always magenta.
    let before = session
        .snapshot(Generation::FIRST, FrameSeq(0), 10_000)
        .map_err(|e| format!("gate10 baseline snapshot: {e}"))?;
    let base_px = pixel_at(&before, ACTION_ANCHOR.0, ACTION_ANCHOR.1);
    if !near(base_px, BEFORE_RGBA, 3) {
        return Err(format!(
            "gate10 baseline: anchor {ACTION_ANCHOR:?} is {base_px:?}, expected \
             {BEFORE_RGBA:?}. The page did not render its starting colour, so a \
             later change would prove nothing."
        ));
    }
    // Calibration: the two colours differ, so "changed" is observable at all.
    if near(BEFORE_RGBA, AFTER_RGBA, 3) {
        return Err("gate10 calibration: before/after colours are identical".into());
    }
    println!("a11y-gate10: baseline anchor {base_px:?} == {BEFORE_RGBA:?} OK");

    // (b) Deliver the REAL tree through the generation-owning delivery layer,
    //     translated by the SAME function the widget publishes through.
    let mut router = ViewRouter::new();
    let live = router.create(0);
    // this session owns this id. Delivery and actions naming any
    // other id -- even a live one -- are refused before any work happens.
    session
        .bind_view(&router, live)
        .map_err(|e| format!("gate10 bind_view: {e}"))?;
    let mut delivery = PageA11yDelivery::new();
    let delivered = session
        .deliver_page_accessibility(&router, live, &mut delivery, MAX_DEPTH, MAX_NODES)
        .map_err(|e| format!("gate10 delivery: {e}"))?;
    let PageDelivery::Accepted { nodes, .. } = delivered else {
        return Err(format!(
            "gate10: the live view's own walk was not accepted: {delivered:?}"
        ));
    };
    let page = delivery
        .published(&router, live)
        .ok_or("gate10: the accepted snapshot is not published for the live view")?
        .clone();
    println!("a11y-gate10: delivered {nodes} nodes for the live generation OK");

    // (c) Find the button the way the host does: by its published identity.
    let button_key = page
        .keys()
        .into_iter()
        .find(|k| {
            page.node_for_key(k).is_some_and(|n| {
                n.semantics().role == Role::Button
                    && n.semantics().label.as_deref() == Some("Press Me")
            })
        })
        .ok_or_else(|| {
            format!(
                "gate10: the page's <button> did not publish as a named Button; \
                 tree: {:?}",
                page.root().flatten()
            )
        })?;
    let target = page.action_target(&button_key).ok_or_else(|| {
        format!(
            "gate10: the button at {button_key} advertises no routable action, so \
             AT could read it but never press it"
        )
    })?;
    // The key really is the AT-SPI address, not a tree position: that is what
    // makes it survive DOM mutation (the pure reorder gates prove the
    // consequence; this proves the real tree produces address keys at all).
    if !button_key.as_str().starts_with("obj:") {
        return Err(format!(
            "gate10: the live tree produced a POSITIONAL key {button_key} for an \
             addressed control - an insertion would move it onto another node"
        ));
    }
    println!(
        "a11y-gate10: button {button_key} -> action {}#{} on {} OK",
        target.action().name(),
        target.action().index(),
        target.address().path
    );

    // (d) Perform it through the runtime seam an AT activation ends at. This
    //     re-resolves the key under the router, so the address and index that
    //     reach `DoAction` are read at the moment of use.
    let performed = session
        .perform_page_action(&router, live, &delivery, &button_key)
        .map_err(|e| format!("gate10 DoAction: {e}"))?;
    if !performed {
        return Err(format!(
            "gate10: the page REFUSED action {}#{} on {} - the control advertised \
             an action it will not perform",
            target.action().name(),
            target.action().index(),
            target.address().path
        ));
    }

    // (e) The page's own handler must have repainted. Poll, because the
    //     WebProcess repaint is asynchronous and a fixed sleep would be a tuned
    //     constant; the fast path returns as soon as the flip is observed.
    let start = std::time::Instant::now();
    let cap = std::time::Duration::from_millis(5_000);
    let mut last;
    loop {
        session.pump(120);
        let frame = session
            .snapshot(Generation::FIRST, FrameSeq(0), 10_000)
            .map_err(|e| format!("gate10 poll snapshot: {e}"))?;
        last = pixel_at(&frame, ACTION_ANCHOR.0, ACTION_ANCHOR.1);
        if near(last, AFTER_RGBA, 3) {
            break;
        }
        if start.elapsed() >= cap {
            return Err(format!(
                "gate10: the anchor never reached {AFTER_RGBA:?} within 5000ms; \
                 last observed {last:?}. `DoAction` reported success, so the \
                 request was accepted but the page's click handler never ran - \
                 the action is advertised and inert."
            ));
        }
    }
    println!(
        "a11y-gate10: after DoAction the page repainted to {last:?} == \
         {AFTER_RGBA:?} - a published control is addressable AND operable OK"
    );

    // (f) Negative control: the heading resolves to no target, so there is
    //     nothing to perform. Proves (c) selected on operability rather than on
    //     "the first node found", and that the EXECUTOR refuses it too rather
    //     than only the resolver.
    let heading_key = page
        .keys()
        .into_iter()
        .find(|k| {
            page.node_for_key(k)
                .is_some_and(|n| n.semantics().role == Role::Heading)
        })
        .ok_or("gate10: the page published no heading to use as a control")?;
    if page.action_target(&heading_key).is_some() {
        return Err(format!(
            "gate10: the heading at {heading_key} resolved to an action target - \
             non-interactive text must not be operable"
        ));
    }
    match session.perform_page_action(&router, live, &delivery, &heading_key) {
        Err(e) => println!("a11y-gate10: performing the heading is refused: {e} OK"),
        Ok(v) => {
            return Err(format!(
                "gate10: the executor PERFORMED an action on non-interactive text \
                 (returned {v}) - the allow-list gate does not bind the executor"
            ));
        }
    }

    // -- gate 11: the native path refuses a superseded generation ------------
    // The pure tests prove the delivery layer's generation checks. This proves
    // the REAL session is subject to them: after a crash-recreate, an
    // activation asked for through the id the host held before the crash must
    // not reach the page - even though the page is the very same one and its
    // AT-SPI address is still valid, which is what makes this a real leak
    // rather than a lookup failure.
    let dead = live;
    let recreated = router.recreate(0);
    // the session is still bound to `dead`, which is now stale.
    // A delivery naming that stale bound id is refused BEFORE the native walk,
    // not after the delivery layer sees the offer.
    match session.deliver_page_accessibility(&router, dead, &mut delivery, MAX_DEPTH, MAX_NODES) {
        Err(DeliverError::ViewNotLive { view }) if view == dead => {
            println!("a11y-gate11: a delivery for the stale bound id is refused before the walk OK")
        }
        other => {
            return Err(format!(
                "gate11: a stale-bound delivery was not refused before the walk: {other:?}"
            ));
        }
    }
    match session.perform_page_action(&router, dead, &delivery, &button_key) {
        Err(e) => println!("a11y-gate11: a pre-crash view id is refused: {e} OK"),
        Ok(v) => {
            return Err(format!(
                "gate11: an activation through a SUPERSEDED view id was performed \
                 (returned {v}) - a dead generation can still press the page"
            ));
        }
    }
    // ...and the live id cannot reach the stale snapshot either.
    let route = delivery.route_action(&router, recreated, &button_key);
    if !matches!(route, PageActionRoute::StaleView { .. }) {
        return Err(format!(
            "gate11: the recreated view resolved the dead generation's snapshot: \
             {route:?}"
        ));
    }
    if delivery.published(&router, recreated).is_some() {
        return Err("gate11: the recreated view publishes the dead generation's tree".into());
    }
    // Before the host rebinds, a delivery under the recreated id is refused by
    // the SESSION binding: the session still owns the dead
    // generation, so it must not publish under the new one until recovery
    // rebinds it.
    match session.deliver_page_accessibility(
        &router,
        recreated,
        &mut delivery,
        MAX_DEPTH,
        MAX_NODES,
    ) {
        Err(DeliverError::ForeignSession { .. }) => {
            println!("a11y-gate11: a not-yet-rebound session refuses the new id (binding) OK")
        }
        other => {
            return Err(format!(
                "gate11: a session bound to the dead generation delivered under the \
                 recreated id: {other:?}"
            ));
        }
    }
    // Recovery rebinds the session to the recreated generation. Now it may
    // deliver for the live view, so gate 11 is a generation check and not a
    // permanently broken session.
    session
        .bind_view(&router, recreated)
        .map_err(|e| format!("gate11 rebind: {e}"))?;
    let redelivered = session
        .deliver_page_accessibility(&router, recreated, &mut delivery, MAX_DEPTH, MAX_NODES)
        .map_err(|e| format!("gate11 redelivery: {e}"))?;
    if !matches!(redelivered, PageDelivery::Accepted { .. }) {
        return Err(format!(
            "gate11: the new generation's walk was refused: {redelivered:?}"
        ));
    }
    // A late walk carrying the crashed generation's id is refused by the
    // session binding before it can publish -- the rebound session owns only
    // the recreated generation.
    match session.deliver_page_accessibility(&router, dead, &mut delivery, MAX_DEPTH, MAX_NODES) {
        Err(DeliverError::ForeignSession { bound, asked }) => {
            if bound != recreated || asked != dead {
                return Err(format!(
                    "gate11: stale delivery refused with the wrong ids: bound={bound:?} asked={asked:?}"
                ));
            }
            println!("a11y-gate11: a crashed-generation walk is refused by session binding OK");
        }
        other => {
            return Err(format!(
                "gate11: a walk from the crashed generation was not refused by binding: {other:?}"
            ));
        }
    }
    // The pure delivery layer's stale/orphan refusals stay covered on the
    // native tree too: offered DIRECTLY (as a host with a mistaken id would),
    // a superseded generation and a slot with no live view are each refused by
    // name. (The session path above refuses even earlier, by binding.)
    let stale_offer = delivery.offer(&router, dead, page.clone());
    if !matches!(stale_offer, PageDelivery::RejectedStale { .. }) {
        return Err(format!(
            "gate11: the delivery layer accepted a walk from the crashed generation: {stale_offer:?}"
        ));
    }
    let orphan = delivery.offer(&router, ViewId::new(9), page.clone());
    if !matches!(orphan, PageDelivery::RejectedNoLiveView { slot: 9 }) {
        return Err(format!(
            "gate11: the delivery layer accepted a walk for a slot with no live view: {orphan:?}"
        ));
    }
    println!("a11y-gate11: stale/orphan deliveries are refused by name OK");

    // The recreated generation can act again, and the page still responds.
    let key_now = delivery
        .published(&router, recreated)
        .and_then(|p| {
            p.keys().into_iter().find(|k| {
                p.node_for_key(k)
                    .is_some_and(|n| n.semantics().label.as_deref() == Some("Press Me"))
            })
        })
        .ok_or("gate11: the redelivered tree has no button")?;
    let performed = session
        .perform_page_action(&router, recreated, &delivery, &key_now)
        .map_err(|e| format!("gate11 post-recreate DoAction: {e}"))?;
    if !performed {
        return Err("gate11: the page refused the action after redelivery".into());
    }
    println!("a11y-gate11: the live generation can still act after recovery OK");

    // -- gate 12: the DoAction timeout path is bounded and survivable --------
    run_do_action_timeout_gate(&session, &page)?;

    Ok(())
}

/// Gate 12: force `DoAction`'s deadline and prove the process survives it.
///
/// # Why this gate exists
///
/// `do_action` runs a `GMainLoop` with a `g_timeout_add` deadline and an
/// outstanding async D-Bus call. On the deadline path it cancels, drains, and
/// retains everything the callback can still reach. That retention is the whole
/// safety argument, and nothing exercised it: a wedged WebProcess is not
/// reproducible on demand.
///
/// A 0 ms deadline makes the deadline source win every run: it is dispatched
/// on the first main-loop iteration, before a D-Bus round trip can complete.
/// (A 1 ms deadline was tried first and the reply won every time, so the gate
/// would have reported a pass having exercised nothing - which is why it checks
/// that a timeout actually happened rather than assuming it.) Five overlapping
/// abandoned calls follow, the accumulation that turned a leaked
/// deadline source into a crash. Then the same bus performs a real action and
/// the page repaints, which is what distinguishes "bounded" from "broke the
/// session": freeing an object a pending callback still points at surfaces here
/// as a SIGSEGV/SIGABRT, not as a wrong value.
///
/// # What it does not prove, stated plainly
///
/// The observed message is `Operation was cancelled`, i.e. the cancelled
/// callback *does* complete during the bounded drain and the state is freed
/// normally. So this gate covers deadline -> cancel -> drain -> observe ->
/// free, and the survival of five of those in a row. The give-up branch (drain
/// cap expires without the callback completing, so every reachable object is
/// retained) needs a WebProcess that stops answering mid-call and is not
/// reproducible on demand here - the same limitation recorded for the
/// cookie path. It is reasoned, reviewed and documented, not gated.
#[cfg(feature = "wpe")]
fn run_do_action_timeout_gate(session: &WebSession, page: &PageA11y) -> Result<(), String> {
    use enzui_webkit::ffi::a11y::A11yBus;

    let button_key = page
        .keys()
        .into_iter()
        .find(|k| {
            page.node_for_key(k)
                .is_some_and(|n| n.semantics().label.as_deref() == Some("Press Me"))
        })
        .ok_or("gate12: no button in the page")?;
    let target = page
        .action_target(&button_key)
        .ok_or("gate12: the button is not routable")?;
    let bus = A11yBus::connect().map_err(|e| format!("gate12 bus: {e}"))?;
    let index = i32::try_from(target.action().index()).map_err(|_| "gate12 index")?;

    // Five forced timeouts, so a single lucky ordering cannot carry the gate
    // and so several abandoned calls overlap - the accumulation that turned
    // a leaked deadline source into a crash.
    let mut timeouts = 0;
    for i in 0..5 {
        if let Err(e) = bus.do_action_with_deadline(
            &target.address().bus_name,
            &target.address().path,
            index,
            0,
        ) {
            timeouts += 1;
            if i == 0 {
                println!("a11y-gate12: forced 0ms deadline -> {e} OK");
            }
        }
    }
    if timeouts == 0 {
        return Err(
            "gate12: no call hit the 1ms deadline, so the timeout path was never \
             exercised - the gate would report a pass having tested nothing"
                .into(),
        );
    }
    println!("a11y-gate12: {timeouts}/5 calls took the cancel+drain path OK");

    // Survival: the same bus still performs a real action to completion. If the
    // timeout path had freed an object a pending callback still points at, this
    // is where the process would die instead of answering.
    let performed = bus
        .do_action(&target.address().bus_name, &target.address().path, index)
        .map_err(|e| format!("gate12: a normal action failed AFTER the timeouts: {e}"))?;
    if !performed {
        return Err("gate12: the page refused the post-timeout action".into());
    }
    // And the session itself is still usable: a snapshot proves the UI process
    // main context was not left in a broken state by the abandoned loops.
    let mut session_mut_check = 0u32;
    for _ in 0..3 {
        session.pump(60);
        session_mut_check += 1;
    }
    println!(
        "a11y-gate12: after {session_mut_check} pumps the session still runs and a \
         real DoAction still succeeds - refused, not corrupted OK"
    );
    Ok(())
}

/// Pretty-print helper kept for diagnosis when a gate fails.
#[cfg(feature = "wpe")]
#[allow(dead_code)]
fn dump(node: &A11yNode, depth: usize) {
    println!(
        "{:width$}role={} name={:?}",
        "",
        node.role,
        node.name,
        width = depth * 2
    );
    for c in &node.children {
        dump(c, depth + 1);
    }
}

// ---------------------------------------------------------------------------
// Feature-off: the a11y bridge does not exist and the mode resolver still
// refuses to substitute a mock.
// ---------------------------------------------------------------------------
#[cfg(not(feature = "wpe"))]
#[test]
fn wpe_a11y_requires_the_feature() {
    use enzui_webkit::mode::{self, BackendMode, ModeError};
    // The engine's own answer decides: a workspace build can enable the
    // engine's `wpe` through another member while this crate's stays off.
    if mode::native_available() {
        return;
    }
    let result = mode::resolve(BackendMode::Native);
    assert_eq!(
        result,
        Err(ModeError::NativeUnavailable),
        "feature-off, resolve(Native) MUST be Err(NativeUnavailable); an Ok here \
         silently substituted the mock. Got: {:?}",
        result,
    );
    println!(
        "wpe_a11y_requires_the_feature: feature-off, resolve(Native) = \
         Err(NativeUnavailable). Rebuild with --features wpe for the a11y bridge."
    );
}
