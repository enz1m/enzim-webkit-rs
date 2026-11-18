// Published-page actions: a published page control is addressable by an AT
// action. These tests prove the round trip through `resolve_action` to the same
// page-tree path.
//
// `include!`d by `web_view/tests.rs` in the same module as `page_a11y.rs`,
// which supplies `AtspiFixture`.

// ---------------------------------------------------------------------------
// Published-page actions: a published page control is addressable by an AT action.
//
// The page accessibility tests prove read-only publication; these prove the
// round trip. The collector advertises `Click` on a routable page node, the
// real `resolve_action` turns an AccessKit request into `Activate(id)`, and that
// id resolves back to the *same* page-tree path the node was published at.
// A tree that published perfect semantics and could not be operated passes
// every publication test and fails these.
// ---------------------------------------------------------------------------

/// A page whose button carries a real machine-readable `click` action.
fn actionable_fixture() -> AtspiFixture {
    AtspiFixture::new(
        atspi::DOCUMENT_WEB,
        "Doc",
        vec![
            AtspiFixture::leaf(atspi::HEADING, "Just A Heading"),
            AtspiFixture::leaf(atspi::PUSH_BUTTON, "Submit Order").with_action("click"),
        ],
    )
}

/// The `NodeId -> Id` map the published tree resolves an action against.
fn published_map(el: Element<'_, ()>) -> enzui_core::collect::NodeIdMap {
    let mut renderer = iced_test::futures::futures::executor::block_on(
        <Renderer as iced::advanced::renderer::Headless>::new(
            iced::advanced::renderer::Settings::default(),
            std::env::var("ICED_TEST_BACKEND").ok().as_deref(),
        ),
    )
    .expect("headless renderer");
    let mut ui = iced_test::runtime::user_interface::UserInterface::build(
        el,
        Size::new(1400.0, 900.0),
        iced_test::runtime::user_interface::Cache::default(),
        &mut renderer,
    );
    let mut collector = SemanticsCollector::new();
    ui.operate(&renderer, &mut collector as &mut dyn Operation);
    collector.to_tree_update_with_ids().1
}

#[test]
fn an_at_click_on_a_published_page_button_resolves_to_an_activation_of_that_node() {
    use enzui_core::a11y_action::{AccessibilityAction, resolve_action};

    let f = frame(1);
    let page = PageA11y::from_source(&actionable_fixture());
    // Calibration: the translation really did make the button routable, so a
    // failure below is about publication/routing rather than about the fixture.
    assert_eq!(
        page.actionable_count(),
        1,
        "calibration: exactly the button must be actionable"
    );
    let el: Element<'_, ()> = enz_web_view(view(), Some(&f), true)
        .title("Example")
        .page_a11y(published(view(), page.clone()), &live_router_for(view()))
        .into();
    let map = published_map(el);

    // Find the published button by the id the one recipe derives for its key.
    let button_key = page.key_at_path("0.1").expect("the button is published");
    let button_id = page_node_id(view(), &button_key);
    let node = map
        .iter_ids()
        .find(|(_, id)| **id == button_id)
        .map(|(node, _)| node)
        .unwrap_or_else(|| panic!("the page's button was not published with a routable id"));

    let resolved = resolve_action(accesskit::Action::Click, node, None, &map);
    assert_eq!(
        resolved,
        Some(AccessibilityAction::Activate(button_id.clone())),
        "an AT Click on the page's button must resolve to an Activate of that \
         node, not to Unhandled"
    );

    // ...and the activated id maps back to the node the action is performed on.
    assert_eq!(
        page_node_key_for_id(&page, view(), &button_id),
        Some(button_key.clone()),
        "the activated id must resolve to the button's own page node"
    );
    let target = page
        .action_target(&button_key)
        .expect("the button must carry an action target");
    assert_eq!(target.address().path, "/page/Submit Order");
    assert_eq!(target.action().name(), "click");
}

#[test]
fn a_dom_insertion_does_not_change_a_published_page_controls_id() {
    // The published id is the handle AT holds between frames and the handle a
    // queued activation comes back with. If it moved when the document did, a
    // positional identifier held across an ordinary insertion would resolve
    // to the control shifted into that position, activating the wrong target.
    let before = PageA11y::from_source(&AtspiFixture::new(
        atspi::DOCUMENT_WEB,
        "Doc",
        vec![AtspiFixture::leaf(atspi::PUSH_BUTTON, "Publish").with_action("click")],
    ));
    let after = PageA11y::from_source(&AtspiFixture::new(
        atspi::DOCUMENT_WEB,
        "Doc",
        vec![
            AtspiFixture::leaf(atspi::HEADING, "Cookie banner"),
            AtspiFixture::leaf(atspi::PUSH_BUTTON, "Publish").with_action("click"),
        ],
    ));

    // The ids are read out of the rendered trees, not computed on the side, so
    // this is what a collector actually published in each case.
    let f = frame(1);
    let render_map = |page: &PageA11y| -> enzui_core::collect::NodeIdMap {
        let el: Element<'_, ()> = enz_web_view(view(), Some(&f), true)
            .title("Example")
            .page_a11y(published(view(), page.clone()), &live_router_for(view()))
            .into();
        published_map(el)
    };
    let before_map = render_map(&before);
    let after_map = render_map(&after);

    let button_before = before
        .key_at_path("0.0")
        .expect("the button is published before the insertion");
    let button_after = after
        .key_at_path("0.1")
        .expect("the button is published after the insertion");
    let id_before = page_node_id(view(), &button_before);
    let id_after = page_node_id(view(), &button_after);

    // Calibration: both trees really published that id.
    assert!(
        before_map.iter_ids().any(|(_, id)| *id == id_before),
        "calibration: the button's id must appear in the pre-insertion tree"
    );
    assert!(
        after_map.iter_ids().any(|(_, id)| *id == id_after),
        "calibration: the button's id must appear in the post-insertion tree"
    );
    // The document really changed shape: the node at the button's pre-
    // insertion position is now the banner, which is what a positional id
    // would have handed the queued activation.
    assert_eq!(
        after
            .node_at("0.0")
            .map(|n| convert::role(n.semantics().role))
            .expect("position 0.0 is occupied after the insertion"),
        Role::Heading,
        "the fixture must actually shift the button, or this gate proves nothing"
    );

    assert_eq!(
        id_before, id_after,
        "the button's published id changed because a sibling was inserted above \
         it -- AT's handle for that control is not stable"
    );
    // And the id still resolves, in the new tree, to the button rather than to
    // the banner that took its index.
    assert_eq!(
        page_node_key_for_id(&after, view(), &id_before),
        Some(button_after),
        "the pre-insertion id must resolve to the button in the post-insertion \
         tree"
    );
}
