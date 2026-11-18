// Embedded-page accessibility: the embedded page's accessible tree reaches
// the host's AT tree. `AtspiFixture` is shared with the page-action fragment.
//
// `include!`d by `web_view/tests.rs`; both fragments occupy the same module
// scope and use one `AtspiFixture` definition.

// ---------------------------------------------------------------------------
// Embedded-page accessibility: the embedded page's accessible tree reaches the host's AT tree.
//
// These assert on nodes collected through the real `operate()` walk of the real
// element - not on a helper's return value. A translation that produced a
// perfect `PageA11y` and published none of it passes every unit test in
// `enzui-webkit::page_a11y` and fails these.
// ---------------------------------------------------------------------------

/// The fixture page's AT-SPI tree, in the shape `wpe_a11y`'s real page produces.
fn atspi_fixture() -> AtspiFixture {
    AtspiFixture::new(
        atspi::DOCUMENT_WEB,
        "Accessible Page Title",
        vec![
            AtspiFixture::leaf(atspi::HEADING, "Main Heading"),
            AtspiFixture::leaf(atspi::PUSH_BUTTON, "Submit Order"),
            AtspiFixture::leaf(atspi::LINK, "Read The Docs"),
            AtspiFixture::leaf(atspi::ENTRY, "Email Address"),
        ],
    )
}

struct AtspiFixture {
    role: u32,
    name: String,
    children: Vec<AtspiFixture>,
    address: Option<PageNodeAddress>,
    actions: Vec<String>,
}

impl AtspiFixture {
    fn new(role: u32, name: &str, children: Vec<AtspiFixture>) -> Self {
        Self {
            role,
            name: name.to_owned(),
            children,
            address: Some(PageNodeAddress::new(":1.9", format!("/page/{name}"))),
            actions: Vec::new(),
        }
    }
    fn leaf(role: u32, name: &str) -> Self {
        Self::new(role, name, Vec::new())
    }
    /// Give the node a real machine-readable AT-SPI action, as a live control
    /// has - the condition under which the widget may advertise activation.
    fn with_action(mut self, action: &str) -> Self {
        self.actions.push(action.to_owned());
        self
    }

}

impl AccessibleSource for AtspiFixture {
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

/// Every `(role, label)` the collector saw.
fn role_labels(nodes: &[CollectedNode]) -> Vec<(Role, String)> {
    nodes
        .iter()
        .map(|n| {
            (
                n.semantics.role,
                n.semantics.label.clone().unwrap_or_default(),
            )
        })
        .collect()
}

#[test]
fn a_witness_minted_for_one_view_is_refused_by_another_widget_and_after_recreate() {
    // A `PublishedPage` is bound to the exact view it was minted for. It
    // is move-only, so it cannot be cloned and replayed; and even a
    // witness that was valid when minted is refused by a widget for a
    // different view id - a different slot, or a generation held across
    // a recreate.
    let f = frame(1);
    let mut router = ViewRouter::new();
    let v0 = router.create(1);
    let mut delivery = PageA11yDelivery::new();
    delivery.offer(&router, v0, PageA11y::from_source(&atspi_fixture()));

    // Calibration: a witness for this view publishes the page's control.
    let own = delivery
        .published_page(&router, v0)
        .expect("a live view must yield a witness");
    let el: Element<'_, ()> = enz_web_view(v0, Some(&f), true)
        .title("Example")
        .page_a11y(own, &router)
        .into();
    assert!(
        role_labels(&collected(el))
            .iter()
            .any(|(_, l)| l == "Submit Order"),
        "calibration: a witness for its own view must publish the page's button"
    );

    // Another widget (a different slot) must refuse the same-shaped witness.
    let foreign = delivery
        .published_page(&router, v0)
        .expect("a live view must still yield a witness");
    let other_slot = ViewId::new(v0.slot() + 1);
    let el: Element<'_, ()> = enz_web_view(other_slot, Some(&f), true)
        .title("Example")
        .page_a11y(foreign, &router)
        .into();
    let nodes = collected(el);
    assert!(
        !role_labels(&nodes).iter().any(|(_, l)| l == "Submit Order"),
        "a witness minted for another view must publish no page content"
    );
    assert!(
        nodes
            .iter()
            .filter_map(|n| n.semantics.description.clone())
            .any(|d| d == WEB_AREA_NOT_EXPOSED),
        "a foreign-view witness must leave the web area stating the content is not exposed"
    );

    // Retained across a recreate: minted while v0 was live, then handed to the
    // recreated generation's widget. The generation differs, so it is refused.
    let retained = delivery
        .published_page(&router, v0)
        .expect("still live before the recreate");
    let v1 = router.recreate(1);
    assert_ne!(v0.generation(), v1.generation());
    let el: Element<'_, ()> = enz_web_view(v1, Some(&f), true)
        .title("Example")
        .page_a11y(retained, &router)
        .into();
    assert!(
        !role_labels(&collected(el))
            .iter()
            .any(|(_, l)| l == "Submit Order"),
        "a witness held across a recreate must not publish under the new generation"
    );
}

#[test]
fn a_truncated_or_unmapped_page_tree_is_announced_not_silently_short() {
    let f = frame(1);
    let deep = AtspiFixture::new(
        atspi::DOCUMENT_WEB,
        "Doc",
        vec![AtspiFixture::new(
            atspi::SECTION,
            "outer",
            vec![AtspiFixture::leaf(129, "Mystery Control")],
        )],
    );
    let page = PageA11y::from_source_with(
        &deep,
        PageLimits {
            max_nodes: 2,
            max_depth: 8,
        },
    );
    assert!(
        page.truncated(),
        "calibration: the fixture must be truncated"
    );
    let el: Element<'_, ()> = enz_web_view(view(), Some(&f), true)
        .title("Example")
        .page_a11y(published(view(), page), &live_router_for(view()))
        .into();
    let described: Vec<String> = collected(el)
        .iter()
        .filter_map(|n| n.semantics.description.clone())
        .collect();
    assert!(
        described.iter().any(|d| d.contains("truncated")),
        "a truncated page tree must be announced; descriptions: {described:?}"
    );
}
