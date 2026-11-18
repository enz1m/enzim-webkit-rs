//! Translation of a page's AT-SPI accessible tree into enzUI accessibility
//! semantics, which `enzui_webview` publishes beneath the web area.
//!

/// A source of AT-SPI facts: one node's role number, accessible name and
/// children.
///
/// A trait rather than a concrete type so the mapping compiles and tests with
/// the `wpe` feature off, while the feature-on adapter is a three-line impl on
/// `crate::ffi::a11y::A11yNode`.
/// What a page node is, in the toolkit-neutral terms a host maps onto its own
/// accessibility roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PageRole {
    /// A push or toggle button.
    Button,
    /// A check box.
    CheckBox,
    /// A table column header.
    ColumnHeader,
    /// A combo box.
    ComboBox,
    /// A table.
    Grid,
    /// A table cell.
    GridCell,
    /// A table row.
    GridRow,
    /// A neutral container that claims nothing.
    Group,
    /// A heading.
    Heading,
    /// An image.
    Image,
    /// Static text.
    Label,
    /// A link.
    Link,
    /// A list item.
    ListItem,
    /// A password field.
    PasswordInput,
    /// A progress bar.
    ProgressIndicator,
    /// A radio button.
    RadioButton,
    /// A slider.
    Slider,
    /// A switch.
    Switch,
    /// A text field.
    TextInput,
}

/// What a host publishes for one page node: its role, its name, and whether
/// it offers a default action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageSemantics {
    /// The node's role.
    pub role: PageRole,
    /// The accessible name, when the page gave one.
    pub label: Option<String>,
    /// Whether activating the node is routed to the page.
    pub supports_default_action: bool,
}

impl PageSemantics {
    /// A node with `role`, no name and no action.
    #[must_use]
    pub fn new(role: PageRole) -> Self {
        Self {
            role,
            label: None,
            supports_default_action: false,
        }
    }

    /// The same node named `label`.
    #[must_use]
    pub fn label(mut self, label: String) -> Self {
        self.label = Some(label);
        self
    }

    /// The same node offering its default action.
    #[must_use]
    pub fn default_action(mut self) -> Self {
        self.supports_default_action = true;
        self
    }
}

pub trait AccessibleSource: Sized {
    /// The AT-SPI role number (`AtspiRole`).
    fn atspi_role(&self) -> u32;
    /// The accessible name (a button's label, a document's `<title>`).
    fn accessible_name(&self) -> &str;
    /// Child nodes, in tree order.
    fn accessible_children(&self) -> &[Self];

    /// Where this node lives on the AT-SPI bus, when the source knows.
    ///
    /// `None` means "this node cannot be acted on" - a canned tree with no bus
    /// behind it, or a walk that did not record addresses. A node without an
    /// address never advertises an action, because there would be nothing to
    /// send the action to.
    fn accessible_address(&self) -> Option<PageNodeAddress>;

    /// The AT-SPI action names this node exposes, in index order - index
    /// `i` of the returned slice is the `i` passed to `Action.DoAction`.
    ///
    /// # Why this has no default implementation
    ///
    /// Neither this nor [`accessible_address`](Self::accessible_address) is
    /// defaulted, deliberately. A default would let a *new* source silently
    /// publish "no actions" by omission, which reads identically to a source
    /// that checked and found none. Requiring both methods makes every source
    /// state its answer.
    fn accessible_actions(&self) -> &[String];
}

/// Where a page node lives on the AT-SPI bus: the bus name that owns it and its
/// object path. Together these are the address `Action.DoAction` is sent to.
///
/// # Provenance is the forgery guard
///
/// An address carries a private `AddressProvenance` that distinguishes an
/// address minted by the crate's own native AT-SPI walk
/// (`native`, crate-internal) from one built by any external
/// [`AccessibleSource`] through the public [`new`](Self::new). Only a native
/// address may drive a real `Action.DoAction`
/// (`WebSession::perform_page_action`
/// checks [`is_native`](Self::is_native) before touching the bus). So a caller
/// can construct an inert `PageA11y` for display and routing bookkeeping, but it
/// can never mint a natively-routable target for an AT-SPI object the crate
/// never walked. The `bus_name`/`path` remain public because the *identity* of a
/// node is its address, and callers legitimately read and compare it; provenance
/// is deliberately excluded from equality and hashing so identity is unchanged.
#[derive(Debug, Clone)]
pub struct PageNodeAddress {
    /// The D-Bus name of the process publishing the node (the WebProcess).
    pub bus_name: String,
    /// The node's AT-SPI object path.
    pub path: String,
    /// Whether this address was minted by the native walk (routable) or by an
    /// external source (inert). Private: an external caller cannot set it.
    provenance: AddressProvenance,
}

/// Whether an address may drive a real native `Action.DoAction`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum AddressProvenance {
    /// Built by an external [`AccessibleSource`] via [`PageNodeAddress::new`].
    /// Display and routing bookkeeping only; never executes a native action.
    Inert,
    /// Minted by the crate's own AT-SPI walk. May execute a native action.
    Native,
}

impl PageNodeAddress {
    /// An inert address from its two parts.
    ///
    /// For demos, fixtures and any external [`AccessibleSource`]. The resulting
    /// address routes at the delivery layer but is refused by the native
    /// executor - see the type documentation.
    #[must_use]
    pub fn new(bus_name: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            bus_name: bus_name.into(),
            path: path.into(),
            provenance: AddressProvenance::Inert,
        }
    }

    /// A native, executable address. Crate-internal: the only producer is
    /// the AT-SPI walk adapter ([`crate::ffi::a11y::A11yNode`]), which exists
    /// only under the `wpe` feature.
    #[must_use]
    #[cfg_attr(not(feature = "wpe"), allow(dead_code))]
    pub(crate) fn native(bus_name: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            bus_name: bus_name.into(),
            path: path.into(),
            provenance: AddressProvenance::Native,
        }
    }

    /// Whether this address was minted by the native walk and may therefore
    /// drive a real `Action.DoAction`. An address from an external source is
    /// inert and returns `false`.
    #[must_use]
    pub fn is_native(&self) -> bool {
        self.provenance == AddressProvenance::Native
    }
}

// Identity is `(bus_name, path)`; provenance is excluded so an inert and a
// native address for the same object compare equal and hash alike. This keeps
// `PageNodeKey` derivation and every address comparison unchanged.
impl PartialEq for PageNodeAddress {
    fn eq(&self, other: &Self) -> bool {
        self.bus_name == other.bus_name && self.path == other.path
    }
}
impl Eq for PageNodeAddress {}
impl core::hash::Hash for PageNodeAddress {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.bus_name.hash(state);
        self.path.hash(state);
    }
}

/// One AT-SPI action on a page node: the index to invoke and the name the page
/// gave it.
///
/// # The fields are private on purpose
///
/// An index paired with the wrong name presses the wrong control, so both are
/// read-only and are only ever written together by [`activation_action`] from
/// one node's own action list. A public field would let a caller keep the name
/// and move the index, which is precisely the mis-activation this type exists
/// to prevent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageAction {
    index: usize,
    name: String,
}

impl PageAction {
    /// The index to pass to `Action.DoAction`.
    #[must_use]
    pub fn index(&self) -> usize {
        self.index
    }

    /// The action's AT-SPI name, lower-cased. Always a member of
    /// [`ACTIVATION_ACTIONS`] - nothing else can build a `PageAction`.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Everything needed to perform a page node's action: which object, which
/// action index.
///
/// # Unforgeable by construction
///
/// There is no public constructor and no public field. The only way to get
/// one is [`PageA11y::action_target`], which reads the address and the action
/// index out of the *same* node of a *published* tree. A struct whose parts
/// could be assembled by a caller would let any code in the process send an
/// arbitrary `DoAction` to an arbitrary AT-SPI object - bypassing the role,
/// name, address and allow-list gate that decides what is operable at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageActionTarget {
    address: PageNodeAddress,
    action: PageAction,
    /// The key of the node this target was resolved from, so an executor can
    /// re-resolve it against the live tree instead of trusting a held value.
    key: PageNodeKey,
}

/// A page node's native, executable action: the AT-SPI object address and
/// the action index, harvested from the crate's *own* native walk.
///
/// # Why this is the native executor's only input
///
/// A `PageNodeAddress::is_native()` bit cannot authorize an action: it rides
/// along on [`Clone`], so a cloned native address in a tree assembled through
/// the public [`AccessibleSource`] path could drive any `Action.DoAction`. A `NativeAction` has no public constructor; the only
/// producer is [`PageA11y::native_action_targets`], and the only thing that
/// installs those into the executor's authority is the session's own native
/// walk - never a caller's `offer`. So a caller-supplied tree can route at the
/// display layer but can never choose a native action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeAction {
    bus_name: String,
    path: String,
    index: usize,
}

impl NativeAction {
    /// The D-Bus name of the WebProcess that owns the object.
    #[must_use]
    pub fn bus_name(&self) -> &str {
        &self.bus_name
    }

    /// The AT-SPI object path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The `Action.DoAction` index recorded by the native walk.
    #[must_use]
    pub fn index(&self) -> usize {
        self.index
    }
}

impl PageActionTarget {
    /// The AT-SPI object to act on.
    #[must_use]
    pub fn address(&self) -> &PageNodeAddress {
        &self.address
    }

    /// The action to perform on it.
    #[must_use]
    pub fn action(&self) -> &PageAction {
        &self.action
    }

    /// The published key of the node this target came from.
    #[must_use]
    pub fn key(&self) -> &PageNodeKey {
        &self.key
    }
}

/// A page node's stable identity in the published tree.
///
/// # Why not the tree position
///
/// A positional path (`"0.1"`) is not a stable key: inserting one element shifts
/// every following sibling, so a queued activation would press a different
/// control, and assistive technology would see one id name another node.
///
/// So an addressed node is keyed on its AT-SPI object address, which WebKit
/// mints per accessible object (`/org/a11y/atspi/accessible/<uuid>`) and does
/// not recycle when siblings move. A node the source could not address falls
/// back to its position, tagged `pos:` so the two can never be confused - and
/// such a node is never operable ([`PageNode::action`] requires an address), so
/// a shifted `pos:` key can misname a read-only node but can never misroute an
/// action.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PageNodeKey(String);

impl PageNodeKey {
    /// The key's string form, as the widget id recipe consumes it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Address-derived: stable across sibling insertion, removal and reorder.
    ///
    /// A D-Bus name never contains `/` and an object path always starts with
    /// one, so `obj:<name>:<path>` cannot be ambiguous even though a unique bus
    /// name itself contains a colon.
    fn from_address(address: &PageNodeAddress) -> Self {
        Self(format!("obj:{}:{}", address.bus_name, address.path))
    }

    /// Position-derived fallback for a node with no address.
    fn from_path(path: &str) -> Self {
        Self(format!("pos:{path}"))
    }
}

impl core::fmt::Display for PageNodeKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// AT-SPI action names that mean "activate this control", lower-cased.
///
/// An allow-list, for the same reason [`map_role`] is one: AT-SPI action
/// names are page-supplied strings, and a deny-list would advertise activation
/// for the first name nobody predicted. `press`/`click`/`activate`/`jump` are
/// the names WebKit's ATK bridge actually emits (`jump` for links).
pub const ACTIVATION_ACTIONS: &[&str] = &["click", "press", "activate", "jump"];

/// Whether `name` is an allow-listed activation action, normalised the same way
/// [`activation_action`] normalises it.
///
/// Exposed so the *executor* can re-check a name immediately before performing
/// it, rather than trusting that whoever built the value checked (the
/// check-once-far-from-use shape).
#[must_use]
pub fn is_activation_action(name: &str) -> bool {
    ACTIVATION_ACTIONS.contains(&name.trim().to_ascii_lowercase().as_str())
}

/// The activation action on `actions`, if any.
///
/// The first match in index order wins, so a node exposing several actions
/// is invoked with the one AT would pick.
#[must_use]
pub fn activation_action(actions: &[String]) -> Option<PageAction> {
    actions.iter().enumerate().find_map(|(index, name)| {
        let lower = name.trim().to_ascii_lowercase();
        is_activation_action(&lower).then_some(PageAction { index, name: lower })
    })
}

/// AT-SPI role numbers used by the mapping, from `atspi-constants.h`
/// (`ATSPI_ROLE_*`) on WPE WebKit 2.52.5's host.
pub mod atspi {
    /// `ATSPI_ROLE_CHECK_BOX`.
    pub const CHECK_BOX: u32 = 7;
    /// `ATSPI_ROLE_COLUMN_HEADER`.
    pub const COLUMN_HEADER: u32 = 10;
    /// `ATSPI_ROLE_COMBO_BOX`.
    pub const COMBO_BOX: u32 = 11;
    /// `ATSPI_ROLE_FILLER` - the WPE socket node.
    pub const FILLER: u32 = 20;
    /// `ATSPI_ROLE_IMAGE`.
    pub const IMAGE: u32 = 27;
    /// `ATSPI_ROLE_LABEL`.
    pub const LABEL: u32 = 29;
    /// `ATSPI_ROLE_LIST` - a `<ul>`/`<ol>`.
    pub const LIST: u32 = 31;
    /// `ATSPI_ROLE_LIST_ITEM` - an `<li>`.
    pub const LIST_ITEM: u32 = 32;
    /// `ATSPI_ROLE_PANEL`.
    pub const PANEL: u32 = 39;
    /// `ATSPI_ROLE_PASSWORD_TEXT`.
    pub const PASSWORD_TEXT: u32 = 40;
    /// `ATSPI_ROLE_PROGRESS_BAR`.
    pub const PROGRESS_BAR: u32 = 42;
    /// `ATSPI_ROLE_PUSH_BUTTON`.
    pub const PUSH_BUTTON: u32 = 43;
    /// `ATSPI_ROLE_RADIO_BUTTON`.
    pub const RADIO_BUTTON: u32 = 44;
    /// `ATSPI_ROLE_SCROLL_PANE` - WebKit's frame node.
    pub const SCROLL_PANE: u32 = 49;
    /// `ATSPI_ROLE_SLIDER`.
    pub const SLIDER: u32 = 51;
    /// `ATSPI_ROLE_TABLE`.
    pub const TABLE: u32 = 55;
    /// `ATSPI_ROLE_TABLE_CELL`.
    pub const TABLE_CELL: u32 = 56;
    /// `ATSPI_ROLE_TOGGLE_BUTTON`.
    pub const TOGGLE_BUTTON: u32 = 62;
    /// `ATSPI_ROLE_PARAGRAPH`.
    pub const PARAGRAPH: u32 = 73;
    /// `ATSPI_ROLE_ENTRY` - a text `<input>`.
    pub const ENTRY: u32 = 79;
    /// `ATSPI_ROLE_DOCUMENT_FRAME`.
    pub const DOCUMENT_FRAME: u32 = 82;
    /// `ATSPI_ROLE_HEADING` - `<h1>`…`<h6>`.
    pub const HEADING: u32 = 83;
    /// `ATSPI_ROLE_SECTION`.
    pub const SECTION: u32 = 85;
    /// `ATSPI_ROLE_FORM`.
    pub const FORM: u32 = 87;
    /// `ATSPI_ROLE_LINK`.
    pub const LINK: u32 = 88;
    /// `ATSPI_ROLE_TABLE_ROW`.
    pub const TABLE_ROW: u32 = 90;
    /// `ATSPI_ROLE_DOCUMENT_WEB` - the page document; its name is the `<title>`.
    pub const DOCUMENT_WEB: u32 = 95;
    /// `ATSPI_ROLE_LANDMARK`.
    pub const LANDMARK: u32 = 110;
    /// `ATSPI_ROLE_STATIC` - non-interactive text.
    pub const STATIC: u32 = 116;
}

/// Map one AT-SPI role number to an enzUI [`PageRole`].
///
/// `None` means "not on the allow-list" - the caller publishes [`PageRole::Group`]
/// and records the number. It deliberately does not guess.
#[must_use]
pub fn map_role(atspi_role: u32) -> Option<PageRole> {
    let role = match atspi_role {
        atspi::PUSH_BUTTON | atspi::TOGGLE_BUTTON => PageRole::Button,
        atspi::LINK => PageRole::Link,
        atspi::HEADING => PageRole::Heading,
        atspi::ENTRY => PageRole::TextInput,
        atspi::PASSWORD_TEXT => PageRole::PasswordInput,
        atspi::CHECK_BOX => PageRole::CheckBox,
        atspi::RADIO_BUTTON => PageRole::RadioButton,
        atspi::SLIDER => PageRole::Slider,
        atspi::COMBO_BOX => PageRole::ComboBox,
        atspi::PROGRESS_BAR => PageRole::ProgressIndicator,
        atspi::IMAGE => PageRole::Image,
        atspi::LIST_ITEM => PageRole::ListItem,
        atspi::TABLE => PageRole::Grid,
        atspi::TABLE_ROW => PageRole::GridRow,
        atspi::TABLE_CELL => PageRole::GridCell,
        atspi::COLUMN_HEADER => PageRole::ColumnHeader,
        atspi::LABEL | atspi::STATIC | atspi::PARAGRAPH => PageRole::Label,
        atspi::DOCUMENT_WEB
        | atspi::DOCUMENT_FRAME
        | atspi::SECTION
        | atspi::PANEL
        | atspi::FORM
        | atspi::LANDMARK
        | atspi::LIST
        | atspi::SCROLL_PANE
        | atspi::FILLER => PageRole::Group,
        _ => return None,
    };
    Some(role)
}

/// Whether an enzUI role means "the user can operate this".
///
/// Used by the unnamed-control demotion: an interactive role with no accessible
/// name is published as a [`PageRole::Group`] instead.
#[must_use]
pub fn is_interactive(role: PageRole) -> bool {
    matches!(
        role,
        PageRole::Button
            | PageRole::Link
            | PageRole::CheckBox
            | PageRole::RadioButton
            | PageRole::Switch
            | PageRole::Slider
            | PageRole::ComboBox
            | PageRole::TextInput
            | PageRole::PasswordInput
    )
}

/// Caps on the translated tree. A page is adversarial input; the published tree
/// is bounded the same way the AT-SPI walk and the frame path are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageLimits {
    /// Maximum number of nodes published (root included).
    pub max_nodes: usize,
    /// Maximum depth below the root.
    pub max_depth: usize,
}

impl Default for PageLimits {
    fn default() -> Self {
        Self {
            max_nodes: 500,
            max_depth: 16,
        }
    }
}

/// One translated node: enzUI semantics plus its translated children.
///
/// # Every field is private, and that is the encapsulation this type exists for
///
/// A published tree is adversarial-adjacent input that ends at a screen reader
/// and, for interactive nodes, at a real `Action.DoAction` on a page control.
/// If `address` and `action` were writable, a caller holding an owned
/// [`PageA11y`] could copy an operable node's [`PageAction`] onto a positional
/// (address-less) node and mint an address of its own - turning a read-only node
/// into an actionable target that routes an activation to an object the
/// translation never certified. Making the fields read-only removes that vector
/// by construction: the only writer is `Translation::node`, which applies the
/// role/name/address/allow-list gate, and a node once built cannot be edited.
#[derive(Debug, Clone, PartialEq)]
pub struct PageNode {
    /// What the toolkit publishes for this node.
    semantics: PageSemantics,
    /// Translated children, in tree order.
    children: Vec<PageNode>,
    /// This node's path in the published tree: `"0"` for the root, `"0.2.1"`
    /// for the second child of the root's third child.
    ///
    /// Diagnostics only. It is unique within one snapshot but *not stable
    /// across page mutation*, so neither the widget id nor action routing may
    /// use it - see [`PageNodeKey`], which both do use.
    path: String,
    /// This node's stable identity: address-derived when the source could
    /// address it, positional otherwise. The published widget `Id` and every
    /// routed action are keyed on this.
    key: PageNodeKey,
    /// Where this node lives on the AT-SPI bus, when the source supplied it.
    address: Option<PageNodeAddress>,
    /// The routable activation action, when this node has one and is
    /// eligible to advertise it.
    ///
    /// `Some` here is exactly the condition under which
    /// `semantics.supports_default_action` is set - the two are written
    /// together in one place, so they cannot disagree.
    action: Option<PageAction>,
}

impl PageNode {
    /// The toolkit semantics this node publishes. Read-only: see the type doc.
    #[must_use]
    pub fn semantics(&self) -> &PageSemantics {
        &self.semantics
    }

    /// This node's translated children, in tree order.
    #[must_use]
    pub fn children(&self) -> &[PageNode] {
        &self.children
    }

    /// This node's positional path (diagnostics only; not stable across
    /// mutation - see [`PageNodeKey`]).
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// This node's stable identity.
    #[must_use]
    pub fn key(&self) -> &PageNodeKey {
        &self.key
    }

    /// Where this node lives on the AT-SPI bus, when the source addressed it.
    /// A positional node returns `None` and can never be made actionable.
    #[must_use]
    pub fn address(&self) -> Option<&PageNodeAddress> {
        self.address.as_ref()
    }

    /// The routable activation action, when this node advertises one.
    #[must_use]
    pub fn action(&self) -> Option<&PageAction> {
        self.action.as_ref()
    }

    /// Every `(role, label)` pair in the subtree, depth-first - the shape the
    /// gates assert on.
    #[must_use]
    pub fn flatten(&self) -> Vec<(PageRole, String)> {
        let mut out = vec![(
            self.semantics.role,
            self.semantics.label.clone().unwrap_or_default(),
        )];
        for c in &self.children {
            out.extend(c.flatten());
        }
        out
    }

    /// Node count in the subtree.
    #[must_use]
    pub fn count(&self) -> usize {
        1 + self.children.iter().map(PageNode::count).sum::<usize>()
    }
}

/// A page's accessible tree, translated into enzUI semantics, with the facts a
/// caller needs in order to know what was *not* translated.
///
/// # The tree is read-only after translation
///
/// A caller cannot reach into a published tree and turn a read-only positional
/// node into an actionable one, because `root` and every routing-relevant
/// [`PageNode`] field are private with read-only accessors. There is no `&mut`
/// path to a node's address or action anywhere in the public API, so the
/// following does not compile:
///
/// ```compile_fail
/// # use enzui_webkit::page_a11y::PageA11y;
/// fn tamper(page: &mut PageA11y) {
///     // error[E0616]: field `root` of struct `PageA11y` is private
///     let _ = &mut page.root;
/// }
/// ```
///
/// ```compile_fail
/// # use enzui_webkit::page_a11y::PageNode;
/// fn tamper(node: &mut PageNode) {
///     // error[E0616]: field `action` of struct `PageNode` is private
///     node.action = None;
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct PageA11y {
    /// The translated root (the page document, in practice). Private so a
    /// caller cannot splice a forged subtree in; read it with [`PageA11y::root`].
    root: PageNode,
    /// AT-SPI role numbers that were not on the allow-list, in first-seen
    /// order and deduplicated. Non-empty means some node was published as a
    /// neutral group rather than its real role. Read-only:
    /// the bridge's honesty diagnostics must not be rewritable after
    /// translation - read via [`unmapped_roles`](Self::unmapped_roles).
    unmapped_roles: Vec<u32>,
    /// How many interactive nodes were demoted for having no accessible name.
    /// Read via [`unnamed_actionable`](Self::unnamed_actionable).
    unnamed_actionable: usize,
    /// Whether [`PageLimits`] cut the tree short. Read via
    /// [`truncated`](Self::truncated).
    truncated: bool,
}

impl PageA11y {
    /// Translate an AT-SPI tree with the default limits.
    #[must_use]
    pub fn from_source<S: AccessibleSource>(root: &S) -> Self {
        Self::from_source_with(root, PageLimits::default())
    }

    /// Translate an AT-SPI tree with explicit limits.
    #[must_use]
    pub fn from_source_with<S: AccessibleSource>(root: &S, limits: PageLimits) -> Self {
        let mut state = Translation {
            budget: limits.max_nodes,
            unmapped: Vec::new(),
            unnamed_actionable: 0,
            truncated: false,
        };
        // `"0"` is the root's path; children extend it (`"0.1"`, `"0.1.2"`).
        let root = state.node(root, limits.max_depth, ROOT_PATH.to_owned());
        Self {
            root,
            unmapped_roles: state.unmapped,
            unnamed_actionable: state.unnamed_actionable,
            truncated: state.truncated,
        }
    }

    /// The translated root node (the page document, in practice). Read-only:
    /// the tree cannot be edited after translation - see [`PageNode`].
    #[must_use]
    pub fn root(&self) -> &PageNode {
        &self.root
    }

    /// AT-SPI role numbers that were not on the allow-list, in first-seen order
    /// and deduplicated. Non-empty means some node was published as a neutral
    /// group rather than its real role.
    #[must_use]
    pub fn unmapped_roles(&self) -> &[u32] {
        &self.unmapped_roles
    }

    /// How many interactive nodes were demoted for having no accessible name.
    #[must_use]
    pub fn unnamed_actionable(&self) -> usize {
        self.unnamed_actionable
    }

    /// Whether [`PageLimits`] cut the translated tree short.
    #[must_use]
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// Total published node count.
    #[must_use]
    pub fn count(&self) -> usize {
        self.root.count()
    }

    /// The first node in the subtree with `role` and that exact label.
    #[must_use]
    pub fn find(&self, role: PageRole, label: &str) -> bool {
        self.root
            .flatten()
            .iter()
            .any(|(r, l)| *r == role && l == label)
    }

    /// The node at positional `path`, if the published tree has one.
    ///
    /// Diagnostics and fixtures only - routing goes through
    /// [`node_for_key`](Self::node_for_key), because a position is not stable
    /// across page mutation.
    #[must_use]
    pub fn node_at(&self, path: &str) -> Option<&PageNode> {
        fn walk<'a>(node: &'a PageNode, path: &str) -> Option<&'a PageNode> {
            if node.path == path {
                return Some(node);
            }
            // Only descend where the path could still match, so a wrong path
            // costs a branch rather than a full tree scan.
            if !path.starts_with(node.path.as_str()) {
                return None;
            }
            node.children.iter().find_map(|c| walk(c, path))
        }
        walk(&self.root, path)
    }

    /// The node with stable identity `key`, if the published tree still has
    /// one.
    ///
    /// A linear walk rather than a map: the tree is capped by [`PageLimits`]
    /// (500 nodes by default), and a second index would be a second source of
    /// truth about which nodes exist.
    #[must_use]
    pub fn node_for_key(&self, key: &PageNodeKey) -> Option<&PageNode> {
        fn walk<'a>(node: &'a PageNode, key: &PageNodeKey) -> Option<&'a PageNode> {
            if &node.key == key {
                return Some(node);
            }
            node.children.iter().find_map(|c| walk(c, key))
        }
        walk(&self.root, key)
    }

    /// The stable key of the node at positional `path`. For fixtures and demo
    /// buttons that know a position and need the identity AT would use.
    #[must_use]
    pub fn key_at_path(&self, path: &str) -> Option<PageNodeKey> {
        self.node_at(path).map(|n| n.key.clone())
    }

    /// The action to perform for the node identified by `key`, or `None` when
    /// that node is gone or advertises no routable action.
    ///
    /// This is the only way to obtain a [`PageActionTarget`]: it pairs the
    /// address and the action index read from the *same* node, so a caller
    /// cannot send one node's action to another node's address.
    #[must_use]
    pub fn action_target(&self, key: &PageNodeKey) -> Option<PageActionTarget> {
        let node = self.node_for_key(key)?;
        Some(PageActionTarget {
            address: node.address.clone()?,
            action: node.action.clone()?,
            key: node.key.clone(),
        })
    }

    /// Every published node path, depth-first. Diagnostics; see
    /// [`keys`](Self::keys) for the identities that are actually published.
    #[must_use]
    pub fn paths(&self) -> Vec<String> {
        fn walk(node: &PageNode, out: &mut Vec<String>) {
            out.push(node.path.clone());
            for c in &node.children {
                walk(c, out);
            }
        }
        let mut out = Vec::new();
        walk(&self.root, &mut out);
        out
    }

    /// Every published node key, depth-first - the subjects a caller derives
    /// ids for. Used by the id-collision and reorder gates, which must
    /// enumerate the tree rather than trust a hand-written list.
    #[must_use]
    pub fn keys(&self) -> Vec<PageNodeKey> {
        fn walk(node: &PageNode, out: &mut Vec<PageNodeKey>) {
            out.push(node.key.clone());
            for c in &node.children {
                walk(c, out);
            }
        }
        let mut out = Vec::new();
        walk(&self.root, &mut out);
        out
    }

    /// Harvest the native, executable action targets from this tree, keyed
    /// by node identity - one entry per node whose address was minted by the
    /// native walk ([`PageNodeAddress::is_native`]) AND that advertises a
    /// routable action.
    ///
    /// This is how the native action authority is seeded. Only the session's
    /// own native walk ever calls it and installs the result; a caller-supplied
    /// tree, even one that cloned a real native address, is never installed, so
    /// it cannot seed the authority. The recorded index is the one the native
    /// walk validated as an allow-listed activation - a caller cannot substitute
    /// a different index for a real object.
    #[must_use]
    pub fn native_action_targets(&self) -> Vec<(PageNodeKey, NativeAction)> {
        fn walk(node: &PageNode, out: &mut Vec<(PageNodeKey, NativeAction)>) {
            if let (Some(addr), Some(action)) = (node.address(), node.action())
                && addr.is_native()
            {
                out.push((
                    node.key().clone(),
                    NativeAction {
                        bus_name: addr.bus_name.clone(),
                        path: addr.path.clone(),
                        index: action.index(),
                    },
                ));
            }
            for c in node.children() {
                walk(c, out);
            }
        }
        let mut out = Vec::new();
        walk(&self.root, &mut out);
        out
    }

    /// How many published nodes advertise a routable action.
    #[must_use]
    pub fn actionable_count(&self) -> usize {
        fn walk(node: &PageNode) -> usize {
            usize::from(node.action.is_some()) + node.children.iter().map(walk).sum::<usize>()
        }
        walk(&self.root)
    }
}

/// The published tree root's path. Children extend it positionally.
pub const ROOT_PATH: &str = "0";

/// Mutable state carried through the recursive translation.
struct Translation {
    budget: usize,
    unmapped: Vec<u32>,
    unnamed_actionable: usize,
    truncated: bool,
}

impl Translation {
    fn node<S: AccessibleSource>(&mut self, src: &S, depth_left: usize, path: String) -> PageNode {
        self.budget = self.budget.saturating_sub(1);
        let atspi_role = src.atspi_role();
        let name = src.accessible_name();

        let mapped = map_role(atspi_role);
        if mapped.is_none() && !self.unmapped.contains(&atspi_role) {
            self.unmapped.push(atspi_role);
        }
        let mut role = mapped.unwrap_or(PageRole::Group);
        // Fail closed: an interactive control this code cannot name is published as a
        // neutral group, never as a nameless button.
        if name.is_empty() && is_interactive(role) {
            self.unnamed_actionable += 1;
            role = PageRole::Group;
        }

        let mut semantics = PageSemantics::new(role);
        if !name.is_empty() {
            semantics = semantics.label(name.to_owned());
        }

        // The routable-action gate. All four conditions, in one
        // place, so `action` and `supports_default_action` are written together
        // and cannot drift apart:
        //   1. the (post-demotion) role is interactive,
        //   2. the node has an accessible name,
        // 3. the source gave this code an address to send the action to,
        //   4. the source reported an allow-listed activation action.
        // Failing any one publishes the node read-only, which is honest: AT is
        // told it can read the control but not operate it, rather than being
        // offered an action that resolves to nothing.
        let address = src.accessible_address();
        let action = if is_interactive(role) && !name.is_empty() && address.is_some() {
            activation_action(src.accessible_actions())
        } else {
            None
        };
        // Stable identity: the AT-SPI object address when this code has one, so
        // sibling insertion/reorder cannot move a queued action onto a
        // different control. Positional only as a last resort, and such a node
        // is never actionable (the gate above requires an address).
        let key = match &address {
            Some(address) => PageNodeKey::from_address(address),
            None => PageNodeKey::from_path(&path),
        };
        if action.is_some() {
            semantics = semantics.default_action();
        }

        let mut children = Vec::new();
        if depth_left > 0 {
            for (i, child) in src.accessible_children().iter().enumerate() {
                if self.budget == 0 {
                    self.truncated = true;
                    break;
                }
                children.push(self.node(child, depth_left - 1, format!("{path}.{i}")));
            }
        } else if !src.accessible_children().is_empty() {
            self.truncated = true;
        }

        PageNode {
            semantics,
            children,
            path,
            key,
            address,
            action,
        }
    }
}
