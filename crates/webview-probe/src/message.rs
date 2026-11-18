//! Every message the probe's one route sends: the protocol buttons, the
//! widget's own input and IME events, the native page's worker notifications,
//! and the accessibility path that activates a published page node.

#[derive(Debug, Clone)]
pub(crate) enum Message {
    BrowserAddress(String),
    BrowserGo,
    BrowserBack,
    BrowserForward,
    BrowserReload,
    BrowserFocusAddress,
    WebViewNavigateHttps,
    /// Unknown scheme (allow-list denies).
    WebViewNavigateBadScheme,
    /// Unknown permission (denied).
    WebViewUnknownPermission,
    WebViewFocusGained,
    WebViewForwardTab,
    WebViewPageConsumedTab,
    WebViewPageExhaustedTab,
    /// Stale Tab reply (discarded).
    WebViewStaleTabReply,
    WebViewFocusLost,
    WebViewOfferFrame,
    WebViewPresentFrame,
    /// Stale frame (discarded).
    WebViewStaleFrame,
    /// Recreate the view (crash recovery).
    WebViewRecreate,
    WebViewCheckProfile,
    WebViewEphemeralProfile,
    /// Camera request on the live view, resolved via `PolicySession`. Positive engine
    /// control.
    WebViewEngineCameraLive,
    /// Late reply after crash-recreate resolves to `ViewGone` with no decision - even
    /// though Camera is granted.
    WebViewEngineCameraViewGone,
    /// Live page tree delivered; live generation only.
    WebViewDeliverPageA11y,
    /// Superseded-generation walk landing after recreate: refused, live tree untouched.
    WebViewDeliverStalePageA11y,
    /// Routable-button activation: resolves to the node's own AT-SPI address and index.
    WebViewActivatePageButton,
    /// Heading activation advertising no action: refused, never silently succeeding.
    WebViewActivatePageHeading,
    /// The production AT path: a resolved widget id naming a published page node
    /// performs that node's own AT-SPI action. The demo buttons above are not what
    /// assistive technology drives.
    A11yActivatePageNode(iced::advanced::widget::Id),
    /// Hide: quiescent, no frame requests.
    WebViewHide,
    /// Show: frame requests resume.
    WebViewShow,
    /// Close: orderly shutdown releases buffers.
    WebViewClose,
    /// Pointer press at the surface centre through the scaled/clipped input path.
    WebViewPointerPress,
    /// Generation-keyed widget input: the app forwards to the engine; no hidden I/O.
    WebViewInput(enzui_webkit::input::InputEvent),
    /// Integer-logical-pixel allocation tagged with its producing generation.
    WebViewViewportResize(enzui_webkit::web::ViewId, enzui_webkit::ViewportSize),
    /// Plain-text caret published to the window input method.
    WebViewFocusTextInput,
    /// Password caret: same path, purpose reaches the window as `Secure`.
    WebViewFocusPasswordInput,
    /// Caret moved fields: an update publishing the NEW rectangle, not a reopen.
    WebViewRelocateCaret,
    /// Composing multibyte text.
    WebViewPreedit,
    /// Composition committed.
    WebViewCommitPreedit,
    /// Composition cancelled; nothing inserted.
    WebViewCancelPreedit,
    /// Field blurred: IME closes, no caret geometry published.
    WebViewBlurInput,
    /// Superseded-generation caret callback: refused, never reopens the IME.
    WebViewStaleImeClaim,
    /// Window-delivered input-method event, forwarded to the engine.
    WebViewImeEvent(enzui_webkit::web::ToolkitImeEvent),
    /// Requested CSS cursor while hovered (`None` clears).
    WebViewPageCursor(Option<&'static str>),
    /// Explicit re-read: attestation scans `/proc`, which must not happen in `view`.
    WebViewRefreshSandbox,
    WebViewOpenNative,
    /// The window renderer has reported its import capabilities, including none.
    WebViewRendererReady,
    /// Coalesced native-worker notifications, drained without running GLib/WPE.
    WebViewNativeReady,
    /// Real-page click at CSS `(x, y)`: the DOM focuses a field for real.
    WebViewNativeClick(f32, f32),
    /// Real-page hover at CSS `(x, y)`: what makes the page request a cursor.
    WebViewNativeHover(f32, f32),
    /// Host-clipboard copy: the button press IS the required user gesture.
    WebViewNativeCopy,
    /// Host text pasted into the focused DOM field.
    WebViewNativePaste(String),
    /// The accessibility bridge has actions waiting; drain them.
    A11yWake(enzui_core::app_runtime::AccessibilityWake),
}

/// Per-action dispatch pairing the shared applier with the page-node activation
/// only this app can perform: no widget-tree element carries page ids, so the
/// shared applier does nothing for them. Ids that name no page node resolve to
/// nothing.
pub(crate) fn a11y_action_tasks(
    routed: &enzui_core::app_runtime::RoutedAccessibilityAction,
) -> Vec<iced::Task<Message>> {
    use enzui_core::app_runtime::AccessibilityActionKind;

    let mut tasks = vec![enzui_widgets::a11y_actions::apply_accessibility_action(
        routed,
    )];
    if routed.kind() == AccessibilityActionKind::Activate {
        tasks.push(iced::Task::done(Message::A11yActivatePageNode(
            routed.widget().clone(),
        )));
    }
    tasks
}

/// The actions behind a wake; a stale receipt applies nothing.
pub(crate) fn drain_a11y_wake(
    receipt: enzui_core::app_runtime::AccessibilityWake,
) -> Vec<iced::Task<Message>> {
    enzui_core::app_runtime::drain_accessibility_wake(receipt)
        .unwrap_or_default()
        .iter()
        .flat_map(a11y_action_tasks)
        .collect()
}

/// Actions queued since the last turn, applied on the next update even when
/// their wake has not arrived yet.
pub(crate) fn drain_a11y_actions() -> Vec<iced::Task<Message>> {
    enzui_core::app_runtime::drain_accessibility_actions()
        .iter()
        .flat_map(a11y_action_tasks)
        .collect()
}
