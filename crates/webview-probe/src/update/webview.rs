impl App {
    /// Protocol-host family on the by-value task thread: order identical to the former
    /// inline arms; any other message here is a routing bug.
    pub(crate) fn update_webview(
        &mut self,
        message: Message,
        mut task: Task<Message>,
    ) -> Task<Message> {
        match message {
            Message::BrowserAddress(address) => {
                self.address = address;
                self.address_dirty = true;
            }
            Message::BrowserGo => {
                let address = self.address.trim();
                let url = if address.contains("://") || address.starts_with("about:") {
                    address.to_owned()
                } else {
                    format!("https://{address}")
                };
                if address.is_empty() {
                    self.webview.borrow_mut().native_error = Some("Enter a website address".into());
                } else {
                    self.address = url.clone();
                    self.address_dirty = false;
                    self.submit_browser_action(crate::webview_native::BrowserAction::Navigate(url));
                }
            }
            Message::BrowserBack => {
                self.submit_browser_action(crate::webview_native::BrowserAction::Back)
            }
            Message::BrowserForward => {
                self.submit_browser_action(crate::webview_native::BrowserAction::Forward)
            }
            Message::BrowserReload => {
                self.submit_browser_action(crate::webview_native::BrowserAction::Reload)
            }
            Message::BrowserFocusAddress => {
                task = Task::batch([
                    iced::advanced::widget::operate(
                        iced::advanced::widget::operation::focusable::focus(
                            iced::advanced::widget::Id::new("browser-address"),
                        ),
                    ),
                    iced::advanced::widget::operate(enzui_widgets::text_field::select_all(
                        iced::advanced::widget::Id::new("browser-address"),
                    )),
                ]);
            }
            Message::WebViewNavigateHttps => {
                self.webview.borrow_mut().navigate_https();
            }
            Message::WebViewNavigateBadScheme => {
                self.webview.borrow_mut().navigate_bad_scheme();
            }
            Message::WebViewUnknownPermission => {
                self.webview.borrow_mut().request_unknown_permission();
            }
            Message::WebViewFocusGained => {
                self.webview.borrow_mut().focus_gained();
            }
            Message::WebViewForwardTab => {
                self.webview.borrow_mut().forward_tab();
            }
            Message::WebViewPageConsumedTab => {
                self.webview.borrow_mut().page_consumed_tab();
            }
            Message::WebViewPageExhaustedTab => {
                self.webview.borrow_mut().page_exhausted_tab();
            }
            Message::WebViewStaleTabReply => {
                self.webview.borrow_mut().deliver_stale_tab_reply();
            }
            Message::WebViewFocusLost => {
                self.webview.borrow_mut().focus_lost();
            }
            Message::WebViewOfferFrame => {
                self.webview.borrow_mut().offer_frame();
            }
            Message::WebViewPresentFrame => {
                self.webview.borrow_mut().present_frame();
            }
            Message::WebViewStaleFrame => {
                self.webview.borrow_mut().offer_stale_frame();
            }
            Message::WebViewRecreate => {
                self.webview.borrow_mut().recreate_view();
            }
            Message::WebViewCheckProfile => {
                self.webview.borrow_mut().check_profile_isolation();
            }
            Message::WebViewEphemeralProfile => {
                self.webview.borrow_mut().switch_to_ephemeral();
            }
            Message::WebViewEngineCameraLive => {
                self.webview.borrow_mut().engine_request_camera_live();
            }
            Message::WebViewEngineCameraViewGone => {
                self.webview.borrow_mut().engine_request_camera_view_gone();
            }
            Message::WebViewDeliverPageA11y => {
                let mut svc = self.webview.borrow_mut();
                if let Some(live) = svc.live_view {
                    svc.deliver_page_a11y(live);
                }
            }
            Message::WebViewDeliverStalePageA11y => {
                self.webview.borrow_mut().deliver_stale_page_a11y();
            }
            Message::WebViewActivatePageButton => {
                // Position `0.1` is the button, resolved to its stable key first.
                self.webview.borrow_mut().activate_page_node_at_path("0.1");
            }
            Message::WebViewActivatePageHeading => {
                // Position `0.0` is the heading: published, not actionable.
                self.webview.borrow_mut().activate_page_node_at_path("0.0");
            }
            // Emitted for resolved activations; other-widget ids resolve to `None`,
            // so fan-out emission is safe.
            Message::WebViewHide => {
                self.webview.borrow_mut().hide_view();
            }
            Message::WebViewShow => {
                self.webview.borrow_mut().show_view();
            }
            Message::WebViewClose => {
                self.pending_native_open = false;
                self.pending_navigation = None;
                self.webview.borrow_mut().close_view();
            }
            Message::WebViewPointerPress => {
                // Non-zero-origin bounds: a forgotten origin subtraction reports wrong
                // here, so the gate can fail.
                self.webview.borrow_mut().forward_pointer_press(
                    (30.0, 20.0, 400.0, 300.0),
                    230.0,
                    170.0,
                );
            }
            Message::WebViewFocusTextInput => {
                // Logical view pixels: output scale changes the backing store, not this
                // location. No `/ scale_factor` transform is valid here.
                self.webview
                    .borrow_mut()
                    .page_focus_input(40.0, 60.0, false);
            }
            Message::WebViewFocusPasswordInput => {
                self.webview
                    .borrow_mut()
                    .page_focus_input(40.0, 120.0, true);
            }
            Message::WebViewRelocateCaret => {
                // Visible location keeps the caret in the clipped surface at scale 2.
                self.webview
                    .borrow_mut()
                    .page_focus_input(150.0, 200.0, false);
            }
            Message::WebViewPreedit => {
                self.webview.borrow_mut().page_preedit("にほ");
            }
            Message::WebViewCommitPreedit => {
                self.webview.borrow_mut().page_commit("にほんご");
            }
            Message::WebViewCancelPreedit => {
                self.webview
                    .borrow_mut()
                    .page_close_ime(enzui_webkit::web::ImeClose::Reset);
            }
            Message::WebViewBlurInput => {
                self.webview
                    .borrow_mut()
                    .page_close_ime(enzui_webkit::web::ImeClose::PageBlur);
            }
            Message::WebViewStaleImeClaim => {
                self.webview.borrow_mut().page_stale_ime_claim();
            }
            Message::WebViewImeEvent(event) => {
                // One app-facing IME route: re-matching here would be a second router
                // disagreeing with the engine.
                self.webview.borrow_mut().route_toolkit_ime(&event);
            }
            Message::WebViewInput(event) => {
                // Widget → service → worker; no pump/snapshot on this path.
                if let Some(direction) = self.webview.borrow_mut().route_widget_input(&event) {
                    task =
                        iced::advanced::widget::operate(enzui_core::focus::traversal_operation::<
                            Message,
                        >(direction));
                }
            }
            Message::WebViewViewportResize(view, size) => {
                // Generation retained through the queue: pre-recovery resizes cannot
                // touch replacements.
                self.webview.borrow_mut().resize_native(view, size);
            }
            Message::WebViewRefreshSandbox => {
                // The ONE place the route pays for sandbox attestation.
                self.webview.borrow_mut().refresh_sandbox();
            }
            Message::WebViewOpenNative => {
                if self.renderer_ready {
                    self.webview.borrow_mut().open_native();
                } else {
                    self.pending_native_open = true;
                }
            }
            Message::WebViewRendererReady => {
                self.renderer_ready = true;
                if std::mem::take(&mut self.pending_native_open) {
                    self.webview.borrow_mut().open_native();
                }
                self.flush_browser_navigation();
            }
            Message::WebViewNativeReady => {
                let traversal = self.pending_native_traversal.take();
                let current = self.webview.borrow_mut().ingest_native();
                if let Some(direction) = traversal.or(current) {
                    task =
                        iced::advanced::widget::operate(enzui_core::focus::traversal_operation::<
                            Message,
                        >(direction));
                }
            }
            Message::WebViewNativeClick(x, y) => {
                self.webview.borrow_mut().native_click(x, y);
            }
            Message::WebViewNativeHover(x, y) => {
                self.webview.borrow_mut().native_hover(x, y);
            }
            Message::WebViewNativeCopy => {
                self.webview.borrow_mut().native_copy();
            }
            Message::WebViewNativePaste(text) => {
                self.webview.borrow_mut().native_paste(&text);
            }
            Message::WebViewPageCursor(name) => {
                self.webview.borrow_mut().set_page_cursor(name);
            }
            Message::A11yWake(_) | Message::A11yActivatePageNode(_) => {
                unreachable!("`update` handles the accessibility messages itself")
            }
        }
        task
    }
}
