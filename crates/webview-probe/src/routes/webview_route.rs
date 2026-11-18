//! The `webview` route: the rendered entry point into `core::web`. Buttons drive
//! the real protocol types through the probe-owned service, whose live state
//! feeds status, decisions, and log - a broken protocol reads differently.
//! Deterministic feature-off; native failure renders rather than mock-replacing.

use crate::{App, Message};

use enzui_theme::{SpacingScale, TypographyScale};
use enzui_webkit::web::IME_TEXT_REDACTION;
use enzui_webview::enz_web_view;
use enzui_widgets::button::{ButtonKind, ButtonSize, enz_button};
use enzui_widgets::enz_text::{TextTone, enz_text};
use iced::advanced::widget::Id;
use iced::widget::{column, row, scrollable, text};
use iced::{Element, Length};

impl App {
    pub(crate) fn view_webview(&self) -> Element<'_, Message> {
        let svc = self.webview.borrow();
        let sp = SpacingScale::default();
        let typ = TypographyScale::default();

        // --- Status line ---
        let status = enz_text(svc.status_line())
            .size_px(typ.body_size)
            .tone(TextTone::Muted)
            .into_element();

        // --- Policy section ---
        let policy_heading = text("Navigation / Policy (allow-list)").size(typ.section_size);
        let policy_buttons = row![
            enz_button("Navigate HTTPS ✓", Message::WebViewNavigateHttps)
                .id(Id::new("probe-webview-navigate-https"))
                .size(ButtonSize::Sm)
                .into_element(),
            enz_button(
                "Navigate weirdproto:// ✗",
                Message::WebViewNavigateBadScheme
            )
            .id(Id::new("probe-webview-navigate-weirdproto"))
            .size(ButtonSize::Sm)
            .kind(ButtonKind::Secondary)
            .into_element(),
            enz_button("Unknown permission ✗", Message::WebViewUnknownPermission)
                .id(Id::new("probe-webview-unknown-permission"))
                .size(ButtonSize::Sm)
                .kind(ButtonKind::Secondary)
                .into_element(),
        ]
        .spacing(sp.space2);

        let decision_text: Element<'_, Message> = match &svc.last_decision {
            Some(d) => enz_text(d.clone())
                .size_px(typ.label_size)
                .tone(TextTone::Muted)
                .into_element(),
            None => text("No decision yet").size(typ.label_size).into(),
        };

        // --- Focus / Tab section ---
        let focus_heading = text("Focus / Tab handoff").size(typ.section_size);
        let focus_buttons = row![
            enz_button("Focus gained", Message::WebViewFocusGained)
                .id(Id::new("probe-webview-focus-gained"))
                .size(ButtonSize::Sm)
                .into_element(),
            enz_button("Tab →", Message::WebViewForwardTab)
                .id(Id::new("probe-webview-tab"))
                .size(ButtonSize::Sm)
                .into_element(),
            enz_button("Page: Consumed", Message::WebViewPageConsumedTab)
                .id(Id::new("probe-webview-page-consumed"))
                .size(ButtonSize::Sm)
                .kind(ButtonKind::Secondary)
                .into_element(),
            enz_button("Page: Exhausted", Message::WebViewPageExhaustedTab)
                .id(Id::new("probe-webview-page-exhausted"))
                .size(ButtonSize::Sm)
                .kind(ButtonKind::Secondary)
                .into_element(),
            enz_button("Stale Tab reply", Message::WebViewStaleTabReply)
                .id(Id::new("probe-webview-stale-tab-reply"))
                .size(ButtonSize::Sm)
                .kind(ButtonKind::Destructive)
                .into_element(),
            enz_button("Focus lost", Message::WebViewFocusLost)
                .id(Id::new("probe-webview-focus-lost"))
                .size(ButtonSize::Sm)
                .kind(ButtonKind::Secondary)
                .into_element(),
        ]
        .spacing(sp.space2);

        let focus_text: Element<'_, Message> = match &svc.last_focus_outcome {
            Some(f) => enz_text(f.clone())
                .size_px(typ.label_size)
                .tone(TextTone::Muted)
                .into_element(),
            None => text("No focus event yet").size(typ.label_size).into(),
        };

        // --- Frame transport section ---
        let frame_heading = text("Frame transport (bounded latest-frame)").size(typ.section_size);
        let frame_buttons = row![
            enz_button("Offer frame", Message::WebViewOfferFrame)
                .id(Id::new("probe-webview-offer-frame"))
                .size(ButtonSize::Sm)
                .into_element(),
            enz_button("Present", Message::WebViewPresentFrame)
                .id(Id::new("probe-webview-present"))
                .size(ButtonSize::Sm)
                .into_element(),
            enz_button("Stale frame (gen 0)", Message::WebViewStaleFrame)
                .id(Id::new("probe-webview-stale-frame-gen-0"))
                .size(ButtonSize::Sm)
                .kind(ButtonKind::Destructive)
                .into_element(),
        ]
        .spacing(sp.space2);

        let frame_text: Element<'_, Message> = match &svc.last_frame_verdict {
            Some(f) => enz_text(f.clone())
                .size_px(typ.label_size)
                .tone(TextTone::Muted)
                .into_element(),
            None => text("No frame event yet").size(typ.label_size).into(),
        };

        let surface = self.webview_surface();

        let visibility_buttons = row![
            enz_button("Hide view", Message::WebViewHide)
                .id(Id::new("probe-webview-hide-view"))
                .size(ButtonSize::Sm)
                .kind(ButtonKind::Secondary)
                .into_element(),
            enz_button("Show view", Message::WebViewShow)
                .id(Id::new("probe-webview-show-view"))
                .size(ButtonSize::Sm)
                .into_element(),
            enz_button("Close view (shutdown)", Message::WebViewClose)
                .id(Id::new("probe-webview-close-view-shutdown"))
                .size(ButtonSize::Sm)
                .kind(ButtonKind::Destructive)
                .into_element(),
            enz_button("Pointer press @center", Message::WebViewPointerPress)
                .id(Id::new("probe-webview-pointer-press-center"))
                .size(ButtonSize::Sm)
                .into_element(),
        ]
        .spacing(sp.space2);

        let input_text: Element<'_, Message> = match &svc.last_input {
            Some(i) => enz_text(i.clone())
                .size_px(typ.label_size)
                .tone(TextTone::Muted)
                .into_element(),
            None => text("No input event yet").size(typ.label_size).into(),
        };

        // --- View / Profile section ---
        let view_heading = text("View generation & Profile isolation").size(typ.section_size);
        let view_buttons = row![
            enz_button("Recreate view (crash)", Message::WebViewRecreate)
                .id(Id::new("probe-webview-recreate-view-crash"))
                .size(ButtonSize::Sm)
                .kind(ButtonKind::Destructive)
                .into_element(),
            enz_button("Check profile isolation", Message::WebViewCheckProfile)
                .id(Id::new("probe-webview-check-profile-isolation"))
                .size(ButtonSize::Sm)
                .into_element(),
            enz_button("Ephemeral profile", Message::WebViewEphemeralProfile)
                .id(Id::new("probe-webview-ephemeral-profile"))
                .size(ButtonSize::Sm)
                .kind(ButtonKind::Secondary)
                .into_element(),
        ]
        .spacing(sp.space2);

        // --- Engine/protocol section ---
        let engine_heading =
            text("Engine protocol (mode / PolicySession / EngineEvent)").size(typ.section_size);
        let engine_buttons = row![
            enz_button("Engine: camera (live) ✓", Message::WebViewEngineCameraLive)
                .id(Id::new("probe-webview-engine-camera-live"))
                .size(ButtonSize::Sm)
                .into_element(),
            enz_button(
                "Engine: camera then view gone ✗",
                Message::WebViewEngineCameraViewGone
            )
            .id(Id::new("probe-webview-engine-camera-then-view-gone"))
            .size(ButtonSize::Sm)
            .kind(ButtonKind::Destructive)
            .into_element(),
        ]
        .spacing(sp.space2);

        let engine_text: Element<'_, Message> = match &svc.last_engine_outcome {
            Some(e) => enz_text(e.clone())
                .size_px(typ.label_size)
                .tone(TextTone::Muted)
                .into_element(),
            None => text("No engine event yet").size(typ.label_size).into(),
        };

        // --- Live page accessibility + routed AT actions ---
        let page_heading =
            text("Page accessibility (live delivery / routed actions)").size(typ.section_size);
        let page_buttons = row![
            enz_button(
                "Deliver page tree (live) ✓",
                Message::WebViewDeliverPageA11y
            )
            .id(Id::new("probe-webview-deliver-page-tree-live"))
            .size(ButtonSize::Sm)
            .into_element(),
            enz_button(
                "Deliver page tree (stale generation) ✗",
                Message::WebViewDeliverStalePageA11y
            )
            .id(Id::new("probe-webview-deliver-page-tree-stale-generation"))
            .size(ButtonSize::Sm)
            .kind(ButtonKind::Destructive)
            .into_element(),
        ]
        .spacing(sp.space2);
        let page_action_buttons = row![
            enz_button(
                "Activate page button (routable)",
                Message::WebViewActivatePageButton
            )
            .id(Id::new("probe-webview-activate-page-button-routable"))
            .size(ButtonSize::Sm)
            .into_element(),
            enz_button(
                "Activate page heading (inert)",
                Message::WebViewActivatePageHeading
            )
            .id(Id::new("probe-webview-activate-page-heading-inert"))
            .size(ButtonSize::Sm)
            .kind(ButtonKind::Secondary)
            .into_element(),
        ]
        .spacing(sp.space2);
        let page_delivery_text: Element<'_, Message> = match &svc.last_page_delivery {
            Some(e) => enz_text(e.clone())
                .size_px(typ.label_size)
                .tone(TextTone::Muted)
                .into_element(),
            None => text("No page a11y delivery yet")
                .size(typ.label_size)
                .into(),
        };
        let page_action_text: Element<'_, Message> = match &svc.last_page_action {
            Some(e) => enz_text(e.clone())
                .size_px(typ.label_size)
                .tone(TextTone::Muted)
                .into_element(),
            None => text("No page action yet").size(typ.label_size).into(),
        };

        // --- Page IME and cursor path ---
        // --- The real page ---
        let native_heading = text("Real WPE page (live WebSession)").size(typ.section_size);
        let native_buttons = row![
            enz_button("Open native page", Message::WebViewOpenNative)
                .id(Id::new("probe-webview-open-native-page"))
                .size(ButtonSize::Sm)
                .into_element(),
            // Sandbox attestation is explicit: it walks the process table, and
            // the status line shows the cached verdict plus check count.
            enz_button("Check sandbox", Message::WebViewRefreshSandbox)
                .id(iced::advanced::widget::Id::new("webview-refresh-sandbox"))
                .size(ButtonSize::Sm)
                .kind(ButtonKind::Secondary)
                .into_element(),
            enz_button(
                "Click text field",
                Message::WebViewNativeClick(
                    200.0,
                    crate::webview_native::TEXT_TOP + crate::webview_native::FIELD_HEIGHT / 2.0,
                )
            )
            .id(iced::advanced::widget::Id::new("webview-native-click-text"))
            .size(ButtonSize::Sm)
            .kind(ButtonKind::Secondary)
            .into_element(),
            enz_button(
                "Click password field",
                Message::WebViewNativeClick(
                    200.0,
                    crate::webview_native::PASSWORD_TOP + crate::webview_native::FIELD_HEIGHT / 2.0,
                )
            )
            .id(iced::advanced::widget::Id::new(
                "webview-native-click-password"
            ))
            .size(ButtonSize::Sm)
            .kind(ButtonKind::Secondary)
            .into_element(),
            enz_button(
                "Hover progress region",
                Message::WebViewNativeHover(200.0, crate::webview_native::HOVER_TOP + 26.0)
            )
            .id(iced::advanced::widget::Id::new("webview-native-hover"))
            .size(ButtonSize::Sm)
            .kind(ButtonKind::Secondary)
            .into_element(),
            // Button press IS the host gesture the session route demands: no page
            // path reaches these commands.
            enz_button("Copy page selection", Message::WebViewNativeCopy)
                .id(iced::advanced::widget::Id::new("webview-native-copy"))
                .size(ButtonSize::Sm)
                .kind(ButtonKind::Secondary)
                .into_element(),
            enz_button(
                "Paste host text",
                Message::WebViewNativePaste("enzui host clipboard text".to_owned())
            )
            .id(iced::advanced::widget::Id::new("webview-native-paste"))
            .size(ButtonSize::Sm)
            .kind(ButtonKind::Secondary)
            .into_element(),
        ]
        .spacing(sp.space2);
        let clipboard_text: Element<'_, Message> = enz_text(match &svc.last_clipboard {
            Some(outcome) => format!("Clipboard: {outcome:?}"),
            None => "Clipboard: no copy/paste yet".to_owned(),
        })
        .size_px(typ.label_size)
        .tone(TextTone::Muted)
        .into_element();
        // The DOM's own words - observed page state, not a host description.
        let dom_text: Element<'_, Message> = enz_text(match &svc.dom_report {
            Some(t) => format!("DOM report: {t}"),
            None => match &svc.native_error {
                Some(e) => format!("no DOM report \u{2014} {e}"),
                None => "no DOM report yet (open the native page)".to_owned(),
            },
        })
        .size_px(typ.label_size)
        .tone(TextTone::Muted)
        .into_element();
        let effect_result_text: Element<'_, Message> = enz_text(match &svc.last_effect_result {
            Some(r) => format!("last effect on the real page: {r}"),
            None => "no effect performed on a real page yet".to_owned(),
        })
        .size_px(typ.label_size)
        .tone(TextTone::Muted)
        .into_element();
        let ime_heading = text("Page IME and cursor (window input method)").size(typ.section_size);
        let ime_buttons = row![
            enz_button("Focus text input", Message::WebViewFocusTextInput)
                .id(iced::advanced::widget::Id::new("webview-ime-focus-text"))
                .size(ButtonSize::Sm)
                .into_element(),
            enz_button("Focus password input", Message::WebViewFocusPasswordInput)
                .id(iced::advanced::widget::Id::new(
                    "webview-ime-focus-password"
                ))
                .size(ButtonSize::Sm)
                .into_element(),
            enz_button("Relocate caret", Message::WebViewRelocateCaret)
                .id(iced::advanced::widget::Id::new(
                    "webview-ime-relocate-caret"
                ))
                .size(ButtonSize::Sm)
                .kind(ButtonKind::Secondary)
                .into_element(),
            enz_button("Blur (close IME)", Message::WebViewBlurInput)
                .id(iced::advanced::widget::Id::new("webview-ime-blur"))
                .size(ButtonSize::Sm)
                .kind(ButtonKind::Secondary)
                .into_element(),
        ]
        .spacing(sp.space2);
        let ime_compose_buttons = row![
            enz_button("Preedit にほ", Message::WebViewPreedit)
                .id(iced::advanced::widget::Id::new("webview-ime-preedit"))
                .size(ButtonSize::Sm)
                .into_element(),
            enz_button("Commit にほんご", Message::WebViewCommitPreedit)
                .id(iced::advanced::widget::Id::new("webview-ime-commit"))
                .size(ButtonSize::Sm)
                .into_element(),
            enz_button("Cancel composition", Message::WebViewCancelPreedit)
                .id(iced::advanced::widget::Id::new("webview-ime-cancel"))
                .size(ButtonSize::Sm)
                .kind(ButtonKind::Secondary)
                .into_element(),
            enz_button("Stale caret claim ✗", Message::WebViewStaleImeClaim)
                .id(iced::advanced::widget::Id::new("webview-ime-stale-claim"))
                .size(ButtonSize::Sm)
                .kind(ButtonKind::Destructive)
                .into_element(),
        ]
        .spacing(sp.space2);
        let cursor_buttons = row![
            enz_button(
                "Page cursor: pointer",
                Message::WebViewPageCursor(Some("pointer"))
            )
            .id(iced::advanced::widget::Id::new("webview-cursor-pointer"))
            .size(ButtonSize::Sm)
            .into_element(),
            enz_button(
                "Page cursor: text",
                Message::WebViewPageCursor(Some("text"))
            )
            .id(iced::advanced::widget::Id::new("webview-cursor-text"))
            .size(ButtonSize::Sm)
            .into_element(),
            enz_button(
                "Page cursor: unknown",
                Message::WebViewPageCursor(Some("a-future-css-keyword"))
            )
            .id(iced::advanced::widget::Id::new("webview-cursor-unknown"))
            .size(ButtonSize::Sm)
            .kind(ButtonKind::Secondary)
            .into_element(),
            enz_button("Page cursor: none", Message::WebViewPageCursor(None))
                .id(iced::advanced::widget::Id::new("webview-cursor-none"))
                .size(ButtonSize::Sm)
                .kind(ButtonKind::Secondary)
                .into_element(),
        ]
        .spacing(sp.space2);
        let ime_state_text: Element<'_, Message> = {
            let owner = match svc.page_ime.owner() {
                Some(v) => format!("slot {}/gen {}", v.slot(), v.generation().0),
                None => "closed".to_owned(),
            };
            let caret = match svc.published_ime() {
                Some(p) => {
                    let c = p.input().caret;
                    format!(
                        "caret ({}, {}) {}x{} view px, purpose {:?}, preedit {:?}",
                        c.x,
                        c.y,
                        c.width,
                        c.height,
                        p.input().purpose,
                        p.preedit().map(|_| IME_TEXT_REDACTION)
                    )
                }
                None => "nothing published".to_owned(),
            };
            let effect = match &svc.last_ime_effect {
                Some(e) => format!("{e:?}"),
                None => "no routed window event yet".to_owned(),
            };
            enz_text(format!(
                "IME owner: {owner} — {caret}; cursor request: {}; last routed \
                 effect: {effect}",
                svc.page_cursor.as_deref().unwrap_or("none")
            ))
            .size_px(typ.label_size)
            .tone(TextTone::Muted)
            .into_element()
        };
        let ime_last_text: Element<'_, Message> = match &svc.last_ime {
            Some(e) => enz_text(e.clone())
                .size_px(typ.label_size)
                .tone(TextTone::Muted)
                .into_element(),
            None => text("No page IME transition yet")
                .size(typ.label_size)
                .into(),
        };

        // Fixed row count prevents diagnostics from moving controls under the pointer.
        const LOG_ROWS: usize = 8;
        let mut log_col = column![].spacing(sp.space1);
        let tail = svc.log.iter().rev().take(LOG_ROWS).rev();
        for _ in tail.len()..LOG_ROWS {
            log_col = log_col.push(
                enz_text(" ")
                    .size_px(typ.label_size)
                    .tone(TextTone::Muted)
                    .into_element(),
            );
        }
        for line in tail {
            log_col = log_col.push(
                enz_text(line.clone())
                    .size_px(typ.label_size)
                    .tone(TextTone::Muted)
                    .into_element(),
            );
        }

        let content = column![
            status,
            policy_heading,
            policy_buttons,
            decision_text,
            focus_heading,
            focus_buttons,
            focus_text,
            frame_heading,
            frame_buttons,
            frame_text,
            text("Presented surface (EnzWebView)").size(typ.section_size),
            surface,
            visibility_buttons,
            input_text,
            view_heading,
            view_buttons,
            engine_heading,
            engine_buttons,
            engine_text,
            page_heading,
            page_buttons,
            page_delivery_text,
            page_action_buttons,
            page_action_text,
            native_heading,
            native_buttons,
            dom_text,
            clipboard_text,
            effect_result_text,
            ime_heading,
            ime_buttons,
            ime_compose_buttons,
            cursor_buttons,
            ime_state_text,
            ime_last_text,
            text("Event log").size(typ.section_size),
            log_col,
        ]
        .spacing(sp.space3)
        .width(Length::Fill);

        scrollable(content).height(Length::Fill).into()
    }
}

impl App {
    pub(crate) fn webview_surface(&self) -> Element<'_, Message> {
        let svc = self.webview.borrow();
        let live_view = svc
            .live_view
            .unwrap_or_else(|| enzui_webkit::web::view_id::ViewId::new(0));
        let page_a11y = svc.published_page();
        let published_ime = svc.published_ime();
        let page_cursor = svc.page_cursor.clone();
        match svc.displayed_frame().cloned() {
            Some(frame) => {
                let wv = enzui_webview::enz_web_view_owned(live_view, frame, svc.is_visible())
                    .title(if self.browser_mode {
                        "Website"
                    } else {
                        "probe demo surface"
                    })
                    .fill_viewport(self.browser_mode)
                    .scale_factor(svc.scale_factor)
                    .page_cursor(page_cursor.as_deref())
                    .on_input(Message::WebViewInput)
                    .on_viewport_resize(Message::WebViewViewportResize)
                    .on_input_method(Message::WebViewImeEvent);
                let wv = if let Some(source) = &svc.gpu_source {
                    wv.gpu_source(source, &svc.router)
                } else {
                    match &svc.gpu_frame {
                        Some(frame) => wv.gpu_frame(frame, &svc.router),
                        None => wv,
                    }
                };
                let wv = match &published_ime {
                    Some(ime) => wv.input_method(ime, &svc.router),
                    None => wv,
                };
                match page_a11y {
                    Some(page) => wv.page_a11y(page, &svc.router).into(),
                    None => wv.into(),
                }
            }
            None => {
                let wv = enz_web_view(live_view, None, svc.is_visible())
                    .title(if self.browser_mode {
                        "Website"
                    } else {
                        "probe demo surface"
                    })
                    .fill_viewport(self.browser_mode)
                    .scale_factor(svc.scale_factor)
                    .page_cursor(page_cursor.as_deref())
                    .on_input(Message::WebViewInput)
                    .on_viewport_resize(Message::WebViewViewportResize)
                    .on_input_method(Message::WebViewImeEvent);
                let wv = if let Some(source) = &svc.gpu_source {
                    wv.gpu_source(source, &svc.router)
                } else {
                    match &svc.gpu_frame {
                        Some(frame) => wv.gpu_frame(frame, &svc.router),
                        None => wv,
                    }
                };
                let wv = match &published_ime {
                    Some(ime) => wv.input_method(ime, &svc.router),
                    None => wv,
                };
                match page_a11y {
                    Some(page) => wv.page_a11y(page, &svc.router),
                    None => wv,
                }
                .into()
            }
        }
    }
}
