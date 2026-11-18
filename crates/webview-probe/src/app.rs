use std::cell::RefCell;

use enzui_theme::EnzTheme;
use iced::{Element, Subscription, Task};

use crate::{Message, webview, webview_native};

/// The probe's state: the live web-view host, whose policy, focus handoff and
/// frame plan accumulate across messages, and the theme it paints with.
pub(crate) struct App {
    pub(crate) webview: RefCell<webview::WebViewService>,
    theme: EnzTheme,
    pub(crate) renderer_ready: bool,
    pub(crate) pending_native_open: bool,
    pub(crate) browser_mode: bool,
    pub(crate) address: String,
    pub(crate) address_dirty: bool,
    pub(crate) last_location: Option<String>,
    pub(crate) native_dispatch_publication: std::cell::Cell<bool>,
    pub(crate) pending_native_traversal: std::cell::Cell<Option<enzui_core::focus::Traversal>>,
    pub(crate) pending_navigation: Option<crate::webview_native::BrowserAction>,
}

impl App {
    /// A fresh host painting with `theme`.
    pub(crate) fn new(theme: EnzTheme) -> Self {
        Self {
            webview: RefCell::new(webview::WebViewService::new()),
            theme,
            renderer_ready: false,
            pending_native_open: false,
            browser_mode: false,
            address: "https://en.wikipedia.org/wiki/Rust_(programming_language)".into(),
            pending_navigation: None,
            native_dispatch_publication: std::cell::Cell::new(false),
            pending_native_traversal: std::cell::Cell::new(None),
            address_dirty: false,
            last_location: None,
        }
    }

    pub(crate) fn boot() -> (Self, Task<Message>) {
        let theme = if std::env::var("ENZUI_PROBE_LIGHT").as_deref() == Ok("1") {
            EnzTheme::light()
        } else {
            EnzTheme::dark()
        };
        let task = if std::env::args().any(|argument| argument == "--open-native") {
            Task::done(Message::WebViewOpenNative)
        } else {
            Task::none()
        };
        let mut app = Self::new(theme);
        let arguments: Vec<String> = std::env::args().collect();
        if let Some(index) = arguments
            .iter()
            .position(|argument| argument == "--browser")
        {
            app.browser_mode = true;
            if let Some(url) = arguments.get(index + 1) {
                app.address = url.clone();
            }
            return (app, Task::done(Message::BrowserGo));
        }
        (app, task)
    }

    pub(crate) fn theme(&self) -> iced::Theme {
        self.theme.iced_theme()
    }

    pub(crate) fn subscription(&self) -> Subscription<Message> {
        let shortcuts = if self.browser_mode {
            iced::event::listen_with(|event, _, _| {
                if let iced::Event::Keyboard(iced::keyboard::Event::KeyPressed {
                    key,
                    modifiers,
                    ..
                }) = event
                    && modifiers.control()
                {
                    match key.as_ref() {
                        iced::keyboard::Key::Character("l" | "L") => {
                            return Some(Message::BrowserFocusAddress);
                        }
                        iced::keyboard::Key::Character("r" | "R") => {
                            return Some(Message::BrowserReload);
                        }
                        _ => {}
                    }
                }
                None
            })
        } else {
            Subscription::none()
        };
        Subscription::batch([
            shortcuts,
            enzui_core::app_runtime::accessibility_wake_subscription(Message::A11yWake),
            webview_native::notification_subscription().map(|()| Message::WebViewNativeReady),
            webview_native::main_thread_subscription().map(|()| Message::WebViewNativeReady),
        ])
    }

    pub(crate) fn title(&self) -> String {
        if self.browser_mode {
            let service = self.webview.borrow();
            match service.dom_report.as_deref() {
                Some(title) if !title.is_empty() => format!("{title} - enzUI Browser"),
                _ => "enzUI Browser".into(),
            }
        } else {
            "enzUI web view probe".into()
        }
    }

    pub(crate) fn submit_browser_action(&mut self, action: crate::webview_native::BrowserAction) {
        self.pending_navigation = Some(action);
        if self.webview.borrow().native.is_none() {
            if self.renderer_ready {
                self.webview.borrow_mut().open_native();
            } else {
                self.pending_native_open = true;
            }
        }
        self.flush_browser_navigation();
    }

    pub(crate) fn flush_browser_navigation(&mut self) {
        if self.webview.borrow().native.is_none() {
            return;
        }
        if let Some(action) = self.pending_navigation.take() {
            let mut service = self.webview.borrow_mut();
            if let (Some(native), Some(view)) = (&service.native, service.live_view) {
                service.native_error = native.browse(&service.router, view, action).err();
            }
        }
    }

    pub(crate) fn browser_view(&self) -> Element<'_, Message> {
        use enzui_widgets::button::{ButtonKind, ButtonSize, enz_button};
        use enzui_widgets::text_field::enz_text_field;
        use iced::Length;
        use iced::widget::{column, container, row, text};
        let address = enz_text_field(
            "",
            "https://example.com",
            &self.address,
            Message::BrowserAddress,
        )
        .aria_label("Website address")
        .id(iced::advanced::widget::Id::new("browser-address"))
        .input_purpose(iced::advanced::input_method::Purpose::Url)
        .on_submit(Message::BrowserGo)
        .into_element();
        let toolbar = row![
            enz_button("Back", Message::BrowserBack)
                .size(ButtonSize::Sm)
                .kind(ButtonKind::Secondary)
                .into_element(),
            enz_button("Forward", Message::BrowserForward)
                .size(ButtonSize::Sm)
                .kind(ButtonKind::Secondary)
                .into_element(),
            enz_button("Reload", Message::BrowserReload)
                .size(ButtonSize::Sm)
                .kind(ButtonKind::Secondary)
                .into_element(),
            address,
            enz_button("Go", Message::BrowserGo)
                .size(ButtonSize::Sm)
                .into_element(),
        ]
        .spacing(8)
        .align_y(iced::Alignment::Center);
        let status = self
            .webview
            .borrow()
            .native_error
            .clone()
            .unwrap_or_else(|| {
                "Test browser | Private session | Ctrl+L: address | Ctrl+R: reload".into()
            });
        column![
            container(toolbar).padding(10).width(Length::Fill),
            self.webview_surface(),
            container(text(status).size(12))
                .padding([4, 10])
                .width(Length::Fill),
        ]
        .height(Length::Fill)
        .into()
    }

    /// The route inside the probe chrome: padded, and scrollable so the
    /// below-the-fold sections can be captured.
    pub(crate) fn view(&self) -> Element<'_, Message> {
        let content = if self.browser_mode {
            self.browser_view()
        } else {
            iced::widget::scrollable(
                iced::widget::container(self.view_webview())
                    .width(iced::Length::Fill)
                    .padding(iced::Padding::new(40.0)),
            )
            .height(iced::Length::Fill)
            .into()
        };
        let mut layers = iced::widget::stack![
            content,
            enzui_webview::gpu::renderer_probe().on_support(|_| Message::WebViewRendererReady)
        ];
        if let Some(dispatcher) = webview_native::main_thread_dispatcher(|unavailable| {
            self.dispatch_native_ready(unavailable)
        }) {
            layers = layers.push(dispatcher);
        }
        layers.into()
    }

    fn dispatch_native_ready(&self, unavailable: bool) -> Option<Message> {
        if unavailable {
            self.webview.borrow_mut().detach_gpu_source();
        }
        let previous = self.webview.borrow().native_visual_revision;
        let discarded = self.webview.borrow_mut().discard_refused_gpu_frame();
        webview_native::pump_main_thread();
        let traversal = self.webview.borrow_mut().ingest_native();
        if let Some(direction) = traversal {
            self.pending_native_traversal.set(Some(direction));
        }
        let publish = unavailable
            || discarded
            || traversal.is_some()
            || self.webview.borrow().native_visual_revision != previous;
        if publish {
            self.native_dispatch_publication.set(true);
        }
        publish.then_some(Message::WebViewNativeReady)
    }
}
