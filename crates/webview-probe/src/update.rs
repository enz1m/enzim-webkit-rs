//! `App::update`: every [`Message`] to its state mutation and follow-up [`Task`].

use crate::{App, Message, drain_a11y_actions, drain_a11y_wake};
use iced::Task;

impl App {
    pub(crate) fn update(&mut self, message: Message) -> Task<Message> {
        let native_ready = matches!(message, Message::WebViewNativeReady);
        let dispatched_publication =
            native_ready && self.native_dispatch_publication.replace(false);
        let native_ready = native_ready && !dispatched_publication;
        let previous_visual = self.webview.borrow().native_visual_revision;
        let discarded_gpu = self.webview.borrow_mut().discard_refused_gpu_frame();
        crate::webview_native::pump_main_thread();
        // Actions applied in the publishing window; enqueue and wake are
        // separate boundaries, so unwoken work applies on the next update.
        let mut task = Task::none();
        let a11y_tasks = drain_a11y_actions();
        let had_a11y = !a11y_tasks.is_empty();
        if had_a11y {
            task = Task::batch(a11y_tasks);
        }

        match message {
            Message::A11yWake(receipt) => {
                let wake_tasks = drain_a11y_wake(receipt);
                if !wake_tasks.is_empty() {
                    task = Task::batch(std::iter::once(task).chain(wake_tasks));
                }
            }
            Message::A11yActivatePageNode(id) => {
                self.webview.borrow_mut().activate_published_node(&id);
            }
            message => task = self.update_webview(message, task),
        }
        crate::webview_native::pump_main_thread();
        if self.browser_mode {
            let location = self.webview.borrow().location.clone();
            if location != self.last_location {
                if !self.address_dirty
                    && let Some(uri) = &location
                {
                    self.address = uri.clone();
                }
                self.last_location = location;
            }
        }
        if native_ready
            && !had_a11y
            && !discarded_gpu
            && self.webview.borrow().native_visual_revision == previous_visual
        {
            Task::batch([task, enzui_core::native_loop::quiet()])
        } else {
            task
        }
    }
}

include!("update/webview.rs");
