//! A page-event flood preserves a live dropdown and its native selection route.
//!
//! ```text
//! cargo test --offline --locked --workspace --features enzui-webkit/wpe --test wpe_event_overflow event_flood_ -- --ignored --nocapture
//! ```

mod wpe_native_support;

use std::time::{Duration, Instant};

use enzui_webkit::ffi::runtime::{HeadlessDisplay, WebSession};
use enzui_webkit::input::{self, InputEvent, Modifiers, PointerButton, ViewportMapping};
use enzui_webkit::page::{PAGE_EVENT_CAPACITY, PageEvent, PagePrompts, ScriptWorld};
use enzui_webkit::web::ViewRouter;

#[test]
#[ignore = "requires native WPE runtime"]
fn event_flood_preserves_a_live_prompt_and_its_answer() {
    wpe_native_support::run("event_flood_preserves_a_live_prompt_and_its_answer", || {
        let display = HeadlessDisplay::new().expect("display");
        let mut session = WebSession::new(&display).expect("session");
        let mut router = ViewRouter::new();
        let view = router.create(91);
        session.bind_view(&router, view).expect("bind view");
        session.set_page_prompts(PagePrompts {
            option_menus: true,
            ..PagePrompts::default()
        });
        assert!(session.register_message_handler("flood", &ScriptWorld::Page));
        assert!(session.forward_input(&InputEvent::FocusGained {
            view,
            modifiers: Modifiers::NONE
        }));
        let html = format!(
            "<title>waiting</title><style>select{{position:absolute;left:20px;top:20px;width:200px;height:60px}}</style>\
             <select onmousedown='setTimeout(flood,50)' onchange=\"document.title='picked:'+this.selectedIndex\">\
             <option>Alpha</option><option>Beta</option></select>\
             <script>function flood(){{for(let i=0;i<{};i++)window.webkit.messageHandlers.flood.postMessage(i);}}</script>",
            PAGE_EVENT_CAPACITY * 4
        );
        session
            .load_html(&html, "about:blank", 10_000)
            .expect("load menu");
        session.pump(100);
        session.take_page_events();
        let before = session.page_events_dropped();
        let mapping = ViewportMapping::new(0.0, 0.0, 1024.0, 768.0, 1.0).expect("mapping");
        for event in [
            input::pointer_moved(view, &mapping, 50.0, 40.0),
            input::pointer_pressed(view, &mapping, 50.0, 40.0, PointerButton::Primary),
            input::pointer_released(view, &mapping, 50.0, 40.0, PointerButton::Primary),
        ] {
            assert!(session.forward_input(&event.expect("inside viewport")));
            session.pump(10);
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while session.page_events_dropped() - before < (PAGE_EVENT_CAPACITY * 3) as u64 {
            assert!(
                Instant::now() < deadline,
                "the page must overflow the native queue"
            );
            session.pump(10);
        }
        let events = session.take_page_events();
        assert_eq!(
            events.len(),
            PAGE_EVENT_CAPACITY,
            "the queue remains bounded"
        );
        let menu = events
            .into_iter()
            .find_map(|event| match event {
                PageEvent::OptionMenu(menu) => Some(menu),
                _ => None,
            })
            .expect("a live prompt must stay visible despite later page events");
        assert_eq!(menu.items[1].label, "Beta");
        session
            .answer_option_menu(menu.id, Some(1))
            .expect("answer the retained prompt");
        let deadline = Instant::now() + Duration::from_secs(5);
        while session.page_title().expect("title").as_deref() != Some("picked:1") {
            assert!(Instant::now() < deadline, "the answer reaches the page");
            session.pump(10);
        }
        assert_eq!(
            session.decline_pending_prompts(),
            0,
            "selection released the native menu"
        );
    });
}
