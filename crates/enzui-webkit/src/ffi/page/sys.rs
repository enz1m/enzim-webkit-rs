//! Declarations this module adds to [`crate::ffi::wpe`]. Each matches its header
//! under `/usr/include/wpe-webkit-2.0/` byte for byte.

use super::{c_char, c_int, c_uint, c_void};
use crate::ffi::wpe::{
    GAsyncResult, GBoolean, GError, WebKitAuthenticationRequest, WebKitCookieManager,
    WebKitNetworkSession, WebKitWebView,
};

macro_rules! opaque {
    ($($name:ident),* $(,)?) => {$(
        #[repr(C)]
        pub struct $name {
            _priv: [u8; 0],
        }
    )*};
}
opaque!(
    WebKitSettings,
    WebKitScriptDialog,
    WebKitFileChooserRequest,
    WebKitHitTestResult,
    WebKitContextMenu,
    WebKitUserContentManager,
    WebKitUserScript,
    WebKitUserStyleSheet,
    WebKitWebsiteDataManager,
    WebKitFindController,
    JSCValue,
    GParamSpec,
    WebKitOptionMenu,
    WebKitOptionMenuItem,
    WebKitNotification,
    WebKitPermissionStateQuery,
    WebKitFeature,
    WebKitFeatureList,
    WebKitContextMenuItem,
    GAction,
);

pub const WEBKIT_CONTEXT_MENU_ACTION_SPELLING_GUESS: c_int = 16;
pub const WEBKIT_CONTEXT_MENU_ACTION_NO_GUESSES_FOUND: c_int = 17;
pub const WEBKIT_CONTEXT_MENU_ACTION_IGNORE_SPELLING: c_int = 18;
pub const WEBKIT_CONTEXT_MENU_ACTION_LEARN_SPELLING: c_int = 19;

/// `WebKitRectangle` (WebKitRectangle.h): four `gint`s.
#[repr(C)]
pub struct WebKitRectangle {
    pub x: c_int,
    pub y: c_int,
    pub width: c_int,
    pub height: c_int,
}

pub const WEBKIT_PERMISSION_STATE_GRANTED: c_int = 0;
pub const WEBKIT_PERMISSION_STATE_DENIED: c_int = 1;

pub type AsyncReady = extern "C" fn(*mut c_void, *mut GAsyncResult, *mut c_void);

pub const WEBKIT_SCRIPT_DIALOG_ALERT: c_int = 0;
pub const WEBKIT_SCRIPT_DIALOG_CONFIRM: c_int = 1;
pub const WEBKIT_SCRIPT_DIALOG_PROMPT: c_int = 2;
pub const WEBKIT_SCRIPT_DIALOG_BEFORE_UNLOAD_CONFIRM: c_int = 3;

pub const WEBKIT_HIT_TEST_RESULT_CONTEXT_LINK: c_uint = 1 << 2;
pub const WEBKIT_HIT_TEST_RESULT_CONTEXT_IMAGE: c_uint = 1 << 3;
pub const WEBKIT_HIT_TEST_RESULT_CONTEXT_MEDIA: c_uint = 1 << 4;
pub const WEBKIT_HIT_TEST_RESULT_CONTEXT_EDITABLE: c_uint = 1 << 5;
pub const WEBKIT_HIT_TEST_RESULT_CONTEXT_SELECTION: c_uint = 1 << 7;

pub const WEBKIT_FIND_OPTIONS_CASE_INSENSITIVE: u32 = 1 << 0;
pub const WEBKIT_FIND_OPTIONS_BACKWARDS: u32 = 1 << 3;
pub const WEBKIT_FIND_OPTIONS_WRAP_AROUND: u32 = 1 << 4;

unsafe extern "C" {
    pub fn webkit_javascript_error_quark() -> u32;
    // WebKitWebView.h
    pub fn webkit_web_view_get_back_forward_list(web_view: *mut WebKitWebView) -> *mut c_void;
    pub fn webkit_back_forward_list_get_nth_item(list: *mut c_void, index: c_int) -> *mut c_void;
    pub fn webkit_back_forward_list_get_current_item(list: *mut c_void) -> *mut c_void;
    pub fn webkit_back_forward_list_item_get_uri(item: *mut c_void) -> *const c_char;
    pub fn webkit_web_view_go_to_back_forward_list_item(
        web_view: *mut WebKitWebView,
        item: *mut c_void,
    );
    pub fn webkit_back_forward_list_get_length(list: *mut c_void) -> c_uint;
    pub fn webkit_web_view_get_session_state(web_view: *mut WebKitWebView) -> *mut c_void;
    pub fn webkit_web_view_session_state_new(bytes: *mut c_void) -> *mut c_void;
    pub fn webkit_web_view_session_state_serialize(state: *mut c_void) -> *mut c_void;
    pub fn webkit_web_view_session_state_unref(state: *mut c_void);
    pub fn webkit_web_view_restore_session_state(web_view: *mut WebKitWebView, state: *mut c_void);
    pub fn g_object_set_data(object: *mut c_void, key: *const c_char, data: *mut c_void);
    pub fn webkit_web_view_reload(web_view: *mut WebKitWebView);
    pub fn webkit_web_view_reload_bypass_cache(web_view: *mut WebKitWebView);
    pub fn webkit_web_view_is_loading(web_view: *mut WebKitWebView) -> GBoolean;
    pub fn webkit_web_view_get_estimated_load_progress(web_view: *mut WebKitWebView) -> f64;
    pub fn webkit_web_view_try_close(web_view: *mut WebKitWebView);
    // gobject.h
    pub fn g_object_weak_ref(
        object: *mut c_void,
        notify: extern "C" fn(*mut c_void, *mut c_void),
        data: *mut c_void,
    );

    pub fn webkit_web_view_get_display(
        web_view: *mut WebKitWebView,
    ) -> *mut crate::ffi::wpe::WPEDisplay;
    pub fn webkit_web_view_get_settings(web_view: *mut WebKitWebView) -> *mut WebKitSettings;
    pub fn webkit_settings_set_default_font_family(
        settings: *mut WebKitSettings,
        family: *const c_char,
    );
    pub fn webkit_settings_set_serif_font_family(
        settings: *mut WebKitSettings,
        family: *const c_char,
    );
    pub fn webkit_settings_set_sans_serif_font_family(
        settings: *mut WebKitSettings,
        family: *const c_char,
    );
    pub fn webkit_settings_set_monospace_font_family(
        settings: *mut WebKitSettings,
        family: *const c_char,
    );
    pub fn webkit_web_view_get_user_content_manager(
        web_view: *mut WebKitWebView,
    ) -> *mut WebKitUserContentManager;
    pub fn webkit_web_view_get_find_controller(
        web_view: *mut WebKitWebView,
    ) -> *mut WebKitFindController;
    pub fn webkit_web_view_evaluate_javascript(
        web_view: *mut WebKitWebView,
        script: *const c_char,
        length: isize,
        world_name: *const c_char,
        source_uri: *const c_char,
        cancellable: *mut c_void,
        callback: AsyncReady,
        user_data: *mut c_void,
    );
    pub fn webkit_web_view_evaluate_javascript_finish(
        web_view: *mut WebKitWebView,
        result: *mut GAsyncResult,
        error: *mut *mut GError,
    ) -> *mut JSCValue;

    pub fn webkit_web_view_call_async_javascript_function(
        web_view: *mut WebKitWebView,
        body: *const c_char,
        length: isize,
        arguments: *mut c_void,
        world_name: *const c_char,
        source_uri: *const c_char,
        cancellable: *mut c_void,
        callback: AsyncReady,
        user_data: *mut c_void,
    );
    pub fn webkit_web_view_call_async_javascript_function_finish(
        web_view: *mut WebKitWebView,
        result: *mut GAsyncResult,
        error: *mut *mut GError,
    ) -> *mut JSCValue;

    // jsc/JSCValue.h
    pub fn jsc_value_to_json(value: *mut JSCValue, indent: c_uint) -> *mut c_char;
    pub fn jsc_value_is_undefined(value: *mut JSCValue) -> GBoolean;
    pub fn jsc_value_is_null(value: *mut JSCValue) -> GBoolean;
    pub fn jsc_value_to_string(value: *mut JSCValue) -> *mut c_char;
    pub fn jsc_value_get_context(value: *mut JSCValue) -> *mut c_void;
    pub fn jsc_context_clear_exception(context: *mut c_void);

    // WebKitSettings.h
    pub fn webkit_settings_set_user_agent(settings: *mut WebKitSettings, ua: *const c_char);
    pub fn webkit_settings_set_user_agent_with_application_details(
        settings: *mut WebKitSettings,
        application_name: *const c_char,
        application_version: *const c_char,
    );
    pub fn webkit_settings_get_user_agent(settings: *mut WebKitSettings) -> *const c_char;
    pub fn webkit_settings_set_enable_javascript(settings: *mut WebKitSettings, on: GBoolean);
    pub fn webkit_settings_set_javascript_can_open_windows_automatically(
        settings: *mut WebKitSettings,
        on: GBoolean,
    );
    pub fn webkit_settings_set_enable_developer_extras(settings: *mut WebKitSettings, on: GBoolean);
    pub fn webkit_settings_set_media_playback_requires_user_gesture(
        settings: *mut WebKitSettings,
        on: GBoolean,
    );
    pub fn webkit_settings_set_enable_webgl(settings: *mut WebKitSettings, on: GBoolean);
    pub fn webkit_settings_get_enable_developer_extras(settings: *mut WebKitSettings) -> GBoolean;
    pub fn webkit_settings_set_enable_encrypted_media(settings: *mut WebKitSettings, on: GBoolean);
    pub fn webkit_settings_set_enable_webrtc(settings: *mut WebKitSettings, on: GBoolean);
    pub fn webkit_settings_set_enable_media_stream(settings: *mut WebKitSettings, on: GBoolean);
    pub fn webkit_settings_set_enable_page_cache(settings: *mut WebKitSettings, on: GBoolean);
    pub fn webkit_settings_set_zoom_text_only(settings: *mut WebKitSettings, on: GBoolean);

    // WebKitScriptDialog.h
    pub fn webkit_script_dialog_ref(dialog: *mut WebKitScriptDialog) -> *mut WebKitScriptDialog;
    pub fn webkit_script_dialog_unref(dialog: *mut WebKitScriptDialog);
    pub fn webkit_script_dialog_get_dialog_type(dialog: *mut WebKitScriptDialog) -> c_int;
    pub fn webkit_script_dialog_get_message(dialog: *mut WebKitScriptDialog) -> *const c_char;
    pub fn webkit_script_dialog_confirm_set_confirmed(
        dialog: *mut WebKitScriptDialog,
        confirmed: GBoolean,
    );
    pub fn webkit_script_dialog_prompt_get_default_text(
        dialog: *mut WebKitScriptDialog,
    ) -> *const c_char;
    pub fn webkit_script_dialog_prompt_set_text(
        dialog: *mut WebKitScriptDialog,
        text: *const c_char,
    );
    pub fn webkit_script_dialog_close(dialog: *mut WebKitScriptDialog);

    // WebKitFileChooserRequest.h
    pub fn webkit_file_chooser_request_get_mime_types(
        request: *mut WebKitFileChooserRequest,
    ) -> *const *const c_char;
    pub fn webkit_file_chooser_request_get_select_multiple(
        request: *mut WebKitFileChooserRequest,
    ) -> GBoolean;
    pub fn webkit_file_chooser_request_select_files(
        request: *mut WebKitFileChooserRequest,
        files: *const *const c_char,
    );
    pub fn webkit_file_chooser_request_cancel(request: *mut WebKitFileChooserRequest);

    // WebKitContextMenu.h / WebKitContextMenuItem.h
    pub fn webkit_context_menu_get_n_items(menu: *mut WebKitContextMenu) -> c_uint;
    pub fn webkit_context_menu_get_item_at_position(
        menu: *mut WebKitContextMenu,
        position: c_uint,
    ) -> *mut WebKitContextMenuItem;
    pub fn webkit_context_menu_item_get_stock_action(item: *mut WebKitContextMenuItem) -> c_int;
    pub fn webkit_context_menu_item_get_gaction(item: *mut WebKitContextMenuItem) -> *mut GAction;
    pub fn webkit_context_menu_item_get_title(item: *mut WebKitContextMenuItem) -> *const c_char;

    // gio/gaction.h
    pub fn g_action_activate(action: *mut GAction, parameter: *mut c_void);

    // WebKitWebContext.h
    pub fn webkit_web_view_get_context(
        view: *mut WebKitWebView,
    ) -> *mut crate::ffi::wpe::WebKitWebContext;
    pub fn webkit_web_context_set_spell_checking_enabled(
        context: *mut crate::ffi::wpe::WebKitWebContext,
        enabled: GBoolean,
    );
    pub fn webkit_web_context_set_spell_checking_languages(
        context: *mut crate::ffi::wpe::WebKitWebContext,
        languages: *const *const c_char,
    );

    // WebKitAuthenticationRequest.h
    pub fn webkit_authentication_request_get_realm(
        request: *mut WebKitAuthenticationRequest,
    ) -> *const c_char;
    pub fn webkit_authentication_request_get_scheme(
        request: *mut WebKitAuthenticationRequest,
    ) -> c_int;
    pub fn webkit_authentication_request_cancel(request: *mut WebKitAuthenticationRequest);

    // WebKitHitTestResult.h
    pub fn webkit_hit_test_result_get_context(hit: *mut WebKitHitTestResult) -> c_uint;
    pub fn webkit_hit_test_result_get_link_uri(hit: *mut WebKitHitTestResult) -> *const c_char;
    pub fn webkit_hit_test_result_get_image_uri(hit: *mut WebKitHitTestResult) -> *const c_char;
    pub fn webkit_hit_test_result_get_media_uri(hit: *mut WebKitHitTestResult) -> *const c_char;

    // WebKitUserContentManager.h / WebKitUserContent.h
    pub fn webkit_user_content_manager_register_script_message_handler(
        manager: *mut WebKitUserContentManager,
        name: *const c_char,
        world_name: *const c_char,
    ) -> GBoolean;
    pub fn webkit_user_content_manager_unregister_script_message_handler(
        manager: *mut WebKitUserContentManager,
        name: *const c_char,
        world_name: *const c_char,
    );
    pub fn webkit_user_content_manager_add_script(
        manager: *mut WebKitUserContentManager,
        script: *mut WebKitUserScript,
    );
    pub fn webkit_user_content_manager_remove_all_scripts(manager: *mut WebKitUserContentManager);
    pub fn webkit_user_script_new_for_world(
        source: *const c_char,
        injected_frames: c_int,
        injection_time: c_int,
        world_name: *const c_char,
        allow_list: *const *const c_char,
        block_list: *const *const c_char,
    ) -> *mut WebKitUserScript;
    pub fn webkit_user_script_new(
        source: *const c_char,
        injected_frames: c_int,
        injection_time: c_int,
        allow_list: *const *const c_char,
        block_list: *const *const c_char,
    ) -> *mut WebKitUserScript;
    pub fn webkit_user_script_unref(script: *mut WebKitUserScript);
    pub fn webkit_user_content_manager_remove_script(
        manager: *mut WebKitUserContentManager,
        script: *mut WebKitUserScript,
    );
    pub fn webkit_user_style_sheet_new(
        source: *const c_char,
        injected_frames: c_int,
        level: c_int,
        allow_list: *const *const c_char,
        block_list: *const *const c_char,
    ) -> *mut WebKitUserStyleSheet;
    pub fn webkit_user_style_sheet_unref(sheet: *mut WebKitUserStyleSheet);
    pub fn webkit_user_content_manager_add_style_sheet(
        manager: *mut WebKitUserContentManager,
        sheet: *mut WebKitUserStyleSheet,
    );
    pub fn webkit_user_content_manager_remove_style_sheet(
        manager: *mut WebKitUserContentManager,
        sheet: *mut WebKitUserStyleSheet,
    );

    // WebKitNetworkSession.h / WebKitWebsiteDataManager.h / WebKitCookieManager.h
    pub fn webkit_network_session_get_website_data_manager(
        session: *mut WebKitNetworkSession,
    ) -> *mut WebKitWebsiteDataManager;
    pub fn webkit_network_session_set_itp_enabled(
        session: *mut WebKitNetworkSession,
        enabled: GBoolean,
    );
    pub fn webkit_cookie_manager_set_accept_policy(
        manager: *mut WebKitCookieManager,
        policy: c_int,
    );
    pub fn webkit_website_data_manager_clear(
        manager: *mut WebKitWebsiteDataManager,
        types: c_uint,
        timespan: i64,
        cancellable: *mut c_void,
        callback: AsyncReady,
        user_data: *mut c_void,
    );
    pub fn webkit_website_data_manager_clear_finish(
        manager: *mut WebKitWebsiteDataManager,
        result: *mut GAsyncResult,
        error: *mut *mut GError,
    ) -> GBoolean;

    // WebKitFeature.h / WebKitSettings.h (feature flags)
    pub fn webkit_settings_get_all_features() -> *mut WebKitFeatureList;
    pub fn webkit_feature_list_get_length(list: *mut WebKitFeatureList) -> usize;
    pub fn webkit_feature_list_get(
        list: *mut WebKitFeatureList,
        index: usize,
    ) -> *mut WebKitFeature;
    pub fn webkit_feature_list_unref(list: *mut WebKitFeatureList);
    pub fn webkit_feature_get_identifier(feature: *mut WebKitFeature) -> *const c_char;
    pub fn webkit_feature_get_default_value(feature: *mut WebKitFeature) -> GBoolean;
    pub fn webkit_settings_set_feature_enabled(
        settings: *mut WebKitSettings,
        feature: *mut WebKitFeature,
        enabled: GBoolean,
    );
    pub fn webkit_settings_get_feature_enabled(
        settings: *mut WebKitSettings,
        feature: *mut WebKitFeature,
    ) -> GBoolean;

    // WebKitOptionMenu.h / WebKitOptionMenuItem.h
    pub fn webkit_option_menu_get_n_items(menu: *mut WebKitOptionMenu) -> c_uint;
    pub fn webkit_option_menu_get_item(
        menu: *mut WebKitOptionMenu,
        index: c_uint,
    ) -> *mut WebKitOptionMenuItem;
    pub fn webkit_option_menu_activate_item(menu: *mut WebKitOptionMenu, index: c_uint);
    pub fn webkit_option_menu_close(menu: *mut WebKitOptionMenu);
    pub fn webkit_option_menu_item_get_label(item: *mut WebKitOptionMenuItem) -> *const c_char;
    pub fn webkit_option_menu_item_get_tooltip(item: *mut WebKitOptionMenuItem) -> *const c_char;
    pub fn webkit_option_menu_item_is_group_label(item: *mut WebKitOptionMenuItem) -> GBoolean;
    pub fn webkit_option_menu_item_is_group_child(item: *mut WebKitOptionMenuItem) -> GBoolean;
    pub fn webkit_option_menu_item_is_enabled(item: *mut WebKitOptionMenuItem) -> GBoolean;
    pub fn webkit_option_menu_item_is_selected(item: *mut WebKitOptionMenuItem) -> GBoolean;

    // WebKitNotification.h
    pub fn webkit_notification_get_title(notification: *mut WebKitNotification) -> *const c_char;
    pub fn webkit_notification_close(notification: *mut WebKitNotification);
    pub fn webkit_notification_get_body(notification: *mut WebKitNotification) -> *const c_char;
    pub fn webkit_notification_get_tag(notification: *mut WebKitNotification) -> *const c_char;
    pub fn webkit_notification_get_id(notification: *mut WebKitNotification) -> u64;
    pub fn webkit_notification_clicked(notification: *mut WebKitNotification);

    // WebKitPermissionStateQuery.h
    pub fn webkit_permission_state_query_get_name(
        query: *mut WebKitPermissionStateQuery,
    ) -> *const c_char;
    pub fn webkit_permission_state_query_finish(
        query: *mut WebKitPermissionStateQuery,
        state: c_int,
    );

    // WebKitWebView.h (media)
    pub fn webkit_web_view_is_playing_audio(web_view: *mut WebKitWebView) -> GBoolean;
    pub fn webkit_web_view_set_is_muted(web_view: *mut WebKitWebView, muted: GBoolean);
    pub fn webkit_web_view_get_is_muted(web_view: *mut WebKitWebView) -> GBoolean;

    // WebKitDownload.h / WebKitURIResponse.h
    pub fn webkit_download_set_destination(
        download: *mut crate::ffi::wpe::WebKitDownload,
        destination: *const c_char,
    );
    pub fn webkit_download_set_allow_overwrite(
        download: *mut crate::ffi::wpe::WebKitDownload,
        allowed: GBoolean,
    );
    pub fn webkit_download_get_response(
        download: *mut crate::ffi::wpe::WebKitDownload,
    ) -> *mut crate::ffi::wpe::WebKitURIResponse;
    pub fn webkit_download_get_received_data_length(
        download: *mut crate::ffi::wpe::WebKitDownload,
    ) -> u64;
    pub fn webkit_uri_response_get_http_headers(
        response: *mut crate::ffi::wpe::WebKitURIResponse,
    ) -> *mut crate::ffi::wpe::SoupMessageHeaders;
    pub fn webkit_uri_response_get_content_length(
        response: *mut crate::ffi::wpe::WebKitURIResponse,
    ) -> u64;

    // WebKitFindController.h
    pub fn webkit_find_controller_search(
        controller: *mut WebKitFindController,
        text: *const c_char,
        options: u32,
        max_match_count: c_uint,
    );
    pub fn webkit_find_controller_search_next(controller: *mut WebKitFindController);
    pub fn webkit_find_controller_search_previous(controller: *mut WebKitFindController);
    pub fn webkit_find_controller_search_finish(controller: *mut WebKitFindController);
    pub fn webkit_find_controller_count_matches(
        controller: *mut WebKitFindController,
        text: *const c_char,
        options: u32,
        max_match_count: c_uint,
    );
}

unsafe extern "C" {
    pub fn webkit_settings_set_enable_mock_capture_devices(
        settings: *mut WebKitSettings,
        enabled: GBoolean,
    );
    pub fn webkit_settings_get_enable_mock_capture_devices(
        settings: *mut WebKitSettings,
    ) -> GBoolean;
}
