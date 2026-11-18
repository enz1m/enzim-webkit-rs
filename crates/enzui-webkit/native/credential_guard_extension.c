/*
 * WPE WebProcess request guard for credential-bearing URLs.
 *
 * WPE 2.52.5 has already normalised the follow-up request URI at
 * WebKitWebPage::send-request.  For redirects, redirected_response retains the
 * wire Location value, so this synchronous cancellable boundary inspects that
 * value before allowing the normalised request to leave the WebProcess.
 *
 * No URI, username, or password leaves this callback. The UI receives only a
 * constant verdict name for its typed audit observation.
 */
#include <string.h>
#include <gmodule.h>
#include <libsoup/soup.h>
#include <wpe/webkit-web-process-extension.h>

#define READY_MESSAGE "enzui-credential-guard-ready-v1"
#define DENIED_MESSAGE "enzui-credentials-in-url-v1"

/*
 * WHATWG URL parsing deletes every ASCII tab, LF and CR from the input before
 * any scheme or authority is read, and WebKit's parser does the same. An HTTP
 * field value may legally carry an interior HTAB, so a redirect `Location`
 * reaches this callback with those bytes intact: they must be skipped here or
 * the guard reads a different URL from the one WebKit will fetch. Skipping in
 * place preserves the rule that the raw value is never copied.
 */
static gboolean
removed_by_url_parser(unsigned char value)
{
    return value == 0x09 || value == 0x0A || value == 0x0D;
}

static const unsigned char *
skip_removed(const unsigned char *cursor)
{
    while (removed_by_url_parser(*cursor))
        cursor++;
    return cursor;
}

/*
 * Case-insensitive scheme match across removed characters. `*after` is set to
 * the first surviving character past the prefix, and only on a match.
 */
static gboolean
scheme_prefix_equal(const unsigned char *cursor, const char *prefix,
                    const unsigned char **after)
{
    for (; *prefix; prefix++) {
        cursor = skip_removed(cursor);
        if (g_ascii_tolower((gchar)*cursor) != g_ascii_tolower(*prefix))
            return FALSE;
        cursor++;
    }
    *after = cursor;
    return TRUE;
}

/*
 * Match the authority grammar WebKit's WHATWG URL parser applies to special
 * HTTP-family schemes. Leading C0 controls/space are stripped, removed
 * characters are skipped wherever they appear, and every run of
 * slash/backslash after a special-scheme colon enters the authority state;
 * WebKit treats backslash as slash for these schemes. Network-path references
 * likewise accept either slash spelling. The raw value is inspected in place
 * and is never copied, formatted, or returned.
 */
static gboolean
has_http_userinfo(const char *uri)
{
    const unsigned char *cursor;
    const unsigned char *after;

    if (!uri)
        return FALSE;

    cursor = (const unsigned char *)uri;
    while (*cursor && *cursor <= 0x20)
        cursor++;

    if (scheme_prefix_equal(cursor, "https:", &after)
        || scheme_prefix_equal(cursor, "http:", &after)) {
        cursor = after;
    } else {
        const unsigned char *second;

        cursor = skip_removed(cursor);
        if (*cursor != '/' && *cursor != '\\')
            return FALSE;
        second = skip_removed(cursor + 1);
        if (*second != '/' && *second != '\\')
            return FALSE;
        cursor = second + 1;
    }

    /* WHATWG special-authority-ignore-slashes consumes an arbitrary mixture. */
    for (;;) {
        cursor = skip_removed(cursor);
        if (*cursor != '/' && *cursor != '\\')
            break;
        cursor++;
    }

    for (;;) {
        cursor = skip_removed(cursor);
        if (!*cursor || *cursor == '/' || *cursor == '\\' || *cursor == '?'
            || *cursor == '#' || *cursor <= 0x20)
            return FALSE;
        if (*cursor == '@')
            return TRUE;
        cursor++;
    }
}

#ifdef ENZUI_CREDENTIAL_GUARD_PARSER_TEST
/* Build-time unit vectors: the extension cannot ship with parser drift. */
int
main(void)
{
    static const struct {
        const char *uri;
        gboolean denied;
    } vectors[] = {
        { "https://u:p@example.invalid/", TRUE },
        { " \thttps://u@example.invalid/", TRUE },
        { "\x01" " https://u@example.invalid/", TRUE },
        { "https:/\\u@example.invalid/", TRUE },
        { "https:\\\\u@example.invalid/", TRUE },
        { "https:\\/u@example.invalid/", TRUE },
        { "https:u@example.invalid/", TRUE },
        { "http:////\\u@example.invalid/", TRUE },
        { "//u@example.invalid/path", TRUE },
        { "\\\\u@example.invalid/path", TRUE },
        { "https://example.invalid/path@segment", FALSE },
        { "https:\\example.invalid\\path@segment", FALSE },
        { "https://example.invalid/?u@example.invalid", FALSE },
        /*
         * Each authority terminator has to end the scan on its own. With a
         * path separator in front of it, the vector above passes whether or
         * not `?` is still a terminator.
         */
        { "https://example.invalid?u@example.invalid", FALSE },
        { "https://example.invalid#u@example.invalid", FALSE },
        { "https://example.invalid u@example.invalid", FALSE },
        { "mailto:u@example.invalid", FALSE },
        /*
         * Removed characters (tab, LF, CR) are deleted before parsing, so they
         * may not hide a scheme, a slash run, or a userinfo separator. An
         * interior HTAB is legal HTTP field content and reaches this guard
         * verbatim from a redirect `Location`.
         */
        { "ht\ttps://u:p@example.invalid/", TRUE },
        { "https\t://u@example.invalid/", TRUE },
        { "https:/\t/u@example.invalid/", TRUE },
        { "https://u\t:p@example.invalid/", TRUE },
        { "ht\ntps://u@example.invalid/", TRUE },
        { "ht\rtps://u@example.invalid/", TRUE },
        { "/\t/u@example.invalid/path", TRUE },
        { "h\tt\tt\tp\t:\t/\t/\tu@example.invalid/", TRUE },
        /* Removal must not manufacture userinfo the parser would not see. */
        { "https://example.invalid/pa\tth@segment", FALSE },
        { "mai\tlto:u@example.invalid", FALSE },
        { "\t", FALSE },
        { "https:", FALSE },
        { NULL, FALSE },
    };
    size_t index;

    for (index = 0; index < G_N_ELEMENTS(vectors); index++) {
        if (has_http_userinfo(vectors[index].uri) != vectors[index].denied)
            return (int)index + 1;
    }
    return 0;
}
#else
typedef gboolean (*NativeDocumentReady)(WebKitWebPage *);

static NativeDocumentReady
native_document_ready(void)
{
    static gsize initialized;
    static NativeDocumentReady function;
    if (g_once_init_enter(&initialized)) {
        GModule *module = g_module_open(NULL, G_MODULE_BIND_LAZY);
        gpointer symbol = NULL;
        if (module) {
            if (g_module_symbol(module, "webkit_web_page_enzui_document_ready_v1", &symbol))
                function = (NativeDocumentReady)symbol;
            g_module_close(module);
        }
        g_once_init_leave(&initialized, 1);
    }
    return function;
}

typedef gboolean (*NativeInspectElement)(WebKitWebPage *, double, double);

static NativeInspectElement
native_inspect_element(void)
{
    static gsize initialized;
    static NativeInspectElement function;
    if (g_once_init_enter(&initialized)) {
        GModule *module = g_module_open(NULL, G_MODULE_BIND_LAZY);
        gpointer symbol = NULL;
        if (module) {
            if (g_module_symbol(module, "webkit_web_page_enzui_inspect_element_at_v1", &symbol))
                function = (NativeInspectElement)symbol;
            g_module_close(module);
        }
        g_once_init_leave(&initialized, 1);
    }
    return function;
}

static gboolean
on_private_message(WebKitWebPage *page, WebKitUserMessage *message, gpointer user_data)
{
    (void)user_data;
    if (!g_strcmp0(webkit_user_message_get_name(message), "enzui-inspect-element-v1")) {
        GVariant *point = webkit_user_message_get_parameters(message);
        NativeInspectElement inspect = native_inspect_element();
        if (inspect && point && g_variant_is_of_type(point, G_VARIANT_TYPE("(ii)"))) {
            gint32 x, y;
            g_variant_get(point, "(ii)", &x, &y);
            inspect(page, x, y);
        }
        return TRUE;
    }
    if (g_strcmp0(webkit_user_message_get_name(message), "enzui-document-probe-v1"))
        return FALSE;
    NativeDocumentReady probe = native_document_ready();
    const char *name = !probe ? "enzui-document-probe-unavailable-v1"
        : probe(page) ? "enzui-document-ready-v1" : "enzui-document-busy-v1";
    webkit_user_message_send_reply(message, webkit_user_message_new(name, NULL));
    return TRUE;
}

static void
send_constant_message(WebKitWebPage *page, const char *name)
{
    WebKitUserMessage *message = webkit_user_message_new(name, NULL);
    /* A newly-created UserMessage is floating; this call consumes it. */
    webkit_web_page_send_message_to_view(page, message, NULL, NULL, NULL);
}

static gboolean
on_send_request(WebKitWebPage *page,
                WebKitURIRequest *request,
                WebKitURIResponse *redirected_response,
                gpointer user_data)
{
    (void)user_data;

    const char *location = NULL;
    if (redirected_response) {
        SoupMessageHeaders *response_headers =
            webkit_uri_response_get_http_headers(redirected_response);
        if (response_headers)
            location = soup_message_headers_get_one(response_headers, "Location");
    }

    /* Returning TRUE synchronously cancels this resource before it is sent. */
    if (!has_http_userinfo(location)
        && !has_http_userinfo(webkit_uri_request_get_uri(request)))
        return FALSE;

    send_constant_message(page, DENIED_MESSAGE);
    return TRUE;
}

static void
on_page_created(WebKitWebProcessExtension *extension,
                WebKitWebPage *page,
                gpointer user_data)
{
    (void)extension;
    (void)user_data;

    g_signal_connect(page, "send-request", G_CALLBACK(on_send_request), NULL);
    g_signal_connect(page, "user-message-received", G_CALLBACK(on_private_message), NULL);
    /* Construction fails closed unless the UI sees this bootstrap handshake. */
    send_constant_message(page, READY_MESSAGE);
}

G_MODULE_EXPORT void
webkit_web_process_extension_initialize(WebKitWebProcessExtension *extension)
{
    g_signal_connect(extension, "page-created", G_CALLBACK(on_page_created), NULL);
}
#endif
