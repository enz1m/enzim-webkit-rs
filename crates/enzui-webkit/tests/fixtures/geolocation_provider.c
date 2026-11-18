#include <wpe/webkit.h>
#include <math.h>

static WebKitGeolocationManager *manager;
static gulong start_handler;
static gulong stop_handler;
static guint starts;
static guint stops;
static guint64 last_timestamp;

static gboolean on_start(WebKitGeolocationManager *source, gpointer data)
{
    (void)source;
    (void)data;
    starts++;
    return TRUE;
}

static void on_stop(WebKitGeolocationManager *source, gpointer data)
{
    (void)source;
    (void)data;
    stops++;
}

gboolean enzui_geolocation_provider_install(void)
{
    if (manager)
        return FALSE;
    WebKitWebContext *context = webkit_web_context_get_default();
    if (!context)
        return FALSE;
    WebKitGeolocationManager *native = webkit_web_context_get_geolocation_manager(context);
    if (!native)
        return FALSE;
    manager = g_object_ref(native);
    starts = 0;
    stops = 0;
    last_timestamp = 0;
    start_handler = g_signal_connect(manager, "start", G_CALLBACK(on_start), NULL);
    stop_handler = g_signal_connect(manager, "stop", G_CALLBACK(on_stop), NULL);
    return start_handler != 0 && stop_handler != 0;
}

gboolean enzui_geolocation_provider_push(double latitude)
{
    if (!manager || !isfinite(latitude) || latitude < -90 || latitude > 90)
        return FALSE;
    WebKitGeolocationPosition *position = webkit_geolocation_position_new(latitude, 0, 1);
    if (!position)
        return FALSE;
    guint64 timestamp = (guint64)(g_get_real_time() / 1000);
    if (timestamp <= last_timestamp)
        timestamp = last_timestamp + 1;
    last_timestamp = timestamp;
    webkit_geolocation_position_set_timestamp(position, timestamp);
    webkit_geolocation_manager_update_position(manager, position);
    webkit_geolocation_position_free(position);
    return TRUE;
}

void enzui_geolocation_provider_get_counts(guint *start_count, guint *stop_count)
{
    if (start_count)
        *start_count = starts;
    if (stop_count)
        *stop_count = stops;
}

void enzui_geolocation_provider_uninstall(void)
{
    if (!manager)
        return;
    g_signal_handler_disconnect(manager, start_handler);
    g_signal_handler_disconnect(manager, stop_handler);
    g_clear_object(&manager);
    start_handler = 0;
    stop_handler = 0;
}
