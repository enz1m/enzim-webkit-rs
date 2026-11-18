#define _GNU_SOURCE
#include <unistd.h>
#include <wpe/wpe-platform.h>

typedef gboolean (*EnzuiRenderBuffer)(WPEView *, WPEBuffer *, const WPERectangle *, guint, GError **);

typedef struct {
    WPEBufferFormats *(*original)(WPEToplevel *);
} EnzuiFormatsClass;

static WPEBufferFormats *preferred_formats(WPEToplevel *toplevel)
{
    WPEBufferFormats *formats = g_object_get_data(G_OBJECT(toplevel), "enzui-buffer-formats");
    if (formats)
        return formats;
    EnzuiFormatsClass *klass = g_type_get_qdata(G_OBJECT_TYPE(toplevel),
        g_quark_from_static_string("enzui-formats-class"));
    return klass && klass->original ? klass->original(toplevel) : NULL;
}

gboolean enzui_wpe_set_buffer_formats(WPEView *view, const guint32 *formats,
    const guint64 *modifiers, guint count)
{
    WPEToplevel *toplevel = wpe_view_get_toplevel(view);
    if (!toplevel)
        return FALSE;
    GQuark key = g_quark_from_static_string("enzui-formats-class");
    if (!g_type_get_qdata(G_OBJECT_TYPE(toplevel), key)) {
        EnzuiFormatsClass *saved = g_new(EnzuiFormatsClass, 1);
        WPEToplevelClass *klass = WPE_TOPLEVEL_GET_CLASS(toplevel);
        saved->original = klass->get_preferred_buffer_formats;
        g_type_set_qdata(G_OBJECT_TYPE(toplevel), key, saved);
        klass->get_preferred_buffer_formats = preferred_formats;
    }
    WPEBufferFormats *preferred = NULL;
    if (count) {
        WPEDisplay *display = wpe_view_get_display(view);
        WPEBufferFormatsBuilder *builder = wpe_buffer_formats_builder_new(
            wpe_display_get_drm_device(display));
        wpe_buffer_formats_builder_append_group(builder, NULL, WPE_BUFFER_FORMAT_USAGE_RENDERING);
        for (guint i = 0; i < count; ++i)
            wpe_buffer_formats_builder_append_format(builder, formats[i], modifiers[i]);
        preferred = wpe_buffer_formats_builder_end(builder);
    }
    g_object_set_data_full(G_OBJECT(toplevel), "enzui-buffer-formats", preferred,
        preferred ? g_object_unref : NULL);
    wpe_toplevel_preferred_buffer_formats_changed(toplevel);
    return TRUE;
}

EnzuiRenderBuffer enzui_wpe_swap_render_buffer(WPEView *view, EnzuiRenderBuffer replacement)
{
    WPEViewClass *klass = WPE_VIEW_GET_CLASS(view);
    EnzuiRenderBuffer original = klass->render_buffer;
    klass->render_buffer = replacement;
    return original;
}

static void frame_rendered(WPEView *view, WPEBuffer *buffer, gpointer data)
{
    (void)view;
    (void)buffer;
    guint64 *count = data;
    if (*count != G_MAXUINT64)
        ++*count;
}

void enzui_wpe_observe_frames(WPEView *view)
{
    if (g_object_get_data(G_OBJECT(view), "enzui-rendered-frame-count"))
        return;
    guint64 *count = g_new0(guint64, 1);
    g_object_set_data_full(G_OBJECT(view), "enzui-rendered-frame-count", count, g_free);
    g_signal_connect(view, "buffer-rendered", G_CALLBACK(frame_rendered), count);
}

guint64 enzui_wpe_rendered_frame_count(WPEView *view)
{
    guint64 *count = g_object_get_data(G_OBJECT(view), "enzui-rendered-frame-count");
    return count ? *count : 0;
}

gboolean enzui_wpe_is_process_main_thread(void)
{
    return getpid() == gettid();
}

guint64 enzui_wpe_buffer_identity(WPEBuffer *buffer)
{
    static guint64 next_id = 1;
    guint64 *id = g_object_get_data(G_OBJECT(buffer), "enzui-buffer-identity");
    if (id)
        return *id;
    if (next_id == G_MAXUINT64)
        return 0;
    id = g_new(guint64, 1);
    *id = next_id++;
    g_object_set_data_full(G_OBJECT(buffer), "enzui-buffer-identity", id, g_free);
    return *id;
}

gpointer enzui_wpe_buffer_export_metadata(WPEBuffer *buffer)
{
    return g_object_get_data(G_OBJECT(buffer), "enzui-export-metadata-v1");
}

void enzui_wpe_buffer_set_export_metadata(WPEBuffer *buffer, gpointer data, GDestroyNotify destroy)
{
    g_object_set_data_full(G_OBJECT(buffer), "enzui-export-metadata-v1", data, destroy);
}
