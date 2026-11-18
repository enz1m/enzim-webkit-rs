#include <wpe/webkit.h>

typedef void (*EnzuiPermissionObserver)(gpointer, gboolean, gboolean);

typedef struct {
    GObject parent;
    EnzuiPermissionObserver observer;
    gpointer owner;
    GDestroyNotify destroy_owner;
    guint timeout;
    guint allows;
    guint denials;
} EnzuiFixturePermissionRequest;

typedef struct {
    GObjectClass parent_class;
} EnzuiFixturePermissionRequestClass;

static void permission_interface_init(WebKitPermissionRequestInterface *interface);

G_DEFINE_TYPE_WITH_CODE(EnzuiFixturePermissionRequest, enzui_fixture_permission_request,
    G_TYPE_OBJECT, G_IMPLEMENT_INTERFACE(WEBKIT_TYPE_PERMISSION_REQUEST, permission_interface_init))

static gboolean source_exists(guint source)
{
    return source && g_main_context_find_source_by_id(g_main_context_default(), source) != NULL;
}

static void complete(WebKitPermissionRequest *request, gboolean allowed)
{
    EnzuiFixturePermissionRequest *fixture = (EnzuiFixturePermissionRequest *)request;
    if (allowed)
        fixture->allows++;
    else
        fixture->denials++;
    if (fixture->observer)
        fixture->observer(fixture->owner, allowed, source_exists(fixture->timeout));
}

static void permission_allow(WebKitPermissionRequest *request)
{
    complete(request, TRUE);
}

static void permission_deny(WebKitPermissionRequest *request)
{
    complete(request, FALSE);
}

static void permission_interface_init(WebKitPermissionRequestInterface *interface)
{
    interface->allow = permission_allow;
    interface->deny = permission_deny;
}

static void finalize(GObject *object)
{
    EnzuiFixturePermissionRequest *fixture = (EnzuiFixturePermissionRequest *)object;
    if (fixture->destroy_owner)
        fixture->destroy_owner(fixture->owner);
    G_OBJECT_CLASS(enzui_fixture_permission_request_parent_class)->finalize(object);
}

static void enzui_fixture_permission_request_class_init(EnzuiFixturePermissionRequestClass *class)
{
    G_OBJECT_CLASS(class)->finalize = finalize;
}

static void enzui_fixture_permission_request_init(EnzuiFixturePermissionRequest *fixture)
{
    (void)fixture;
}

GObject *enzui_permission_fixture_new(EnzuiPermissionObserver observer, gpointer owner, GDestroyNotify destroy_owner)
{
    EnzuiFixturePermissionRequest *fixture = g_object_new(enzui_fixture_permission_request_get_type(), NULL);
    fixture->observer = observer;
    fixture->owner = owner;
    fixture->destroy_owner = destroy_owner;
    g_object_set_data_full(G_OBJECT(fixture), "enzui-permission-requesting-origin-v1", g_strdup("https://frame.example"), g_free);
    g_object_set_data_full(G_OBJECT(fixture), "enzui-permission-top-origin-v1", g_strdup("https://top.example"), g_free);
    return G_OBJECT(fixture);
}

void enzui_permission_fixture_set_timeout(GObject *object, guint timeout)
{
    ((EnzuiFixturePermissionRequest *)object)->timeout = timeout;
}

guint enzui_permission_fixture_count(GObject *object, gboolean allowed)
{
    EnzuiFixturePermissionRequest *fixture = (EnzuiFixturePermissionRequest *)object;
    return allowed ? fixture->allows : fixture->denials;
}

gboolean enzui_permission_fixture_source_exists(guint source)
{
    return source_exists(source);
}
