/*
 * IMSIsting — GTK4 front end for the cellular security toolkit.
 *
 * The GUI is a view over the standalone shell modules in modules/. It is not
 * a container: every action it can take is also a command you can run by hand,
 * and a button here is only a convenience over `modules/NN_name.sh <verb>`.
 *
 * Architecture
 * ------------
 *   ModuleDefinition    one row per module — id, name, category, icon
 *   ModuleSubmenuEntry  one row per page inside a module, each with a builder
 *   module_registry     maps a module id to its entries + its per-module data
 *   AppState            the window, the notebook, the terminal, the drawer
 *
 * A module page is a submenu on the left and a stack of views on the right.
 * A module with no registered entries gets a placeholder that still lists its
 * verbs, so a module added on the shell side is never invisible in the GUI.
 *
 * Every module invocation goes through imsisting_action_run(), which spawns
 * `modules/<id>.sh <verb...>`, optionally prefixed with pkexec, and streams
 * the result into the events drawer. Nothing is spawned on the GTK thread that
 * can block for long: g_subprocess_communicate_utf8_async does the waiting.
 */

#define _GNU_SOURCE
#include <gtk/gtk.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

/* config.h comes first: it carries the build-time answers (HAVE_VTE, the
   project root and version) that the includes below branch on. */
#include "config.h"

#ifdef HAVE_VTE
#include <vte/vte.h>
#endif

/* Orbitron and Neuropol ride in the binary with the icons; fontconfig is how
   this process gets to see them without installing anything system-wide. */
#include <fontconfig/fontconfig.h>

/* The generated module index. tools/gen-module-index.sh rewrites this file;
   it is included rather than linked so the GUI always agrees with the tree. */
#include "module_index.c"

/* The version is NOT compiled in. It is read at runtime from the top-level
   VERSION file, the same file imsisting.sh reads, so the header label and
   `imsisting.sh --version` cannot disagree -- they did: the CLI printed v0.4
   while config.h still carried 0.1.0 from meson.build. See
   imsisting_version_label(). */

/* ==================================================================== */
/*  TYPES                                                               */
/* ==================================================================== */

/* AppState is referenced by the submenu builder signature, so it is
   forward-declared here and defined further down. */
struct _AppState;
typedef struct _AppState AppState;

typedef struct {
    const char *id;
    const char *name;
    const char *category;
    const char *icon;
    const char *desc;
} ModuleDefinition;

/* One CSS accent class per taxonomy group, so the category colour is set in a
   single place and followed by the sidebar, the cards and the module header. */
/* Load a bundled icon, falling back to the system theme.
 *
 * These used to be referenced by icon name, which resolves through the system
 * icon theme - so every tile depended on IMSIsting having installed 56 SVGs
 * into ~/.local/share/icons/hicolor AND on that theme being visible to the
 * app. That is not portable across distros, and where a stale copy WAS
 * installed the stale copy won, so a rebuilt icon set changed nothing on
 * screen. Bundling them in the binary removes the dependency: they ship with
 * the executable and cannot be missing or out of date. The theme lookup stays
 * as a fallback for names that are not ours, like GTK's own
 * window-close-symbolic. */
static GtkWidget *
imsisting_icon_image(const char *name)
{
    if (name != NULL && *name != '\0') {
        g_autofree char *res = g_strdup_printf(
            "/com/imsisting/native/icons/scalable/actions/%s.svg", name);

        if (g_resources_get_info(res, G_RESOURCE_LOOKUP_FLAGS_NONE,
                                 NULL, NULL, NULL))
            return gtk_image_new_from_resource(res);
    }
    return gtk_image_new_from_icon_name(
        (name != NULL && *name != '\0') ? name : "dialog-information-symbolic");
}

/* The drawing the tool is named after, sized for the header.
 *
 * The asset is authored with transparency, so normally this is just the
 * resource at a size. The fallback matters because the first version of this
 * file was glow-on-black with NO alpha channel - drawn for the splash, where
 * it is composited additively, so black cost nothing there. Dropped into the
 * header unchanged that version would be a black tile with a blue smudge in
 * it. For a format with no alpha channel the key is therefore taken from the
 * pixels: alpha becomes the brightest channel, which makes the black
 * transparent and leaves the glow its colour. Every channel is then <= alpha,
 * so the result is valid premultiplied data. */
static gboolean
memory_format_alpha_at(GdkMemoryFormat fmt, int *off_r, int *off_g, int *off_b,
                       int *bpp)
{
    int r = 0, g = 0, b = 0, n = 0;
    gboolean has;

    switch (fmt) {
    case GDK_MEMORY_B8G8R8A8:
    case GDK_MEMORY_B8G8R8A8_PREMULTIPLIED:
        r = 2; g = 1; b = 0; n = 4; has = TRUE; break;
    case GDK_MEMORY_R8G8B8A8:
    case GDK_MEMORY_R8G8B8A8_PREMULTIPLIED:
        r = 0; g = 1; b = 2; n = 4; has = TRUE; break;
    case GDK_MEMORY_A8R8G8B8:
    case GDK_MEMORY_A8R8G8B8_PREMULTIPLIED:
        r = 1; g = 2; b = 3; n = 4; has = TRUE; break;
    case GDK_MEMORY_A8B8G8R8:
    case GDK_MEMORY_A8B8G8R8_PREMULTIPLIED:
        r = 0; g = 1; b = 2; n = 4; has = TRUE; break;
    default:
        has = FALSE; break;
    }

    /* Callers that only want the verdict pass NULLs, so every write is
       conditional: this is a predicate as often as it is an accessor. */
    if (off_r != NULL) *off_r = r;
    if (off_g != NULL) *off_g = g;
    if (off_b != NULL) *off_b = b;
    if (bpp   != NULL) *bpp   = n;
    return has;
}

static gboolean
memory_format_rgb(GdkMemoryFormat fmt, int *off_r, int *off_g, int *off_b)
{
    switch (fmt) {
    case GDK_MEMORY_B8G8R8:
        *off_r = 2; *off_g = 1; *off_b = 0; return TRUE;
    case GDK_MEMORY_R8G8B8:
        *off_r = 0; *off_g = 1; *off_b = 2; return TRUE;
    default:
        return FALSE;
    }
}

static GtkWidget *
imsisting_logo_image(int size)
{
    const char *res = "/com/imsisting/native/imsisting_logo.png";
    g_autoptr(GdkTexture) tex = NULL;
    g_autofree guchar *px = NULL;
    GdkMemoryFormat fmt, out_fmt;
    GdkTexture *keyed;
    GtkWidget *image;
    int w, h, off_r, off_g, off_b, bpp;
    gsize stride, len;

    if (!g_resources_get_info(res, G_RESOURCE_LOOKUP_FLAGS_NONE,
                              NULL, NULL, NULL))
        return gtk_image_new();

    tex = gdk_texture_new_from_resource(res);
    if (tex == NULL)
        return gtk_image_new();

    fmt = gdk_texture_get_format(tex);
    if (memory_format_alpha_at(fmt, NULL, NULL, NULL, NULL)) {
        /* Nothing to key: hand the resource straight to the image. */
        image = gtk_image_new_from_resource(res);
        gtk_image_set_pixel_size(GTK_IMAGE(image), size);
        return image;
    }

    if (!memory_format_rgb(fmt, &off_r, &off_g, &off_b))
        return gtk_image_new();

    w = gdk_texture_get_width(tex);
    h = gdk_texture_get_height(tex);
    stride = (gsize) w * 3;
    len = stride * (gsize) h;
    px = g_malloc(len);
    gdk_texture_download(tex, px, stride);

    {
        gsize out_len = (gsize) w * 4 * (gsize) h;
        guchar *out = g_malloc(out_len);

        for (gsize i = 0, o = 0; i + 2 < len; i += 3, o += 4) {
            guchar r = px[i + off_r], g = px[i + off_g], b = px[i + off_b];
            out[o]     = r;
            out[o + 1] = g;
            out[o + 2] = b;
            out[o + 3] = MAX(r, MAX(g, b));
        }
        out_fmt = (off_r == 0) ? GDK_MEMORY_R8G8B8A8_PREMULTIPLIED
                               : GDK_MEMORY_B8G8R8A8_PREMULTIPLIED;
        keyed = gdk_memory_texture_new(w, h, out_fmt,
                                       g_bytes_new_take(out, out_len),
                                       (gsize) w * 4);
    }

    image = gtk_image_new_from_paintable(GDK_PAINTABLE(keyed));
    g_object_unref(keyed);
    gtk_image_set_pixel_size(GTK_IMAGE(image), size);
    return image;
}

static const char *
category_class(const char *cat)
{
    if (cat == NULL) return "cat-system";
    if (g_strcmp0(cat, "RECON") == 0)               return "cat-recon";
    if (g_strcmp0(cat, "RADIO") == 0)               return "cat-radio";
    if (g_strcmp0(cat, "ACCESS") == 0)              return "cat-access";
    if (g_strcmp0(cat, "CORE NETWORK") == 0)        return "cat-core";
    if (g_strcmp0(cat, "SIM / IDENTITY") == 0)      return "cat-sim";
    if (g_strcmp0(cat, "BASEBAND / DEVICE") == 0)   return "cat-baseband";
    if (g_strcmp0(cat, "TRACKING") == 0)            return "cat-tracking";
    if (g_strcmp0(cat, "ANALYSIS") == 0)            return "cat-analysis";
    if (g_strcmp0(cat, "EXPLOIT KITS") == 0)        return "cat-kits";
    if (g_strcmp0(cat, "INTERCEPT / CARRIER") == 0) return "cat-intercept";
    return "cat-system";
}

/* Module icons resolve by name from the hicolor theme: the symbolic SVGs in
   native/resources/icons/symbolic are installed there by the launcher and
   looked up as "imsisting-<id>-symbolic". The accessors below are the single
   place that maps a module id to its icon/name, the way wifisting does. */

typedef struct {
    const char *name;
    const char *icon;
    /* The buttons a submenu holds, as "verb[:Label][!]" entries separated by
       '|'.  ! = needs root. A leading '~' marks a verb that needs an argument,
       which is kept on the command line rather than put behind a button.
       Sections may be named with a leading '#': "#CONTROLS|--a|#STATUS|--b".
       Ignored when `build` is set. */
    const char *spec;
    /* Optional module-specific view, used when a view is a LIST with per-row
       actions rather than a row of buttons - Cell Recon's surveyed cells, the
       way wifisting's Targets view works. Signature mirrors
       build_group_view() so it can produce the same output card. */
    GtkWidget *(*build)(struct _AppState *state, const char *module_id,
                        GtkWidget *status, GtkTextBuffer *out);
} ModuleSubmenuEntry;

/* One row in a module's left-hand menu, in display order. The registered
   entries are wrapped with an Overview at the top and the full command list at
   the bottom, so every module's menu reads the same way. */
typedef struct {
    const char *name;
    const char *icon;
    GtkWidget *page;
} ModuleView;

/* One file in the evidence index. The whole index is rebuilt from disk on
   every refresh, so an entry never outlives the scan that produced it. */
typedef struct {
    char   *path;      /* absolute */
    char   *name;      /* basename - the thing the user searches for */
    char   *module;    /* the loot/ subdirectory it came from */
    guint64 size;
    gint64  mtime;
} LootEntry;

/* Defined with the Overview cards further down, but called from
   casebook_refresh() above them. */
static GtkWidget *casebook_card(const char *title, GtkWidget **body_out);
static void casebook_kv_fill(GtkWidget *body, const char *tsv, const char *empty_msg);
static void casebook_counts_fill(GtkWidget *body, const char *tsv);

typedef struct {
    AppState *state;
    const ModuleDefinition *module;
    GtkWidget *page;
    GtkWidget *submenu_list;
    GtkWidget *stack;
    GtkWidget *header_box;
    GtkWidget *status_pill;
    gpointer module_data;
    ModuleView *views;
    int n_views;
} ModulePage;

/* How many signal samples the target panel's spark keeps. At the live feed's
   frame rate this is a few minutes of history, which is the window in which
   moving an antenna or a hand changes what you see. */
#define RTARGET_SPARK 96

struct _AppState {
    GtkApplication *application;
    GtkWidget *window;
    GtkWidget *sidebar;
    GtkWidget *notebook;
    GtkWidget *event_drawer;
    GtkWidget *event_revealer;
    GtkTextBuffer *event_buffer;
    GtkWidget *toast_box;

    /* The last notifications, newest first. A toast is an announcement, not a
       record: it slides away in a few seconds, and only five share the corner
       at once. Everything that toasts is also written here, and the
       Notifications page is what reads it. */
    GQueue    *notifs;
    GtkWidget *notif_list;
    GtkWidget *notif_summary;

    /* Diagnostics: stderr is redirected here and polled into the drawer. */
    int stderr_fd;
    off_t stderr_pos;

    GPtrArray *running;

    /* Permanent-tab and status-strip widgets. */
    GtkWidget *sidebar_revealer;

    /* The page panel. Everything that is not the dashboard is shown here,
       floating over it, rather than replacing it. */
    GtkWidget *sheet;
    GtkWidget *sheet_scrim;

    /* The header's search field and the result list it opens under itself. */
    GtkWidget *header_search;
    GtkWidget *palette;
    GtkWidget *palette_list;
    GtkWidget *sidebar_search;
    /* The six permanent pages as a list at the top of the drawer. Held so
       the highlight can follow the notebook instead of being rebuilt. */
    GtkWidget *drawer_nav;
    GtkWidget *drawer_nav_rows[7];
    gboolean   drawer_nav_syncing;
    GtkWidget *status_sdr, *status_tx, *status_cells, *status_gps, *status_freq;
    /* The strip's own heartbeat. Without it the chips look equally certain
       whether the radio answered a second ago or the poll died an hour ago -
       which is the one lie a status strip must not tell. */
    GtkWidget *status_fresh;
    gint64     status_seen_us;
    /* Live station band on the dashboard: case-scoped facts the status strip
       does not carry (case, targets, evidence, alerts). */
    GtkWidget *dash_case, *dash_targets, *dash_evidence, *dash_alerts;
    /* Dashboard grid handle + the pin/recent sets behind the card cues. */
    GtkWidget *dash_flow, *dash_search;
    GtkWidget *dash_empty;   /* shown when a search matches nothing */
    GtkWidget *dash_mission; /* the "Start here" panel, hidden while searching */
    GHashTable *pins, *recent;
    /* Persisted personalisation. `recent_counts` is module id -> number of
       runs, which is what "Most used" orders by; `density` is the tile
       density class kept on the window from launch to launch. */
    GHashTable *recent_counts;
    /* Drawer "recent places": module ids most-recent-first, and the list box
       they are rendered into. Session-scoped — the persisted counts above
       answer "what do I use", this answers "what was I just in". */
    GPtrArray *recent_mru;
    /* A view to select once the page that owns it has been built. The recent
       list can name a submenu, and the module page does not exist yet when
       the row is pressed, so the wish waits here for one build. */
    char      *pending_view;
    GtkWidget *drawer_recent_box;
    char       *density;
    GtkWidget *loot_list;
    GtkWidget *loot_search;
    GtkWidget *loot_sort;
    GtkWidget *loot_count_lbl;
    GPtrArray *loot_entries;   /* of LootEntry, the sorted index */
    int        loot_sort_mode; /* 0 name, 1 size, 2 newest, 3 module */

    /* The Stats tiles' value labels. The counts they show describe a
       filesystem that modules keep writing to while the app runs, so they are
       recomputed when the tab is opened rather than frozen at startup. */
    GtkWidget *stat_selftests, *stat_loot_dirs, *stat_loot_files, *stat_offline;
    guint      status_source;

    /* Sidebar active state. Each category is its own GtkListBox, so selection
       is per-list and "which module is open" cannot be read off the widgets.
       One id is the source of truth; sidebar_set_active() paints it. */
    GHashTable *sidebar_rows;          /* module id -> GtkListBoxRow */
    /* The box that actually holds the category expanders. NOT
       gtk_scrolled_window_get_child(sidebar): GtkScrolledWindow inserts a
       GtkViewport of its own, so that returns the viewport and every walk of
       "the children" finds one GtkBox instead of the expanders. */
    GtkWidget  *sidebar_content;
    char       *active_module_id;      /* NULL while a permanent tab is shown */
    guint       sidebar_scroll_idle;   /* pending scroll-into-view */
    guint       sidebar_scroll_tries;  /* passes spent waiting for layout */

    /* Live GSMTAP feed. */
    GtkWidget     *live_view;          /* the GtkColumnView */
    GtkWidget     *live_status;
    GtkWidget     *live_button;
    GtkWidget     *live_filter_entry;
    GtkWidget     *live_summary;       /* count / rate chip */
    GtkWidget     *live_empty;         /* empty-state box */
    GtkTextBuffer *live_inspector_buf; /* full detail for the selected row */
    GtkWidget     *live_pause_button;
    GtkWidget     *live_scroll;        /* scroller, for Follow */
    gboolean       live_follow;
    GSocket       *live_socket;
    GListStore    *live_store;         /* what the view shows */
    GPtrArray     *live_msgs;          /* retained, filtered into the store */
    char          *live_filter;
    guint          live_poll;          /* timer that drains the socket */
    guint          live_count;
    guint          live_hint;
    gboolean       live_paused;
    gboolean       live_announced;  /* the user started the feed, not the page */
    /* Operational state for the feed: how fast it is arriving, and when
       anything last did. A cumulative count alone cannot distinguish a live
       emitter from one that died an hour ago. */
    guint          live_rate;          /* datagrams in the last whole second */
    guint          live_rate_prev;     /* live_count at the previous tick */
    gint64         live_last_us;       /* monotonic time of the last datagram */
    guint          live_rate_timer;
    guint          live_follow_idle;   /* pending coalesced follow-scroll */

    /* Writing the feed to disk. The listener already receives every datagram,
       so the capture is written from the same bytes the table was built from
       rather than from a second process competing for the port. */
    FILE          *live_pcap;
    char          *live_pcap_path;
    guint64        live_pcap_packets;
    guint64        live_pcap_bytes;
    guint          live_pcap_rotate_s;   /* 0 = one file for the whole run */
    guint          live_pcap_rotate_id;
    gint64         live_pcap_opened_us;
    gint64         live_pcap_flushed_us;
    gboolean       live_pcap_failed;     /* reported once, not once per packet */
    GtkWidget     *live_save_check;
    GtkWidget     *live_path_entry;
    GtkWidget     *live_rotate_spin;
    GtkWidget     *live_capture_label;   /* file name and size read-out */

    /* The listener's port is a field, not a constant: a second instance, a
       different emitter, or a forward from another host all need it. */
    guint          live_port;
    GtkWidget     *live_port_entry;
    GtkWidget     *live_port_label;

    /* Filters that read the decoded header rather than the payload text. */
    gboolean       live_show_ul;
    gboolean       live_show_dl;
    gint           live_min_dbm;         /* 0 = off, else hide anything weaker */
    gint           live_filter_arfcn;    /* -1 = any */
    gint           live_filter_channel;  /* -1 = any, else the GSMTAP channel code */
    GtkWidget     *live_ul_toggle;
    GtkWidget     *live_dl_toggle;
    GtkWidget     *live_dbm_spin;
    GtkWidget     *live_arfcn_entry;
    GtkWidget     *live_channel_drop;

    /* Event drawer chrome. */
    GtkWidget     *event_filter_entry;
    GtkWidget     *event_badge;
    GtkWidget     *event_button;
    gboolean       event_autoscroll;
    gboolean       event_errors_only;
    guint          event_errors;

    /* Casebook workspace. */
    GtkWidget     *casebook_tabs;        /* the inner notebook */
    guint          casebook_filled;      /* bit per tab: filled at least once */
    /* The radio's status, probed while the splash is still up. The first
       --status-tsv walks six drivers and costs about two seconds; started
       before the interface is built, it overlaps that work instead of
       following it. */
    char          *radio_prefetch;
    GPid           radio_prefetch_pid;
    int            radio_prefetch_fd;
    GtkWidget     *casebook_case_body;   /* Overview cards */
    GtkWidget     *casebook_target_body;
    GtkWidget     *casebook_counts_body;
    GtkTextBuffer *casebook_overview;   /* Overview still a dump; converted next */
    /* Records, not text: these were monospace TSV dumps, which is what made
       the Casebook tabs look like a terminal sitting in the window. */
    GtkWidget *casebook_captures_list;
    GtkWidget *casebook_timeline_list;
    GtkWidget *casebook_alerts_list;
    GtkWidget *casebook_nodes_list;
    GtkWidget *casebook_reports_list;
    GtkWidget *casebook_brief_case, *casebook_brief_target;
    GtkWidget *casebook_brief_evidence, *casebook_brief_alerts;
    GtkWidget *casebook_brief_scope, *casebook_brief_auth, *casebook_brief_alert;
    GtkWidget *case_name_entry, *case_scope_entry, *case_auth_entry;
    GtkWidget *case_select_entry;
    /* The radio target, reachable from every page through the header. Kept
       apart from the Casebook target_*_entry widgets above: those describe a
       case, this one is what the cellular modules tune to. */
    GtkWidget *rtarget_revealer, *rtarget_button, *rtarget_state_lbl;
    GtkWidget *rtarget_rat, *rtarget_arfcn, *rtarget_plmn, *rtarget_cell;
    /* What the panel shows back: the mark says what generation the target is
       and whether its traffic is ciphered, the four identity rows say which
       cell it is, the spark plots the signal of the live feed, and the times
       say how long it has been held. All of them are filled by
       rtarget_panel_refresh() so there is one place that decides what the
       panel means. */
    GtkWidget *rtarget_mark, *rtarget_mark_rat, *rtarget_mark_gen;
    GtkWidget *rtarget_mark_rat_owner;
    GtkWidget *rtarget_mark_lock, *rtarget_mark_lock_lbl;
    GtkWidget *rtarget_id_plmn, *rtarget_id_cell, *rtarget_id_chan, *rtarget_id_band;
    GtkWidget *rtarget_sig_now, *rtarget_sig_range, *rtarget_sig_state;
    GtkWidget *rtarget_spark_area;
    GtkWidget *rtarget_bars;
    GtkWidget *rtarget_held, *rtarget_seen, *rtarget_editor;
    double rtarget_spark[RTARGET_SPARK];
    int    rtarget_spark_n;
    GtkWidget *node_name_entry, *node_host_entry, *node_transport_entry;

    /* Output buffer of the module page on screen, or NULL on a non-module
       tab. A run started while a module page is visible writes into it, so
       the result shows next to the button that was pressed. Held with a
       ref: a run in flight can outlive the page it started from. */
    GtkTextBuffer *active_output;

    /* The splash owns the application's only window for the second or so
       between process start and the main window, which is what makes it
       possible to report the boot instead of hiding it. Everything here is
       NULL or zero once the main window is up. */
    GtkApplication *splash_app;
    GtkWidget      *splash_window;
    GtkWidget      *splash_area;
    cairo_surface_t *splash_art;      /* the two PNGs, decoded once */
    cairo_surface_t *splash_logo;
    cairo_surface_t *splash_bg;       /* art + shade + gradient, composed once */
    int              splash_bg_w, splash_bg_h;
    guint           splash_source;    /* the tick that drives the stages */
    guint           splash_step;      /* stages completed so far */
    const char     *splash_label;     /* the stage being run, or NULL */
    gint64          splash_stage_us;  /* when the last one was started */
    double          splash_shown;     /* the bar's position, 0.0 .. 1.0 */
    gboolean        splash_video;     /* this launch plays the film, not the art */
    GtkMediaStream *splash_media;     /* the film, polled for "has it ended" */
    gint64          splash_film_us;   /* when the film started playing */
    gint64          splash_start_us;  /* when the splash first appeared */
};

/* A run that has ended, handed to whoever asked to be told. `text` is the
   module's own output and nothing the interface added around it: a card that
   shows a result shows what the module said, not the shell line that asked. */
typedef void (*ActionDoneFn)(const char *text, gboolean ok, int status,
                             gpointer user_data);

typedef struct {
    AppState *state;
    char *module_id;
    char *label;
    GtkWidget *status_label;
    GSubprocess *proc;
    GDataInputStream *out;
    GDataInputStream *err;
    GString *captured;      /* stdout + stderr, for the ERROR scan */
    gboolean saw_error;
    int refs;               /* two pipe readers + one waiter */
    GtkTextBuffer *output;  /* page output card to echo into, or NULL */
    char *last_announced;   /* the previous line that earned a toast */
    guint announced;        /* how many this run has spent */
    ActionDoneFn done;      /* told when the run ends, or NULL */
    GObject *done_owner;    /* held open until then, so the callback is safe */
    gboolean wait_ok;       /* how the process itself ended */
    int wait_status;
    gboolean reported;      /* the callback has run */
    gboolean stopped;       /* the operator cancelled it, so it is not a fault */
} ActionRun;

/* The answer surface a card owns: where the records a run prints land, the one
   line that says how many there are, and the Stop that belongs to whatever is
   running there. Declared here because the card builders below name it. */
#define RESULT_MAX_ROWS 400

typedef struct {
    GtkWidget *rect;
    GtkWidget *rows;      /* where the run's records land */
    GtkWidget *idle;      /* the one-line invitation, before the first run */
    GtkWidget *stop;      /* cancels the run this surface started */
    GtkWidget *summary;   /* "3 records  ·  done (exit 0)" */
    GtkTextBuffer *buf;   /* what the run writes into */
} ResultRect;

static void result_begin(AppState *state, ResultRect *rr);
static gint result_rows_count(ResultRect *rr);
static void result_compact(ResultRect *rr, const char *receipt);
static gboolean run_receipt(ActionRun *run, char **out);
static GtkWidget *result_rect_new(AppState *state, ResultRect **out);
static void result_end(ResultRect *rr);

/* Which pipe a read callback belongs to. */
typedef struct {
    ActionRun *run;
    gboolean is_err;
} ActionStream;

/* ==================================================================== */
/*  MODULE TABLE                                                        */
/* ==================================================================== */

/* Category names here also drive the sidebar grouping. Keep the order: the
   sidebar renders in table order, so this table is the menu. */
/* Grouped by what a module does, not by radio generation: setup, survey, air
   interface, core, subscription, offence, analysis, RF. The Kernel keeps
   categories contiguous so the sidebar and the CLI group cleanly, and each
   module carries a one-line description shown under its title. */
static const ModuleDefinition modules[] = {
    /* SYSTEM — setup, radio and automation */
    { "00_deps",             "Dependency Manager",   "SYSTEM",
      "imsisting-00_deps-symbolic",
      "Checks the cellular toolchain against a per-distro table and installs what is missing." },
    { "01_radio",            "SDR / Radio Manager",  "SYSTEM",
      "imsisting-01_radio-symbolic",
      "Enumerates SDRs, reports driver, serial and range, and flags receive-only devices." },
    { "05_field_kit",        "Field Kit",            "SYSTEM",
      "imsisting-05_field_kit-symbolic",
      "RF pre-flight, honesty verification of every radio verb, and a synthetic GSMTAP source." },
    { "25_killchain",        "Cellular Killchain",   "SYSTEM",
      "imsisting-25_killchain-symbolic",
      "Chains module verbs into repeatable runs from a TSV chain file." },

    /* RECON — passive survey of the RF environment: no target, no identity */
    { "02_cell_recon",       "Cell Recon",           "RECON",
      "imsisting-02_cell_recon-symbolic",
      "ARFCN/EARFCN/NR-ARFCN to frequency, PLMN to operator, and a cell survey from an SDR or capture." },
    { "03_gsmtap",           "GSMTAP Live Feed",       "RECON",
      "imsisting-03_gsmtap-symbolic",
      "GSMTAP header codec and pcap I/O; listens for gr-gsm and srsRAN traffic." },
    { "04_tower_map",        "Tower Survey",         "RECON",
      "imsisting-04_tower_map-symbolic",
      "GPS-tagged cell survey with CSV, KML and GeoJSON export." },

    /* RADIO — the air interface per RAT, plus radio-layer attacks and RF effects */
    { "06_gsm_air",          "GSM Air Interface",    "RADIO",
      "imsisting-06_gsm_air-symbolic",
      "GSM system information, paging, cipher audit and A5/1 keystream, proved against the BGW vector." },
    { "07_gsm_attack",       "GSM Attack",           "RADIO",
      "imsisting-07_gsm_attack-symbolic",
      "IMSI-catcher sequence, A5/1 downgrade, TMSI de-anonymisation and Kc recovery." },
    { "08_umts_air",         "UMTS Air Interface",   "RADIO",
      "imsisting-08_umts_air-symbolic",
      "UMTS UARFCN, SIB decode, RRC integrity (UIA1/UIA2) and the AKA relay flow." },
    { "10_lte_air",          "LTE Air Interface",    "RADIO",
      "imsisting-10_lte_air-symbolic",
      "LTE EARFCN, RRC/SIB decode, paging maths and srsRAN eNB orchestration." },
    { "12_nr_air",           "5G NR Air Interface",  "RADIO",
      "imsisting-12_nr_air-symbolic",
      "NR-ARFCN, MIB/SIB1 decode, PCI, PRACH occasions and gNB config generation." },
    { "15_downgrade",        "Downgrade Attacks",    "RADIO",
      "imsisting-15_downgrade-symbolic",
      "Reject causes, null-cipher tables, Security Mode Command and downgrade detection." },
    { "45_iot",              "NB-IoT / Cat-M1",      "RADIO",
      "imsisting-45_iot-symbolic",
      "NB-IoT and Cat-M1: NPRACH, NPSS/NSSS, SIB1-NB and NPRFCN." },
    { "50_gprs",             "GPRS / EDGE",          "RADIO",
      "imsisting-50_gprs-symbolic",
      "GPRS/EDGE packet-switched: GEA ciphering, APN coding, PDP context and downgrade detection." },
    { "51_sidelink",         "NR Sidelink / V2X",    "RADIO",
      "imsisting-51_sidelink-symbolic",
      "NR sidelink on PC5: resource pools, SCI-1A, ITS certificates and relay checks." },
    { "49_ntn",              "5G NTN / Satellite",   "RADIO",
      "imsisting-49_ntn-symbolic",
      "Non-terrestrial access: Doppler, round-trip delay, TA, k_offset and the SIB19 fields." },
    { "53_non3gpp",          "TETRA / DMR / GSM-R",  "RADIO",
      "imsisting-53_non3gpp-symbolic",
      "Non-3GPP land mobile radio: TETRA, DMR and GSM-R structure, ciphers and band classification." },
    /* The name carried "Detection" from the revision when detection was the
       whole module. Phase 9 built the transmit half behind the lab gate, so the
       name has to say the module does both -- the same rule this file already
       applies to 35_baseband, 42_li_probe, 44_carrier_api and 31_sim_defense:
       a name that describes half the module is a name that lies about the
       other half, and the gate is described in the page, not in the title. */
    { "33_jamming_detect",   "Jamming Detect & Effect", "RADIO",
      "imsisting-33_jamming_detect-symbolic",
      "Detection and measurement are the authority: jamming told apart from congestion and a coverage hole. Behind an explicit lab gate it also constructs the waveform." },

    /* ACCESS — attach, registration and the access-network edge */
    { "09_lte_attach",       "LTE Attach Forge",     "ACCESS",
      "imsisting-09_lte_attach-symbolic",
      "NAS EMM/ESM encode-decode, BCD IMSI/IMEI, attach forge and identity-exposure detection." },
    { "34_slicing",          "Slicing Escape",      "ACCESS",
      "imsisting-34_slicing-symbolic",
      "S-NSSAI encode-decode, slice selection and cross-slice isolation testing." },
    { "36_vowifi",           "VoWiFi / ePDG Attacks",        "ACCESS",
      "imsisting-36_vowifi-symbolic",
      "IKEv2 over SWu, EAP-AKA, the SWu NAI and an encryption/integrity transform audit." },
    { "37_femtocell",        "Small Cell / eNB Attacks",     "ACCESS",
      "imsisting-37_femtocell-symbolic",
      "Small-cell and eNB assessment: CSG/PCI conflicts, the S1 backhaul, Iuh legacy and a TR-069 management audit." },
    { "38_ussd",             "USSD Forge",                 "ACCESS",
      "imsisting-38_ussd-symbolic",
      "USSD/MMI parsing, 7-bit packing and USSD/STK injection detection." },
    { "43_ran_share",        "RAN Sharing",          "ACCESS",
      "imsisting-43_ran_share-symbolic",
      "PLMN coding, MOCN/MORAN/GWCN classification and cross-operator leakage detection." },
    { "47_wifioff",          "Wi-Fi Offload / LWA",  "ACCESS",
      "imsisting-47_wifioff-symbolic",
      "Wi-Fi offload and LWA: ePDG FQDN, certificate validation and LWA configuration." },

    /* CORE NETWORK — the network behind the RAN, and the interconnect */
    { "11_lte_core",         "LTE Core (EPC)",       "CORE NETWORK",
      "imsisting-11_lte_core-symbolic",
      "Diameter S6a/S6d, GTP-C/GTP-U and S1AP; decodes the EPC core and forges registration moves." },
    { "13_nr_core",          "5G Core (SBA)",        "CORE NETWORK",
      "imsisting-13_nr_core-symbolic",
      "5G SBA: NGAP, 5GS NAS, 5G-GUTI, PFCP rules and 5G-AKA." },
    { "26_ss7_map",          "SS7 / MAP Attacks",    "CORE NETWORK",
      "imsisting-26_ss7_map-symbolic",
      "MTP3/SCCP/TCAP/MAP decode and forge, M3UA framing both ways and GRX reachability." },
    { "27_cellular_dns",     "Cellular DNS Spoof",    "CORE NETWORK",
      "imsisting-27_cellular_dns-symbolic",
      "DNS encode-decode, the aLTEr redirection sequence and response-tampering detection." },
    { "30_volte_ims",        "VoLTE / IMS Attacks",  "CORE NETWORK",
      "imsisting-30_volte_ims-symbolic",
      "VoLTE keystream reuse (ReVoLTE), IMP4GT identity mapping and SIP/IMS analysis." },
    /* The description has to name both halves, for the reason Phase 12 wrote
       down: a name or a subtitle that describes half the module lies about the
       other half. Measurement is still the authority; the builders emit the
       messages an MME sends before it has authenticated anybody, and never send
       them. */
    { "32_nas_signaling",    "NAS Signalling",       "CORE NETWORK",
      "imsisting-32_nas_signaling-symbolic",
      "Rate, procedure mix and storm detection over captures -- plus the pre-authentication messages (reject, identity, auth, security mode) built as octets and never sent." },
    { "40_sba_pivot",        "5G SBA Pivot",         "CORE NETWORK",
      "imsisting-40_sba_pivot-symbolic",
      "HTTP/2 SBI framing, NRF discovery and OAuth2 token audit." },
    { "48_oran",             "O-RAN / xApp Attacks",     "CORE NETWORK",
      "imsisting-48_oran-symbolic",
      "O-RAN interfaces, deployment assessment and xApp-authority modelling." },

    /* SIM / IDENTITY — the subscription, the card and the subscriber identity */
    { "14_suci",             "SUCI Deconcealment",          "SIM / IDENTITY",
      "imsisting-14_suci-symbolic",
      "SUCI conceal/deconceal (ECIES profile A/B), HKDF and the null-scheme audit." },
    { "16_sim",              "SIM / eSIM / OTA Attacks",     "SIM / IDENTITY",
      "imsisting-16_sim-symbolic",
      "ISO-7816 APDU, USIM files, EF_AD in both layouts, OTA parsing and eSIM profiles." },
    { "18_imsi_exposure",    "IMSI Harvest",         "SIM / IDENTITY",
      "imsisting-18_imsi_exposure-symbolic",
      "Identity harvesting, TMSI/GUTI to IMSI correlation and per-subscriber exposure scoring." },
    { "31_sim_defense",      "SIM Swap Attack/Defence",     "SIM / IDENTITY",
      "imsisting-31_sim_defense-symbolic",
      "Detection and defence for a SIM port in flight, plus eSIM profile integrity." },
    { "41_ota_sms",          "OTA Binary SMS Attacks",       "SIM / IDENTITY",
      "imsisting-41_ota_sms-symbolic",
      "TS 23.048 OTA command-packet construction with an SPI/counter/key audit. Own-SIM and lab." },
    { "52_stk",              "STK Attacks",    "SIM / IDENTITY",
      "imsisting-52_stk-symbolic",
      "TS 31.111 proactive commands: build, parse and audit for silent off-device actions." },

    /* BASEBAND / DEVICE — below the stack and at the handset */
    { "35_baseband",         "Baseband Fuzzing",    "BASEBAND / DEVICE",
      "imsisting-35_baseband-symbolic",
      "Baseband research scaffolding: ASN.1 mutation, corpus generation and crash triage." },
    { "54_baseband_exploit", "Baseband Exploits",    "BASEBAND / DEVICE",
      "imsisting-54_baseband_exploit-symbolic",
      "L1/L2 malformed-PDU construction, 5G control-plane forgery, and the baseband CVE catalogue." },
    { "55_nr_inject",        "5G NR Injection",      "BASEBAND / DEVICE",
      "imsisting-55_nr_inject-symbolic",
      "NR RNTI tracking, MAC-NR framing, descrambling and the injection exploit set." },
    { "56_baseband_diag",    "Baseband NV/EFS",      "BASEBAND / DEVICE",
      "imsisting-56_baseband_diag-symbolic",
      "Qualcomm DM/DIAG framing, NV and EFS2 codecs, state-info identity decode and the AT/device surface." },

    /* TRACKING — locating and following a subscriber or a transmitter */
    { "24_rf_fingerprint",   "RF Fingerprint / CSI", "TRACKING",
      "imsisting-24_rf_fingerprint-symbolic",
      "IQ fingerprinting (CFO, IRR, transients) and CSI side-channel extraction." },
    { "28_paging_track",     "Paging / Torpedo",     "TRACKING",
      "imsisting-28_paging_track-symbolic",
      "Paging occasion maths, paging capture, and the Torpedo/Piercer models." },
    { "39_ta_geoloc",        "TA Geolocation",       "TRACKING",
      "imsisting-39_ta_geoloc-symbolic",
      "Timing-advance ranging and multi-cell trilateration from TA measurements." },
    { "46_lpp",              "LPP Position Forgery",      "TRACKING",
      "imsisting-46_lpp-symbolic",
      "LTE Positioning Protocol: procedure codes, header codec and position-forgery detection." },

    /* ANALYSIS — offline work on captures and logs */
    { "17_pcap_analysis",    "Capture Analysis",     "ANALYSIS",
      "imsisting-17_pcap_analysis-symbolic",
      "From-scratch pcap reader that dissects GSMTAP, Diameter, NGAP, S1AP, GTP, PFCP and RTP." },
    { "19_cipher_audit",     "Cipher Audit",         "ANALYSIS",
      "imsisting-19_cipher_audit-symbolic",
      "Scores negotiated ciphers per session across 2G-5G and finds null or downgraded bearers." },
    { "23_traffic_analysis", "Traffic Analysis",     "ANALYSIS",
      "imsisting-23_traffic_analysis-symbolic",
      "Flow and burst analysis, website fingerprinting and padding/shaping detection." },
    { "29_mac_layer",        "MAC / RLC Analysis",            "ANALYSIS",
      "imsisting-29_mac_layer-symbolic",
      "LTE MAC PDU decode, RNTI tracking, scheduling-pattern inference and DCI/MCS mapping." },

    /* EXPLOIT KITS — probe-or-handoff CVE kits */
    { "20_gsm_cve",          "GSM/UMTS CVE Kit",     "EXPLOIT KITS",
      "imsisting-20_gsm_cve-symbolic",
      "Per-CVE probes and handoffs for 2G/3G stack bugs." },
    { "21_lte_cve",          "LTE CVE Kit",          "EXPLOIT KITS",
      "imsisting-21_lte_cve-symbolic",
      "LTE stack CVEs: baseband, NAS, ASN.1 and Diameter." },
    { "22_nr_cve",           "5G CVE Kit",           "EXPLOIT KITS",
      "imsisting-22_nr_cve-symbolic",
      "5G NR, SBA and SUCI CVEs." },

    /* INTERCEPT / CARRIER — lawful intercept and carrier-side interfaces */
    { "42_li_probe",         "LI Interception",         "INTERCEPT / CARRIER",
      "imsisting-42_li_probe-symbolic",
      "Lawful-interception interfaces and interception-posture signals. Detection only." },
    { "44_carrier_api",      "Carrier API Abuse",    "INTERCEPT / CARRIER",
      "imsisting-44_carrier_api-symbolic",
      "Carrier API surface, authorisation-boundary testing and token/rate-limit audit." }

};

static const char *
module_icon_for(const char *module_id)
{
    for (guint i = 0; i < G_N_ELEMENTS(modules); i++)
        if (g_strcmp0(modules[i].id, module_id) == 0)
            return modules[i].icon;
    return "dialog-information-symbolic";
}

static const char *
module_name_for(const char *module_id)
{
    for (guint i = 0; i < G_N_ELEMENTS(modules); i++)
        if (g_strcmp0(modules[i].id, module_id) == 0)
            return modules[i].name;
    return (module_id && *module_id) ? module_id : "imsisting";
}

#define N_MODULES ((int) G_N_ELEMENTS(modules))

/* ==================================================================== */
/*  FORWARD DECLARATIONS                                                */
/* ==================================================================== */

static void append_event(AppState *state, const char *message);
static void recents_bump(AppState *state, const char *module_id);
static void drawer_recent_push(AppState *state, const char *key);
/* A place is "<owner>|<view>" - a module or permanent page and the view that
   was on screen inside it. Defined with the recent list, called from the
   module page as soon as a view is opened. */
static void place_push_view(AppState *state, const char *owner,
                            const char *view);
/* Defined with the Settings page, which owns the only permanent page with
   sub-views; the recent list can send the operator straight to one. */
static void settings_show_view(AppState *state, const char *name);
static void drawer_recent_refresh(AppState *state);
static guint recent_count_of(int idx);
static void live_inspector_reset(AppState *state);
static guint live_shown_count(AppState *state);
static gboolean live_follow_idle(gpointer user_data);
/* The live page's capture and the target panel write back into each other:
   a row can set the target, and turning the checkbox on mid-run opens the
   file - both are defined after their callers. */
static void live_capture_begin(AppState *state, gboolean announce);
static gboolean live_pcap_open(AppState *state, const char *path, gboolean announce);
static void live_pcap_close(AppState *state);
static void live_capture_label_update(AppState *state);
static char *live_pcap_default_path(void);
static gboolean live_pcap_rotate_cb(gpointer user_data);
static void rtarget_apply(AppState *state);
static void sidebar_set_active(AppState *state, const char *module_id);
static void drawer_set_open(AppState *state, gboolean open);
static GtkWidget *empty_state(const char *icon, const char *title,
                              const char *hint);
static void show_toast_full(AppState *state, const char *title,
                            const char *message, const char *severity);
static void imsisting_action_run(AppState *state, const char *module_id,
                                 const char *label, GtkWidget *status_label,
                                 const char *const *argv, gboolean privileged);
static GtkWidget *create_module_page(AppState *state,
                                     const ModuleDefinition *module,
                                     ModuleSubmenuEntry *entries, int n_entries,
                                     gpointer module_data);
static void module_page_free(gpointer data);
static char *casebook_call(const char *const *args, gboolean *ok_out);
/* status_poll refreshes the target panel's read-out, and the poll is emitted
   long before the panel itself is defined. */
static void rtarget_panel_refresh(AppState *state);
static void casebook_home_refresh(AppState *state);
static void casebook_refresh(AppState *state);

static AppState *g_app_state = NULL;

/* --tab N opens the GUI on the Nth permanent tab (0 Dashboard, 1 Live
   Traffic, 2 Loot, 3 Stats, 4 Help, 5 Settings). -1 leaves the default. */
static int g_start_tab = -1;

/* --module <id> opens that module's page at startup. */
static const char *g_start_module = NULL;

/* ==================================================================== */
/*  SMALL HELPERS                                                       */
/* ==================================================================== */

/* Defined with the rest of the label helpers, but needed by the button that
   runs a verb, which is emitted long before that. */
static char *verb_label(const char *verb);

static char *
imsisting_root(void)
{
    return g_strdup(IMSISTING_ROOT);
}

static char *
module_script_path(const char *module_id)
{
    g_autofree char *root = imsisting_root();
    return g_strdup_printf("%s/modules/%s.sh", root, module_id);
}

static gboolean
module_script_exists(const char *module_id)
{
    g_autofree char *p = module_script_path(module_id);
    return g_file_test(p, G_FILE_TEST_IS_EXECUTABLE);
}

/* The index table is generated from the shell tree, so a module that exists
   on disk but is not in the C table would be invisible. This reports both
   directions of drift for the event drawer. */
static void
report_index_drift(AppState *state)
{
    int missing_in_table = 0;

    for (int i = 0; i < MODULE_INDEX_N; i++) {
        const ModuleIndexEntry *e = &module_index[i];
        gboolean found = FALSE;
        for (int j = 0; j < N_MODULES; j++) {
            if (g_strcmp0(modules[j].id, e->id) == 0) { found = TRUE; break; }
        }
        if (!found) missing_in_table++;
    }

    if (missing_in_table > 0) {
        g_autofree char *m = g_strdup_printf(
            "module index lists %d module(s) with no entry in the GUI table "
            "— run tools/gen-module-index.sh and add the module to main1.c",
            missing_in_table);
        append_event(state, m);
    }
}

/* ==================================================================== */
/*  DIAGNOSTICS: stderr capture                                         */
/* ==================================================================== */

/* GTK and GLib write to stderr; so does any subprocess spawned without its
   own stderr. Redirecting stderr to a file and polling it keeps that noise
   in the events drawer instead of on a terminal nobody is watching.

   The file is BOUNDED at STDERR_LOG_MAX. It was not, and that is not a
   theoretical problem: a dangling-widget assertion firing in a redraw loop
   made one run write 12.97 GB in under an hour and took the root filesystem
   to 100% with 112 MB free. Nothing trimmed the log, because stderr_poll()
   only advanced a read offset -- the file grew for the whole life of the
   process and was reset only by the next launch. */
#ifndef STDERR_LOG_MAX
#define STDERR_LOG_MAX (8 * 1024 * 1024)
#endif

static void
stderr_redirect(AppState *state)
{
    g_autofree char *dir = g_strdup_printf("%s/tmp", IMSISTING_ROOT);
    g_mkdir_with_parents(dir, 0755);

    g_autofree char *path = g_strdup_printf("%s/gui.stderr", dir);
    state->stderr_fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (state->stderr_fd < 0)
        return;

    dup2(state->stderr_fd, STDERR_FILENO);
    setvbuf(stderr, NULL, _IOLBF, 0);
    state->stderr_pos = 0;
}

/* GTK's repeated icon-snapshot chatter filled a 1.3 GB log upstream. Filter
   the known-noisy lines; deliberately do not filter our own style.css
   parser complaints, because those are ours to fix. */
static gboolean
is_log_noise(const char *msg)
{
    if (msg == NULL) return FALSE;
    if (strstr(msg, "snapshot symbolic icon using mask") != NULL) return TRUE;
    if (strstr(msg, "Gtk: snapshot") != NULL) return TRUE;
    if (strstr(msg, "Theme parser error") != NULL) {
        static const char *foreign[] = {
            "gtk-dark.css", "gtk.css", "Adwaita", "HighContrast",
            "libadwaita", "gtk-light.css", NULL
        };
        for (int i = 0; foreign[i] != NULL; i++)
            if (strstr(msg, foreign[i]) != NULL) return TRUE;
    }
    if (strstr(msg, "Unknown name of pseudo-class") != NULL &&
        strstr(msg, "style.css") == NULL)
        return TRUE;
    return FALSE;
}

static gboolean
stderr_poll(gpointer user_data)
{
    AppState *state = user_data;
    if (state->stderr_fd < 0 || state->window == NULL)
        return G_SOURCE_CONTINUE;

    struct stat st;
    g_autofree char *path = g_strdup_printf("%s/tmp/gui.stderr", IMSISTING_ROOT);
    if (stat(path, &st) != 0)
        return G_SOURCE_CONTINUE;
    if (st.st_size <= state->stderr_pos)
        return G_SOURCE_CONTINUE;

    FILE *f = fopen(path, "r");
    if (f == NULL) return G_SOURCE_CONTINUE;

    if (fseeko(f, state->stderr_pos, SEEK_SET) != 0) { fclose(f); return G_SOURCE_CONTINUE; }

    char line[2048];
    while (fgets(line, sizeof line, f) != NULL) {
        g_strchomp(line);
        if (*line == '\0') continue;
        if (is_log_noise(line)) continue;
        append_event(state, line);
    }
    state->stderr_pos = ftello(f);
    fclose(f);

    /* Bound the log. Truncating through state->stderr_fd is safe because
       dup2 made fd 2 and this descriptor share ONE open file description,
       so they also share the file offset -- the lseek below rewinds the
       writer as well. Without it the next write would land at the old,
       now-past-EOF offset and leave a sparse hole the size of the log. */
    if (st.st_size > STDERR_LOG_MAX) {
        if (ftruncate(state->stderr_fd, 0) == 0) {
            lseek(state->stderr_fd, 0, SEEK_SET);
            state->stderr_pos = 0;
        }
    }
    return G_SOURCE_CONTINUE;
}

/* ==================================================================== */
/*  EVENTS AND TOASTS                                                   */
/* ==================================================================== */

static void
event_scroll_to_end(AppState *state)
{
    if (state->event_buffer == NULL) return;
    if (!state->event_autoscroll) return;
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(state->event_buffer, &end);
    GtkTextMark *mark = gtk_text_buffer_create_mark(state->event_buffer, NULL, &end, FALSE);
    /* state->event_drawer is the GtkTextView itself. Asking for its first
       child and casting that to a GtkTextView is invalid: the first child is
       GTK's internal text window, not a view. */
    gtk_text_view_scroll_to_mark(
        GTK_TEXT_VIEW(state->event_drawer),
        mark, 0.0, FALSE, 0.0, 0.0);
}

static gboolean
event_line_is_error(const char *s)
{
    if (s == NULL) return FALSE;
    return strstr(s, "ERROR") != NULL || strstr(s, "[err]") != NULL ||
           strstr(s, "error") != NULL || strstr(s, "failed") != NULL ||
           strstr(s, "Failed") != NULL || strstr(s, "Missing") != NULL ||
           strstr(s, "not found") != NULL || strstr(s, "cannot") != NULL ||
           strstr(s, "denied") != NULL || strstr(s, "fabricat") != NULL;
}

/* ── which lines earn a toast ─────────────────────────────────────────
   Copied from wifisting, where the corner is driven by the event stream and
   not only by the ends of runs. The case that matters is a long module: a
   scan that has been running for forty seconds has said nothing since it
   started, and "it started", "it stopped early", "it saved something" are
   exactly what you want to be told without sitting on the Events drawer.
   Every error is announced, and a success only when it says one of the
   things worth interrupting for - the same keyword list wifisting uses - so
   a module that prints a line per record does not paper over the window.

   Two brakes on top of the policy: the same line twice in a row is one
   event, and a run gets at most four announcements, because the deps audit
   legitimately prints a dozen lines that each look like news. */
static void
action_line_announce(ActionRun *run, const char *line)
{
    static const char *success_words[] = {
        "captured", "Captured", "launched", "Launched", "installed",
        "Installed", "found", "Found", "hash", "Hash", "extracted",
        "Extracted", "started", "Started", "stopped", "Stopped", "saved",
        "Saved", NULL
    };
    const char *severity = NULL;

    if (event_line_is_error(line)) {
        severity = "error";
    } else {
        for (int i = 0; success_words[i] != NULL; i++) {
            if (strstr(line, success_words[i]) != NULL) {
                severity = "ok";
                break;
            }
        }
    }
    if (severity == NULL) return;
    if (g_strcmp0(line, run->last_announced) == 0) return;
    if (run->announced >= 4) return;

    run->announced++;
    g_free(run->last_announced);
    run->last_announced = g_strdup(line);

    {
        g_autofree char *clean = g_strdup(line);
        g_strstrip(clean);
        show_toast_full(run->state, run->label, clean, severity);
    }
}

static void
event_badge_update(AppState *state)
{
    if (state->event_button == NULL) return;
    if (state->event_errors > 0) {
        g_autofree char *t = g_strdup_printf("Events ● %u", state->event_errors);
        gtk_button_set_label(GTK_BUTTON(state->event_button), t);
    } else {
        gtk_button_set_label(GTK_BUTTON(state->event_button), "Events");
    }
}

static void
append_event(AppState *state, const char *message)
{
    if (state == NULL || state->event_buffer == NULL || message == NULL)
        return;

    gboolean is_err = event_line_is_error(message);
    if (is_err) {
        state->event_errors++;
        event_badge_update(state);
    }
    if (state->event_errors_only && !is_err) return;

    g_autofree char *ts = NULL;
    GDateTime *now = g_date_time_new_now_local();
    if (now != NULL) {
        ts = g_date_time_format(now, "%H:%M:%S");
        g_date_time_unref(now);
    }

    GtkTextIter end;
    gtk_text_buffer_get_end_iter(state->event_buffer, &end);
    gint start_off = gtk_text_iter_get_offset(&end);
    g_autofree char *line = g_strdup_printf("%s  %s\n", ts ? ts : "--:--:--", message);
    gtk_text_buffer_insert(state->event_buffer, &end, line, -1);

    GtkTextIter s2, e2;
    gtk_text_buffer_get_iter_at_offset(state->event_buffer, &s2, start_off);
    gtk_text_buffer_get_end_iter(state->event_buffer, &e2);
    gtk_text_buffer_apply_tag_by_name(state->event_buffer,
                                      is_err ? "event-err" : "event-line", &s2, &e2);
    event_scroll_to_end(state);
}

/* ── toasts ─────────────────────────────────────────────────────────
   Modelled on wifisting's show_toast_full. Each toast is its own revealer
   over a box of [icon | title over content | close glyph]: it slides in
   from the right, slides back out, and is destroyed when the slide
   finishes. The stack is capped, because the previous version appended
   forever and a long session walked the newest toast off the top of the
   screen.

   What this replaced: one label with <b> markup and an x icon button,
   appended and removed with no transition. It appeared and disappeared in
   a single frame, which reads as a repaint glitch rather than as
   something the program is telling you. */
typedef struct {
    GtkWidget *revealer;
    guint      timeout_id;
} ToastEntry;

static void
toast_entry_free(gpointer data)
{
    ToastEntry *t = data;

    if (t->timeout_id != 0) g_source_remove(t->timeout_id);
    g_free(t);
}

static gboolean
toast_dismiss_cb(gpointer user_data)
{
    ToastEntry *t = user_data;

    t->timeout_id = 0;
    if (t->revealer != NULL)
        gtk_revealer_set_reveal_child(GTK_REVEALER(t->revealer), FALSE);
    return G_SOURCE_REMOVE;
}

/* The toast is removed when its slide-out finishes, not when the timer
   fires, so the exit animation is never cut off half way. */
static void
toast_reveal_done(GObject *obj, GParamSpec *pspec, gpointer user_data)
{
    ToastEntry *t = user_data;
    GtkWidget *parent;

    (void) obj; (void) pspec;
    if (t->revealer == NULL) return;
    if (gtk_revealer_get_child_revealed(GTK_REVEALER(t->revealer))) return;
    parent = gtk_widget_get_parent(t->revealer);
    if (parent != NULL && GTK_IS_BOX(parent))
        gtk_box_remove(GTK_BOX(parent), t->revealer);
}

static void
toast_close_clicked(GtkButton *button, gpointer user_data)
{
    ToastEntry *t = user_data;

    (void) button;
    if (t->timeout_id != 0) {
        g_source_remove(t->timeout_id);
        t->timeout_id = 0;
    }
    if (t->revealer != NULL)
        gtk_revealer_set_reveal_child(GTK_REVEALER(t->revealer), FALSE);
}

/* Read by the toast gate below, which is defined before the store itself. */
static const char *settings_get(const char *key, const char *fallback);

/* A comma-separated list, matched case-insensitively against the toast's
   title. The log is the record and the corner is the interruption: a muted
   title is still logged, it just stops interrupting. */
static gboolean
settings_list_has(const char *key, const char *needle)
{
    const char *list = settings_get(key, NULL);
    gboolean found = FALSE;

    if (list == NULL || *list == '\0' || needle == NULL) return FALSE;
    g_autofree char *hay = g_ascii_strdown(needle, -1);
    g_auto(GStrv) parts = g_strsplit(list, ",", -1);

    /* Lowercased, then a plain substring test: GLib has no strcasestr, and
       lowercasing four short titles costs less than the alternative. */
    for (guint i = 0; parts[i] != NULL && !found; i++) {
        g_autofree char *one = g_strstrip(g_strdup(parts[i]));
        g_autofree char *low = g_ascii_strdown(one, -1);
        if (*one != '\0' && strstr(hay, low) != NULL)
            found = TRUE;
    }
    return found;
}

#define TOAST_STACK_MAX 5
#define NOTIF_MAX 100

/* ---- Declared settings -------------------------------------------------
   state/settings.tsv: key<TAB>value, one per line, '#' starts a comment, and
   a missing key means the default. It is the same file imsisting.sh reads at
   startup and the same shape as state/ui.tsv, on purpose: the window is one
   client of the file, not its owner. A setting changed here changes what a
   command typed by hand does, and `./imsisting.sh --settings set k v` changes
   what the window does - the button and the command stay the same thing.

   Precedence is environment > file > default, which the launcher applies to
   the module-facing keys; these are the window's own. */

static GHashTable *g_settings;   /* key -> value, both owned */

static char *
settings_path(void)
{
    return g_build_filename(IMSISTING_ROOT, "state", "settings.tsv", NULL);
}

static void
settings_load(void)
{
    g_autofree char *path = settings_path();
    g_autofree char *text = NULL;
    g_auto(GStrv) lines = NULL;

    if (g_settings == NULL)
        g_settings = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    else
        g_hash_table_remove_all(g_settings);

    if (!g_file_get_contents(path, &text, NULL, NULL)) return;
    lines = g_strsplit(text, "\n", -1);
    for (int i = 0; lines[i] != NULL; i++) {
        char *tab;
        if (lines[i][0] == '\0' || lines[i][0] == '#') continue;
        tab = strchr(lines[i], '\t');
        if (tab == NULL) continue;          /* no tab: not a pair, ignore it */
        *tab = '\0';
        g_hash_table_insert(g_settings, g_strdup(lines[i]), g_strdup(tab + 1));
    }
}

static void
settings_save(void)
{
    g_autofree char *path = settings_path();
    g_autoptr(GString) out = g_string_new(
        "# IMSIsting settings — key<TAB>value, one per line, # starts a comment.\n"
        "# A missing key means the default; `./imsisting.sh --settings list` "
        "shows what is declared.\n");
    GList *keys = g_hash_table_get_keys(g_settings);
    GList *it;

    keys = g_list_sort(keys, (GCompareFunc) g_strcmp0);
    for (it = keys; it != NULL; it = it->next)
        g_string_append_printf(out, "%s\t%s\n", (const char *) it->data,
            (const char *) g_hash_table_lookup(g_settings, it->data));
    g_list_free(keys);
    g_file_set_contents(path, out->str, -1, NULL);
}

static const char *
settings_get(const char *key, const char *fallback)
{
    const char *v;

    if (g_settings == NULL || key == NULL) return fallback;
    v = g_hash_table_lookup(g_settings, key);
    return (v != NULL && *v != '\0') ? v : fallback;
}

static gboolean
settings_declared(const char *key)
{
    if (g_settings == NULL || key == NULL) return FALSE;
    return g_hash_table_contains(g_settings, key);
}

/* A value of NULL takes the key back out, which is what "default" means. */
static void
settings_put(const char *key, const char *value)
{
    if (key == NULL) return;
    if (g_settings == NULL) settings_load();
    if (value == NULL)
        g_hash_table_remove(g_settings, key);
    else
        g_hash_table_insert(g_settings, g_strdup(key), g_strdup(value));
    settings_save();
}

static gboolean
settings_flag(const char *key, gboolean fallback)
{
    const char *v = settings_get(key, NULL);

    if (v == NULL) return fallback;
    return g_ascii_strcasecmp(v, "on") == 0 ||
           g_ascii_strcasecmp(v, "yes") == 0 ||
           g_ascii_strcasecmp(v, "true") == 0 ||
           g_strcmp0(v, "1") == 0;
}

/* Clamped integer, defaulted, never fatal: a hand-edited file with a typo in
   it must not take the window down. */
static int
settings_int(const char *key, int fallback, int lo, int hi)
{
    const char *v = settings_get(key, NULL);
    char *end = NULL;
    long n;

    if (v == NULL) return fallback;
    n = strtol(v, &end, 10);
    if (end == v) return fallback;
    return (int) CLAMP(n, lo, hi);
}

/* One line of the notification log: what was said, in what tone, and when.
   Kept apart from the toast widget because the widget is gone in five seconds
   and this is what the Notifications page reads back. */
typedef struct {
    gint64 when;          /* g_get_real_time(), for the clock in the list */
    char  *title;
    char  *body;
    char  *severity;      /* error | warn | ok | info */
} NotifEntry;

static void
notif_entry_free(gpointer data)
{
    NotifEntry *n = data;

    if (n == NULL) return;
    g_free(n->title);
    g_free(n->body);
    g_free(n->severity);
    g_free(n);
}

static void notif_page_refill(AppState *state);

/* The tone of a notification, as a class name. Every kind gets a dot and a
   colour in the list, so the shape of a session reads at a glance: a column of
   green with one red in it is a different story from the reverse. */
static const char *
notif_kind_class(const char *severity)
{
    if (g_strcmp0(severity, "error") == 0) return "notif-error";
    if (g_strcmp0(severity, "warn") == 0)  return "notif-warn";
    if (g_strcmp0(severity, "ok") == 0)    return "notif-ok";
    return "notif-info";
}

static GtkWidget *
notif_row_new(const NotifEntry *n)
{
    GtkWidget *row = gtk_list_box_row_new();
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *dot = gtk_label_new("●");
    GtkWidget *col = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *head = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *title = gtk_label_new(n->title);
    GtkWidget *body = gtk_label_new(n->body);
    GDateTime *dt = g_date_time_new_from_unix_local(n->when / G_USEC_PER_SEC);
    g_autofree char *clock = dt != NULL
        ? g_date_time_format(dt, "%H:%M:%S") : g_strdup("--:--:--");
    GtkWidget *time = gtk_label_new(clock);

    if (dt != NULL) g_date_time_unref(dt);

    gtk_widget_add_css_class(box, "notif-row");
    gtk_widget_add_css_class(dot, "status-dot");
    gtk_widget_add_css_class(dot, notif_kind_class(n->severity));
    gtk_widget_add_css_class(time, "notif-time");
    gtk_widget_add_css_class(title, "notif-title");
    gtk_widget_add_css_class(body, "notif-body");

    gtk_widget_set_valign(dot, GTK_ALIGN_START);
    gtk_widget_set_margin_top(dot, 3);
    gtk_widget_set_valign(time, GTK_ALIGN_START);
    gtk_widget_set_margin_top(time, 1);
    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(body), 0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(title), PANGO_ELLIPSIZE_END);
    gtk_widget_set_hexpand(title, TRUE);
    gtk_label_set_wrap(GTK_LABEL(body), TRUE);
    gtk_label_set_wrap_mode(GTK_LABEL(body), PANGO_WRAP_WORD_CHAR);
    gtk_label_set_selectable(GTK_LABEL(body), TRUE);

    gtk_box_append(GTK_BOX(head), title);
    gtk_box_append(GTK_BOX(col), head);
    gtk_box_append(GTK_BOX(col), body);
    gtk_widget_set_hexpand(col, TRUE);
    gtk_box_append(GTK_BOX(box), dot);
    gtk_box_append(GTK_BOX(box), time);
    gtk_box_append(GTK_BOX(box), col);
    gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), box);
    return row;
}

/* Called from show_toast_full, so the log holds exactly what was announced:
   nothing here is a second, hand-maintained list of events that can drift out
   of step with the toasts. */
static void
notif_push(AppState *state, const char *title, const char *body,
           const char *severity)
{
    NotifEntry *n;

    if (state == NULL) return;

    if (state->notifs == NULL)
        state->notifs = g_queue_new();

    n = g_new0(NotifEntry, 1);
    n->when = g_get_real_time();
    n->title = g_strdup((title != NULL && *title != '\0') ? title : "IMSIsting");
    n->body = g_strdup(body != NULL ? body : "");
    n->severity = g_strdup((severity != NULL && *severity != '\0')
                           ? severity : "info");

    g_queue_push_head(state->notifs, n);
    while (g_queue_get_length(state->notifs) >
           (guint) settings_int("notify.keep", NOTIF_MAX, 10, 1000))
        notif_entry_free(g_queue_pop_tail(state->notifs));

    if (state->notif_list != NULL)
        notif_page_refill(state);
}

static void
show_toast_full(AppState *state, const char *title,
                const char *message, const char *severity)
{
    ToastEntry *t;
    GtkWidget *rev, *box, *icon, *col, *title_lbl, *content_lbl, *close, *glyph;
    const char *icon_name;
    gboolean is_err = (g_strcmp0(severity, "error") == 0);
    guint n = 0;

    /* The log first: a toast that is never seen - because five are already
       stacked, or because the operator was reading another page - still has to
       be in the record. */
    notif_push(state, title, message, severity);

    /* A muted title is logged and not shown, which is what "mute" has to mean
       if the log is to stay the record. */
    if (settings_list_has("notify.mute", title)) return;

    /* notify.severities is a comma-separated list of the tones that are worth
       interrupting for. Silence here does not mean silence in the log: the
       record keeps everything, the corner keeps what was asked for. */
    {
        const char *want = settings_get("notify.severities", NULL);
        if (want != NULL) {
            g_autofree char *needle = g_strdup_printf("%s",
                severity != NULL ? severity : "info");
            g_autofree char *hay = g_ascii_strdown(want, -1);
            g_autofree char *low = g_ascii_strdown(needle, -1);
            if (strstr(hay, low) == NULL) return;
        }
    }


    /* GTK_IS_WIDGET, not == NULL: at shutdown the state can hold a pointer
       that is non-NULL and no longer a widget, and touching it aborts. */
    if (state == NULL || !GTK_IS_WIDGET(state->toast_box)) return;

    {
        GtkWidget *c = gtk_widget_get_first_child(state->toast_box);
        while (c != NULL) { n++; c = gtk_widget_get_next_sibling(c); }
        if (n >= (guint) settings_int("notify.stack", TOAST_STACK_MAX, 1, 20)) {
            GtkWidget *first = gtk_widget_get_first_child(state->toast_box);
            if (first != NULL)
                gtk_box_remove(GTK_BOX(state->toast_box), first);
        }
    }

    if (is_err)                                     icon_name = "dialog-error-symbolic";
    else if (g_strcmp0(severity, "warn") == 0)      icon_name = "dialog-warning-symbolic";
    else if (g_strcmp0(severity, "ok") == 0)        icon_name = "emblem-ok-symbolic";
    else                                            icon_name = "dialog-information-symbolic";

    rev = gtk_revealer_new();
    box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    icon = imsisting_icon_image(icon_name);
    col = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    title_lbl = gtk_label_new((title != NULL && *title != '\0') ? title : "IMSIsting");
    content_lbl = gtk_label_new(message != NULL ? message : "");
    close = gtk_button_new();
    glyph = gtk_label_new("×");

    gtk_widget_add_css_class(box, "toast");
    gtk_widget_add_css_class(icon, "toast-icon");
    gtk_widget_add_css_class(title_lbl, "toast-title");
    gtk_widget_add_css_class(content_lbl, "toast-content");
    gtk_widget_add_css_class(close, "toast-close");
    gtk_widget_add_css_class(glyph, "toast-close-glyph");
    if (severity != NULL && *severity != '\0') {
        g_autofree char *cls = g_strdup_printf("toast-%s", severity);
        gtk_widget_add_css_class(box, cls);
    }

    gtk_image_set_pixel_size(GTK_IMAGE(icon), 18);
    gtk_widget_set_valign(icon, GTK_ALIGN_START);
    gtk_widget_set_margin_top(icon, 2);

    gtk_label_set_xalign(GTK_LABEL(title_lbl), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(content_lbl), 0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(title_lbl), PANGO_ELLIPSIZE_END);
    gtk_label_set_wrap(GTK_LABEL(content_lbl), TRUE);
    gtk_label_set_wrap_mode(GTK_LABEL(content_lbl), PANGO_WRAP_WORD_CHAR);
    gtk_label_set_max_width_chars(GTK_LABEL(content_lbl), 58);
    /* Selectable: a toast often carries the one line worth pasting into a
       report, and it used to be impossible to copy. */
    gtk_label_set_selectable(GTK_LABEL(content_lbl), TRUE);

    gtk_widget_set_hexpand(col, TRUE);
    gtk_widget_set_halign(title_lbl, GTK_ALIGN_START);
    gtk_widget_set_halign(content_lbl, GTK_ALIGN_START);

    gtk_button_set_child(GTK_BUTTON(close), glyph);
    gtk_widget_set_valign(close, GTK_ALIGN_START);
    gtk_widget_set_tooltip_text(close, "Dismiss");

    gtk_box_append(GTK_BOX(col), title_lbl);
    gtk_box_append(GTK_BOX(col), content_lbl);
    gtk_box_append(GTK_BOX(box), icon);
    gtk_box_append(GTK_BOX(box), col);
    gtk_box_append(GTK_BOX(box), close);

    gtk_revealer_set_child(GTK_REVEALER(rev), box);
    gtk_revealer_set_transition_type(GTK_REVEALER(rev),
                                     GTK_REVEALER_TRANSITION_TYPE_SLIDE_LEFT);
    gtk_revealer_set_transition_duration(GTK_REVEALER(rev), 220);
    gtk_revealer_set_reveal_child(GTK_REVEALER(rev), FALSE);

    t = g_new0(ToastEntry, 1);
    t->revealer = rev;

    g_object_set_data_full(G_OBJECT(rev), "toast-entry", t, toast_entry_free);
    g_signal_connect(close, "clicked", G_CALLBACK(toast_close_clicked), t);
    g_signal_connect(rev, "notify::child-revealed",
                     G_CALLBACK(toast_reveal_done), t);

    gtk_box_append(GTK_BOX(state->toast_box), rev);
    gtk_revealer_set_reveal_child(GTK_REVEALER(rev), TRUE);

    /* Errors are the ones worth reading twice. notify.toast_ms sets how long
       a toast of any kind lingers; 0 means "until it is closed by hand". */
    {
        int ms = settings_int("notify.toast_ms", is_err ? 9000 : 4200, 0, 120000);
        t->timeout_id = ms > 0 ? g_timeout_add((guint) ms, toast_dismiss_cb, t) : 0;
    }
}

/* ==================================================================== */
/*  ACTION RUNNER                                                       */
/* ==================================================================== */

static void
status_label_set(GtkWidget *label, const char *text, const char *css)
{
    if (label == NULL || !GTK_IS_LABEL(label)) return;
    gtk_label_set_text(GTK_LABEL(label), text);

    const char *classes[] = { "status-idle", "status-running",
                              "status-ok", "status-error", NULL };
    for (int i = 0; classes[i] != NULL; i++)
        gtk_widget_remove_css_class(label, classes[i]);
    if (css != NULL && *css != '\0')
        gtk_widget_add_css_class(label, css);
}

static void action_read_line(ActionRun *run, gboolean is_err);
/* Defined with the module output card further down; the action runner
   writes into a page's output buffer as lines arrive. */
static void console_append(GtkTextBuffer *buf, const char *text);

static void
action_run_unref(ActionRun *run)
{
    if (run == NULL) return;
    if (--run->refs > 0) return;

    /* Last release: the process has been reaped, and both pipes have reached
       EOF, so this is the first moment the module's whole answer is known. A
       card that asked to be told gets the module's output and nothing the
       interface added around it - no command line, no "-- done" trailer. */
    if (run->done != NULL && !run->reported) {
        run->reported = TRUE;
        run->done(run->captured != NULL ? run->captured->str : "",
                  run->wait_ok && run->wait_status == 0 && !run->saw_error,
                  run->wait_status, run->done_owner);
    }

    /* Now the module's whole answer is known: close the card it was read in
       with one line saying how the run ended, then take the Stop away. */
    if (run->output != NULL) {
        ResultRect *rr = g_object_get_data(G_OBJECT(run->output), "result-rect");
        g_autofree char *verdict = run->stopped
            ? g_strdup("stopped")
            : ((!run->wait_ok || run->wait_status != 0 || run->saw_error)
                ? g_strdup_printf("failed (exit %d)", run->wait_status)
                : g_strdup("done"));

        if (rr != NULL) {
            gint records = result_rows_count(rr);
            g_autofree char *receipt = NULL;

            g_object_set_data_full(G_OBJECT(rr->rows), "verdict",
                                   g_strdup(verdict), g_free);

            /* One or two records are a receipt, not a table: say it in a toast
               and leave the card holding the same sentence. A refusal is never
               compacted - a refusal has to be readable where it lands. */
            if (records >= 1 && records <= 2 && !run->saw_error && !run->stopped &&
                run_receipt(run, &receipt) && receipt != NULL) {
                result_compact(rr, receipt);
                show_toast_full(run->state, run->label, receipt, "ok");
            } else {
                result_end(rr);
            }
        } else {
            console_append(run->output, verdict);
        }
    }

    if (run->state->running != NULL &&
        g_ptr_array_find(run->state->running, run, NULL))
        g_ptr_array_remove(run->state->running, run);

    g_clear_object(&run->output);
    g_clear_object(&run->done_owner);
    g_clear_object(&run->proc);
    g_clear_object(&run->out);
    g_clear_object(&run->err);
    if (run->captured != NULL) g_string_free(run->captured, TRUE);
    g_free(run->module_id);
    g_free(run->label);
    g_free(run->last_announced);
    g_free(run);
}

/* One line arrived on stdout or stderr. Append it now rather than at exit:
 * a 30-second scan that shows nothing until it finishes reads as a hang. */
static void
action_line_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    ActionStream *st = user_data;
    ActionRun *run = st->run;
    gboolean is_err = st->is_err;
    g_autoptr(GError) error = NULL;
    gsize len = 0;

    g_autofree char *line = g_data_input_stream_read_line_finish_utf8(
        G_DATA_INPUT_STREAM(source), result, &len, &error);

    if (line == NULL) {
        /* EOF (or a read error) — this reader is finished. */
        g_free(st);
        action_run_unref(run);
        return;
    }

    if (*line != '\0') {
        g_autofree char *l = g_strdup_printf("  %s", line);
        append_event(run->state, l);
        action_line_announce(run, line);
        console_append(run->output, line);
        if (run->captured != NULL) {
            g_string_append(run->captured, line);
            g_string_append_c(run->captured, '\n');
        }
        /* Anything on stderr, or an ERROR marker on stdout, marks the run
           failed even if the exit status is 0. */
        if (is_err || strstr(line, "ERROR") != NULL)
            run->saw_error = TRUE;
    }

    g_free(st);
    action_read_line(run, is_err);
}

static void
action_read_line(ActionRun *run, gboolean is_err)
{
    GDataInputStream *stream = is_err ? run->err : run->out;
    if (stream == NULL) return;

    ActionStream *st = g_new0(ActionStream, 1);
    st->run = run;
    st->is_err = is_err;
    g_data_input_stream_read_line_async(stream, G_PRIORITY_DEFAULT, NULL,
                                        action_line_cb, st);
}

static void
action_waited(GObject *source, GAsyncResult *result, gpointer user_data)
{
    ActionRun *run = user_data;
    AppState *state = run->state;
    g_autoptr(GError) error = NULL;

    gboolean ok = g_subprocess_wait_check_finish(G_SUBPROCESS(source),
                                                 result, &error);

    int status = 0;
    if (!g_subprocess_get_if_exited(G_SUBPROCESS(source)))
        status = -1;
    else
        status = g_subprocess_get_exit_status(G_SUBPROCESS(source));

    /* A cancelled run is a verdict of its own. It is not a failure - the
       operator asked for it - and it is not a success either, so neither word
       is used and the card says which one happened. */
    if (run->stopped) {
        g_autofree char *m = g_strdup_printf("%s: stopped", run->label);
        append_event(state, m);
        show_toast_full(state, run->label, "stopped", "warn");
        status_label_set(run->status_label, "Stopped", "status-stopped");
    } else if (!ok || status != 0 || run->saw_error) {
        g_autofree char *m = g_strdup_printf("%s: failed (exit %d)",
                                             run->label, status);
        append_event(state, m);
        show_toast_full(state, run->label, m, "error");
        status_label_set(run->status_label, "Error", "status-error");
    } else {
        g_autofree char *m = g_strdup_printf("%s: done", run->label);
        append_event(state, m);
        /* A success used to be silent here while a failure raised a toast,
           so the only notification the operator ever saw was bad news. A
           button that worked and a button that did nothing looked the same. */
        show_toast_full(state, run->label, "completed", "ok");
        status_label_set(run->status_label, "Done", "status-ok");
    }

    /* The card's closing line is written on the run's LAST release, below, not
       here: the process can exit while its pipes still hold records, so a
       verdict written at exit landed in the middle of the module's answer. */

    /* The card that started the run is told directly, so it can build its own
       result from what the module said. That happens on the run's LAST
       release, not here: the process can exit while its pipes still hold
       output, and a card fed at that moment shows only the first line or two.
       So the verdict is recorded now and reported once every reader is done. */
    run->wait_ok = ok;
    run->wait_status = status;

    /* If a Casebook is active, preserve the result as a correlated event.
       No evidence is hashed automatically: indexing large IQ files remains an
       explicit operator action in Casebook > Captures. */
    const char *severity = run->stopped ? "INFO"
        : ((!ok || status != 0 || run->saw_error) ? "HIGH" : "INFO");
    const char *outcome = run->stopped ? "stopped"
        : ((!ok || status != 0 || run->saw_error) ? "failed" : "completed");
    g_autofree char *message = g_strdup_printf("%s: %s (exit %d)",
                                               run->label, outcome, status);
    const char *cb_args[] = { "--timeline-add", severity, "module-run",
                              run->module_id, message, "-", NULL };
    gboolean cb_ok = FALSE;
    g_autofree char *cb_out = casebook_call(cb_args, &cb_ok);
    (void) cb_out; /* no active case is normal and intentionally silent */
    if (cb_ok && state->casebook_timeline_list != NULL)
        casebook_refresh(state);

    action_run_unref(run);
}

/* `console` is where the run echoes line by line; NULL means the caller has
   somewhere better to put the result and wants nothing written to a page-wide
   card. `done` is called once with the module's whole output, and `done_owner`
   - the widget the caller will read the result out of - is held open until
   then, so a page closed mid-run cannot pull the callback's ground away. */
static void
imsisting_action_run_full(AppState *state, const char *module_id,
                          const char *label, GtkWidget *status_label,
                          const char *const *argv, gboolean privileged,
                          GtkTextBuffer *console, ActionDoneFn done,
                          GObject *done_owner)
{
    g_autoptr(GError) error = NULL;
    GSubprocess *proc;

    if (state == NULL || argv == NULL || argv[0] == NULL) return;

    /* Mark the module recent so its dashboard cue reflects use, and count the
       run so the dashboard can be ordered by what this operator really uses. */
    if (state->recent != NULL && module_id != NULL)
        g_hash_table_add(state->recent, g_strdup(module_id));
    recents_bump(state, module_id);

    append_event(state, label);
    status_label_set(status_label, "Running", "status-running");

    /* The Events drawer is not opened here on purpose. A press is answered by
       the status label going to "Running", by the card that started it filling
       in place and by a toast when the run ends - so the drawer can stay shut
       until the operator asks for it. Opening it on every press made a button
       look like it did nothing but open the drawer, which is the complaint
       this fixes. */

    if (privileged) {
        /* pkexec must see the real script path as its program so a polkit
           rule matching the module path can fire. Never wrap in `env`. */
        GPtrArray *full = g_ptr_array_new();
        g_ptr_array_add(full, (gpointer) "pkexec");
        for (guint i = 0; argv[i] != NULL; i++)
            g_ptr_array_add(full, (gpointer) argv[i]);
        g_ptr_array_add(full, NULL);

        proc = g_subprocess_newv((const char * const *) full->pdata,
                                 G_SUBPROCESS_FLAGS_STDOUT_PIPE |
                                 G_SUBPROCESS_FLAGS_STDERR_PIPE,
                                 &error);
        g_ptr_array_unref(full);
    } else {
        proc = g_subprocess_newv(argv,
                                 G_SUBPROCESS_FLAGS_STDOUT_PIPE |
                                 G_SUBPROCESS_FLAGS_STDERR_PIPE,
                                 &error);
    }

    if (proc == NULL) {
        g_autofree char *m = g_strdup_printf(
            "%s: %s", label, error ? error->message : "spawn failed");
        append_event(state, m);
        show_toast_full(state, label, m, "error");
        status_label_set(status_label, "Error", "status-error");
        return;
    }

    ActionRun *a = g_new0(ActionRun, 1);
    a->state        = state;
    a->module_id    = g_strdup(module_id);
    a->label        = g_strdup(label);
    a->status_label = status_label;
    a->proc         = g_object_ref(proc);
    a->captured     = g_string_new(NULL);
    a->refs         = 3;   /* stdout reader + stderr reader + waiter */
    a->done         = done;
    a->done_owner   = done_owner != NULL ? g_object_ref(done_owner) : NULL;

    /* Echo the run into the output card of the page that is on screen. The
       run keeps its own reference, so closing the page mid-run is safe. */
    a->output = console != NULL ? g_object_ref(console) : NULL;
    if (a->output != NULL) {
        g_autofree char *hdr = g_strdup_printf("$ %s", label);
        console_append(a->output, hdr);
    }

    if (state->running == NULL)
        state->running = g_ptr_array_new();
    g_ptr_array_add(state->running, a);

    a->out = g_data_input_stream_new(g_subprocess_get_stdout_pipe(proc));
    a->err = g_data_input_stream_new(g_subprocess_get_stderr_pipe(proc));
    g_data_input_stream_set_newline_type(a->out, G_DATA_STREAM_NEWLINE_TYPE_ANY);
    g_data_input_stream_set_newline_type(a->err, G_DATA_STREAM_NEWLINE_TYPE_ANY);

    action_read_line(a, FALSE);
    action_read_line(a, TRUE);
    g_subprocess_wait_check_async(proc, NULL, action_waited, a);

    g_object_unref(proc);
}

/* The common case: echo into the page that is on screen, tell nobody. */
static void
imsisting_action_run(AppState *state, const char *module_id,
                     const char *label, GtkWidget *status_label,
                     const char *const *argv, gboolean privileged)
{
    imsisting_action_run_full(state, module_id, label, status_label, argv,
                              privileged,
                              state != NULL ? state->active_output : NULL,
                              NULL, NULL);
}

/* Run a module verb with no arguments beyond the verb itself. */
static void
run_module_verb(AppState *state, const char *module_id, const char *verb,
                const char *label, GtkWidget *status_label, gboolean privileged)
{
    g_autofree char *script = module_script_path(module_id);

    if (!g_file_test(script, G_FILE_TEST_EXISTS)) {
        g_autofree char *m = g_strdup_printf(
            "module %s is not present at %s", module_id, script);
        append_event(state, m);
        show_toast_full(state, label, m, "error");
        status_label_set(status_label, "Missing", "status-error");
        return;
    }

    const char *argv[3] = { script, verb, NULL };
    imsisting_action_run(state, module_id, label, status_label, argv, privileged);
}

/* ==================================================================== */
/*  MODULE REGISTRY                                                     */
/* ==================================================================== */

typedef struct {
    const char *module_id;
    ModuleSubmenuEntry *entries;
    int n_entries;
    gpointer (*get_module_data)(AppState *state);
} ModuleRegistryEntry;

static ModuleRegistryEntry *module_registry = NULL;
static int module_registry_size = 0;

void
module_registry_register(const char *module_id, ModuleSubmenuEntry *entries,
                         int n_entries,
                         gpointer (*get_module_data)(AppState *state))
{
    module_registry = g_realloc(module_registry,
        (module_registry_size + 1) * sizeof(ModuleRegistryEntry));
    module_registry[module_registry_size].module_id = module_id;
    module_registry[module_registry_size].entries = entries;
    module_registry[module_registry_size].n_entries = n_entries;
    module_registry[module_registry_size].get_module_data = get_module_data;
    module_registry_size++;
}

static ModuleRegistryEntry *
module_registry_find(const char *module_id)
{
    for (int i = 0; i < module_registry_size; i++) {
        if (g_strcmp0(module_registry[i].module_id, module_id) == 0)
            return &module_registry[i];
    }
    return NULL;
}

/* ==================================================================== */
/*  GENERIC PAGE HELPERS                                                */
/* ==================================================================== */

/* Fallback handler for the placeholder page, used only by a module that has no
   registered submenu at all. Its buttons are derived from the generated index,
   so even an unregistered module is not frozen. */
static void
verb_button_dyn_clicked(GtkButton *button, gpointer user_data)
{
    AppState *state = g_object_get_data(G_OBJECT(button), "state");
    const char *module_id = g_object_get_data(G_OBJECT(button), "module-id");
    const char *verb = g_object_get_data(G_OBJECT(button), "verb");
    GtkWidget *status = g_object_get_data(G_OBJECT(button), "status");

    if (module_id == NULL || verb == NULL)
        return;
    g_autofree char *label = g_strdup_printf("%s %s", module_id, verb);
    run_module_verb(state, module_id, verb, label, status, FALSE);
    (void) user_data;
}

/* The newest file in captures/, used as the default for the verbs that read a
   capture: the button works on the most recent one without a prompt. */
static char *
newest_capture(void)
{
    g_autofree char *dir = g_build_filename(IMSISTING_ROOT, "captures", NULL);
    g_autoptr(GDir) d = g_dir_open(dir, 0, NULL);
    const char *name;
    GStatBuf best;
    g_autofree char *best_path = NULL;

    if (d == NULL)
        return NULL;
    while ((name = g_dir_read_name(d)) != NULL) {
        g_autofree char *p = g_build_filename(dir, name, NULL);
        GStatBuf st;
        if (g_stat(p, &st) != 0 || !S_ISREG(st.st_mode))
            continue;
        if (best_path == NULL || st.st_mtime > best.st_mtime) {
            g_free(best_path);
            best_path = g_strdup(p);
            best = st;
        }
    }
    return g_steal_pointer(&best_path);
}

/* One button in a curated module group. The verb, its privilege and its
   default arguments are attached to the button; one click runs it. A token of
   "{capture}" resolves to the newest capture so file verbs work untouched. */
static void
group_verb_clicked(GtkButton *button, gpointer user_data)
{
    AppState *state = g_object_get_data(G_OBJECT(button), "state");
    const char *module_id = g_object_get_data(G_OBJECT(button), "module-id");
    const char *verb = g_object_get_data(G_OBJECT(button), "verb");
    const char *argspec = g_object_get_data(G_OBJECT(button), "args");
    GtkWidget *status = g_object_get_data(G_OBJECT(button), "status");
    gboolean privileged =
        GPOINTER_TO_INT(g_object_get_data(G_OBJECT(button), "privileged"));
    g_autofree char *script = NULL;
    g_autofree char *cap = NULL;
    g_autofree char *label = NULL;
    /* Function scope on purpose: argv holds pointers INTO these strings, so
       they must outlive imsisting_action_run() below. Declared inside the
       'if' they were freed the moment that block closed, and argv pointed at
       released memory - which usually still held the text, so it went
       unnoticed until something allocated in between (the label build) and
       reused the block. The verb then ran with a clobbered argument. */
    g_auto(GStrv) parts = NULL;
    g_autofree char *args_root = NULL;
    const char *argv[12];
    int n = 0;

    if (module_id == NULL || verb == NULL)
        return;

    script = module_script_path(module_id);
    if (!g_file_test(script, G_FILE_TEST_EXISTS)) {
        g_autofree char *m = g_strdup_printf(
            "module %s is not present at %s", module_id, script);
        g_autofree char *title = verb_label(verb);

        append_event(state, m);
        show_toast_full(state, title, m, "error");
        return;
    }

    argv[n++] = script;
    argv[n++] = verb;

    /* {root} is the project directory, resolved at press time. The pages are
       static tables, but the root is not, and a preset that writes a capture
       has to name the same directory the app reads - wherever the app was
       launched from, and whichever user launched it. */
    if (argspec != NULL && strstr(argspec, "{root}") != NULL) {
        g_auto(GStrv) chunks = g_strsplit(argspec, "{root}", -1);
        args_root = g_strjoinv(IMSISTING_ROOT, chunks);
        argspec = args_root;
    }

    if (argspec != NULL && *argspec != '\0') {
        parts = g_strsplit_set(argspec, " \t", -1);
        for (int i = 0; parts[i] != NULL && n < 11; i++) {
            if (*parts[i] == '\0')
                continue;
            if (g_strcmp0(parts[i], "{capture}") == 0) {
                cap = newest_capture();
                if (cap == NULL) {
                    show_toast_full(state, verb,
                        "no capture found in captures/", "error");
                    return;
                }
                argv[n++] = cap;
            } else {
                argv[n++] = parts[i];
            }
        }
    }
    argv[n] = NULL;

    /* What the operator reads afterwards - the toast, the Events drawer, the
       card the run started from. A label set on the button wins; otherwise the
       verb is spelled the way a reader spells it. The command line the run
       stands for is never what the interface shows: `--run-cve` is a thing to
       type in a shell, not a thing to read in a window. */
    {
        const char *wanted = g_object_get_data(G_OBJECT(button), "label");

        if (wanted != NULL && *wanted != '\0') {
            label = g_strdup(wanted);
        } else {
            /* The arguments are a shell fragment - `--cause 15` is a flag, not
               something a window should read - so the label is the job, and a
               reader who wants the values looks at the module's own output,
               which prints them back. */
            label = verb_label(verb);
            }
    }
    {
        /* A button may ask to be told when the run ends, so the card it lives
           in can show the result itself. Without that the run only toasts. */
        ActionDoneFn done =
            (ActionDoneFn) g_object_get_data(G_OBJECT(button), "done");
        GObject *owner = g_object_get_data(G_OBJECT(button), "done-owner");
        GtkWidget *result = g_object_get_data(G_OBJECT(button), "result");

        /* The rect the press came from becomes where this run is read, and
           where its Stop lives. Done before the spawn: the first line of
           output can arrive before imsisting_action_run_full() returns. */
        if (result != NULL) {
            ResultRect *rr = g_object_get_data(G_OBJECT(result), "result-rect");
            result_begin(state, rr);
        }

        imsisting_action_run_full(state, module_id, label, status, argv,
                                  privileged, state->active_output,
                                  done, owner);
    }
    (void) user_data;
}

/* A titled panel, the way a module page groups its content. */
static GtkWidget *
verb_card(const char *heading, GtkWidget **body_out)
{
    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    GtkWidget *h = gtk_label_new(heading);
    GtkWidget *body = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);

    gtk_widget_add_css_class(card, "card");
    gtk_widget_add_css_class(h, "card-heading");
    gtk_label_set_xalign(GTK_LABEL(h), 0.0f);
    gtk_widget_set_margin_start(body, 14);
    gtk_widget_set_margin_end(body, 14);
    gtk_widget_set_margin_bottom(body, 14);

    gtk_box_append(GTK_BOX(card), h);
    gtk_box_append(GTK_BOX(card), body);
    if (body_out != NULL) *body_out = body;
    return card;
}

/* ── what a module's own words look like on the page ────────────────────
 *
 * The rule is that no verb appears in this interface, and the hardest place to
 * keep it is not our own labels - it is the text the modules print, which is
 * written for a terminal and says things like
 *     step 1: 02_cell_recon --scan gsm GSM900
 * Showing that verbatim puts a command-line flag on screen, which the rule
 * forbids and which also reads badly: a reader wants to know what is happening,
 * not which switch was passed.
 *
 * So module text is translated for display, never stored translated:
 *   --flag        becomes the job's own name, between two raised dots, so the
 *                 sentence still parses and the flag is gone;
 *   02_cell_recon becomes "cell recon", because a module id is an address in
 *                 the tree, not a thing an operator says.
 *
 * The copy action keeps the original line. What is displayed is a reading of
 * the record; what is copied is the record.
 */
static gboolean
token_is_verb(const char *tok)
{
    if (tok == NULL || tok[0] != '-' || tok[1] != '-') return FALSE;
    if (tok[2] == '\0') return FALSE;
    for (const char *c = tok + 2; *c != '\0'; c++)
        if (!(g_ascii_isalnum(*c) || *c == '-' || *c == '.' || *c == '_'))
            return FALSE;
    return TRUE;
}

static gboolean
token_is_module_id(const char *tok)
{
    if (tok == NULL || !g_ascii_isdigit(tok[0]) || !g_ascii_isdigit(tok[1]))
        return FALSE;
    if (tok[2] != '_') return FALSE;
    for (const char *c = tok + 3; *c != '\0'; c++)
        if (!(g_ascii_isalnum(*c) || *c == '_')) return FALSE;
    return tok[3] != '\0';
}

/* "cell_recon" -> "cell recon": the id's own words, no path, no number. */
static char *
module_id_words(const char *tok)
{
    /* g_strdelimit returns its argument, but it is allowed to reallocate it, so
       the returned pointer is the only one that may be freed. Handing the
       original to g_autofree as well is a double free - which is what crashed
       the page the first time a chain narrated its own steps. */
    char *spaced = g_strdelimit(g_strdup(tok + 3), "_", ' ');
    char *out = g_strdup(spaced);

    g_free(spaced);
    return out;
}

static char *
display_text(const char *raw)
{
    g_auto(GStrv) words = NULL;
    GString *out = g_string_new(NULL);

    if (raw == NULL) return g_strdup("");
    words = g_strsplit(raw, " ", -1);

    for (int i = 0; words[i] != NULL; i++) {
        const char *w = words[i];
        g_autofree char *clean = NULL;

        if (*w == '\0') continue;

        /* A flag can be glued to punctuation the module wrote: strip the ends,
           translate the middle, then put the punctuation back. */
        {
            gsize lead = 0, len = strlen(w);
            g_autofree char *core = NULL;
            char tail = '\0';

            while (lead < len && !(w[lead] == '-' || g_ascii_isalnum(w[lead])))
                lead++;
            while (len > lead && !(g_ascii_isalnum(w[len - 1]) ||
                                   w[len - 1] == '-' || w[len - 1] == '_'))
                len--;
            if (len > lead) {
                if (len < strlen(w)) tail = w[len];
                core = g_strndup(w + lead, len - lead);
            }

            if (core != NULL && token_is_verb(core)) {
                g_autofree char *job = verb_label(core + 2);
                g_autofree char *head = g_strndup(w, lead);
                clean = g_strdup_printf("%s\u00b7 %s \u00b7%s", head, job,
                                        tail != '\0' ? " " : "");
                if (tail != '\0') {
                    g_autofree char *with = g_strdup_printf("%s%c", clean, tail);
                    g_free(clean);
                    clean = g_steal_pointer(&with);
                }
            } else if (core != NULL && token_is_module_id(core)) {
                g_autofree char *head = g_strndup(w, lead);
                g_autofree char *words_of = module_id_words(core);
                clean = g_strdup_printf("%s%s", head, words_of);
            }
        }

        if (out->len > 0) g_string_append_c(out, ' ');
        g_string_append(out, clean != NULL ? clean : w);
    }

    return g_string_free(out, FALSE);
}

/* Turn a verb into a label when the layout does not give one:
   --decode-sib becomes "Decode SIB". */
static char *
verb_label(const char *verb)
{
    static const char *const acronyms[] = {
        "sib","mib","sib1","sib6","sib19","nas","5gs","gtp","gtpu","gtpc",
        "ngap","pfcp","s1ap","ss7","map","tcap","msu","ati","sri","sm",
        "imsi","suci","supi","msin","impi","apdu","ota","ussd","mmi","sba",
        "nrf","jwt","h2","oran","e2","e2sm","a1","ntn","gprs","gea","pdp",
        "apn","tetra","dmr","gsmr","tea","tdma","lpp","pids","ta","csi","rf",
        "cve","nr","lte","gsm","umts","vowifi","ike","eap","nai","epdg",
        "tr069","sst","snssai","nssai","prach","ssb","pci","arfcn","earfcn",
        "nprach","npss","nss","kc","a5","csg","iuh","lcid","dci","mac","rnti",
        "ra","pfi","sci1a","l2id","its","stk","sat","sim","spi","ad","ef",
        "tmsi","guti","pco","po","lwa","ip","id","api","xml","csv","tsv",
        "kml","pcap","ue","enb","gnb","c1","c0","esim","usim","aka","kseaf",
        "grx","stp","ssn","pc","plmn","eplmn","simjacker","henb","5g","4g",
        "2g","3g","s1","ng","x2",
    };
    g_autofree char *work = g_strdup(verb);
    char *s = work;
    while (*s == '-') s++;
    g_auto(GStrv) parts = g_strsplit(s, "-", -1);
    GString *out = g_string_new(NULL);

    for (int i = 0; parts[i] != NULL; i++) {
        const char *p = parts[i];
        gboolean up = FALSE;
        if (*p == '\0') continue;
        for (guint a = 0; a < G_N_ELEMENTS(acronyms); a++)
            if (g_ascii_strcasecmp(p, acronyms[a]) == 0) { up = TRUE; break; }
        if (out->len > 0) g_string_append_c(out, ' ');
        if (up) {
            g_autofree char *U = g_ascii_strup(p, -1);
            g_string_append(out, U);
        } else {
            g_autofree char *T = g_ascii_strdown(p, -1);
            if (T[0] != '\0') T[0] = g_ascii_toupper(T[0]);
            g_string_append(out, T);
        }
    }
    return g_string_free(out, FALSE);
}

/* ── verbs that need a typed argument ───────────────────────────────────
   A '~' verb cannot be defaulted, so it cannot be a plain button. Leaving it
   out of the GUI entirely - which is what used to happen - makes the action
   unreachable: six modules declared one and the operator had no way to run
   any of them. wifisting puts an entry next to the button for the same case
   (its WPA3 RECON "capture.pcap or wlan0" field), so this does that. */

static void
group_arg_clicked(GtkButton *button, gpointer user_data)
{
    GtkWidget *entry = g_object_get_data(G_OBJECT(button), "arg-entry");
    const char *text = entry != NULL
        ? gtk_editable_get_text(GTK_EDITABLE(entry)) : "";
    AppState *state = g_object_get_data(G_OBJECT(button), "state");

    (void) user_data;

    if (text == NULL || *text == '\0') {
        const char *verb = g_object_get_data(G_OBJECT(button), "verb");
        const char *set = g_object_get_data(G_OBJECT(button), "label");
        g_autofree char *title = (set != NULL && *set != '\0')
            ? g_strdup(set)
            : (verb != NULL ? verb_label(verb) : g_strdup("Nothing to run"));

        show_toast_full(state, title, "type a value first", "error");
        return;
    }

    /* group_verb_clicked already knows how to turn verb + args into a process,
       so hand it what was typed rather than duplicating that here. */
    g_object_set_data_full(G_OBJECT(button), "args", g_strdup(text), g_free);
    group_verb_clicked(button, user_data);
}

/* One entry + Run pair for a single '~' verb, in the same grammar as a
   button: verb [!] [:label]. */
static void
group_arg_row(AppState *state, const char *module_id, const char *spec,
              GtkWidget *status, GtkWidget *body, GtkWidget *result)
{
    g_autofree char *item = g_strdup(spec);
    g_autofree char *verb = NULL;
    g_autofree char *auto_lab = NULL;
    const char *label = NULL;
    gboolean privileged = FALSE;
    char *colon;
    char *eq;
    char *bang;
    GtkWidget *row;
    GtkWidget *entry;
    GtkWidget *btn;

    if (item == NULL) return;

    colon = strchr(item, ':');
    if (colon != NULL) { *colon = '\0'; label = colon + 1; }
    eq = strchr(item, '=');
    if (eq != NULL) *eq = '\0';          /* any declared default is unused */
    bang = strchr(item, '!');
    if (bang != NULL) { privileged = TRUE; *bang = '\0'; }

    verb = g_strdup(item);
    g_strstrip(verb);
    if (*verb == '\0') return;

    auto_lab = verb_label(verb);
    if (label == NULL || *label == '\0') label = auto_lab;

    row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    entry = gtk_entry_new();
    btn = gtk_button_new_with_label("Run");

    /* A form row reads as a sentence: what it is for, the field, the action.
       The caption is the job's own name and never the verb - a window in this
       toolkit does not show a command-line flag, and a placeholder that did
       was the last place one still leaked. */
    {
        GtkWidget *cap = gtk_label_new(label);
        gtk_widget_add_css_class(cap, "form-caption");
        gtk_label_set_xalign(GTK_LABEL(cap), 0.0f);
        gtk_widget_set_size_request(cap, 150, -1);
        gtk_widget_set_valign(cap, GTK_ALIGN_CENTER);
        gtk_box_append(GTK_BOX(row), cap);
    }
    gtk_widget_set_hexpand(entry, TRUE);
    gtk_widget_add_css_class(entry, "verb-arg-entry");
    gtk_widget_add_css_class(btn, "verb-button");
    gtk_widget_add_css_class(btn, "primary");

    g_object_set_data(G_OBJECT(btn), "state", state);
    g_object_set_data(G_OBJECT(btn), "module-id", (gpointer) module_id);
    g_object_set_data(G_OBJECT(btn), "status", status);
    if (result != NULL)
        g_object_set_data(G_OBJECT(btn), "result", result);
    g_object_set_data(G_OBJECT(btn), "privileged", GINT_TO_POINTER(privileged));
    g_object_set_data_full(G_OBJECT(btn), "verb", g_strdup(verb), g_free);
    g_object_set_data(G_OBJECT(btn), "arg-entry", entry);

    g_signal_connect(btn, "clicked", G_CALLBACK(group_arg_clicked), NULL);
    /* Enter runs it: a one-field form should submit on Enter. */
    g_signal_connect(entry, "activate", G_CALLBACK(group_arg_clicked), NULL);

    gtk_box_append(GTK_BOX(row), entry);
    gtk_box_append(GTK_BOX(row), btn);
    gtk_box_append(GTK_BOX(body), row);
}

/* Fill a card body with one button per verb in the spec, in one click. A verb
   prefixed with '~' needs an argument and gets an entry of its own. */
static gboolean
spec_has_buttons(const char *spec)
{
    g_auto(GStrv) items = NULL;
    if (spec == NULL) return FALSE;
    items = g_strsplit(spec, "|", -1);
    /* A '~' verb counts as content: it renders as an entry + Run instead of
       being skipped, so a card holding only one is not empty. Treating it as
       empty hid such cards, and any entry made only of them, entirely. */
    for (int i = 0; items[i] != NULL; i++)
        if (items[i][0] != '\0')
            return TRUE;
    return FALSE;
}

static void
group_fill(AppState *state, const char *module_id, const char *spec,
           GtkWidget *status, GtkWidget *body, gboolean primary_first,
           GtkWidget *result)
{
    GtkWidget *flow = gtk_flow_box_new();
    gboolean primary_done = FALSE;
    /* '~' verbs collected during the pass, built after the flow so they sit
       under the buttons rather than above them. */
    GPtrArray *arg_specs = g_ptr_array_new_with_free_func(g_free);

    gtk_flow_box_set_selection_mode(GTK_FLOW_BOX(flow), GTK_SELECTION_NONE);
    gtk_flow_box_set_column_spacing(GTK_FLOW_BOX(flow), 8);
    gtk_flow_box_set_row_spacing(GTK_FLOW_BOX(flow), 8);
    gtk_flow_box_set_max_children_per_line(GTK_FLOW_BOX(flow), 4);

    if (spec != NULL) {
        g_auto(GStrv) items = g_strsplit(spec, "|", -1);
        for (int i = 0; items[i] != NULL; i++) {
            g_autofree char *item = NULL;
            g_autofree char *verb = NULL;
            g_autofree char *def = NULL;
            g_autofree char *auto_lab = NULL;
            const char *label = NULL;
            const char *lab_ptr = NULL;
            gboolean privileged = FALSE;
            GtkWidget *btn;
            GtkWidget *child;
            char *colon;
            char *eq;
            char *bang;

            if (*items[i] == '\0') continue;
            /* A leading '~' marks a verb whose value cannot be defaulted
               safely. It gets an entry of its own after the buttons, rather
               than being dropped from the GUI entirely. */
            if (*items[i] == '~') {
                g_ptr_array_add(arg_specs, g_strdup(items[i] + 1));
                continue;
            }

            /* Entry grammar: verb [!] [=default] [:label]. The default may
               hold several space-separated arguments. */
            item = g_strdup(items[i]);
            colon = strchr(item, ':');
            if (colon != NULL) { *colon = '\0'; lab_ptr = colon + 1; }
            eq = strchr(item, '=');
            if (eq != NULL) { *eq = '\0'; def = g_strdup(eq + 1); }
            bang = strchr(item, '!');
            if (bang != NULL) { privileged = TRUE; *bang = '\0'; }

            verb = g_strdup(item);
            g_strstrip(verb);
            auto_lab = verb_label(verb);
            label = (lab_ptr != NULL && *lab_ptr != '\0') ? lab_ptr : auto_lab;

            btn = gtk_button_new_with_label(label);
            gtk_widget_add_css_class(btn, "verb-button");
            if (primary_first && !primary_done) {
                gtk_widget_add_css_class(btn, "primary");
                primary_done = TRUE;
            }
            gtk_widget_set_tooltip_text(btn, verb);
            g_object_set_data(G_OBJECT(btn), "state", state);
            g_object_set_data(G_OBJECT(btn), "module-id", (gpointer) module_id);
            g_object_set_data(G_OBJECT(btn), "status", status);
            if (result != NULL)
                g_object_set_data(G_OBJECT(btn), "result", result);
            g_object_set_data(G_OBJECT(btn), "privileged",
                              GINT_TO_POINTER(privileged));
            g_object_set_data_full(G_OBJECT(btn), "verb", g_strdup(verb), g_free);
            if (def != NULL)
                g_object_set_data_full(G_OBJECT(btn), "args",
                                       g_strdup(def), g_free);
            g_signal_connect(btn, "clicked",
                             G_CALLBACK(group_verb_clicked), NULL);

            child = gtk_flow_box_child_new();
            gtk_flow_box_child_set_child(GTK_FLOW_BOX_CHILD(child), btn);
            gtk_flow_box_append(GTK_FLOW_BOX(flow), child);
        }
    }

    gtk_box_append(GTK_BOX(body), flow);

    /* The verbs that needed an argument, each with its own entry. */
    for (guint i = 0; i < arg_specs->len; i++)
        group_arg_row(state, module_id, g_ptr_array_index(arg_specs, i),
                      status, body, result);
    g_ptr_array_unref(arg_specs);
}

/* Build a group as one or more titled cards.
 *
 * A spec may name sections with a leading '#':
 *     "#CONTROLS|--scan:Start scan|--stop:Stop scan|#SURVEY|--list:List Cells"
 * Each section becomes its own card, which is how wifisting's module pages
 * read: a card per job - controls, then status, then results - rather than
 * one undifferentiated row of buttons. Modules differ in how many jobs they
 * have, so that belongs in the data, not in per-module C.
 *
 * A spec with no '#' keeps the old shape exactly: a single card titled with
 * the group's own name, which is already the submenu entry's name. */
static GtkWidget *
build_group_cards(AppState *state, const char *module_id, const char *title,
                  const char *spec, GtkWidget *status, gboolean primary_first)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    g_auto(GStrv) sections = g_strsplit(spec != NULL ? spec : "", "#", -1);
    gboolean any = FALSE;

    for (int s = 0; sections[s] != NULL; s++) {
        const char *text = sections[s];
        const char *heading = title;
        g_autofree char *named = NULL;

        if (s == 0) {
            /* Anything before the first '#': the group's own card. Usually
               empty for a sectioned spec, so it is skipped. */
            if (!spec_has_buttons(text)) continue;
        } else {
            /* "#Name|items" - the name runs up to the first '|'. */
            const char *bar = strchr(text, '|');
            if (bar == NULL) continue;
            named = g_strndup(text, (gsize)(bar - text));
            g_strstrip(named);
            if (*named != '\0') heading = named;
            text = bar + 1;
            if (!spec_has_buttons(text)) continue;
        }

        GtkWidget *body, *result;
        ResultRect *rr = NULL;
        GtkWidget *card = verb_card(heading, &body);

        result = result_rect_new(state, &rr);
        group_fill(state, module_id, text, status, body,
                   primary_first && !any, result);
        /* Inside the same rectangle as the buttons, under them. */
        gtk_box_append(GTK_BOX(body), result);
        gtk_box_append(GTK_BOX(box), card);
        any = TRUE;
    }

    return box;
}

static GtkWidget *
build_group_card(AppState *state, const char *module_id, const char *title,
                 const char *spec, GtkWidget *status, gboolean primary_first)
{
    GtkWidget *body, *result;
    ResultRect *rr = NULL;
    GtkWidget *card = verb_card(title, &body);

    result = result_rect_new(state, &rr);
    group_fill(state, module_id, spec, status, body, primary_first, result);
    gtk_box_append(GTK_BOX(body), result);
    return card;
}

/* ---- module output card -------------------------------------------
   Every module view carries one of these under its buttons, so a run's
   stdout/stderr appears next to the control that started it instead of
   only in the app-wide Events drawer - which is off-screen on a short
   window and made working buttons look broken.
   One buffer per page is shared by the cards in each view, so switching
   views keeps the output visible. The card lives INSIDE the view's
   scrolled content: a strip appended to the page itself got squeezed to
   zero height, because a module page's content does not shrink. */
static GtkTextBuffer *
output_buffer_new(void)
{
    return gtk_text_buffer_new(NULL);
}

/* Append a line and keep every on-screen card for this buffer pinned to
   the bottom. One buffer feeds one card per view (Overview, Packages,
   System...); scrolling only the most recently built card left the card
   the operator was actually looking at frozen at the top, so fresh output
   sat below the fold and the button read as doing nothing. */
/* Pin the card to its newest line. */
static void
console_scroll_bottom(GtkWidget *list)
{
    GtkWidget *sw = gtk_widget_get_ancestor(list, GTK_TYPE_SCROLLED_WINDOW);
    GtkAdjustment *adj;

    if (sw == NULL) return;
    adj = gtk_scrolled_window_get_vadjustment(GTK_SCROLLED_WINDOW(sw));
    if (adj == NULL) return;
    gtk_adjustment_set_value(adj,
        gtk_adjustment_get_upper(adj) - gtk_adjustment_get_page_size(adj));
}

/* One line of output, as a row rather than a line of monospace text.
 *
 * The card used to be a GtkTextView in a monospace font, which made every
 * module look like it was dumping to a terminal - at odds with the rest of
 * the interface, where nothing else is monospace and nothing else is a black
 * box. Severity is carried by a coloured marker and the message is set in
 * the interface font, so a run reads as activity rather than as a console.
 *
 * The one thing that stays monospace is the command echo, because that IS a
 * command line and should look like one. */
/* Is this line a record the module printed as `key<TAB>value`?
 *
 * Almost every verb in the tree answers in TSV, and echoing that as a sentence
 * with the tab flattened to spaces is what made a result read like a log. A
 * record has a shape, so it is drawn with one: the key is a dim caption on the
 * left, the value is the thing to read. The rule is deliberately narrow - one
 * tab, a key of word characters, dashes and dots, and no spaces in the key -
 * so a prose line that happens to contain a tab is still shown as prose. */
static gboolean
console_tsv_split(const char *text, char **key_out, const char **val_out)
{
    const char *tab = strchr(text, '\t');
    if (tab == NULL || tab == text) return FALSE;
    for (const char *c = text; c < tab; c++) {
        if (!(g_ascii_isalnum(*c) || *c == '_' || *c == '-' || *c == '.' ||
              *c == ' '))
            return FALSE;
    }
    /* A single leading space is an indent from the module, not part of the key. */
    *key_out = g_strndup(text, (gsize)(tab - text));
    g_strstrip(*key_out);
    if (**key_out == '\0') { g_free(*key_out); *key_out = NULL; return FALSE; }
    *val_out = tab + 1;
    return TRUE;
}

static GtkWidget *mod_arg_row(AppState *state, const char *module_id,
                              GtkWidget *status, const char *button_label,
                              const char *verb, const char *placeholder,
                              const char *hint);
static GtkWidget *mod_arg_choices(AppState *state, const char *module_id,
                                  GtkWidget *status, const char *caption,
                                  const char *placeholder, const char *hint,
                                  const char *const *verbs,
                                  const char *const *labels, int n);
static void mod_card_begin(GtkWidget *result);
static void mod_card_end(void);
static gboolean record_copy_reset(gpointer button);
static void record_copy_clicked(GtkButton *button, gpointer user_data);

/* ── tabular answers ────────────────────────────────────────────────────
 *
 * Most module lists are tables: the first line the module prints is its column
 * names, and every line after that has the same fields. Drawn as a table, that
 * reads at a glance; drawn as a stack of identity rows it reads as noise, with
 * the header line pretending to be a record.
 *
 * So the first row of three or more fields opens a table: its fields become the
 * column headings, and every row with the same field count joins it. Column
 * widths are the content's own - the grid sizes itself - and the last column
 * takes the slack, because the last field of a module's record is usually the
 * description and the description is the thing that can wrap.
 */
static void
table_cell_add(GtkWidget *grid, const char *text, int col, int row,
               gboolean header, gboolean grow)
{
    g_autofree char *clean = display_text(text != NULL ? text : "");
    GtkWidget *label = gtk_label_new(clean);

    /* A last column of prose should wrap; a column of identifiers must not. */
    gtk_widget_add_css_class(label, header ? "table-head" : "table-cell");
    gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
    if (header)
        gtk_label_set_ellipsize(GTK_LABEL(label), PANGO_ELLIPSIZE_NONE);
    else
        gtk_label_set_ellipsize(GTK_LABEL(label), PANGO_ELLIPSIZE_END);
    /* A column of counts is a column of digits and nothing else; an identifier
       that merely starts with one ("5g-privacy") is not a number and stays
       left, where a reader looks for a name. */
    if (!header && text != NULL && *text != '\0') {
        gboolean numeric = TRUE;
        for (const char *c = text; *c != '\0'; c++)
            if (!g_ascii_isdigit(*c)) { numeric = FALSE; break; }
        if (numeric) {
            gtk_label_set_xalign(GTK_LABEL(label), 1.0f);
            gtk_widget_set_halign(label, GTK_ALIGN_END);
        }
    }
    if (!header) gtk_label_set_selectable(GTK_LABEL(label), TRUE);
    if (grow) {
        gtk_label_set_ellipsize(GTK_LABEL(label), PANGO_ELLIPSIZE_NONE);
        gtk_label_set_wrap(GTK_LABEL(label), TRUE);
        gtk_label_set_wrap_mode(GTK_LABEL(label), PANGO_WRAP_WORD_CHAR);
        gtk_widget_set_hexpand(label, TRUE);
    }
    gtk_grid_attach(GTK_GRID(grid), label, col, row, 1, 1);
}

/* Add one row of fields to a tabular answer. */
static void
table_body(GtkWidget *list, GtkWidget *grid, GStrv fields, int cols)
{
    AppState *state = g_object_get_data(G_OBJECT(list), "state");
    int row = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(grid), "rows"));
    int col;

    for (col = 0; col < cols; col++)
        table_cell_add(grid, fields[col], col, row, FALSE, col == cols - 1);

    if (state != NULL) {
        g_autoptr(GString) joined = g_string_new(NULL);
        for (col = 0; col < cols; col++) {
            if (col > 0) g_string_append_c(joined, '\t');
            g_string_append(joined, fields[col] != NULL ? fields[col] : "");
        }
        {
            GtkWidget *copy = gtk_button_new_with_label("Copy");
            gtk_widget_add_css_class(copy, "record-copy");
            gtk_widget_add_css_class(copy, "flat");
            gtk_widget_set_valign(copy, GTK_ALIGN_CENTER);
            g_object_set_data(G_OBJECT(copy), "state", state);
            g_signal_connect(copy, "clicked", G_CALLBACK(record_copy_clicked),
                             (gpointer) g_strdup(joined->str));
            gtk_grid_attach(GTK_GRID(grid), copy, cols, row, 1, 1);
        }
    }
    g_object_set_data(G_OBJECT(grid), "rows", GINT_TO_POINTER(row + 1));
    {
        gint n = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(list), "records"));
        g_object_set_data(G_OBJECT(list), "records", GINT_TO_POINTER(n + 1));
    }
}

/* Copy one record to the clipboard. A record is worth keeping - an IMSI, a
   chain, a byte string - and selecting a label by hand is not a control. */
static void
record_copy_clicked(GtkButton *button, gpointer user_data)
{
    const char *text = user_data;
    AppState *state = g_object_get_data(G_OBJECT(button), "state");
    GdkClipboard *clip;

    if (text == NULL || state == NULL) return;
    clip = gdk_display_get_clipboard(gtk_widget_get_display(state->window));
    gdk_clipboard_set_text(clip, text);
    gtk_button_set_label(button, "Copied");
    g_timeout_add_seconds(2, (GSourceFunc) record_copy_reset, button);
}

/* The Copy label is a receipt: it says Copied, then goes back to saying what
   it does, so the row still offers the action a second time. */
static gboolean
record_copy_reset(gpointer button)
{
    if (GTK_IS_BUTTON(button)) gtk_button_set_label(GTK_BUTTON(button), "Copy");
    return G_SOURCE_REMOVE;
}

static gboolean
stop_button_reset(gpointer button)
{
    if (GTK_IS_BUTTON(button)) gtk_button_set_label(GTK_BUTTON(button), "Stop");
    return G_SOURCE_REMOVE;
}

/* One record, drawn as a record: identity, badges, the rest as meta. */
static void
record_row_append(GtkWidget *list, const char *text, GStrv fields)
{
    AppState *state = g_object_get_data(G_OBJECT(list), "state");
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *head = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *mark = gtk_label_new("\u25cf");
    g_autofree char *ident_txt = display_text(fields[0]);
    GtkWidget *ident = gtk_label_new(ident_txt);
    g_autoptr(GString) meta = g_string_new(NULL);
    int used = 1;

    gtk_widget_add_css_class(row, "record-row");
    gtk_widget_add_css_class(mark, "record-mark");
    gtk_widget_add_css_class(ident, "record-id");
    gtk_label_set_xalign(GTK_LABEL(mark), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(ident), 0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(ident), PANGO_ELLIPSIZE_MIDDLE);
    gtk_label_set_selectable(GTK_LABEL(ident), TRUE);
    gtk_widget_set_valign(mark, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(head), mark);
    gtk_box_append(GTK_BOX(head), ident);

    /* A short second field with no spaces is a classifier - imsi, guti, PASS -
       and belongs in a chip beside the identity, where it reads at a glance. */
    if (fields[1] != NULL && !strchr(fields[1], ' ') && strlen(fields[1]) <= 18 &&
        !g_ascii_isdigit(fields[1][0])) {
        g_autofree char *badge_txt = display_text(fields[1]);
        GtkWidget *badge = gtk_label_new(badge_txt);
        gtk_widget_add_css_class(badge, "record-badge");
        gtk_label_set_xalign(GTK_LABEL(badge), 0.0f);
        gtk_box_append(GTK_BOX(head), badge);
        used = 2;
    }

    for (int i = used; fields[i] != NULL; i++) {
        if (g_strstrip(fields[i])[0] == '\0') continue;
        g_autofree char *cell = display_text(fields[i]);
        if (meta->len > 0) g_string_append(meta, "  \u00b7  ");
        g_string_append(meta, cell);
    }

    if (state != NULL) {
        GtkWidget *copy = gtk_button_new_with_label("Copy");
        gtk_widget_add_css_class(copy, "record-copy");
        gtk_widget_add_css_class(copy, "flat");
        gtk_widget_set_valign(copy, GTK_ALIGN_START);
        gtk_widget_set_hexpand(copy, FALSE);
        gtk_widget_set_halign(copy, GTK_ALIGN_END);
        g_object_set_data(G_OBJECT(copy), "state", state);
        g_signal_connect(copy, "clicked", G_CALLBACK(record_copy_clicked),
                         (gpointer) g_strdup(text));
        gtk_box_append(GTK_BOX(head), copy);
        gtk_widget_set_hexpand(ident, TRUE);
    }

    gtk_box_append(GTK_BOX(row), head);

    if (meta->len > 0) {
        GtkWidget *m = gtk_label_new(meta->str);
        gtk_widget_add_css_class(m, "record-meta");
        gtk_label_set_xalign(GTK_LABEL(m), 0.0f);
        gtk_label_set_wrap(GTK_LABEL(m), TRUE);
        gtk_label_set_wrap_mode(GTK_LABEL(m), PANGO_WRAP_WORD_CHAR);
        gtk_widget_set_margin_start(m, 18);
        gtk_box_append(GTK_BOX(row), m);
    }

    gtk_box_append(GTK_BOX(list), row);
    {
        gint n = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(list), "records"));
        g_object_set_data(G_OBJECT(list), "records", GINT_TO_POINTER(n + 1));
    }
}

static void
console_row_append(GtkWidget *list, const char *text)
{
    const char *cls = "log-note";
    const char *marker = "\u25cf";     /* a dot, as in the status strip */
    const char *body = text;
    GtkWidget *row, *glyph, *msg;
    g_autofree char *tkey = NULL;
    const char *tval = NULL;

    if (text == NULL || *text == '\0') return;

    /* A card has one line saying how the run ended - the summary - so the
       trailer is not repeated as a record under a table already wearing it,
       and neither is the command echo: the button that ran it is directly
       above, carrying the same words, and a shell line in a record list reads
       as a leak from another program. */
    if (g_object_get_data(G_OBJECT(list), "no-pin") != NULL &&
        (g_str_has_prefix(text, "$ ") ||
         g_str_has_prefix(text, "-- done") || g_str_has_prefix(text, "-- failed") ||
         g_str_has_prefix(text, "-- stopped")))
        return;

    /* Three or more tab-separated fields: a table. The first such row is the
       module's own column headings, and it says how wide the table is; a later
       row with a different width is not part of it and is drawn as a record. */
    {
        g_auto(GStrv) fields = g_strsplit(text, "\t", -1);
        int n = g_strv_length(fields);
        GtkWidget *grid = g_object_get_data(G_OBJECT(list), "answer-grid");
        int cols = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(list),
                                                     "answer-cols"));

        if (n >= 3) {
            if (grid == NULL) {
                gtk_box_append(GTK_BOX(list), gtk_separator_new(GTK_ORIENTATION_HORIZONTAL));
                grid = gtk_grid_new();
                gtk_widget_add_css_class(grid, "answer-table");
                gtk_grid_set_column_spacing(GTK_GRID(grid), 18);
                gtk_grid_set_row_spacing(GTK_GRID(grid), 3);
                g_object_set_data(G_OBJECT(grid), "rows", GINT_TO_POINTER(1));
                g_object_set_data(G_OBJECT(list), "answer-grid", grid);
                g_object_set_data(G_OBJECT(list), "answer-cols",
                                  GINT_TO_POINTER(n));
                for (int c = 0; c < n; c++)
                    table_cell_add(grid, fields[c], c, 0, TRUE, c == n - 1);
                gtk_box_append(GTK_BOX(list), grid);
                return;
            }
            if (n == cols) {
                table_body(list, grid, fields, cols);
                return;
            }
        }
    }

    /* Two fields are the parts of one answer: a name and its value. */
    if (console_tsv_split(text, &tkey, &tval)) {
        g_autofree char *val_txt = display_text(tval);
        GtkWidget *k = gtk_label_new(tkey);
        GtkWidget *v = gtk_label_new(val_txt);

        row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
        gtk_widget_add_css_class(row, "answer-row");
        gtk_widget_add_css_class(k, "answer-key");
        gtk_widget_add_css_class(v, "answer-value");
        gtk_label_set_xalign(GTK_LABEL(k), 0.0f);
        gtk_label_set_xalign(GTK_LABEL(v), 0.0f);
        gtk_label_set_wrap(GTK_LABEL(v), TRUE);
        gtk_label_set_wrap_mode(GTK_LABEL(v), PANGO_WRAP_WORD_CHAR);
        gtk_label_set_selectable(GTK_LABEL(v), TRUE);
        gtk_widget_set_valign(k, GTK_ALIGN_START);
        gtk_widget_set_size_request(k, 172, -1);
        gtk_widget_set_hexpand(v, TRUE);
        gtk_box_append(GTK_BOX(row), k);
        gtk_box_append(GTK_BOX(row), v);
        gtk_box_append(GTK_BOX(list), row);
        {
            gint n = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(list), "records"));
            g_object_set_data(G_OBJECT(list), "records", GINT_TO_POINTER(n + 1));
        }
        return;
    }

    if (g_str_has_prefix(text, "$ ")) {
        cls = "log-cmd"; marker = "$"; body = text + 2;
    } else if (g_str_has_prefix(text, "ERROR")) {
        cls = "log-error"; body = text + 5;
    } else if (g_str_has_prefix(text, "[err]")) {
        cls = "log-error"; body = text + 5;
    } else if (g_str_has_prefix(text, "[warn]")) {
        cls = "log-warn"; body = text + 6;
    } else if (g_str_has_prefix(text, "[ok]")) {
        cls = "log-ok"; body = text + 4;
    } else if (g_str_has_prefix(text, "[info]")) {
        cls = "log-info"; body = text + 6;
    } else if (g_str_has_prefix(text, "-- failed")) {
        cls = "log-error";
    } else if (g_str_has_prefix(text, "-- done")) {
        cls = "log-ok";
    }
    while (*body == ' ' || *body == '\t') body++;

    row   = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    glyph = gtk_label_new(marker);
    {
        g_autofree char *readable = display_text(body);
        msg = gtk_label_new(readable);
    }

    gtk_widget_add_css_class(row, "log-row");
    gtk_widget_add_css_class(row, cls);
    gtk_widget_add_css_class(glyph, "log-glyph");
    gtk_widget_add_css_class(msg, "log-msg");

    gtk_label_set_xalign(GTK_LABEL(glyph), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(msg), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(msg), TRUE);
    gtk_label_set_wrap_mode(GTK_LABEL(msg), PANGO_WRAP_WORD_CHAR);
    gtk_label_set_selectable(GTK_LABEL(msg), TRUE);
    gtk_widget_set_valign(glyph, GTK_ALIGN_START);
    gtk_widget_set_size_request(glyph, 14, -1);
    gtk_widget_set_hexpand(msg, TRUE);

    gtk_box_append(GTK_BOX(row), glyph);
    gtk_box_append(GTK_BOX(row), msg);
    gtk_box_append(GTK_BOX(list), row);
}

/* ── stopping a run ─────────────────────────────────────────────────────
 *
 * A scan, a sweep, a capture or a storm runs until it is done or until the
 * operator has seen enough, and a page whose only control is "start" leaves
 * them closing the window. So every run is interruptible, and the interrupt
 * is honest about what it did.
 *
 * Signals go to the whole tree, not just the process the module started: a
 * module's long verb is usually a shell that has spawned a scanner, and
 * killing the shell alone leaves the scanner holding the radio. The tree is
 * walked in /proc rather than assumed, so no `setsid` and no change to how a
 * module is spawned was needed.
 *
 * First press asks (SIGTERM); pressing again insists (SIGKILL). Neither is
 * silent: the run says `-- stopping` and then reports `stopped`, which is a
 * verdict, not a fault - a cancelled run is not a failed one.
 */
static void
kill_tree(pid_t root, int sig)
{
    /* /proc/<pid>/stat holds `pid (comm) state ppid ...`, and comm can contain
       spaces and parentheses, so the parent is read from the LAST ')'. */
    GHashTable *parent_of = g_hash_table_new(g_direct_hash, g_direct_equal);
    GPtrArray *order = g_ptr_array_new();          /* children before parents */
    g_autoptr(GDir) d = g_dir_open("/proc", 0, NULL);
    const char *name;
    GQueue queue = G_QUEUE_INIT;

    if (d == NULL) { kill(root, sig); return; }

    while ((name = g_dir_read_name(d)) != NULL) {
        g_autofree char *path = NULL;
        g_autofree char *data = NULL;
        const char *close_paren;
        long pid, ppid;

        if (!g_ascii_isdigit(name[0])) continue;
        pid = strtol(name, NULL, 10);
        if (pid <= 0) continue;

        path = g_strdup_printf("/proc/%ld/stat", pid);
        if (!g_file_get_contents(path, &data, NULL, NULL)) continue;
        close_paren = strrchr(data, ')');
        if (close_paren == NULL) continue;
        if (sscanf(close_paren + 1, " %*c %ld", &ppid) != 1) continue;
        g_hash_table_insert(parent_of, GINT_TO_POINTER((int) pid),
                            GINT_TO_POINTER((int) ppid));
    }
    /* Breadth-first from the root, collecting descendants. */
    g_queue_push_tail(&queue, GINT_TO_POINTER((int) root));
    while (!g_queue_is_empty(&queue)) {
        int pid = GPOINTER_TO_INT(g_queue_pop_head(&queue));
        GHashTableIter it;
        gpointer k, v;

        g_hash_table_iter_init(&it, parent_of);
        while (g_hash_table_iter_next(&it, &k, &v)) {
            if (GPOINTER_TO_INT(v) != pid) continue;
            g_ptr_array_add(order, k);
            g_queue_push_tail(&queue, k);
        }
        if (order->len > 4096) break;
    }

    /* Deepest first: a parent that dies re-parents its children and the walk
       would stop seeing them. */
    for (gint i = (gint) order->len - 1; i >= 0; i--)
        kill((pid_t) GPOINTER_TO_INT(g_ptr_array_index(order, i)), sig);
    kill(root, sig);

    g_ptr_array_unref(order);
    g_hash_table_destroy(parent_of);
}

/* Ask a run to stop, or insist. Returns FALSE when there is nothing running
   that this control is allowed to stop. */
static gboolean
action_stop(ActionRun *run, gboolean force)
{
    g_autofree char *pid_text = NULL;
    pid_t pid;

    if (run == NULL || run->proc == NULL) return FALSE;
    pid_text = g_strdup(g_subprocess_get_identifier(run->proc));
    if (pid_text == NULL || *pid_text == '\0') return FALSE;
    pid = (pid_t) strtol(pid_text, NULL, 10);
    if (pid <= 0) return FALSE;

    run->stopped = TRUE;
    if (run->output != NULL)
        console_append(run->output,
                       force ? "-- stopping: force" : "-- stopping");
    if (force) {
        kill_tree(pid, SIGKILL);
    } else {
        status_label_set(run->status_label, "Stopping", "status-running");
        kill_tree(pid, SIGTERM);
    }
    return TRUE;
}

static void
console_append(GtkTextBuffer *buf, const char *text)
{
    GtkTextIter end;
    GPtrArray *views;
    g_auto(GStrv) lines = NULL;

    if (buf == NULL || text == NULL) return;

    /* The buffer stays the handle every caller already passes around, and
       still accumulates the text, but the cards render rows built here. */
    gtk_text_buffer_get_end_iter(buf, &end);
    gtk_text_buffer_insert(buf, &end, text, -1);
    gtk_text_buffer_insert(buf, &end, "\n", -1);

    views = g_object_get_data(G_OBJECT(buf), "output-views");
    if (views == NULL) return;

    lines = g_strsplit(text, "\n", -1);
    for (guint i = 0; i < views->len; i++) {
        GtkWidget *list = g_ptr_array_index(views, i);
        if (list == NULL) continue;
        for (guint j = 0; lines[j] != NULL; j++) {
            if (*lines[j] == '\0') continue;
            console_row_append(list, lines[j]);
        }
        /* Append whether or not the page is on screen - the text has to be
           there when it is shown - but only scroll what is visible.

           An answer list is not pinned to the bottom: a list of records is read
           from the first one, and the newest thing in it is not the interesting
           thing the way the newest log line is. */
        if (gtk_widget_get_mapped(list) &&
            g_object_get_data(G_OBJECT(list), "no-pin") == NULL)
            console_scroll_bottom(list);
    }
}

static void
console_clear_clicked(GtkButton *button, gpointer user_data)
{
    GPtrArray *views;

    (void) button;
    if (user_data == NULL) return;
    gtk_text_buffer_set_text(GTK_TEXT_BUFFER(user_data), "", -1);

    views = g_object_get_data(G_OBJECT(user_data), "output-views");
    if (views == NULL) return;
    for (guint i = 0; i < views->len; i++) {
        GtkWidget *list = g_ptr_array_index(views, i);
        GtkWidget *child;
        if (list == NULL) continue;
        child = gtk_widget_get_first_child(list);
        while (child != NULL) {
            GtkWidget *next = gtk_widget_get_next_sibling(child);
            gtk_box_remove(GTK_BOX(list), child);
            child = next;
        }
    }
}

static void
console_view_destroyed(GtkWidget *view, gpointer buf)
{
    GPtrArray *views;
    if (buf == NULL) return;
    views = g_object_get_data(G_OBJECT(buf), "output-views");
    if (views != NULL)
        g_ptr_array_remove(views, view);
}

/* ── the answer ─────────────────────────────────────────────────────────
 *
 * Every card that can run something owns the place its answer appears, and
 * the answer is DATA IN THAT CARD, not a log well with a caption over it.
 * The operator's rule, given three times, is that a card reads like the
 * workbook page it replaces: controls in a row at the top, then the answer
 * filling the rest of the same surface.
 *
 * So there is no RESULT caption, no boxed pseudo-terminal and no rectangle
 * that exists only to hold text. What a card grows, in order, is:
 *   - a hairline, because the answer is a different thing from the controls;
 *   - a summary line: how many records, and how the run ended;
 *   - the records themselves, one of two shapes.
 *
 * The shape is decided by what the module printed, because the module already
 * knows: a two-field `key<TAB>value` row is a field of one answer and is drawn
 * as a labelled value; a tab-separated row of three or more fields is one
 * record among many and is drawn as a record - its first field as the identity,
 * the rest as a meta line, and a Copy action for the whole line.
 */
static void
result_rows_clear(ResultRect *rr)
{
    GtkWidget *child;

    if (rr == NULL || rr->rows == NULL) return;
    g_object_set_data(G_OBJECT(rr->rows), "answer-grid", NULL);
    g_object_set_data(G_OBJECT(rr->rows), "answer-cols", NULL);
    g_object_set_data(G_OBJECT(rr->rows), "records", GINT_TO_POINTER(0));
    child = gtk_widget_get_first_child(rr->rows);
    while (child != NULL) {
        GtkWidget *next = gtk_widget_get_next_sibling(child);
        gtk_box_remove(GTK_BOX(rr->rows), child);
        child = next;
    }
}

static gint
result_rows_count(ResultRect *rr)
{
    if (rr == NULL || rr->rows == NULL) return 0;
    return GPOINTER_TO_INT(g_object_get_data(G_OBJECT(rr->rows), "records"));
}

/* Find the newest run writing into this rect's buffer. Matched on the buffer
   itself, which is the one handle the run and the card share. */
static ActionRun *
result_running(AppState *state, ResultRect *rr)
{
    if (state == NULL || state->running == NULL || rr == NULL) return NULL;
    for (guint i = state->running->len; i > 0; i--) {
        ActionRun *a = g_ptr_array_index(state->running, i - 1);
        if (a != NULL && a->output == rr->buf) return a;
    }
    return NULL;
}

static void
result_stop_clicked(GtkButton *button, gpointer user_data)
{
    ResultRect *rr = user_data;
    AppState *state = g_object_get_data(G_OBJECT(button), "state");
    ActionRun *a = result_running(state, rr);

    /* If the card cannot find its own run - a buffer that moved, a page that
       was rebuilt - fall back to the newest run on the machine, because the
       operator pressed Stop on the only thing they are watching. A Stop that
       silently does nothing is worse than a Stop that stops too much, and it
       says which run it stopped. */
    if (a == NULL && state != NULL && state->running != NULL &&
        state->running->len > 0)
        a = g_ptr_array_index(state->running, state->running->len - 1);
    if (a == NULL) {
        gtk_button_set_label(button, "Nothing to stop");
        g_timeout_add_seconds(2, (GSourceFunc) stop_button_reset, button);
        return;
    }

    /* First press asks, second press insists. The label says which it will do,
       so nobody has to guess whether the first press was enough. */
    if (g_object_get_data(G_OBJECT(button), "insisting") != NULL) {
        action_stop(a, TRUE);
        gtk_button_set_label(button, "Stopping");
        gtk_widget_set_sensitive(GTK_WIDGET(button), FALSE);
        return;
    }
    action_stop(a, FALSE);
    g_object_set_data(G_OBJECT(button), "insisting", GINT_TO_POINTER(1));
    gtk_button_set_label(button, "Force Stop");
    gtk_widget_set_tooltip_text(GTK_WIDGET(button),
        "Pressing again kills the run outright, including anything it started.");
}

/* A run is starting in this rect: clear what the last one left, hide the
   invitation, offer the Stop, and point the page's output at this card so the
   run's records land here and not in a card on another view. */
/* One line that says what is in the card. The RESULT heading said nothing;
   this says how many records there are, which is what a reader wants first. */
static void
result_summary_set(ResultRect *rr, const char *text)
{
    if (rr == NULL || rr->summary == NULL) return;
    gtk_label_set_text(GTK_LABEL(rr->summary), text != NULL ? text : "");
    gtk_widget_set_visible(rr->summary, text != NULL);
}

static void
result_begin(AppState *state, ResultRect *rr)
{
    if (rr == NULL) return;
    result_rows_clear(rr);
    if (rr->idle != NULL) gtk_widget_set_visible(rr->idle, FALSE);
    result_summary_set(rr, "running\u2026");
    if (rr->stop != NULL) {
        g_object_set_data(G_OBJECT(rr->stop), "insisting", NULL);
        gtk_button_set_label(GTK_BUTTON(rr->stop), "Stop");
        gtk_widget_set_tooltip_text(rr->stop,
            "Asks the run and everything it started to stop.");
        gtk_widget_set_sensitive(rr->stop, TRUE);
        gtk_widget_set_visible(rr->stop, TRUE);
    }
    if (state != NULL) {
        state->active_output = rr->buf;
        g_object_set_data(G_OBJECT(rr->stop), "state", state);
    }
}

/* The run has ended: the Stop no longer belongs on screen, and an empty result
   goes back to inviting the next press rather than showing a blank rectangle. */
/* A short answer does not need a table. One or two records - a path, a number,
   a verdict - are read once and then belong where a receipt belongs: in a toast
   that says what happened, with the card keeping the same sentence as its one
   line. The Events drawer still has the full output, so nothing is lost; what
   is avoided is a card that fills up with a single row and pushes the next one
   off the page. */
static void
result_compact(ResultRect *rr, const char *receipt)
{
    if (rr == NULL) return;
    result_rows_clear(rr);
    if (rr->idle != NULL) gtk_widget_set_visible(rr->idle, FALSE);
    result_summary_set(rr, receipt);
}

/* The printable part of what a run said: the values of its records, or the
   prose lines it printed, joined into one sentence. */
static gboolean
run_receipt(ActionRun *run, char **out)
{
    g_auto(GStrv) lines = NULL;
    GString *receipt = g_string_new(NULL);
    gboolean saw_error = run->saw_error;

    if (run->captured == NULL || run->captured->len == 0) return FALSE;

    lines = g_strsplit(run->captured->str, "\n", -1);
    for (int i = 0; lines[i] != NULL; i++) {
        const char *line = lines[i];
        g_autofree char *tkey = NULL;
        const char *tval = NULL;
        const char *part = line;
        g_autofree char *clean = NULL;

        if (*line == '\0') continue;
        if (g_str_has_prefix(line, "$ ") || g_str_has_prefix(line, "-- "))
            continue;

        if (console_tsv_split(line, &tkey, &tval)) part = tval;
        else if (g_str_has_prefix(part, "[info]")) part += 6;
        else if (g_str_has_prefix(part, "[ok]")) part += 4;
        while (*part == ' ' || *part == '\t') part++;

        clean = display_text(part);
        if (*clean == '\0') continue;
        if (receipt->len > 0) g_string_append(receipt, "  \u00b7  ");
        g_string_append(receipt, clean);
    }

    if (receipt->len == 0) {
        g_string_free(receipt, TRUE);
        return FALSE;
    }
    *out = g_string_free(receipt, FALSE);
    return !saw_error;
}

static void
result_end(ResultRect *rr)
{
    if (rr == NULL) return;
    if (rr->stop != NULL) {
        g_object_set_data(G_OBJECT(rr->stop), "insisting", NULL);
        gtk_button_set_label(GTK_BUTTON(rr->stop), "Stop");
        gtk_widget_set_sensitive(rr->stop, TRUE);
        gtk_widget_set_visible(rr->stop, FALSE);
    }
    if (rr->idle != NULL)
        gtk_widget_set_visible(rr->idle, result_rows_count(rr) == 0);
    {
        gint n = result_rows_count(rr);
        const char *verdict = g_object_get_data(G_OBJECT(rr->rows), "verdict");
        g_autofree char *t = (verdict != NULL && *verdict != '\0')
            ? g_strdup_printf("%d record%s  \u00b7  %s", n, n == 1 ? "" : "s", verdict)
            : g_strdup_printf("%d record%s", n, n == 1 ? "" : "s");
        result_summary_set(rr, n > 0 ? t : NULL);

        /* Read from the top: put this card at the top of the page it lives on. */
        if (n == 0) return;
        GtkWidget *sw = gtk_widget_get_ancestor(rr->rect, GTK_TYPE_SCROLLED_WINDOW);
        GtkWidget *page = sw != NULL ? gtk_scrolled_window_get_child(
                              GTK_SCROLLED_WINDOW(sw)) : NULL;

        if (page != NULL) {
            graphene_rect_t b;
            if (gtk_widget_compute_bounds(rr->rect, page, &b)) {
                GtkAdjustment *adj =
                    gtk_scrolled_window_get_vadjustment(GTK_SCROLLED_WINDOW(sw));
                if (adj != NULL)
                    gtk_adjustment_set_value(adj, MAX(0.0, b.origin.y - 12.0));
            }
        }
    }
}

static GtkWidget *
result_rect_new(AppState *state, ResultRect **out)
{
    ResultRect *rr = g_new0(ResultRect, 1);
    GtkWidget *rule = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    GtkWidget *head = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *scroll = gtk_scrolled_window_new();
    GtkWidget *rect = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);

    rr->rect = rect;
    rr->rows = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    g_object_set_data(G_OBJECT(rr->rows), "state", state);
    rr->buf     = gtk_text_buffer_new(NULL);
    rr->stop    = gtk_button_new_with_label("Stop");
    rr->idle    = gtk_label_new(NULL);
    rr->summary = gtk_label_new(NULL);

    gtk_widget_add_css_class(rect, "answer-body");
    gtk_widget_add_css_class(rule, "answer-rule");
    gtk_widget_add_css_class(rr->stop, "stop-inline");
    gtk_widget_add_css_class(rr->idle, "answer-idle");
    gtk_widget_add_css_class(rr->rows, "answer-rows");
    gtk_widget_add_css_class(rr->summary, "answer-summary");

    gtk_widget_set_hexpand(rr->summary, TRUE);
    gtk_label_set_xalign(GTK_LABEL(rr->summary), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(rr->idle), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(rr->idle), TRUE);
    /* One line, not a paragraph: a card that has never been used should look
       ready rather than empty, and the line leaves as soon as a record lands. */
    gtk_label_set_text(GTK_LABEL(rr->idle), "Nothing run in this card yet.");
    gtk_widget_set_visible(rr->stop, FALSE);
    gtk_widget_set_visible(rr->summary, FALSE);

    gtk_box_append(GTK_BOX(head), rr->summary);
    gtk_box_append(GTK_BOX(head), rr->stop);

    gtk_widget_set_margin_top(rr->rows, 2);
    gtk_widget_set_margin_bottom(rr->rows, 2);
    gtk_widget_set_valign(rr->rows, GTK_ALIGN_START);

    (void) scroll;   /* no inner scroller: the card grows, the page scrolls */
    gtk_widget_add_css_class(rr->rows, "answer-list");
    g_object_set_data(G_OBJECT(rr->rows), "no-pin", GINT_TO_POINTER(1));

    gtk_box_append(GTK_BOX(rect), rule);
    gtk_box_append(GTK_BOX(rect), rr->idle);
    gtk_box_append(GTK_BOX(rect), head);
    gtk_box_append(GTK_BOX(rect), rr->rows);

    /* The run writes into the same buffer the console card uses, so the rows
       are built by the one renderer that already knows how to draw a record. */
    {
        GPtrArray *views = g_ptr_array_new();
        g_ptr_array_add(views, rr->rows);
        g_object_set_data_full(G_OBJECT(rr->buf), "output-views", views,
                               (GDestroyNotify) g_ptr_array_unref);
    }
    g_object_set_data(G_OBJECT(rr->buf), "result-rect", rr);
    g_object_set_data(G_OBJECT(rr->stop), "state", NULL);
    g_signal_connect(rr->stop, "clicked", G_CALLBACK(result_stop_clicked), rr);
    g_object_set_data_full(G_OBJECT(rect), "result-rect", rr, g_free);

    if (out != NULL) *out = rr;
    return rect;
}

static GtkWidget *
build_output_card(GtkTextBuffer *buf)
{
    GtkWidget *card   = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *head   = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *title  = gtk_label_new("OUTPUT");
    GtkWidget *clear  = gtk_button_new_with_label("Clear");
    GtkWidget *scroll = gtk_scrolled_window_new();
    GtkWidget *view   = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);

    gtk_widget_add_css_class(card,  "output-card");
    gtk_widget_add_css_class(head,  "output-card-head");
    gtk_widget_add_css_class(title, "output-card-title");
    gtk_widget_add_css_class(clear, "flat");
    gtk_widget_add_css_class(view,  "output-log");

    gtk_widget_set_halign(title, GTK_ALIGN_START);
    gtk_widget_set_hexpand(title, TRUE);
    gtk_box_append(GTK_BOX(head), title);
    gtk_box_append(GTK_BOX(head), clear);

    gtk_widget_set_margin_top(view, 8);
    gtk_widget_set_margin_bottom(view, 8);
    gtk_widget_set_margin_start(view, 10);
    gtk_widget_set_margin_end(view, 10);
    gtk_widget_set_valign(view, GTK_ALIGN_START);
    gtk_widget_set_size_request(scroll, -1, 150);

    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), view);

    gtk_box_append(GTK_BOX(card), head);
    gtk_box_append(GTK_BOX(card), scroll);

    g_object_set_data(G_OBJECT(buf), "output-view", view);
    {
        GPtrArray *views = g_object_get_data(G_OBJECT(buf), "output-views");
        if (views == NULL) {
            views = g_ptr_array_new();
            g_object_set_data_full(G_OBJECT(buf), "output-views", views,
                                   (GDestroyNotify) g_ptr_array_unref);
        }
        g_ptr_array_add(views, view);
    }
    g_signal_connect(view, "destroy",
                     G_CALLBACK(console_view_destroyed), buf);
    g_signal_connect(clear, "clicked",
                     G_CALLBACK(console_clear_clicked), buf);
    return card;
}

static GtkWidget *
build_group_view(AppState *state, const char *module_id, const char *title,
                 const char *spec, GtkWidget *status, GtkTextBuffer *out)
{
    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *inner = gtk_box_new(GTK_ORIENTATION_VERTICAL, 14);

    gtk_widget_set_margin_top(inner, 16);
    gtk_widget_set_margin_bottom(inner, 16);
    gtk_widget_set_margin_start(inner, 16);
    gtk_widget_set_margin_end(inner, 16);
    gtk_widget_set_hexpand(inner, TRUE);
    gtk_box_append(GTK_BOX(inner),
        build_group_cards(state, module_id, title, spec, status, FALSE));
    /* No page-wide output card here. Each card above owns its own result, and
       a second place for the same text is the thing this replaces. `out` stays
       in the signature because the page still owns a buffer for the controls
       that are not part of a card, and because changing every caller to prove
       a point would be churn. */
    (void) out;
    gtk_box_append(GTK_BOX(outer), inner);
    return outer;
}

/* A module with no registered entries still gets a page that lists what the
   shell side can do, so nothing is invisible. */
static GtkWidget *
create_placeholder_page(AppState *state, const ModuleDefinition *module)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    GtkWidget *title = gtk_label_new(module->name);
    GtkWidget *id = gtk_label_new(module->id);
    GtkWidget *note = gtk_label_new(NULL);
    GtkWidget *desc = gtk_label_new(module->desc ? module->desc : "");
    GtkWidget *status = gtk_label_new("Idle");
    GtkWidget *flow = gtk_flow_box_new();

    gtk_widget_set_margin_top(box, 16);
    gtk_widget_set_margin_start(box, 16);
    gtk_widget_set_margin_end(box, 16);
    gtk_widget_set_margin_bottom(box, 16);
    gtk_widget_add_css_class(title, "module-header-title");
    gtk_widget_set_halign(title, GTK_ALIGN_START);
    gtk_widget_add_css_class(id, "mono");
    gtk_widget_add_css_class(id, "dim");
    gtk_widget_set_halign(id, GTK_ALIGN_START);
    gtk_label_set_wrap(GTK_LABEL(note), TRUE);
    gtk_label_set_xalign(GTK_LABEL(note), 0.0f);
    gtk_widget_add_css_class(note, "dim");
    gtk_label_set_markup(GTK_LABEL(note),
        "This module has no registered GUI view. Its verbs are listed below.");
    gtk_widget_add_css_class(desc, "module-header-desc");
    gtk_label_set_xalign(GTK_LABEL(desc), 0.5f);
    gtk_label_set_justify(GTK_LABEL(desc), GTK_JUSTIFY_CENTER);
    gtk_label_set_wrap(GTK_LABEL(desc), TRUE);
    gtk_widget_add_css_class(status, "status-pill");
    gtk_widget_add_css_class(status, "status-idle");
    gtk_widget_set_halign(status, GTK_ALIGN_START);
    gtk_flow_box_set_selection_mode(GTK_FLOW_BOX(flow), GTK_SELECTION_NONE);
    gtk_flow_box_set_column_spacing(GTK_FLOW_BOX(flow), 6);
    gtk_flow_box_set_row_spacing(GTK_FLOW_BOX(flow), 6);

    for (int i = 0; i < MODULE_INDEX_N; i++) {
        if (g_strcmp0(module_index[i].id, module->id) != 0) continue;
        g_auto(GStrv) words = g_strsplit_set(module_index[i].verbs, " \t\n", -1);
        for (int wi = 0; words[wi] != NULL; wi++) {
            const char *v = words[wi];
            GtkWidget *btn;
            GtkWidget *child;
            if (!g_str_has_prefix(v, "--")) continue;
            if (g_strcmp0(v, "--menu") == 0 || g_strcmp0(v, "--selftest") == 0 ||
                g_strcmp0(v, "--status-tsv") == 0)
                continue;
            btn = gtk_button_new_with_label(v);
            gtk_widget_add_css_class(btn, "verb-button");
            gtk_widget_set_tooltip_text(btn, v);
            g_object_set_data(G_OBJECT(btn), "state", state);
            g_object_set_data(G_OBJECT(btn), "module-id", (gpointer) module->id);
            g_object_set_data(G_OBJECT(btn), "status", status);
            g_object_set_data_full(G_OBJECT(btn), "verb", g_strdup(v), g_free);
            g_signal_connect(btn, "clicked",
                G_CALLBACK(verb_button_dyn_clicked), NULL);
            child = gtk_flow_box_child_new();
            gtk_flow_box_child_set_child(GTK_FLOW_BOX_CHILD(child), btn);
            gtk_flow_box_append(GTK_FLOW_BOX(flow), child);
        }
        break;
    }

    gtk_box_append(GTK_BOX(box), title);
    gtk_box_append(GTK_BOX(box), desc);
    gtk_box_append(GTK_BOX(box), id);
    gtk_box_append(GTK_BOX(box), note);
    gtk_box_append(GTK_BOX(box), status);
    gtk_box_append(GTK_BOX(box), flow);
    {
        GtkTextBuffer *out = output_buffer_new();
        gtk_box_append(GTK_BOX(box), build_output_card(out));
        g_object_set_data(G_OBJECT(box), "output-buffer", out);
    }
    return box;
}

/* Point the run target at one view's output buffer.
 *
 * This used to happen only inside the row-activated handler, so a module page
 * opened directly - the first view, by definition, is never activated - left
 * state->active_output pointing at nothing. A verb run from that page then had
 * its output captured and dropped: the radio indicator said Error, the Events
 * drawer recorded the failure, and the output card the operator was looking at
 * stayed empty. One click on a view row in the left column "fixed" it, which is
 * how a bug like this survives: it looks like the first run was unlucky.
 *
 * Every path that puts a view on screen calls this, so "what is on screen" and
 * "where output goes" cannot disagree. */
static void
module_page_retarget_output(ModulePage *mp, int index)
{
    if (mp == NULL || mp->state == NULL) return;
    if (index < 0 || index >= mp->n_views) return;

    GtkTextBuffer *vb = g_object_get_data(
        G_OBJECT(mp->views[index].page), "output-buffer");
    if (vb == NULL) return;

    mp->state->active_output = vb;
    if (mp->page != NULL)
        g_object_set_data(G_OBJECT(mp->page), "output-buffer", vb);
}

static void
module_page_submenu_row_activated(GtkListBox *list, GtkListBoxRow *row,
                                  gpointer user_data)
{
    ModulePage *mp = user_data;
    int index = gtk_list_box_row_get_index(row);
    if (index >= 0 && index < mp->n_views) {
        gtk_stack_set_visible_child_name(GTK_STACK(mp->stack),
                                         mp->views[index].name);
        gtk_list_box_select_row(list, row);

        /* The recent list is a list of places, and the place is the view.
           "Field Kit" says less than "Field Kit - Guards". */
        if (mp->state != NULL && mp->module != NULL)
            place_push_view(mp->state, mp->module->id, mp->views[index].name);

        /* Output goes to the submenu on screen. The page's record is kept in
           step so switching tabs away and back retargets correctly. */
        module_page_retarget_output(mp, index);
    }
}

/* Put a named view back on screen, for a recent place. Returns FALSE when
   the module no longer has a view by that name, which is what an older entry
   in the recent list looks like after a module is reorganised. */
static gboolean
module_page_show_view(ModulePage *mp, const char *name)
{
    if (mp == NULL || name == NULL || mp->submenu_list == NULL) return FALSE;
    for (int i = 0; i < mp->n_views; i++) {
        if (g_strcmp0(mp->views[i].name, name) != 0) continue;
        GtkListBoxRow *r = gtk_list_box_get_row_at_index(
            GTK_LIST_BOX(mp->submenu_list), i);
        if (r != NULL) {
            module_page_submenu_row_activated(GTK_LIST_BOX(mp->submenu_list),
                                              r, mp);
            return TRUE;
        }
    }
    return FALSE;
}

static GtkWidget *
module_page_build_submenu(ModulePage *mp)
{
    GtkWidget *list = gtk_list_box_new();
    GtkWidget *col = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *scrolled = gtk_scrolled_window_new();
    GtkWidget *hdr = gtk_label_new("VIEWS");

    gtk_widget_add_css_class(list, "module-menu");
    gtk_widget_add_css_class(col, "module-menu");
    gtk_widget_add_css_class(col, category_class(mp->module->category));
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(list), GTK_SELECTION_SINGLE);
    gtk_list_box_set_activate_on_single_click(GTK_LIST_BOX(list), TRUE);

    for (int i = 0; i < mp->n_views; i++) {
        GtkWidget *row = gtk_list_box_row_new();
        GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
        GtkWidget *icon = imsisting_icon_image(mp->views[i].icon);
        GtkWidget *label = gtk_label_new(mp->views[i].name);
        gtk_widget_add_css_class(row, "module-menu-row");
        gtk_image_set_pixel_size(GTK_IMAGE(icon), 20);
        gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
        gtk_widget_set_hexpand(label, TRUE);
        gtk_box_append(GTK_BOX(box), icon);
        gtk_box_append(GTK_BOX(box), label);
        gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), box);
        gtk_list_box_append(GTK_LIST_BOX(list), row);
    }

    g_signal_connect(list, "row-activated",
                     G_CALLBACK(module_page_submenu_row_activated), mp);

    if (mp->n_views > 0) {
        gtk_list_box_select_row(GTK_LIST_BOX(list),
            gtk_list_box_get_row_at_index(GTK_LIST_BOX(list), 0));

        /* The first view is on screen from the moment the module opens, so it
           is the output target from that moment too - see the note on
           module_page_retarget_output. */
        module_page_retarget_output(mp, 0);

        /* Opening a module is arriving at its first view, so that is the
           place worth remembering - unless a recent row asked for another
           one, in which case that view wins. */
        if (mp->state != NULL && mp->module != NULL) {
            place_push_view(mp->state, mp->module->id, mp->views[0].name);
            if (mp->state->pending_view != NULL) {
                g_autofree char *want = g_strdup(mp->state->pending_view);
                g_clear_pointer(&mp->state->pending_view, g_free);
                module_page_show_view(mp, want);
            }
        }
    }

    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), list);
    gtk_widget_set_size_request(scrolled, 250, -1);
    gtk_widget_set_vexpand(scrolled, TRUE);

    /* A heading over the menu, so the column reads as navigation. */
    gtk_widget_add_css_class(hdr, "menu-heading");
    gtk_label_set_xalign(GTK_LABEL(hdr), 0.0f);
    gtk_widget_set_margin_top(hdr, 12);
    gtk_widget_set_margin_bottom(hdr, 6);
    gtk_widget_set_margin_start(hdr, 16);
    gtk_box_append(GTK_BOX(col), hdr);
    gtk_box_append(GTK_BOX(col), scrolled);
    gtk_widget_set_vexpand(col, TRUE);

    mp->submenu_list = list;
    return col;
}

/* A key/value line for the Overview card. */
static GtkWidget *
overview_row(const char *key, const char *value)
{
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *k = gtk_label_new(key);
    GtkWidget *v = gtk_label_new(value != NULL ? value : "");
    gtk_widget_add_css_class(k, "overview-key");
    gtk_widget_add_css_class(v, "overview-value");
    gtk_label_set_xalign(GTK_LABEL(k), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(v), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(v), TRUE);
    gtk_label_set_selectable(GTK_LABEL(v), TRUE);
    gtk_widget_set_size_request(k, 110, -1);
    gtk_widget_set_hexpand(v, TRUE);
    gtk_box_append(GTK_BOX(row), k);
    gtk_box_append(GTK_BOX(row), v);
    return row;
}

static GtkWidget *
workflow_step(const char *number, const char *title, const char *detail)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *n = gtk_label_new(number);
    GtkWidget *t = gtk_label_new(title);
    GtkWidget *d = gtk_label_new(detail);
    gtk_widget_add_css_class(box, "workflow-step");
    gtk_widget_add_css_class(n, "workflow-number");
    gtk_widget_add_css_class(t, "workflow-title");
    gtk_widget_add_css_class(d, "workflow-detail");
    gtk_label_set_xalign(GTK_LABEL(n), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(t), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(d), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(d), TRUE);
    return box;
}

/* The Overview view: what this module is (ABOUT) and the handful of actions
   that make sense to reach immediately (QUICK ACTIONS). */
static GtkWidget *
build_overview_view(AppState *state, const ModuleDefinition *module,
                    const char *quick_spec, GtkWidget *status,
                    GtkTextBuffer *out)
{
    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *inner = gtk_box_new(GTK_ORIENTATION_VERTICAL, 14);
    const ModuleIndexEntry *idx = NULL;

    gtk_widget_set_margin_top(inner, 16);
    gtk_widget_set_margin_bottom(inner, 16);
    gtk_widget_set_margin_start(inner, 16);
    gtk_widget_set_margin_end(inner, 16);
    gtk_widget_set_hexpand(inner, TRUE);

    {
        GtkWidget *flow = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        gtk_widget_add_css_class(flow, "workflow-ribbon");
        gtk_box_set_homogeneous(GTK_BOX(flow), TRUE);
        gtk_box_append(GTK_BOX(flow), workflow_step("01", "CONTEXT",
            "Review the target and module scope."));
        gtk_box_append(GTK_BOX(flow), workflow_step("02", "RUN",
            "Choose a focused action below."));
        gtk_box_append(GTK_BOX(flow), workflow_step("03", "REVIEW",
            "Read the result in Events and preserve evidence."));
        gtk_box_append(GTK_BOX(inner), flow);
    }

    for (int i = 0; i < MODULE_INDEX_N; i++)
        if (g_strcmp0(module_index[i].id, module->id) == 0) {
            idx = &module_index[i];
            break;
        }

    /* 01 · CONTEXT — what this module is and what it can do. */
    {
        GtkWidget *body;
        GtkWidget *card = verb_card("01 · CONTEXT", &body);
        gtk_box_append(GTK_BOX(body), overview_row("Id", module->id));
        gtk_box_append(GTK_BOX(body), overview_row("Category", module->category));
        if (module->desc != NULL && *module->desc != '\0')
            gtk_box_append(GTK_BOX(body), overview_row("Summary", module->desc));
        if (idx != NULL) {
            int nv = 0;
            g_auto(GStrv) words = g_strsplit_set(idx->verbs, " \t\n", -1);
            g_autofree char *nvs = NULL;
            for (int w = 0; words[w] != NULL; w++)
                if (g_str_has_prefix(words[w], "--"))
                    nv++;
            nvs = g_strdup_printf("%d", nv);
            gtk_box_append(GTK_BOX(body), overview_row("Verbs", nvs));
            if (idx->info != NULL && *idx->info != '\0')
                gtk_box_append(GTK_BOX(body), overview_row("Notes", idx->info));
        }
        gtk_box_append(GTK_BOX(inner), card);
    }

    /* 02 · RUN — the primary action leads; the rest sit beside it. */
    if (spec_has_buttons(quick_spec))
        gtk_box_append(GTK_BOX(inner),
            build_group_card(state, module->id, "02 · RUN NOW",
                             quick_spec, status, TRUE));

    /* 03 · EVIDENCE — where the output goes and how it is preserved. */
    {
        GtkWidget *body;
        GtkWidget *card = verb_card("03 · EVIDENCE", &body);
        GtkWidget *note = gtk_label_new(
            "Every run is logged in the Events drawer and, when a case is "
            "open, appended to its timeline. Index captures under Casebook > "
            "Captures to preserve them as evidence.");
        gtk_widget_add_css_class(note, "card-note");
        gtk_label_set_wrap(GTK_LABEL(note), TRUE);
        gtk_label_set_xalign(GTK_LABEL(note), 0.0f);
        gtk_box_append(GTK_BOX(body), note);
        gtk_box_append(GTK_BOX(inner), card);
    }

    if (out != NULL)
        gtk_box_append(GTK_BOX(inner), build_output_card(out));

    gtk_box_append(GTK_BOX(outer), inner);
    return outer;
}

/* Closing a module page from its own header. The tab strip that used to
   carry the close control is gone, so without this a module could only ever
   be replaced, never put away. */
static void
module_close_clicked(GtkButton *button, gpointer user_data)
{
    AppState *state = g_object_get_data(G_OBJECT(button), "state");
    GtkWidget *page = user_data;
    int index = gtk_notebook_page_num(GTK_NOTEBOOK(state->notebook), page);
    if (index >= 0)
        gtk_notebook_remove_page(GTK_NOTEBOOK(state->notebook), index);

    /* Removing the page you are standing on makes GTK pick the next one for
       you, and its pick is the last page left in the notebook - Settings. So
       closing a module used to open Settings. Page 0 is the dashboard's slot,
       and landing there is what closing means: notebook_page_switched() reads
       it and lifts the sheet off the dashboard. */
    gtk_notebook_set_current_page(GTK_NOTEBOOK(state->notebook), 0);
}

static GtkWidget *
create_module_page(AppState *state, const ModuleDefinition *module,
                   ModuleSubmenuEntry *entries, int n_entries,
                   gpointer module_data)
{
    ModulePage *mp = g_new0(ModulePage, 1);
    mp->state = state;
    mp->module = module;
    mp->module_data = module_data;

    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_add_css_class(outer, "module-page");
    gtk_widget_set_vexpand(outer, TRUE);

    /* Header: icon, name, category, status pill, then the module's one-line
       description beneath them. */
    GtkWidget *header = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *hrow   = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *hicon = imsisting_icon_image(module_icon_for(module->id));
    gtk_image_set_pixel_size(GTK_IMAGE(hicon), 34);
    GtkWidget *htitle = gtk_label_new(module_name_for(module->id));
    GtkWidget *hcat = gtk_label_new(module->category);
    GtkWidget *pill = gtk_label_new("Idle");
    GtkWidget *hdesc = gtk_label_new(module->desc ? module->desc : "");

    gtk_widget_add_css_class(header, "module-header-bar");
    gtk_widget_add_css_class(header, category_class(module->category));
    gtk_widget_add_css_class(hcat, "breadcrumb");
    gtk_widget_add_css_class(htitle, "module-header-title");
    gtk_widget_add_css_class(hcat, "module-header-category");
    gtk_widget_add_css_class(pill, "status-pill");
    gtk_widget_add_css_class(pill, "status-idle");
    gtk_widget_add_css_class(hdesc, "module-header-desc");

    gtk_widget_set_hexpand(htitle, TRUE);
    gtk_label_set_ellipsize(GTK_LABEL(htitle), PANGO_ELLIPSIZE_END);
    gtk_label_set_xalign(GTK_LABEL(hdesc), 0.5f);
    gtk_label_set_justify(GTK_LABEL(hdesc), GTK_JUSTIFY_CENTER);
    gtk_label_set_wrap(GTK_LABEL(hdesc), TRUE);

    gtk_box_append(GTK_BOX(hrow), hicon);
    gtk_box_append(GTK_BOX(hrow), htitle);
    gtk_box_append(GTK_BOX(hrow), hcat);
    gtk_box_append(GTK_BOX(hrow), pill);

    GtkWidget *hclose = gtk_button_new_from_icon_name("window-close-symbolic");
    gtk_widget_add_css_class(hclose, "flat");
    gtk_widget_add_css_class(hclose, "module-close");
    gtk_widget_set_tooltip_text(hclose, "close this module");
    g_object_set_data(G_OBJECT(hclose), "state", state);
    g_signal_connect(hclose, "clicked", G_CALLBACK(module_close_clicked), outer);
    gtk_box_append(GTK_BOX(hrow), hclose);

    gtk_box_append(GTK_BOX(header), hrow);
    if (module->desc != NULL && *module->desc != '\0')
        gtk_box_append(GTK_BOX(header), hdesc);
    mp->header_box = header;
    mp->status_pill = pill;

    /* Body: submenu + stack of views. */
    GtkWidget *body = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    GtkWidget *stack = gtk_stack_new();
    /* One output buffer for the whole page; every view's card shows it, so
       a result stays on screen when the operator switches views. */
    GtkTextBuffer *out = output_buffer_new();
    gtk_stack_set_transition_type(GTK_STACK(stack),
                                  GTK_STACK_TRANSITION_TYPE_CROSSFADE);
    /* Not homogeneous: a GtkStack defaults to sizing itself to its LARGEST
       child, so one tall view (a long Packages or System list) set the
       minimum height of the whole page. That minimum was bigger than the
       window, which squeezed the output console at the bottom of the page
       down to nothing. Only the visible view should claim height. */
    gtk_stack_set_vhomogeneous(GTK_STACK(stack), FALSE);
    gtk_stack_set_hhomogeneous(GTK_STACK(stack), FALSE);
    mp->stack = stack;

    /* Every registered entry becomes its own view, named and grouped by the
       module itself - Overview, Packages, Decode, Headers, Export. Entry 0
       used to be forced through a generic "01 CONTEXT / 02 RUN NOW / 03
       EVIDENCE" template, which made every module in the toolkit render as
       the same page whatever that module actually needed. The module's own
       grouping is the part that has a reason behind it, so it drives the
       layout instead of being poured into a fixed shell. */
    mp->views = g_new0(ModuleView, n_entries > 0 ? n_entries : 1);
    {
        int k = 0;
        for (int i = 0; i < n_entries; i++) {
            /* A custom view brings its own content, so it is never skipped
               for having no buttons in its spec. */
            if (entries[i].build == NULL &&
                !spec_has_buttons(entries[i].spec))
                continue;
            /* One buffer per VIEW, not one per page. A page-wide buffer
               meant the result of a run followed you into every other
               submenu: press Start scan in Overview, switch to Channel, and
               the scan's output was still sitting there. */
            GtkTextBuffer *vout = output_buffer_new();
            mp->views[k].name = entries[i].name;
            mp->views[k].icon = entries[i].icon;
            mp->views[k].page = entries[i].build != NULL
                ? entries[i].build(state, module->id, pill, vout)
                : build_group_view(state, module->id, entries[i].name,
                                   entries[i].spec, pill, vout);
            g_object_set_data_full(G_OBJECT(mp->views[k].page),
                                   "output-buffer", vout, g_object_unref);
            k++;
        }
        if (k == 0) {
            /* Nothing module-specific to draw: no registry entry, or every
               group needs typed arguments and so has no buttons. Only then
               fall back to the generated page. */
            mp->views[0].name = "Overview";
            mp->views[0].icon = "dialog-information-symbolic";
            {
                GtkTextBuffer *vout = output_buffer_new();
                mp->views[0].page = build_overview_view(state, module, NULL,
                                                        pill, vout);
                g_object_set_data_full(G_OBJECT(mp->views[0].page),
                                       "output-buffer", vout, g_object_unref);
            }
            k = 1;
        }
        mp->n_views = k;
    }

    for (int i = 0; i < mp->n_views; i++) {
        GtkWidget *view = mp->views[i].page;
        if (view == NULL) {
            GtkWidget *lbl = gtk_label_new("this view could not be built");
            gtk_widget_add_css_class(lbl, "dim");
            view = lbl;
        }
        GtkWidget *scrolled = gtk_scrolled_window_new();
        gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),
                                       GTK_POLICY_NEVER,
                                       GTK_POLICY_AUTOMATIC);
        /* The scroller, rather than the page, owns the remaining height.
           Without an explicit expansion request a tall custom view can be
           allocated at its natural height and its lower controls are clipped
           below the notebook instead of becoming reachable by scrolling. */
        gtk_widget_set_vexpand(scrolled, TRUE);
        gtk_widget_set_hexpand(scrolled, TRUE);
        gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), view);
        gtk_stack_add_named(GTK_STACK(stack), scrolled, mp->views[i].name);
    }

    if (mp->n_views > 0)
        gtk_stack_set_visible_child_name(GTK_STACK(stack), mp->views[0].name);

    /* body fills the page; without vexpand everything collapses to its
       natural height and the theme background shows through the rest. */
    gtk_widget_add_css_class(body, "module-body");
    gtk_widget_set_vexpand(body, TRUE);
    gtk_widget_set_hexpand(body, TRUE);

    gtk_box_append(GTK_BOX(body), module_page_build_submenu(mp));
    gtk_widget_set_hexpand(stack, TRUE);
    gtk_widget_set_vexpand(stack, TRUE);
    gtk_box_append(GTK_BOX(body), stack);

    gtk_box_append(GTK_BOX(outer), header);
    gtk_widget_set_vexpand(body, TRUE);
    gtk_box_append(GTK_BOX(outer), body);

    g_object_set_data_full(G_OBJECT(outer), "module-id",
                           g_strdup(module->id), g_free);
    g_object_set_data_full(G_OBJECT(outer), "module-page",
                           mp, (GDestroyNotify) module_page_free);

    /* The console a run writes to is the visible view's, so that is what this
       page advertises to notebook_page_switched(). It used to advertise a
       page-wide buffer that no widget displayed: opening a module and pressing
       a verb on its first view then produced an Error verdict in the Events
       drawer and an empty output card, because the text went into a buffer
       nothing was rendering. Clicking a view in the left column appeared to
       cure it, since that path aimed at the view's own buffer. */
    mp->page = outer;
    g_object_set_data(G_OBJECT(outer), "output-buffer",
                      mp->n_views > 0
                          ? g_object_get_data(G_OBJECT(mp->views[0].page),
                                              "output-buffer")
                          : out);

    return outer;
}

static void
module_page_free(gpointer data)
{
    g_free(data);
}

/* ==================================================================== */
/*  WINDOW                                                              */
/* ==================================================================== */

static GtkWidget *
find_module_page(AppState *state, const char *module_id)
{
    int n = gtk_notebook_get_n_pages(GTK_NOTEBOOK(state->notebook));
    for (int i = 0; i < n; i++) {
        GtkWidget *child = gtk_notebook_get_nth_page(GTK_NOTEBOOK(state->notebook), i);
        const char *id = g_object_get_data(G_OBJECT(child), "module-id");
        if (g_strcmp0(id, module_id) == 0)
            return child;
    }
    return NULL;
}

static void
tab_close_clicked(GtkButton *button, gpointer user_data)
{
    AppState *state = g_object_get_data(G_OBJECT(button), "state");
    GtkWidget *page = user_data;
    int index = gtk_notebook_page_num(GTK_NOTEBOOK(state->notebook), page);
    if (index >= 0)
        gtk_notebook_remove_page(GTK_NOTEBOOK(state->notebook), index);
}

static GtkWidget *
create_closable_tab_label(const char *title, GtkWidget *page, AppState *state)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *label = gtk_label_new(title);
    GtkWidget *close = gtk_button_new_from_icon_name("window-close-symbolic");
    gtk_widget_add_css_class(close, "flat");
    gtk_widget_set_tooltip_text(close, "close this module");
    g_object_set_data(G_OBJECT(close), "state", state);
    g_signal_connect(close, "clicked", G_CALLBACK(tab_close_clicked), page);
    gtk_box_append(GTK_BOX(box), label);
    gtk_box_append(GTK_BOX(box), close);
    return box;
}

static void
open_module(AppState *state, const ModuleDefinition *module)
{
    if (state == NULL || module == NULL) return;
    GtkWidget *existing = find_module_page(state, module->id);
    if (existing != NULL) {
        ModulePage *mp = g_object_get_data(G_OBJECT(existing), "module-page");
        int index = gtk_notebook_page_num(GTK_NOTEBOOK(state->notebook), existing);
        gtk_notebook_set_current_page(GTK_NOTEBOOK(state->notebook), index);
        sidebar_set_active(state, module->id);

        /* The page is already built, so nothing will consume a pending view
           for us and its current view is the place to remember. */
        if (state->pending_view != NULL) {
            g_autofree char *want = g_strdup(state->pending_view);
            g_clear_pointer(&state->pending_view, g_free);
            if (module_page_show_view(mp, want)) return;
        }
        if (mp != NULL)
            place_push_view(state, module->id,
                            gtk_stack_get_visible_child_name(GTK_STACK(mp->stack)));
        return;
    }

    GtkWidget *page;
    ModuleRegistryEntry *reg = module_registry_find(module->id);

    if (reg != NULL) {
        gpointer data = reg->get_module_data ? reg->get_module_data(state) : NULL;
        page = create_module_page(state, module, reg->entries,
                                  reg->n_entries, data);
    } else {
        page = create_placeholder_page(state, module);
    }

    /* Which module this page belongs to, so the notebook switch handler can
       keep the sidebar in step without a lookup table of its own.
       create_module_page() already tags its page; this covers the placeholder
       path, and re-tagging with the same value is harmless. */
    g_object_set_data_full(G_OBJECT(page), "module-id",
                           g_strdup(module->id), g_free);

    GtkWidget *tab = create_closable_tab_label(module->name, page, state);
    int index = gtk_notebook_append_page(GTK_NOTEBOOK(state->notebook), page, tab);
    gtk_notebook_set_current_page(GTK_NOTEBOOK(state->notebook), index);
    sidebar_set_active(state, module->id);

    /* A view the page turned out not to have (a module with no views at all,
       or one that was reorganised since the entry was written) must not wait
       here for the next page and surprise it. */
    g_clear_pointer(&state->pending_view, g_free);

    g_autofree char *msg = g_strdup_printf("Opened module: %s [%s]",
                                           module->name, module->id);
    append_event(state, msg);
}

static void
module_row_activated(GtkListBox *list, GtkListBoxRow *row, gpointer user_data)
{
    AppState *state = user_data;
    const ModuleDefinition *module =
        g_object_get_data(G_OBJECT(row), "module");
    const char *view = g_object_get_data(G_OBJECT(row), "place-view");

    /* A recent place can name the view it was in. The page that owns that
       view may not exist yet, so the wish waits on the state until it does. */
    if (view != NULL && state != NULL) {
        g_free(state->pending_view);
        state->pending_view = g_strdup(view);
    }

    if (module != NULL) {
        open_module(state, module);
        /* A drawer has done its job the moment it is used: leaving it over
           the page it just opened would hide the thing that was asked for. */
        drawer_set_open(state, FALSE);
    } else {
        int index = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(row), "page-index"));
        if (state != NULL && index >= 0 &&
            index < gtk_notebook_get_n_pages(GTK_NOTEBOOK(state->notebook))) {
            gtk_notebook_set_current_page(GTK_NOTEBOOK(state->notebook), index);
            settings_show_view(state, view);
            drawer_set_open(state, FALSE);
        }
        g_clear_pointer(&state->pending_view, g_free);
    }
    (void) list;
}

/* Filter the sidebar by name, id or description; a group with no surviving
   row is hidden, and a searched group auto-expands so hits are visible. */
static void
sidebar_apply_filter(GtkWidget *content, const char *q)
{
    g_autofree char *needle = (q && *q) ? g_ascii_strdown(q, -1) : NULL;
    gboolean searching = needle != NULL && *needle != '\0';
    gboolean was_searching =
        GPOINTER_TO_INT(g_object_get_data(G_OBJECT(content), "searching"));

    gboolean searching_any = FALSE;

    for (GtkWidget *child = gtk_widget_get_first_child(content);
         child != NULL; child = gtk_widget_get_next_sibling(child)) {
        if (!GTK_IS_EXPANDER(child)) continue;
        GtkWidget *list = gtk_expander_get_child(GTK_EXPANDER(child));
        if (list == NULL) continue;
        gboolean any = FALSE;

        /* Remember how the operator had the group folded, so clearing the box
           puts it back rather than leaving every category expanded. */
        if (searching && !was_searching)
            g_object_set_data(G_OBJECT(child), "expanded-before",
                              GINT_TO_POINTER(gtk_expander_get_expanded(
                                  GTK_EXPANDER(child))));

        for (GtkWidget *row = gtk_widget_get_first_child(list);
             row != NULL; row = gtk_widget_get_next_sibling(row)) {
            const ModuleDefinition *m = g_object_get_data(G_OBJECT(row), "module");
            if (m == NULL) continue;
            gboolean show = TRUE;
            if (searching) {
                /* The same fields the dashboard searches. Category was the one
                   missing here, so typing "RADIO" filtered the dashboard and
                   emptied the sidebar. */
                g_autofree char *joined = g_strdup_printf("%s %s %s %s",
                    m->name, m->id, m->category, m->desc ? m->desc : "");
                g_autofree char *hay = g_ascii_strdown(joined, -1);
                show = g_strrstr(hay, needle) != NULL;
            }
            gtk_widget_set_visible(row, show);
            if (show) any = TRUE;
        }

        gtk_widget_set_visible(child, searching ? any : TRUE);
        if (any) searching_any = TRUE;
        if (searching)
            gtk_expander_set_expanded(GTK_EXPANDER(child), any);
        else if (was_searching)
            gtk_expander_set_expanded(GTK_EXPANDER(child),
                GPOINTER_TO_INT(g_object_get_data(G_OBJECT(child),
                                                   "expanded-before")));
    }

    /* With every category hidden the list went completely blank, which reads
       as a broken sidebar rather than "nothing matched". */
    GtkWidget *empty = g_object_get_data(G_OBJECT(content), "empty");
    if (empty != NULL)
        gtk_widget_set_visible(empty, searching && !searching_any);

    g_object_set_data(G_OBJECT(content), "searching", GINT_TO_POINTER(searching));
}

static void
sidebar_search_changed(GtkEditable *e, gpointer user_data)
{
    sidebar_apply_filter(GTK_WIDGET(user_data), gtk_editable_get_text(e));
}

static void
drawer_nav_row_selected(GtkListBox *list, GtkListBoxRow *row, gpointer user_data)
{
    AppState *state = user_data;
    int index;
    (void) list;

    /* A row selected programmatically -- because the notebook moved and the
       list is catching up -- must not be read as a click, or every page
       change would also close the drawer. */
    if (state->drawer_nav_syncing || row == NULL) return;

    index = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(row), "page-index"));
    if (index >= 0 &&
        index < gtk_notebook_get_n_pages(GTK_NOTEBOOK(state->notebook)))
        gtk_notebook_set_current_page(GTK_NOTEBOOK(state->notebook), index);
    drawer_set_open(state, FALSE);
}

/* The drawer's own navigation: the six permanent pages in tab order, which
   is the order they are appended in. Above the catalogue, because the
   drawer is read top to bottom -- where you can go, then everything that
   can be opened once you are there. */
static GtkWidget *
build_drawer_nav(AppState *state)
{
    static const char *names[7] = {
        "Dashboard", "Live Traffic", "Casebook", "Stats", "Notifications",
        "Help", "Settings"
    };
    static const char *icons[7] = {
        "view-grid-symbolic", "network-wireless-symbolic", "folder-symbolic",
        "office-chart-bar-symbolic", "notification-symbolic",
        "help-browser-symbolic", "emblem-system-symbolic"
    };

    GtkWidget *nav = gtk_list_box_new();
    gtk_widget_add_css_class(nav, "drawer-nav");
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(nav), GTK_SELECTION_SINGLE);

    for (int i = 0; i < 7; i++) {
        GtkWidget *rowbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 9);
        GtkWidget *icon = imsisting_icon_image(icons[i]);
        GtkWidget *label = gtk_label_new(names[i]);
        gtk_image_set_pixel_size(GTK_IMAGE(icon), 16);
        gtk_widget_set_hexpand(label, TRUE);
        gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
        gtk_label_set_ellipsize(GTK_LABEL(label), PANGO_ELLIPSIZE_END);
        gtk_widget_add_css_class(label, "drawer-nav-label");
        gtk_box_append(GTK_BOX(rowbox), icon);
        gtk_box_append(GTK_BOX(rowbox), label);

        GtkWidget *row = gtk_list_box_row_new();
        gtk_widget_add_css_class(row, "drawer-nav-row");
        gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), rowbox);
        g_object_set_data(G_OBJECT(row), "page-index", GINT_TO_POINTER(i));
        gtk_list_box_append(GTK_LIST_BOX(nav), row);
        state->drawer_nav_rows[i] = row;
    }

    g_signal_connect(nav, "row-selected",
                     G_CALLBACK(drawer_nav_row_selected), state);
    state->drawer_nav = nav;
    return nav;
}

/* ---- recent places ----
   The catalogue is ordered by category, which is the right order to browse
   in and the wrong order to return in: the module you were just inside is
   the one you are most likely to want next, and finding it again means
   remembering which category it was filed under. */
#define DRAWER_RECENT_MAX 6

/* A place is "<owner>|<view>": the module or permanent page that was open,
   and the view that was on screen inside it. A bar cannot appear in a module
   id or a view name, so the two halves split apart again unambiguously. */
static char *
place_key(const char *owner, const char *view)
{
    if (owner == NULL) return NULL;
    if (view == NULL || *view == '\0') return g_strdup(owner);
    return g_strdup_printf("%s|%s", owner, view);
}

static const char *
place_bar(const char *key)
{
    return key != NULL ? strchr(key, '|') : NULL;
}

/* The permanent pages, in notebook order, so a place that is a page rather
   than a module can be named and opened again from the recent list. */
static const struct {
    const char *id;
    const char *name;
    const char *icon;
} g_place_pages[] = {
    { "dashboard",     "Dashboard",     "view-grid-symbolic" },
    { "live",          "Live Traffic",  "network-wireless-symbolic" },
    { "casebook",      "Casebook",      "folder-symbolic" },
    { "stats",         "Stats",         "office-chart-bar-symbolic" },
    { "notifications", "Notifications", "notification-symbolic" },
    { "help",          "Help",          "help-browser-symbolic" },
    { "settings",      "Settings",      "emblem-system-symbolic" },
};

#define SETTINGS_PLACE_PAGE 6

static void
drawer_recent_refresh(AppState *state)
{
    GtkWidget *list = state->drawer_recent_box;
    GtkWidget *row;

    if (list == NULL) return;

    while ((row = gtk_widget_get_first_child(list)) != NULL)
        gtk_list_box_remove(GTK_LIST_BOX(list), row);

    if (state->recent_mru == NULL || state->recent_mru->len == 0) {
        GtkWidget *empty = gtk_label_new("Nothing opened yet");
        gtk_widget_add_css_class(empty, "drawer-recent-empty");
        gtk_label_set_xalign(GTK_LABEL(empty), 0.0f);
        row = gtk_list_box_row_new();
        gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), empty);
        gtk_list_box_row_set_activatable(GTK_LIST_BOX_ROW(row), FALSE);
        gtk_list_box_row_set_selectable(GTK_LIST_BOX_ROW(row), FALSE);
        gtk_list_box_append(GTK_LIST_BOX(list), row);
        return;
    }

    for (guint i = 0; i < state->recent_mru->len; i++) {
        const char *key = g_ptr_array_index(state->recent_mru, i);
        g_auto(GStrv) parts = g_strsplit(key, "|", 2);
        const char *owner = parts[0];
        const char *view  = parts[1];
        const ModuleDefinition *mod = NULL;
        const char *pname = NULL, *picon = NULL;
        int pindex = -1;
        const char *title, *belongs;
        GtkWidget *hb, *icon, *label;

        for (int m = 0; m < N_MODULES; m++)
            if (g_strcmp0(modules[m].id, owner) == 0) { mod = &modules[m]; break; }
        if (mod == NULL) {
            for (int p = 0; p < (int) G_N_ELEMENTS(g_place_pages); p++)
                if (g_strcmp0(g_place_pages[p].id, owner) == 0) {
                    pname  = g_place_pages[p].name;
                    picon  = g_place_pages[p].icon;
                    pindex = p;
                    break;
                }
        }
        if (mod == NULL && pname == NULL) continue;

        belongs = mod != NULL ? mod->name : pname;
        /* The view is the name of the place; the module is the context that
           makes it unambiguous, because half the toolkit has an Overview. */
        title = (view != NULL && *view != '\0') ? view : belongs;

        hb = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        icon = imsisting_icon_image(mod != NULL
                 ? (mod->icon != NULL ? mod->icon
                                      : "application-x-executable-symbolic")
                 : picon);
        label = gtk_label_new(title);
        gtk_image_set_pixel_size(GTK_IMAGE(icon), 14);
        gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
        gtk_label_set_ellipsize(GTK_LABEL(label), PANGO_ELLIPSIZE_END);
        gtk_widget_set_hexpand(label, TRUE);
        gtk_box_append(GTK_BOX(hb), icon);
        gtk_box_append(GTK_BOX(hb), label);

        if (view != NULL && *view != '\0' && belongs != NULL) {
            GtkWidget *where = gtk_label_new(belongs);
            gtk_widget_add_css_class(where, "dim");
            gtk_label_set_xalign(GTK_LABEL(where), 1.0f);
            gtk_label_set_ellipsize(GTK_LABEL(where), PANGO_ELLIPSIZE_END);
            gtk_box_append(GTK_BOX(hb), where);
        }

        row = gtk_list_box_row_new();
        gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), hb);
        /* The same payloads the catalogue and the page list carry, so the
           existing handler opens these too. */
        if (mod != NULL) {
            g_object_set_data(G_OBJECT(row), "module", (gpointer) mod);
        } else {
            g_object_set_data(G_OBJECT(row), "page-index",
                              GINT_TO_POINTER(pindex));
        }
        if (view != NULL)
            g_object_set_data_full(G_OBJECT(row), "place-view",
                                   g_strdup(view), g_free);
        gtk_list_box_append(GTK_LIST_BOX(list), row);
    }
}

/* One row per module or page, not one per view: the section is six rows
   tall, and six rows all reading "Overview" would be worse than useless. So
   arriving at a new view replaces that owner's row instead of adding one. */
static void
drawer_recent_push(AppState *state, const char *key)
{
    g_autofree char *owner = NULL;

    if (state == NULL || key == NULL) return;
    if (state->recent_mru == NULL)
        state->recent_mru = g_ptr_array_new_with_free_func(g_free);

    {
        const char *bar = place_bar(key);
        owner = bar != NULL ? g_strndup(key, (gsize) (bar - key)) : g_strdup(key);
    }

    for (guint i = 0; i < state->recent_mru->len; ) {
        const char *have = g_ptr_array_index(state->recent_mru, i);
        const char *bar = place_bar(have);
        gsize n = bar != NULL ? (gsize) (bar - have) : strlen(have);
        if (strlen(owner) == n && strncmp(have, owner, n) == 0)
            g_ptr_array_remove_index(state->recent_mru, i);
        else
            i++;
    }
    g_ptr_array_insert(state->recent_mru, 0, g_strdup(key));
    while (state->recent_mru->len > DRAWER_RECENT_MAX)
        g_ptr_array_remove_index(state->recent_mru,
                                 state->recent_mru->len - 1);

    drawer_recent_refresh(state);
}

/* Remember that the operator was here: the owner is a module id or a page
   id, the view is what the page calls the submenu they were looking at. */
static void
place_push_view(AppState *state, const char *owner, const char *view)
{
    g_autofree char *key = place_key(owner, view);
    if (key != NULL) drawer_recent_push(state, key);
}

static GtkWidget *
build_sidebar(AppState *state)
{
    /* The drawer is one surface: the page list, a rule, then the catalogue.
       The background lives on the outer box rather than on the list so the
       two halves cannot drift apart. */
    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_add_css_class(outer, "sidebar");

    gtk_box_append(GTK_BOX(outer), build_drawer_nav(state));

    GtkWidget *rule = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_widget_add_css_class(rule, "drawer-rule");
    gtk_box_append(GTK_BOX(outer), rule);

    GtkWidget *content = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    state->sidebar_content = content;

    /* The module catalogue used to live here: a search field over category
       expanders listing all 57 modules. It went because every one of those
       modules is already reachable the two ways an operator actually uses —
       the dashboard grid for browsing and the header palette (Ctrl+K) for
       naming a module outright — and a third list of the same 57 items was
       three navigation systems answering one question.

       `content` is still built and still recorded on the state because the
       open-module highlight helpers read it back; it simply never enters the
       hierarchy now, so those helpers operate on a detached box instead of
       needing to be unwound first. */


    /* ---- recent places ----
       Pinned under the catalogue instead of scrolling inside it: the whole
       point of the list is that it is reachable without hunting, and a
       section that scrolls away is one you have to go and find. */
    {
        GtkWidget *wrap = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
        GtkWidget *head = gtk_label_new("RECENT");
        GtkWidget *list = gtk_list_box_new();

        gtk_widget_add_css_class(wrap, "drawer-recent");
        gtk_widget_add_css_class(head, "drawer-recent-head");
        gtk_label_set_xalign(GTK_LABEL(head), 0.0f);
        gtk_widget_add_css_class(list, "drawer-nav");
        gtk_list_box_set_selection_mode(GTK_LIST_BOX(list), GTK_SELECTION_NONE);
        gtk_list_box_set_activate_on_single_click(GTK_LIST_BOX(list), TRUE);
        g_signal_connect(list, "row-activated",
                         G_CALLBACK(module_row_activated), state);

        state->drawer_recent_box = list;
        gtk_box_append(GTK_BOX(wrap), head);
        gtk_box_append(GTK_BOX(wrap), list);
        gtk_box_append(GTK_BOX(outer), wrap);
        drawer_recent_refresh(state);
    }

    return outer;
}

/* Bring the active sidebar row into view, once there is a layout to measure.

   This cannot run while the module is being opened: at startup the sidebar has
   never been allocated, so the row reports no bounds and the scroll silently
   does nothing. It re-arms until the geometry exists rather than guessing a
   delay, and gives up after a few passes so a hidden sidebar cannot spin. */
static gboolean
sidebar_scroll_idle(gpointer user_data)
{
    AppState *state = user_data;
    GtkWidget *content, *row;
    GtkAdjustment *adj;
    graphene_rect_t b;
    double top, bottom, page, val;

    if (state->active_module_id == NULL || state->sidebar_rows == NULL ||
        state->sidebar == NULL || !GTK_IS_SCROLLED_WINDOW(state->sidebar)) {
        state->sidebar_scroll_idle = 0;
        return G_SOURCE_REMOVE;
    }

    content = state->sidebar_content;
    row = g_hash_table_lookup(state->sidebar_rows, state->active_module_id);
    adj = gtk_scrolled_window_get_vadjustment(GTK_SCROLLED_WINDOW(state->sidebar));

    if (content != NULL && row != NULL && adj != NULL &&
        gtk_widget_compute_bounds(row, content, &b) &&
        b.size.height > 0 && gtk_adjustment_get_page_size(adj) > 0) {
        top    = b.origin.y;
        bottom = top + b.size.height;
        page   = gtk_adjustment_get_page_size(adj);
        val    = gtk_adjustment_get_value(adj);
        if (top < val)                gtk_adjustment_set_value(adj, top);
        else if (bottom > val + page) gtk_adjustment_set_value(adj, bottom - page);
        state->sidebar_scroll_idle = 0;
        state->sidebar_scroll_tries = 0;
        return G_SOURCE_REMOVE;
    }

    if (++state->sidebar_scroll_tries < 20) return G_SOURCE_CONTINUE;
    state->sidebar_scroll_idle = 0;
    state->sidebar_scroll_tries = 0;
    return G_SOURCE_REMOVE;
}

/* Show which module is open.

   The sidebar is one GtkListBox per category, so selection is per-list: a row
   picked in RECON stays marked when a SYSTEM module is opened afterwards, and
   two rows read as active at once. Nothing tied the sidebar to the notebook
   at all, so opening a module from a dashboard card, from a CLI --module, or
   switching to a permanent tab left the highlight pointing at whatever was
   last clicked.

   Every list is cleared first, then the open module's row is selected, its
   category expanded and the row scrolled into view. Exactly one row is ever
   marked, and it is the one you are looking at. */
static void
sidebar_set_active(AppState *state, const char *module_id)
{
    GtkWidget *content, *row, *list, *exp;

    if (state == NULL || state->sidebar == NULL) return;
    content = state->sidebar_content;
    if (content == NULL) return;

    g_free(state->active_module_id);
    state->active_module_id = g_strdup(module_id);

    for (exp = gtk_widget_get_first_child(content); exp != NULL;
         exp = gtk_widget_get_next_sibling(exp)) {
        if (!GTK_IS_EXPANDER(exp)) continue;
        list = gtk_expander_get_child(GTK_EXPANDER(exp));
        if (list == NULL || !GTK_IS_LIST_BOX(list)) continue;
        gtk_list_box_unselect_all(GTK_LIST_BOX(list));
    }

    if (module_id == NULL || state->sidebar_rows == NULL) return;
    row = g_hash_table_lookup(state->sidebar_rows, module_id);
    if (row == NULL || !GTK_IS_LIST_BOX_ROW(row)) return;

    list = gtk_widget_get_parent(row);
    if (list == NULL || !GTK_IS_LIST_BOX(list)) return;
    gtk_list_box_select_row(GTK_LIST_BOX(list), GTK_LIST_BOX_ROW(row));

    exp = gtk_widget_get_parent(list);
    if (exp != NULL && GTK_IS_EXPANDER(exp))
        gtk_expander_set_expanded(GTK_EXPANDER(exp), TRUE);

    /* A highlight inside a collapsed group, or scrolled out of sight, is not
       an indication of anything. The scroll is deferred because it needs a
       layout that may not exist yet. */
    if (state->sidebar_scroll_idle == 0) {
        state->sidebar_scroll_tries = 0;
        state->sidebar_scroll_idle = g_idle_add(sidebar_scroll_idle, state);
    }
}

/* ==================================================================== */
/*  EVENT DRAWER                                                        */
/* ==================================================================== */

static void
event_drawer_toggle(GtkToggleButton *button, gpointer user_data)
{
    AppState *state = user_data;
    gboolean active = gtk_toggle_button_get_active(button);
    gtk_revealer_set_reveal_child(GTK_REVEALER(state->event_revealer), active);
}

static void
event_errors_only_toggled(GtkToggleButton *b, gpointer user_data)
{
    AppState *state = user_data;
    state->event_errors_only = gtk_toggle_button_get_active(b);
}

static void
event_autoscroll_toggled(GtkToggleButton *b, gpointer user_data)
{
    AppState *state = user_data;
    state->event_autoscroll = gtk_toggle_button_get_active(b);
    if (state->event_autoscroll) event_scroll_to_end(state);
}

static void
event_copy_clicked(GtkButton *b, gpointer user_data)
{
    AppState *state = user_data;
    if (state->event_buffer == NULL) return;
    GtkTextIter a, z;
    gtk_text_buffer_get_bounds(state->event_buffer, &a, &z);
    g_autofree char *t = gtk_text_buffer_get_text(state->event_buffer, &a, &z, FALSE);
    gdk_clipboard_set_text(gtk_widget_get_clipboard(GTK_WIDGET(b)), t);
}

static void
event_clear_clicked(GtkButton *b, gpointer user_data)
{
    AppState *state = user_data;
    (void) b;
    if (state->event_buffer != NULL)
        gtk_text_buffer_set_text(state->event_buffer, "", -1);
    state->event_errors = 0;
    event_badge_update(state);
}

static GtkWidget *
build_event_drawer(AppState *state)
{
    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_add_css_class(outer, "event-drawer");

    GtkWidget *view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(view), TRUE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(view), GTK_WRAP_WORD_CHAR);
    state->event_buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));
    state->event_drawer = view;
    gtk_text_buffer_create_tag(state->event_buffer, "event-line",
                               "foreground", "#8b97a8", NULL);
    gtk_text_buffer_create_tag(state->event_buffer, "event-err",
                               "foreground", "#ef8b8b", NULL);

    /* Toolbar: filter, copy, clear, auto-scroll. */
    GtkWidget *bar    = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *label  = gtk_label_new("EVENTS");
    GtkWidget *errs   = gtk_check_button_new_with_label("Errors only");
    GtkWidget *asroll = gtk_check_button_new_with_label("Auto-scroll");
    GtkWidget *copy   = gtk_button_new_with_label("Copy");
    GtkWidget *clear  = gtk_button_new_with_label("Clear");

    gtk_widget_add_css_class(bar, "event-toolbar");
    gtk_widget_add_css_class(label, "menu-heading");
    gtk_check_button_set_active(GTK_CHECK_BUTTON(asroll), TRUE);
    state->event_autoscroll = TRUE;
    gtk_widget_set_hexpand(label, TRUE);
    gtk_label_set_xalign(GTK_LABEL(label), 0.0f);

    g_signal_connect(errs,   "toggled", G_CALLBACK(event_errors_only_toggled), state);
    g_signal_connect(asroll, "toggled", G_CALLBACK(event_autoscroll_toggled), state);
    g_signal_connect(copy,   "clicked", G_CALLBACK(event_copy_clicked), state);
    g_signal_connect(clear,  "clicked", G_CALLBACK(event_clear_clicked), state);

    gtk_box_append(GTK_BOX(bar), label);
    gtk_box_append(GTK_BOX(bar), errs);
    gtk_box_append(GTK_BOX(bar), asroll);
    gtk_box_append(GTK_BOX(bar), copy);
    gtk_box_append(GTK_BOX(bar), clear);
    gtk_box_append(GTK_BOX(outer), bar);

    GtkWidget *scrolled = gtk_scrolled_window_new();
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), view);
    gtk_widget_set_size_request(scrolled, -1, 170);

    gtk_box_append(GTK_BOX(outer), scrolled);

    GtkWidget *revealer = gtk_revealer_new();
    gtk_revealer_set_transition_type(GTK_REVEALER(revealer),
                                     GTK_REVEALER_TRANSITION_TYPE_SLIDE_UP);
    gtk_revealer_set_child(GTK_REVEALER(revealer), outer);
    gtk_revealer_set_reveal_child(GTK_REVEALER(revealer), FALSE);
    state->event_revealer = revealer;

    return revealer;
}


/* ==================================================================== */
/*  REGISTRATION                                                        */
/* ==================================================================== */

static void register_all_modules(void);

/* ==================================================================== */
/*  APP SETUP                                                           */
/* ==================================================================== */


/* ==================================================================== */
/*  LIVE STATUS STRIP                                                   */
/*                                                                      */
/*  wifisting shows interface / mode / MAC / channel in its header. The  */
/*  cellular equivalents are the things a tester actually watches: the   */
/*  radio that is attached, whether it can transmit, how many cells the  */
/*  survey has, whether there is a GPS fix, and the tuned frequency.     */
/*                                                                      */
/*  Each value comes from a module's own --status-tsv, so the header     */
/*  cannot disagree with what the module reports. Every one of those     */
/*  verbs returns in well under 100 ms; the strip is polled on a timer   */
/*  rather than spawned on every redraw.                                 */
/* ==================================================================== */

static char *
run_capture(const char *const *argv)
{
    g_autoptr(GError) error = NULL;
    g_autofree char *out = NULL;
    int status = 0;

    if (!g_spawn_sync(NULL, (char **) argv, NULL,
                      G_SPAWN_STDERR_TO_DEV_NULL | G_SPAWN_SEARCH_PATH,
                      NULL, NULL, &out, NULL, &status, &error))
        return NULL;
    if (!g_spawn_check_wait_status(status, NULL))
        return NULL;
    return g_steal_pointer(&out);
}

/* The same, for the half a module writes to stderr. The transmit path puts
   its warning there on purpose, so that stdout stays parseable TSV; a page
   that shows that warning has to ask for the other stream explicitly rather
   than being handed one merged blob it would have to guess apart. */
static char *
run_capture_stderr(const char *const *argv)
{
    g_autoptr(GError) error = NULL;
    g_autofree char *err = NULL;
    int status = 0;

    if (!g_spawn_sync(NULL, (char **) argv, NULL,
                      G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_SEARCH_PATH,
                      NULL, NULL, NULL, &err, &status, &error))
        return NULL;
    if (!g_spawn_check_wait_status(status, NULL))
        return NULL;
    return g_steal_pointer(&err);
}

/* Pull KEY's value out of a KEY\tVALUE TSV body. */
static char *
tsv_field(const char *text, const char *key)
{
    if (text == NULL || key == NULL) return NULL;

    g_auto(GStrv) lines = g_strsplit(text, "\n", -1);
    for (int i = 0; lines[i] != NULL; i++) {
        const char *tab = strchr(lines[i], '\t');
        if (tab == NULL) continue;
        if ((gsize) (tab - lines[i]) == strlen(key) &&
            strncmp(lines[i], key, tab - lines[i]) == 0)
            return g_strdup(tab + 1);
    }
    return NULL;
}

/* Pull KEY's value out of the first data row of a keyboard-style TSV whose
   first line is a header (e.g. casebook's target-current). */
static char *
tsv_row_field(const char *text, const char *key)
{
    g_auto(GStrv) head = NULL;
    g_auto(GStrv) row = NULL;
    int col = -1;
    if (text == NULL || key == NULL) return NULL;
    head = g_strsplit(text, "\n", -1);
    if (head[0] == NULL || head[1] == NULL) return NULL;
    g_auto(GStrv) cols = g_strsplit(head[0], "\t", -1);
    for (int i = 0; cols[i] != NULL; i++)
        if (g_strcmp0(cols[i], key) == 0) { col = i; break; }
    if (col < 0) return NULL;
    row = g_strsplit(head[1], "\t", -1);
    /* A header with no data line under it splits to a single empty field, so
       the column index can point past the end of row. That used to be read
       anyway - a heap overrun that crashed the app the first time a case
       existed and the target table was empty. Index only what exists. */
    return (col >= 0 && col < (int) g_strv_length(row)) ? g_strdup(row[col]) : NULL;
}

/* Same, but the last data row (the newest alert). */
static char *
tsv_last_field(const char *text, const char *key)
{
    g_auto(GStrv) lines = NULL;
    int col = -1, last;
    if (text == NULL || key == NULL) return NULL;
    lines = g_strsplit(text, "\n", -1);
    if (lines[0] == NULL) return NULL;
    for (last = 0; lines[last] != NULL; last++) ;
    /* drop a trailing empty line */
    while (last > 1 && lines[last - 1][0] == '\0') last--;
    if (last < 2) return NULL;
    g_auto(GStrv) cols = g_strsplit(lines[0], "\t", -1);
    for (int i = 0; cols[i] != NULL; i++)
        if (g_strcmp0(cols[i], key) == 0) { col = i; break; }
    if (col < 0) return NULL;
    g_auto(GStrv) row = g_strsplit(lines[last - 1], "\t", -1);
    return (col >= 0 && col < (int) g_strv_length(row)) ? g_strdup(row[col]) : NULL;
}

static char *
module_status(const char *module_id)
{
    g_autofree char *script = module_script_path(module_id);
    if (!g_file_test(script, G_FILE_TEST_IS_EXECUTABLE))
        return NULL;

    const char *argv[3] = { script, "--status-tsv", NULL };
    return run_capture(argv);
}

static void
status_set(GtkWidget *label, const char *value, const char *css)
{
    if (label == NULL || !GTK_IS_LABEL(label)) return;

    gboolean blank = (value == NULL || *value == '\0');
    gtk_label_set_text(GTK_LABEL(label), blank ? "—" : value);

    /* Every state the stylesheet can paint, or a cell can be left holding a
       stale one: status-running existed in CSS but was never cleared here,
       so it could not be used on the strip at all. */
    const char *classes[] = { "status-ok", "status-warn", "status-dim",
                              "status-running", "status-idle", NULL };
    GtkWidget *cell = gtk_widget_get_parent(label);
    for (int i = 0; classes[i] != NULL; i++) {
        gtk_widget_remove_css_class(label, classes[i]);
        if (cell != NULL)
            gtk_widget_remove_css_class(cell, classes[i]);
    }
    if (css != NULL && *css != '\0') {
        gtk_widget_add_css_class(label, css);
        if (cell != NULL)
            gtk_widget_add_css_class(cell, css);
    }
}

static gboolean
status_poll(gpointer user_data)
{
    AppState *state = user_data;
    if (state->window == NULL) return G_SOURCE_CONTINUE;

    /* Radio: device, transmit capability, tuned frequency. The splash starts
       this probe early and hands the answer over, because it is the single
       slowest thing the tick does. */
    g_autofree char *radio = state->radio_prefetch != NULL
                           ? g_steal_pointer(&state->radio_prefetch)
                           : module_status("01_radio");
    if (radio != NULL) {
        g_autofree char *drv = tsv_field(radio, "selected_driver");
        g_autofree char *sel = tsv_field(radio, "selected");
        g_autofree char *tx  = tsv_field(radio, "can_tx");
        g_autofree char *hz  = tsv_field(radio, "freq_hz");

        const char *shown = (sel && *sel) ? sel : drv;
        gboolean present = shown && *shown && g_strcmp0(shown, "none") != 0;
        status_set(state->status_sdr, present ? shown : "none",
                   present ? "status-ok" : "status-warn");

        gboolean can = g_strcmp0(tx, "yes") == 0;
        status_set(state->status_tx, can ? "yes" : "no",
                   can ? "status-ok" : "status-warn");

        if (hz != NULL && *hz != '\0') {
            double f = g_ascii_strtod(hz, NULL) / 1e6;
            g_autofree char *m = g_strdup_printf("%.3f MHz", f);
            status_set(state->status_freq, m, "status-ok");
        } else {
            status_set(state->status_freq, NULL, "status-dim");
        }
    } else {
        status_set(state->status_sdr, NULL, "status-dim");
        status_set(state->status_tx, NULL, "status-dim");
        status_set(state->status_freq, NULL, "status-dim");
    }

    /* Survey: how many cells are on the docket. */
    g_autofree char *crec = module_status("02_cell_recon");
    g_autofree char *cells = tsv_field(crec, "cells");
    if (cells != NULL) {
        status_set(state->status_cells, cells,
                   g_strcmp0(cells, "0") == 0 ? "status-dim" : "status-ok");
    } else {
        status_set(state->status_cells, NULL, "status-dim");
    }

    /* GPS: the survey's position source. */
    g_autofree char *tmap = module_status("04_tower_map");
    g_autofree char *gps = tsv_field(tmap, "gps");
    if (gps != NULL) {
        /* gpsd up without a fix yet is working, not healthy - the strip has
           a running state and this is what it is for. */
        status_set(state->status_gps, gps,
                   (g_strcmp0(gps, "running") == 0) ? "status-running"
                                                    : "status-warn");
    } else {
        status_set(state->status_gps, NULL, "status-dim");
    }

    /* Case-scoped facts for the dashboard band: the case, and how much it
       holds. The strip already carries the radio, so the band does not. */
    if (state->dash_case != NULL) {
        gboolean cb_ok = FALSE;
        const char *cb_args[] = { "status", NULL };
        g_autofree char *cb = casebook_call(cb_args, &cb_ok);
        g_autofree char *act   = cb_ok ? tsv_field(cb, "active_case") : NULL;
        g_autofree char *tgt   = cb_ok ? tsv_field(cb, "targets") : NULL;
        g_autofree char *ev    = cb_ok ? tsv_field(cb, "evidence") : NULL;
        g_autofree char *al    = cb_ok ? tsv_field(cb, "alerts") : NULL;
        gboolean none = (act == NULL || *act == '\0' ||
                         g_strcmp0(act, "none") == 0);
        int nt = (tgt && *tgt) ? atoi(tgt) : 0;
        int ne = (ev && *ev) ? atoi(ev) : 0;
        int na = (al && *al) ? atoi(al) : 0;
        g_autofree char *st = g_strdup_printf("%d", nt);
        g_autofree char *se = g_strdup_printf("%d", ne);
        g_autofree char *sa = g_strdup_printf("%d", na);

        status_set(state->dash_case, none ? "not set" : act,
                   none ? "status-warn" : "status-ok");
        status_set(state->dash_targets, st, nt > 0 ? "status-ok" : "status-dim");
        status_set(state->dash_evidence, se, ne > 0 ? "status-ok" : "status-dim");
        status_set(state->dash_alerts, sa, na > 0 ? "status-warn" : "status-dim");
    }

    /* The target panel reads the same casebook the counters above do, plus
       the live feed's own file, so it rides the same tick rather than
       polling on a timer of its own. */
    rtarget_panel_refresh(state);

    /* Stamped last, on purpose: the marker means "this strip was filled in",
       not "a poll was started". It is set once everything above has landed. */
    state->status_seen_us = g_get_monotonic_time();

    return G_SOURCE_CONTINUE;
}

static GtkWidget *
status_cell(const char *key, GtkWidget **value_out)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *head = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *dot = gtk_label_new("●");
    GtkWidget *k = gtk_label_new(key);
    GtkWidget *v = gtk_label_new("—");

    gtk_widget_add_css_class(box, "status-cell");
    gtk_widget_add_css_class(box, "status-dim");
    gtk_widget_add_css_class(head, "status-cell-head");
    gtk_widget_add_css_class(dot, "status-dot");
    gtk_widget_add_css_class(k, "status-key");
    gtk_widget_add_css_class(v, "status-value");
    gtk_widget_add_css_class(v, "status-dim");
    gtk_label_set_xalign(GTK_LABEL(k), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(v), 0.0f);

    gtk_box_append(GTK_BOX(head), dot);
    gtk_box_append(GTK_BOX(head), k);
    gtk_box_append(GTK_BOX(box), head);
    gtk_box_append(GTK_BOX(box), v);
    *value_out = v;
    return box;
}

static GtkWidget *
build_status_strip(AppState *state)
{
    GtkWidget *strip = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_add_css_class(strip, "status-strip");

    gtk_box_append(GTK_BOX(strip),
        status_cell("SDR",     &state->status_sdr));
    gtk_box_append(GTK_BOX(strip),
        status_cell("TX",      &state->status_tx));
    gtk_box_append(GTK_BOX(strip),
        status_cell("FREQ",    &state->status_freq));
    gtk_box_append(GTK_BOX(strip),
        status_cell("CELLS",   &state->status_cells));
    gtk_box_append(GTK_BOX(strip),
        status_cell("GPS",     &state->status_gps));

    /* Right end: when the strip was last told anything. The gap in the middle
       is deliberate - it keeps the hardware chips from reading as one long
       line, and splits the row into what the bench IS (left) and how current
       that reading is (right). */
    {
        GtkWidget *spacer = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
        gtk_widget_set_hexpand(spacer, TRUE);
        gtk_box_append(GTK_BOX(strip), spacer);
    }
    state->status_fresh = gtk_label_new(NULL);
    gtk_widget_add_css_class(state->status_fresh, "status-fresh");
    gtk_label_set_xalign(GTK_LABEL(state->status_fresh), 1.0f);
    gtk_widget_set_valign(state->status_fresh, GTK_ALIGN_CENTER);
    gtk_box_append(GTK_BOX(strip), state->status_fresh);

    return strip;
}

/* Runs once a second, off the poll's own clock, so the age keeps climbing even
   if the 3 s poll stops coming back. A strip that freezes at "polled 2 s ago"
   is a lied-about strip; this timer refuses to lie. */
static gboolean
status_freshness_tick(gpointer user_data)
{
    AppState *state = user_data;
    gint64 age_s;
    gboolean stale;
    g_autofree char *text = NULL;

    if (state->status_fresh == NULL)
        return G_SOURCE_CONTINUE;

    if (state->status_seen_us == 0) {
        gtk_label_set_text(GTK_LABEL(state->status_fresh),
                           "waiting for the first poll");
        return G_SOURCE_CONTINUE;
    }

    age_s = (g_get_monotonic_time() - state->status_seen_us) / G_USEC_PER_SEC;
    if (age_s < 0) age_s = 0;

    /* Said in the unit that reads, not in the unit that computes. Past a
       minute, seconds stop meaning anything and only make the number long. */
    stale = age_s > 10;
    if (age_s <= 1)
        text = g_strdup("polled just now");
    else if (age_s < 90)
        text = g_strdup_printf("polled %" G_GINT64_FORMAT " s ago", age_s);
    else if (age_s < 5400)
        text = g_strdup_printf("polled %" G_GINT64_FORMAT " min ago", age_s / 60);
    else
        text = g_strdup_printf("polled %" G_GINT64_FORMAT " h ago", age_s / 3600);

    gtk_label_set_text(GTK_LABEL(state->status_fresh), text);

    if (stale)
        gtk_widget_add_css_class(state->status_fresh, "stale");
    else
        gtk_widget_remove_css_class(state->status_fresh, "stale");

    return G_SOURCE_CONTINUE;
}

/* Unique categories in first-appearance order. The modules[] table is not
   category-contiguous — later additions repeat earlier category names — so
   grouping by "did the category change" emits the same section twice. Used by
   the Stats page; the Dashboard no longer groups by category. */
static GPtrArray *
category_order(void)
{
    GPtrArray *cats = g_ptr_array_new();
    for (int i = 0; i < N_MODULES; i++) {
        gboolean seen = FALSE;
        for (guint j = 0; j < cats->len; j++) {
            if (g_strcmp0(g_ptr_array_index(cats, j),
                          modules[i].category) == 0) { seen = TRUE; break; }
        }
        if (!seen) g_ptr_array_add(cats, (gpointer) modules[i].category);
    }
    return cats;
}

/* ==================================================================== */
/*  DASHBOARD                                                           */
/* ==================================================================== */

static void
module_card_clicked(GtkButton *button, gpointer user_data)
{
    AppState *state = user_data;
    const ModuleDefinition *mod = g_object_get_data(G_OBJECT(button), "module");
    if (mod != NULL) open_module(state, mod);
}


static const ModuleDefinition *
dashboard_module(const char *id)
{
    for (int i = 0; i < N_MODULES; i++)
        if (g_strcmp0(modules[i].id, id) == 0)
            return &modules[i];
    return NULL;
}

static void
dashboard_tab_clicked(GtkButton *button, gpointer user_data)
{
    AppState *state = user_data;
    int tab = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(button), "dashboard-tab"));
    if (state != NULL && state->notebook != NULL)
        gtk_notebook_set_current_page(GTK_NOTEBOOK(state->notebook), tab);
}

static GtkWidget *
dashboard_shortcut(AppState *state, const char *eyebrow, const char *title,
                   const char *detail, const char *icon,
                   const ModuleDefinition *module, int tab)
{
    GtkWidget *button = gtk_button_new();
    GtkWidget *box    = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *image  = imsisting_icon_image(icon);
    GtkWidget *label  = gtk_label_new(eyebrow);
    GtkWidget *name   = gtk_label_new(title);
    GtkWidget *chev   = imsisting_icon_image("go-next-symbolic");

    /* One line per step instead of a three-line card: the strip is an order of
       operations, and it must not outweigh the module grid it introduces. The
       sentence that used to print on the card is now the tooltip. */
    gtk_image_set_pixel_size(GTK_IMAGE(image), 16);
    gtk_image_set_pixel_size(GTK_IMAGE(chev), 12);
    gtk_widget_add_css_class(button, "mission-step");
    gtk_widget_add_css_class(box,    "mission-step-inner");
    gtk_widget_add_css_class(image,  "mission-step-icon");
    gtk_widget_add_css_class(label,  "mission-step-eyebrow");
    gtk_widget_add_css_class(name,   "mission-step-title");
    gtk_widget_add_css_class(chev,   "mission-step-chevron");
    gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(name), 0.0f);
    /* Only the title may ellipsize. The step index is two digits and is the
       one thing on the chip that must survive a narrow window. */
    gtk_label_set_ellipsize(GTK_LABEL(name),  PANGO_ELLIPSIZE_END);
    gtk_widget_set_hexpand(name, TRUE);
    gtk_widget_set_valign(image, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(chev,  GTK_ALIGN_CENTER);
    gtk_widget_set_tooltip_text(button, detail);
    gtk_box_append(GTK_BOX(box), image);
    gtk_box_append(GTK_BOX(box), label);
    gtk_box_append(GTK_BOX(box), name);
    gtk_box_append(GTK_BOX(box), chev);
    gtk_button_set_child(GTK_BUTTON(button), box);
    if (module != NULL) {
        g_object_set_data(G_OBJECT(button), "module", (gpointer) module);
        g_signal_connect(button, "clicked", G_CALLBACK(module_card_clicked), state);
    } else {
        g_object_set_data(G_OBJECT(button), "dashboard-tab", GINT_TO_POINTER(tab));
        g_signal_connect(button, "clicked", G_CALLBACK(dashboard_tab_clicked), state);
    }
    return button;
}

/* Card cues and favourites. The grid helpers that use these live below. */
static void pin_toggled(GtkButton *button, gpointer user_data);
static AppState *g_dash_state = NULL;   /* set by dash_fill, read by dash_cmp */

static GtkWidget *
make_module_card(AppState *state, const ModuleDefinition *mod)
{
    GtkWidget *button = gtk_button_new();
    GtkWidget *card   = gtk_box_new(GTK_ORIENTATION_VERTICAL, 3);
    GtkWidget *top    = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    GtkWidget *cat    = gtk_label_new(mod->category);
    GtkWidget *icon   = imsisting_icon_image(mod->icon);
    gboolean offline  = !module_script_exists(mod->id);
    gboolean pinned   = state->pins != NULL &&
                        g_hash_table_contains(state->pins, mod->id);
    gboolean recent   = state->recent != NULL &&
                        g_hash_table_contains(state->recent, mod->id);
    /* Only a state that DIFFERS from the norm gets a badge. A tile that is
       present and unpinned says nothing, because READY on 56 tiles is not
       information, it is wallpaper - and it teaches the reader to ignore the
       one corner where OFFLINE has to be noticed. */
    const char *chip_text = offline ? "OFFLINE"
                          : pinned  ? "PINNED"
                          : recent  ? "RECENT" : NULL;
    GtkWidget *chip   = chip_text ? gtk_label_new(chip_text) : NULL;
    gtk_image_set_pixel_size(GTK_IMAGE(icon), 57);
    gtk_widget_add_css_class(icon, category_class(mod->category));
    GtkWidget *name   = gtk_label_new(mod->name);
    GtkWidget *id     = gtk_label_new(mod->id);

    gtk_widget_add_css_class(button, "module-card");
    gtk_widget_add_css_class(card,   "module-card-inner");
    /* A GtkButton hands its child its natural width and centres it, so the
       inner surface stayed card-width while the tile around it was set to
       the width the grid computed - the tile looked small and the space
       inside it looked like a margin. Filling makes size_request on the
       button mean what it says. */
    gtk_widget_set_hexpand(card, TRUE);
    gtk_widget_set_halign(card, GTK_ALIGN_FILL);
    gtk_widget_add_css_class(card,   category_class(mod->category));
    gtk_widget_add_css_class(top,    "module-card-toprow");
    gtk_widget_add_css_class(cat,    "module-card-category");
    if (chip != NULL) {
        gtk_widget_add_css_class(chip, "module-card-state");
        gtk_widget_add_css_class(chip, offline ? "module-card-offline"
                                               : "module-card-ready");
        if (!offline && pinned)
            gtk_widget_add_css_class(chip, "module-card-pinned");
        else if (!offline && recent)
            gtk_widget_add_css_class(chip, "module-card-recent");
    }
    gtk_widget_add_css_class(cat,    category_class(mod->category));
    gtk_widget_add_css_class(icon,   "module-card-icon");
    gtk_widget_add_css_class(name,   "module-card-title");
    gtk_widget_add_css_class(id,     "module-card-id");
    /* The id was the third line of every tile. 56 monospace filenames read as
       a wall, and the name above already identifies the module; the id is in
       the tooltip and in the palette. Hiding rather than deleting keeps the
       label available for the search that still matches on it. */
    gtk_widget_set_visible(id, FALSE);
    if (offline)
        gtk_widget_add_css_class(icon, "module-card-offline");

    /* Left-aligned on the same rail as the category, the name and the id. It
       used to be centred and vexpanded, which let it swallow every spare pixel
       in the tile and push the text away from it - the emptiness the tile was
       criticised for. */
    gtk_widget_set_halign(icon, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(icon, GTK_ALIGN_CENTER);

    gtk_label_set_xalign(GTK_LABEL(cat), 0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(cat), PANGO_ELLIPSIZE_END);
    gtk_widget_set_hexpand(cat, TRUE);
    if (chip != NULL)
        gtk_widget_set_margin_end(chip, 4);

    gtk_label_set_ellipsize(GTK_LABEL(name), PANGO_ELLIPSIZE_END);
    gtk_label_set_xalign(GTK_LABEL(name), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(id), 0.0f);

    /* Bound the labels' NATURAL width - it is what decides how many tiles a
       row holds. */
    gtk_label_set_width_chars(GTK_LABEL(name), 18);

    /* Tile size lives in style.css (button.module-card) so there is one
       place to change it; the old 218x188 request fought the stylesheet
       and produced a different card size on every screen. */
    gtk_widget_set_hexpand(button, FALSE);
    gtk_widget_set_halign(button, GTK_ALIGN_START);
    gtk_widget_set_valign(button, GTK_ALIGN_START);

    /* The description moved to the tooltip. It was the only thing forcing a
       fixed card height, and a sentence printed on every tile is what turned
       a grid into a wall of text; the words stay one hover away. */
    if (offline) {
        gtk_widget_set_tooltip_text(button, "module script not found");
    } else {
        char *tip = (mod->desc && *mod->desc)
            ? g_strdup_printf("%s\n\n%s", mod->desc, mod->id)
            : g_strdup(mod->id);
        gtk_widget_set_tooltip_text(button, tip);
        g_free(tip);
    }

    gtk_box_append(GTK_BOX(top), cat);
    gtk_box_append(GTK_BOX(card), top);
    if (chip != NULL)
        gtk_box_append(GTK_BOX(top), chip);
    gtk_box_append(GTK_BOX(card), icon);
    gtk_box_append(GTK_BOX(card), name);
    gtk_button_set_child(GTK_BUTTON(button), card);
    gtk_box_append(GTK_BOX(card), id);

    g_object_set_data(G_OBJECT(button), "module", (gpointer) mod);
    g_signal_connect(button, "clicked", G_CALLBACK(module_card_clicked), state);

    /* The pin rides an overlay layer above the card, so tapping it does not
       also open the module the way a nested button would. It is revealed on
       hover and stays put once pinned: a permanent outline star on every tile
       is 56 pieces of furniture for an action used on two or three. */
    {
        GtkWidget *overlay = gtk_overlay_new();
        GtkWidget *star = gtk_button_new_with_label(pinned ? "★" : "☆");
        gtk_widget_add_css_class(overlay, "module-card-host");
        gtk_widget_add_css_class(star, "flat");
        gtk_widget_add_css_class(star, "card-pin");
        if (pinned)
            gtk_widget_add_css_class(star, "card-pin-on");
        gtk_widget_set_tooltip_text(star,
            pinned ? "unpin this module" : "pin this module");
        gtk_widget_set_halign(star, GTK_ALIGN_END);
        gtk_widget_set_valign(star, GTK_ALIGN_START);
        gtk_widget_set_margin_top(star, 4);
        gtk_widget_set_margin_end(star, 4);
        g_object_set_data(G_OBJECT(star), "state", state);
        g_object_set_data(G_OBJECT(star), "module-id", (gpointer) mod->id);
        g_signal_connect(star, "clicked", G_CALLBACK(pin_toggled), NULL);
        gtk_overlay_set_child(GTK_OVERLAY(overlay), button);
        gtk_overlay_add_overlay(GTK_OVERLAY(overlay), star);
        g_object_set_data(G_OBJECT(overlay), "module", (gpointer) mod);
        return overlay;
    }
}

#define DASH_COLS 7

/* Sort modes for the single dashboard grid. */
enum { DASH_SORT_WORKFLOW = 0, DASH_SORT_MOST_USED, DASH_SORT_NAME,
       DASH_SORT_CATEGORY };
static int g_dash_sort = DASH_SORT_WORKFLOW;
static const char *dash_sort_names[] = {
    "Workflow", "Most used", "Name (A–Z)", "Category", NULL
};

static int
dash_cmp(const void *pa, const void *pb)
{
    int a = *(const int *) pa, b = *(const int *) pb;
    gboolean pin_a = g_dash_state != NULL && g_dash_state->pins != NULL &&
                     g_hash_table_contains(g_dash_state->pins, modules[a].id);
    gboolean pin_b = g_dash_state != NULL && g_dash_state->pins != NULL &&
                     g_hash_table_contains(g_dash_state->pins, modules[b].id);
    if (pin_a != pin_b) return pin_a ? -1 : 1;   /* pinned cards lead */
    switch (g_dash_sort) {
        case DASH_SORT_MOST_USED: {
            guint ca = recent_count_of(a), cb = recent_count_of(b);
            if (ca != cb) return ca > cb ? -1 : 1;   /* most used leads */
            return a - b;
        }
        case DASH_SORT_NAME:
            return g_ascii_strcasecmp(modules[a].name, modules[b].name);
        case DASH_SORT_CATEGORY: {
            int r = g_ascii_strcasecmp(modules[a].category, modules[b].category);
            return r != 0 ? r : g_ascii_strcasecmp(modules[a].name, modules[b].name);
        }
        default:
            return a - b;   /* table order is the workflow order */
    }
}

/* ── Filling the line ────────────────────────────────────────────────
   GtkFlowBox sizes every child to its own minimum and then pours the
   space left over in a line into the GAPS. At 1180x760 that was 42
   pixels of dead desk between four 178-pixel tiles: the tiles were not
   too big, the line was simply not full, and no property of the flow box
   stretches a child to close it.

   So the width is handed to the tiles directly. Count how many columns
   the line can hold at the density's preferred width, then give every
   tile the exact width that fills the line at that count. The gaps go
   back to being the 8 pixels they are declared as. Wrapping is still the
   flow box's to decide, so this only has to run when the width changes,
   when the density changes, and when a search changes the visible count.
   ─────────────────────────────────────────────────────────────────── */

static int
dash_tile_preferred(AppState *state)
{
    /* This is the number that decides how many tiles fit on a line, so it is
       the number that decides how big they are: the cap in dash_fit_tiles()
       only ever shaves the last few pixels off, it cannot make a row of five
       become a row of four. Raised from 158/178/200 so the grid lays out
       fewer, larger tiles and the icon has room to be the thing you scan. */
    const char *d = state->density ? state->density : "density-comfortable";
    if (g_strcmp0(d, "density-compact") == 0) return 158;
    if (g_strcmp0(d, "density-spacious") == 0) return 200;
    return 178;
}

/* The card inside a flow box child, or the widget itself when it is not
   one. Both callers here need it, and the filter above learned the hard
   way that the flow box's direct children are wrappers. */
static GtkWidget *
dash_card_of(GtkWidget *w)
{
    if (GTK_IS_FLOW_BOX_CHILD(w))
        return gtk_flow_box_child_get_child(GTK_FLOW_BOX_CHILD(w));
    return w;
}

static gboolean
dash_fit_tiles(gpointer user_data)
{
    GtkWidget *flow  = GTK_WIDGET(user_data);
    AppState  *state = g_object_get_data(G_OBJECT(flow), "state");

    int avail = gtk_widget_get_width(flow);
    if (state == NULL || avail <= 0)
        return G_SOURCE_REMOVE;

    const int gap = 4;    /* matches column-spacing */
    const int cap = 300;  /* a lone search result should not span the desk */

    int cols = (avail + gap) / (dash_tile_preferred(state) + gap);
    if (cols < 1) cols = 1;
    if (cols > 7) cols = 7;   /* past seven a "tile" is a table row */

    /* A short result set should fill its line too, but two tiles stretched
       across the whole width read as a layout accident, so the tile stops
       at the cap and the rest of the line stays empty. */
    int visible = 0;
    for (GtkWidget *w = gtk_widget_get_first_child(flow); w != NULL;
         w = gtk_widget_get_next_sibling(w))
        if (gtk_widget_get_visible(w)) visible++;
    if (visible > 0 && cols > visible) cols = visible;

    int target = (avail - (cols - 1) * gap) / cols;
    /* The cap is for a grid with almost nothing in it: one search result
       should not stretch to the width of the desk. On a full line it is
       actively wrong, because the clamp hands the leftover width to the flow
       box to spread into the gaps - the exact spacing it was meant to fix. */
    if (cols <= 2 && target > cap) target = cap;
    if (target < 96)  target = 96;

    if (g_getenv("IMSISTING_FIT_DEBUG") != NULL)
        g_printerr("fit: avail=%d cols=%d visible=%d target=%d\n",
                   avail, cols, visible, target);

    if (GPOINTER_TO_INT(g_object_get_data(G_OBJECT(flow), "tile-w")) == target)
        return G_SOURCE_REMOVE;
    g_object_set_data(G_OBJECT(flow), "tile-w", GINT_TO_POINTER(target));

    /* Pin the column count. Left to itself the flow box reflows on the
       children's *natural* width, which is the width we are setting here --
       a feedback loop whose fixed point is not the line we computed. Naming
       the count makes the box lay out the grid we asked for; homogeneous
       gives every column the same share of the line instead of letting the
       widest card set the width and the rest hang.
       Only the maximum is pinned. A minimum would become the grid's own
       minimum width, the window would be unable to shrink below one full
       line, and the content would hang off the right edge of a window that
       refused to grow. With a maximum the box simply uses fewer columns
       when there is less room, which is the reflow we wanted. */
    gtk_flow_box_set_homogeneous(GTK_FLOW_BOX(flow), TRUE);
    gtk_flow_box_set_min_children_per_line(GTK_FLOW_BOX(flow), 1);
    gtk_flow_box_set_max_children_per_line(GTK_FLOW_BOX(flow), cols);
    gtk_flow_box_set_column_spacing(GTK_FLOW_BOX(flow), gap);

    for (GtkWidget *w = gtk_widget_get_first_child(flow); w != NULL;
         w = gtk_widget_get_next_sibling(w)) {
        GtkWidget *c = dash_card_of(w);
        if (c != NULL) gtk_widget_set_size_request(c, target, -1);
    }
    return G_SOURCE_REMOVE;
}

/* Deferred: the fit must read the width the flow box was actually given,
   and measure() must not be re-entered from inside an allocation. */
static void
dash_fit_soon(GtkWidget *flow)
{
    if (g_getenv("IMSISTING_FIT_DEBUG") != NULL)
        g_printerr("soon: flow=%p w=%d\n", (void*)flow,
                   flow ? gtk_widget_get_width(flow) : -1);
    if (flow == NULL) return;
    g_idle_add_full(G_PRIORITY_HIGH_IDLE, dash_fit_tiles,
                    g_object_ref(flow), g_object_unref);
}

/* There is no reliable event for "the line got wider". GtkWidget has no
   width property, GTK4 removed ::size-allocate, and a frame-clock tick is
   only delivered while the clock is running - under a bare X server it
   never ran once, so the first fit was the only fit and the grid kept the
   width of a window that did not exist yet. A 200 ms poll costs two
   integer compares when the window is still, and changing the width is a
   user action, so the latency is not perceptible. */
static gboolean
dash_width_poll(gpointer user_data)
{
    GtkWidget *flow = GTK_WIDGET(user_data);
    int w = gtk_widget_get_width(flow);

    if (g_getenv("IMSISTING_FIT_DEBUG") != NULL)
        g_printerr("poll: w=%d\n", w);

    if (w != GPOINTER_TO_INT(g_object_get_data(G_OBJECT(flow), "last-w"))) {
        g_object_set_data(G_OBJECT(flow), "last-w", GINT_TO_POINTER(w));
        dash_fit_soon(flow);
        if (g_getenv("IMSISTING_FIT_DEBUG") != NULL) {
            int n = 0;
            for (GtkWidget *c = gtk_widget_get_first_child(flow); c != NULL;
                 c = gtk_widget_get_next_sibling(c)) {
                int cw = gtk_widget_get_width(c);
                if (n < 4)
                    g_printerr("child[%d] w=%d req=%d\n", n, cw,
                               gtk_widget_get_width(
                                   dash_card_of(c)));
                n++;
            }
            g_printerr("poll: children=%d\n", n);
        }
    }
    return G_SOURCE_CONTINUE;
}

/* Rebuild the flow for a given sort mode. */
static void
dash_fill(AppState *state, GtkWidget *flow, int mode)
{
    GtkWidget *child;
    int idx[N_MODULES];

    g_dash_state = state;
    while ((child = gtk_widget_get_first_child(flow)) != NULL)
        gtk_flow_box_remove(GTK_FLOW_BOX(flow), child);

    g_dash_sort = mode;
    for (int i = 0; i < N_MODULES; i++) idx[i] = i;
    qsort(idx, N_MODULES, sizeof idx[0], dash_cmp);

    for (int k = 0; k < N_MODULES; k++)
        gtk_flow_box_append(GTK_FLOW_BOX(flow),
                            make_module_card(state, &modules[idx[k]]));

    dash_fit_soon(flow);
}

/* Show only the cards matching a query, over name, id, category and the
   module's own one-line description. */
static void
dash_apply_filter(GtkWidget *flow, const char *q)
{
    g_autofree char *needle = (q && *q) ? g_ascii_strdown(q, -1) : NULL;
    gboolean searching = needle != NULL && *needle != '\0';
    guint shown = 0;

    for (GtkWidget *w = gtk_widget_get_first_child(flow);
         w != NULL; w = gtk_widget_get_next_sibling(w)) {
        /* GtkFlowBox wraps every appended child in its own GtkFlowBoxChild,
           so the direct children of the flow box are wrappers, not the cards
           that carry the "module" data. Looking it up on the wrapper found
           NULL for all 56 and skipped every one, which is why this filter
           never hid a card. Unwrap first, and hide the wrapper so the grid
           reflows instead of leaving a gap. */
        GtkWidget *c = GTK_IS_FLOW_BOX_CHILD(w)
                     ? gtk_flow_box_child_get_child(GTK_FLOW_BOX_CHILD(w)) : w;
        if (c == NULL) continue;
        const ModuleDefinition *m = g_object_get_data(G_OBJECT(c), "module");
        if (m == NULL) continue;
        gboolean show = TRUE;
        if (searching) {
            g_autofree char *joined = g_strdup_printf("%s %s %s %s",
                m->name, m->id, m->category, m->desc ? m->desc : "");
            g_autofree char *hay = g_ascii_strdown(joined, -1);
            show = g_strrstr(hay, needle) != NULL;
        }
        gtk_widget_set_visible(w, show);
        if (show) shown++;
    }

    AppState *state = g_object_get_data(G_OBJECT(flow), "state");
    if (state != NULL && state->dash_empty != NULL)
        gtk_widget_set_visible(state->dash_empty, searching && shown == 0);
    /* Searching is about the grid, so the landing panel steps aside: without
       this the results (and the no-match note) sit below the fold of a
       window that is already showing the hero and the quick cards. */
    if (state != NULL && state->dash_mission != NULL)
        gtk_widget_set_visible(state->dash_mission, !searching);

    /* The visible count just changed, so the same line can hold a
       different number of tiles at the same width. */
    dash_fit_soon(flow);
}

/* ---- Favourites ------------------------------------------------------ */

static char *
pins_path(void)
{
    return g_build_filename(IMSISTING_ROOT, "state", "pins.tsv", NULL);
}

static void
pins_load(AppState *state)
{
    g_autofree char *path = pins_path();
    g_autofree char *data = NULL;
    g_auto(GStrv) lines = NULL;
    if (!g_file_get_contents(path, &data, NULL, NULL))
        return;
    lines = g_strsplit(data, "\n", -1);
    for (int i = 0; lines[i] != NULL; i++) {
        g_strstrip(lines[i]);
        if (*lines[i] != '\0')
            g_hash_table_insert(state->pins, g_strdup(lines[i]),
                                GINT_TO_POINTER(1));
    }
}

static void
pins_save(AppState *state)
{
    g_autofree char *path = pins_path();
    GString *out = g_string_new(NULL);
    GHashTableIter it;
    gpointer k;
    g_hash_table_iter_init(&it, state->pins);
    while (g_hash_table_iter_next(&it, &k, NULL))
        g_string_append_printf(out, "%s\n", (const char *) k);
    g_file_set_contents(path, out->str, -1, NULL);
    g_string_free(out, TRUE);
}

/* ---- Personalisation -------------------------------------------------
   Favourites live in state/pins.tsv, above. Everything else the operator
   tunes - tile density, dashboard order, and how often each module is
   actually run - lives in state/ui.tsv and state/recent.tsv, so a session
   opens the way the last one was left. Plain TSV: no parser to get wrong,
   and a file that survives being read by hand. */

static char *
ui_state_path(void)
{
    return g_build_filename(IMSISTING_ROOT, "state", "ui.tsv", NULL);
}

static char *
recents_path(void)
{
    return g_build_filename(IMSISTING_ROOT, "state", "recent.tsv", NULL);
}

/* How many times a module has been run. Missing means never. */
static guint
recent_count_of(int idx)
{
    if (g_dash_state == NULL || g_dash_state->recent_counts == NULL) return 0;
    return GPOINTER_TO_UINT(g_hash_table_lookup(g_dash_state->recent_counts,
                                                modules[idx].id));
}

static void
ui_state_save(AppState *state)
{
    g_autofree char *path = ui_state_path();
    GString *out = g_string_new(NULL);

    g_string_append_printf(out, "sort\t%d\n", g_dash_sort);
    g_string_append_printf(out, "density\t%s\n",
                           state->density ? state->density : "density-comfortable");
    g_file_set_contents(path, out->str, -1, NULL);
    g_string_free(out, TRUE);
}

static void
recents_save(AppState *state)
{
    g_autofree char *path = recents_path();
    GString *out = g_string_new(NULL);
    GHashTableIter it;
    gpointer k, v;

    if (state->recent_counts == NULL) return;
    g_hash_table_iter_init(&it, state->recent_counts);
    while (g_hash_table_iter_next(&it, &k, &v))
        g_string_append_printf(out, "%s\t%u\n", (const char *) k,
                               GPOINTER_TO_UINT(v));
    g_file_set_contents(path, out->str, -1, NULL);
    g_string_free(out, TRUE);
}

static void
recents_bump(AppState *state, const char *module_id)
{
    guint n;

    if (state == NULL || module_id == NULL) return;
    if (state->recent_counts == NULL)
        state->recent_counts =
            g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    n = GPOINTER_TO_UINT(g_hash_table_lookup(state->recent_counts, module_id));
    if (n < G_MAXUINT) n++;
    g_hash_table_insert(state->recent_counts, g_strdup(module_id),
                        GUINT_TO_POINTER(n));
    recents_save(state);
}

/* Density is one class on the window; the stylesheet carries the sizes, so
   nothing has to be re-measured or re-requested when it changes. */
static void
density_apply(AppState *state)
{
    static const char *classes[] = {
        "density-compact", "density-comfortable", "density-spacious", NULL
    };

    if (state == NULL || state->window == NULL) return;
    for (int i = 0; classes[i] != NULL; i++)
        gtk_widget_remove_css_class(state->window, classes[i]);
    gtk_widget_add_css_class(state->window, state->density
                             ? state->density : "density-comfortable");
    if (state->dash_flow != NULL) {
        g_object_set_data(G_OBJECT(state->dash_flow), "tile-w", NULL);
        dash_fit_soon(state->dash_flow);
    }
}

static int
density_index(AppState *state)
{
    const char *d = state->density ? state->density : "density-comfortable";

    if (g_strcmp0(d, "density-compact") == 0) return 0;
    if (g_strcmp0(d, "density-spacious") == 0) return 2;
    return 1;
}

static void
density_changed(GObject *dd, GParamSpec *pspec, gpointer user_data)
{
    static const char *names[] = {
        "density-compact", "density-comfortable", "density-spacious"
    };
    AppState *state = g_object_get_data(dd, "state");
    guint sel = gtk_drop_down_get_selected(GTK_DROP_DOWN(dd));

    if (state == NULL || sel > 2) return;
    g_free(state->density);
    state->density = g_strdup(names[sel]);
    density_apply(state);
    ui_state_save(state);
    (void) pspec; (void) user_data;
}

static void
ui_state_load(AppState *state)
{
    g_autofree char *path = ui_state_path();
    g_autofree char *data = NULL;

    if (state->recent_counts == NULL)
        state->recent_counts =
            g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

    if (g_file_get_contents(path, &data, NULL, NULL)) {
        g_auto(GStrv) lines = g_strsplit(data, "\n", -1);
        for (int i = 0; lines[i] != NULL; i++) {
            g_auto(GStrv) f = g_strsplit(lines[i], "\t", 2);
            if (f[0] == NULL || *f[0] == '\0' || f[1] == NULL) continue;
            if (g_strcmp0(f[0], "sort") == 0)
                g_dash_sort = CLAMP(atoi(f[1]), 0, DASH_SORT_CATEGORY);
            else if (g_strcmp0(f[0], "density") == 0) {
                g_free(state->density);
                state->density = g_strdup(f[1]);
            }
        }
    }

    g_autofree char *rpath = recents_path();
    g_autofree char *rdata = NULL;
    if (g_file_get_contents(rpath, &rdata, NULL, NULL)) {
        g_auto(GStrv) rlines = g_strsplit(rdata, "\n", -1);
        for (int i = 0; rlines[i] != NULL; i++) {
            g_auto(GStrv) f = g_strsplit(rlines[i], "\t", 2);
            if (f[0] == NULL || *f[0] == '\0' || f[1] == NULL) continue;
            g_hash_table_insert(state->recent_counts, g_strdup(f[0]),
                                GUINT_TO_POINTER((guint) atoi(f[1])));
        }
    }
}

static void
dash_refresh(AppState *state)
{
    if (state->dash_flow == NULL) return;
    dash_fill(state, state->dash_flow, g_dash_sort);
    if (state->dash_search != NULL)
        dash_apply_filter(state->dash_flow,
            gtk_editable_get_text(GTK_EDITABLE(state->dash_search)));
}

static void
pin_toggled(GtkButton *button, gpointer user_data)
{
    AppState *state = g_object_get_data(G_OBJECT(button), "state");
    const char *id = g_object_get_data(G_OBJECT(button), "module-id");
    if (state == NULL || id == NULL) return;
    if (g_hash_table_contains(state->pins, id))
        g_hash_table_remove(state->pins, id);
    else
        g_hash_table_insert(state->pins, g_strdup(id), GINT_TO_POINTER(1));
    pins_save(state);
    dash_refresh(state);
    (void) user_data;
}

static void
dash_sort_changed(GObject *dd, GParamSpec *pspec, gpointer user_data)
{
    GtkWidget *flow   = g_object_get_data(dd, "grid");
    GtkWidget *search = g_object_get_data(dd, "search");
    AppState  *state  = g_object_get_data(dd, "state");
    guint sel = gtk_drop_down_get_selected(GTK_DROP_DOWN(dd));
    dash_fill(state, flow, (int) sel);
    ui_state_save(state);   /* the operator's order outlives the session */
    dash_apply_filter(flow,
        search ? gtk_editable_get_text(GTK_EDITABLE(search)) : "");
    (void) pspec; (void) user_data;
}

static void
dash_search_changed(GtkEditable *e, gpointer user_data)
{
    dash_apply_filter(GTK_WIDGET(user_data), gtk_editable_get_text(e));
}

static GtkWidget *
create_dashboard_page(AppState *state)
{
    GtkWidget *outer    = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *scroll   = gtk_scrolled_window_new();
    GtkWidget *body     = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    GtkWidget *bar      = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *mission = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *mission_head = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *mission_title = gtk_label_new("Start here");
    GtkWidget *mission_sub = gtk_label_new(
        "In order — set the case, verify the bench, then move into collection.");
    GtkWidget *mission_grid = gtk_flow_box_new();
    GtkWidget *grid_head = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *grid_title = gtk_label_new("All modules");
    GtkWidget *grid_sub = gtk_label_new(
        "The full catalogue — search or sort, then click a card to open it.");
    gtk_widget_add_css_class(mission, "mission-panel");
    gtk_widget_add_css_class(mission_title, "section-eyebrow");
    gtk_widget_add_css_class(mission_sub, "section-note");
    gtk_widget_add_css_class(grid_title, "section-eyebrow");
    gtk_widget_add_css_class(grid_sub, "section-note");
    gtk_label_set_xalign(GTK_LABEL(mission_title), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(mission_sub), 1.0f);
    gtk_label_set_xalign(GTK_LABEL(grid_title), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(grid_sub), 1.0f);
    gtk_widget_set_hexpand(mission_title, TRUE);
    gtk_widget_set_hexpand(grid_title, TRUE);
    gtk_flow_box_set_selection_mode(GTK_FLOW_BOX(mission_grid), GTK_SELECTION_NONE);
    gtk_flow_box_set_homogeneous(GTK_FLOW_BOX(mission_grid), TRUE);
    gtk_flow_box_set_max_children_per_line(GTK_FLOW_BOX(mission_grid), 2);
    gtk_flow_box_set_min_children_per_line(GTK_FLOW_BOX(mission_grid), 2);
    gtk_flow_box_set_column_spacing(GTK_FLOW_BOX(mission_grid), 8);
    gtk_flow_box_set_row_spacing(GTK_FLOW_BOX(mission_grid), 8);
    gtk_flow_box_append(GTK_FLOW_BOX(mission_grid),
        dashboard_shortcut(state, "01", "Define the operation",
            "CASEBOOK — set the case, the target and the evidence ledger",
            "book-open-symbolic", NULL, 2));
    gtk_flow_box_append(GTK_FLOW_BOX(mission_grid),
        dashboard_shortcut(state, "02", "Check the field kit",
            "BENCH — confirm hardware and capture readiness",
            "imsisting-05_field_kit-symbolic",
            dashboard_module("05_field_kit"), -1));
    gtk_flow_box_append(GTK_FLOW_BOX(mission_grid),
        dashboard_shortcut(state, "03", "Survey the cell layer",
            "RECON — identify the carrier before deeper work",
            "imsisting-02_cell_recon-symbolic",
            dashboard_module("02_cell_recon"), -1));
    gtk_flow_box_append(GTK_FLOW_BOX(mission_grid),
        dashboard_shortcut(state, "04", "Watch traffic",
            "LIVE — inspect the GSMTAP feed as it arrives",
            "network-receive-symbolic", NULL, 1));
    gtk_box_append(GTK_BOX(mission_head), mission_title);
    gtk_box_append(GTK_BOX(mission_head), mission_sub);
    gtk_box_append(GTK_BOX(mission), mission_head);
    /* The case counters used to sit here as a band. They moved to the target
       column, which is the one panel that can be open over every page: on
       the dashboard they were only readable while the dashboard was the
       page in front. */
    gtk_box_append(GTK_BOX(mission), mission_grid);
    GtkWidget *sortlab  = gtk_label_new("Sort");
    GtkWidget *dd       = gtk_drop_down_new_from_strings(dash_sort_names);
    /* The flow is already built in the persisted order, so the control has to
       agree with it or it reads "Workflow" over a most-used list. Set before
       the notify handler is attached, so this does not re-fill the grid. */
    gtk_drop_down_set_selected(GTK_DROP_DOWN(dd),
                               CLAMP(g_dash_sort, 0, DASH_SORT_CATEGORY));
    /* Density sits next to Sort because both are "how I want to see the
       desk" rather than "what the desk is doing". */
    static const char *density_names[] = {
        "Compact", "Comfortable", "Spacious", NULL
    };
    GtkWidget *denslab  = gtk_label_new("Density");
    GtkWidget *dens     = gtk_drop_down_new_from_strings(density_names);
    GtkWidget *search   = gtk_search_entry_new();
    GtkWidget *flow     = gtk_flow_box_new();

    gtk_widget_add_css_class(sortlab, "dim");
    gtk_widget_add_css_class(denslab, "dim");
    gtk_drop_down_set_selected(GTK_DROP_DOWN(dens), density_index(state));
    g_object_set_data(G_OBJECT(dens), "state", state);
    g_signal_connect(dens, "notify::selected", G_CALLBACK(density_changed), NULL);

    /* One label per layer and no H1. The tab above already reads "Dashboard",
       so an in-page "Command Dashboard" repeated it, and "Start here" sat
       three lines below that: three titles for one screen, with the quick
       cards drawn heavier than the 57 modules they were meant to introduce.
       What was missing was never another heading, it was a stated hierarchy -
       the strip is an order of operations, the grid is the catalogue, and
       each now says so exactly once. */
    gtk_widget_set_margin_start(mission, 16);
    gtk_widget_set_margin_end(mission, 16);
    gtk_widget_set_margin_top(mission, 10);
    gtk_box_append(GTK_BOX(body), mission);

    gtk_box_append(GTK_BOX(grid_head), grid_title);
    gtk_box_append(GTK_BOX(grid_head), grid_sub);
    gtk_widget_set_margin_top(grid_head, 10);
    gtk_widget_set_margin_start(grid_head, 16);
    gtk_widget_set_margin_end(grid_head, 16);
    gtk_box_append(GTK_BOX(body), grid_head);

    gtk_search_entry_set_placeholder_text(GTK_SEARCH_ENTRY(search),
        "Search name, id or purpose…");
    gtk_widget_set_hexpand(search, TRUE);
    gtk_box_append(GTK_BOX(bar), sortlab);
    gtk_box_append(GTK_BOX(bar), dd);
    gtk_box_append(GTK_BOX(bar), denslab);
    gtk_box_append(GTK_BOX(bar), dens);
    gtk_box_append(GTK_BOX(bar), search);
    gtk_widget_set_margin_start(bar, 16);
    gtk_widget_set_margin_end(bar, 16);
    gtk_widget_set_margin_top(bar, 4);
    gtk_box_append(GTK_BOX(body), bar);

    state->dash_mission = mission;   /* hidden while a search is active */

    /* A responsive flow instead of a fixed grid: columns follow the width.
       Not homogeneous: with it on, every row stretched its children to
       fill the line, so a row of four and a row of two drew different
       sized cards. Tiles now keep one size and simply pack. */
    gtk_flow_box_set_selection_mode(GTK_FLOW_BOX(flow), GTK_SELECTION_NONE);
    gtk_flow_box_set_homogeneous(GTK_FLOW_BOX(flow), TRUE);
    gtk_flow_box_set_max_children_per_line(GTK_FLOW_BOX(flow), 8);
    gtk_flow_box_set_min_children_per_line(GTK_FLOW_BOX(flow), 1);
    gtk_flow_box_set_column_spacing(GTK_FLOW_BOX(flow), 8);
    gtk_flow_box_set_row_spacing(GTK_FLOW_BOX(flow), 8);
    gtk_widget_set_halign(flow, GTK_ALIGN_FILL);
    gtk_widget_set_margin_start(flow, 16);
    gtk_widget_set_margin_end(flow, 16);
    gtk_widget_set_margin_top(flow, 6);
    gtk_box_append(GTK_BOX(body), flow);

    /* A search that matches nothing used to blank the grid with no word of
       explanation. This states it, in the space the cards would have used;
       it stays hidden unless a search is active and hides every card. It
       lives inside the scrolling body rather than on an overlay, because an
       overlay centres over the whole body and would land on the quick cards. */
    state->dash_empty = empty_state("system-search-symbolic",
        "No module matches", "Clear the search, or try a category such as "
        "RADIO, ACCESS or ANALYSIS.");
    gtk_widget_set_visible(state->dash_empty, FALSE);
    gtk_widget_set_margin_top(state->dash_empty, 28);
    gtk_widget_set_margin_bottom(state->dash_empty, 28);
    gtk_box_append(GTK_BOX(body), state->dash_empty);

    g_object_set_data(G_OBJECT(dd), "grid",   flow);
    g_object_set_data(G_OBJECT(dd), "search", search);
    g_object_set_data(G_OBJECT(dd), "state",  state);
    g_object_set_data(G_OBJECT(flow), "state", state);
    g_timeout_add_full(G_PRIORITY_DEFAULT_IDLE, 200, dash_width_poll,
                       g_object_ref(flow), g_object_unref);
    g_signal_connect(dd, "notify::selected", G_CALLBACK(dash_sort_changed), NULL);
    g_signal_connect(search, "search-changed",
                     G_CALLBACK(dash_search_changed), flow);

    if (state->pins == NULL) {
        state->pins = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
        pins_load(state);
    }
    if (state->recent == NULL)
        state->recent = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    state->dash_flow = flow;
    state->dash_search = search;

    dash_fill(state, flow, g_dash_sort);   /* honour the persisted order */

    gtk_widget_set_margin_bottom(body, 18);
    /* Never scroll the module grid sideways. With an automatic horizontal
       policy the flow box is handed its *natural* width once that exceeds
       the viewport, so the width the fit reads back is the width it just
       asked for: the column count feeds itself and the grid settles on six
       columns that hang off the right edge. A reflowing grid must be told
       the viewport width, which only happens when sideways scrolling is
       impossible. */
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), body);
    gtk_widget_set_vexpand(scroll, TRUE);
    gtk_box_append(GTK_BOX(outer), scroll);
    return outer;
}

/* ==================================================================== */
/*  LOOT                                                                */
/* ==================================================================== */

/* A reusable empty / loading state: a muted glyph, a title, and the exact
   command that fills the page. */
static GtkWidget *
empty_state(const char *icon, const char *title, const char *hint)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GtkWidget *ic  = imsisting_icon_image(icon);
    GtkWidget *t   = gtk_label_new(title);
    GtkWidget *h   = gtk_label_new(hint);

    gtk_widget_add_css_class(box, "empty-state");
    gtk_widget_add_css_class(ic,  "empty-icon");
    gtk_widget_add_css_class(t,   "empty-title");
    gtk_widget_add_css_class(h,   "empty-hint");
    gtk_image_set_pixel_size(GTK_IMAGE(ic), 56);
    /* The sidebar is narrow, so the hint has to fold instead of running off
       the edge; the dashboard is wide enough that it simply stays one line. */
    gtk_label_set_wrap(GTK_LABEL(h), TRUE);
    gtk_label_set_wrap_mode(GTK_LABEL(h), PANGO_WRAP_WORD_CHAR);
    gtk_label_set_justify(GTK_LABEL(h), GTK_JUSTIFY_CENTER);
    gtk_label_set_max_width_chars(GTK_LABEL(h), 34);
    gtk_widget_set_halign(box, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(box, GTK_ALIGN_CENTER);
    gtk_box_append(GTK_BOX(box), ic);
    gtk_box_append(GTK_BOX(box), t);
    gtk_box_append(GTK_BOX(box), h);
    return box;
}

static guint
count_files(const char *dir)
{
    g_autoptr(GDir) d = g_dir_open(dir, 0, NULL);
    guint n = 0;
    const char *name;
    if (d == NULL) return 0;
    while ((name = g_dir_read_name(d)) != NULL) {
        g_autofree char *p = g_build_filename(dir, name, NULL);
        if (g_file_test(p, G_FILE_TEST_IS_REGULAR)) n++;
    }
    return n;
}

static char *
loot_fmt_size(guint64 n)
{
    if (n < 1024)                   return g_strdup_printf("%llu B", (unsigned long long) n);
    if (n < 1024 * 1024)            return g_strdup_printf("%.1f KB", n / 1024.0);
    if (n < 1024ULL * 1024 * 1024)  return g_strdup_printf("%.1f MB", n / (1024.0 * 1024.0));
    return g_strdup_printf("%.2f GB", n / (1024.0 * 1024.0 * 1024.0));
}

static void
loot_entry_free(gpointer p)
{
    LootEntry *e = p;
    if (e == NULL) return;
    g_free(e->path);
    g_free(e->name);
    g_free(e->module);
    g_free(e);
}

static const char *
loot_ext(const char *name)
{
    const char *dot = strrchr(name != NULL ? name : "", '.');
    return dot != NULL ? dot + 1 : "";
}

static gboolean
loot_is_image(const char *name)
{
    static const char *ext[] = { "png", "jpg", "jpeg", "gif", "webp", "bmp",
                                 "svg", "tif", "tiff", NULL };
    for (int i = 0; ext[i] != NULL; i++)
        if (g_ascii_strcasecmp(loot_ext(name), ext[i]) == 0) return TRUE;
    return FALSE;
}

static gboolean
loot_is_text(const char *name)
{
    static const char *ext[] = { "txt", "log", "csv", "tsv", "json", "md", "xml",
                                 "yaml", "yml", "py", "sh", "c", "h", "conf", "ini",
                                 "hex", "kml", "geojson", "sql", "html", "htm",
                                 "pcap", "pcapng", "cap", "gsmtap", NULL };
    for (int i = 0; ext[i] != NULL; i++)
        if (g_ascii_strcasecmp(loot_ext(name), ext[i]) == 0) return TRUE;
    return FALSE;
}

/* No known extension: decide by looking, because a great deal of what these
   modules write is plain text under a name nobody anticipated. A NUL in the
   first kilobyte is the one signal that survives every format. */
static gboolean
loot_bytes_look_text(const char *buf, gsize len)
{
    if (buf == NULL) return FALSE;
    gsize n = MIN(len, (gsize) 1024);
    for (gsize i = 0; i < n; i++)
        if (buf[i] == '\0') return FALSE;
    return TRUE;
}

static const char *
loot_icon_for(const char *name)
{
    if (loot_is_image(name)) return "image-x-generic-symbolic";
    if (loot_is_text(name))  return "text-x-generic-symbolic";
    return "application-x-generic-symbolic";
}

/* Every regular file one level under loot/<module>/ - the same shape the
   modules write, and the level at which a file still has a module to blame. */
static GPtrArray *
loot_scan(void)
{
    GPtrArray *out = g_ptr_array_new_with_free_func(loot_entry_free);
    g_autofree char *root = g_build_filename(IMSISTING_ROOT, "loot", NULL);
    g_autoptr(GDir) d = g_dir_open(root, 0, NULL);
    if (d == NULL) return out;

    const char *mod;
    while ((mod = g_dir_read_name(d)) != NULL) {
        g_autofree char *sub = g_build_filename(root, mod, NULL);
        if (!g_file_test(sub, G_FILE_TEST_IS_DIR)) continue;
        g_autoptr(GDir) sd = g_dir_open(sub, 0, NULL);
        if (sd == NULL) continue;
        const char *fn;
        while ((fn = g_dir_read_name(sd)) != NULL) {
            g_autofree char *fp = g_build_filename(sub, fn, NULL);
            GStatBuf st;
            if (g_stat(fp, &st) != 0 || !S_ISREG(st.st_mode)) continue;
            LootEntry *e = g_new0(LootEntry, 1);
            e->path   = g_strdup(fp);
            e->name   = g_strdup(fn);
            e->module = g_strdup(mod);
            e->size   = (guint64) st.st_size;
            e->mtime  = (gint64)  st.st_mtime;
            g_ptr_array_add(out, e);
        }
    }
    return out;
}

static gint
loot_cmp(gconstpointer a, gconstpointer b, gpointer user_data)
{
    const LootEntry *x = *(LootEntry *const *) a;
    const LootEntry *y = *(LootEntry *const *) b;
    AppState *state = user_data;

    switch (state != NULL ? state->loot_sort_mode : 0) {
    case 1:   /* biggest first: the thing you are looking for is usually large */
        return x->size < y->size ? 1 : x->size > y->size ? -1 : 0;
    case 2:   /* newest first */
        return x->mtime < y->mtime ? 1 : x->mtime > y->mtime ? -1 : 0;
    case 3: { /* grouped by the module that produced it */
        int c = g_ascii_strcasecmp(x->module, y->module);
        return c != 0 ? c : g_ascii_strcasecmp(x->name, y->name);
    }
    default:
        return g_ascii_strcasecmp(x->name, y->name);
    }
}

static gboolean
loot_match(const LootEntry *e, const char *needle)
{
    if (needle == NULL || *needle == '\0') return TRUE;
    g_autofree char *n   = g_ascii_strdown(needle, -1);
    g_autofree char *nm  = g_ascii_strdown(e->name, -1);
    g_autofree char *mod = g_ascii_strdown(e->module, -1);
    return strstr(nm, n) != NULL || strstr(mod, n) != NULL;
}

/* The seven fixed tabs of the casebook notebook, in the order
   create_casebook_page appends them. Evidence files open after these. */
#define CASEBOOK_TAB_COUNT     7
#define CASEBOOK_TAB_OVERVIEW  0
#define CASEBOOK_TAB_EVIDENCE  1
#define CASEBOOK_TAB_CAPTURES  2
#define CASEBOOK_TAB_TIMELINE  3
#define CASEBOOK_TAB_ALERTS    4
#define CASEBOOK_TAB_NODES     5
#define CASEBOOK_TAB_REPORTS   6

static void
casebook_file_close_clicked(GtkButton *button, gpointer user_data)
{
    AppState *state = g_object_get_data(G_OBJECT(button), "state");
    GtkWidget *page = user_data;
    int index;

    if (state == NULL || state->casebook_tabs == NULL) return;
    index = gtk_notebook_page_num(GTK_NOTEBOOK(state->casebook_tabs), page);
    if (index < 0) return;

    /* Same trap as closing a module: removing the page you are standing on
       makes GTK pick the next one, and its pick is the last page left - so
       closing the file you are reading used to jump to Reports. Land back on
       Evidence, which is where files are opened from. Closing a tab you were
       not reading changes nothing. */
    gboolean was_current =
        gtk_notebook_get_current_page(GTK_NOTEBOOK(state->casebook_tabs)) == index;
    gtk_notebook_remove_page(GTK_NOTEBOOK(state->casebook_tabs), index);
    if (was_current && index >= CASEBOOK_TAB_COUNT)
        gtk_notebook_set_current_page(GTK_NOTEBOOK(state->casebook_tabs),
                                      CASEBOOK_TAB_EVIDENCE);
}

static void
casebook_system_open_clicked(GtkButton *button, gpointer user_data)
{
    const char *path = g_object_get_data(G_OBJECT(button), "file-path");
    g_autofree char *uri = NULL;

    (void) user_data;
    if (path == NULL) return;
    uri = g_filename_to_uri(path, NULL, NULL);
    if (uri != NULL)
        g_app_info_launch_default_for_uri(uri, NULL, NULL);
}

/* A file opened from Evidence becomes a page in the Casebook's own notebook,
   so it sits beside the case it belongs to instead of in a modal the user has
   to dismiss before getting back to the work. */
static GtkWidget *
casebook_file_view(const char *path)
{
    GtkWidget *outer  = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *bar    = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *where  = gtk_label_new(path);
    GtkWidget *scroll = gtk_scrolled_window_new();
    GtkWidget *open   = gtk_button_new_with_label("Open with system");
    g_autofree char *base = g_path_get_basename(path);
    GStatBuf st;

    gtk_widget_add_css_class(outer, "cb-file");
    gtk_widget_add_css_class(where, "cb-file-path");
    gtk_label_set_xalign(GTK_LABEL(where), 0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(where), PANGO_ELLIPSIZE_MIDDLE);
    gtk_widget_set_hexpand(where, TRUE);
    gtk_widget_add_css_class(open, "verb-button");
    g_object_set_data_full(G_OBJECT(open), "file-path", g_strdup(path), g_free);
    g_signal_connect(open, "clicked", G_CALLBACK(casebook_system_open_clicked), NULL);
    gtk_box_append(GTK_BOX(bar), where);
    gtk_box_append(GTK_BOX(bar), open);
    gtk_widget_set_margin_top(bar, 12);
    gtk_widget_set_margin_bottom(bar, 8);
    gtk_widget_set_margin_start(bar, 16);
    gtk_widget_set_margin_end(bar, 16);
    gtk_box_append(GTK_BOX(outer), bar);

    if (loot_is_image(base)) {
        GtkWidget *pic = gtk_picture_new_for_filename(path);
        gtk_picture_set_can_shrink(GTK_PICTURE(pic), TRUE);
        gtk_widget_set_halign(pic, GTK_ALIGN_CENTER);
        gtk_widget_set_valign(pic, GTK_ALIGN_CENTER);
        gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), pic);
    } else {
        GtkWidget *view = gtk_text_view_new();
        GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));
        guint64 size = (g_stat(path, &st) == 0) ? (guint64) st.st_size : 0;

        if (size > 8ULL * 1024 * 1024) {
            g_autofree char *sz = loot_fmt_size(size);
            g_autofree char *msg = g_strdup_printf(
                "This file is %s — too large to render here.\n\n"
                "Use Open with system to inspect it, or index it from Captures "
                "where the toolchain reads it properly.", sz);
            gtk_text_buffer_set_text(buf, msg, -1);
        } else {
            g_autofree char *body = NULL;
            gsize len = 0;
            if (g_file_get_contents(path, &body, &len, NULL) &&
                loot_bytes_look_text(body, len)) {
                gtk_text_buffer_set_text(buf, body, -1);
            } else {
                g_autofree char *sz = loot_fmt_size(size);
                g_autofree char *msg = g_strdup_printf(
                    "This is a binary file (%s), so there is nothing readable "
                    "to show.\n\nOpen with system hands it to whichever tool "
                    "you have registered for it.", sz);
                gtk_text_buffer_set_text(buf, msg, -1);
            }
        }
        gtk_text_view_set_editable(GTK_TEXT_VIEW(view), FALSE);
        gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(view), FALSE);
        gtk_text_view_set_monospace(GTK_TEXT_VIEW(view), TRUE);
        gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(view), GTK_WRAP_WORD_CHAR);
        gtk_text_view_set_left_margin(GTK_TEXT_VIEW(view), 16);
        gtk_text_view_set_right_margin(GTK_TEXT_VIEW(view), 16);
        gtk_widget_add_css_class(view, "cb-file-text");
        gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), view);
    }

    gtk_widget_set_vexpand(scroll, TRUE);
    gtk_box_append(GTK_BOX(outer), scroll);
    return outer;
}

static void
casebook_open_file(AppState *state, const char *path)
{
    int n, idx;
    GtkWidget *page, *tab, *label, *close;

    if (state == NULL || state->casebook_tabs == NULL || path == NULL) return;

    n = gtk_notebook_get_n_pages(GTK_NOTEBOOK(state->casebook_tabs));
    for (int i = 0; i < n; i++) {
        GtkWidget *p = gtk_notebook_get_nth_page(GTK_NOTEBOOK(state->casebook_tabs), i);
        if (g_strcmp0(g_object_get_data(G_OBJECT(p), "file-path"), path) == 0) {
            gtk_notebook_set_current_page(GTK_NOTEBOOK(state->casebook_tabs), i);
            return;
        }
    }

    page = casebook_file_view(path);
    g_object_set_data_full(G_OBJECT(page), "file-path", g_strdup(path), g_free);

    tab   = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    label = gtk_label_new(g_path_get_basename(path));
    close = gtk_button_new_from_icon_name("window-close-symbolic");
    gtk_widget_add_css_class(close, "flat");
    gtk_widget_set_tooltip_text(close, "close this file");
    g_object_set_data(G_OBJECT(close), "state", state);
    g_signal_connect(close, "clicked", G_CALLBACK(casebook_file_close_clicked), page);
    gtk_box_append(GTK_BOX(tab), label);
    gtk_box_append(GTK_BOX(tab), close);

    idx = gtk_notebook_append_page(GTK_NOTEBOOK(state->casebook_tabs), page, tab);
    gtk_notebook_set_current_page(GTK_NOTEBOOK(state->casebook_tabs), idx);
}

static void
loot_open_clicked(GtkButton *button, gpointer user_data)
{
    casebook_open_file(user_data, g_object_get_data(G_OBJECT(button), "loot-file"));
}

static void
loot_add_row(AppState *state, const LootEntry *e)
{
    GtkWidget *row   = gtk_list_box_row_new();
    GtkWidget *box   = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *icon  = imsisting_icon_image(loot_icon_for(e->name));
    GtkWidget *text  = gtk_box_new(GTK_ORIENTATION_VERTICAL, 1);
    GtkWidget *name  = gtk_label_new(e->name);
    GtkWidget *meta  = gtk_label_new(NULL);
    GtkWidget *open  = gtk_button_new_with_label("Open");
    g_autofree char *sz = loot_fmt_size(e->size);
    g_autofree char *when = NULL;
    g_autofree char *sub = NULL;

    if (e->mtime > 0) {
        GDateTime *dt = g_date_time_new_from_unix_local(e->mtime);
        when = g_date_time_format(dt, "%Y-%m-%d %H:%M");
        g_date_time_unref(dt);
    }
    sub = g_strdup_printf("%s · %s · %s", e->module, sz, when != NULL ? when : "—");

    gtk_image_set_pixel_size(GTK_IMAGE(icon), 20);
    gtk_label_set_xalign(GTK_LABEL(name), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(meta), 0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(name), PANGO_ELLIPSIZE_MIDDLE);
    gtk_widget_add_css_class(name, "loot-name");
    gtk_widget_add_css_class(meta, "loot-meta");
    gtk_widget_add_css_class(open, "verb-button");
    gtk_widget_set_valign(open, GTK_ALIGN_CENTER);
    gtk_widget_set_hexpand(text, TRUE);
    gtk_label_set_text(GTK_LABEL(meta), sub);

    gtk_box_append(GTK_BOX(text), name);
    gtk_box_append(GTK_BOX(text), meta);
    gtk_box_append(GTK_BOX(box), icon);
    gtk_box_append(GTK_BOX(box), text);
    gtk_box_append(GTK_BOX(box), open);
    gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), box);

    g_object_set_data_full(G_OBJECT(row), "loot-file", g_strdup(e->path), g_free);
    g_object_set_data_full(G_OBJECT(open), "loot-file", g_strdup(e->path), g_free);
    g_signal_connect(open, "clicked", G_CALLBACK(loot_open_clicked), state);
    gtk_list_box_append(GTK_LIST_BOX(state->loot_list), row);
}

static void
loot_refresh(AppState *state)
{
    GtkWidget *child;
    const char *needle;
    guint shown = 0;
    guint64 bytes = 0;

    if (state->loot_list == NULL) return;
    while ((child = gtk_widget_get_first_child(state->loot_list)) != NULL)
        gtk_list_box_remove(GTK_LIST_BOX(state->loot_list), child);

    g_clear_pointer(&state->loot_entries, g_ptr_array_unref);
    state->loot_entries = loot_scan();
    g_ptr_array_sort_with_data(state->loot_entries, loot_cmp, state);

    needle = state->loot_search != NULL
           ? gtk_editable_get_text(GTK_EDITABLE(state->loot_search)) : NULL;

    for (guint i = 0; i < state->loot_entries->len; i++) {
        LootEntry *e = g_ptr_array_index(state->loot_entries, i);
        if (!loot_match(e, needle)) continue;
        loot_add_row(state, e);
        shown++;
        bytes += e->size;
    }

    if (shown == 0) {
        gboolean empty = state->loot_entries->len == 0;
        GtkWidget *row = gtk_list_box_row_new();
        GtkWidget *es  = empty_state("folder-symbolic",
            empty ? "No evidence yet" : "Nothing matches",
            empty ? "run a module that collects something, then Refresh"
                  : "clear the search to see every file again");
        gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), es);
        gtk_list_box_row_set_selectable(GTK_LIST_BOX_ROW(row), FALSE);
        gtk_list_box_row_set_activatable(GTK_LIST_BOX_ROW(row), FALSE);
        gtk_list_box_append(GTK_LIST_BOX(state->loot_list), row);
    }

    if (state->loot_count_lbl != NULL) {
        g_autofree char *sz = loot_fmt_size(bytes);
        g_autofree char *txt = (needle != NULL && *needle != '\0')
            ? g_strdup_printf("%u of %u files · %s", shown, state->loot_entries->len, sz)
            : g_strdup_printf("%u file%s · %s", shown, shown == 1 ? "" : "s", sz);
        gtk_label_set_text(GTK_LABEL(state->loot_count_lbl), txt);
    }
}


static void
loot_row_activated(GtkListBox *lb, GtkListBoxRow *row, gpointer user_data)
{
    casebook_open_file(user_data, row ? g_object_get_data(G_OBJECT(row), "loot-file") : NULL);
    (void) lb;
}

static void
loot_search_changed(GtkEditable *editable, gpointer user_data)
{
    (void) editable;
    loot_refresh(user_data);
}

static void
loot_sort_changed(GObject *dropdown, GParamSpec *pspec, gpointer user_data)
{
    AppState *state = user_data;
    state->loot_sort_mode = (int) gtk_drop_down_get_selected(GTK_DROP_DOWN(dropdown));
    loot_refresh(state);
    (void) pspec;
}

static void
loot_refresh_clicked(GtkButton *b, gpointer user_data)
{
    (void) b;
    loot_refresh(user_data);
}

static GtkWidget *
create_evidence_page(AppState *state)
{
    GtkWidget *outer  = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *head   = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *box    = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *title  = gtk_label_new("Evidence Browser");
    GtkWidget *sub    = gtk_label_new(NULL);
    GtkWidget *list   = gtk_list_box_new();
    GtkWidget *refresh = gtk_button_new_with_label("Refresh");
    GtkWidget *lscroll = gtk_scrolled_window_new();
    g_autofree char *dir = g_build_filename(IMSISTING_ROOT, "loot", NULL);

    gtk_widget_add_css_class(title, "page-title");
    gtk_widget_add_css_class(sub,   "page-subtitle");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(sub),   0.0f);
    gtk_label_set_text(GTK_LABEL(sub), dir);
    gtk_widget_set_hexpand(box, TRUE);

    gtk_box_append(GTK_BOX(box), title);
    gtk_box_append(GTK_BOX(box), sub);
    gtk_box_append(GTK_BOX(head), box);
    gtk_box_append(GTK_BOX(head), refresh);
    gtk_widget_set_margin_top(head, 14);
    gtk_widget_set_margin_bottom(head, 8);
    gtk_widget_set_margin_start(head, 16);
    gtk_widget_set_margin_end(head, 16);
    gtk_box_append(GTK_BOX(outer), head);

    /* Finding a file is the whole job of this tab once a case has been
       running for a while, so search and order sit above the list rather
       than behind a menu. */
    {
        GtkWidget *bar    = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        GtkWidget *search = gtk_search_entry_new();
        GtkWidget *sort   = gtk_drop_down_new_from_strings(
            (const char *[]) { "Name", "Size", "Newest", "Module", NULL });
        GtkWidget *count  = gtk_label_new("No evidence yet");
        GtkWidget *spacer = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);

        gtk_search_entry_set_placeholder_text(GTK_SEARCH_ENTRY(search),
                                              "Search files and modules");
        gtk_widget_set_size_request(search, 320, -1);
        gtk_widget_set_hexpand(spacer, TRUE);
        gtk_widget_add_css_class(count, "loot-count-lbl");
        gtk_widget_add_css_class(sort, "loot-sort");
        gtk_widget_set_valign(search, GTK_ALIGN_CENTER);
        gtk_widget_set_valign(sort,   GTK_ALIGN_CENTER);
        gtk_widget_set_valign(count,  GTK_ALIGN_CENTER);

        gtk_box_append(GTK_BOX(bar), search);
        gtk_box_append(GTK_BOX(bar), sort);
        gtk_box_append(GTK_BOX(bar), spacer);
        gtk_box_append(GTK_BOX(bar), count);
        gtk_widget_set_margin_bottom(bar, 8);
        gtk_widget_set_margin_start(bar, 16);
        gtk_widget_set_margin_end(bar, 16);
        gtk_box_append(GTK_BOX(outer), bar);

        state->loot_search = search;
        state->loot_sort = sort;
        state->loot_count_lbl = count;
        g_signal_connect(search, "changed",
                         G_CALLBACK(loot_search_changed), state);
        g_signal_connect(sort, "notify::selected",
                         G_CALLBACK(loot_sort_changed), state);
    }

    gtk_widget_add_css_class(list, "loot-list");
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(list), GTK_SELECTION_SINGLE);
    state->loot_list = list;
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(lscroll), list);

    /* The list owns the tab. It used to share it with a preview pane that held
       a third of the width and was empty until a file was selected, which made
       every row stop short of the right edge with nothing beside it. A file
       opens as its own tab now, so the glance value is covered and the rows
       can run the full width with Open on the right. */
    gtk_widget_set_vexpand(lscroll, TRUE);
    gtk_box_append(GTK_BOX(outer), lscroll);

    g_signal_connect(refresh, "clicked", G_CALLBACK(loot_refresh_clicked), state);
    g_signal_connect(list, "row-activated", G_CALLBACK(loot_row_activated), state);
    loot_refresh(state);
    return outer;
}

/* ==================================================================== */
/*  CASEBOOK — CASES, EVIDENCE, ALERTS AND REPORTS                      */
/* ==================================================================== */

/* Casebook operations are small local state reads/writes. They never need
 * privilege. Capture and module execution remain asynchronous elsewhere. */
static char *
casebook_call(const char *const *args, gboolean *ok_out)
{
    g_autofree char *tool = g_build_filename(IMSISTING_ROOT, "tools",
                                             "casebook.py", NULL);
    GPtrArray *argv = g_ptr_array_new();
    g_autoptr(GError) error = NULL;
    g_autoptr(GSubprocess) proc = NULL;
    g_autofree char *out = NULL;
    g_autofree char *errout = NULL;

    g_ptr_array_add(argv, tool);
    for (guint i = 0; args != NULL && args[i] != NULL; i++)
        g_ptr_array_add(argv, (gpointer) args[i]);
    g_ptr_array_add(argv, NULL);
    proc = g_subprocess_newv((const char *const *) argv->pdata,
        G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_PIPE,
        &error);
    g_ptr_array_unref(argv);
    if (proc == NULL) {
        if (ok_out != NULL) *ok_out = FALSE;
        return g_strdup(error != NULL ? error->message : "could not launch Casebook");
    }

    gboolean sent = g_subprocess_communicate_utf8(proc, NULL, NULL,
                                                   &out, &errout, &error);
    gboolean ok = sent && g_subprocess_get_successful(proc);
    if (ok_out != NULL) *ok_out = ok;
    if (!sent)
        return g_strdup(error != NULL ? error->message : "Casebook command failed");
    if (ok)
        return g_steal_pointer(&out);
    if (errout != NULL && *errout != 0)
        return g_steal_pointer(&errout);
    return g_steal_pointer(&out);
}

static void
casebook_list_clear(GtkWidget *list)
{
    GtkWidget *child = gtk_widget_get_first_child(list);
    while (child != NULL) {
        GtkWidget *next = gtk_widget_get_next_sibling(child);
        gtk_list_box_remove(GTK_LIST_BOX(list), child);
        child = next;
    }
}

/* A note row: used for both "nothing recorded" and "no active case". The
   latter is the common state, not an error, so it reads as information. */
static void
casebook_list_note(GtkWidget *list, const char *title, const char *hint)
{
    GtkWidget *row = gtk_list_box_row_new();
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *t = gtk_label_new(title != NULL ? title : "");
    GtkWidget *h = gtk_label_new(hint != NULL ? hint : "");

    gtk_widget_add_css_class(t, "cell-name");
    gtk_widget_add_css_class(h, "cell-meta");
    gtk_label_set_xalign(GTK_LABEL(t), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(h), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(t), TRUE);
    gtk_label_set_wrap(GTK_LABEL(h), TRUE);
    if (hint == NULL || *hint == '\0') gtk_widget_set_visible(h, FALSE);
    gtk_widget_set_margin_top(box, 12);
    gtk_widget_set_margin_bottom(box, 12);
    gtk_widget_set_margin_start(box, 6);
    gtk_box_append(GTK_BOX(box), t);
    gtk_box_append(GTK_BOX(box), h);
    gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), box);
    gtk_list_box_row_set_activatable(GTK_LIST_BOX_ROW(row), FALSE);
    gtk_list_box_row_set_selectable(GTK_LIST_BOX_ROW(row), FALSE);
    gtk_list_box_append(GTK_LIST_BOX(list), row);
}

/* One record: icon, title with an optional right-hand badge, a monospace
   identifier line, then the facts worth comparing down the list. */
static GtkWidget *
casebook_row_new(const char *icon_name, const char *title, const char *ident,
                 const char *meta, const char *badge, const char *badge_class)
{
    GtkWidget *row = gtk_list_box_row_new();
    GtkWidget *content = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    GtkWidget *text = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *top = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *icon = imsisting_icon_image(icon_name);
    GtkWidget *t = gtk_label_new(title != NULL ? title : "");
    GtkWidget *i = gtk_label_new(ident != NULL ? ident : "");
    GtkWidget *m = gtk_label_new(meta != NULL ? meta : "");

    gtk_image_set_pixel_size(GTK_IMAGE(icon), 26);
    gtk_widget_add_css_class(row, "cell-row");
    gtk_widget_add_css_class(icon, "cell-icon");
    gtk_widget_add_css_class(t, "cell-name");
    gtk_widget_add_css_class(i, "cell-ident");
    gtk_widget_add_css_class(m, "cell-meta");

    gtk_label_set_xalign(GTK_LABEL(t), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(i), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(m), 0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(t), PANGO_ELLIPSIZE_END);
    gtk_label_set_ellipsize(GTK_LABEL(i), PANGO_ELLIPSIZE_END);
    gtk_label_set_ellipsize(GTK_LABEL(m), PANGO_ELLIPSIZE_END);
    /* Without a bound a long sha256 or ssh detail forces the whole list to
       scroll sideways, which is most of what looked wrong before. */
    gtk_label_set_max_width_chars(GTK_LABEL(t), 40);
    gtk_label_set_max_width_chars(GTK_LABEL(i), 40);
    gtk_label_set_max_width_chars(GTK_LABEL(m), 48);

    gtk_widget_set_hexpand(text, TRUE);
    gtk_box_append(GTK_BOX(top), t);
    if (badge != NULL && *badge != '\0') {
        GtkWidget *b = gtk_label_new(badge);
        gtk_widget_add_css_class(b, "status-pill");
        gtk_widget_add_css_class(b, badge_class != NULL ? badge_class : "status-dim");
        gtk_widget_set_halign(b, GTK_ALIGN_END);
        gtk_widget_set_valign(b, GTK_ALIGN_CENTER);
        gtk_box_append(GTK_BOX(top), b);
    }
    gtk_box_append(GTK_BOX(text), top);
    gtk_box_append(GTK_BOX(text), i);
    gtk_box_append(GTK_BOX(text), m);
    gtk_box_append(GTK_BOX(content), icon);
    gtk_box_append(GTK_BOX(content), text);
    gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), content);
    return row;
}

/* Column lookup by name rather than by position: the table's fields are
   declared in the tool, and a positional parser silently shifts the day one
   is inserted. */
static int
casebook_col(gchar **header, const char *name)
{
    for (int i = 0; header != NULL && header[i] != NULL; i++)
        if (g_strcmp0(header[i], name) == 0) return i;
    return -1;
}

static const char *
casebook_f(gchar **f, int idx)
{
    if (idx < 0 || f == NULL || f[idx] == NULL) return "";
    return f[idx];
}

static const char *
casebook_size(const char *bytes)
{
    static char buf[32];
    guint64 n = (bytes != NULL && *bytes != '\0')
        ? g_ascii_strtoull(bytes, NULL, 10) : 0;
    g_autofree char *s = loot_fmt_size(n);
    g_strlcpy(buf, s, sizeof buf);
    return buf;
}

static const char *
casebook_base(const char *path)
{
    const char *slash;
    if (path == NULL || *path == '\0') return "";
    slash = strrchr(path, '/');
    return (slash != NULL) ? slash + 1 : path;
}

static const char *
casebook_sev_class(const char *sev)
{
    if (sev == NULL) return "status-dim";
    if (g_ascii_strcasecmp(sev, "CRITICAL") == 0 ||
        g_ascii_strcasecmp(sev, "HIGH") == 0)   return "status-error";
    if (g_ascii_strcasecmp(sev, "MEDIUM") == 0 ||
        g_ascii_strcasecmp(sev, "WARN") == 0)   return "status-warn";
    if (g_ascii_strcasecmp(sev, "LOW") == 0 ||
        g_ascii_strcasecmp(sev, "INFO") == 0)   return "status-ok";
    return "status-dim";
}

typedef void (*CasebookRowFn)(GtkWidget *list, gchar **header, gchar **f);

static void
cb_row_capture(GtkWidget *list, gchar **h, gchar **f)
{
    const char *kind = casebook_f(f, casebook_col(h, "kind"));
    g_autofree char *ident = g_strdup_printf("%s  ·  %s",
        casebook_f(f, casebook_col(h, "module")), kind);
    g_autofree char *sha = g_strndup(casebook_f(f, casebook_col(h, "sha256")), 12);
    g_autofree char *meta = g_strdup_printf("%s  ·  %s  ·  %s  ·  %s",
        casebook_size(casebook_f(f, casebook_col(h, "bytes"))),
        casebook_f(f, casebook_col(h, "added")),
        sha, casebook_f(f, casebook_col(h, "tags")));
    const char *icon = (g_strcmp0(kind, "pcap") == 0)
        ? "network-wireless-symbolic"
        : (g_strcmp0(kind, "iq") == 0) ? "audio-input-microphone-symbolic"
                                       : "text-x-generic-symbolic";

    gtk_list_box_append(GTK_LIST_BOX(list), casebook_row_new(icon,
        casebook_base(casebook_f(f, casebook_col(h, "path"))),
        ident, meta, kind, "status-dim"));
}

static void
cb_row_timeline(GtkWidget *list, gchar **h, gchar **f)
{
    const char *sev = casebook_f(f, casebook_col(h, "severity"));
    g_autofree char *ident = g_strdup_printf("%s  ·  %s",
        casebook_f(f, casebook_col(h, "type")),
        casebook_f(f, casebook_col(h, "source")));
    g_autofree char *meta = g_strdup_printf("%s  ·  %s",
        casebook_f(f, casebook_col(h, "time")),
        casebook_base(casebook_f(f, casebook_col(h, "reference"))));

    gtk_list_box_append(GTK_LIST_BOX(list), casebook_row_new(
        "document-open-recent-symbolic",
        casebook_f(f, casebook_col(h, "message")), ident, meta,
        sev, casebook_sev_class(sev)));
}

static void
cb_row_alert(GtkWidget *list, gchar **h, gchar **f)
{
    const char *sev = casebook_f(f, casebook_col(h, "severity"));
    g_autofree char *ident = g_strdup_printf("%s  ·  %s",
        casebook_f(f, casebook_col(h, "kind")),
        casebook_f(f, casebook_col(h, "source")));
    g_autofree char *meta = g_strdup_printf("%s  ·  %s  ·  %s",
        casebook_f(f, casebook_col(h, "time")),
        casebook_base(casebook_f(f, casebook_col(h, "evidence"))),
        casebook_f(f, casebook_col(h, "status")));

    gtk_list_box_append(GTK_LIST_BOX(list), casebook_row_new(
        "dialog-warning-symbolic",
        casebook_f(f, casebook_col(h, "message")), ident, meta,
        sev, casebook_sev_class(sev)));
}

static void
cb_row_node(GtkWidget *list, gchar **h, gchar **f)
{
    const char *st = casebook_f(f, casebook_col(h, "status"));
    g_autofree char *ident = g_strdup_printf("%s  ·  %s  ·  %s",
        casebook_f(f, casebook_col(h, "host")),
        casebook_f(f, casebook_col(h, "transport")),
        casebook_f(f, casebook_col(h, "role")));
    g_autofree char *meta = g_strdup_printf("%s  ·  %s",
        casebook_f(f, casebook_col(h, "last_seen")),
        casebook_f(f, casebook_col(h, "detail")));
    const char *cls = (g_ascii_strcasecmp(st, "ONLINE") == 0)  ? "status-ok"
                    : (g_ascii_strcasecmp(st, "OFFLINE") == 0) ? "status-error"
                                                              : "status-dim";

    gtk_list_box_append(GTK_LIST_BOX(list), casebook_row_new(
        "network-server-symbolic",
        casebook_f(f, casebook_col(h, "name")), ident, meta, st, cls));
}

static void
cb_row_report(GtkWidget *list, gchar **h, gchar **f)
{
    const char *path = casebook_f(f, casebook_col(h, "path"));
    const char *base = casebook_base(path);
    const char *dot = strrchr(base, '.');
    g_autofree char *fmt = g_strdup(dot != NULL ? dot + 1 : "");
    g_autofree char *fmt_up = g_ascii_strup(fmt, -1);
    g_autofree char *when = NULL;
    const char *mt = casebook_f(f, casebook_col(h, "mtime"));
    g_autofree char *ident = NULL;

    if (mt != NULL && *mt != '\0') {
        GDateTime *dt = g_date_time_new_from_unix_local(
            (gint64) g_ascii_strtoll(mt, NULL, 10));
        if (dt != NULL) {
            when = g_date_time_format(dt, "%m-%d %H:%M");
            g_date_time_unref(dt);
        }
    }
    ident = g_strdup_printf("%s  ·  %s", fmt_up,
                            when != NULL ? when : "");

    gtk_list_box_append(GTK_LIST_BOX(list), casebook_row_new(
        "x-office-document-symbolic", base, ident,
        casebook_size(casebook_f(f, casebook_col(h, "bytes"))),
        fmt_up, "status-dim"));
}

/* Run a TSV verb and render one row per record. An empty table arrives as a
   header line with nothing under it, so "one line" means empty. */
/* The fetched text, the row builder and the empty-state copy are kept on the
   list itself, so the search field can re-render without asking the CLI
   again - and so a filter never turns into a second source of truth. */
static void
casebook_list_render(GtkWidget *list, const char *text, CasebookRowFn row_fn,
                     const char *empty_title, const char *empty_hint,
                     const char *needle)
{
    g_auto(GStrv) lines = NULL;
    g_auto(GStrv) header = NULL;
    g_autoptr(GPtrArray) rows = g_ptr_array_new_with_free_func(g_free);
    g_autofree char *low = NULL;
    guint matched = 0;

    casebook_list_clear(list);

    if (text == NULL || *text == '\0') {
        casebook_list_note(list, empty_title, empty_hint);
        return;
    }

    lines  = g_strsplit(text, "\n", -1);
    header = g_strsplit(lines[0], "\t", -1);

    if (needle != NULL && *needle != '\0')
        low = g_ascii_strdown(needle, -1);

    for (guint i = 1; lines[i] != NULL; i++) {
        if (*lines[i] == '\0') continue;
        if (low != NULL) {
            g_autofree char *hay = g_ascii_strdown(lines[i], -1);
            if (strstr(hay, low) == NULL) continue;
        }
        g_ptr_array_add(rows, g_strdup(lines[i]));
    }

    for (guint i = 0; i < rows->len; i++) {
        g_auto(GStrv) f = g_strsplit(g_ptr_array_index(rows, i), "\t", -1);
        row_fn(list, header, f);
        matched++;
    }

    /* Distinguish "this case has no captures" from "your search matched
       nothing" - they call for different next actions. */
    if (matched == 0)
        casebook_list_note(list,
            (needle != NULL && *needle != '\0') ? "Nothing matches" : empty_title,
            (needle != NULL && *needle != '\0') ? "clear the search to see everything again"
                                                : empty_hint);
}

static void
casebook_list_fill(GtkWidget *list, const char *command, CasebookRowFn row_fn,
                   const char *empty_title, const char *empty_hint)
{
    const char *args[] = { command, NULL };
    gboolean ok = FALSE;
    g_autofree char *text = NULL;

    if (list == NULL) return;

    text = casebook_call(args, &ok);
    if (!ok) {
        /* No active case is the common state, not a record to render: the
           tool's stderr line is context, not data. */
        g_autofree char *first = NULL;
        if (text != NULL) {
            g_auto(GStrv) l = g_strsplit(text, "\n", 2);
            g_autofree char *raw = g_strdup(l[0] != NULL ? l[0] : "");
            g_strstrip(raw);
            /* The tool prefixes its refusal with "ERROR\t", which under a
               heading that already says "No active case" is just noise. */
            first = g_str_has_prefix(raw, "ERROR")
                ? g_strdup(g_strstrip(raw + 5))
                : g_strdup(raw);
            /* The tool's refusal names its own flags. Under a heading that
               already says "No active case", "--case-create or --case-select"
               is a man page, not a next step. */
            if (first != NULL && g_ascii_strncasecmp(first, "no active case", 14) == 0) {
                g_free(first);
                first = g_strdup("Create or select a case in Overview.");
            }
        }
        g_object_set_data_full(G_OBJECT(list), "cb-text", g_strdup(""), g_free);
        casebook_list_note(list, "No active case",
            (first != NULL && *first != '\0')
                ? first : "Create or select a case in Overview.");
        return;
    }

    g_object_set_data_full(G_OBJECT(list), "cb-text", g_strdup(text), g_free);
    g_object_set_data(G_OBJECT(list), "cb-rowfn", (gpointer) row_fn);
    g_object_set_data_full(G_OBJECT(list), "cb-empty", g_strdup(empty_title), g_free);
    g_object_set_data_full(G_OBJECT(list), "cb-hint", g_strdup(empty_hint), g_free);

    casebook_list_render(list, text, row_fn, empty_title, empty_hint,
                         g_object_get_data(G_OBJECT(list), "cb-needle"));
}

static void
casebook_list_filter_changed(GtkEditable *editable, gpointer user_data)
{
    GtkWidget *list = user_data;
    const char *text = g_object_get_data(G_OBJECT(list), "cb-text");

    g_object_set_data_full(G_OBJECT(list), "cb-needle",
                           g_strdup(gtk_editable_get_text(editable)), g_free);
    if (text == NULL) return;
    casebook_list_render(list, text,
                         (CasebookRowFn) g_object_get_data(G_OBJECT(list), "cb-rowfn"),
                         g_object_get_data(G_OBJECT(list), "cb-empty"),
                         g_object_get_data(G_OBJECT(list), "cb-hint"),
                         gtk_editable_get_text(editable));
}

/* The Casebook home: the facts an investigator wants before touching a tab —
   the case, its scope and authorization, the current target, how much evidence
   and how many alerts it holds, and the latest alert line. Refreshed by
   casebook_home_refresh(), which runs with Refresh All. */
static GtkWidget *
build_casebook_home(AppState *state)
{
    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *row  = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 26);
    GtkWidget *alert = gtk_label_new(
        "No active case. Create or select one to begin.");

    gtk_widget_add_css_class(card, "case-home");
    gtk_widget_add_css_class(row, "station-band");
    gtk_widget_add_css_class(alert, "case-home-alert");
    gtk_label_set_xalign(GTK_LABEL(alert), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(alert), TRUE);

    gtk_box_append(GTK_BOX(row), status_cell("CASE", &state->casebook_brief_case));
    gtk_box_append(GTK_BOX(row), status_cell("SCOPE", &state->casebook_brief_scope));
    gtk_box_append(GTK_BOX(row), status_cell("AUTHORIZATION", &state->casebook_brief_auth));
    gtk_box_append(GTK_BOX(row), status_cell("TARGET", &state->casebook_brief_target));
    gtk_box_append(GTK_BOX(row), status_cell("EVIDENCE", &state->casebook_brief_evidence));
    gtk_box_append(GTK_BOX(row), status_cell("ALERTS", &state->casebook_brief_alerts));
    state->casebook_brief_alert = alert;
    gtk_box_append(GTK_BOX(card), row);
    gtk_box_append(GTK_BOX(card), alert);
    return card;
}

/* The page-head band. Pure rendering: the four TSVs it describes are
   fetched once by the Overview and handed in. They used to be fetched twice -
   once for the band and once for the cards - and every fetch is a process. */
static void
casebook_fill_head(AppState *state, const char *show, const char *tgt,
                   const char *status, const char *al)
{
    g_autofree char *name = NULL, *cstat = NULL, *scope = NULL, *auth = NULL;
    g_autofree char *evc = NULL, *alc = NULL, *rat = NULL, *plmn = NULL;
    g_autofree char *cell = NULL, *asev = NULL, *amsg = NULL, *tstr = NULL;
    gboolean none;

    if (state->casebook_brief_case == NULL) return;

    name  = show ? tsv_field(show, "name") : NULL;
    cstat = show ? tsv_field(show, "status") : NULL;
    scope = show ? tsv_field(show, "scope") : NULL;
    auth  = show ? tsv_field(show, "authorization") : NULL;
    evc   = status ? tsv_field(status, "evidence") : NULL;
    alc   = status ? tsv_field(status, "alerts") : NULL;
    rat   = tgt ? tsv_row_field(tgt, "rat") : NULL;
    plmn  = tgt ? tsv_row_field(tgt, "plmn") : NULL;
    cell  = tgt ? tsv_row_field(tgt, "cell_id") : NULL;
    asev  = al ? tsv_last_field(al, "severity") : NULL;
    amsg  = al ? tsv_last_field(al, "message") : NULL;

    none = (name == NULL || *name == '\0');

    if (none)
        status_set(state->casebook_brief_case, "not set", "status-warn");
    else {
        g_autofree char *cs = g_strdup_printf("%s \u00b7 %s", name,
            (cstat && *cstat) ? cstat : "OPEN");
        status_set(state->casebook_brief_case, cs, "status-ok");
    }
    status_set(state->casebook_brief_scope,
        (scope && *scope) ? scope : "\u2014",
        (scope && *scope) ? NULL : "status-dim");
    status_set(state->casebook_brief_auth,
        (auth && *auth) ? auth : "\u2014",
        (auth && *auth) ? NULL : "status-dim");

    tstr = (rat || plmn || cell)
        ? g_strdup_printf("%s%s%s%s%s",
            (rat && *rat) ? rat : "", (rat && *rat) ? " " : "",
            (plmn && *plmn) ? plmn : "", (plmn && *plmn) ? " " : "",
            (cell && *cell) ? cell : "")
        : NULL;
    status_set(state->casebook_brief_target,
        (tstr && *tstr) ? tstr : "none",
        (tstr && *tstr) ? "status-ok" : "status-dim");

    {
        int ne = (evc && *evc) ? atoi(evc) : 0;
        int na = (alc && *alc) ? atoi(alc) : 0;
        g_autofree char *se = g_strdup_printf("%d", ne);
        g_autofree char *sa = g_strdup_printf("%d", na);
        status_set(state->casebook_brief_evidence, se,
                   ne > 0 ? "status-ok" : "status-dim");
        status_set(state->casebook_brief_alerts, sa,
                   na > 0 ? "status-warn" : "status-dim");
    }

    if (asev && amsg && *amsg)
        gtk_label_set_text(GTK_LABEL(state->casebook_brief_alert),
                           g_strdup_printf("Latest alert \u00b7 %s \u2014 %s", asev, amsg));
    else
        gtk_label_set_text(GTK_LABEL(state->casebook_brief_alert),
            none ? "No active case. Create or select one to begin."
                 : "No alerts recorded for this case.");
}

/* Overview: three cards - the case, the target, the counts - and the band
   above them, all from four TSVs fetched once. The monospace dump that used
   to live here mixed all three together and gave a missing value nowhere to
   be seen. */
static void
casebook_fill_overview(AppState *state)
{
    gboolean ok = FALSE;
    const char *status_args[] = { "--status-tsv", NULL };
    const char *case_args[] = { "--case-show-tsv", NULL };
    const char *target_args[] = { "--target-current-tsv", NULL };
    const char *alert_args[] = { "--alerts-tsv", NULL };
    g_autofree char *status = casebook_call(status_args, &ok);
    g_autofree char *details = ok ? casebook_call(case_args, NULL) : NULL;
    g_autofree char *target = ok ? casebook_call(target_args, NULL) : NULL;
    g_autofree char *alerts = ok ? casebook_call(alert_args, NULL) : NULL;

    if (state->casebook_case_body != NULL) {
        casebook_kv_fill(state->casebook_case_body,
            (details != NULL && !g_str_has_prefix(details, "ERROR")) ? details : NULL,
            "No active case. Create one above, or select an existing case.");
        casebook_kv_fill(state->casebook_target_body,
            (target != NULL && !g_str_has_prefix(target, "ERROR")) ? target : NULL,
            "No target selected for this case.");
        casebook_counts_fill(state->casebook_counts_body, status);
    }
    casebook_fill_head(state, details, target, status, alerts);
}

/* One fill per tab. Each forks two to four processes, and building the page
   used to pay for all seven at once - 3.2 s of the window's startup, spent
   before the window had ever been drawn, for data the user might not look
   at. A tab now loads the first time it is opened, and remembers that it
   did. */
static void
casebook_refresh_tab(AppState *state, guint tab)
{
    switch (tab) {
    case CASEBOOK_TAB_OVERVIEW:
        casebook_fill_overview(state);
        break;
    case CASEBOOK_TAB_EVIDENCE:
        loot_refresh(state);
        break;
    case CASEBOOK_TAB_CAPTURES:
        casebook_list_fill(state->casebook_captures_list, "--captures-tsv",
            cb_row_capture, "No captures indexed.",
            "Index Files, then Refresh.");
        break;
    case CASEBOOK_TAB_TIMELINE:
        casebook_list_fill(state->casebook_timeline_list, "--timeline-tsv",
            cb_row_timeline, "No timeline events.",
            "Index captures, then Correlate Evidence.");
        break;
    case CASEBOOK_TAB_ALERTS:
        casebook_list_fill(state->casebook_alerts_list, "--alerts-tsv",
            cb_row_alert, "No alerts recorded.",
            "Build Baseline writes the reference snapshot to compare against.");
        break;
    case CASEBOOK_TAB_NODES:
        casebook_list_fill(state->casebook_nodes_list, "--node-list-tsv",
            cb_row_node, "No remote sensor nodes configured.",
            "Add a sensor above.");
        break;
    case CASEBOOK_TAB_REPORTS:
        casebook_list_fill(state->casebook_reports_list, "--reports-tsv",
            cb_row_report, "No reports exported.",
            "Export HTML or JSON from the toolbar.");
        break;
    default:
        return;
    }
    state->casebook_filled |= (1u << tab);
}

/* Refresh All, and the Refresh button on any tab, still mean every tab. */
static void
casebook_refresh(AppState *state)
{
    for (guint i = 0; i < CASEBOOK_TAB_COUNT; i++)
        casebook_refresh_tab(state, i);
}

/* A tab loads the first time it is shown. switch-page is emitted while the
   switch is still in progress, so the fill lands before the page is drawn
   and the unfilled state is never on screen. */
static void
casebook_tab_switched(GtkNotebook *notebook, GtkWidget *page, guint tab,
                      gpointer user_data)
{
    AppState *state = user_data;
    (void) notebook;
    (void) page;

    /* Evidence files are appended past the seven fixed tabs. */
    if (tab >= CASEBOOK_TAB_COUNT) return;
    if (state->casebook_filled & (1u << tab)) return;
    casebook_refresh_tab(state, tab);
}

static gboolean
casebook_run(AppState *state, const char *title, const char *const *args)
{
    gboolean ok = FALSE;
    g_autofree char *text = casebook_call(args, &ok);
    if (text != NULL && *text != 0) append_event(state, text);
    show_toast_full(state, title,
        ok ? "Done" : (text != NULL ? text : "Failed"), ok ? "ok" : "error");
    casebook_refresh(state);
    return ok;
}

static const char *
casebook_entry(GtkWidget *entry)
{
    return entry != NULL ? gtk_editable_get_text(GTK_EDITABLE(entry)) : "";
}

static void
casebook_refresh_clicked(GtkButton *button, gpointer user_data)
{
    (void) button;
    casebook_refresh(user_data);
}

static void
casebook_simple_clicked(GtkButton *button, gpointer user_data)
{
    AppState *state = user_data;
    const char *command = g_object_get_data(G_OBJECT(button), "casebook-command");
    const char *args[] = { command, NULL };
    if (command != NULL && casebook_run(state, gtk_button_get_label(button), args) &&
        g_strcmp0(command, "--index") == 0)
        loot_refresh(state);
}

static GtkWidget *
casebook_action(AppState *state, const char *label, const char *command)
{
    GtkWidget *button = gtk_button_new_with_label(label);
    g_object_set_data(G_OBJECT(button), "casebook-command", (gpointer) command);
    g_signal_connect(button, "clicked", G_CALLBACK(casebook_simple_clicked), state);
    return button;
}

static void
casebook_create_clicked(GtkButton *button, gpointer user_data)
{
    AppState *state = user_data;
    const char *name = casebook_entry(state->case_name_entry);
    if (*name == 0) {
        show_toast_full(state, "Create Case", "A case name is required", "error");
        return;
    }
    const char *args[] = { "--case-create", name,
        casebook_entry(state->case_scope_entry),
        casebook_entry(state->case_auth_entry), NULL };
    if (casebook_run(state, "Create Case", args))
        gtk_editable_set_text(GTK_EDITABLE(state->case_name_entry), "");
    (void) button;
}

static void
casebook_select_clicked(GtkButton *button, gpointer user_data)
{
    AppState *state = user_data;
    const char *id = casebook_entry(state->case_select_entry);
    if (*id == 0) {
        show_toast_full(state, "Select Case", "Enter an existing case ID", "error");
        return;
    }
    const char *args[] = { "--case-select", id, NULL };
    casebook_run(state, "Select Case", args);
    (void) button;
}

static void
casebook_node_add_clicked(GtkButton *button, gpointer user_data)
{
    AppState *state = user_data;
    const char *name = casebook_entry(state->node_name_entry);
    const char *host = casebook_entry(state->node_host_entry);
    const char *transport = casebook_entry(state->node_transport_entry);
    if (*name == 0 || *host == 0) {
        show_toast_full(state, "Add Sensor", "Name and host are required", "error");
        return;
    }
    if (*transport == 0) transport = "ssh";
    const char *args[] = { "--node-add", name, host, transport, "sensor", NULL };
    casebook_run(state, "Add Sensor", args);
    (void) button;
}

static void
casebook_node_probe_clicked(GtkButton *button, gpointer user_data)
{
    AppState *state = user_data;
    const char *name = casebook_entry(state->node_name_entry);
    if (*name == 0) {
        show_toast_full(state, "Probe Sensor", "Enter the sensor name", "error");
        return;
    }
    const char *args[] = { "--node-probe", name, NULL };
    casebook_run(state, "Probe Sensor", args);
    (void) button;
}

static GtkWidget *
casebook_text_view(GtkTextBuffer **buffer_out, const char *placeholder)
{
    GtkWidget *scroll = gtk_scrolled_window_new();
    GtkWidget *view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(view), TRUE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(view), GTK_WRAP_NONE);
    gtk_widget_add_css_class(view, "casebook-text");
    *buffer_out = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));
    gtk_text_buffer_set_text(*buffer_out, placeholder, -1);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), view);
    gtk_widget_set_vexpand(scroll, TRUE);
    return scroll;
}

static GtkWidget *
casebook_shell(GtkWidget *toolbar, GtkWidget *content)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_margin_top(box, 12);
    gtk_widget_set_margin_bottom(box, 12);
    gtk_widget_set_margin_start(box, 14);
    gtk_widget_set_margin_end(box, 14);
    if (toolbar != NULL) {
        gtk_widget_add_css_class(toolbar, "casebook-toolbar");
        gtk_box_append(GTK_BOX(box), toolbar);
    }
    gtk_widget_set_vexpand(content, TRUE);
    gtk_box_append(GTK_BOX(box), content);
    return box;
}

/* The Overview used to be a monospace dump of whatever the Casebook CLI
   printed. It was legible to whoever wrote the CLI and to nobody else: no
   hierarchy, no empty state, and a wall of text where three facts mattered.
   These three cards replace it - and a field that has no value says "not set"
   rather than going blank, because a blank is indistinguishable from a bug. */
static GtkWidget *
casebook_card(const char *title, GtkWidget **body_out)
{
    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *head = gtk_label_new(title);
    GtkWidget *body = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);

    gtk_widget_add_css_class(card, "cb-card");
    gtk_widget_add_css_class(head, "cb-card-title");
    gtk_label_set_xalign(GTK_LABEL(head), 0.0f);
    gtk_box_append(GTK_BOX(card), head);
    gtk_box_append(GTK_BOX(card), body);
    if (body_out != NULL) *body_out = body;
    return card;
}

static void
casebook_card_empty(GtkWidget *body, const char *msg)
{
    GtkWidget *lbl = gtk_label_new(msg);
    gtk_widget_add_css_class(lbl, "cb-empty");
    gtk_label_set_xalign(GTK_LABEL(lbl), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(lbl), TRUE);
    gtk_box_append(GTK_BOX(body), lbl);
}

/* Renders a key<TAB>value block. Anything the CLI could not answer arrives as
   an ERROR row, which is shown as the card's own empty state instead of as a
   field called ERROR. */
static void
casebook_kv_fill(GtkWidget *body, const char *tsv, const char *empty_msg)
{
    GtkWidget *child;
    gboolean errored = tsv != NULL && g_str_has_prefix(tsv, "ERROR");

    if (body == NULL) return;
    while ((child = gtk_widget_get_first_child(body)) != NULL)
        gtk_box_remove(GTK_BOX(body), child);

    if (tsv == NULL || *tsv == '\0' || errored) {
        casebook_card_empty(body, (errored && tsv != NULL)
            ? g_strstrip((char *) tsv + 6) : empty_msg);
        return;
    }

    g_auto(GStrv) lines = g_strsplit(tsv, "\n", -1);
    for (guint i = 0; lines[i] != NULL; i++) {
        g_auto(GStrv) f = NULL;
        const char *key, *val;
        GtkWidget *row, *k, *v;

        if (*lines[i] == '\0') continue;
        f = g_strsplit(lines[i], "\t", 2);
        key = f[0] != NULL ? f[0] : "";
        val = (f[1] != NULL && *f[1] != '\0') ? f[1] : NULL;

        row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
        k = gtk_label_new(key);
        v = gtk_label_new(val != NULL ? val : "not set");
        gtk_widget_add_css_class(k, "cb-k");
        gtk_widget_add_css_class(v, val != NULL ? "cb-v" : "cb-v-none");
        gtk_label_set_xalign(GTK_LABEL(k), 0.0f);
        gtk_label_set_xalign(GTK_LABEL(v), 0.0f);
        gtk_widget_set_size_request(k, 168, -1);
        gtk_label_set_selectable(GTK_LABEL(v), TRUE);
        gtk_label_set_wrap(GTK_LABEL(v), TRUE);
        gtk_widget_set_hexpand(v, TRUE);
        gtk_box_append(GTK_BOX(row), k);
        gtk_box_append(GTK_BOX(row), v);
        gtk_box_append(GTK_BOX(body), row);
    }
}

/* Counts read as a row of tiles: a number is scanned, a sentence is read. */
static void
casebook_counts_fill(GtkWidget *body, const char *tsv)
{
    GtkWidget *child;
    GtkWidget *row = NULL;

    if (body == NULL) return;
    while ((child = gtk_widget_get_first_child(body)) != NULL)
        gtk_box_remove(GTK_BOX(body), child);

    if (tsv == NULL || *tsv == '\0' || g_str_has_prefix(tsv, "ERROR")) {
        casebook_card_empty(body, "No case is open, so there is nothing to count.");
        return;
    }

    row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    g_auto(GStrv) lines = g_strsplit(tsv, "\n", -1);
    for (guint i = 0; lines[i] != NULL; i++) {
        g_auto(GStrv) f = NULL;
        const char *key, *val;
        GtkWidget *tile, *num, *lbl;
        g_autofree char *up = NULL;

        if (*lines[i] == '\0') continue;
        f = g_strsplit(lines[i], "\t", 2);
        key = f[0] != NULL ? f[0] : "";
        val = (f[1] != NULL && *f[1] != '\0') ? f[1] : "0";
        up = g_ascii_strup(key, -1);
        g_strdelimit(up, "_", ' ');

        tile = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
        num  = gtk_label_new(val);
        lbl  = gtk_label_new(up);
        gtk_widget_add_css_class(tile, "cb-count");
        gtk_widget_add_css_class(num, "cb-count-num");
        gtk_widget_add_css_class(lbl, "cb-count-key");
        gtk_label_set_xalign(GTK_LABEL(num), 0.0f);
        gtk_label_set_xalign(GTK_LABEL(lbl), 0.0f);
        gtk_label_set_ellipsize(GTK_LABEL(lbl), PANGO_ELLIPSIZE_END);
        gtk_widget_set_hexpand(tile, TRUE);
        gtk_box_append(GTK_BOX(tile), num);
        gtk_box_append(GTK_BOX(tile), lbl);
        gtk_box_append(GTK_BOX(row), tile);
    }
    gtk_box_append(GTK_BOX(body), row);
}

static GtkWidget *
create_casebook_overview(AppState *state)
{
    GtkWidget *body = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *create_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *select_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *create = gtk_button_new_with_label("Create Case");
    GtkWidget *select = gtk_button_new_with_label("Select Case");
    GtkWidget *hint = gtk_label_new(
        "Targets are set from the Target panel in the header, so the target "
        "stays reachable from every page - and is recorded into the case.");

    state->case_name_entry = gtk_entry_new();
    state->case_scope_entry = gtk_entry_new();
    state->case_auth_entry = gtk_entry_new();
    state->case_select_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(state->case_name_entry), "Case name");
    gtk_entry_set_placeholder_text(GTK_ENTRY(state->case_scope_entry), "Scope / owned lab");
    gtk_entry_set_placeholder_text(GTK_ENTRY(state->case_auth_entry), "Authorization reference");
    gtk_entry_set_placeholder_text(GTK_ENTRY(state->case_select_entry), "Existing case ID");
    gtk_widget_add_css_class(create, "primary");
    gtk_widget_add_css_class(hint, "casebook-hint");
    gtk_label_set_xalign(GTK_LABEL(hint), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(hint), TRUE);
    g_signal_connect(create, "clicked", G_CALLBACK(casebook_create_clicked), state);
    g_signal_connect(select, "clicked", G_CALLBACK(casebook_select_clicked), state);

    gtk_box_append(GTK_BOX(create_row), state->case_name_entry);
    gtk_box_append(GTK_BOX(create_row), state->case_scope_entry);
    gtk_box_append(GTK_BOX(create_row), state->case_auth_entry);
    gtk_box_append(GTK_BOX(create_row), create);
    gtk_box_append(GTK_BOX(select_row), state->case_select_entry);
    gtk_box_append(GTK_BOX(select_row), select);
    gtk_box_append(GTK_BOX(select_row), casebook_action(state, "Close Active", "--case-close"));
    gtk_box_append(GTK_BOX(body), create_row);
    gtk_box_append(GTK_BOX(body), select_row);
    gtk_box_append(GTK_BOX(body), hint);
    {
        GtkWidget *cards = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
        gtk_widget_set_margin_top(cards, 12);
        gtk_box_append(GTK_BOX(cards),
            casebook_card("ACTIVE CASE", &state->casebook_case_body));
        gtk_box_append(GTK_BOX(cards),
            casebook_card("CURRENT TARGET", &state->casebook_target_body));
        gtk_box_append(GTK_BOX(cards),
            casebook_card("CASEBOOK AT A GLANCE", &state->casebook_counts_body));
        gtk_box_append(GTK_BOX(body), cards);
    }
    /* Every other tab puts its content in a scroller, and this one did not -
       which made the cards set the notebook's minimum height. A notebook
       cannot shrink below that minimum, so the whole Casebook page grew past
       the window and the bottom of every tab was off-screen and unreachable:
       the counts card here, the last files in Evidence. A scroller gives the
       page a minimum it can shrink to. */
    {
        GtkWidget *scroll = gtk_scrolled_window_new();
        gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                       GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
        gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), body);
        gtk_widget_set_vexpand(scroll, TRUE);
        return casebook_shell(NULL, scroll);
    }
}

static GtkWidget *
create_casebook_listing(AppState *state, GtkWidget **list_out,
                        const char *placeholder, const char *search_hint,
                        const char *label1,
                        const char *command1, const char *label2,
                        const char *command2, const char *label3,
                        const char *command3)
{
    GtkWidget *toolbar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *refresh = gtk_button_new_with_label("Refresh");
    GtkWidget *scroll = gtk_scrolled_window_new();
    GtkWidget *list = gtk_list_box_new();
    GtkWidget *search = gtk_search_entry_new();

    gtk_search_entry_set_placeholder_text(GTK_SEARCH_ENTRY(search),
        search_hint != NULL ? search_hint : "Search this list");
    gtk_widget_set_hexpand(search, TRUE);
    gtk_widget_set_valign(search, GTK_ALIGN_CENTER);
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(list), GTK_SELECTION_NONE);
    gtk_widget_add_css_class(list, "cell-list");
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), list);
    gtk_widget_set_vexpand(scroll, TRUE);
    *list_out = list;

    g_signal_connect(refresh, "clicked", G_CALLBACK(casebook_refresh_clicked), state);
    g_signal_connect(search, "changed",
                     G_CALLBACK(casebook_list_filter_changed), list);
    gtk_box_append(GTK_BOX(toolbar), search);
    gtk_box_append(GTK_BOX(toolbar), refresh);
    if (label1 != NULL) gtk_box_append(GTK_BOX(toolbar), casebook_action(state, label1, command1));
    if (label2 != NULL) gtk_box_append(GTK_BOX(toolbar), casebook_action(state, label2, command2));
    if (label3 != NULL) gtk_box_append(GTK_BOX(toolbar), casebook_action(state, label3, command3));
    return casebook_shell(toolbar, scroll);
}

static GtkWidget *
create_casebook_nodes(AppState *state)
{
    GtkWidget *body = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *toolbar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *add = gtk_button_new_with_label("Add Sensor");
    GtkWidget *probe = gtk_button_new_with_label("Probe");
    GtkWidget *refresh = gtk_button_new_with_label("Refresh");
    state->node_name_entry = gtk_entry_new();
    state->node_host_entry = gtk_entry_new();
    state->node_transport_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(state->node_name_entry), "Node name");
    gtk_entry_set_placeholder_text(GTK_ENTRY(state->node_host_entry), "user@host or localhost");
    gtk_entry_set_placeholder_text(GTK_ENTRY(state->node_transport_entry), "ssh or local");
    gtk_widget_add_css_class(add, "primary");
    g_signal_connect(add, "clicked", G_CALLBACK(casebook_node_add_clicked), state);
    g_signal_connect(probe, "clicked", G_CALLBACK(casebook_node_probe_clicked), state);
    g_signal_connect(refresh, "clicked", G_CALLBACK(casebook_refresh_clicked), state);
    gtk_box_append(GTK_BOX(toolbar), state->node_name_entry);
    gtk_box_append(GTK_BOX(toolbar), state->node_host_entry);
    gtk_box_append(GTK_BOX(toolbar), state->node_transport_entry);
    gtk_box_append(GTK_BOX(toolbar), add);
    gtk_box_append(GTK_BOX(toolbar), probe);
    gtk_box_append(GTK_BOX(toolbar), refresh);
    gtk_box_append(GTK_BOX(body), toolbar);
    {
        GtkWidget *scroll = gtk_scrolled_window_new();
        GtkWidget *list = gtk_list_box_new();
        GtkWidget *nodesearch = gtk_search_entry_new();
        gtk_search_entry_set_placeholder_text(GTK_SEARCH_ENTRY(nodesearch),
                                              "Search sensors");
        gtk_widget_set_margin_bottom(nodesearch, 6);
        gtk_list_box_set_selection_mode(GTK_LIST_BOX(list), GTK_SELECTION_NONE);
        gtk_widget_add_css_class(list, "cell-list");
        gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                       GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
        gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), list);
        gtk_widget_set_vexpand(scroll, TRUE);
        state->casebook_nodes_list = list;
        g_signal_connect(nodesearch, "changed",
                         G_CALLBACK(casebook_list_filter_changed), list);
        gtk_box_append(GTK_BOX(body), nodesearch);
        gtk_box_append(GTK_BOX(body), scroll);
    }
    return casebook_shell(NULL, body);
}

static GtkWidget *
create_casebook_page(AppState *state)
{
    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *head = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *titles = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *title = gtk_label_new("Casebook");
    GtkWidget *sub = gtk_label_new(
        "Cases, targets, evidence, captures, alerts, sensors and reports");
    GtkWidget *refresh = gtk_button_new_with_label("Refresh All");
    GtkWidget *tabs = gtk_notebook_new();

    gtk_widget_add_css_class(outer, "casebook");
    gtk_widget_add_css_class(title, "page-title");
    gtk_widget_add_css_class(sub, "page-subtitle");
    gtk_widget_add_css_class(tabs, "casebook-tabs");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(sub), 0.0f);
    gtk_widget_set_hexpand(titles, TRUE);
    gtk_box_append(GTK_BOX(titles), title);
    gtk_box_append(GTK_BOX(titles), sub);
    gtk_box_append(GTK_BOX(head), titles);
    gtk_box_append(GTK_BOX(head), refresh);
    gtk_widget_set_margin_top(head, 14);
    gtk_widget_set_margin_bottom(head, 8);
    gtk_widget_set_margin_start(head, 16);
    gtk_widget_set_margin_end(head, 16);
    gtk_box_append(GTK_BOX(outer), head);
    {
        GtkWidget *home = build_casebook_home(state);
        gtk_widget_set_margin_start(home, 16);
        gtk_widget_set_margin_end(home, 16);
        gtk_widget_set_margin_bottom(home, 8);
        gtk_box_append(GTK_BOX(outer), home);
    }
    gtk_widget_set_vexpand(tabs, TRUE);
    gtk_box_append(GTK_BOX(outer), tabs);
    state->casebook_tabs = tabs;
    gtk_notebook_set_scrollable(GTK_NOTEBOOK(tabs), TRUE);
    g_signal_connect(refresh, "clicked", G_CALLBACK(casebook_refresh_clicked), state);

    gtk_notebook_append_page(GTK_NOTEBOOK(tabs), create_casebook_overview(state),
                             gtk_label_new("Overview"));
    gtk_notebook_append_page(GTK_NOTEBOOK(tabs), create_evidence_page(state),
                             gtk_label_new("Evidence"));
    gtk_notebook_append_page(GTK_NOTEBOOK(tabs),
        create_casebook_listing(state, &state->casebook_captures_list,
            "No captures indexed.", "Search captures", "Index Files", "--index",
            NULL, NULL, NULL, NULL), gtk_label_new("Captures"));
    gtk_notebook_append_page(GTK_NOTEBOOK(tabs),
        create_casebook_listing(state, &state->casebook_timeline_list,
            "No timeline events.", "Search events", "Correlate Evidence", "--correlate",
            NULL, NULL, NULL, NULL), gtk_label_new("Timeline"));
    gtk_notebook_append_page(GTK_NOTEBOOK(tabs),
        create_casebook_listing(state, &state->casebook_alerts_list,
            "No alerts.", "Search alerts", "Build Baseline", "--baseline-build",
            "Clear Alerts", "--alerts-clear", NULL, NULL), gtk_label_new("Alerts"));
    gtk_notebook_append_page(GTK_NOTEBOOK(tabs), create_casebook_nodes(state),
                             gtk_label_new("Nodes"));
    gtk_notebook_append_page(GTK_NOTEBOOK(tabs),
        create_casebook_listing(state, &state->casebook_reports_list,
            "No reports exported.", "Search reports", "Export HTML", "--report-html",
            "Export JSON", "--report-json", "Export TSV", "--report-tsv"),
            gtk_label_new("Reports"));
    g_signal_connect(tabs, "switch-page",
                     G_CALLBACK(casebook_tab_switched), state);
    return outer;
}

/* ==================================================================== */
/*  STATS / SETTINGS                                                    */
/* ==================================================================== */

/* text_page() used to live here. It rendered a title, a subtitle and one
   scrolled body of text, and its only caller was the Help page. The Help
   page is now a subject list with a view each -- native/src/help_page.c --
   so the helper had no callers left and was deleted rather than kept
   against a future that had not asked for it. Its layout survives as
   help_body_view() in that file, where the class and margin choices are
   recorded next to the reason for them. */

/* A single headline number. */
static GtkWidget *
stat_tile(const char *value, const char *label)
{
    GtkWidget *b = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *v = gtk_label_new(value);
    GtkWidget *l = gtk_label_new(label);

    gtk_widget_add_css_class(b, "stat-tile");
    gtk_widget_add_css_class(v, "stat-value");
    gtk_widget_add_css_class(l, "stat-label");
    gtk_label_set_xalign(GTK_LABEL(v), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(l), 0.0f);
    gtk_box_append(GTK_BOX(b), v);
    gtk_box_append(GTK_BOX(b), l);
    return b;
}

/* label — bar — count, so the shape of the tree is visible at a glance. */
static GtkWidget *
stat_bar_row(const char *label, guint n, guint max)
{
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *l = gtk_label_new(label);
    GtkWidget *bar = gtk_progress_bar_new();
    GtkWidget *c = gtk_label_new(NULL);
    g_autofree char *cs = g_strdup_printf("%u", n);

    gtk_widget_add_css_class(l, "stat-row-label");
    gtk_widget_add_css_class(bar, "stat-bar");
    gtk_widget_add_css_class(c, "stat-row-count");

    gtk_label_set_xalign(GTK_LABEL(l), 0.0f);
    gtk_widget_set_size_request(l, 132, -1);
    gtk_widget_set_hexpand(bar, TRUE);
    gtk_widget_set_valign(bar, GTK_ALIGN_CENTER);
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(bar),
        max > 0 ? (double) n / (double) max : 0.0);
    gtk_progress_bar_set_show_text(GTK_PROGRESS_BAR(bar), FALSE);
    gtk_label_set_text(GTK_LABEL(c), cs);
    gtk_widget_set_size_request(c, 32, -1);
    gtk_label_set_xalign(GTK_LABEL(c), 1.0f);

    gtk_box_append(GTK_BOX(row), l);
    gtk_box_append(GTK_BOX(row), bar);
    gtk_box_append(GTK_BOX(row), c);
    return row;
}

/* The counts behind the Stats tiles. Recomputed on every visit, because loot
   is written by modules while the app runs and a frozen number is worse than
   no number at all. */
static void
stats_counts(guint *selftests, guint *loot_dirs, guint *loot_files, guint *offline)
{
    guint s = 0, dirs = 0, files = 0, off = 0;

    for (int i = 0; i < N_MODULES; i++)
        if (!module_script_exists(modules[i].id)) off++;
    for (int i = 0; i < MODULE_INDEX_N; i++)
        if (module_index[i].has_selftest) s++;

    g_autofree char *loot = g_build_filename(IMSISTING_ROOT, "loot", NULL);
    g_autoptr(GDir) d = g_dir_open(loot, 0, NULL);
    const char *name;

    if (d != NULL) {
        while ((name = g_dir_read_name(d)) != NULL) {
            g_autofree char *p = g_build_filename(loot, name, NULL);
            if (g_file_test(p, G_FILE_TEST_IS_DIR)) {
                dirs++;
                files += count_files(p);
            }
        }
    }
    *selftests  = s;
    *loot_dirs  = dirs;
    *loot_files = files;
    *offline    = off;
}

static void
stat_set(GtkWidget *label, guint n)
{
    g_autofree char *v = g_strdup_printf("%u", n);
    if (label != NULL) gtk_label_set_text(GTK_LABEL(label), v);
}

static GtkWidget *
create_stats_page(AppState *state)
{
    GtkWidget *outer  = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *scroll = gtk_scrolled_window_new();
    GtkWidget *inner  = gtk_box_new(GTK_ORIENTATION_VERTICAL, 14);
    GtkWidget *head   = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *title  = gtk_label_new("Stats");
    GtkWidget *sub    = gtk_label_new("Modules, collections and health");
    GtkWidget *tiles  = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GHashTable *by_cat = g_hash_table_new(g_str_hash, g_str_equal);
    guint selftests = 0, loot_files = 0, loot_dirs = 0, offline = 0, maxcat = 0;

    gtk_widget_add_css_class(title, "page-title");
    gtk_widget_add_css_class(sub,   "page-subtitle");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(sub),   0.0f);
    gtk_box_append(GTK_BOX(head), title);
    gtk_box_append(GTK_BOX(head), sub);
    gtk_box_append(GTK_BOX(inner), head);

    for (int i = 0; i < N_MODULES; i++) {
        gpointer v = g_hash_table_lookup(by_cat, modules[i].category);
        g_hash_table_insert(by_cat, (gpointer) modules[i].category,
                            GINT_TO_POINTER(GPOINTER_TO_INT(v) + 1));
    }
    stats_counts(&selftests, &loot_dirs, &loot_files, &offline);

    {
        g_autofree char *v = g_strdup_printf("%d", N_MODULES);
        gtk_box_append(GTK_BOX(tiles), stat_tile(v, "MODULES"));
    }
    {
        g_autofree char *v = g_strdup_printf("%u", selftests);
        GtkWidget *t = stat_tile(v, "WITH SELFTEST");
        state->stat_selftests = gtk_widget_get_first_child(t);
        gtk_box_append(GTK_BOX(tiles), t);
    }
    {
        g_autofree char *v = g_strdup_printf("%u", loot_dirs);
        GtkWidget *t = stat_tile(v, "LOOT DIRS");
        state->stat_loot_dirs = gtk_widget_get_first_child(t);
        gtk_box_append(GTK_BOX(tiles), t);
    }
    {
        g_autofree char *v = g_strdup_printf("%u", loot_files);
        GtkWidget *t = stat_tile(v, "LOOT FILES");
        state->stat_loot_files = gtk_widget_get_first_child(t);
        gtk_box_append(GTK_BOX(tiles), t);
    }
    {
        g_autofree char *v = g_strdup_printf("%u", offline);
        GtkWidget *t = stat_tile(v, "OFFLINE");
        state->stat_offline = gtk_widget_get_first_child(t);
        gtk_box_append(GTK_BOX(tiles), t);
    }
    gtk_box_append(GTK_BOX(inner), tiles);

    /* ---- by category ---- */
    {
        GtkWidget *body;
        GtkWidget *card = verb_card("BY CATEGORY", &body);
        g_autoptr(GPtrArray) cats = category_order();
        GHashTableIter it;
        gpointer k, v;

        g_hash_table_iter_init(&it, by_cat);
        while (g_hash_table_iter_next(&it, &k, &v))
            if (GPOINTER_TO_UINT(v) > maxcat) maxcat = GPOINTER_TO_UINT(v);

        for (guint c = 0; c < cats->len; c++) {
            const char *cat = g_ptr_array_index(cats, c);
            guint n = GPOINTER_TO_UINT(g_hash_table_lookup(by_cat, cat));
            gtk_box_append(GTK_BOX(body), stat_bar_row(cat, n, maxcat));
        }
        gtk_box_append(GTK_BOX(inner), card);
    }

    /* ---- where things live ---- */
    {
        GtkWidget *body;
        GtkWidget *card = verb_card("LOCATIONS", &body);
        const char *rows[][2] = {
            { "Project root", IMSISTING_ROOT },
            { "Modules",      IMSISTING_ROOT "/modules" },
            { "Loot",         IMSISTING_ROOT "/loot" },
            { "Captures",     IMSISTING_ROOT "/captures" },
            { "Scratch",      "/tmp/imsisting" },
        };
        for (guint i = 0; i < G_N_ELEMENTS(rows); i++) {
            GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
            GtkWidget *k = gtk_label_new(rows[i][0]);
            GtkWidget *v = gtk_label_new(rows[i][1]);
            gtk_widget_add_css_class(k, "stat-row-label");
            gtk_widget_add_css_class(v, "mono");
            gtk_widget_add_css_class(v, "dim");
            gtk_widget_set_size_request(k, 132, -1);
            gtk_label_set_xalign(GTK_LABEL(k), 0.0f);
            gtk_label_set_xalign(GTK_LABEL(v), 0.0f);
            gtk_label_set_selectable(GTK_LABEL(v), TRUE);
            gtk_box_append(GTK_BOX(row), k);
            gtk_box_append(GTK_BOX(row), v);
            gtk_box_append(GTK_BOX(body), row);
        }
        gtk_box_append(GTK_BOX(inner), card);
    }

    gtk_widget_add_css_class(inner, "page");
    gtk_widget_set_margin_top(inner, 16);
    gtk_widget_set_margin_bottom(inner, 16);
    gtk_widget_set_margin_start(inner, 16);
    gtk_widget_set_margin_end(inner, 16);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), inner);
    gtk_widget_set_vexpand(scroll, TRUE);
    gtk_box_append(GTK_BOX(outer), scroll);

    g_hash_table_unref(by_cat);
    g_object_set_data(G_OBJECT(outer), "stats-page", GINT_TO_POINTER(1));
    return outer;
}

/* ── Notifications ─────────────────────────────────────────────────────
   The record of what the toolkit said, newest first. A toast is easy to miss
   and impossible to look back at: it slides away after five seconds, only five
   share the corner, and the thing it usually reports - a scan that started, a
   scan that stopped, a run that failed - is exactly the thing worth checking
   afterwards. The log is written by show_toast_full, so it holds what was
   actually announced rather than a second list that can drift out of step. */
static void
notif_page_refill(AppState *state)
{
    GtkWidget *child;
    guint shown = 0;

    if (state == NULL || state->notif_list == NULL) return;

    while ((child = gtk_widget_get_first_child(state->notif_list)) != NULL)
        gtk_list_box_remove(GTK_LIST_BOX(state->notif_list), child);

    if (state->notifs != NULL) {
        for (GList *l = state->notifs->head; l != NULL; l = l->next) {
            gtk_list_box_append(GTK_LIST_BOX(state->notif_list),
                                notif_row_new(l->data));
            shown++;
        }
    }

    if (state->notif_summary == NULL) return;
    if (shown == 0) {
        gtk_label_set_text(GTK_LABEL(state->notif_summary),
            "Nothing yet — toasts land here as they happen.");
    } else if (shown == 1) {
        gtk_label_set_text(GTK_LABEL(state->notif_summary),
            "1 notification · newest first");
    } else {
        g_autofree char *t = g_strdup_printf(
            "%u notifications · newest first", shown);
        gtk_label_set_text(GTK_LABEL(state->notif_summary), t);
    }
}

static void
notif_clear_clicked(GtkButton *button, gpointer user_data)
{
    AppState *state = user_data;

    (void) button;
    if (state->notifs != NULL) {
        g_queue_free_full(state->notifs, notif_entry_free);
        state->notifs = NULL;
    }
    notif_page_refill(state);
}

static GtkWidget *
create_notifications_page(AppState *state)
{
    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *scroll = gtk_scrolled_window_new();
    GtkWidget *inner = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    GtkWidget *head = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *titles = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *title = gtk_label_new("Notifications");
    GtkWidget *sub = gtk_label_new(
        "Everything the toolkit has announced, newest first.");
    GtkWidget *clear = gtk_button_new_with_label("Clear");
    GtkWidget *list = gtk_list_box_new();

    gtk_widget_add_css_class(title, "page-title");
    gtk_widget_add_css_class(sub, "page-subtitle");
    gtk_widget_add_css_class(clear, "verb-button");
    gtk_widget_add_css_class(list, "notif-list");
    gtk_widget_add_css_class(inner, "page");
    gtk_widget_add_css_class(inner, "notif-page");

    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(sub), 0.0f);
    gtk_widget_set_hexpand(titles, TRUE);
    gtk_widget_set_halign(titles, GTK_ALIGN_START);
    gtk_widget_set_valign(clear, GTK_ALIGN_CENTER);
    gtk_widget_set_tooltip_text(clear, "forget every notification kept here");

    gtk_label_set_wrap(GTK_LABEL(sub), TRUE);
    gtk_box_append(GTK_BOX(titles), title);
    gtk_box_append(GTK_BOX(titles), sub);
    gtk_box_append(GTK_BOX(head), titles);
    gtk_box_append(GTK_BOX(head), clear);

    /* One column, no selection: these are lines to read, not rows to act on. */
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(list), GTK_SELECTION_NONE);
    gtk_list_box_set_show_separators(GTK_LIST_BOX(list), TRUE);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), list);
    gtk_widget_set_vexpand(scroll, TRUE);

    state->notif_list = list;
    state->notif_summary = sub;

    gtk_box_append(GTK_BOX(inner), head);
    gtk_box_append(GTK_BOX(inner), scroll);
    gtk_box_append(GTK_BOX(outer), inner);
    g_signal_connect(clear, "clicked",
                     G_CALLBACK(notif_clear_clicked), state);

    notif_page_refill(state);
    return outer;
}

/* Recount the tiles when the page is opened. Counting is cheap (56 stat calls
   plus a walk of loot/) and the alternative — numbers from launch time — is
   actively misleading once a module has run. */
static void
stats_refresh(AppState *state)
{    guint selftests = 0, loot_dirs = 0, loot_files = 0, offline = 0;

    stats_counts(&selftests, &loot_dirs, &loot_files, &offline);
    stat_set(state->stat_selftests, selftests);
    stat_set(state->stat_loot_dirs, loot_dirs);
    stat_set(state->stat_loot_files, loot_files);
    stat_set(state->stat_offline, offline);
}
/* The Help page lives in its own translation unit, native/src/help_page.c.
   It used to be a single string here, rendered through text_page(): one
   79-line scroll, so the answer to "where does loot/ go" and the answer to
   "what does exit code 3 mean" were the same scroll position. It is now a
   subject list with one view each, built from the same classes a module
   submenu uses.

   It is called out here because main1.c cannot see the definition: the
   page needs nothing from this file, and keeping the prototype rather than
   the text keeps a body of reference prose that changes for unrelated
   reasons out of the middle of the interface source. */
GtkWidget *create_help_page(void);

/* The note line is shared with the Field Kit page, which is defined much
   further down; the settings views are the page's first caller. */
static GtkWidget *fkit_note(const char *text);

/* ---- A row ----------------------------------------------------------
   Caption, control, where the value came from, and what the setting does.
   The origin chip is also the way back: pressing it takes the key out of
   settings.tsv, which is what "default" means. */

typedef struct {
    AppState   *state;
    const char *key;          /* static string, NULL for the ui.tsv rows */
    GtkWidget  *chip;         /* the origin chip, so it can say "default" */
    GtkWidget  *control;      /* the entry / switch / dropdown to put back */
    GCallback   handler;      /* its change handler, to block while we do */
    gpointer    ctx;          /* ...and the context that handler was given */
    const char *fallback;     /* entries and switches: the default */
    guint       fallback_index;  /* choices: the default's index */
    guint       kind;         /* 0 entry, 1 switch, 2 choice */
    gboolean    fallback_on;
} SettingsReset;

/* Taking the key out of the file is the easy half. The control has to go back
   to the default with it, and it has to do so with its own handler blocked -
   otherwise "back to the default" would immediately write the default into
   the file as though it had been chosen. */
static void
settings_reset_clicked(GtkButton *button, gpointer user_data)
{
    SettingsReset *r = g_object_get_data(G_OBJECT(button), "settings-reset");
    (void) user_data;
    if (r == NULL || r->key == NULL) return;

    if (r->control != NULL &&
        g_signal_handlers_block_by_func(r->control, r->handler, r->ctx)) {
        switch (r->kind) {
        case 1:
            gtk_switch_set_active(GTK_SWITCH(r->control), r->fallback_on);
            break;
        case 2:
            gtk_drop_down_set_selected(GTK_DROP_DOWN(r->control),
                                       r->fallback_index);
            break;
        default:
            gtk_editable_set_text(GTK_EDITABLE(r->control),
                                  r->fallback != NULL ? r->fallback : "");
            break;
        }
        g_signal_handlers_unblock_by_func(r->control, r->handler, r->ctx);
    }

    settings_put(r->key, NULL);
    if (r->chip != NULL) gtk_label_set_text(GTK_LABEL(r->chip), "default");
    if (r->state != NULL)
        show_toast_full(r->state, "Settings",
                        "back to the default", "info");
}

static GtkWidget *
settings_row(const char *label, SettingsReset *spec, const char *origin,
             const char *note, GtkWidget *control, AppState *state)
{
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_VERTICAL, 3);
    GtkWidget *top = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    GtkWidget *cap = gtk_label_new(label);
    g_autofree char *where = NULL;

    if (origin == NULL)
        where = g_strdup((spec != NULL && settings_declared(spec->key))
                         ? "settings.tsv" : "default");
    else
        where = g_strdup(origin);

    gtk_widget_add_css_class(row, "settings-row");
    gtk_widget_add_css_class(cap, "settings-key");
    gtk_label_set_xalign(GTK_LABEL(cap), 0.0f);
    gtk_widget_set_hexpand(cap, TRUE);
    gtk_box_append(GTK_BOX(top), cap);
    if (control != NULL) gtk_box_append(GTK_BOX(top), control);

    {
        GtkWidget *chip = gtk_label_new(where);
        gtk_widget_add_css_class(chip, "settings-origin");
        if (spec != NULL) {
            spec->state = state;
            spec->chip = chip;
            gtk_widget_set_tooltip_text(chip, "press to go back to the default");
            g_object_set_data_full(G_OBJECT(chip), "settings-reset", spec, g_free);
            GtkGesture *g = gtk_gesture_click_new();
            g_signal_connect_swapped(g, "pressed",
                                     G_CALLBACK(settings_reset_clicked), chip);
            gtk_widget_add_controller(chip, GTK_EVENT_CONTROLLER(g));
        }
        gtk_box_append(GTK_BOX(top), chip);
    }

    gtk_box_append(GTK_BOX(row), top);
    if (note != NULL && *note != '\0') {
        GtkWidget *n = gtk_label_new(note);
        gtk_widget_add_css_class(n, "settings-note");
        gtk_label_set_xalign(GTK_LABEL(n), 0.0f);
        gtk_label_set_wrap(GTK_LABEL(n), TRUE);
        gtk_box_append(GTK_BOX(row), n);
    }
    return row;
}

/* ---- Entries -------------------------------------------------------- */

typedef struct { AppState *state; const char *key; } SettingsText;

static void
settings_entry_changed(GtkEditable *editable, gpointer user_data)
{
    SettingsText *t = user_data;
    const char *txt = gtk_editable_get_text(editable);

    if (t == NULL || t->key == NULL) return;
    settings_put(t->key, (*txt != '\0') ? txt : NULL);
}

static GtkWidget *
settings_entry(const char *label, const char *key, const char *origin,
               const char *note, const char *placeholder, int width,
               AppState *state)
{
    GtkWidget *entry = gtk_entry_new();
    SettingsText *t = g_new0(SettingsText, 1);
    SettingsReset *spec = g_new0(SettingsReset, 1);
    const char *declared = settings_get(key, NULL);

    t->state = state;
    t->key = key;
    if (placeholder != NULL) gtk_entry_set_placeholder_text(GTK_ENTRY(entry),
                                                            placeholder);
    if (declared != NULL) gtk_editable_set_text(GTK_EDITABLE(entry), declared);
    if (width > 0) gtk_widget_set_size_request(entry, width, -1);
    g_signal_connect(entry, "changed", G_CALLBACK(settings_entry_changed), t);
    g_object_set_data_full(G_OBJECT(entry), "settings-text", t, g_free);

    if (key == NULL) {
        /* Not a settings.tsv key at all (the density and sort rows are
           kept in state/ui.tsv), so there is no default to go back to. */
        g_free(spec);
        spec = NULL;
    } else {
        spec->key = key;
        spec->control = entry;
        spec->handler = G_CALLBACK(settings_entry_changed);
        spec->ctx = t;
        spec->fallback = "";
        spec->kind = 0;
    }

    return settings_row(label, spec, origin, note, entry, state);
}

/* ---- Switches ------------------------------------------------------- */

typedef struct {
    AppState *state;
    const char *key;
    void (*apply)(AppState *state, gboolean on);
} SettingsToggle;

static void
settings_switch_changed(GObject *sw, GParamSpec *pspec, gpointer user_data)
{
    SettingsToggle *t = user_data;
    gboolean on;

    (void) pspec;
    if (t == NULL || t->key == NULL) return;
    on = gtk_switch_get_active(GTK_SWITCH(sw));
    settings_put(t->key, on ? "on" : "off");
    if (t->apply != NULL) t->apply(t->state, on);
}

static GtkWidget *
settings_switch(const char *label, const char *key, const char *note,
                gboolean fallback, void (*apply)(AppState *, gboolean),
                AppState *state)
{
    GtkWidget *sw = gtk_switch_new();
    SettingsToggle *t = g_new0(SettingsToggle, 1);
    SettingsReset *spec = g_new0(SettingsReset, 1);

    t->state = state;
    t->key = key;
    t->apply = apply;
    gtk_switch_set_active(GTK_SWITCH(sw), settings_flag(key, fallback));
    gtk_widget_set_valign(sw, GTK_ALIGN_CENTER);
    g_signal_connect(sw, "notify::active", G_CALLBACK(settings_switch_changed), t);
    g_object_set_data_full(G_OBJECT(sw), "settings-toggle", t, g_free);

    if (key == NULL) {
        /* Not a settings.tsv key at all (the density and sort rows are
           kept in state/ui.tsv), so there is no default to go back to. */
        g_free(spec);
        spec = NULL;
    } else {
        spec->key = key;
        spec->control = sw;
        spec->handler = G_CALLBACK(settings_switch_changed);
        spec->ctx = t;
        spec->kind = 1;
        spec->fallback_on = fallback;
    }

    return settings_row(label, spec, NULL, note, sw, state);
}

/* ---- Choices -------------------------------------------------------- */

typedef struct {
    AppState *state;
    const char *key;
    const char *const *values;
    void (*apply)(AppState *state, guint index);
} SettingsChoice;

static void
settings_choice_changed(GObject *dd, GParamSpec *pspec, gpointer user_data)
{
    SettingsChoice *c = user_data;
    guint sel;

    (void) pspec;
    if (c == NULL || c->key == NULL) return;
    sel = gtk_drop_down_get_selected(GTK_DROP_DOWN(dd));
    if (sel == GTK_INVALID_LIST_POSITION || c->values[sel] == NULL) return;
    settings_put(c->key, c->values[sel]);
    if (c->apply != NULL) c->apply(c->state, sel);
}

static GtkWidget *
settings_choice(const char *label, const char *key, const char *const *values,
                const char *const *labels, guint n, guint fallback,
                const char *note, void (*apply)(AppState *, guint),
                AppState *state)
{
    GtkWidget *dd = gtk_drop_down_new_from_strings(labels);
    SettingsChoice *c = g_new0(SettingsChoice, 1);
    SettingsReset *spec = g_new0(SettingsReset, 1);
    const char *cur = settings_get(key, NULL);
    guint sel = fallback;

    for (guint i = 0; i < n; i++)
        if (cur != NULL && g_strcmp0(cur, values[i]) == 0) sel = i;
    gtk_drop_down_set_selected(GTK_DROP_DOWN(dd), sel);

    c->state = state;
    c->key = key;
    c->values = values;
    c->apply = apply;
    g_signal_connect(dd, "notify::selected", G_CALLBACK(settings_choice_changed), c);
    g_object_set_data_full(G_OBJECT(dd), "settings-choice", c, g_free);

    if (key == NULL) {
        /* Not a settings.tsv key at all (the density and sort rows are
           kept in state/ui.tsv), so there is no default to go back to. */
        g_free(spec);
        spec = NULL;
    } else {
        spec->key = key;
        spec->control = dd;
        spec->handler = G_CALLBACK(settings_choice_changed);
        spec->ctx = c;
        spec->kind = 2;
        spec->fallback_index = fallback;
    }

    return settings_row(label, spec, NULL, note, dd, state);
}

/* ---- The effects ---------------------------------------------------- */

static void
settings_density_apply(AppState *state, guint index)
{
    static const char *names[] = {
        "density-compact", "density-comfortable", "density-spacious"
    };

    if (state == NULL) return;
    g_free(state->density);
    state->density = g_strdup(names[index]);
    density_apply(state);
    ui_state_save(state);
}

static void
settings_sort_apply(AppState *state, guint index)
{
    if (state == NULL) return;
    g_dash_sort = (int) index;
    dash_refresh(state);
    ui_state_save(state);
}

static void
settings_fonts_apply(AppState *state, guint index)
{
    if (state == NULL || state->window == NULL) return;
    if (index == 1)
        gtk_widget_add_css_class(state->window, "fonts-system");
    else
        gtk_widget_remove_css_class(state->window, "fonts-system");
}

static void
settings_motion_apply(AppState *state, guint index)
{
    if (state == NULL || state->window == NULL) return;
    if (index == 1)
        gtk_widget_add_css_class(state->window, "motion-reduced");
    else
        gtk_widget_remove_css_class(state->window, "motion-reduced");
}

static GtkWidget *
settings_card(const char *heading, GtkWidget **body_out)
{
    return verb_card(heading, body_out);
}

/* ---- Views ---------------------------------------------------------- */

static GtkWidget *
settings_view_interface(AppState *state)
{
    static const char *density_v[] = { "compact", "comfortable", "spacious" };
    static const char *density_l[] = { "Compact", "Comfortable", "Spacious" };
    static const char *sort_v[] = { "workflow", "alpha", "category" };
    static const char *sort_l[] = { "Workflow", "Alphabetical", "Category" };
    static const char *fonts_v[] = { "bundled", "system" };
    static const char *fonts_l[] = { "Neuropol + Orbitron", "System interface font" };
    static const char *motion_v[] = { "full", "reduced" };
    static const char *motion_l[] = { "Full", "Reduced" };
    static const char *splash_v[] = { "on", "off" };
    static const char *splash_l[] = { "Show a splash", "Go straight to the window" };
    static const char *art_v[] = { "all", "films", "still" };
    static const char *art_l[] = { "Films and the still", "Films only", "The still only" };
    static const char *drawer_v[] = { "hover", "click" };
    static const char *drawer_l[] = { "Pointer at the edge", "Click the edge" };

    GtkWidget *col = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    GtkWidget *card, *body;
    guint d = 1, s = 0, f = 0, m = 0;

    if (state != NULL && state->density != NULL) {
        if (strstr(state->density, "compact") != NULL) d = 0;
        else if (strstr(state->density, "spacious") != NULL) d = 2;
    }
    s = (guint) CLAMP(g_dash_sort, 0, 2);

    card = settings_card("INTERFACE", &body);
    gtk_box_append(GTK_BOX(body), settings_choice("Tile density",
        NULL, density_v, density_l, 3, d,
        "How much room each module tile is given on the dashboard. Kept in "
        "state/ui.tsv with the rest of what the last session was using; the "
        "dashboard dropdown changes the same value.",
        settings_density_apply, state));
    gtk_box_append(GTK_BOX(body), settings_choice("Dashboard order",
        NULL, sort_v, sort_l, 3, s,
        "The order the full catalogue is laid out in.",
        settings_sort_apply, state));
    gtk_box_append(GTK_BOX(col), card);

    card = settings_card("TYPE AND MOTION", &body);
    gtk_box_append(GTK_BOX(body), settings_choice("Display fonts",
        "ui.fonts", fonts_v, fonts_l, 2, f,
        "The two faces this toolkit ships — Neuropol for headings, Orbitron "
        "for labels. Off falls back to the system interface font everywhere, "
        "which is also the honest answer if the bundled licences ever become "
        "a problem.",
        settings_fonts_apply, state));
    gtk_box_append(GTK_BOX(body), settings_choice("Motion",
        "ui.motion", motion_v, motion_l, 2, m,
        "Reduced drops the tile growth and the fade-ins. Nothing is lost from "
        "the interface: it is the same layout, arriving still.",
        settings_motion_apply, state));
    gtk_box_append(GTK_BOX(col), card);

    card = settings_card("LAUNCH", &body);
    gtk_box_append(GTK_BOX(body), settings_choice("Splash screen",
        "ui.splash", splash_v, splash_l, 2, 0,
        "Read before the first window is built, so it takes effect on the "
        "next launch. The escape hatch stays: IMSISTING_NO_SPLASH=1 always "
        "wins over this.",
        NULL, state));
    gtk_box_append(GTK_BOX(body), settings_choice("Splash artwork",
        "ui.splash_art", art_v, art_l, 3, 0,
        "Four films and one still; the still is drawn over the artwork with "
        "its own card. Next launch, like the row above.",
        NULL, state));
    gtk_box_append(GTK_BOX(body), settings_choice("Page drawer",
        "ui.drawer", drawer_v, drawer_l, 2, 0,
        "The drawer that slides out over the page. Pointer at the edge is the "
        "default; click the edge is steadier on a touchpad.",
        NULL, state));
    gtk_box_append(GTK_BOX(col), card);

    card = settings_card("SHORTCUTS", &body);
    {
        static const char *keys[][2] = {
            { "Ctrl+K", "focus the header search — modules, pages and settings" },
            { "Enter",  "open the first result" },
            { "Escape", "close the results, then the open module" },
        };
        for (guint i = 0; i < G_N_ELEMENTS(keys); i++)
            gtk_box_append(GTK_BOX(body), overview_row(keys[i][0], keys[i][1]));
    }
    gtk_box_append(GTK_BOX(col), card);
    return col;
}

static void
settings_open_dir_clicked(GtkButton *button, gpointer user_data)
{
    const char *path = g_object_get_data(G_OBJECT(button), "path");
    g_autofree char *uri = NULL;
    g_autoptr(GError) error = NULL;

    (void) user_data;
    if (path == NULL || *path == '\0') return;
    uri = g_filename_to_uri(path, NULL, NULL);
    if (uri == NULL) return;
    if (!g_app_info_launch_default_for_uri(uri, NULL, &error) && error != NULL)
        g_printerr("imsisting: cannot open %s: %s\n", path, error->message);
}

static GtkWidget *
settings_dir_button(const char *label, const char *path)
{
    GtkWidget *b = gtk_button_new_with_label(label);

    gtk_widget_add_css_class(b, "verb-button");
    g_object_set_data(G_OBJECT(b), "path", (gpointer) path);
    g_signal_connect(b, "clicked", G_CALLBACK(settings_open_dir_clicked), NULL);
    return b;
}

static GtkWidget *
settings_view_paths(AppState *state)
{
    GtkWidget *col = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    GtkWidget *card, *body;
    struct { const char *label; const char *key; const char *env;
             const char *leaf; } dirs[] = {
        { "Loot",     "paths.loot",     "LOOT_DIR",     "loot" },
        { "Captures", "paths.captures", "CAPTURES_DIR", "captures" },
        { "Scratch",  "paths.tmp",      "TMP_DIR",      "tmp" },
        { "Logs",     "paths.logs",     "LOG_DIR",      "logs" },
        { "State",    "paths.state",    "STATE_DIR",    "state" },
        { "Cases",    "paths.cases",    "CASES_DIR",    "cases" },
    };
    const char *eff[G_N_ELEMENTS(dirs)];
    g_autofree char *def[G_N_ELEMENTS(dirs)];

    card = settings_card("WHERE THINGS GO", &body);
    gtk_box_append(GTK_BOX(body), fkit_note(
        "The launcher reads these before any module starts, so a change here "
        "lands on the next launch — and the same file is what "
        "`./imsisting.sh --settings set` writes, so the command line and this "
        "window cannot drift apart. A variable already exported in the shell "
        "wins over the file, which is why the row says where its value came "
        "from."));
    for (guint i = 0; i < G_N_ELEMENTS(dirs); i++) {
        const char *env = g_getenv(dirs[i].env);
        g_autofree char *note = NULL;
        def[i] = g_build_filename(IMSISTING_ROOT, dirs[i].leaf, NULL);
        eff[i] = (env != NULL && *env != '\0') ? env : def[i];
        note = g_strdup_printf("In use now: %s — from the %s", eff[i],
                               (env != NULL && *env != '\0') ? "environment"
                                                             : "built-in default");
        gtk_box_append(GTK_BOX(body), settings_entry(dirs[i].label, dirs[i].key,
            NULL, note, eff[i], 320, state));
    }
    gtk_box_append(GTK_BOX(col), card);

    card = settings_card("OPEN", &body);
    {
        GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        gtk_box_append(GTK_BOX(row), settings_dir_button("Loot", eff[0]));
        gtk_box_append(GTK_BOX(row), settings_dir_button("Captures", eff[1]));
        gtk_box_append(GTK_BOX(row), settings_dir_button("Scratch", eff[2]));
        gtk_box_append(GTK_BOX(body), row);
    }
    gtk_box_append(GTK_BOX(col), card);
    return col;
}

static GtkWidget *
settings_view_radio(AppState *state)
{
    static const char *hint_v[] = { "none", "dcs", "pcs" };
    static const char *hint_l[] = { "No hint", "DCS 1800", "PCS 1900" };
    GtkWidget *col = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    GtkWidget *card, *body;

    card = settings_card("ARFCN", &body);
    gtk_box_append(GTK_BOX(body), settings_choice("GSM band hint",
        "radio.arfcn_hint", hint_v, hint_l, 3, 0,
        "GSM ARFCN 512..810 is PCS 1900 uplink and DCS 1800 downlink at the "
        "same time; nothing in the number itself says which. The hint decides, "
        "and it is passed to every conversion the window makes.",
        NULL, state));
    gtk_box_append(GTK_BOX(body), fkit_note(
        "02_cell_recon.sh --arfcn takes the same hint as a fourth argument, so "
        "a conversion done here and one done by hand agree."));
    gtk_box_append(GTK_BOX(col), card);

    card = settings_card("THE BENCH", &body);
    gtk_box_append(GTK_BOX(body), fkit_note(
        "What the SDR is tuned to is part of the bench, not a preference: it "
        "lives on the SDR / Radio Manager page and in the status strip, and "
        "the header Target panel is where a cell is set."));
    gtk_box_append(GTK_BOX(body), overview_row("Choosing a radio", "SDR / Radio Manager → Device inventory"));
    gtk_box_append(GTK_BOX(body), overview_row("Current tuning", "SDR / Radio Manager → Tuning"));
    gtk_box_append(GTK_BOX(col), card);
    return col;
}

static GtkWidget *
settings_view_live(AppState *state)
{
    static const char *bind_v[] = { "127.0.0.1", "0.0.0.0" };
    static const char *bind_l[] = { "This machine only (127.0.0.1)",
                                    "Any interface (0.0.0.0)" };
    GtkWidget *col = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    GtkWidget *card, *body;
    g_autofree char *port = g_strdup_printf("%d", settings_int("live.port", 4729, 1, 65535));
    g_autofree char *rot = g_strdup_printf("%d", settings_int("live.rotate_s", 0, 0, 86400));
    g_autofree char *keep = g_strdup_printf("%d", settings_int("live.keep", 20, 1, 5000));
    g_autofree char *dbm = g_strdup_printf("%d", settings_int("live.min_dbm", 0, -120, 0));

    card = settings_card("LISTENER", &body);
    gtk_box_append(GTK_BOX(body), settings_entry("GSMTAP port",
        "live.port", NULL,
        "What the live view binds, and what the Listen udp field on Live "
        "Traffic starts with. gr-gsm, srsRAN and Open5GS all emit to 4729 by "
        "default.", port, 120, state));
    gtk_box_append(GTK_BOX(body), settings_choice("Bind address",
        "live.bind", bind_v, bind_l, 2, 0,
        "0.0.0.0 accepts GSMTAP from anywhere that can reach this machine, "
        "which is convenient on a bench and wrong on a shared network: anyone "
        "who can reach the port can put frames into what you are treating as "
        "evidence. 127.0.0.1 is the careful default.",
        NULL, state));
    gtk_box_append(GTK_BOX(col), card);

    card = settings_card("CAPTURES", &body);
    gtk_box_append(GTK_BOX(body), settings_switch("Save as soon as it starts",
        "live.autosave", "The Save pcap box on Live Traffic starts checked, and "
        "a file opens when the listener does. Everything received is written, "
        "filtered or not: the capture is evidence, not what was on screen.",
        FALSE, NULL, state));
    gtk_box_append(GTK_BOX(body), settings_entry("Rotate every",
        "live.rotate_s", NULL, "Seconds per capture file; 0 means one file for "
        "the whole session.", rot, 120, state));
    gtk_box_append(GTK_BOX(body), settings_entry("Keep at most",
        "live.keep", NULL, "How many live_*.pcap files the prune keeps in the "
        "capture directory, newest first.", keep, 120, state));
    gtk_box_append(GTK_BOX(col), card);

    card = settings_card("WHAT THE VIEW STARTS WITH", &body);
    gtk_box_append(GTK_BOX(body), settings_entry("Minimum signal",
        "live.min_dbm", NULL, "dBm. 0 means off. A frame whose signal the "
        "emitter never reported is never hidden by this.", dbm, 120, state));
    gtk_box_append(GTK_BOX(col), card);
    return col;
}

static GtkWidget *
settings_view_notify(AppState *state)
{
    GtkWidget *col = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    GtkWidget *card, *body;
    g_autofree char *ms = g_strdup_printf("%d", settings_int("notify.toast_ms", 4200, 0, 120000));
    g_autofree char *keep = g_strdup_printf("%d", settings_int("notify.keep", 100, 10, 1000));
    g_autofree char *stack = g_strdup_printf("%d", settings_int("notify.stack", 5, 1, 20));

    card = settings_card("TOASTS", &body);
    gtk_box_append(GTK_BOX(body), settings_entry("Linger",
        "notify.toast_ms", NULL, "Milliseconds a toast stays before it fades. "
        "0 keeps it until it is closed by hand. Errors are given twice this "
        "when the default is in force — they are the ones worth reading twice.",
        ms, 120, state));
    gtk_box_append(GTK_BOX(body), settings_entry("At most on screen",
        "notify.stack", NULL, "A new toast past this closes the oldest one.",
        stack, 120, state));
    gtk_box_append(GTK_BOX(body), settings_entry("Tones worth interrupting for",
        "notify.severities", NULL, "Any of: error, warn, ok, info — separated "
        "by commas, or with spaces, which are ignored. The notification log "
        "keeps everything either way; this is only about the corner.",
        "error, warn, ok, info", 320, state));
    gtk_box_append(GTK_BOX(col), card);

    card = settings_card("THE LOG", &body);
    gtk_box_append(GTK_BOX(body), settings_entry("Keep",
        "notify.keep", NULL, "How many notifications the Notifications page "
        "remembers, newest first.", keep, 120, state));
    gtk_box_append(GTK_BOX(body), settings_entry("Muted titles",
        "notify.mute", NULL, "Comma-separated toast titles — usually a module "
        "name — that are logged but never shown. Empty means nothing is muted.",
        "e.g. Live Traffic", 320, state));
    {
        GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        GtkWidget *clear = gtk_button_new_with_label("Clear the log");
        gtk_widget_add_css_class(clear, "verb-button");
        g_signal_connect(clear, "clicked", G_CALLBACK(notif_clear_clicked), state);
        gtk_box_append(GTK_BOX(row), clear);
        gtk_box_append(GTK_BOX(body), row);
    }
    gtk_box_append(GTK_BOX(col), card);
    return col;
}

static GtkWidget *
settings_view_diagnostics(AppState *state)
{
    GtkWidget *col = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    GtkWidget *card, *body;
    GtkWidget *scroll, *view;
    g_autofree char *body_text = NULL;
    const char *tmp = g_getenv("TMP_DIR");
    const char *loot = g_getenv("LOOT_DIR");
    const char *caps = g_getenv("CAPTURES_DIR");

    if (tmp == NULL)  tmp  = IMSISTING_ROOT "/tmp";
    if (loot == NULL) loot = IMSISTING_ROOT "/loot";
    if (caps == NULL) caps = IMSISTING_ROOT "/captures";

    card = settings_card("ENVIRONMENT", &body);
    body_text = g_strdup_printf(
        "Project root      %s\n"
        "Loot directory    %s\n"
        "Captures          %s\n"
        "Scratch           %s\n"
        "\n"
        "GTK               %u.%u.%u\n"
        "GLib              %u.%u.%u\n"
        "Modules           %d\n"
        "Index entries     %d\n"
        "\n"
        "Privileged actions run through pkexec, per action rather than once at\n"
        "startup. A module invoked without root reports the failure instead of\n"
        "silently doing nothing.\n"
        "\n"
        "Bundled fonts     Neuropol (headings), Orbitron (labels, OFL 1.1)\n"
        "                  native/resources/fonts/NOTICE.md\n",
        IMSISTING_ROOT, loot, caps, tmp,
        gtk_get_major_version(), gtk_get_minor_version(), gtk_get_micro_version(),
        glib_major_version, glib_minor_version, glib_micro_version,
        N_MODULES, MODULE_INDEX_N);

    view = gtk_text_view_new();
    scroll = gtk_scrolled_window_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(view), GTK_WRAP_WORD_CHAR);
    gtk_widget_add_css_class(view, "page-text");
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(view)),
                             body_text, -1);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), view);
    gtk_widget_set_size_request(scroll, -1, 260);
    gtk_box_append(GTK_BOX(body), scroll);
    gtk_box_append(GTK_BOX(col), card);

    card = settings_card("MAINTENANCE", &body);
    {
        GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        GtkWidget *deps  = gtk_button_new_with_label("Check dependencies");
        GtkWidget *radio = gtk_button_new_with_label("Probe SDRs");
        GtkWidget *st    = gtk_label_new("Idle");

        gtk_widget_add_css_class(st, "status-pill");
        gtk_widget_add_css_class(st, "status-idle");

        g_object_set_data(G_OBJECT(deps), "state", state);
        g_object_set_data(G_OBJECT(deps), "module-id", (gpointer) "00_deps");
        g_object_set_data(G_OBJECT(deps), "status", st);
        g_object_set_data_full(G_OBJECT(deps), "verb",
                               g_strdup("--check-versions"), g_free);
        g_signal_connect(deps, "clicked", G_CALLBACK(group_verb_clicked), NULL);

        g_object_set_data(G_OBJECT(radio), "state", state);
        g_object_set_data(G_OBJECT(radio), "module-id", (gpointer) "01_radio");
        g_object_set_data(G_OBJECT(radio), "status", st);
        g_object_set_data_full(G_OBJECT(radio), "verb",
                               g_strdup("--list-tsv"), g_free);
        g_signal_connect(radio, "clicked", G_CALLBACK(group_verb_clicked), NULL);

        gtk_box_append(GTK_BOX(row), deps);
        gtk_box_append(GTK_BOX(row), radio);
        gtk_box_append(GTK_BOX(row), st);
        gtk_box_append(GTK_BOX(body), row);
    }
    gtk_box_append(GTK_BOX(col), card);
    return col;
}

/* ---- The page ------------------------------------------------------- */

typedef struct {
    AppState  *state;
    GtkWidget *stack;
    GtkWidget *list;
    const char *names[6];
    GtkWidget *pages[6];
    guint n;
} SettingsViews;

static void
settings_view_activated(GtkListBox *list, GtkListBoxRow *row, gpointer user_data)
{
    SettingsViews *sv = user_data;
    int index = gtk_list_box_row_get_index(row);

    if (sv == NULL || index < 0 || (guint) index >= sv->n) return;
    gtk_stack_set_visible_child_name(GTK_STACK(sv->stack), sv->names[index]);
    gtk_list_box_select_row(list, row);

    /* "Settings" is a place worth returning to, and the view is the part of it
       worth naming: Paths and Diagnostics are two different intentions. */
    if (sv->state != NULL)
        place_push_view(sv->state, "settings", sv->names[index]);
}

/* Open the Settings page on a named view, for a recent place. A name that no
   longer exists leaves the page as it is rather than failing loudly: the
   recent list is a convenience, not a contract. */
static void
settings_show_view(AppState *state, const char *name)
{
    GtkWidget *page;
    SettingsViews *sv;

    if (state == NULL || name == NULL || state->notebook == NULL) return;
    page = gtk_notebook_get_nth_page(GTK_NOTEBOOK(state->notebook),
                                     SETTINGS_PLACE_PAGE);
    if (page == NULL) return;
    sv = g_object_get_data(G_OBJECT(page), "settings-views");
    if (sv == NULL || sv->list == NULL) return;

    for (guint i = 0; i < sv->n; i++) {
        if (g_strcmp0(sv->names[i], name) != 0) continue;
        {
            GtkListBoxRow *r = gtk_list_box_get_row_at_index(
                GTK_LIST_BOX(sv->list), (int) i);
            if (r != NULL)
                settings_view_activated(GTK_LIST_BOX(sv->list), r, sv);
        }
        return;
    }
}

static GtkWidget *
create_settings_page(AppState *state)
{
    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *head  = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *title = gtk_label_new("Settings");
    GtkWidget *sub   = gtk_label_new("What this toolkit does by default");
    GtkWidget *cols  = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    GtkWidget *menu_col = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *hdr   = gtk_label_new("VIEWS");
    GtkWidget *list  = gtk_list_box_new();
    GtkWidget *menu_scroll = gtk_scrolled_window_new();
    GtkWidget *stack = gtk_stack_new();
    SettingsViews *sv = g_new0(SettingsViews, 1);
    static const struct { const char *name; const char *icon; } views[] = {
        { "Interface",     "preferences-desktop-symbolic" },
        { "Paths",         "folder-symbolic" },
        { "Radio",         "network-wireless-symbolic" },
        { "Live traffic",  "media-record-symbolic" },
        { "Notifications", "notification-symbolic" },
        { "Diagnostics",   "dialog-information-symbolic" },
    };

    gtk_widget_add_css_class(title, "page-title");
    gtk_widget_add_css_class(sub, "page-subtitle");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(sub), 0.0f);
    gtk_box_append(GTK_BOX(head), title);
    gtk_box_append(GTK_BOX(head), sub);
    gtk_widget_set_margin_top(head, 14);
    gtk_widget_set_margin_start(head, 16);
    gtk_widget_add_css_class(outer, "doc-page");
    gtk_box_append(GTK_BOX(outer), head);

    sv->stack = stack;
    sv->list = list;
    sv->n = G_N_ELEMENTS(views);
    sv->pages[0] = settings_view_interface(state);
    sv->pages[1] = settings_view_paths(state);
    sv->pages[2] = settings_view_radio(state);
    sv->pages[3] = settings_view_live(state);
    sv->pages[4] = settings_view_notify(state);
    sv->pages[5] = settings_view_diagnostics(state);

    gtk_widget_add_css_class(list, "module-menu");
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(list), GTK_SELECTION_SINGLE);
    gtk_list_box_set_activate_on_single_click(GTK_LIST_BOX(list), TRUE);
    gtk_stack_set_transition_type(GTK_STACK(stack), GTK_STACK_TRANSITION_TYPE_NONE);

    for (guint i = 0; i < sv->n; i++) {
        GtkWidget *row = gtk_list_box_row_new();
        GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
        GtkWidget *icon = imsisting_icon_image(views[i].icon);
        GtkWidget *label = gtk_label_new(views[i].name);
        GtkWidget *scroll = gtk_scrolled_window_new();
        GtkWidget *pad = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);

        sv->names[i] = views[i].name;
        gtk_widget_add_css_class(row, "module-menu-row");
        gtk_image_set_pixel_size(GTK_IMAGE(icon), 20);
        gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
        gtk_widget_set_hexpand(label, TRUE);
        gtk_box_append(GTK_BOX(box), icon);
        gtk_box_append(GTK_BOX(box), label);
        gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), box);
        gtk_list_box_append(GTK_LIST_BOX(list), row);

        gtk_widget_set_margin_start(sv->pages[i], 18);
        gtk_widget_set_margin_end(sv->pages[i], 18);
        gtk_widget_set_margin_top(sv->pages[i], 10);
        gtk_widget_set_margin_bottom(sv->pages[i], 18);
        gtk_box_append(GTK_BOX(pad), sv->pages[i]);
        gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                       GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
        gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), pad);
        gtk_widget_set_vexpand(scroll, TRUE);
        gtk_stack_add_named(GTK_STACK(stack), scroll, views[i].name);
    }
    g_signal_connect(list, "row-activated",
                     G_CALLBACK(settings_view_activated), sv);

    gtk_widget_add_css_class(hdr, "menu-heading");
    gtk_label_set_xalign(GTK_LABEL(hdr), 0.0f);
    gtk_widget_set_margin_top(hdr, 12);
    gtk_widget_set_margin_bottom(hdr, 6);
    gtk_widget_set_margin_start(hdr, 16);
    gtk_box_append(GTK_BOX(menu_col), hdr);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(menu_scroll),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(menu_scroll), list);
    gtk_widget_set_size_request(menu_scroll, 250, -1);
    gtk_widget_set_vexpand(menu_scroll, TRUE);
    gtk_box_append(GTK_BOX(menu_col), menu_scroll);
    gtk_widget_set_vexpand(menu_col, TRUE);
    gtk_box_append(GTK_BOX(menu_col), gtk_separator_new(GTK_ORIENTATION_VERTICAL));
    gtk_box_append(GTK_BOX(cols), menu_col);
    gtk_widget_set_hexpand(stack, TRUE);
    gtk_box_append(GTK_BOX(cols), stack);
    gtk_widget_set_vexpand(cols, TRUE);
    gtk_box_append(GTK_BOX(outer), cols);

    gtk_list_box_select_row(GTK_LIST_BOX(list),
                            gtk_list_box_get_row_at_index(GTK_LIST_BOX(list), 0));

    sv->state = state;
    g_object_set_data_full(G_OBJECT(outer), "settings-views", sv, g_free);
    return outer;
}


/* ==================================================================== */
/*  LIVE TRAFFIC — GSMTAP                                               */
/*                                                                      */
/*  There is no way to demodulate GSM/LTE inside a GUI process; that     */
/*  needs a full PHY. What every PHY in this ecosystem does instead is   */
/*  emit GSMTAP — the raw message wrapped in UDP on 4729 — which is what */
/*  Wireshark keys off and what 03_gsmtap already consumes offline.      */
/*                                                                      */
/*  So the live view is a GSMTAP listener. It is genuinely useful from   */
/*  both sides: passively to watch paging, SI and identity exchanges as  */
/*  they happen, and offensively to confirm an emitter is actually       */
/*  transmitting and see what the UE answers with.                       */
/*                                                                      */
/*  The header layout below is the one verified against Wireshark's      */
/*  GSMTAP dissector: 16-byte version-2 header, hdr_len in 32-bit words, */
/*  the GSM channel in sub_type, uplink as 0x4000 in the arfcn field.    */
/* ==================================================================== */

#define LIVE_PORT 4729
#define LIVE_MAX_LINES 600
/* A GSMTAP message is a signalling frame - tens of bytes. The cap exists so a
   malformed emitter cannot grow the retained history without bound, and the
   inspector says so when it bites. */
#define LIVE_PAYLOAD_MAX 2048
/* Silence longer than this, while listening, is reported as "quiet Ns"
   rather than left to look like a healthy feed with a frozen counter. */
#define LIVE_QUIET_SECONDS 5

static const char *
gsmtap_type_name(guint8 t)
{
    switch (t) {
    case 0x01: return "GSM Um (CS)";
    case 0x02: return "GSM Um (PS)";
    case 0x03: return "UMTS RRC";
    case 0x04: return "LTE RRC";
    case 0x05: return "LTE NAS";
    case 0x06: return "NR RRC";
    case 0x07: return "NR NAS";
    case 0x08: return "GSM Abis";
    case 0x0a: return "LTE X2AP";
    case 0x0b: return "NR NGAP";
    case 0x0c: return "LTE S1AP";
    default:   return "unknown";
    }
}

static const char *
gsmtap_channel_name(guint8 c)
{
    switch (c) {
    case 0x00: return "UNKNOWN"; case 0x01: return "BCCH";
    case 0x02: return "CCCH";    case 0x03: return "RACH";
    case 0x04: return "AGCH";    case 0x05: return "PCH";
    case 0x06: return "SDCCH";   case 0x07: return "SDCCH4";
    case 0x08: return "SDCCH8";  case 0x09: return "TCH/F";
    case 0x0a: return "TCH/H";   case 0x0b: return "PACCH";
    default:   return "?";
    }
}

static gboolean gsmtap_is_gsm(guint8 t)
{
    return t == 0x01 || t == 0x02 || t == 0x08;
}

/* Live Traffic is permanent page 1. Start the listener when it is opened and
   stop it when it is left, so the socket is only bound while the view is up. */
static void live_start(AppState *state, gboolean announce);
static void live_stop(AppState *state, gboolean announce);

#define LIVE_TAB_INDEX 1

/* ── the palette ──────────────────────────────────────────────────────────
   The header's search field opens a result list under itself. It answers
   the same question the drawer's catalogue does, one keystroke in instead
   of a pointer journey to the window edge, which is the difference between
   the search being the fastest way somewhere and being the last resort. */
static void
palette_add_row(AppState *state, const char *icon, const char *name,
                const char *sub, const char *haystack, int page_index,
                const ModuleDefinition *module)
{
    GtkWidget *row = gtk_list_box_row_new();
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *img = imsisting_icon_image(icon);
    GtkWidget *col = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *lname = gtk_label_new(name);
    GtkWidget *lsub = gtk_label_new(sub);

    gtk_image_set_pixel_size(GTK_IMAGE(img), 18);
    gtk_widget_set_valign(img, GTK_ALIGN_CENTER);
    gtk_label_set_xalign(GTK_LABEL(lname), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(lsub), 0.0f);
    gtk_widget_set_hexpand(lname, TRUE);
    gtk_widget_add_css_class(lname, "palette-name");
    gtk_widget_add_css_class(lsub, "palette-sub");
    gtk_label_set_ellipsize(GTK_LABEL(lsub), PANGO_ELLIPSIZE_END);
    gtk_box_append(GTK_BOX(col), lname);
    gtk_box_append(GTK_BOX(col), lsub);
    gtk_widget_set_hexpand(col, TRUE);
    gtk_box_append(GTK_BOX(box), img);
    gtk_box_append(GTK_BOX(box), col);
    gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), box);

    /* Owned by the row: g_ascii_strdown returns a fresh string, and a
       g_autofree would hand the row a pointer it had already freed. */
    g_object_set_data_full(G_OBJECT(row), "haystack",
                           g_ascii_strdown(haystack, -1), g_free);
    g_object_set_data(G_OBJECT(row), "page-index", GINT_TO_POINTER(page_index));
    g_object_set_data(G_OBJECT(row), "module", (gpointer) module);
    gtk_list_box_append(GTK_LIST_BOX(state->palette_list), row);
}

static void
palette_refilter(AppState *state)
{
    const char *q = state->header_search != NULL
        ? gtk_editable_get_text(GTK_EDITABLE(state->header_search)) : NULL;
    g_autofree char *needle = (q != NULL && *q != '\0') ? g_ascii_strdown(q, -1) : NULL;
    int shown = 0;

    if (state->palette == NULL) return;
    for (GtkWidget *row = gtk_widget_get_first_child(state->palette_list);
         row != NULL; row = gtk_widget_get_next_sibling(row)) {
        const char *hay = g_object_get_data(G_OBJECT(row), "haystack");
        gboolean hit = needle != NULL && hay != NULL && strstr(hay, needle) != NULL;
        gtk_widget_set_visible(row, hit);
        if (hit) shown++;
    }
    gtk_widget_set_visible(state->palette, needle != NULL && shown > 0);
}

static void
palette_row_activated(GtkListBox *list, GtkListBoxRow *row, gpointer user_data)
{
    AppState *state = user_data;
    const ModuleDefinition *module = g_object_get_data(G_OBJECT(row), "module");
    int page = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(row), "page-index"));

    gtk_editable_set_text(GTK_EDITABLE(state->header_search), "");
    gtk_widget_set_visible(state->palette, FALSE);
    if (module != NULL)
        open_module(state, module);
    else if (page >= 0)
        gtk_notebook_set_current_page(GTK_NOTEBOOK(state->notebook), page);
    (void) list;
}

static void
palette_search_changed(GtkSearchEntry *entry, gpointer user_data)
{
    (void) entry;
    palette_refilter(user_data);
}

static void
palette_activate(GtkSearchEntry *entry, gpointer user_data)
{
    AppState *state = user_data;
    for (GtkWidget *row = gtk_widget_get_first_child(state->palette_list);
         row != NULL; row = gtk_widget_get_next_sibling(row)) {
        if (gtk_widget_get_visible(row)) {
            palette_row_activated(NULL, GTK_LIST_BOX_ROW(row), state);
            return;
        }
    }
    (void) entry;
}

static void
palette_stopped(GtkSearchEntry *entry, gpointer user_data)
{
    AppState *state = user_data;
    gtk_editable_set_text(GTK_EDITABLE(entry), "");
    gtk_widget_set_visible(state->palette, FALSE);
}

/* The dashboard is the only view that is never covered, so it is the
   overlay's main child and the notebook's page 0 is an empty slot standing
   in for it. Every other page is this panel: floating over the dashboard
   with a scrim behind it, opened by the drawer and closed by Escape, by a
   click on the scrim, or by the page's own close button. */
static void
sheet_set_open(AppState *state, gboolean open)
{
    if (state->sheet == NULL) return;
    gtk_widget_set_visible(state->sheet, open);
    gtk_widget_set_visible(state->sheet_scrim, open);
}

static void
sheet_dismiss(AppState *state)
{
    if (state->notebook == NULL) return;
    if (gtk_widget_get_visible(state->sheet))
        gtk_notebook_set_current_page(GTK_NOTEBOOK(state->notebook), 0);
}

static void
sheet_scrim_clicked(GtkGestureClick *gesture, int n_press, double x, double y,
                    gpointer user_data)
{
    (void) gesture; (void) n_press; (void) x; (void) y;
    sheet_dismiss(user_data);
}

static gboolean
sheet_key_pressed(GtkEventControllerKey *controller, guint keyval,
                  guint keycode, GdkModifierType modifiers, gpointer user_data)
{
    AppState *state = user_data;
    (void) controller; (void) keycode;

    if ((modifiers & GDK_CONTROL_MASK) != 0 &&
        (keyval == GDK_KEY_k || keyval == GDK_KEY_K)) {
        if (state->header_search != NULL)
            gtk_widget_grab_focus(state->header_search);
        return TRUE;
    }
    if (keyval != GDK_KEY_Escape) return FALSE;
    if (state->palette != NULL && gtk_widget_get_visible(state->palette)) {
        gtk_editable_set_text(GTK_EDITABLE(state->header_search), "");
        gtk_widget_set_visible(state->palette, FALSE);
        return TRUE;
    }
    if (!gtk_widget_get_visible(state->sheet)) return FALSE;
    sheet_dismiss(state);
    return TRUE;
}

static void
notebook_page_switched(GtkNotebook *nb, GtkWidget *child, guint page,
                       gpointer user_data)
{
    AppState *state = user_data;
    GtkTextBuffer *buf;
    (void) nb;

    /* Page 0 is the dashboard's slot, and the dashboard is behind the sheet
       rather than in it, so landing on page 0 is what closing looks like. */
    sheet_set_open(state, page != 0);

    /* Aim output at the console of whichever page is on screen. Non-module
       tabs carry no "output-buffer", which clears the target so a run can
       never write into a page that is no longer visible. */
    buf = child != NULL
        ? g_object_get_data(G_OBJECT(child), "output-buffer") : NULL;
    if (state->active_output != buf) {
        g_clear_object(&state->active_output);
        state->active_output = buf != NULL ? g_object_ref(buf) : NULL;
    }

    /* Keep the sidebar highlight on the module actually on screen. A
       permanent tab carries no module id, which clears the highlight rather
       than leaving the last module marked while you look at the dashboard. */
    sidebar_set_active(state, child != NULL
                       ? g_object_get_data(G_OBJECT(child), "module-id") : NULL);

    /* The drawer's page list replaced the tab strip, so it has to follow the
       notebook the way the module rows already do -- including onto a module
       page, which is on no list entry and so clears the highlight. */
    if (state->drawer_nav != NULL) {
        state->drawer_nav_syncing = TRUE;
        if (page < 6 && state->drawer_nav_rows[page] != NULL)
            gtk_list_box_select_row(GTK_LIST_BOX(state->drawer_nav),
                GTK_LIST_BOX_ROW(state->drawer_nav_rows[page]));
        else
            gtk_list_box_unselect_all(GTK_LIST_BOX(state->drawer_nav));
        state->drawer_nav_syncing = FALSE;
    }

    /* Stats counts filesystem state that modules change while the app runs. */
    if (child != NULL && g_object_get_data(G_OBJECT(child), "stats-page") != NULL)
        stats_refresh(state);

    if (state->live_view == NULL) return;

    if ((int) page == LIVE_TAB_INDEX) {
        if (state->live_socket == NULL) live_start(state, FALSE);
    } else if (state->live_socket != NULL) {
        live_stop(state, FALSE);
    }
}

/* ---- a decoded GSMTAP message, one per row ---- */
#define LIVE_TYPE_MSG (live_msg_get_type())
G_DECLARE_FINAL_TYPE(LiveMsg, live_msg, LIVE, MSG, GObject)

struct _LiveMsg {
    GObject parent;
    guint   seq, arfcn, ts, len;
    gint    sig;
    guint8  raw_type;      /* the GSMTAP type byte, for the RAT a row implies */
    guint8  ch_code;       /* the channel code, for filtering by channel */
    gboolean pcs;          /* 0x8000 on the ARFCN: PCS1900, not DCS1800 */
    gboolean up;           /* 0x4000: the phone's direction, not the cell's */
    /* The whole message, not the first fourteen bytes of it. The column
       abbreviates; the inspector and the row actions need all of it. */
    char   *time, *type, *ch, *dir, *payload;
};

G_DEFINE_FINAL_TYPE(LiveMsg, live_msg, G_TYPE_OBJECT)

static void
live_msg_finalize(GObject *o)
{
    LiveMsg *m = LIVE_MSG(o);
    g_free(m->time); g_free(m->type); g_free(m->ch);
    g_free(m->dir);  g_free(m->payload);
    G_OBJECT_CLASS(live_msg_parent_class)->finalize(o);
}

static void
live_msg_class_init(LiveMsgClass *k)
{
    G_OBJECT_CLASS(k)->finalize = live_msg_finalize;
}

static void
live_msg_init(LiveMsg *m) { (void) m; }

static const char *
live_col_title(int which)
{
    switch (which) {
    case 0: return "#";       case 1: return "TIME";
    case 2: return "TYPE";    case 3: return "CH";
    case 4: return "ARFCN";   case 5: return "TS";
    case 6: return "SIG";     case 7: return "DIR";
    case 8: return "LEN";     default: return "PAYLOAD";
    }
}

static void
live_col_setup(GtkSignalListItemFactory *f, GtkListItem *item, gpointer d)
{
    GtkWidget *l = gtk_label_new(NULL);
    gtk_label_set_xalign(GTK_LABEL(l), 0.0f);
    gtk_widget_add_css_class(l, "live-cell");
    gtk_list_item_set_child(item, l);
    (void) f; (void) d;
}

static void
live_col_bind(GtkSignalListItemFactory *f, GtkListItem *item, gpointer d)
{
    GtkWidget *l = gtk_list_item_get_child(item);
    LiveMsg *m = LIVE_MSG(gtk_list_item_get_item(item));
    int which = GPOINTER_TO_INT(d);
    g_autofree char *s = NULL;

    switch (which) {
    case 0: s = g_strdup_printf("%u", m->seq);      break;
    case 1: s = g_strdup(m->time);                  break;
    case 2: s = g_strdup(m->type);                  break;
    case 3: s = g_strdup(m->ch);                    break;
    case 4: s = g_strdup_printf("%u", m->arfcn);    break;
    case 5: s = g_strdup_printf("%u", m->ts);       break;
    case 6: s = g_strdup_printf("%d", m->sig);      break;
    case 7: s = g_strdup(m->dir);                   break;
    case 8: s = g_strdup_printf("%u", m->len);      break;
    default:
        /* A glance, not the record: the whole message is in the inspector
           and in the capture. Sixteen bytes is enough to see what it is. */
        if (m->payload != NULL && strlen(m->payload) > 32)
            s = g_strdup_printf("%.32s..", m->payload);
        else
            s = g_strdup(m->payload != NULL ? m->payload : "");
        break;
    }
    gtk_label_set_text(GTK_LABEL(l), s ? s : "");
    /* The label cannot be picked (labels do not take pointer events), and the
       widget that can be is the one wrapping it. It carries the message so a
       right-click anywhere in the cell finds it by walking up. */
    {
        GtkWidget *cellw = gtk_widget_get_parent(l);
        if (cellw != NULL)
            g_object_set_data(G_OBJECT(cellw), "live-msg", m);
    }
    gboolean right = (which == 4 || which == 5 || which == 6 || which == 8);
    gtk_label_set_xalign(GTK_LABEL(l), right ? 1.0f : 0.0f);
    if (which == 7) {
        gtk_widget_remove_css_class(l, "dir-ul");
        gtk_widget_remove_css_class(l, "dir-dl");
        if (g_strcmp0(m->dir, "UL") == 0)
            gtk_widget_add_css_class(l, "dir-ul");
        else
            gtk_widget_add_css_class(l, "dir-dl");
    }
    (void) f;
}

/* GLib's case-insensitive search is for whole strings or sorted keys, so the
   feed carries its own. The strings are a type, a channel and a payload of a
   few hundred bytes, so the plain scan is the right shape. */
static gboolean
live_ci_contains(const char *hay, const char *needle)
{
    gsize nlen;

    if (needle == NULL || *needle == '\0') return TRUE;
    if (hay == NULL) return FALSE;
    nlen = strlen(needle);
    for (; *hay != '\0'; hay++) {
        if (g_ascii_strncasecmp(hay, needle, nlen) == 0) return TRUE;
    }
    return FALSE;
}

static gboolean
live_matches(AppState *state, LiveMsg *m)
{
    /* The decoded filters come first: they answer "show me the uplink" and
       "only this cell" without the operator having to spell out a substring.
       A signal of 0 is the emitter saying it does not know, so a strength
       filter does not throw those rows away - it would be a filter that hides
       frames for a reason the operator never asked for. */
    if (!state->live_show_ul && m->up)  return FALSE;
    if (!state->live_show_dl && !m->up) return FALSE;
    if (state->live_min_dbm != 0 && m->sig != 0 && m->sig < state->live_min_dbm)
        return FALSE;
    if (state->live_filter_arfcn >= 0 &&
        (gint) m->arfcn != state->live_filter_arfcn)
        return FALSE;
    if (state->live_filter_channel >= 0 &&
        (gint) m->ch_code != state->live_filter_channel)
        return FALSE;

    if (state->live_filter == NULL || *state->live_filter == '\0') return TRUE;
    /* Case-insensitive, because the one field anybody types by hand is hex.
       GLib has no ascii strcasestr, and lowercasing every payload on every
       message would cost more than this. */
    return live_ci_contains(m->type, state->live_filter) ||
           live_ci_contains(m->ch, state->live_filter) ||
           live_ci_contains(m->payload, state->live_filter);
}

/* Any filter the user can set, so the chip knows whether to say "of N". */
static gboolean
live_filtered(AppState *state)
{
    return (state->live_filter != NULL && *state->live_filter != '\0') ||
           !state->live_show_ul || !state->live_show_dl ||
           state->live_min_dbm != 0 || state->live_filter_arfcn >= 0 ||
           state->live_filter_channel >= 0;
}

/* Rebuild the visible model from the retained messages. */
static void
live_refilter(AppState *state)
{
    if (state->live_store == NULL || state->live_msgs == NULL) return;
    g_list_store_remove_all(G_LIST_STORE(state->live_store));
    for (guint i = 0; i < state->live_msgs->len; i++) {
        LiveMsg *m = g_ptr_array_index(state->live_msgs, i);
        if (live_matches(state, m))
            g_list_store_append(G_LIST_STORE(state->live_store), m);
    }
    /* The selected row can be filtered away, or evicted by the history cap.
       Leaving its detail up would describe a row that is no longer there. */
    if (live_shown_count(state) == 0)
        live_inspector_reset(state);
}

static void
live_set_status(AppState *state, const char *msg, const char *css)
{
    if (state->live_status == NULL) return;
    gtk_label_set_text(GTK_LABEL(state->live_status), msg);

    const char *classes[] = { "status-idle", "status-running",
                              "status-ok", "status-error", NULL };
    for (int i = 0; classes[i] != NULL; i++)
        gtk_widget_remove_css_class(state->live_status, classes[i]);
    if (css != NULL && *css != '\0')
        gtk_widget_add_css_class(state->live_status, css);
}

/* The inspector's resting state. One definition, so Clear, a filter that
   matches nothing and the first paint all agree on what "nothing selected"
   looks like instead of leaving the last packet on screen. */
static void
live_inspector_reset(AppState *state)
{
    if (state->live_inspector_buf == NULL) return;
    gtk_text_buffer_set_text(state->live_inspector_buf,
        "Select a row to inspect its decoded GSMTAP fields.", -1);
}

/* How many rows the view is actually showing, as opposed to how many have
   arrived - the difference is the whole point of the filter. */
static guint
live_shown_count(AppState *state)
{
    if (state->live_store == NULL) return 0;
    return g_list_model_get_n_items(G_LIST_MODEL(state->live_store));
}

/* Keep the count chip and the empty state in step with the feed.

   The chip is the operational read-out: how much has arrived, how fast it is
   still arriving, how much of it survives the filter, and whether the feed
   has gone quiet. The state word stays on the pill next to it, so the two
   never overwrite each other - the poll callback used to rewrite the pill
   with the counter eight times a second, which is what buried "listening". */
static void
live_update_summary(AppState *state)
{
    if (state->live_summary != NULL) {
        GString *s = g_string_new(NULL);
        gboolean filtered = live_filtered(state);
        guint shown = live_shown_count(state);

        if (filtered)
            g_string_append_printf(s, "%u of %u shown", shown, state->live_count);
        else
            g_string_append_printf(s, "%u msg%s", state->live_count,
                                   state->live_count == 1 ? "" : "s");

        if (state->live_socket != NULL && !state->live_paused)
            g_string_append_printf(s, " · %u/s", state->live_rate);

        /* Silence while listening is a condition, not an absence of one. */
        if (state->live_socket != NULL && !state->live_paused &&
            state->live_count > 0 && state->live_last_us > 0) {
            gint64 quiet_s = (g_get_monotonic_time() - state->live_last_us) / 1000000;
            if (quiet_s >= LIVE_QUIET_SECONDS)
                g_string_append_printf(s, " · quiet %" G_GINT64_FORMAT "s", quiet_s);
        }

        if (state->live_paused) g_string_append(s, " · paused");

        gtk_label_set_text(GTK_LABEL(state->live_summary), s->str);
        g_string_free(s, TRUE);
    }
    if (state->live_empty != NULL)
        gtk_widget_set_visible(state->live_empty, state->live_count == 0);
}

/* One tick a second is enough to read as live without redrawing the chip
   eight times a second for no new information. */
static gboolean
live_rate_tick(gpointer user_data)
{
    AppState *state = user_data;
    state->live_rate = state->live_count - state->live_rate_prev;
    state->live_rate_prev = state->live_count;
    live_update_summary(state);
    return G_SOURCE_CONTINUE;
}

static void
live_add_msg(AppState *state, LiveMsg *m)
{
    if (state->live_msgs == NULL)
        state->live_msgs = g_ptr_array_new_with_free_func(g_object_unref);
    if (state->live_store == NULL)
        state->live_store = g_list_store_new(LIVE_TYPE_MSG);

    g_ptr_array_add(state->live_msgs, m);          /* takes the ref */

    /* Cap retained history so a long run cannot grow without bound. */
    if (state->live_msgs->len > LIVE_MAX_LINES) {
        g_ptr_array_remove_index(state->live_msgs, 0);
        live_refilter(state);
    } else if (live_matches(state, m)) {
        g_list_store_append(G_LIST_STORE(state->live_store), m);
    }

    state->live_count++;
    /* The first datagram since start or Clear retires the "no emitter yet"
       hint. The pill is set by start/stop/pause now, so nothing else would
       ever take that message down once traffic started arriving. */
    if (state->live_count == 1 && state->live_socket != NULL && !state->live_paused)
        live_set_status(state, "listening on udp/4729", "status-running");

    /* Deliberately no summary update here. This runs inside the model-append
       path, and redrawing the chip from there re-enters the column view while
       it is still handling items-changed - which is what tripped GTK's
       gtk_list_item_manager_ensure_items assertion during a busy feed. The
       chip is a once-a-second read-out anyway; live_rate_tick owns it. */
}

/* ── writing the feed to disk ─────────────────────────────────────────────
   A GSMTAP capture is an ordinary Ethernet/IPv4/UDP pcap, which is what
   Wireshark dissects and what `modules/03_gsmtap.sh --decode` reads back.
   The layout below matches gtap_write_pcap in that module — link type 1,
   port to port, GSMTAP in the payload — so a file written here opens in
   both. Two differences, both deliberate: the timestamps are the real
   arrival times rather than a counter, and the IPv4 header checksum is
   computed. Neither is verified by a dissector, but a capture whose clock is
   a counter is worthless next to a log, and a checksum costs two lines.

   The bytes written are the datagram exactly as it arrived, so what lands on
   disk is what the table showed — including anything a filter hid. */
static void
live_pcap_put32(FILE *fp, guint32 v)
{
    guint8 b[4] = { (guint8) (v & 0xff), (guint8) ((v >> 8) & 0xff),
                    (guint8) ((v >> 16) & 0xff), (guint8) ((v >> 24) & 0xff) };
    if (fwrite(b, 1, 4, fp) != 4) { /* the failure is reported by the caller */ }
}

static void
live_pcap_write_header(FILE *fp)
{
    live_pcap_put32(fp, 0xa1b2c3d4);   /* magic: microseconds, little-endian */
    live_pcap_put32(fp, 0x00040002);   /* version 2.4 */
    live_pcap_put32(fp, 0);            /* thiszone */
    live_pcap_put32(fp, 0);            /* sigfigs */
    live_pcap_put32(fp, 65535);        /* snaplen */
    live_pcap_put32(fp, 1);            /* LINKTYPE_ETHERNET */
}

/* One datagram, wrapped so it looks like the UDP/GSMTAP packet it is. */
static gsize
live_pcap_frame(AppState *state, const guint8 *g, gsize glen,
                guint8 *out, gsize outsz)
{
    static const guint8 dst_mac[6] = { 0x00,0x11,0x22,0x33,0x44,0x55 };
    static const guint8 src_mac[6] = { 0x66,0x77,0x88,0x99,0xaa,0xbb };
    gsize o = 0, ip, i;
    guint32 csum = 0;
    guint16 udp_len;

    if (glen > 1500) glen = 1500;      /* keep one record inside one MTU */
    udp_len = (guint16) (8 + glen);
    if (14 + 20 + 8 + glen > outsz) return 0;

    memcpy(out + o, dst_mac, 6); o += 6;
    memcpy(out + o, src_mac, 6); o += 6;
    out[o++] = 0x08; out[o++] = 0x00;

    ip = o;
    out[o++] = 0x45; out[o++] = 0x00;                      /* v4, 20-byte header */
    out[o++] = (guint8) ((20 + udp_len) >> 8);
    out[o++] = (guint8) ((20 + udp_len) & 0xff);
    out[o++] = 0x00; out[o++] = 0x00;                      /* id */
    out[o++] = 0x40; out[o++] = 0x00;                      /* don't fragment */
    out[o++] = 64;   out[o++] = 17;                        /* ttl, UDP */
    out[o++] = 0x00; out[o++] = 0x00;                      /* checksum, below */
    out[o++] = 10; out[o++] = 0; out[o++] = 0; out[o++] = 1;
    out[o++] = 10; out[o++] = 0; out[o++] = 0; out[o++] = 2;

    for (i = ip; i < ip + 20; i += 2)
        csum += (guint32) ((out[i] << 8) | out[i + 1]);
    while (csum >> 16) csum = (csum & 0xffff) + (csum >> 16);
    csum = (~csum) & 0xffff;
    out[ip + 10] = (guint8) (csum >> 8);
    out[ip + 11] = (guint8) (csum & 0xff);

    /* The port the listener is on, both ends: this is a capture of what
       arrived, not of a conversation with a peer. */
    out[o++] = (guint8) ((state->live_port >> 8) & 0xff);
    out[o++] = (guint8) (state->live_port & 0xff);
    out[o++] = (guint8) ((state->live_port >> 8) & 0xff);
    out[o++] = (guint8) (state->live_port & 0xff);
    out[o++] = (guint8) (udp_len >> 8);
    out[o++] = (guint8) (udp_len & 0xff);
    out[o++] = 0x00; out[o++] = 0x00;   /* checksum 0 = not computed, RFC 768 */

    memcpy(out + o, g, glen); o += glen;
    return o;
}

static void
live_capture_label_update(AppState *state)
{
    if (state->live_capture_label == NULL) return;
    if (state->live_pcap == NULL) {
        gtk_label_set_text(GTK_LABEL(state->live_capture_label), "not saving");
        gtk_widget_remove_css_class(state->live_capture_label, "capture-live");
        return;
    }
    g_autofree char *base = g_path_get_basename(state->live_pcap_path);
    g_autofree char *m = g_strdup_printf("%s · %" G_GUINT64_FORMAT " frames · %.1f MB",
        base, state->live_pcap_packets,
        (double) state->live_pcap_bytes / (1024.0 * 1024.0));
    gtk_label_set_text(GTK_LABEL(state->live_capture_label), m);
    gtk_widget_add_css_class(state->live_capture_label, "capture-live");
}

/* The default name carries the start time, so two runs never overwrite each
   other the way a fixed captures/live.pcap would. */
static char *
live_pcap_default_path(void)
{
    g_autoptr(GDateTime) now = g_date_time_new_now_local();
    g_autofree char *stamp = now ? g_date_time_format(now, "%Y%m%d_%H%M%S") : NULL;
    g_autofree char *name = g_strdup_printf("live_%s.pcap",
                                            stamp ? stamp : "capture");
    return g_build_filename(IMSISTING_ROOT, "captures", name, NULL);
}

static void
live_pcap_close(AppState *state)
{
    if (state->live_pcap != NULL) {
        fclose(state->live_pcap);
        state->live_pcap = NULL;
    }
    if (state->live_pcap_rotate_id != 0) {
        g_source_remove(state->live_pcap_rotate_id);
        state->live_pcap_rotate_id = 0;
    }
}

/* Opens the file the path entry names, creating the directory if it is one we
   own. Returns FALSE and toasts on failure: a feed that is quietly not being
   recorded is the one failure mode a capture must never have. */
static gboolean
live_pcap_open(AppState *state, const char *path, gboolean announce)
{
    g_autofree char *dir = NULL;

    live_pcap_close(state);
    g_free(state->live_pcap_path);
    state->live_pcap_path = g_strdup(path);

    dir = g_path_get_dirname(state->live_pcap_path);
    if (g_mkdir_with_parents(dir, 0755) != 0 && errno != EEXIST) {
        g_autofree char *m = g_strdup_printf("cannot create %s: %s", dir,
                                             g_strerror(errno));
        if (announce) show_toast_full(state, "Live Traffic", m, "error");
        live_set_status(state, m, "status-error");
        return FALSE;
    }

    state->live_pcap = fopen(state->live_pcap_path, "wb");
    if (state->live_pcap == NULL) {
        g_autofree char *m = g_strdup_printf("cannot write %s: %s",
            state->live_pcap_path, g_strerror(errno));
        if (announce) show_toast_full(state, "Live Traffic", m, "error");
        live_set_status(state, m, "status-error");
        return FALSE;
    }
    setvbuf(state->live_pcap, NULL, _IOFBF, 1 << 16);
    live_pcap_write_header(state->live_pcap);
    state->live_pcap_packets = 0;
    state->live_pcap_bytes = 24;   /* the global header counts too */
    state->live_pcap_opened_us = g_get_monotonic_time();
    state->live_pcap_flushed_us = state->live_pcap_opened_us;
    state->live_pcap_failed = FALSE;
    live_capture_label_update(state);
    return TRUE;
}

/* Rotation keeps the window's worth of files, not the whole disk: a capture
   left running overnight must not fill the partition it is evidence on. */
static gint
live_path_cmp(gconstpointer a, gconstpointer b)
{
    return g_strcmp0(*(const char *const *) a, *(const char *const *) b);
}

static void
live_pcap_prune(const char *dir)
{
    GDir *d = g_dir_open(dir, 0, NULL);
    const char *name;
    GPtrArray *live = g_ptr_array_new_with_free_func(g_free);
    guint i, drop;

    if (d == NULL) return;
    while ((name = g_dir_read_name(d)) != NULL) {
        if (!g_str_has_prefix(name, "live_") || !g_str_has_suffix(name, ".pcap"))
            continue;
        g_ptr_array_add(live, g_build_filename(dir, name, NULL));
    }
    g_dir_close(d);

    /* The names carry the time they were opened, so sorting by name sorts by
       age. Oldest first, then everything past the newest N goes - and the
       prune only ever touches the files this window wrote itself. */
    guint keep = (guint) settings_int("live.keep", 20, 1, 5000);
    g_ptr_array_sort(live, live_path_cmp);
    drop = live->len > keep ? live->len - keep : 0;
    for (i = 0; i < drop; i++)
        g_remove((const char *) g_ptr_array_index(live, i));
    g_ptr_array_free(live, TRUE);
}

static gboolean
live_pcap_rotate_cb(gpointer user_data)
{
    AppState *state = user_data;
    g_autofree char *dir = NULL;
    g_autofree char *next = NULL;
    g_autoptr(GDateTime) now = NULL;
    g_autofree char *stamp = NULL;
    g_autofree char *base = NULL;

    if (state->live_pcap == NULL) { state->live_pcap_rotate_id = 0; return G_SOURCE_REMOVE; }

    dir = g_path_get_dirname(state->live_pcap_path);
    now = g_date_time_new_now_local();
    stamp = now ? g_date_time_format(now, "%Y%m%d_%H%M%S") : NULL;
    base = g_strdup_printf("live_%s.pcap", stamp ? stamp : "capture");
    next = g_build_filename(dir, base, NULL);
    if (!live_pcap_open(state, next, FALSE)) {
        state->live_pcap_rotate_id = 0;
        return G_SOURCE_REMOVE;
    }
    live_pcap_prune(dir);
    live_set_status(state, "saving to a new file", "status-running");
    return G_SOURCE_CONTINUE;
}

static void
live_pcap_write(AppState *state, const guint8 *g, gsize glen)
{
    guint8 pkt[14 + 20 + 8 + 1500];
    gsize n;
    gint64 us;

    if (state->live_pcap == NULL) return;

    n = live_pcap_frame(state, g, glen, pkt, sizeof pkt);
    if (n == 0) return;

    us = g_get_real_time();
    live_pcap_put32(state->live_pcap, (guint32) (us / G_USEC_PER_SEC));
    live_pcap_put32(state->live_pcap, (guint32) (us % G_USEC_PER_SEC));
    live_pcap_put32(state->live_pcap, (guint32) n);
    live_pcap_put32(state->live_pcap, (guint32) n);
    if (fwrite(pkt, 1, n, state->live_pcap) != n) {
        if (!state->live_pcap_failed) {
            state->live_pcap_failed = TRUE;
            show_toast_full(state, "Live Traffic",
                            "the capture file stopped accepting writes — "
                            "the disk may be full", "error");
        }
        live_pcap_close(state);
        live_capture_label_update(state);
        return;
    }
    state->live_pcap_packets++;
    state->live_pcap_bytes += 16 + n;

    /* The file is buffered because a live feed is a stream of small writes,
       but a capture that only lands on disk when the window closes is not
       evidence - it is a promise. A flush a few times a second costs little
       and bounds what a crash can take with it. */
    if (g_get_monotonic_time() - state->live_pcap_flushed_us > 200000) {
        fflush(state->live_pcap);
        state->live_pcap_flushed_us = g_get_monotonic_time();
        live_capture_label_update(state);
    }
}

static gboolean
live_poll_cb(gpointer user_data)
{
    AppState *state = user_data;
    guint8 buf[2048];
    gssize n;

    if (state->live_paused) return G_SOURCE_CONTINUE;
    if (state->live_socket == NULL) return G_SOURCE_CONTINUE;

    while ((n = g_socket_receive(state->live_socket, (gchar *) buf,
                                 sizeof buf, NULL, NULL)) > 0) {
        if (n < 16) continue;

        state->live_last_us = g_get_monotonic_time();

        /* Disk first, filter later. A capture is evidence, and evidence is
           not "what the operator happened to be looking at". */
        live_pcap_write(state, buf, (gsize) n);

        guint hdr_bytes = (guint) buf[1] * 4;
        if (hdr_bytes < 16 || hdr_bytes > (guint) n) hdr_bytes = 16;

        guint8  type = buf[2];
        guint8  ts   = buf[3];
        guint16 arf  = (guint16) ((buf[4] << 8) | buf[5]);
        gint8   sig  = (gint8) buf[6];
        guint8  sub  = buf[12];
        guint   paylen = (guint) n - hdr_bytes;
        gboolean up = (arf & 0x4000) != 0;

        const char *ch = "-";
        guint8 ch_code = 0;
        if (gsmtap_is_gsm(type)) {
            guint8 c = sub;
            if (c == 0) c = (guint8) ((arf >> 8) & 0xff);
            ch_code = c;
            ch = gsmtap_channel_name(c);
        }

        GDateTime *now = g_date_time_new_now_local();
        g_autofree char *t = now ? g_date_time_format(now, "%H:%M:%S") : NULL;
        if (now) g_date_time_unref(now);

        GString *pay = g_string_new(NULL);
        guint keep = paylen > LIVE_PAYLOAD_MAX ? LIVE_PAYLOAD_MAX : paylen;
        for (guint i = 0; i < keep; i++)
            g_string_append_printf(pay, "%02x", buf[hdr_bytes + i]);

        LiveMsg *m = g_object_new(LIVE_TYPE_MSG, NULL);
        m->seq     = state->live_count + 1;
        m->time    = g_strdup(t ? t : "--:--:--");
        m->type    = g_strdup(gsmtap_type_name(type));
        m->ch      = g_strdup(ch);
        m->arfcn   = arf & 0x3fff;
        m->ts      = ts;
        m->sig     = sig;
        m->dir     = g_strdup(up ? "UL" : "DL");
        m->len     = paylen;
        m->raw_type = type;
        m->ch_code  = ch_code;
        m->pcs     = (arf & 0x8000) != 0;
        m->up      = up;
        m->payload = g_string_free(pay, FALSE);

        live_add_msg(state, m);   /* live_add_msg takes the reference */
    }

    /* Deliberately no label write here. This runs every 120 ms; the state
       word on the pill is set by start/stop/pause, and the numbers live in
       the summary chip, which updates on its own one-second tick. */
    return G_SOURCE_CONTINUE;
}

static gboolean
live_hint_cb(gpointer user_data)
{
    AppState *state = user_data;
    state->live_hint = 0;
    if (state->live_count == 0 && state->live_socket != NULL) {
        live_set_status(state,
            "listening — no emitter yet. Start grgsm_livemon, or an eNB/gNB "
            "with GSMTAP enabled.", "status-error");
        /* The pill alone cannot be trusted to be read: this is the "it did
           not work" case, three seconds after the operator asked for a feed,
           and it is worth interrupting for once. */
        if (state->live_announced) {
            show_toast_full(state, "Live Traffic",
                "listening on udp/4729, but nothing has arrived — start "
                "grgsm_livemon or enable GSMTAP on the eNB/gNB", "warn");
            state->live_announced = FALSE;
        }
    }
    return G_SOURCE_REMOVE;
}

static void
live_stop(AppState *state, gboolean announce)
{
    /* Only the button announces. The listener also starts and stops by itself
       when the page is opened or left, and a toast for every visit to Live
       Traffic is the noise that makes people stop reading the corner. */
    gboolean was_listening = (state->live_socket != NULL);

    if (state->live_poll != 0) {
        g_source_remove(state->live_poll);
        state->live_poll = 0;
    }
    if (state->live_socket != NULL) {
        g_socket_close(state->live_socket, NULL);
        g_clear_object(&state->live_socket);
    }
    if (state->live_hint != 0) {
        g_source_remove(state->live_hint);
        state->live_hint = 0;
    }
    if (state->live_button != NULL)
        gtk_button_set_label(GTK_BUTTON(state->live_button), "Start");
    if (state->live_socket == NULL && state->live_count == 0)
        live_set_status(state, "stopped", "status-idle");
    else if (state->live_count > 0) {
        g_autofree char *m = g_strdup_printf("%u message%s",
            state->live_count, state->live_count == 1 ? "" : "s");
        live_set_status(state, m, "status-ok");
    }

    /* The capture belongs to the listener: no listener, no file. Leaving it
       open would keep "recording" a feed nobody is receiving. */
    if (state->live_pcap != NULL) {
        g_autofree char *base = g_path_get_basename(state->live_pcap_path);
        guint64 frames = state->live_pcap_packets;
        g_autofree char *saved = g_strdup(base);
        live_pcap_close(state);
        live_capture_label_update(state);
        if (announce && frames > 0) {
            g_autofree char *m = g_strdup_printf(
                "capture closed — %s, %" G_GUINT64_FORMAT " frames",
                saved, frames);
            show_toast_full(state, "Live Traffic", m, "ok");
        }
    }

    if (announce && was_listening) {
        g_autofree char *m = (state->live_count > 0)
            ? g_strdup_printf("listener stopped — %u message%s captured",
                              state->live_count, state->live_count == 1 ? "" : "s")
            : g_strdup("listener stopped");
        show_toast_full(state, "Live Traffic", m, "warn");
    }
}

static void
live_start(AppState *state, gboolean announce)
{
    g_autoptr(GError) error = NULL;
    GSocketAddress *addr;

    state->live_announced = announce;

    state->live_socket = g_socket_new(G_SOCKET_FAMILY_IPV4,
                                      G_SOCKET_TYPE_DATAGRAM,
                                      G_SOCKET_PROTOCOL_UDP, &error);
    if (state->live_socket == NULL) {
        live_set_status(state, error ? error->message : "socket failed",
                        "status-error");
        if (announce)
            show_toast_full(state, "Live Traffic",
                            error ? error->message : "socket failed", "error");
        return;
    }

    addr = g_inet_socket_address_new_from_string(
        settings_get("live.bind", "127.0.0.1"), state->live_port);
    if (!g_socket_bind(state->live_socket, addr, TRUE, &error)) {
        g_autofree char *m = g_strdup_printf("cannot bind udp/%u — %s",
            state->live_port, error ? error->message : "in use");
        live_set_status(state, m, "status-error");
        if (announce) show_toast_full(state, "Live Traffic", m, "error");
        g_object_unref(addr);
        g_clear_object(&state->live_socket);
        return;
    }
    g_object_unref(addr);

    g_socket_set_blocking(state->live_socket, FALSE);
    state->live_poll = g_timeout_add(120, live_poll_cb, state);

    if (state->live_button != NULL)
        gtk_button_set_label(GTK_BUTTON(state->live_button), "Stop");
    {
        g_autofree char *m = g_strdup_printf("listening on udp/%u",
                                             state->live_port);
        live_set_status(state, m, "status-running");
        if (announce) {
            g_autofree char *t = g_strdup_printf(
                "listening on udp/%u — the feed gr-gsm and srsRAN emit into",
                state->live_port);
            show_toast_full(state, "Live Traffic", t, "ok");
        }
    }
    /* The checkbox is the operator's intent, so the file opens when the
       listener does rather than on a separate button. */
    if (state->live_save_check != NULL &&
        gtk_check_button_get_active(GTK_CHECK_BUTTON(state->live_save_check)))
        live_capture_begin(state, FALSE);
    state->live_hint = g_timeout_add(3000, live_hint_cb, state);
}

static void
live_toggle_clicked(GtkButton *b, gpointer user_data)
{
    AppState *state = user_data;
    (void) b;
    if (state->live_socket != NULL) live_stop(state, TRUE);
    else                            live_start(state, TRUE);
}

static void
live_clear_clicked(GtkButton *b, gpointer user_data)
{
    AppState *state = user_data;
    (void) b;
    if (state->live_msgs != NULL) g_ptr_array_set_size(state->live_msgs, 0);
    if (state->live_store != NULL)
        g_list_store_remove_all(G_LIST_STORE(state->live_store));
    state->live_count = 0;
    state->live_rate = 0;
    state->live_rate_prev = 0;
    state->live_last_us = 0;
    live_inspector_reset(state);
    live_update_summary(state);
    live_set_status(state, state->live_socket ? "listening on udp/4729"
                                              : "stopped",
                    state->live_socket ? "status-running" : "status-idle");
}

static void
live_follow_toggled(GtkToggleButton *b, gpointer user_data)
{
    AppState *state = user_data;
    state->live_follow = gtk_toggle_button_get_active(b);
    /* Turning Follow back on should catch up immediately, not wait for the
       next datagram to arrive. */
    if (state->live_follow && state->live_follow_idle == 0)
        state->live_follow_idle = g_idle_add(live_follow_idle, state);
}

/* Scroll to the newest row, after the model change has been fully processed.

   This used to run straight from the items-changed handler. Setting the
   adjustment there scrolls the column view from inside its own model
   notification, which re-enters the list item manager while it is still
   placing the row that was just appended. Under a busy feed that ends in
   GTK's "gtk_list_item_manager_ensure_items: code should not be reached"
   assertion and an abort. An idle hop costs nothing visible and cannot
   re-enter. */
static gboolean
live_follow_idle(gpointer user_data)
{
    AppState *state = user_data;
    GtkAdjustment *adj;

    state->live_follow_idle = 0;
    if (!state->live_follow || state->live_scroll == NULL) return G_SOURCE_REMOVE;

    adj = gtk_scrolled_window_get_vadjustment(
        GTK_SCROLLED_WINDOW(state->live_scroll));
    if (adj != NULL)
        gtk_adjustment_set_value(adj,
            gtk_adjustment_get_upper(adj) - gtk_adjustment_get_page_size(adj));
    return G_SOURCE_REMOVE;
}

/* Keep the newest row in view while Follow is on. One pending scroll is
   enough however many rows arrive in a burst. */
static void
live_items_changed(GListModel *model, guint pos, guint removed, guint added,
                   gpointer user_data)
{
    AppState *state = user_data;
    (void) model; (void) pos; (void) removed; (void) added;

    if (!state->live_follow || state->live_scroll == NULL) return;
    if (state->live_follow_idle != 0) return;
    state->live_follow_idle = g_idle_add(live_follow_idle, state);
}

static void
live_pause_clicked(GtkButton *button, gpointer user_data)
{
    AppState *state = user_data;
    state->live_paused = !state->live_paused;
    gtk_button_set_label(button, state->live_paused ? "Resume" : "Pause");
    live_update_summary(state);
    live_set_status(state, state->live_paused ? "feed paused" : "listening on udp/4729",
                    state->live_paused ? "status-idle" : "status-running");
}

static void
live_selection_changed(GObject *selection, GParamSpec *pspec, gpointer user_data)
{
    AppState *state = user_data;
    guint pos = gtk_single_selection_get_selected(GTK_SINGLE_SELECTION(selection));
    if (state->live_inspector_buf == NULL) return;
    if (pos == GTK_INVALID_LIST_POSITION) {
        gtk_text_buffer_set_text(state->live_inspector_buf,
            "Select a row to inspect its fields and its payload.", -1);
        return;
    }
    LiveMsg *m = g_list_model_get_item(G_LIST_MODEL(selection), pos);
    if (m == NULL) return;
    {
        /* The column abbreviates; this does not. The one thing it must say
           out loud is when the message was longer than what is held here -
           a silently shortened payload is a lie about the capture. */
        const char *hex = m->payload != NULL ? m->payload : "";
        gsize have = strlen(hex) / 2;
        g_autofree char *payload = NULL;

        if (have * 2 < (gsize) m->len) {
            payload = g_strdup_printf(
                "%s\n\n[%u of %u bytes held - the rest is in the capture]",
                hex, (guint) have, m->len);
        } else {
            payload = g_strdup(hex);
        }
        g_autofree char *detail = g_strdup_printf(
            "PACKET %u\n\nTime      %s\nType      %s\nChannel   %s\nARFCN     %u\nTimeslot  %u\nSignal    %d dBm\nDirection %s\nLength    %u bytes\nPayload   %u bytes\n\nPAYLOAD\n%s",
            m->seq, m->time, m->type, m->ch, m->arfcn, m->ts, m->sig, m->dir,
            m->len, (guint) have, payload);
        gtk_text_buffer_set_text(state->live_inspector_buf, detail, -1);
    }
    g_object_unref(m);
    (void) pspec;
}

static void
live_filter_changed(GtkEditable *e, gpointer user_data)
{
    AppState *state = user_data;
    g_free(state->live_filter);
    state->live_filter = g_strdup(gtk_editable_get_text(e));
    live_refilter(state);
    /* The chip reports "shown of total", so it has to follow the filter
       rather than wait for the next rate tick. */
    live_update_summary(state);
}

static void
live_filter_cleared(GtkButton *b, gpointer user_data)
{
    AppState *state = user_data;
    (void) b;
    if (state->live_filter_entry != NULL)
        gtk_editable_set_text(GTK_EDITABLE(state->live_filter_entry), "");
}

/* ── the decoded-field filters, the port and the capture ─────────────────
   wifisting reads its traffic out of tshark, so its filter row is MAC, SSID
   and a signal floor. A GSMTAP feed has none of those fields, but it has the
   ones that matter more: which direction the frame went, which cell it came
   from, which logical channel carried it, and how strong it was. The
   free-text filter above stays as the escape hatch for everything else. */
static const guint8 live_channel_codes[] = {
    0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x00
};
static const char *const live_channel_labels[] = {
    "any channel", "BCCH", "CCCH", "RACH", "AGCH", "PCH", "SDCCH", "SDCCH4",
    "SDCCH8", "TCH/F", "TCH/H", "PACCH", "unknown", NULL
};

static void
live_filters_changed(AppState *state)
{
    live_refilter(state);
    /* The chip says "shown of total", so it has to follow the filters rather
       than wait for the next rate tick. */
    live_update_summary(state);
}

static void
live_dir_toggled(GtkToggleButton *btn, gpointer user_data)
{
    AppState *state = user_data;
    (void) btn;
    if (state->live_ul_toggle == NULL || state->live_dl_toggle == NULL) return;
    state->live_show_ul = gtk_toggle_button_get_active(
        GTK_TOGGLE_BUTTON(state->live_ul_toggle));
    state->live_show_dl = gtk_toggle_button_get_active(
        GTK_TOGGLE_BUTTON(state->live_dl_toggle));
    live_filters_changed(state);
}

static void
live_dbm_changed(GtkSpinButton *spin, gpointer user_data)
{
    AppState *state = user_data;
    state->live_min_dbm = (gint) gtk_spin_button_get_value(spin);
    live_filters_changed(state);
}

static void
live_arfcn_changed(GtkEditable *e, gpointer user_data)
{
    AppState *state = user_data;
    const char *t = gtk_editable_get_text(e);

    /* Typing is not a parse: an empty box means "any", digits mean that cell,
       and anything else is ignored until it becomes a number rather than
       emptying the feed on every keystroke. */
    g_strstrip((char *) t);
    state->live_filter_arfcn = (*t != '\0' && g_ascii_isdigit(*t))
        ? (gint) g_ascii_strtoull(t, NULL, 10) : -1;
    live_filters_changed(state);
}

static void
live_channel_changed(GObject *drop, GParamSpec *pspec, gpointer user_data)
{
    AppState *state = user_data;
    guint sel = gtk_drop_down_get_selected(GTK_DROP_DOWN(drop));
    guint8 code = (sel < G_N_ELEMENTS(live_channel_codes))
        ? live_channel_codes[sel] : 0xff;

    state->live_filter_channel = (code == 0xff) ? -1 : (gint) code;
    live_filters_changed(state);
    (void) pspec;
}

static void
live_port_label_update(AppState *state)
{
    if (state->live_port_label == NULL) return;
    g_autofree char *t = g_strdup_printf(
        "GSMTAP on udp/%u — the feed gr-gsm, srsRAN and Open5GS all emit.",
        state->live_port);
    gtk_label_set_text(GTK_LABEL(state->live_port_label), t);
}

static void
live_port_changed(GtkEditable *e, gpointer user_data)
{
    AppState *state = user_data;
    const char *t = gtk_editable_get_text(e);
    gulong v;

    if (t == NULL || !g_ascii_isdigit(*t)) return;
    v = g_ascii_strtoull(t, NULL, 10);
    if (v < 1 || v > 65535) return;
    /* The label follows what is typed; the socket only moves on a restart,
       which is what the tooltip promises. */
    state->live_port = (guint) v;
    live_port_label_update(state);
}

/* The checkbox and the path entry together decide one thing: whether the next
   datagram is written. Opening happens on the first packet's behalf, so the
   file appears when there is something in it. */
static void
live_save_toggled(GtkToggleButton *btn, gpointer user_data)
{
    AppState *state = user_data;
    /* GtkCheckButton is not a GtkToggleButton in GTK4 - they are siblings -
       so the checked state has to be asked of the check button itself. */
    if (!gtk_check_button_get_active(GTK_CHECK_BUTTON(btn))) {
        if (state->live_pcap != NULL) {
            g_autofree char *name = g_path_get_basename(state->live_pcap_path);
            guint64 frames = state->live_pcap_packets;
            live_pcap_close(state);
            live_capture_label_update(state);
            if (frames > 0) {
                g_autofree char *m = g_strdup_printf(
                    "%s closed — %" G_GUINT64_FORMAT " frames", name, frames);
                show_toast_full(state, "Live Traffic", m, "ok");
            }
        } else {
            live_capture_label_update(state);
        }
        return;
    }

    /* Turning it on mid-run captures from here; turning it on before the run
       is the normal case and the listener opens the file when it starts. */
    if (state->live_socket != NULL)
        live_capture_begin(state, TRUE);
    else
        gtk_label_set_text(GTK_LABEL(state->live_capture_label),
                           "starts with the listener");
}

static void
live_rotate_changed(GtkSpinButton *spin, gpointer user_data)
{
    AppState *state = user_data;
    state->live_pcap_rotate_s = (guint) gtk_spin_button_get_value(spin);
    if (state->live_pcap_rotate_id != 0) {
        g_source_remove(state->live_pcap_rotate_id);
        state->live_pcap_rotate_id = 0;
    }
    if (state->live_pcap != NULL && state->live_pcap_rotate_s > 0)
        state->live_pcap_rotate_id = g_timeout_add_seconds(
            state->live_pcap_rotate_s, live_pcap_rotate_cb, state);
}

/* Opening the capture is one decision made from two widgets, so it lives in
   one place rather than in whichever callback fired first. */
static void
live_capture_begin(AppState *state, gboolean announce)
{
    const char *typed = state->live_path_entry != NULL
        ? gtk_editable_get_text(GTK_EDITABLE(state->live_path_entry)) : "";
    g_autofree char *path = NULL;

    if (typed != NULL && *typed != '\0') {
        path = g_path_is_absolute(typed)
            ? g_strdup(typed)
            : g_build_filename(IMSISTING_ROOT, typed, NULL);
    } else {
        path = live_pcap_default_path();
        if (state->live_path_entry != NULL) {
            gtk_editable_set_text(GTK_EDITABLE(state->live_path_entry), path);
            /* The name at the end is the part that identifies the file, so
               the box shows the end of the path rather than its prefix. */
            gtk_editable_set_position(GTK_EDITABLE(state->live_path_entry), -1);
        }
    }

    if (!live_pcap_open(state, path, announce)) return;

    if (state->live_pcap_rotate_s > 0 && state->live_pcap_rotate_id == 0)
        state->live_pcap_rotate_id = g_timeout_add_seconds(
            state->live_pcap_rotate_s, live_pcap_rotate_cb, state);
    if (announce) {
        g_autofree char *base = g_path_get_basename(path);
        g_autofree char *m = g_strdup_printf("capturing to %s", base);
        show_toast_full(state, "Live Traffic", m, "ok");
    }
}

/* ── what a row can do ───────────────────────────────────────────────────
   The feed is a list of cells you might want to act on, so the actions are
   the ones that turn a row into something else: into the target, into a
   filter, into a tuned radio, into the clipboard. */
static const char *
live_rat_from_type(guint8 t)
{
    switch (t) {
    case 0x01: case 0x02: case 0x08: return "GSM";
    case 0x03: return "UMTS";
    case 0x04: case 0x05: case 0x0a: case 0x0c: return "LTE";
    case 0x06: case 0x07: case 0x0b: return "NR";
    default: return NULL;
    }
}

static const char *
live_conv_rat(guint8 t)
{
    const char *rat = live_rat_from_type(t);
    if (rat == NULL) return NULL;
    if (g_strcmp0(rat, "GSM") == 0)  return "gsm";
    if (g_strcmp0(rat, "LTE") == 0)  return "lte";
    if (g_strcmp0(rat, "NR") == 0)   return "nr";
    return NULL;   /* UMTS ARFCNs are not in the conversion table */
}

/* The frequency a receiver would have to sit on for this row, asked of the
   module that owns the table rather than kept as a second copy here. NULL
   when the ARFCN is outside the table: better no menu item than a tune to a
   frequency nobody computed. */
static char *
live_row_freq(AppState *state, LiveMsg *m)
{
    g_autofree char *script = module_script_path("02_cell_recon");
    g_autofree char *out = NULL;
    g_autofree char *n = NULL;
    const char *rat = live_conv_rat(m->raw_type);
    const char *argv[8];
    int i = 0;

    if (rat == NULL || script == NULL) return NULL;

    n = g_strdup_printf("%u", m->arfcn);
    argv[i++] = script;
    argv[i++] = "--arfcn";
    argv[i++] = rat;
    argv[i++] = n;
    if (g_strcmp0(rat, "gsm") == 0) {
        const char *hint = settings_get("radio.arfcn_hint", "none");
        argv[i++] = m->up ? "ul" : "dl";
        /* The frame's own PCS flag is the better evidence when it is set; the
           setting is what to assume when it is not, and "none" leaves the
           ambiguity in place rather than guessing a band. */
        if (m->pcs)
            argv[i++] = "pcs";
        else if (g_strcmp0(hint, "none") != 0)
            argv[i++] = hint;
    }
    argv[i] = NULL;

    out = run_capture(argv);
    if (out == NULL || g_strstr_len(out, -1, "ERROR") != NULL) return NULL;

    g_auto(GStrv) lines = g_strsplit(out, "\n", -1);
    for (guint k = 0; lines[k] != NULL; k++) {
        g_auto(GStrv) kv = g_strsplit(lines[k], "\t", 2);
        if (g_strv_length(kv) == 2 && g_strcmp0(kv[0], "freq_mhz") == 0)
            return g_strdup(kv[1]);
    }
    (void) state;
    return NULL;
}

static void
live_tune_to(AppState *state, const char *mhz)
{
    /* One process, built the way every other verb button builds one, so the
       run lands in the output card and the event log like any other. */
    GtkWidget *b = gtk_button_new();

    g_object_set_data(G_OBJECT(b), "state", state);
    g_object_set_data(G_OBJECT(b), "module-id", (gpointer) "01_radio");
    g_object_set_data(G_OBJECT(b), "verb", (gpointer) "--set-freq");
    g_object_set_data_full(G_OBJECT(b), "args", g_strdup(mhz), g_free);
    g_object_set_data(G_OBJECT(b), "status", state->live_status);
    group_verb_clicked(GTK_BUTTON(b), NULL);
    g_object_unref(b);
}

static void
live_copy_text(AppState *state, GtkWidget *anchor, const char *text,
               const char *what)
{
    gdk_clipboard_set_text(gtk_widget_get_clipboard(anchor), text);
    g_autofree char *m = g_strdup_printf("%s copied", what);
    show_toast_full(state, "Live Traffic", m, "ok");
}

static void
live_menu_copy_payload(GtkButton *b, gpointer user_data)
{
    (void) user_data;
    AppState *state = g_object_get_data(G_OBJECT(b), "state");
    LiveMsg *m = g_object_get_data(G_OBJECT(b), "msg");
    live_copy_text(state, GTK_WIDGET(b), m->payload != NULL ? m->payload : "",
                   "payload");
}

static void
live_menu_copy_arfcn(GtkButton *b, gpointer user_data)
{
    (void) user_data;
    AppState *state = g_object_get_data(G_OBJECT(b), "state");
    LiveMsg *m = g_object_get_data(G_OBJECT(b), "msg");
    g_autofree char *t = g_strdup_printf("%u", m->arfcn);
    live_copy_text(state, GTK_WIDGET(b), t, "ARFCN");
}

static void
live_menu_copy_row(GtkButton *b, gpointer user_data)
{
    (void) user_data;
    AppState *state = g_object_get_data(G_OBJECT(b), "state");
    LiveMsg *m = g_object_get_data(G_OBJECT(b), "msg");
    g_autofree char *t = g_strdup_printf(
        "%u\t%s\t%s\t%s\t%u\t%u\t%d\t%s\t%u\t%s",
        m->seq, m->time, m->type, m->ch, m->arfcn, m->ts, m->sig, m->dir,
        m->len, m->payload != NULL ? m->payload : "");
    live_copy_text(state, GTK_WIDGET(b), t, "row");
}

static void
live_menu_filter_arfcn(GtkButton *b, gpointer user_data)
{
    (void) user_data;
    AppState *state = g_object_get_data(G_OBJECT(b), "state");
    LiveMsg *m = g_object_get_data(G_OBJECT(b), "msg");
    g_autofree char *t = g_strdup_printf("%u", m->arfcn);

    if (state->live_arfcn_entry != NULL)
        gtk_editable_set_text(GTK_EDITABLE(state->live_arfcn_entry), t);
}

static void
live_menu_set_target(GtkButton *b, gpointer user_data)
{
    (void) user_data;
    AppState *state = g_object_get_data(G_OBJECT(b), "state");
    LiveMsg *m = g_object_get_data(G_OBJECT(b), "msg");
    const char *rat = live_rat_from_type(m->raw_type);
    g_autofree char *t = g_strdup_printf("%u", m->arfcn);

    if (rat == NULL) {
        show_toast_full(state, "Live Traffic",
                        "this message type does not name a RAT", "error");
        return;
    }
    if (state->rtarget_rat != NULL)
        gtk_editable_set_text(GTK_EDITABLE(state->rtarget_rat), rat);
    if (state->rtarget_arfcn != NULL)
        gtk_editable_set_text(GTK_EDITABLE(state->rtarget_arfcn), t);
    /* Through the panel's own Apply, so the validation and the state files
       are the same ones a typed target gets. */
    rtarget_apply(state);
}

static void
live_menu_tune(GtkButton *b, gpointer user_data)
{
    (void) user_data;
    AppState *state = g_object_get_data(G_OBJECT(b), "state");
    const char *mhz = g_object_get_data(G_OBJECT(b), "mhz");
    live_tune_to(state, mhz);
}

/* A pick returns the row, not the cell under the pointer: the cells are
   children of the row and none of them is targetable. Every cell of a row
   carries the same message, so descending to whichever one holds it answers
   the same question the pointer asked. */
static gpointer
live_find_msg(GtkWidget *w)
{
    gpointer it;

    if (w == NULL) return NULL;
    it = g_object_get_data(G_OBJECT(w), "live-msg");
    if (it != NULL) return it;
    for (GtkWidget *c = gtk_widget_get_first_child(w); c != NULL;
         c = gtk_widget_get_next_sibling(c)) {
        gpointer r = live_find_msg(c);
        if (r != NULL) return r;
    }
    return NULL;
}

static void
live_row_menu_pressed(GtkGestureClick *gesture, int n_press,
                      double x, double y, gpointer user_data)
{
    AppState *state = user_data;
    LiveMsg *m = NULL;
    GtkWidget *pop, *box;
    GtkWidget *item;
    g_autofree char *mhz = NULL;

    (void) n_press;
    /* The pick cannot land on a cell's label - labels do not take pointer
       events - so it lands on the row widget, and the row knows its own item.
       That item is the message the row is showing. */
    {
        GtkWidget *w = gtk_widget_pick(state->live_view, x, y, GTK_PICK_DEFAULT);
        for (; w != NULL; w = gtk_widget_get_parent(w)) {
            gpointer it = live_find_msg(w);
            if (it != NULL) { m = g_object_ref(it); break; }
        }
    }
    /* A right-click that lands on the header or on empty space below the rows
       has no message behind it, and the menu is about a message. */
    if (m == NULL) return;
    pop = gtk_popover_new();
    box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    gtk_widget_add_css_class(box, "live-menu");

#define LIVE_MENU_ITEM(label, cb)                                            \
    do {                                                                     \
        item = gtk_button_new_with_label(label);                             \
        gtk_widget_add_css_class(item, "flat");                              \
        gtk_widget_add_css_class(item, "live-menu-item");                    \
        g_object_set_data(G_OBJECT(item), "state", state);                   \
        g_object_set_data(G_OBJECT(item), "msg", m);                         \
        g_signal_connect(item, "clicked", G_CALLBACK(cb), NULL);             \
        gtk_box_append(GTK_BOX(box), item);                                  \
    } while (0)

    g_autofree char *tune_label = NULL;
    mhz = live_row_freq(state, m);
    if (mhz != NULL) {
        g_autofree char *rat = g_strdup(live_rat_from_type(m->raw_type));
        tune_label = g_strdup_printf("Tune the SDR to %s MHz (%s %s)", mhz,
                                     rat != NULL ? rat : "",
                                     m->up ? "uplink" : "downlink");
    }

    LIVE_MENU_ITEM("Copy payload", live_menu_copy_payload);
    LIVE_MENU_ITEM("Copy ARFCN", live_menu_copy_arfcn);
    LIVE_MENU_ITEM("Copy row", live_menu_copy_row);
    LIVE_MENU_ITEM("Filter to this ARFCN", live_menu_filter_arfcn);
    LIVE_MENU_ITEM(g_strdup_printf("Set %u as the target", m->arfcn),
                   live_menu_set_target);
    if (tune_label != NULL) {
        item = gtk_button_new_with_label(tune_label);
        gtk_widget_add_css_class(item, "flat");
        gtk_widget_add_css_class(item, "live-menu-item");
        g_object_set_data(G_OBJECT(item), "state", state);
        g_object_set_data(G_OBJECT(item), "mhz", g_strdup(mhz));
        g_signal_connect_data(item, "clicked", G_CALLBACK(live_menu_tune),
                              NULL, NULL, 0);
        gtk_box_append(GTK_BOX(box), item);
    }
#undef LIVE_MENU_ITEM

    g_signal_connect_swapped(pop, "closed", G_CALLBACK(g_object_unref), m);
    gtk_popover_set_child(GTK_POPOVER(pop), box);
    gtk_popover_set_has_arrow(GTK_POPOVER(pop), FALSE);
    gtk_widget_set_parent(pop, state->live_view);
    /* The popover is rebuilt per click, so it is unparented with the click
       rather than kept in the page. */
    g_signal_connect_swapped(pop, "closed", G_CALLBACK(gtk_widget_unparent), pop);
    {
        GdkRectangle r = { (int) x, (int) y, 1, 1 };
        gtk_popover_set_pointing_to(GTK_POPOVER(pop), &r);
    }
    gtk_popover_popup(GTK_POPOVER(pop));
    (void) gesture;
}

/* The packet inspector used to be a permanent right-hand pane, so the live
   feed - the only thing this page exists for - was 320px narrower than the
   window at all times, and every payload column paid for a panel that sits
   empty until a row is selected. It is now a popover over the table, opened
   from "Inspect" in the toolbar and closed on Escape or a click outside. */
static void
live_inspector_toggled(GtkToggleButton *btn, gpointer user_data)
{
    GtkWidget *popover = user_data;

    if (gtk_toggle_button_get_active(btn))
        gtk_popover_popup(GTK_POPOVER(popover));
    else
        gtk_popover_popdown(GTK_POPOVER(popover));
}

/* Closing the popover has to release the button, or the next press toggles it
   OFF and pops nothing up - the control would look dead every second click.
   Setting the state re-enters the handler above, which calls popdown() on an
   already-closed popover; that is a no-op, and cheaper than a guard flag. */
static void
live_inspector_closed(GtkPopover *popover, gpointer user_data)
{
    GtkToggleButton *btn = user_data;
    (void) popover;
    gtk_toggle_button_set_active(btn, FALSE);
}

static GtkWidget *
create_live_traffic_page(AppState *state)
{
    GtkWidget *outer  = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *head   = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *box    = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *title  = gtk_label_new("Live Traffic");
    GtkWidget *sub    = gtk_label_new(
        "GSMTAP on udp/4729 — the feed gr-gsm, srsRAN and Open5GS all emit.");
    GtkWidget *status = gtk_label_new("stopped");
    GtkWidget *start  = gtk_button_new_with_label("Start");
    GtkWidget *clear  = gtk_button_new_with_label("Clear");
    GtkWidget *pause  = gtk_button_new_with_label("Pause");
    GtkWidget *follow = gtk_toggle_button_new_with_label("Follow");
    GtkWidget *inspector_btn  = gtk_toggle_button_new_with_label("Inspect");
    GtkWidget *inspector_pop  = gtk_popover_new();
    GtkWidget *inspector_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GtkWidget *inspector_title = gtk_label_new("PACKET INSPECTOR");
    GtkWidget *inspector = gtk_text_view_new();
    GtkWidget *bar    = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *flabel = gtk_label_new("Filter");
    GtkWidget *fentry = gtk_entry_new();
    GtkWidget *fclear = gtk_button_new_with_label("Reset");
    GtkWidget *bar2   = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *ulbtn  = gtk_toggle_button_new_with_label("UL");
    GtkWidget *dlbtn  = gtk_toggle_button_new_with_label("DL");
    GtkWidget *dlabel = gtk_label_new("min dBm");
    GtkWidget *dspin  = gtk_spin_button_new_with_range(-120, 0, 1);
    GtkWidget *alabel = gtk_label_new("ARFCN");
    GtkWidget *aentry = gtk_entry_new();
    GtkWidget *chlabel = gtk_label_new("Channel");
    GtkWidget *chdrop = gtk_drop_down_new_from_strings(live_channel_labels);
    GtkWidget *bar3   = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *plabel = gtk_label_new("Listen udp");
    GtkWidget *portentry = gtk_entry_new();
    GtkWidget *savecheck = gtk_check_button_new_with_label("Save pcap");
    gtk_check_button_set_active(GTK_CHECK_BUTTON(savecheck),
                                settings_flag("live.autosave", FALSE));
    GtkWidget *cappath = gtk_entry_new();
    GtkWidget *rotlabel = gtk_label_new("rotate every");
    GtkWidget *rotspin = gtk_spin_button_new_with_range(0, 3600, 30);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(rotspin),
        settings_int("live.rotate_s", 0, 0, 86400));
    GtkWidget *rotunit = gtk_label_new("s");
    GtkWidget *caplabel = gtk_label_new("not saving");
    GtkWidget *scroll = gtk_scrolled_window_new();
    GtkWidget *view   = gtk_column_view_new(NULL);
    GtkWidget *summary = gtk_label_new("0 msg");
    GtkWidget *overlay = gtk_overlay_new();
    GtkWidget *empty   = empty_state("network-receive-symbolic",
        "No traffic yet",
        "./modules/05_field_kit.sh --emit  ·  or start grgsm_livemon");

    gtk_widget_add_css_class(title,  "page-title");
    gtk_widget_add_css_class(sub,    "page-subtitle");
    gtk_widget_add_css_class(status, "status-pill");
    gtk_widget_add_css_class(status, "status-idle");
    gtk_widget_add_css_class(start,  "verb-button");
    gtk_widget_add_css_class(clear,  "verb-button");
    gtk_widget_add_css_class(flabel, "dim");
    gtk_widget_add_css_class(summary, "live-summary");
    gtk_widget_add_css_class(pause,  "verb-button");
    gtk_widget_add_css_class(follow, "verb-button");
    gtk_widget_add_css_class(inspector_box, "live-inspector");
    gtk_widget_add_css_class(inspector_btn, "verb-button");
    gtk_widget_set_tooltip_text(inspector_btn,
        "every field of the selected packet, and its whole payload");
    /* Fixed, because a popover sizes to its content and the text view's
       natural width is the longest decoded line - without this the panel
       grows a horizontal scrollbar and covers the feed it is describing. */
    gtk_widget_set_size_request(inspector_box, 340, 280);
    gtk_widget_add_css_class(inspector_title, "live-inspector-title");
    gtk_widget_add_css_class(view,   "live-table");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(sub),   0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(sub), PANGO_ELLIPSIZE_END);
    gtk_label_set_ellipsize(GTK_LABEL(status), PANGO_ELLIPSIZE_END);
    gtk_label_set_max_width_chars(GTK_LABEL(status), 26);
    gtk_widget_set_hexpand(box, TRUE);

    /* ---- title row ---- */
    gtk_box_append(GTK_BOX(box), title);
    gtk_box_append(GTK_BOX(box), sub);
    gtk_box_append(GTK_BOX(head), box);
    gtk_box_append(GTK_BOX(head), summary);
    gtk_box_append(GTK_BOX(head), status);
    gtk_box_append(GTK_BOX(head), start);
    gtk_box_append(GTK_BOX(head), clear);
    gtk_widget_set_margin_top(head, 12);
    gtk_widget_set_margin_bottom(head, 8);
    gtk_widget_set_margin_start(head, 16);
    gtk_widget_set_margin_end(head, 16);
    gtk_box_append(GTK_BOX(outer), head);
    gtk_box_append(GTK_BOX(head), pause);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(follow), TRUE);
    gtk_widget_set_tooltip_text(follow, "keep the newest packet in view");
    gtk_box_append(GTK_BOX(head), follow);
    gtk_box_append(GTK_BOX(head), inspector_btn);
    g_signal_connect(follow, "toggled", G_CALLBACK(live_follow_toggled), state);

    /* ---- toolbar ---- */
    gtk_entry_set_placeholder_text(GTK_ENTRY(fentry),
        "type, channel or payload substring");
    gtk_widget_set_hexpand(fentry, TRUE);
    gtk_box_append(GTK_BOX(bar), flabel);
    gtk_box_append(GTK_BOX(bar), fentry);
    gtk_box_append(GTK_BOX(bar), fclear);
    gtk_widget_set_margin_start(bar, 16);
    gtk_widget_set_margin_end(bar, 16);
    gtk_widget_set_margin_bottom(bar, 6);
    gtk_box_append(GTK_BOX(outer), bar);

    /* The decoded-field row. A GSMTAP feed is read by direction and by cell,
       and neither of those is a substring of anything on screen. */
    gtk_widget_add_css_class(ulbtn, "verb-button");
    gtk_widget_add_css_class(dlbtn, "verb-button");
    gtk_widget_add_css_class(dlabel, "dim");
    gtk_widget_add_css_class(alabel, "dim");
    gtk_widget_add_css_class(chlabel, "dim");
    gtk_widget_set_tooltip_text(ulbtn, "show what the phone sends (uplink)");
    gtk_widget_set_tooltip_text(dlbtn, "show what the network sends (downlink)");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(ulbtn), TRUE);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(dlbtn), TRUE);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(dspin), 0);
    gtk_widget_set_tooltip_text(dspin,
        "hide frames weaker than this — 0 means off, and a frame whose signal "
        "the emitter did not report is never hidden");
    gtk_widget_set_size_request(dspin, 78, -1);
    gtk_entry_set_placeholder_text(GTK_ENTRY(aentry), "any");
    gtk_widget_set_size_request(aentry, 80, -1);
    gtk_widget_set_tooltip_text(aentry, "show one ARFCN only");
    gtk_widget_set_tooltip_text(chdrop,
        "show one logical channel only — BCCH, CCCH, SDCCH, TCH and so on");
    gtk_box_append(GTK_BOX(bar2), ulbtn);
    gtk_box_append(GTK_BOX(bar2), dlbtn);
    gtk_box_append(GTK_BOX(bar2), dlabel);
    gtk_box_append(GTK_BOX(bar2), dspin);
    gtk_box_append(GTK_BOX(bar2), alabel);
    gtk_box_append(GTK_BOX(bar2), aentry);
    gtk_box_append(GTK_BOX(bar2), chlabel);
    gtk_box_append(GTK_BOX(bar2), chdrop);
    gtk_widget_set_margin_start(bar2, 16);
    gtk_widget_set_margin_end(bar2, 16);
    gtk_widget_set_margin_bottom(bar2, 6);
    gtk_box_append(GTK_BOX(outer), bar2);

    /* The listener's port and the capture. Both are settings for the run, not
       for the view, so they sit together and away from the filters. */
    gtk_widget_add_css_class(plabel, "dim");
    gtk_widget_add_css_class(rotlabel, "dim");
    gtk_widget_add_css_class(rotunit, "dim");
    gtk_widget_add_css_class(caplabel, "live-capture");
    gtk_widget_set_tooltip_text(portentry,
        "the UDP port the listener binds — applied when it starts");
    gtk_widget_set_size_request(portentry, 74, -1);
    gtk_widget_set_tooltip_text(savecheck,
        "write every datagram to a pcap as it arrives, filtered or not");
    gtk_entry_set_placeholder_text(GTK_ENTRY(cappath),
        "captures/live_<time>.pcap");
    gtk_widget_set_hexpand(cappath, TRUE);
    gtk_widget_set_tooltip_text(rotspin,
        "start a new file this often — 0 keeps one file for the whole run, "
        "and the newest twenty are kept");
    gtk_widget_set_size_request(rotspin, 80, -1);
    gtk_label_set_ellipsize(GTK_LABEL(caplabel), PANGO_ELLIPSIZE_MIDDLE);
    gtk_label_set_xalign(GTK_LABEL(caplabel), 0.0f);
    gtk_box_append(GTK_BOX(bar3), plabel);
    gtk_box_append(GTK_BOX(bar3), portentry);
    gtk_box_append(GTK_BOX(bar3), savecheck);
    gtk_box_append(GTK_BOX(bar3), cappath);
    gtk_box_append(GTK_BOX(bar3), rotlabel);
    gtk_box_append(GTK_BOX(bar3), rotspin);
    gtk_box_append(GTK_BOX(bar3), rotunit);
    gtk_box_append(GTK_BOX(bar3), caplabel);
    gtk_widget_set_margin_start(bar3, 16);
    gtk_widget_set_margin_end(bar3, 16);
    gtk_widget_set_margin_bottom(bar3, 8);
    gtk_box_append(GTK_BOX(outer), bar3);

    /* ---- table ---- */
    state->live_store = g_list_store_new(LIVE_TYPE_MSG);
    state->live_scroll = scroll;
    state->live_follow = TRUE;
    g_signal_connect(state->live_store, "items-changed",
                     G_CALLBACK(live_items_changed), state);
    GtkSingleSelection *selection = gtk_single_selection_new(
        G_LIST_MODEL(g_object_ref(state->live_store)));
    gtk_column_view_set_model(GTK_COLUMN_VIEW(view), GTK_SELECTION_MODEL(selection));
    g_signal_connect(selection, "notify::selected",
                     G_CALLBACK(live_selection_changed), state);
    gtk_column_view_set_show_row_separators(GTK_COLUMN_VIEW(view), TRUE);
    gtk_column_view_set_show_column_separators(GTK_COLUMN_VIEW(view), FALSE);

    for (int c = 0; c < 10; c++) {
        GtkListItemFactory *f = gtk_signal_list_item_factory_new();
        GtkColumnViewColumn *col;

        g_signal_connect(f, "setup", G_CALLBACK(live_col_setup), NULL);
        g_signal_connect(f, "bind", G_CALLBACK(live_col_bind),
                         GINT_TO_POINTER(c));
        col = gtk_column_view_column_new(live_col_title(c), f);
        gtk_column_view_column_set_resizable(col, TRUE);
        if (c == 9) gtk_column_view_column_set_expand(col, TRUE);
        gtk_column_view_append_column(GTK_COLUMN_VIEW(view), col);
        g_object_unref(col);
    }

    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), view);
    gtk_widget_set_vexpand(scroll, TRUE);
    gtk_overlay_set_child(GTK_OVERLAY(overlay), scroll);
    gtk_overlay_add_overlay(GTK_OVERLAY(overlay), empty);
    gtk_text_view_set_editable(GTK_TEXT_VIEW(inspector), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(inspector), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(inspector), TRUE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(inspector), GTK_WRAP_WORD_CHAR);
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(inspector)),
        "Select a row to inspect its decoded GSMTAP fields.", -1);
    /* A GtkTextView appended bare into a box reports its full wrapped content
       height as its minimum. This one propagated all the way up and pinned the
       toplevel's minimum height at 1322px, so the window could not fit a
       1000px-tall screen and a long payload could not scroll. Scrolling it
       keeps the minimum at the small default instead. */
    GtkWidget *inspector_scroll = gtk_scrolled_window_new();
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(inspector_scroll),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(inspector_scroll),
                                  inspector);
    gtk_widget_set_vexpand(inspector_scroll, TRUE);
    gtk_box_append(GTK_BOX(inspector_box), inspector_title);
    gtk_box_append(GTK_BOX(inspector_box), inspector_scroll);

    /* The inspector is a popover over the feed, not a sibling of it, so the
       table gets the full width of the page. It is parented to the button so
       GTK can anchor and destroy it with the toolbar. */
    gtk_popover_set_position(GTK_POPOVER(inspector_pop), GTK_POS_BOTTOM);
    gtk_popover_set_has_arrow(GTK_POPOVER(inspector_pop), TRUE);
    gtk_widget_set_parent(inspector_pop, inspector_btn);
    gtk_popover_set_child(GTK_POPOVER(inspector_pop), inspector_box);
    g_signal_connect(inspector_pop, "closed",
                     G_CALLBACK(live_inspector_closed), inspector_btn);
    g_signal_connect(inspector_btn, "toggled",
                     G_CALLBACK(live_inspector_toggled), inspector_pop);
    gtk_box_append(GTK_BOX(outer), overlay);

    state->live_view         = view;
    state->live_status       = status;
    state->live_button       = start;
    state->live_filter_entry = fentry;
    state->live_summary      = summary;
    state->live_empty        = empty;
    state->live_count        = 0;
    state->live_pause_button = pause;
    state->live_inspector_buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(inspector));
    state->live_paused       = FALSE;
    state->live_socket       = NULL;
    state->live_poll         = 0;
    state->live_hint         = 0;
    state->live_msgs         = NULL;
    state->live_filter       = NULL;
    state->live_rate         = 0;
    state->live_rate_prev    = 0;
    state->live_last_us      = 0;
    /* One tick a second drives the arrival rate and the quiet indicator. */
    state->live_rate_timer   = g_timeout_add_seconds(1, live_rate_tick, state);

    /* The listener's port, the capture, and the decoded-field filters. The
       stored values are what this page opens with; the controls below are how
       they are changed for this run, and a change made here is not written
       back - the settings window is the one place that owns the file. */
    state->live_port          = (guint) settings_int("live.port", LIVE_PORT,
                                                     1, 65535);
    state->live_port_entry    = portentry;
    {
        g_autofree char *pt = g_strdup_printf("%u", state->live_port);
        gtk_editable_set_text(GTK_EDITABLE(portentry), pt);
    }
    state->live_port_label    = sub;
    state->live_save_check    = savecheck;
    state->live_path_entry    = cappath;
    state->live_rotate_spin   = rotspin;
    state->live_capture_label = caplabel;
    state->live_ul_toggle     = ulbtn;
    state->live_dl_toggle     = dlbtn;
    state->live_dbm_spin      = dspin;
    state->live_arfcn_entry   = aentry;
    state->live_channel_drop  = chdrop;
    state->live_show_ul       = settings_flag("live.ul", TRUE);
    state->live_show_dl       = settings_flag("live.dl", TRUE);
    state->live_min_dbm       = (gint) settings_int("live.min_dbm", 0, -120, 0);
    state->live_filter_arfcn  = -1;
    state->live_filter_channel = -1;
    state->live_pcap          = NULL;
    state->live_pcap_path     = NULL;
    state->live_pcap_rotate_s = 0;
    state->live_pcap_rotate_id = 0;
    state->live_pcap_failed   = FALSE;
    {
        g_autofree char *port = g_strdup_printf("%u", state->live_port);
        gtk_editable_set_text(GTK_EDITABLE(portentry), port);
    }
    live_port_label_update(state);

    g_signal_connect(start,  "clicked", G_CALLBACK(live_toggle_clicked), state);
    g_signal_connect(clear,  "clicked", G_CALLBACK(live_clear_clicked), state);
    g_signal_connect(fentry, "changed", G_CALLBACK(live_filter_changed), state);
    g_signal_connect(pause,  "clicked", G_CALLBACK(live_pause_clicked), state);
    g_signal_connect(fclear, "clicked", G_CALLBACK(live_filter_cleared), state);
    g_signal_connect(ulbtn,  "toggled", G_CALLBACK(live_dir_toggled), state);
    g_signal_connect(dlbtn,  "toggled", G_CALLBACK(live_dir_toggled), state);
    g_signal_connect(dspin,  "value-changed", G_CALLBACK(live_dbm_changed), state);
    g_signal_connect(aentry, "changed", G_CALLBACK(live_arfcn_changed), state);
    g_signal_connect(chdrop, "notify::selected", G_CALLBACK(live_channel_changed), state);
    g_signal_connect(savecheck, "toggled", G_CALLBACK(live_save_toggled), state);
    g_signal_connect(rotspin, "value-changed", G_CALLBACK(live_rotate_changed), state);
    g_signal_connect(portentry, "changed", G_CALLBACK(live_port_changed), state);
    /* Right-click on a row: the actions that need the row's own values. */
    {
        GtkGesture *rc = gtk_gesture_click_new();
        gtk_gesture_single_set_button(GTK_GESTURE_SINGLE(rc), GDK_BUTTON_SECONDARY);
        /* On release, not on press: the popover would be dismissed by the
           very button release that opened it if it appeared while the button
           was still down. */
        g_signal_connect(rc, "released", G_CALLBACK(live_row_menu_pressed), state);
        gtk_widget_add_controller(view, GTK_EVENT_CONTROLLER(rc));
    }
    return outer;
}

/* ==================================================================== */
/*  THE MODULE DRAWER                                                   */
/* ==================================================================== */

/* The list slides out over the page instead of sitting beside it. Pushing
   the page aside was not just a layout choice, it was a cost: every toggle
   re-ran the dashboard's tile fit and re-wrapped every module page, and it
   made the list compete with the content for width instead of being called
   up when it is wanted. */
static void
drawer_set_open(AppState *state, gboolean open)
{
    if (state->sidebar_revealer == NULL) return;

    gtk_revealer_set_reveal_child(GTK_REVEALER(state->sidebar_revealer), open);

    /* Opening it is a request to find something, and where you already are
       is part of that. The caret is deliberately NOT moved: the drawer now
       opens on hover, and a hover that quietly took the keyboard would
       swallow the next keystroke into a search box the pointer only passed
       over. Clicking the entry is how you type in it. */
    if (open && state->drawer_nav != NULL) {
        int cur = gtk_notebook_get_current_page(GTK_NOTEBOOK(state->notebook));
        state->drawer_nav_syncing = TRUE;
        if (cur >= 0 && cur < 7 && state->drawer_nav_rows[cur] != NULL)
            gtk_list_box_select_row(GTK_LIST_BOX(state->drawer_nav),
                GTK_LIST_BOX_ROW(state->drawer_nav_rows[cur]));
        else
            gtk_list_box_unselect_all(GTK_LIST_BOX(state->drawer_nav));
        state->drawer_nav_syncing = FALSE;
    }
}

static gboolean
drawer_is_open(AppState *state)
{
    return state->sidebar_revealer != NULL &&
           gtk_revealer_get_reveal_child(GTK_REVEALER(state->sidebar_revealer));
}

/* The left edge of the page is the handle. There is no button in the
   titlebar any more: a hover target costs no header space, and the header
   is the scarcest strip in the window.

   There is no timer on the way in either. A delay would have to be a GLib
   timeout, and this process has been observed not to dispatch them, so the
   drawer opens on the motion event itself. Nothing needs debouncing:
   travelling from the edge to a row keeps the pointer inside the drawer
   the whole way, so the close fires only once the pointer is well clear. */
/* Measured from the window, not from the overlay: the card leaves a 22px
   gutter around the content, so an edge defined inside the overlay would sit
   a finger's width away from the edge of the screen and the pointer would
   have to be dragged through the margin before anything happened. */
#define DRAWER_EDGE   34.0
#define DRAWER_CLEAR (DRAWER_EDGE + 272.0 + 24.0)
static void
drawer_edge_motion(GtkEventControllerMotion *controller, double x, double y,
                   gpointer user_data)
{
    AppState *state = user_data;
    (void) controller;
    (void) y;

    /* Hover-to-open is the default; "click" waits for the press instead, which
       is steadier on a touchpad. The movement is still what is measured, so
       the two differ only in whether the drawer opens on arrival. */
    if (g_strcmp0(settings_get("ui.drawer", "hover"), "click") == 0)
        return;

    if (x <= DRAWER_EDGE) {
        if (!drawer_is_open(state)) drawer_set_open(state, TRUE);
    } else if (x > DRAWER_CLEAR) {
        if (drawer_is_open(state)) drawer_set_open(state, FALSE);
    }
}

/* The other half of the drawer's two behaviours: in "click" mode the
   movement does nothing and the press does the work. It is the same test of
   x, on the same controller's coordinates, so the two modes open the drawer
   at the same place. */
static void
drawer_edge_pressed(GtkGestureClick *gesture, int n_press, double x, double y,
                    gpointer user_data)
{
    AppState *state = user_data;
    (void) gesture;
    (void) n_press;
    (void) y;

    if (g_strcmp0(settings_get("ui.drawer", "hover"), "click") != 0) return;
    if (x <= DRAWER_EDGE) {
        drawer_set_open(state, TRUE);
    } else if (x > DRAWER_CLEAR) {
        drawer_set_open(state, FALSE);
    }
}

/* ── global radio target ────────────────────────────────────────────────
   wifisting keeps its target in the header, reachable from any page, and
   that is what the panel below is. IMSIsting had the state without a home:
   the cellular modules read $TMP_DIR/target_arfcn and target_plmn, nothing
   ever wrote them, and the only target fields sat inside Casebook where
   they describe a case rather than the radio. So the target was invisible
   and unsettable from anywhere else. */

static void
rtarget_fill_from_state(AppState *state, const char *rat, const char *arfcn,
                        const char *plmn)
{
    /* Only fills gaps: never overwrites something the operator has typed. */
    if (rat != NULL && *rat != '\0' &&
        *casebook_entry(state->rtarget_rat) == '\0')
        gtk_editable_set_text(GTK_EDITABLE(state->rtarget_rat), rat);
    if (arfcn != NULL && *arfcn != '\0' &&
        *casebook_entry(state->rtarget_arfcn) == '\0')
        gtk_editable_set_text(GTK_EDITABLE(state->rtarget_arfcn), arfcn);
    if (plmn != NULL && *plmn != '\0' &&
        *casebook_entry(state->rtarget_plmn) == '\0')
        gtk_editable_set_text(GTK_EDITABLE(state->rtarget_plmn), plmn);
}

static void
rtarget_refresh(AppState *state)
{
    const char *argv[3];
    g_autofree char *script = NULL;
    g_autofree char *out = NULL;
    g_autofree char *rat = NULL;
    g_autofree char *arfcn = NULL;
    g_autofree char *plmn = NULL;
    g_autofree char *text = NULL;

    if (state == NULL || state->rtarget_state_lbl == NULL) return;

    script = module_script_path("02_cell_recon");
    argv[0] = script;
    argv[1] = "--target-tsv";
    argv[2] = NULL;
    out = run_capture(argv);

    if (out != NULL) {
        g_auto(GStrv) lines = g_strsplit(out, "\n", -1);
        for (guint i = 0; lines[i] != NULL; i++) {
            g_auto(GStrv) kv = g_strsplit(lines[i], "\t", 2);
            if (g_strv_length(kv) != 2) continue;
            if (g_strcmp0(kv[0], "rat") == 0)        rat   = g_strdup(kv[1]);
            else if (g_strcmp0(kv[0], "arfcn") == 0) arfcn = g_strdup(kv[1]);
            else if (g_strcmp0(kv[0], "plmn") == 0)  plmn  = g_strdup(kv[1]);
        }
    }

    if (rat == NULL && arfcn == NULL && plmn == NULL) {
        gtk_label_set_text(GTK_LABEL(state->rtarget_state_lbl), "No target set");
        gtk_widget_remove_css_class(state->rtarget_state_lbl, "target-set");
        return;
    }

    text = g_strdup_printf("%s %s%s%s",
                           rat   != NULL ? rat   : "cell",
                           arfcn != NULL ? arfcn : "?",
                           plmn  != NULL ? "  ·  " : "",
                           plmn  != NULL ? plmn : "");
    gtk_label_set_text(GTK_LABEL(state->rtarget_state_lbl), text);
    gtk_widget_add_css_class(state->rtarget_state_lbl, "target-set");
    rtarget_fill_from_state(state, rat, arfcn, plmn);
}

/* Is a case open? Only then does Apply record the target into the case: a
   casebook target lives in a per-case targets.tsv, so there is nothing to
   write to otherwise and the call would fail noisily on every Apply. */
static gboolean
rtarget_case_active(AppState *state)
{
    const char *args[] = { "status", NULL };
    gboolean ok = FALSE;
    g_autofree char *cb = casebook_call(args, &ok);
    g_autofree char *act = ok ? tsv_field(cb, "active_case") : NULL;

    (void) state;
    return act != NULL && *act != '\0' && g_strcmp0(act, "none") != 0;
}

static void rtarget_clear(AppState *state);

static void
rtarget_apply(AppState *state)
{
    const char *rat   = casebook_entry(state->rtarget_rat);
    const char *arfcn = casebook_entry(state->rtarget_arfcn);
    const char *plmn  = casebook_entry(state->rtarget_plmn);
    const char *cell  = casebook_entry(state->rtarget_cell);
    const char *argv[6];
    g_autofree char *script = NULL;
    g_autofree char *out = NULL;

    if (state == NULL || state->rtarget_state_lbl == NULL) return;

    /* Empty arfcn with a RAT is a half-filled form, not a clear. Both empty
       means the operator wants the target gone. */
    if (*arfcn == '\0' && *rat == '\0' && *plmn == '\0') {
        rtarget_clear(state);
        return;
    }
    if (*rat == '\0' || *arfcn == '\0') {
        gtk_label_set_text(GTK_LABEL(state->rtarget_state_lbl),
                           "RAT and ARFCN are both required");
        gtk_widget_remove_css_class(state->rtarget_state_lbl, "target-set");
        return;
    }

    script = module_script_path("02_cell_recon");
    argv[0] = script;
    argv[1] = "--set-target";
    argv[2] = rat;
    argv[3] = arfcn;
    argv[4] = plmn;
    argv[5] = NULL;
    out = run_capture(argv);

    /* A rejected target (an ARFCN out of range, a RAT the converter does not
       know) must not be dressed up as success. */
    if (out != NULL && g_strstr_len(out, -1, "ERROR") != NULL) {
        g_autofree char *line = g_strdup(out);
        g_strstrip(line);
        gtk_label_set_text(GTK_LABEL(state->rtarget_state_lbl), line);
        gtk_widget_remove_css_class(state->rtarget_state_lbl, "target-set");
        append_event(state, line);
        return;
    }

    /* One place to set a target, so one place that records it. The case keeps
       the target it will be reported against; the files above are what the
       modules actually tune to. */
    if (rtarget_case_active(state)) {
        const char *cb_args[] = { "--target-set", rat, plmn, arfcn,
                                  (*cell != '\0') ? cell : "-", NULL };
        gboolean cb_ok = FALSE;
        g_autofree char *cb_out = casebook_call(cb_args, &cb_ok);
        if (cb_out != NULL && *cb_out != '\0') append_event(state, cb_out);
        casebook_refresh(state);
    }

    rtarget_refresh(state);
    append_event(state, "Radio target updated");
}

static void
rtarget_clear(AppState *state)
{
    const char *argv[6];
    g_autofree char *script = NULL;

    if (state == NULL) return;

    gtk_editable_set_text(GTK_EDITABLE(state->rtarget_rat), "");
    gtk_editable_set_text(GTK_EDITABLE(state->rtarget_arfcn), "");
    gtk_editable_set_text(GTK_EDITABLE(state->rtarget_plmn), "");
    gtk_editable_set_text(GTK_EDITABLE(state->rtarget_cell), "");

    /* Remove the stored target too, or the panel would say "no target" while
       every cellular module still read the old one. */
    script = module_script_path("02_cell_recon");
    argv[0] = script;
    argv[1] = "--set-target";
    argv[2] = "";
    argv[3] = "";
    argv[4] = "";
    argv[5] = NULL;
    run_capture(argv);

    /* Forget it in the case too, or the case would keep reporting a target
       the radio no longer has. */
    if (rtarget_case_active(state)) {
        const char *cb_args[] = { "--target-clear", NULL };
        gboolean cb_ok = FALSE;
        g_autofree char *cb_out = casebook_call(cb_args, &cb_ok);
        if (cb_out != NULL && *cb_out != '\0') append_event(state, cb_out);
        casebook_refresh(state);
    }

    if (state->rtarget_state_lbl != NULL) {
        gtk_label_set_text(GTK_LABEL(state->rtarget_state_lbl), "No target set");
        gtk_widget_remove_css_class(state->rtarget_state_lbl, "target-set");
    }
}

static void
rtarget_apply_clicked(GtkButton *button, gpointer user_data)
{
    (void) button;
    rtarget_apply((AppState *) user_data);
}

static void
rtarget_clear_clicked(GtkButton *button, gpointer user_data)
{
    (void) button;
    rtarget_clear((AppState *) user_data);
}

static void
rtarget_toggled(GtkToggleButton *button, gpointer user_data)
{
    AppState *state = user_data;
    gboolean on = gtk_toggle_button_get_active(button);

    if (state == NULL || state->rtarget_revealer == NULL) return;
    if (on) rtarget_refresh(state);
    gtk_revealer_set_reveal_child(GTK_REVEALER(state->rtarget_revealer), on);
}

/* ── What the target panel shows back ────────────────────────────────
   The panel is a read-out first and a form second, in three zones:

     Identity   a mark for the generation, the operator if it is known, a
                padlock for whether the cell's traffic is ciphered, and the
                fields that name the cell.
     Live       the signal the live feed is seeing, as a spark with bars.
     Context    how long the target has been held, when it was last seen,
                and the case counters.

   The four fields that SET a target are behind an expander: they are typed
   once and read past many times, and the three zones need the room.

   Every reading is taken from something that already exists - casebook's
   target row for identity, loot/cell_recon/cells.tsv for the operator, band
   and cipher, loot/gsmtap/decoded.tsv for the signal. A reading that is not
   there says so; none of them is invented and none is shown as a zero. */

static const char *
rtarget_rat_icon(const char *rat)
{
    if (rat == NULL || *rat == '\0') return "imsisting-02_cell_recon-symbolic";
    if (g_ascii_strcasecmp(rat, "GSM") == 0)  return "imsisting-06_gsm_air-symbolic";
    if (g_ascii_strcasecmp(rat, "UMTS") == 0) return "imsisting-08_umts_air-symbolic";
    if (g_ascii_strcasecmp(rat, "LTE") == 0)  return "imsisting-10_lte_air-symbolic";
    if (g_ascii_strcasecmp(rat, "NR") == 0 ||
        g_ascii_strcasecmp(rat, "5G") == 0)   return "imsisting-12_nr_air-symbolic";
    return "imsisting-02_cell_recon-symbolic";
}

/* The generation rather than the RAT: "2G" is what is read at a glance, and
   the RAT itself is spelled out next to it. */
static const char *
rtarget_rat_generation(const char *rat)
{
    if (rat == NULL || *rat == '\0') return "--";
    if (g_ascii_strcasecmp(rat, "GSM") == 0)  return "2G";
    if (g_ascii_strcasecmp(rat, "UMTS") == 0) return "3G";
    if (g_ascii_strcasecmp(rat, "LTE") == 0)  return "4G";
    if (g_ascii_strcasecmp(rat, "NR") == 0 ||
        g_ascii_strcasecmp(rat, "5G") == 0)   return "5G";
    return rat;
}

/* The generation's own colour, so the mark is readable before the word is. */
static const char *
rtarget_rat_class(const char *rat)
{
    if (rat == NULL || *rat == '\0') return "target-gen-none";
    if (g_ascii_strcasecmp(rat, "GSM") == 0)  return "target-gen-2g";
    if (g_ascii_strcasecmp(rat, "UMTS") == 0) return "target-gen-3g";
    if (g_ascii_strcasecmp(rat, "LTE") == 0)  return "target-gen-4g";
    if (g_ascii_strcasecmp(rat, "NR") == 0 ||
        g_ascii_strcasecmp(rat, "5G") == 0)   return "target-gen-5g";
    return "target-gen-none";
}

/* A zone: an eyebrow and a body. The eyebrow is what makes the panel read as
   three answers rather than a dozen loose fields. */
static GtkWidget *
rtarget_zone(const char *title, GtkWidget **body_out)
{
    GtkWidget *box  = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GtkWidget *head = gtk_label_new(title);
    GtkWidget *body = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);

    gtk_widget_add_css_class(box, "target-zone");
    gtk_widget_add_css_class(box, "card");
    gtk_widget_add_css_class(head, "target-zone-head");
    gtk_label_set_xalign(GTK_LABEL(head), 0.0f);
    gtk_box_append(GTK_BOX(box), head);
    gtk_box_append(GTK_BOX(box), body);
    if (body_out != NULL) *body_out = body;
    return box;
}

/* One key and one value. Returns the value label, which is the only thing
   refresh() has to touch. The key is a fixed width so a column of values
   lines up down the panel. */
static GtkWidget *
rtarget_kv(GtkWidget *body, const char *key)
{
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *k   = gtk_label_new(key);
    GtkWidget *v   = gtk_label_new("--");

    gtk_widget_add_css_class(row, "target-kv");
    gtk_widget_add_css_class(k, "target-kv-key");
    gtk_widget_add_css_class(v, "target-kv-val");
    gtk_widget_set_size_request(k, 66, -1);
    gtk_label_set_xalign(GTK_LABEL(k), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(v), 0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(v), PANGO_ELLIPSIZE_END);
    gtk_widget_set_hexpand(v, TRUE);
    gtk_box_append(GTK_BOX(row), k);
    gtk_box_append(GTK_BOX(row), v);
    gtk_box_append(GTK_BOX(body), row);
    return v;
}

/* A value the panel could not read says so, rather than showing -- at the
   operator as though the cell had no PLMN. */
static void
rtarget_put(GtkWidget *label, const char *value)
{
    /* "-" is Casebook's own word for a field it does not have, so it reads as
       absent here too rather than as a value that happens to be a dash. */
    gboolean there = value != NULL && *value != '\0' &&
                     g_strcmp0(value, "-") != 0;

    gtk_label_set_text(GTK_LABEL(label), there ? value : "--");
}

/* The spark. Split out of the panel so the drawing is one function that only
   ever looks at the samples refresh() left behind. */
static void
rtarget_spark_draw(GtkDrawingArea *area, cairo_t *cr,
                   int width, int height, gpointer user_data)
{
    AppState *state = user_data;
    int n = state->rtarget_spark_n;
    double lo, hi, span;

    (void) area;
    if (n < 1 || width < 2 || height < 2) return;

    lo = hi = state->rtarget_spark[0];
    for (int i = 1; i < n; i++) {
        if (state->rtarget_spark[i] < lo) lo = state->rtarget_spark[i];
        if (state->rtarget_spark[i] > hi) hi = state->rtarget_spark[i];
    }
    /* A flat trace is a real reading, not an empty one: give it a band so it
       draws down the middle instead of dividing by zero. 6 dB is about the
       smallest change a receiver reports meaningfully. */
    if (hi - lo < 6.0) {
        double mid = (hi + lo) / 2.0;

        lo = mid - 3.0;
        hi = mid + 3.0;
    }
    span = hi - lo;

    /* Two faint rules, so the trace has a scale to be read against. */
    cairo_set_line_width(cr, 1.0);
    cairo_set_source_rgba(cr, 0.25, 0.33, 0.46, 0.55);
    for (int i = 1; i < 3; i++) {
        double y = height * i / 3.0;

        cairo_move_to(cr, 0.0, y);
        cairo_line_to(cr, width, y);
    }
    cairo_stroke(cr);

    cairo_set_source_rgba(cr, 0.31, 0.80, 0.88, 1.0);
    if (n == 1) {
        /* A single reading is a level, and drawing it as a level is more
           honest than leaving the box empty. */
        double y = height - (state->rtarget_spark[0] - lo) / span * height;

        if (y < 0.0) y = 0.0;
        if (y > height) y = height;
        cairo_set_line_width(cr, 1.6);
        cairo_move_to(cr, 0.0, y);
        cairo_line_to(cr, width, y);
        cairo_stroke(cr);
        return;
    }
    cairo_set_line_width(cr, 1.6);
    cairo_set_line_join(cr, CAIRO_LINE_JOIN_ROUND);
    for (int i = 0; i < n; i++) {
        double x = width * (double) i / (double) (n - 1);
        double y = height - (state->rtarget_spark[i] - lo) / span * height;

        if (y < 0.0) y = 0.0;
        if (y > height) y = height;
        if (i == 0) cairo_move_to(cr, x, y);
        else        cairo_line_to(cr, x, y);
    }
    cairo_stroke(cr);
}

/* Ring -> straight, oldest first. */
static void
rtarget_spark_unwrap(AppState *state, const double *ring, int have)
{
    int n = have < RTARGET_SPARK ? have : RTARGET_SPARK;
    int start = have <= RTARGET_SPARK ? 0 : have % RTARGET_SPARK;

    for (int i = 0; i < n; i++)
        state->rtarget_spark[i] = ring[(start + i) % RTARGET_SPARK];
    state->rtarget_spark_n = n;
}

/* The readings the live feed took, newest last. The feed writes
   loot/gsmtap/decoded.tsv one row per frame with signal_dbm and the arfcn it
   arrived on. Rows for the target's own channel are preferred; when the
   target names no channel, or the feed has nothing on that one, every frame
   counts. Returns FALSE when there is no reading at all - which is said in
   words rather than drawn as a flat line at zero. */
static gboolean
rtarget_read_signal(AppState *state, const char *arfcn)
{
    g_autofree char *path = g_build_filename(IMSISTING_ROOT, "loot", "gsmtap",
                                             "decoded.tsv", NULL);
    g_autofree char *text = NULL;
    g_auto(GStrv) lines = NULL;
    double on_chan[RTARGET_SPARK], anywhere[RTARGET_SPARK];
    int n_chan = 0, n_any = 0;
    int sig_col = -1, arf_col = -1;
    gboolean want_chan;

    state->rtarget_spark_n = 0;
    if (!g_file_get_contents(path, &text, NULL, NULL)) return FALSE;
    lines = g_strsplit(text, "\n", -1);
    if (lines[0] == NULL) return FALSE;

    {
        g_auto(GStrv) cols = g_strsplit(lines[0], "\t", -1);

        for (int i = 0; cols[i] != NULL; i++) {
            if (g_strcmp0(cols[i], "signal_dbm") == 0) sig_col = i;
            else if (g_strcmp0(cols[i], "arfcn") == 0) arf_col = i;
        }
    }
    if (sig_col < 0) return FALSE;
    want_chan = arfcn != NULL && *arfcn != '\0' && arf_col >= 0;

    for (int i = 1; lines[i] != NULL; i++) {
        g_auto(GStrv) f = g_strsplit(lines[i], "\t", -1);
        char *end = NULL;
        double dbm;

        if (f[0] == NULL || *f[0] == '\0') continue;
        if ((int) g_strv_length(f) <= sig_col) continue;
        dbm = g_ascii_strtod(f[sig_col], &end);
        if (end == f[sig_col]) continue;      /* "-", or blank */

        anywhere[n_any % RTARGET_SPARK] = dbm;
        n_any++;
        if (want_chan && (int) g_strv_length(f) > arf_col &&
            g_strcmp0(f[arf_col], arfcn) == 0) {
            on_chan[n_chan % RTARGET_SPARK] = dbm;
            n_chan++;
        }
    }

    if (n_chan > 0) rtarget_spark_unwrap(state, on_chan, n_chan);
    else if (n_any > 0) rtarget_spark_unwrap(state, anywhere, n_any);
    return state->rtarget_spark_n > 0;
}

/* Read the casebook's selected target, and refresh the whole read-out from
   it. Called from status_poll, so the panel is never older than the radio
   strip beside it. */
static void
rtarget_panel_refresh(AppState *state)
{
    const char *cur_args[] = { "--target-current-tsv", NULL };
    gboolean ok = FALSE;
    g_autofree char *cur = casebook_call(cur_args, &ok);
    g_autofree char *rat = ok && cur != NULL
                         ? tsv_row_field(cur, "rat") : NULL;
    g_autofree char *plmn = ok && cur != NULL
                          ? tsv_row_field(cur, "plmn") : NULL;
    g_autofree char *chan = ok && cur != NULL
                          ? tsv_row_field(cur, "channel") : NULL;
    g_autofree char *cell = ok && cur != NULL
                          ? tsv_row_field(cur, "cell_id") : NULL;
    g_autofree char *band = ok && cur != NULL
                          ? tsv_row_field(cur, "band") : NULL;
    g_autofree char *pci = ok && cur != NULL
                         ? tsv_row_field(cur, "pci") : NULL;
    g_autofree char *first = ok && cur != NULL
                           ? tsv_row_field(cur, "first_seen") : NULL;
    g_autofree char *last = ok && cur != NULL
                          ? tsv_row_field(cur, "last_seen") : NULL;
    gboolean have = rat != NULL && *rat != '\0';
    gboolean live;

    if (state->rtarget_mark == NULL) return;

    /* ---- Identity ---- */
    gtk_image_set_from_icon_name(GTK_IMAGE(state->rtarget_mark),
                                 rtarget_rat_icon(rat));
    /* The generation's colour goes on the words as well as the glyph: the
       panel should say which network it is at a glance, and the two words
       are what there is to read. */
    {
        GtkWidget *marks[3] = { state->rtarget_mark,
                                state->rtarget_mark_rat,
                                state->rtarget_mark_gen };

        for (int i = 0; i < 3; i++) {
            gtk_widget_remove_css_class(marks[i], "target-gen-2g");
            gtk_widget_remove_css_class(marks[i], "target-gen-3g");
            gtk_widget_remove_css_class(marks[i], "target-gen-4g");
            gtk_widget_remove_css_class(marks[i], "target-gen-5g");
            gtk_widget_remove_css_class(marks[i], "target-gen-none");
            gtk_widget_add_css_class(marks[i], rtarget_rat_class(rat));
        }
    }
    gtk_label_set_text(GTK_LABEL(state->rtarget_mark_rat),
                       have ? rat : "No target");
    gtk_label_set_text(GTK_LABEL(state->rtarget_mark_gen),
                       have ? rtarget_rat_generation(rat) : "--");

    /* Rows may be absent; the panel says so rather than leaving a zero. */
    rtarget_put(state->rtarget_id_plmn, plmn);
    rtarget_put(state->rtarget_id_cell, cell);
    rtarget_put(state->rtarget_id_chan, chan);
    {
        g_autofree char *bp = NULL;

        if (band != NULL && *band != '\0' && pci != NULL && *pci != '\0')
            bp = g_strdup_printf("%s  ·  PCI %s", band, pci);
        else if (band != NULL && *band != '\0') bp = g_strdup(band);
        else if (pci != NULL && *pci != '\0')   bp = g_strdup_printf("PCI %s", pci);
        rtarget_put(state->rtarget_id_band, bp);
    }

    /* The cipher and the operator come from the last cell survey, because a
       casebook target does not carry either. */
    {
        g_autofree char *cells = g_build_filename(IMSISTING_ROOT, "loot",
                                                  "cell_recon", "cells.tsv", NULL);
        g_autofree char *text = NULL;

        if (g_file_get_contents(cells, &text, NULL, NULL)) {
            g_auto(GStrv) lines = g_strsplit(text, "\n", -1);
            int arf_col = -1, cell_col = -1, op_col = -1, ciph_col = -1;

            if (lines[0] != NULL) {
                g_auto(GStrv) cols = g_strsplit(lines[0], "\t", -1);

                for (int i = 0; cols[i] != NULL; i++) {
                    if (g_strcmp0(cols[i], "arfcn") == 0)   arf_col = i;
                    else if (g_strcmp0(cols[i], "cell_id") == 0) cell_col = i;
                    else if (g_strcmp0(cols[i], "operator") == 0) op_col = i;
                    else if (g_strcmp0(cols[i], "cipher") == 0)  ciph_col = i;
                }
            }
            for (int i = 1; lines[i] != NULL && arf_col >= 0; i++) {
                g_auto(GStrv) f = g_strsplit(lines[i], "\t", -1);
                gboolean hit = FALSE;

                if ((int) g_strv_length(f) <= arf_col) continue;
                if (cell != NULL && *cell != '\0' && cell_col >= 0 &&
                    (int) g_strv_length(f) > cell_col)
                    hit = g_strcmp0(f[cell_col], cell) == 0;
                else if (chan != NULL && *chan != '\0')
                    hit = g_strcmp0(f[arf_col], chan) == 0;
                if (!hit) continue;

                if (op_col >= 0 && (int) g_strv_length(f) > op_col)
                    rtarget_put(state->rtarget_mark_rat_owner, f[op_col]);
                if (ciph_col >= 0 && (int) g_strv_length(f) > ciph_col) {
                    const char *c = f[ciph_col];
                    gboolean sealed = c != NULL && *c != '\0' &&
                                      g_ascii_strcasecmp(c, "none") != 0 &&
                                      g_ascii_strcasecmp(c, "null") != 0 &&
                                      g_ascii_strcasecmp(c, "-") != 0;

                    gtk_label_set_text(GTK_LABEL(state->rtarget_mark_lock_lbl),
                                       (c != NULL && *c != '\0') ? c : "--");
                    gtk_image_set_from_icon_name(
                        GTK_IMAGE(state->rtarget_mark_lock),
                        sealed ? "channel-secure-symbolic" : "dialog-warning-symbolic");
                    /* Green says the cipher is on, orange says the cell is
                       there and the cipher is not. The two are different
                       findings, so they are different colours. */
                    gtk_widget_remove_css_class(state->rtarget_mark_lock, "target-open");
                    gtk_widget_remove_css_class(state->rtarget_mark_lock, "target-lock-on");
                    gtk_widget_add_css_class(state->rtarget_mark_lock,
                                             sealed ? "target-lock-on" : "target-open");
                }
                break;
            }
        }
    }
    if (!have) {
        rtarget_put(state->rtarget_mark_rat_owner, NULL);
        gtk_label_set_text(GTK_LABEL(state->rtarget_mark_lock_lbl), "--");
        gtk_image_set_from_icon_name(GTK_IMAGE(state->rtarget_mark_lock),
                                     "channel-secure-symbolic");
        /* No target is not an open cipher, or a closed one: it is nothing
           known, and it is drawn as nothing known. */
        gtk_widget_remove_css_class(state->rtarget_mark_lock, "target-open");
        gtk_widget_remove_css_class(state->rtarget_mark_lock, "target-lock-on");
    }

    /* ---- Live ---- */
    live = rtarget_read_signal(state, chan);
    if (live) {
        g_autofree char *now = g_strdup_printf("%.0f dBm",
                                               state->rtarget_spark[state->rtarget_spark_n - 1]);
        g_autofree char *rng = NULL;
        double lo = state->rtarget_spark[0], hi = state->rtarget_spark[0];

        for (int i = 1; i < state->rtarget_spark_n; i++) {
            if (state->rtarget_spark[i] < lo) lo = state->rtarget_spark[i];
            if (state->rtarget_spark[i] > hi) hi = state->rtarget_spark[i];
        }
        rng = g_strdup_printf("%d sample%s  ·  %.0f to %.0f dBm",
                              state->rtarget_spark_n,
                              state->rtarget_spark_n == 1 ? "" : "s", lo, hi);
        gtk_label_set_text(GTK_LABEL(state->rtarget_sig_now), now);
        gtk_label_set_text(GTK_LABEL(state->rtarget_sig_range), "");
        /* The count and the range get their own line: beside the reading they
           ran off the edge of a 300px panel. */
        gtk_label_set_text(GTK_LABEL(state->rtarget_sig_state), rng);
        gtk_widget_set_visible(state->rtarget_sig_state, TRUE);
        /* Five bars, filled from the current reading. -113 dBm is the weakest
           a GSM receiver is specified to hear and -51 the strongest, so the
           scale is the standard's own rather than an invented one. */
        {
            double dbm = state->rtarget_spark[state->rtarget_spark_n - 1];
            int lit = (int) (((dbm + 113.0) / 62.0) * 5.0 + 0.5);

            if (lit < 0) lit = 0;
            if (lit > 5) lit = 5;
            for (int i = 0; i < 5; i++) {
                GtkWidget *bar = g_object_get_data(G_OBJECT(state->rtarget_bars),
                                                   i == 0 ? "bar0" : i == 1 ? "bar1"
                                                   : i == 2 ? "bar2" : i == 3 ? "bar3"
                                                   : "bar4");

                if (bar == NULL) continue;
                if (i < lit) gtk_widget_add_css_class(bar, "on");
                else         gtk_widget_remove_css_class(bar, "on");
            }
        }
    } else {
        gtk_label_set_text(GTK_LABEL(state->rtarget_sig_now), "--");
        gtk_label_set_text(GTK_LABEL(state->rtarget_sig_range), "");
        gtk_label_set_text(GTK_LABEL(state->rtarget_sig_state),
                           "No live feed — nothing has been decoded yet.");
        gtk_widget_set_visible(state->rtarget_sig_state, TRUE);
        for (int i = 0; i < 5; i++) {
            GtkWidget *bar = g_object_get_data(G_OBJECT(state->rtarget_bars),
                                               i == 0 ? "bar0" : i == 1 ? "bar1"
                                               : i == 2 ? "bar2" : i == 3 ? "bar3"
                                               : "bar4");

            if (bar != NULL) gtk_widget_remove_css_class(bar, "on");
        }
    }
    gtk_widget_queue_draw(state->rtarget_spark_area);

    /* ---- Context ---- */
    rtarget_put(state->rtarget_held, first);
    rtarget_put(state->rtarget_seen, last);
}

static GtkWidget *
build_target_panel(AppState *state)
{
    GtkWidget *revealer = gtk_revealer_new();
    GtkWidget *panel    = gtk_box_new(GTK_ORIENTATION_VERTICAL, 14);
    GtkWidget *title    = gtk_label_new("TARGET");
    GtkWidget *id_body  = NULL, *live_body = NULL, *ctx_body = NULL;
    GtkWidget *mark_row, *mark_text, *mark_icon;
    GtkWidget *apply    = gtk_button_new_with_label("Apply");
    GtkWidget *clear    = gtk_button_new_with_label("Clear");

    gtk_widget_add_css_class(panel, "target-panel");
    gtk_widget_add_css_class(title, "target-title");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_box_append(GTK_BOX(panel), title);

    /* ---- Identity ---- */
    {
        GtkWidget *zone = rtarget_zone("IDENTITY", &id_body);

        mark_row  = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
        mark_icon = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
        mark_text = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
        gtk_widget_add_css_class(mark_row, "target-mark-row");
        gtk_widget_add_css_class(mark_icon, "target-mark-icon");

        state->rtarget_mark = imsisting_icon_image(rtarget_rat_icon(NULL));
        gtk_image_set_pixel_size(GTK_IMAGE(state->rtarget_mark), 40);
        gtk_widget_add_css_class(state->rtarget_mark, "target-gen-none");
        gtk_box_append(GTK_BOX(mark_icon), state->rtarget_mark);

        state->rtarget_mark_rat  = gtk_label_new("No target");
        state->rtarget_mark_gen  = gtk_label_new("--");
        state->rtarget_mark_rat_owner = gtk_label_new(NULL);
        gtk_widget_add_css_class(state->rtarget_mark_rat, "target-mark-rat");
        gtk_widget_add_css_class(state->rtarget_mark_gen, "target-mark-gen");
        gtk_widget_add_css_class(state->rtarget_mark_rat_owner, "target-mark-owner");
        gtk_label_set_xalign(GTK_LABEL(state->rtarget_mark_rat), 0.0f);
        gtk_label_set_xalign(GTK_LABEL(state->rtarget_mark_gen), 0.0f);
        gtk_label_set_xalign(GTK_LABEL(state->rtarget_mark_rat_owner), 0.0f);
        gtk_label_set_ellipsize(GTK_LABEL(state->rtarget_mark_rat_owner),
                                PANGO_ELLIPSIZE_END);
        gtk_box_append(GTK_BOX(mark_text), state->rtarget_mark_rat);
        gtk_box_append(GTK_BOX(mark_text), state->rtarget_mark_gen);
        gtk_box_append(GTK_BOX(mark_text), state->rtarget_mark_rat_owner);

        /* The padlock: which cipher protects the cell's traffic, if any. */
        {
            GtkWidget *lock = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);

            state->rtarget_mark_lock = imsisting_icon_image("channel-secure-symbolic");
            gtk_image_set_pixel_size(GTK_IMAGE(state->rtarget_mark_lock), 14);
            gtk_widget_add_css_class(state->rtarget_mark_lock, "target-lock");
            state->rtarget_mark_lock_lbl = gtk_label_new("--");
            gtk_widget_add_css_class(state->rtarget_mark_lock_lbl, "target-lock-lbl");
            gtk_label_set_xalign(GTK_LABEL(state->rtarget_mark_lock_lbl), 0.0f);
            gtk_box_append(GTK_BOX(lock), state->rtarget_mark_lock);
            gtk_box_append(GTK_BOX(lock), state->rtarget_mark_lock_lbl);
            gtk_box_append(GTK_BOX(mark_text), lock);
        }

        gtk_widget_set_valign(mark_icon, GTK_ALIGN_START);
        gtk_widget_set_hexpand(mark_text, TRUE);
        gtk_box_append(GTK_BOX(mark_row), mark_icon);
        gtk_box_append(GTK_BOX(mark_row), mark_text);
        gtk_box_append(GTK_BOX(id_body), mark_row);

        state->rtarget_id_plmn = rtarget_kv(id_body, "PLMN");
        state->rtarget_id_cell = rtarget_kv(id_body, "Cell");
        state->rtarget_id_chan = rtarget_kv(id_body, "Channel");
        state->rtarget_id_band = rtarget_kv(id_body, "Band");
        gtk_box_append(GTK_BOX(panel), zone);
    }

    /* ---- Live ---- */
    {
        GtkWidget *zone = rtarget_zone("SIGNAL", &live_body);
        GtkWidget *bars = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 3);

        state->rtarget_bars = bars;
        gtk_widget_add_css_class(bars, "target-bars");
        gtk_widget_set_valign(bars, GTK_ALIGN_END);
        for (int i = 0; i < 5; i++) {
            GtkWidget *bar = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
            g_autofree char *key = g_strdup_printf("bar%d", i);

            gtk_widget_add_css_class(bar, "target-bar");
            gtk_widget_set_size_request(bar, 4, 6 + i * 3);
            gtk_widget_set_valign(bar, GTK_ALIGN_END);
            gtk_box_append(GTK_BOX(bars), bar);
            g_object_set_data(G_OBJECT(state->rtarget_bars), key, bar);
        }

        state->rtarget_spark_area = gtk_drawing_area_new();
        gtk_widget_add_css_class(state->rtarget_spark_area, "target-spark");
        gtk_widget_set_size_request(state->rtarget_spark_area, -1, 54);
        gtk_drawing_area_set_content_width(GTK_DRAWING_AREA(state->rtarget_spark_area), -1);
        gtk_drawing_area_set_draw_func(GTK_DRAWING_AREA(state->rtarget_spark_area),
                                       rtarget_spark_draw, state, NULL);

        {
            GtkWidget *under = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);

            state->rtarget_sig_now   = gtk_label_new("--");
            state->rtarget_sig_range = gtk_label_new("");
            gtk_widget_add_css_class(state->rtarget_sig_now, "target-sig-now");
            gtk_widget_add_css_class(state->rtarget_sig_range, "target-sig-range");
            gtk_label_set_xalign(GTK_LABEL(state->rtarget_sig_now), 0.0f);
            gtk_label_set_xalign(GTK_LABEL(state->rtarget_sig_range), 0.0f);
            gtk_label_set_ellipsize(GTK_LABEL(state->rtarget_sig_range),
                                    PANGO_ELLIPSIZE_END);
            gtk_widget_set_hexpand(state->rtarget_sig_range, TRUE);
            gtk_widget_set_valign(bars, GTK_ALIGN_CENTER);
            gtk_box_append(GTK_BOX(under), bars);
            gtk_box_append(GTK_BOX(under), state->rtarget_sig_now);
            gtk_box_append(GTK_BOX(under), state->rtarget_sig_range);
            gtk_box_append(GTK_BOX(live_body), state->rtarget_spark_area);
            gtk_box_append(GTK_BOX(live_body), under);
        }

        state->rtarget_sig_state = gtk_label_new("No live feed.");
        gtk_widget_add_css_class(state->rtarget_sig_state, "target-sig-state");
        gtk_label_set_xalign(GTK_LABEL(state->rtarget_sig_state), 0.0f);
        gtk_label_set_wrap(GTK_LABEL(state->rtarget_sig_state), TRUE);
        gtk_box_append(GTK_BOX(live_body), state->rtarget_sig_state);
        gtk_box_append(GTK_BOX(panel), zone);
    }

    /* ---- Context ---- */
    {
        GtkWidget *zone = rtarget_zone("HELD", &ctx_body);

        state->rtarget_held = rtarget_kv(ctx_body, "Since");
        state->rtarget_seen = rtarget_kv(ctx_body, "Last");
        gtk_box_append(GTK_BOX(panel), zone);
    }

    /* ---- Case counters ---- */
    {
        GtkWidget *head = gtk_label_new("CASE");
        GtkWidget *grid = gtk_grid_new();
        GtkWidget *cells[4];

        gtk_widget_add_css_class(head, "target-case-head");
        gtk_label_set_xalign(GTK_LABEL(head), 0.0f);
        gtk_grid_set_row_spacing(GTK_GRID(grid), 8);
        gtk_grid_set_column_spacing(GTK_GRID(grid), 10);

        cells[0] = status_cell("CASE", &state->dash_case);
        cells[1] = status_cell("TARGETS", &state->dash_targets);
        cells[2] = status_cell("EVIDENCE", &state->dash_evidence);
        cells[3] = status_cell("ALERTS", &state->dash_alerts);
        for (int i = 0; i < 4; i++) {
            gtk_widget_set_hexpand(cells[i], TRUE);
            gtk_grid_attach(GTK_GRID(grid), cells[i], i % 2, i / 2, 1, 1);
        }

        gtk_box_append(GTK_BOX(panel), head);
        gtk_box_append(GTK_BOX(panel), grid);
    }

    /* ---- The form, folded away ----
       Setting a target happens once; reading it happens every time. The
       expander is closed by default so the three zones above get the panel,
       and it opens onto the same four fields and the same Apply and Clear. */
    {
        GtkWidget *expander = gtk_expander_new("Set target");
        GtkWidget *form     = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);

        gtk_widget_add_css_class(expander, "target-editor");
        gtk_expander_set_expanded(GTK_EXPANDER(expander), FALSE);
        state->rtarget_editor = expander;

        state->rtarget_rat   = gtk_entry_new();
        state->rtarget_arfcn = gtk_entry_new();
        state->rtarget_plmn  = gtk_entry_new();
        state->rtarget_cell  = gtk_entry_new();
        state->rtarget_state_lbl = gtk_label_new("No target set");

        gtk_entry_set_placeholder_text(GTK_ENTRY(state->rtarget_rat), "RAT — GSM, UMTS, LTE, NR");
        gtk_entry_set_placeholder_text(GTK_ENTRY(state->rtarget_arfcn), "ARFCN or channel");
        gtk_entry_set_placeholder_text(GTK_ENTRY(state->rtarget_plmn), "PLMN — 6 digits");
        gtk_entry_set_placeholder_text(GTK_ENTRY(state->rtarget_cell), "Cell ID");
        gtk_entry_set_max_length(GTK_ENTRY(state->rtarget_rat), 6);
        gtk_entry_set_max_length(GTK_ENTRY(state->rtarget_arfcn), 12);
        gtk_entry_set_max_length(GTK_ENTRY(state->rtarget_plmn), 10);
        gtk_entry_set_max_length(GTK_ENTRY(state->rtarget_cell), 24);

        gtk_widget_add_css_class(state->rtarget_state_lbl, "target-value");
        gtk_widget_add_css_class(apply, "verb-button");
        gtk_widget_add_css_class(apply, "primary");
        gtk_widget_add_css_class(clear, "verb-button");
        gtk_label_set_xalign(GTK_LABEL(state->rtarget_state_lbl), 0.0f);
        gtk_label_set_ellipsize(GTK_LABEL(state->rtarget_state_lbl),
                                PANGO_ELLIPSIZE_END);
        gtk_widget_set_hexpand(state->rtarget_state_lbl, TRUE);

        g_signal_connect(apply, "clicked", G_CALLBACK(rtarget_apply_clicked), state);
        g_signal_connect(clear, "clicked", G_CALLBACK(rtarget_clear_clicked), state);

        {
            GtkWidget *fields[4] = { state->rtarget_rat, state->rtarget_arfcn,
                                     state->rtarget_plmn, state->rtarget_cell };

            for (int i = 0; i < 4; i++) {
                gtk_widget_set_hexpand(fields[i], TRUE);
                gtk_box_append(GTK_BOX(form), fields[i]);
            }
        }

        {
            GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);

            gtk_box_append(GTK_BOX(row), apply);
            gtk_box_append(GTK_BOX(row), clear);
            gtk_box_append(GTK_BOX(form), row);
        }
        gtk_box_append(GTK_BOX(form), state->rtarget_state_lbl);
        gtk_expander_set_child(GTK_EXPANDER(expander), form);
        gtk_box_append(GTK_BOX(panel), expander);
    }

    /* A column hugs the right edge and folds sideways; sliding down was
       what the panel did when it was a strip across the top. */
    gtk_revealer_set_transition_type(GTK_REVEALER(revealer),
                                     GTK_REVEALER_TRANSITION_TYPE_SLIDE_LEFT);
    gtk_revealer_set_transition_duration(GTK_REVEALER(revealer), 180);
    /* The read-out plus the folded form is taller than a 760px window, and a
       clipped control is a control the operator cannot reach. */
    {
        GtkWidget *scroll = gtk_scrolled_window_new();

        gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                       GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
        gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), panel);
        gtk_widget_add_css_class(scroll, "target-scroll");
        gtk_revealer_set_child(GTK_REVEALER(revealer), scroll);
    }
    gtk_widget_set_size_request(revealer, 300, -1);
    gtk_widget_set_vexpand(revealer, TRUE);
    state->rtarget_revealer = revealer;

    return revealer;
}

/* Open the panel from anywhere and put a target in it - what the Targets
   list's Set target does. */
void
imsisting_target_offer(AppState *state, const char *rat, const char *arfcn,
                       const char *plmn, const char *cell)
{
    if (state == NULL) return;

    if (state->rtarget_rat != NULL)
        gtk_editable_set_text(GTK_EDITABLE(state->rtarget_rat), rat ? rat : "");
    if (state->rtarget_arfcn != NULL)
        gtk_editable_set_text(GTK_EDITABLE(state->rtarget_arfcn), arfcn ? arfcn : "");
    if (state->rtarget_plmn != NULL)
        gtk_editable_set_text(GTK_EDITABLE(state->rtarget_plmn), plmn ? plmn : "");
    if (state->rtarget_cell != NULL)
        gtk_editable_set_text(GTK_EDITABLE(state->rtarget_cell), cell ? cell : "");

    rtarget_apply(state);

    if (state->rtarget_button != NULL)
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(state->rtarget_button), TRUE);
}


/* ──────────────────────────────── Splash ────────────────────────────────
   The first screen: the illustration, the logo over it, and a bar that
   reports what the boot is doing.

   Three things about how it is drawn are deliberate.

   The logo asset is glow-on-black with no alpha channel, and that is not a
   defect to work around. Compositing it with CAIRO_OPERATOR_ADD makes the
   black contribute nothing and the glow add to whatever is underneath, which
   is how the art was drawn in the first place. Cutting an alpha channel by
   hand would be the wrong fix: it would have to be redrawn for every edge,
   and it would throw away the halo the additive pass produces for free.

   The art is drawn to cover, not to fit. The splash window is the art's own
   aspect ratio, so cover and fit agree at the natural size; cover is what
   keeps them agreeing if the window manager hands us a different one, at the
   cost of cropping rather than letterboxing.

   The bar is not decoration. Each stage below does the work its label names,
   and the percentage is that stage's place in the sequence. The pacing is
   deliberate - a stage stays up long enough to read even when its work
   returns in a millisecond - because a bar that jumps straight to 100% has
   told the user nothing and looks like the app skipped something.
   ─────────────────────────────────────────────────────────────────────── */

#define SPLASH_BAR_R 0.184
#define SPLASH_BAR_G 0.427
#define SPLASH_BAR_B 1.000   /* #2f6dff - the blue the logo is drawn in */
#define SPLASH_TXT_R 0.435
#define SPLASH_TXT_G 0.659
#define SPLASH_TXT_B 1.000   /* #6fa8ff */
#define SPLASH_DIM_R 0.545
#define SPLASH_DIM_G 0.592
#define SPLASH_DIM_B 0.659   /* #8b97a8, the app's text_dim */

static void
splash_rounded_rect(cairo_t *cr, double x, double y, double w, double h, double r)
{
    if (r > h / 2.0) r = h / 2.0;
    if (r > w / 2.0) r = w / 2.0;
    cairo_new_sub_path(cr);
    cairo_arc(cr, x + w - r, y + r,     r, -G_PI_2, 0.0);
    cairo_arc(cr, x + w - r, y + h - r, r, 0.0, G_PI_2);
    cairo_arc(cr, x + r,     y + h - r, r, G_PI_2, G_PI);
    cairo_arc(cr, x + r,     y + r,     r, G_PI, G_PI + G_PI_2);
    cairo_close_path(cr);
}

/* A GdkTexture as a Cairo surface, downloaded once at startup.
   gdk_cairo_set_source_paint() would do this in one call, but it arrived in
   GTK 4.20 and this has to build against what the distro ships (4.14 here).
   Converting per frame would copy several megabytes sixty times a second. */
static cairo_surface_t *
splash_surface(GdkTexture *tex)
{
    int w = gdk_texture_get_width(tex);
    int h = gdk_texture_get_height(tex);
    gsize stride = (gsize) w * 4;

    g_autofree guchar *src = g_malloc(stride * h);
    gdk_texture_download(tex, src, stride);

    cairo_surface_t *s = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, w, h);
    guchar *dst = cairo_image_surface_get_data(s);
    gsize dstride = (gsize) cairo_image_surface_get_stride(s);
    for (int y = 0; y < h; y++)
        memcpy(dst + (gsize) y * dstride, src + (gsize) y * stride,
               MIN(stride, dstride));
    cairo_surface_mark_dirty(s);
    return s;
}

/* Draw a surface so it covers the given rectangle: scaled by whichever axis
   needs more, centred, and cropped by the clip. */
static void
splash_cover(cairo_t *cr, cairo_surface_t *s, double x, double y,
             double w, double h)
{
    double tw = cairo_image_surface_get_width(s);
    double th = cairo_image_surface_get_height(s);
    if (tw <= 0.0 || th <= 0.0 || w <= 0.0 || h <= 0.0) return;

    double k = MAX(w / tw, h / th);

    cairo_save(cr);
    cairo_rectangle(cr, x, y, w, h);
    cairo_clip(cr);
    cairo_translate(cr, x + (w - tw * k) / 2.0, y + (h - th * k) / 2.0);
    cairo_scale(cr, k, k);
    cairo_set_source_surface(cr, s, 0.0, 0.0);
    cairo_pattern_set_filter(cairo_get_source(cr), CAIRO_FILTER_GOOD);
    cairo_paint(cr);
    cairo_restore(cr);
}

/* One centred line of monospace, which is the face the rest of the app uses. */
static void
splash_text(cairo_t *cr, const char *text, double cx, double y, double px,
            gboolean bold, double r, double g, double b, double a)
{
    PangoLayout *layout = pango_cairo_create_layout(cr);
    PangoFontDescription *fd = pango_font_description_new();
    pango_font_description_set_family(fd, "monospace");
    pango_font_description_set_absolute_size(fd, px * PANGO_SCALE);
    pango_font_description_set_weight(fd, bold ? PANGO_WEIGHT_BOLD
                                               : PANGO_WEIGHT_NORMAL);
    pango_layout_set_font_description(layout, fd);
    pango_layout_set_text(layout, text, -1);

    int tw = 0, th = 0;
    pango_layout_get_pixel_size(layout, &tw, &th);

    cairo_set_source_rgba(cr, r, g, b, a);
    cairo_move_to(cr, cx - tw / 2.0, y);
    pango_cairo_show_layout(cr, layout);

    g_object_unref(layout);
    pango_font_description_free(fd);
}

/* Everything above the bar is the same in every frame - the art, the shade
   under the logo, the footer gradient. Composing it once into a backdrop at
   the widget's device size and blitting that afterwards is the difference
   between a bar that moves and one that jumps: scaling two images of this
   size per frame, in software, measured at roughly 130 ms a frame, so the
   animation was asking for 60 fps and being given seven. */
static void
splash_backdrop(AppState *state, int width, int height, int scale)
{
    if (state->splash_bg != NULL &&
        state->splash_bg_w == width * scale &&
        state->splash_bg_h == height * scale)
        return;
    if (state->splash_bg != NULL)
        cairo_surface_destroy(state->splash_bg);

    state->splash_bg = cairo_image_surface_create(CAIRO_FORMAT_ARGB32,
                                                  width * scale, height * scale);
    state->splash_bg_w = width * scale;
    state->splash_bg_h = height * scale;

    cairo_t *cr = cairo_create(state->splash_bg);
    cairo_scale(cr, scale, scale);

    /* Base colour first, so a resource that somehow did not carry the art
       still gives a dark panel rather than a hole in the screen. */
    cairo_set_source_rgb(cr, 0.043, 0.063, 0.090);
    cairo_paint(cr);

    if (state->splash_art != NULL)
        splash_cover(cr, state->splash_art, 0, 0, width, height);

    /* The logo goes in the middle. The art underneath is an illustration
       with its own focal point, so the logo gets a soft radial shade to sit
       on - without it the glow and the artwork fight and neither reads. */
    if (state->splash_logo != NULL) {
        double size = MIN(width * 0.40, height * 0.62);
        double lx = (width - size) / 2.0;
        double ly = height * 0.45 - size / 2.0;

        if (size > 8.0) {
            cairo_pattern_t *shade = cairo_pattern_create_radial(
                width / 2.0, ly + size / 2.0, size * 0.10,
                width / 2.0, ly + size / 2.0, size * 0.78);
            cairo_pattern_add_color_stop_rgba(shade, 0.0, 0.02, 0.03, 0.06, 0.62);
            cairo_pattern_add_color_stop_rgba(shade, 1.0, 0.02, 0.03, 0.06, 0.0);
            cairo_set_source(cr, shade);
            cairo_paint(cr);
            cairo_pattern_destroy(shade);

            cairo_save(cr);
            cairo_set_operator(cr, CAIRO_OPERATOR_ADD);
            splash_cover(cr, state->splash_logo, lx, ly, size, size);
            cairo_restore(cr);
        }
    }

    /* Darken the bottom so the bar and its text read over any crop of the
       art. Transparent at the top edge of the strip, so there is no seam. */
    cairo_pattern_t *foot = cairo_pattern_create_linear(0, height - 170.0,
                                                        0, (double) height);
    cairo_pattern_add_color_stop_rgba(foot, 0.0, 0.02, 0.03, 0.06, 0.0);
    cairo_pattern_add_color_stop_rgba(foot, 1.0, 0.02, 0.03, 0.06, 0.78);
    cairo_set_source(cr, foot);
    cairo_rectangle(cr, 0, height - 170.0, width, 170.0);
    cairo_fill(cr);
    cairo_pattern_destroy(foot);

    cairo_destroy(cr);
}

static void
splash_draw(GtkDrawingArea *area, cairo_t *cr, int width, int height,
            gpointer data)
{
    AppState *state = data;

    splash_backdrop(state, width, height,
                    gtk_widget_get_scale_factor(GTK_WIDGET(area)));
    if (state->splash_bg != NULL) {
        cairo_set_source_surface(cr, state->splash_bg, 0, 0);
        cairo_paint(cr);
    }

    double bar_w = CLAMP(width * 0.42, 220.0, 560.0);
    double bar_h = 7.0;
    double bar_x = (width - bar_w) / 2.0;
    double bar_y = height - 84.0;
    double shown = CLAMP(state->splash_shown, 0.0, 1.0);

    /* Track. */
    splash_rounded_rect(cr, bar_x, bar_y, bar_w, bar_h, bar_h / 2.0);
    cairo_set_source_rgba(cr, 1.0, 1.0, 1.0, 0.13);
    cairo_fill_preserve(cr);
    cairo_set_source_rgba(cr, 0.0, 0.0, 0.0, 0.35);
    cairo_set_line_width(cr, 1.0);
    cairo_stroke(cr);

    /* Fill, with a halo. Cairo has no blur, so the glow is the same path
       stroked a few times at decreasing width and increasing alpha. */
    double fw = bar_w * shown;
    if (fw > 0.75) {
        for (int i = 2; i >= 0; i--) {
            double grow = 3.0 + i * 5.0;
            splash_rounded_rect(cr, bar_x, bar_y, fw, bar_h, bar_h / 2.0);
            cairo_set_source_rgba(cr, SPLASH_BAR_R, SPLASH_BAR_G, SPLASH_BAR_B,
                                  0.05 + (2 - i) * 0.05);
            cairo_set_line_width(cr, bar_h + grow);
            cairo_stroke(cr);
        }
        splash_rounded_rect(cr, bar_x, bar_y, fw, bar_h, bar_h / 2.0);
        cairo_set_source_rgb(cr, SPLASH_BAR_R, SPLASH_BAR_G, SPLASH_BAR_B);
        cairo_fill(cr);
    }

    /* What the boot is on, in the app's dim grey - it is a caption for the
       bar, not a second headline competing with the logo. */
    if (state->splash_label != NULL)
        splash_text(cr, state->splash_label, width / 2.0, bar_y - 28.0,
                    12.0, FALSE, SPLASH_DIM_R, SPLASH_DIM_G, SPLASH_DIM_B, 1.0);

    g_autofree char *pct = g_strdup_printf("%d %%", (int) (shown * 100.0 + 0.5));
    splash_text(cr, pct, width / 2.0, bar_y + bar_h + 14.0, 15.0, TRUE,
                SPLASH_TXT_R, SPLASH_TXT_G, SPLASH_TXT_B, 1.0);
}

/* ─────────────────────────────── Boot ───────────────────────────────────
   on_activate used to do all of the following in one block, which meant the
   process had no window on screen for the whole of it: the launch looked
   like nothing had happened until everything had. These are that same block
   cut at the points where it already paused naturally, so the splash can
   report each one and the window can appear as soon as there is one.

   The order is not cosmetic. density_apply() writes a CSS class onto
   state->window, so the window has to exist before it runs - which is why
   creating it is part of the first stage rather than a stage of its own.
   ─────────────────────────────────────────────────────────────────────── */

static void
boot_restore_session(AppState *state, GtkApplication *app)
{
    /* The module icons are compiled into this binary (see
       tools/gen-icons-xml.sh) and published as icons/scalable/actions/
       <name>.svg. imsisting_icon_image() reads them straight out of the
       resource, so the dashboard depends on neither the launcher having
       copied the SVGs into ~/.local/share/icons/hicolor nor whichever theme
       the distro exposes. They stay symbolic, so each category's accent
       colour still applies. */

    state->window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(state->window), "IMSIsting");
    gtk_window_set_default_size(GTK_WINDOW(state->window), 1180, 760);
    /* The layout's measured floor is ~448px plus the 52px titlebar. Without a
       minimum the window manager lets the user shrink past it, and the Events
       drawer - the last child of a box that cannot scroll - is then allocated
       below the bottom edge instead of the page shrinking. The drawer carries
       a 170px minimum of its own plus its toolbar; this is the cheap guard
       that keeps it reachable. */
    gtk_widget_set_size_request(state->window, -1, 500);

    /* Open the way the last session was left: tile density, dashboard order
       and the run counts behind "Most used". */
    ui_state_load(state);
    density_apply(state);
}

static void
boot_load_css(AppState *state, GtkApplication *app)
{
    (void) state;
    (void) app;

    g_autoptr(GtkCssProvider) css = gtk_css_provider_new();
    gtk_css_provider_load_from_resource(css, "/com/imsisting/native/style.css");
    gtk_style_context_add_provider_for_display(
        gdk_display_get_default(), GTK_STYLE_PROVIDER(css),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
}

/* ── The terminal ──────────────────────────────────────────────────────
   A shell standing in the project directory. Every button in this window runs
   something that could have been typed, and the modules are shell scripts that
   read and write files under IMSISTING_ROOT - so the fastest way to see what a
   module actually did is to be standing where it lives. VTE is what makes this
   a terminal rather than a log pane: job control, colour, interactive prompts,
   a real shell you can leave running while you work in the window. It is
   optional at build time, so if the dependency is missing this falls back to
   whatever terminal the desktop already has rather than doing nothing. */
#ifdef HAVE_VTE
static void
terminal_child_exited(VteTerminal *terminal, gint status, gpointer user_data)
{
    GtkWindow *window = user_data;

    (void) terminal;
    (void) status;
    /* The shell is the window: when it ends there is nothing left to show. */
    gtk_window_destroy(window);
}

static void
terminal_spawned(VteTerminal *terminal, GPid pid, GError *error,
                 gpointer user_data)
{
    AppState *state = user_data;

    (void) terminal;
    (void) pid;
    if (error != NULL) {
        show_toast_full(state, "Terminal", error->message, "error");
        g_error_free(error);
    }
}
#endif

static void
terminal_opened(GtkButton *button, gpointer user_data)
{
    AppState *state = user_data;

    (void) button;

#ifdef HAVE_VTE
    {
        const char *shell = g_getenv("SHELL");
        GtkWidget *window = gtk_window_new();
        GtkWidget *terminal = vte_terminal_new();
        char *argv[2];

        if (shell == NULL || *shell == '\0') shell = "/bin/bash";
        argv[0] = (char *) shell;
        argv[1] = NULL;

        gtk_window_set_title(GTK_WINDOW(window), "IMSIsting — shell");
        gtk_window_set_default_size(GTK_WINDOW(window), 900, 460);
        gtk_window_set_transient_for(GTK_WINDOW(window),
                                     GTK_WINDOW(state->window));
        gtk_window_set_icon_name(GTK_WINDOW(window), "utilities-terminal");
        gtk_widget_add_css_class(window, "terminal-window");
        vte_terminal_set_scrollback_lines(VTE_TERMINAL(terminal), 10000);
        vte_terminal_set_cursor_blink_mode(VTE_TERMINAL(terminal),
                                           VTE_CURSOR_BLINK_ON);
        gtk_widget_set_vexpand(terminal, TRUE);
        gtk_window_set_child(GTK_WINDOW(window), terminal);
        g_signal_connect(terminal, "child-exited",
                         G_CALLBACK(terminal_child_exited), window);
        /* The working directory is the point: modules/ and loot/ are one `ls`
           away, and a relative path from a module's own help text works. */
        vte_terminal_spawn_async(VTE_TERMINAL(terminal), VTE_PTY_DEFAULT,
                                 IMSISTING_ROOT, argv, NULL,
                                 G_SPAWN_SEARCH_PATH, NULL, NULL, NULL,
                                 -1, NULL, terminal_spawned, state);
        gtk_window_present(GTK_WINDOW(window));
    }
#else
    {
        static const char *candidates[] = {
            "konsole", "gnome-terminal", "xfce4-terminal",
            "x-terminal-emulator", "xterm", NULL
        };
        char *program = NULL;

        for (int i = 0; candidates[i] != NULL && program == NULL; i++)
            program = g_find_program_in_path(candidates[i]);

        if (program == NULL) {
            show_toast_full(state, "Terminal",
                            "no terminal emulator found on this system",
                            "error");
            return;
        }

        {
            /* konsole is the one that needs telling where to start; the rest
               inherit the working directory from the spawn itself. */
            gboolean konsole = (strstr(program, "konsole") != NULL);
            char *argv[4];

            argv[0] = program;
            argv[1] = konsole ? "--workdir" : NULL;
            argv[2] = konsole ? (char *) IMSISTING_ROOT : NULL;
            argv[3] = NULL;
            if (!g_spawn_async(IMSISTING_ROOT, argv, NULL, G_SPAWN_SEARCH_PATH,
                               NULL, NULL, NULL, NULL))
                show_toast_full(state, "Terminal",
                                "could not start a terminal", "error");
        }
        g_free(program);
    }
#endif
}

/* "v0.6.0", read from the top-level VERSION file.
 *
 * Read at runtime rather than compiled in: the CLI reads the same file, so
 * they cannot disagree, and bumping the version needs no rebuild. Returns
 * NULL when VERSION is missing or empty, and the caller hides the label
 * rather than print a version number nobody can trust.
 */
static char *
imsisting_version_label(void)
{
    g_autofree char *path = g_build_filename(IMSISTING_ROOT, "VERSION", NULL);
    g_autofree char *contents = NULL;

    if (g_file_get_contents(path, &contents, NULL, NULL)) {
        g_strstrip(contents);
        if (*contents != '\0')
            return g_strdup_printf("v%s", contents);
    }
    return NULL;
}

static void
boot_build_ui(AppState *state, GtkApplication *app)
{
    (void) app;

    GtkWidget *root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);

    /* Header bar. */
    GtkWidget *header = gtk_header_bar_new();
    GtkWidget *wordmark = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *mark = imsisting_logo_image(30);
    GtkWidget *titlebox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *titleline = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 7);
    GtkWidget *title = gtk_label_new("IMSIsting");
    g_autofree char *version_text = imsisting_version_label();
    GtkWidget *version = gtk_label_new(version_text ? version_text : "");
    gtk_widget_set_visible(version, version_text != NULL);
    GtkWidget *subtitle = gtk_label_new("2G · 3G · 4G · 5G cellular research toolkit");
    gtk_widget_add_css_class(title, "title");
    gtk_widget_add_css_class(version, "app-version");
    gtk_widget_add_css_class(subtitle, "app-subtitle");
    /* The version sits on the name's baseline rather than its centre: centred
       on a 20px word it floats, and read as part of the word it looks like the
       tool is called "IMSIsting v0.6.0". Dim and small, it is a footnote to
       the name, which is what a version is. */
    gtk_widget_set_valign(version, GTK_ALIGN_END);
    gtk_widget_set_margin_bottom(version, 3);
    /* Both lines centre inside the title block. Left-aligned, the longer
       subtitle set the block's width and the shorter word "IMSIsting" hung
       off its left edge, which is what read as the title being off-centre -
       the block was centred, the word inside it was not. */
    gtk_widget_set_halign(title, GTK_ALIGN_START);
    gtk_widget_set_halign(subtitle, GTK_ALIGN_START);
    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(subtitle), 0.0f);
    gtk_widget_set_halign(titlebox, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(titleline), title);
    gtk_box_append(GTK_BOX(titleline), version);
    gtk_box_append(GTK_BOX(titlebox), titleline);
    gtk_box_append(GTK_BOX(titlebox), subtitle);
    gtk_widget_set_valign(mark, GTK_ALIGN_CENTER);
    gtk_box_append(GTK_BOX(wordmark), mark);
    gtk_box_append(GTK_BOX(wordmark), titlebox);

    /* The wordmark moves to the start and the search takes the centre. The
       centre of the header is the most expensive real estate in the window
       and it was spending it on a name that never changes, while the one
       control that goes anywhere was inside a drawer you have to reach for
       by moving the pointer to the edge of the screen. */
    gtk_header_bar_pack_start(GTK_HEADER_BAR(header), wordmark);

    GtkWidget *searchbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_widget_add_css_class(searchbox, "header-search");
    GtkWidget *search = gtk_search_entry_new();
    gtk_widget_set_size_request(search, 380, -1);
    gtk_search_entry_set_placeholder_text(GTK_SEARCH_ENTRY(search),
                                          "Search modules and pages");
    gtk_box_append(GTK_BOX(searchbox), search);
    gtk_header_bar_set_title_widget(GTK_HEADER_BAR(header), searchbox);
    state->header_search = search;
    /* "search-changed" is emitted through a 150ms GLib timeout, and timers
       do not dispatch in this process, so the palette would never open.
       "changed" is the editable's own signal and fires on the keystroke. */
    g_signal_connect(search, "changed",
                     G_CALLBACK(palette_search_changed), state);
    g_signal_connect(search, "activate", G_CALLBACK(palette_activate), state);
    g_signal_connect(search, "stop-search", G_CALLBACK(palette_stopped), state);

    /* No drawer button: the drawer opens from the left edge of the page,
       which costs the header nothing. This strip is the scarcest in the
       window -- title, target and events all compete for it. */

    GtkWidget *events_btn = gtk_toggle_button_new_with_label("Events");
    gtk_widget_add_css_class(events_btn, "header-pill");
    gtk_widget_set_tooltip_text(events_btn,
        "show the event drawer — module output and diagnostics");
    g_signal_connect(events_btn, "toggled",
                     G_CALLBACK(event_drawer_toggle), state);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(header), events_btn);
    state->event_button = events_btn;

    /* Packed after Events, so it lands to its left: Target then Events, the
       order wifisting uses. Reachable from every page, which is the whole
       point of putting the target here. */
    GtkWidget *rtarget_btn = gtk_toggle_button_new_with_label("Target");
    gtk_widget_add_css_class(rtarget_btn, "header-pill");
    gtk_widget_set_tooltip_text(rtarget_btn,
        "the radio target the cellular modules tune to — accessible from any page");
    g_signal_connect(rtarget_btn, "toggled",
                     G_CALLBACK(rtarget_toggled), state);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(header), rtarget_btn);
    state->rtarget_button = rtarget_btn;

    /* Packed last of the three, so it lands furthest left: search, terminal,
       Target, Events, then the window controls. The terminal sits next to the
       search because both are how you go and find something out. */
    GtkWidget *terminal_btn =
        gtk_button_new_from_icon_name("utilities-terminal-symbolic");
    gtk_widget_add_css_class(terminal_btn, "header-pill");
    gtk_widget_add_css_class(terminal_btn, "icon-only");
    gtk_widget_set_tooltip_text(terminal_btn,
        "open a shell in the project directory — every button here is a command you can run yourself");
    g_signal_connect(terminal_btn, "clicked",
                     G_CALLBACK(terminal_opened), state);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(header), terminal_btn);

    gtk_window_set_titlebar(GTK_WINDOW(state->window), header);

    /* Live cellular state, read from the modules themselves. */
    gtk_box_append(GTK_BOX(root), build_status_strip(state));
    /* Not appended here: the target is the right-hand column of the body,
       so it is built now and packed beside the overlay below. */
    GtkWidget *target_col = build_target_panel(state);

    /* Body: sidebar | notebook. */
    state->notebook = gtk_notebook_new();
    gtk_notebook_set_scrollable(GTK_NOTEBOOK(state->notebook), TRUE);
    gtk_notebook_set_show_border(GTK_NOTEBOOK(state->notebook), FALSE);
    /* No tab strip. The six permanent pages are the first six rows of the
       drawer and module pages are reached from the catalogue below them, so
       a strip naming the same six pages again would be exactly the second
       navigation layer the old dashboard was criticised for. */
    gtk_notebook_set_show_tabs(GTK_NOTEBOOK(state->notebook), FALSE);
    gtk_widget_set_vexpand(state->notebook, TRUE);
    gtk_widget_set_hexpand(state->notebook, TRUE);

    /* ---- the permanent pages, appended first ----
       First because the drawer lists them in this order and resolves them
       by index, and because "Dashboard" has to be page zero. The label is
       never shown with the strip hidden, but the notebook still wants one,
       and keeping it means the pages are described correctly if a strip
       ever comes back. */
    /* Page 0 is the dashboard's index, not the dashboard itself -- that
       widget is the overlay's main child. Keeping the index means every
       page number in the rest of this file still means what it did when the
       dashboard was page 0 of the notebook. */
    gtk_notebook_append_page(GTK_NOTEBOOK(state->notebook),
        gtk_box_new(GTK_ORIENTATION_VERTICAL, 0), gtk_label_new("Dashboard"));
    gtk_notebook_append_page(GTK_NOTEBOOK(state->notebook),
        create_live_traffic_page(state), gtk_label_new("Live Traffic"));
    gtk_notebook_append_page(GTK_NOTEBOOK(state->notebook),
        create_casebook_page(state), gtk_label_new("Casebook"));
    gtk_notebook_append_page(GTK_NOTEBOOK(state->notebook),
        create_stats_page(state), gtk_label_new("Stats"));
    gtk_notebook_append_page(GTK_NOTEBOOK(state->notebook),
        create_notifications_page(state), gtk_label_new("Notifications"));
    gtk_notebook_append_page(GTK_NOTEBOOK(state->notebook),
        create_help_page(),
        gtk_label_new("Help"));
    gtk_notebook_append_page(GTK_NOTEBOOK(state->notebook),
        create_settings_page(state), gtk_label_new("Settings"));

    g_signal_connect(state->notebook, "switch-page",
                     G_CALLBACK(notebook_page_switched), state);


    /* ---- the drawer ----
       The notebook is the overlay's main child, so it keeps the full width
       of the window at all times and the drawer is drawn on top of it
       rather than beside it. The revealer supplies the slide.

       measure_overlay FALSE is the load-bearing line: with it TRUE the
       overlay reports notebook + 272 as its own preferred width, so the
       drawer does not float over the page, it sets a floor under the whole
       window and the page is never narrow enough to need the drawer. */
    GtkWidget *overlay = gtk_overlay_new();
    gtk_overlay_set_child(GTK_OVERLAY(overlay), create_dashboard_page(state));

    /* ---- the target column ----
       It floats over the page the way the drawer does rather than sitting
       beside it. Sizing it here rather than in the box means opening it
       never costs the grid a column: the page keeps every pixel it had and
       the panel covers the right-hand tiles instead of reflowing them.

       Added AFTER the sheet, not before it. An overlay paints its children in
       the order they were added, and the sheet is what every page - the seven
       permanent ones and every module page - lives inside. Built here, the
       panel sat under the sheet and was invisible the moment any page was
       open, which is whenever the operator wants to read a target. */
    gtk_widget_set_halign(target_col, GTK_ALIGN_END);
    gtk_widget_set_valign(target_col, GTK_ALIGN_FILL);

    /* ---- the sheet and its scrim ----
       Added before the drawer so the drawer still floats above both. The
       scrim swallows the click that would otherwise land on a dashboard
       tile behind the panel and turn a dismissal into a navigation. */
    state->sheet_scrim = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_add_css_class(state->sheet_scrim, "sheet-scrim");
    GtkGesture *scrim_click = gtk_gesture_click_new();
    g_signal_connect(scrim_click, "released", G_CALLBACK(sheet_scrim_clicked), state);
    gtk_widget_add_controller(state->sheet_scrim,
                              GTK_EVENT_CONTROLLER(scrim_click));
    gtk_overlay_add_overlay(GTK_OVERLAY(overlay), state->sheet_scrim);
    gtk_overlay_set_measure_overlay(GTK_OVERLAY(overlay), state->sheet_scrim, FALSE);

    state->sheet = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_add_css_class(state->sheet, "sheet");
    gtk_box_append(GTK_BOX(state->sheet), state->notebook);
    gtk_overlay_add_overlay(GTK_OVERLAY(overlay), state->sheet);
    gtk_overlay_set_measure_overlay(GTK_OVERLAY(overlay), state->sheet, FALSE);
    sheet_set_open(state, FALSE);

    /* Above the sheet, so a target stays readable while a page is open. */
    gtk_overlay_add_overlay(GTK_OVERLAY(overlay), target_col);
    gtk_overlay_set_measure_overlay(GTK_OVERLAY(overlay), target_col, FALSE);

    GtkEventController *sheet_keys = gtk_event_controller_key_new();
    g_signal_connect(sheet_keys, "key-pressed", G_CALLBACK(sheet_key_pressed), state);
    gtk_widget_add_controller(GTK_WIDGET(state->window), sheet_keys);

    /* ---- the palette ----
       Anchored to the top of the content area rather than to the field, so
       it cannot be clipped by the header's own height and does not move
       when the field's neighbours change width. */
    state->palette = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_add_css_class(state->palette, "palette");
    gtk_widget_set_halign(state->palette, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(state->palette, GTK_ALIGN_START);
    gtk_widget_set_size_request(state->palette, 520, -1);
    state->palette_list = gtk_list_box_new();
    gtk_widget_add_css_class(state->palette_list, "palette-list");
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(state->palette_list),
                                    GTK_SELECTION_SINGLE);
    gtk_list_box_set_activate_on_single_click(GTK_LIST_BOX(state->palette_list), TRUE);
    g_signal_connect(state->palette_list, "row-activated",
                     G_CALLBACK(palette_row_activated), state);
    gtk_list_box_set_placeholder(GTK_LIST_BOX(state->palette_list),
                                 gtk_label_new("Nothing matches"));
    gtk_box_append(GTK_BOX(state->palette), state->palette_list);
    gtk_overlay_add_overlay(GTK_OVERLAY(overlay), state->palette);
    gtk_overlay_set_measure_overlay(GTK_OVERLAY(overlay), state->palette, FALSE);
    gtk_widget_set_visible(state->palette, FALSE);

    /* Every destination in one list: the six permanent pages, then every
       module, in the order the drawer shows them. Built once and filtered
       by visibility, because the set never changes at runtime. */
    palette_add_row(state, "view-grid-symbolic", "Dashboard",
                    "Case, bench, recon and live traffic",
                    "dashboard start here command overview home", 0, NULL);
    palette_add_row(state, "network-wireless-symbolic", "Live Traffic",
                    "The GSMTP feed as it arrives",
                    "live traffic gsmtp packets feed capture", LIVE_TAB_INDEX, NULL);
    palette_add_row(state, "folder-symbolic", "Casebook",
                    "Cases, evidence and nodes",
                    "casebook case evidence nodes exhibits", 2, NULL);
    palette_add_row(state, "org.gnome.SystemMonitor-symbolic", "Stats",
                    "Modules, collections and health",
                    "stats counts modules health inventory", 3, NULL);
    palette_add_row(state, "help-about-symbolic", "Help",
                    "How this is put together",
                    "help about documentation", 4, NULL);
    palette_add_row(state, "emblem-system-symbolic", "Settings",
                    "Preferences and paths",
                    "settings preferences paths configuration", 5, NULL);
    for (int i = 0; i < N_MODULES; i++) {
        g_autofree char *sub = g_strdup_printf("%s  ·  %s",
                                               modules[i].category, modules[i].id);
        g_autofree char *hay = g_strdup_printf("%s %s %s %s",
                                               modules[i].name, modules[i].id,
                                               modules[i].category, modules[i].desc);
        palette_add_row(state, modules[i].icon, modules[i].name, sub, hay, -1,
                        &modules[i]);
    }

    state->sidebar = build_sidebar(state);
    gtk_widget_set_size_request(state->sidebar, 272, -1);

    GtkWidget *revealer = gtk_revealer_new();
    state->sidebar_revealer = revealer;
    gtk_revealer_set_transition_type(GTK_REVEALER(revealer),
                                     GTK_REVEALER_TRANSITION_TYPE_SLIDE_RIGHT);
    gtk_revealer_set_transition_duration(GTK_REVEALER(revealer), 170);
    gtk_revealer_set_child(GTK_REVEALER(revealer), state->sidebar);
    gtk_widget_set_halign(revealer, GTK_ALIGN_START);
    gtk_widget_set_valign(revealer, GTK_ALIGN_FILL);
    gtk_overlay_add_overlay(GTK_OVERLAY(overlay), revealer);
    gtk_overlay_set_measure_overlay(GTK_OVERLAY(overlay), revealer, FALSE);

    /* The left edge of the window is the handle. One controller on the
       window and not one on the drawer: a motion controller reports the
       pointer in the controller's own coordinates, so a single listener can
       decide "at the edge" and "clear of the drawer" without having to
       reason about enter/leave as the pointer crosses from the drawer onto
       its own rows -- and the window is the only widget whose origin is the
       edge of the screen. */
    GtkEventController *motion = gtk_event_controller_motion_new();
    g_signal_connect(motion, "motion", G_CALLBACK(drawer_edge_motion), state);
    gtk_widget_add_controller(GTK_WIDGET(state->window), motion);

    /* Same edge, pressed instead of crossed, for the steadier mode. */
    GtkGesture *edge = gtk_gesture_click_new();
    gtk_gesture_single_set_button(GTK_GESTURE_SINGLE(edge), 1);
    g_signal_connect(edge, "pressed", G_CALLBACK(drawer_edge_pressed), state);
    gtk_widget_add_controller(GTK_WIDGET(state->window),
                              GTK_EVENT_CONTROLLER(edge));

    gtk_widget_set_vexpand(overlay, TRUE);
    gtk_box_append(GTK_BOX(root), overlay);

    if (g_start_module != NULL) {
        for (int i = 0; i < N_MODULES; i++) {
            if (g_strcmp0(modules[i].id, g_start_module) == 0) {
                open_module(state, &modules[i]);
                break;
            }
        }
    } else if (g_start_tab >= 0 &&
        g_start_tab < gtk_notebook_get_n_pages(GTK_NOTEBOOK(state->notebook))) {
        gtk_notebook_set_current_page(GTK_NOTEBOOK(state->notebook),
                                      g_start_tab);
    }

    /* Toast stack floats above the drawer. */
    state->toast_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_set_halign(state->toast_box, GTK_ALIGN_END);
    gtk_widget_set_valign(state->toast_box, GTK_ALIGN_END);

    state->event_drawer = NULL;
    GtkWidget *drawer = build_event_drawer(state);
    gtk_box_append(GTK_BOX(root), drawer);
    gtk_box_append(GTK_BOX(root), state->toast_box);

    /* A visual self-check for the notification layer, off unless asked for.
       IMSISTING_TOAST_DEMO=1 raises one toast of each severity at startup,
       so the component can be looked at without having to navigate to a
       button and run a real command to produce one. */
    if (g_getenv("IMSISTING_TOAST_DEMO") != NULL) {
        show_toast_full(state, "Dependency Manager",
                        "completed — 28 present, 3 missing, 2 broken", "ok");
        show_toast_full(state, "grgsm_decode",
                        "gnuradio present but no gr-gsm OOT blocks (import grgsm fails)",
                        "warn");
        show_toast_full(state, "Install Missing", "failed (exit 1)", "error");
    }

    /* The card, drawn in two halves: the stylesheet gives the header the top
       corners and this box the bottom ones. See "the frame" in style.css. */
    gtk_widget_add_css_class(root, "app-root");
    gtk_window_set_child(GTK_WINDOW(state->window), root);
}

static void
boot_check_index(AppState *state, GtkApplication *app)
{
    (void) app;
    report_index_drift(state);
    append_event(state, "IMSIsting started — modules are standalone scripts "
                        "in modules/; the GUI is a view over them.");
}

static void
boot_poll_status(AppState *state, GtkApplication *app)
{
    (void) app;

    /* Collect the probe splash_begin started. It has had the whole interface
       build to finish, so this read is short - and if it somehow is not, the
       child is what this stage is waiting for anyway. */
    if (state->radio_prefetch_fd >= 0) {
        GString *out = g_string_new(NULL);
        char buf[4096];
        ssize_t got;
        while ((got = read(state->radio_prefetch_fd, buf, sizeof buf)) > 0)
            g_string_append_len(out, buf, got);
        close(state->radio_prefetch_fd);
        state->radio_prefetch_fd = -1;
        if (state->radio_prefetch_pid > 0) {
            g_spawn_close_pid(state->radio_prefetch_pid);
            state->radio_prefetch_pid = 0;
        }
        if (out->len > 0) {
            g_free(state->radio_prefetch);
            state->radio_prefetch = g_string_free(out, FALSE);
        } else {
            g_string_free(out, TRUE);
        }
    }
    /* Cheap: every value is a --status-tsv verb that returns in well under
       100 ms. */
    status_poll(state);
    state->status_source = g_timeout_add_seconds(3, status_poll, state);
    /* Its own once-a-second clock, so the age on the strip keeps climbing
       even when a poll is stuck inside a module that will not answer. */
    g_timeout_add_seconds(1, status_freshness_tick, state);
}

/* The Overview is the tab the Casebook opens on, so switch-page never fires
   for it. Filling it from a short timeout rather than here puts the window on
   screen first: the fill forks four processes, and doing it inline would hold
   the first paint behind them - which is the cost this whole exercise is
   about removing. Idle would not do; a frame is painted from the frame clock,
   and a timeout is the only ordering that is not a guess. */
static gboolean
boot_fill_overview(gpointer data)
{
    AppState *state = data;
    if (state->window != NULL && state->casebook_tabs != NULL &&
        !(state->casebook_filled & (1u << CASEBOOK_TAB_OVERVIEW)))
        casebook_refresh_tab(state, CASEBOOK_TAB_OVERVIEW);
    return G_SOURCE_REMOVE;
}

static void
boot_present(AppState *state, GtkApplication *app)
{
    /* With a splash on screen the window is not shown from here: it would be
       up, and painting, while the splash still had seconds to run, and the two
       would be visible at once - the window is the larger of the two, so its
       edges show around the splash. splash_close is what puts it up. */
    if (state->splash_window == NULL)
        gtk_window_present(GTK_WINDOW(state->window));
    (void) app;
}

/* The bar's stages, in order. Each label is what the step does; the
   percentage is the step's place in this list, so adding a stage lengthens
   the sequence rather than making the last one lie. */
static const struct {
    const char *label;
    void (*run)(AppState *state, GtkApplication *app);
} boot_steps[] = {
    { "restoring the last session", boot_restore_session },
    { "loading the stylesheet",     boot_load_css        },
    { "building the interface",     boot_build_ui        },
    { "checking the module index",  boot_check_index     },
    { "polling the radio",          boot_poll_status     },
    { "ready",                      boot_present         },
};

#define SPLASH_MIN_STEP_MS 165  /* a stage stays up at least this long */
#define SPLASH_TAIL_MS     260  /* pause on the full bar before it goes */
#define SPLASH_FRAME_MS     16
/* A splash that blinks out in half a second reads as a flash, not as a title.
   The boot is usually over inside three seconds, so the splash is held to
   this regardless - the work being finished is not the splash's cue to go. */
#define SPLASH_MIN_TOTAL_MS 6000
/* If the film never reports an end (no decoder, a truncated file) the splash
   still has to let go. */
#define SPLASH_VIDEO_CAP_MS 13000

/* One of these is printed at the bottom left of the film, drawn fresh each
   launch, so that two starts of the same program do not say the same thing.
   The claims and their citations are the cards'; do not soften them. */
typedef struct {
    const char *title;
    const char *body;
} SplashFact;

static const SplashFact splash_facts[] = {
    { "the mechanism",
      "GSM authenticates the subscriber to the network. It never authenticates "
      "the network to the subscriber. A phone attaches to whichever cell proves "
      "strongest, and no part of the 2G air interface proves that cell belongs "
      "to its operator. 3GPP TS 43.020" },
    { "what a catcher is, stated honestly",
      "An IMSI catcher is not a device that reads a SIM. It is a base station "
      "that wins a selection contest \u2014 same broadcast channel, closer, louder. "
      "Everything it learns, it learns because the phone was asked and "
      "answered." },
    { "where the identity comes from",
      "The TMSI exists so the IMSI does not have to travel. It is a 32-bit "
      "alias the network assigns, valid inside one location area and nowhere "
      "else. On 2G the IMSI still crosses the air in the clear whenever the "
      "network asks for it." },
    { "mutual authentication, and what it forced",
      "UMTS added the missing half: the phone verifies the network with AUTN. "
      "That is why the practical attacks moved from impersonate the tower to "
      "make the phone believe the tower is old \u2014 a downgrade to 2G restores "
      "the one-way world." },
    { "5G fixed the identity, not the problem",
      "5G stops broadcasting the permanent identity: the SUCI is the SUPI "
      "encrypted to the home network's public key (ECIES, profile A or B), so "
      "a passive receiver cannot resolve it back to a subscriber. It does not "
      "follow that a false gNB is harmless. TS 33.501 \u00a76.12" },
    { "the distance clue nobody uses",
      "GSM timing advance is measured in bit periods. One step is 3.69 \u00b5s of "
      "round trip \u2014 about 554 metres of range, 63 steps to the 35 km cell "
      "limit. It is the only distance information the 2G air interface hands "
      "out for free." },
    { "where encryption stops",
      "A5 protects the link between the phone and the base station and nothing "
      "else. The ciphertext ends at the tower. From there your traffic is the "
      "operator's plaintext, and the cipher choice was the network's, not "
      "yours." },
};

/* The baseband chip - the second computer in every handset. */
static const SplashFact splash_chip_facts[] = {
    { "a second computer, and it has the microphone",
      "The modem is not a peripheral of the application processor. It has its "
      "own CPU, its own RTOS, its own firmware and its own memory, and the "
      "audio path runs through it \u2014 which is why a compromised baseband is a "
      "compromised microphone, not one you reach through the OS." },
    { "it has to answer strangers",
      "A cell the phone has never met tells it how to behave, and the modem "
      "parses that before it has authenticated anything: SIBs and paging in "
      "every generation, NAS before the security mode command. A rogue base "
      "station that sends a malformed one attacks a parser written by a chip "
      "vendor." },
    { "a fix is a firmware blob",
      "A modem defect is repaired in a signed image the vendor builds and the "
      "carrier stages, months after the disclosure. The phone's OS version "
      "says nothing about it: the two are on different release schedules, and "
      "the modem's build is usually far older than the system's." },
    { "the air is the cheap path",
      "Reaching a modem over the air costs a radio and a specification; "
      "reaching it through a cable costs physical possession. The 2023 Exynos "
      "modem disclosures were reachable from a malicious base station \u2014 "
      "remote, no user action, and the phone cannot tell a well-formed hostile "
      "message from a friendly one." },
    { "the link to the application processor",
      "The operating system does not see inside the modem. It talks to it over "
      "a proprietary interface (DIAG, QMI) across shared memory or a "
      "high-speed link, and that interface has its own parser and its own "
      "bugs; the 2021 Qualcomm flaws lived there, not in the radio." },
};

/* IMSIsting itself - how the toolkit is put together, and what it refuses. */
static const SplashFact splash_kit_facts[] = {
    { "it says when something failed",
      "Every module answers in TSV, and a failure comes back as a failure: no "
      "radio, no dependency, a refused verb \u2014 an ERROR line the interface "
      "renders as an error rather than as an empty result. A toolkit that "
      "reports 0 cells when it means it could not run is worse than one that "
      "reports nothing." },
    { "every button is a command",
      "Nothing is locked behind the interface. Each card invokes one "
      "standalone, ./modules/02_cell_recon.sh --plmn 208-01, and "
      "tools/check-verbs.sh verifies that the verbs the window binds to exist "
      "and are documented in the module's own header. If you can click it, you "
      "can script it." },
    { "the modules do not need the interface",
      "All 57 modules are shell scripts with no GUI dependency; the window is "
      "a view over them, not the program. That is a constraint, not an "
      "accident \u2014 a research tool has to survive being run over ssh, inside a "
      "pipeline, or in a container with no display at all." },
    { "hardware is stated, not assumed",
      "01_radio enumerates what is genuinely attached \u2014 HackRF, BladeRF, "
      "LimeSDR, USRP, RTL-SDR, SoapySDR \u2014 and the status strip shows SDR, TX, "
      "FREQ, CELLS and GPS before any work starts. Modules that need a radio "
      "say so and stop; the ones that only read files run anywhere." },
    { "the casebook keeps the chain, not just the files",
      "Cases, targets, evidence, captures, timeline, alerts, nodes and "
      "reports, with an authorisation reference recorded when the case is "
      "created, so the record says what was done, against what, and under "
      "whose authority. Evidence stays in loot/ as plain files; the casebook "
      "indexes them." },
};

/* An SDR - what the hardware decides before any software runs. */
static const SplashFact splash_sdr_facts[] = {
    { "the ADC sets your ceiling",
      "Sample rate is instantaneous bandwidth and bit depth is dynamic range, "
      "and neither can be argued with afterwards. An 8-bit converter tops out "
      "near 50 dB of signal-to-noise, a 12-bit one near 74. Where a strong "
      "cell and the weak one you want differ by 60 dB, that gap is the whole "
      "experiment." },
    { "the antenna beats the radio",
      "At 900 MHz a kilometre of free space costs about 91 dB, so a handset's "
      "0.2 W arrives 68 dB down \u2014 and every dBi you fail to collect is signal "
      "you never sampled. A wideband antenna hears everything badly; a tuned "
      "quarter-wave for one band usually beats it where it matters." },
    { "half duplex cannot sit in the middle",
      "Being a base station means answering inside the same exchange you are "
      "listening to. A radio that transmits or receives \u2014 HackRF, RTL-SDR \u2014 "
      "cannot do both at once, so it can imitate a network in bursts but not "
      "hold a conversation. Full duplex, or two radios, is the price." },
    { "time is the hard part",
      "GSM's bit period is 48/13 \u00b5s, about 3.7 \u00b5s, and a handset expects a "
      "burst inside its own slot. A sample clock that drifts by a fraction of "
      "that produces a base station the phone refuses to hear, which is why "
      "timing is disciplined against a reference and not trusted to a "
      "crystal." },
    { "a radio is not a decoder",
      "An SDR delivers samples; the protocol is a stack above them, and srsRAN "
      "or OpenAirInterface does the decoding, not the hardware. Most SDRs stop "
      "at 6 GHz, which puts NR FR2 out of reach entirely \u2014 the honest module "
      "says which of the two it can see." },
};

/* The films. One is chosen per launch, and the card that goes with it comes
   from its own set, so a launch does not repeat the film or the sentence. */
typedef struct {
    const char *film;
    const SplashFact *facts;
    guint n_facts;
} SplashFilm;

static const SplashFilm splash_films[] = {
    { "/com/imsisting/native/imsisting_splash2.mp4",
      splash_facts,      G_N_ELEMENTS(splash_facts)      },  /* the network */
    { "/com/imsisting/native/imsisting_splash3.mp4",
      splash_chip_facts, G_N_ELEMENTS(splash_chip_facts) },  /* the chip     */
    { "/com/imsisting/native/imsisting_splash4.mp4",
      splash_kit_facts,  G_N_ELEMENTS(splash_kit_facts)  },  /* the toolkit  */
    { "/com/imsisting/native/imsisting_splash5.mp4",
      splash_sdr_facts,  G_N_ELEMENTS(splash_sdr_facts)  },  /* the SDR      */
};

/* The still is a splash in its own right, not a pre-roll and not a fallback
   that happens first: it takes its turn in the same draw as the four films,
   and it draws its card from a randomly picked set because it has no film of
   its own to belong to. It is also what plays when the media backend cannot
   give us a window, which is why it always has to work. */
static const SplashFilm splash_still = {
    NULL, splash_facts, G_N_ELEMENTS(splash_facts)
};

static char *
splash_fact_markup(const SplashFact *facts, guint n_facts)
{
    guint i = (guint) g_random_int_range(0, (gint32) n_facts);
    g_autofree char *title = g_markup_escape_text(facts[i].title, -1);
    g_autofree char *body  = g_markup_escape_text(facts[i].body, -1);
    return g_strdup_printf(
        "<span size=\"large\" foreground=\"#6fa8ff\">%s</span>\n%s",
        title, body);
}

/* The card at the foot of every splash. `bottom` is what keeps it clear of
   the loading bar on the still, where both share the lower third. */
static GtkWidget *
splash_fact_label(const SplashFact *facts, guint n_facts, int bottom)
{
    g_autofree char *markup = splash_fact_markup(facts, n_facts);
    GtkWidget *fact = gtk_label_new(NULL);

    gtk_label_set_markup(GTK_LABEL(fact), markup);
    gtk_label_set_wrap(GTK_LABEL(fact), TRUE);
    gtk_label_set_wrap_mode(GTK_LABEL(fact), PANGO_WRAP_WORD_CHAR);
    gtk_label_set_xalign(GTK_LABEL(fact), 0.0);
    gtk_label_set_yalign(GTK_LABEL(fact), 1.0);
    gtk_label_set_justify(GTK_LABEL(fact), GTK_JUSTIFY_LEFT);
    gtk_widget_set_size_request(fact, 440, -1);
    gtk_widget_set_halign(fact, GTK_ALIGN_START);
    gtk_widget_set_valign(fact, GTK_ALIGN_END);
    gtk_widget_set_margin_start(fact, 44);
    gtk_widget_set_margin_bottom(fact, bottom);
    gtk_widget_set_margin_end(fact, 24);
    gtk_widget_add_css_class(fact, "splash-fact");
    return fact;
}

static void
splash_close(AppState *state)
{
    if (state->splash_source != 0) {
        g_source_remove(state->splash_source);
        state->splash_source = 0;
    }
    if (state->splash_window != NULL) {
        gtk_window_destroy(GTK_WINDOW(state->splash_window));
        state->splash_window = NULL;
    }
    state->splash_area = NULL;
    state->splash_label = NULL;
    /* Owned by the video widget, which the destroyed window took with it. */
    state->splash_media = NULL;
    state->splash_video = FALSE;
    /* The handover. The main window is built by now; it has only been kept
       off the screen so that the splash could have its time to itself. */
    if (state->window != NULL)
        gtk_window_present(GTK_WINDOW(state->window));
    /* The Overview's fill forks four processes. It is started here rather than
       when the window was built, so that it never runs while the splash is
       still on screen - a film that stutters because four shells were forked
       under it is worse than an Overview that fills a moment later. */
    g_timeout_add(300, boot_fill_overview, state);
    if (state->splash_art != NULL) {
        cairo_surface_destroy(state->splash_art);
        state->splash_art = NULL;
    }
    if (state->splash_logo != NULL) {
        cairo_surface_destroy(state->splash_logo);
        state->splash_logo = NULL;
    }
    if (state->splash_bg != NULL) {
        cairo_surface_destroy(state->splash_bg);
        state->splash_bg = NULL;
        state->splash_bg_w = state->splash_bg_h = 0;
    }
}

static gboolean
splash_tick(gpointer data)
{
    AppState *state = data;
    guint n = G_N_ELEMENTS(boot_steps);
    gint64 now = g_get_monotonic_time();

    /* The film's own length is measured from the moment it had something to
       show rather than from the moment the window opened, because the media
       backend takes a variable second or two to get there. */
    if (state->splash_media != NULL &&
        gtk_media_stream_is_prepared(state->splash_media) &&
        state->splash_film_us == 0)
        state->splash_film_us = now;

    /* The film draws itself and needs no easing; the still splash's bar is
       the only thing this tick animates. */
    if (!state->splash_video) {
        /* The bar reports the stage that is *running*, not the one before it,
           so it is already full while the last stage presents the window. The
           main window's first paint is the one thing here that has to block,
           and at that moment a bar still climbing would look like the freeze
           it is. */
        double target = n > 0
                      ? (double) (state->splash_step + 1) / (double) n : 1.0;
        if (target > 1.0)
            target = 1.0;
        double gap = target - state->splash_shown;
        if (gap > 0.0) {
            /* Eased, but with a floor under the step. Pure exponential easing
               never quite arrives, and at a low frame rate the tail of it is
               seconds long - the bar would reach 99% and sit there while the
               boot waited on it. */
            state->splash_shown += MAX(gap * 0.22, 0.05);
            if (state->splash_shown > target)
                state->splash_shown = target;
        }
    }

    if (state->splash_step < n &&
        (now - state->splash_stage_us) / 1000 >= SPLASH_MIN_STEP_MS) {
        boot_steps[state->splash_step].run(state, state->splash_app);
        state->splash_step++;
        state->splash_stage_us = now;
        state->splash_label = state->splash_step < n
                            ? boot_steps[state->splash_step].label : NULL;
        /* The last stage presents the main window, and that first paint is the
           one thing here that has to block the loop. The bar is filled before
           it starts, so the pause that follows reads as "done" and not as a
           bar that stopped climbing. */
        if (!state->splash_video && state->splash_step + 1 >= n)
            state->splash_shown = 1.0;
    }

    if (state->splash_step >= n &&
        (now - state->splash_start_us) / 1000 >= SPLASH_MIN_TOTAL_MS) {
        gboolean finished;
        if (state->splash_video) {
            /* The GStreamer backend does not always report the end of a
               stream, so the film's own duration is what decides; the cap is
               only there so that a decoder that never finishes cannot keep
               the splash on screen. */
            GtkMediaStream *film = state->splash_media;
            gint64 length = film != NULL ? gtk_media_stream_get_duration(film) : -1;
            gboolean ran_out = film != NULL && state->splash_film_us > 0 &&
                               length > 0 &&
                               now - state->splash_film_us >= length;
            finished = film == NULL
                    || gtk_media_stream_get_ended(film)
                    || ran_out
                    || gtk_media_stream_get_error(film) != NULL
                    || (now - state->splash_start_us) / 1000 >= SPLASH_VIDEO_CAP_MS;
        } else {
            finished = state->splash_shown >= 0.999 &&
                       (now - state->splash_stage_us) / 1000 >= SPLASH_TAIL_MS;
        }
        if (finished) {
            splash_close(state);
            return G_SOURCE_REMOVE;
        }
    }

    if (state->splash_area != NULL)
        gtk_widget_queue_draw(state->splash_area);

    /* Re-armed rather than returned G_SOURCE_CONTINUE: a stage can present
       the main window, and anything that closes the splash from inside that
       has to be able to cancel this source by id. */
    state->splash_source = g_timeout_add(SPLASH_FRAME_MS, splash_tick, state);
    return G_SOURCE_REMOVE;
}

/* The still splash: the artwork, the logo over it, a card, and the boot's own
   progress at the foot of the frame. */
static void
splash_window_art(AppState *state, GtkApplication *app,
                  const SplashFact *facts, guint n_facts)
{
    /* Loaded from the binary's own resources, like the module icons and for
       the same reason: the splash is the first thing on screen, before any
       theme, working directory or installed copy can be trusted. */
    GdkTexture *art = gdk_texture_new_from_resource(
        "/com/imsisting/native/imsisting_splash.png");
    if (art != NULL) {
        state->splash_art = splash_surface(art);
        g_object_unref(art);
    }
    GdkTexture *logo = gdk_texture_new_from_resource(
        "/com/imsisting/native/imsisting_logo.png");
    if (logo != NULL) {
        state->splash_logo = splash_surface(logo);
        g_object_unref(logo);
    }

    GtkWidget *area = gtk_drawing_area_new();
    gtk_drawing_area_set_content_width(GTK_DRAWING_AREA(area), 960);
    gtk_drawing_area_set_content_height(GTK_DRAWING_AREA(area), 540);
    gtk_drawing_area_set_draw_func(GTK_DRAWING_AREA(area), splash_draw,
                                   state, NULL);

    /* The card rides over the drawing, the same way it does over a film, and
       sits high enough to leave the loading bar the bottom of the frame. */
    GtkWidget *overlay = gtk_overlay_new();
    gtk_overlay_set_child(GTK_OVERLAY(overlay), area);
    gtk_overlay_add_overlay(GTK_OVERLAY(overlay),
                            splash_fact_label(facts, n_facts, 152));

    GtkWidget *win = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(win), "IMSIsting");
    gtk_window_set_decorated(GTK_WINDOW(win), FALSE);
    gtk_window_set_resizable(GTK_WINDOW(win), FALSE);
    gtk_window_set_default_size(GTK_WINDOW(win), 960, 540);
    gtk_window_set_child(GTK_WINDOW(win), overlay);
    /* A film has no first frame for a moment; without this the window shows
       the theme's background in that gap instead of the near-black the films
       are drawn on. */
    gtk_widget_add_css_class(win, "splash-window");

    state->splash_window = win;
    state->splash_area = area;
}

/* The film splash. GtkVideo plays it through the media backend (GStreamer) -
   the one dependency in this file that can be absent, which is why the caller
   falls back to the still if no window comes back. Nothing is drawn over the
   film: its own caption says LOADING, and the only thing added is the fact. */
/* GtkVideo is the obvious widget for a film and the wrong one here: it carries
   a control bar that fades in over the picture on hover - a play/pause button,
   an orange transport with a running clock and a mute toggle, floating on top
   of a splash screen. A GtkMediaStream is itself a GdkPaintable, so a
   GtkPicture shows exactly the same frames with nothing drawn over them. The
   price is the piece GtkVideo would otherwise do for us: the stream has to be
   realized against a surface by hand before it will play. */
static void
splash_film_mapped(GtkWidget *widget, gpointer user_data)
{
    GtkMediaStream *film = user_data;
    GdkSurface *surface = gtk_native_get_surface(gtk_widget_get_native(widget));
    if (surface == NULL)
        return;
    gtk_media_stream_realize(film, surface);
    gtk_media_stream_play(film);
}

static void
splash_film_unmapped(GtkWidget *widget, gpointer user_data)
{
    GtkMediaStream *film = user_data;
    GdkSurface *surface = gtk_native_get_surface(gtk_widget_get_native(widget));
    gtk_media_stream_pause(film);
    if (surface != NULL)
        gtk_media_stream_unrealize(film, surface);
}

static void
splash_window_video(AppState *state, GtkApplication *app,
                    const SplashFilm *choice)
{
    const char *path = choice->film;
    if (!g_resources_get_info(path, G_RESOURCE_LOOKUP_FLAGS_NONE,
                              NULL, NULL, NULL))
        return;                     /* not built in: fall back to the still */

    GtkMediaStream *film = gtk_media_file_new_for_resource(path);
    if (film == NULL)
        return;
    /* A launch that makes a noise is a launch that gets muted, and the film
       carries an audio track with nothing to say. */
    gtk_media_stream_set_muted(film, TRUE);
    gtk_media_stream_set_loop(film, FALSE);

    GtkWidget *video = gtk_picture_new_for_paintable(GDK_PAINTABLE(film));
    gtk_picture_set_content_fit(GTK_PICTURE(video), GTK_CONTENT_FIT_COVER);
    gtk_picture_set_can_shrink(GTK_PICTURE(video), TRUE);
    gtk_widget_set_size_request(video, 960, 540);
    gtk_widget_set_hexpand(video, TRUE);
    gtk_widget_set_vexpand(video, TRUE);
    g_signal_connect(video, "map", G_CALLBACK(splash_film_mapped), film);
    g_signal_connect(video, "unmap", G_CALLBACK(splash_film_unmapped), film);

    GtkWidget *fact = splash_fact_label(choice->facts, choice->n_facts, 40);

    /* No stand-in artwork here. The still used to be laid over the film until
       the decoder produced its first frame, so every launch opened on the same
       picture before showing the one it had chosen. The window is dark and the
       card is up from the first frame instead; the film fades into its own
       place once the backend is ready. */
    GtkWidget *overlay = gtk_overlay_new();
    gtk_overlay_set_child(GTK_OVERLAY(overlay), video);
    gtk_overlay_add_overlay(GTK_OVERLAY(overlay), fact);

    GtkWidget *win = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(win), "IMSIsting");
    gtk_window_set_decorated(GTK_WINDOW(win), FALSE);
    gtk_window_set_resizable(GTK_WINDOW(win), FALSE);
    gtk_window_set_default_size(GTK_WINDOW(win), 960, 540);
    gtk_window_set_child(GTK_WINDOW(win), overlay);
    /* A film has no first frame for a moment; without this the window shows
       the theme's background in that gap instead of the near-black the films
       are drawn on. */
    gtk_widget_add_css_class(win, "splash-window");

    state->splash_window = win;
    state->splash_area = NULL;
    state->splash_media = film;      /* the video widget holds the reference */
    state->splash_video = TRUE;
}

static void
splash_begin(AppState *state, GtkApplication *app)
{
    state->splash_app = app;
    state->radio_prefetch_fd = -1;
    state->splash_video = FALSE;
    state->splash_media = NULL;
    state->splash_film_us = 0;
    state->splash_start_us = g_get_monotonic_time();

    /* Start the radio probe first: it is the one cold call in the boot (six
       drivers, about two seconds) and everything else here can run while it
       does. boot_poll_status collects it. */
    {
        g_autofree char *script = module_script_path("01_radio");
        if (script != NULL && g_file_test(script, G_FILE_TEST_IS_EXECUTABLE)) {
            const char *argv[3] = { script, "--status-tsv", NULL };
            g_autoptr(GError) error = NULL;
            if (!g_spawn_async_with_pipes(NULL, (char **) argv, NULL,
                    G_SPAWN_SEARCH_PATH | G_SPAWN_DO_NOT_REAP_CHILD |
                    G_SPAWN_STDERR_TO_DEV_NULL, NULL, NULL,
                    &state->radio_prefetch_pid, NULL,
                    &state->radio_prefetch_fd, NULL, &error))
                state->radio_prefetch_fd = -1;
        }
    }

    /* A splash every launch, chosen from five: the four films and the still,
       each with the card that belongs to it. IMSISTING_SPLASH=art (or 1) pins
       the still and =2..=5 pins a film, which is how one is looked at without
       relaunching until it comes round. If no window comes back - the media
       backend absent, the film not built in - the still is built instead. */
    /* Where the splash comes from: the settings file decides, the environment
       overrides it - an explicit IMSISTING_SPLASH for one launch outranks a
       stored preference, including a stored "off", because saying it on the
       command line is a deliberate act about this run. */
    const char *which = g_getenv("IMSISTING_SPLASH");
    const char *art = (which == NULL) ? settings_get("ui.splash_art", "all") : NULL;
    gboolean splash_off =
        g_getenv("IMSISTING_NO_SPLASH") != NULL ||
        (which == NULL && !settings_flag("ui.splash", TRUE));
    gboolean pin_still = !splash_off &&
        ((which != NULL && (g_ascii_strcasecmp(which, "art") == 0 ||
                            g_strcmp0(which, "1") == 0)) ||
         (art != NULL && g_strcmp0(art, "still") == 0));
    gboolean films_only = (art != NULL && g_strcmp0(art, "films") == 0);

    if (pin_still) {
        const SplashFilm *r = &splash_films[g_random_int_range(
            0, (gint32) G_N_ELEMENTS(splash_films))];
        splash_window_art(state, app, r->facts, r->n_facts);
    } else if (!splash_off) {
        gint32 n_films = (gint32) G_N_ELEMENTS(splash_films);
        const SplashFilm *choice = NULL;

        if (which != NULL && which[0] >= '2' && which[0] <= '5' &&
            which[1] == '\0')
            choice = &splash_films[which[0] - '2'];
        else if (films_only)
            choice = &splash_films[g_random_int_range(0, n_films)];
        else if (g_random_int_range(0, n_films + 1) == n_films)
            choice = &splash_still;
        else
            choice = &splash_films[g_random_int_range(0, n_films)];

        if (choice == &splash_still) {
            const SplashFilm *r = &splash_films[g_random_int_range(0, n_films)];
            splash_window_art(state, app, r->facts, r->n_facts);
        } else {
            splash_window_video(state, app, choice);
        }
    }
    if (!splash_off && state->splash_window == NULL) {
        const SplashFilm *r = &splash_films[g_random_int_range(
            0, (gint32) G_N_ELEMENTS(splash_films))];
        splash_window_art(state, app, r->facts, r->n_facts);
    }

    if (splash_off || state->splash_window == NULL) return;

    gtk_window_present(GTK_WINDOW(state->splash_window));

    state->splash_shown = 0.0;
    state->splash_step = 0;
    state->splash_label = boot_steps[0].label;
    /* Starts one stage-interval out, so the art is on screen and read before
       the first label replaces it. */
    state->splash_stage_us = g_get_monotonic_time();
    state->splash_source = g_timeout_add(SPLASH_FRAME_MS, splash_tick, state);
}

static void
on_activate(GtkApplication *app, gpointer user_data)
{
    AppState *state = user_data;

    if (state->window != NULL) {
        gtk_window_present(GTK_WINDOW(state->window));
        return;
    }
    if (state->splash_window != NULL) {
        gtk_window_present(GTK_WINDOW(state->splash_window));
        return;
    }

    /* The escape hatch matters more than usual here: with the splash on, the
       window cannot be reached until the boot finishes, so a splash that
       misbehaves would have to be waited out on every launch. It is the
       environment variable and the setting together: either one turns it off,
       and neither can be set by accident from the other's direction. The same
       condition as the one splash_begin() uses to pick the art, restated here
       because this is a different function and the decision is about whether
       to call it at all. */
    if (g_getenv("IMSISTING_NO_SPLASH") != NULL ||
        (g_getenv("IMSISTING_SPLASH") == NULL &&
         !settings_flag("ui.splash", TRUE))) {
        for (guint i = 0; i < G_N_ELEMENTS(boot_steps); i++)
            boot_steps[i].run(state, app);
        /* Normally splash_close starts this; with no splash there is nobody
           else to do it. */
        g_timeout_add(600, boot_fill_overview, state);
        return;
    }

    splash_begin(state, app);
}

static void
on_shutdown(GtkApplication *app, gpointer user_data)
{
    AppState *state = user_data;
    (void) app;
    if (state->stderr_fd >= 0)
        close(state->stderr_fd);
    if (state->running != NULL) {
        g_ptr_array_unref(state->running);
        state->running = NULL;
    }
    if (state->status_source != 0) {
        g_source_remove(state->status_source);
        state->status_source = 0;
    }
    if (state->live_socket != NULL)
        live_stop(state, FALSE);
}

/* The two faces the interface uses are compiled in, but fontconfig only reads
   files. Each is written once into the per-user cache directory and registered
   for this process only, so a machine with neither font installed still shows
   the interface as designed -- and nothing is installed system-wide. */
static void
imsisting_load_fonts(void)
{
    static const char *const files[] = {
        "fonts/Orbitron-Regular.ttf",
        "fonts/Orbitron-Bold.ttf",
        "fonts/Neuropol-Regular.otf",
    };
    g_autofree char *dir = g_build_filename(g_get_user_cache_dir(),
                                            "imsisting", "fonts", NULL);

    g_mkdir_with_parents(dir, 0700);

    for (gsize i = 0; i < G_N_ELEMENTS(files); i++) {
        g_autofree char *res = g_strdup_printf("/com/imsisting/native/%s",
                                               files[i]);
        const char *slash = strrchr(files[i], '/');
        g_autofree char *path = g_build_filename(
            dir, slash != NULL ? slash + 1 : files[i], NULL);
        g_autoptr(GBytes) bytes = g_resources_lookup_data(
            res, G_RESOURCE_LOOKUP_FLAGS_NONE, NULL);
        const char *data;
        GStatBuf st;
        gsize len = 0;

        if (bytes == NULL)
            continue;

        data = g_bytes_get_data(bytes, &len);

        /* Rewritten only when it is missing or a different size, so an
           ordinary start costs one stat() per face and no writes. */
        if (g_stat(path, &st) != 0 || st.st_size != (goffset) len)
            g_file_set_contents(path, data, (gssize) len, NULL);

        FcConfigAppFontAddFile(NULL, (const FcChar8 *) path);
    }
}

int
main(int argc, char **argv)
{
    /* Before the interface, because density, the splash and the toast rules
       are all read from here. */
    settings_load();
    AppState state = { 0 };
    state.stderr_fd = -1;
    g_app_state = &state;

    /* --selftest: verify the GUI's own invariants without a display. This is
       what the tree-wide selftest runner calls, so the GUI is covered by the
       same net as the shell modules. */
    for (int i = 1; i < argc; i++) {
        if (g_strcmp0(argv[i], "--selftest") == 0) {
            int bad = 0;
            printf("gui-modules\t%s\n",
                   N_MODULES > 0 ? "PASS" : "FAIL");

            if (MODULE_INDEX_N <= 0) {
                printf("gui-module-index\tFAIL no index entries\n");
                bad++;
            } else {
                printf("gui-module-index\tPASS %d entries\n", MODULE_INDEX_N);
            }

            /* Every module in the C table must be in the generated index,
               or the sidebar and the index disagree. */
            for (int i2 = 0; i2 < N_MODULES; i2++) {
                gboolean found = FALSE;
                for (int j = 0; j < MODULE_INDEX_N; j++) {
                    if (g_strcmp0(module_index[j].id, modules[i2].id) == 0) {
                        found = TRUE; break;
                    }
                }
                if (!found) {
                    printf("gui-table-%s\tFAIL not in generated index\n",
                           modules[i2].id);
                    bad++;
                }
            }

            /* Every script the table names must exist and be executable. A
               missing one is dimmed in the sidebar, but it is still a failure
               worth reporting. */
            for (int i2 = 0; i2 < N_MODULES; i2++) {
                g_autofree char *p = module_script_path(modules[i2].id);
                if (!g_file_test(p, G_FILE_TEST_IS_EXECUTABLE)) {
                    printf("gui-script-%s\tFAIL %s not executable\n",
                           modules[i2].id, p);
                    bad++;
                }
            }

            printf("RESULT\t%s\n", bad == 0 ? "PASS" : "FAIL");
            return bad == 0 ? 0 : 1;
        }
        if (g_strcmp0(argv[i], "--tab") == 0 && i + 1 < argc) {
            g_start_tab = atoi(argv[i + 1]);
            /* fall through to run the app */
        }
        if (g_strcmp0(argv[i], "--module") == 0 && i + 1 < argc) {
            g_start_module = argv[i + 1];
            /* fall through to run the app */
        }
        if (g_strcmp0(argv[i], "--list-modules") == 0) {
            for (int j = 0; j < N_MODULES; j++)
                printf("%s\t%s\t%s\n", modules[j].id, modules[j].category,
                       modules[j].name);
            return 0;
        }
    }

    stderr_redirect(&state);
    register_all_modules();
    imsisting_load_fonts();

    GtkApplication *app = gtk_application_new("com.imsisting.native",
                                              G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(on_activate), &state);
    g_signal_connect(app, "shutdown", G_CALLBACK(on_shutdown), &state);

    g_timeout_add(500, stderr_poll, &state);

    /* Strip our own flags before GApplication's option parser sees them.
       An unregistered option does not warn and continue -- g_application_run
       fails outright with "Unknown option", which is a silent exit here
       because stderr is already redirected to the diagnostics file. */
    g_autofree char **app_argv = g_new0(char *, argc + 1);
    int app_argc = 0;
    for (int i = 0; i < argc; i++) {
        if ((g_strcmp0(argv[i], "--tab") == 0 ||
             g_strcmp0(argv[i], "--module") == 0) && i + 1 < argc) {
            i++; continue;
        }
        app_argv[app_argc++] = argv[i];
    }
    app_argv[app_argc] = NULL;

    int status = g_application_run(G_APPLICATION(app), app_argc, app_argv);
    g_object_unref(app);
    return status;
}

/* ==================================================================== */
/*  REGISTRATION TABLE                                                  */
/* ==================================================================== */

/* ==================================================================== */
/*  DEPENDENCY MANAGER — the Packages view                              */
/*                                                                      */
/*  Built like wifisting's Dependencies page because it answers the same */
/*  question the same way: what is registered, what is installed, and a  */
/*  button on the line that fixes it. What differs is the data - this    */
/*  module's --status-tsv carries a level and a version as well as the   */
/*  package, so a row says more than installed or missing.               */
/*                                                                      */
/*  The read is asynchronous on purpose. On a cold machine (65 tools,    */
/*  each probed by the shell) that call has been measured at 35 seconds, */
/*  and a synchronous read would freeze the window for the whole of it.  */
/* ==================================================================== */

typedef struct {
    AppState   *state;
    const char *module_id;
    GtkWidget  *list;
    GtkWidget  *summary;
    GtkWidget  *search;
    GtkWidget  *critical;
    GtkWidget  *optional;
    GtkWidget  *status;         /* the page's own pill */
    GtkWidget  *refresh;
    GtkWidget  *busy;           /* spinner + message, hidden unless reading */
    GtkWidget  *busy_label;
    GtkWidget  *entry;          /* install by name */
    GSubprocess *process;
    guint       refresh_source;
} DepsPage;

typedef struct {
    DepsPage  *page;
    char      *tool;
    char      *package;
    char      *group;           /* "critical" or "optional" */
    char      *meta;            /* "level · version" */
    gboolean   installed;
} DepsRow;

static void deps_page_free(gpointer data);
static void deps_refresh(DepsPage *page);
static void deps_apply_filter(DepsPage *page);

static const char *
deps_field(char **f, guint i)
{
    return (f != NULL && i < g_strv_length(f)) ? f[i] : "";
}

static void
deps_clear_rows(DepsPage *page)
{
    GtkWidget *child = gtk_widget_get_first_child(page->list);

    while (child != NULL) {
        GtkWidget *next = gtk_widget_get_next_sibling(child);
        gtk_list_box_remove(GTK_LIST_BOX(page->list), child);
        child = next;
    }
}

static void
deps_row_free(gpointer data)
{
    DepsRow *row = data;

    g_free(row->tool);
    g_free(row->package);
    g_free(row->group);
    g_free(row->meta);
    g_free(row);
}

static gboolean
deps_row_matches(DepsRow *row)
{
    DepsPage *page = row->page;
    const char *query = gtk_editable_get_text(GTK_EDITABLE(page->search));
    gboolean show_critical = gtk_toggle_button_get_active(
        GTK_TOGGLE_BUTTON(page->critical));
    gboolean show_optional = gtk_toggle_button_get_active(
        GTK_TOGGLE_BUTTON(page->optional));
    gboolean group_ok =
        (g_strcmp0(row->group, "critical") == 0 && show_critical) ||
        (g_strcmp0(row->group, "optional") == 0 && show_optional);

    if (!group_ok)
        return FALSE;
    if (query == NULL || *query == '\0')
        return TRUE;

    {
        g_autofree char *needle = g_utf8_strdown(query, -1);
        g_autofree char *tool   = g_utf8_strdown(row->tool, -1);
        g_autofree char *pkg    = g_utf8_strdown(row->package, -1);

        return strstr(tool, needle) != NULL || strstr(pkg, needle) != NULL;
    }
}

static void
deps_apply_filter(DepsPage *page)
{
    GtkWidget *child = gtk_widget_get_first_child(page->list);
    while (child != NULL) {
        GtkWidget *next = gtk_widget_get_next_sibling(child);
        DepsRow *row = g_object_get_data(G_OBJECT(child), "deps-row");

        if (row != NULL)
            gtk_widget_set_visible(child, deps_row_matches(row));
        child = next;
    }
}

static void
deps_filter_changed(GtkWidget *widget, gpointer data)
{
    (void) widget;
    deps_apply_filter(data);
}

static void
deps_set_busy(DepsPage *page, gboolean busy, const char *message)
{
    if (page->busy != NULL)
        gtk_widget_set_visible(page->busy, busy);
    if (busy && message != NULL && page->busy_label != NULL)
        gtk_label_set_text(GTK_LABEL(page->busy_label), message);
    if (page->refresh != NULL)
        gtk_widget_set_sensitive(page->refresh, !busy);
}

/* The install leaves through the same door as every other privileged verb
   (group_verb_clicked -> pkexec, per the polkit rule), so this only has to
   arrange for the list to be re-read once the install has had time to
   land. */
static gboolean
deps_refresh_later(gpointer data)
{
    DepsPage *page = data;

    page->refresh_source = 0;
    deps_refresh(page);
    return G_SOURCE_REMOVE;
}

static void
deps_install_one_clicked(GtkButton *button, gpointer data)
{
    DepsRow *row = data;

    (void) button;
    if (row->package == NULL || *row->package == '\0')
        return;
    if (row->page->refresh_source != 0)
        g_source_remove(row->page->refresh_source);
    row->page->refresh_source = g_timeout_add_seconds(4, deps_refresh_later,
                                                      row->page);
}

static void
deps_install_named_clicked(GtkButton *button, gpointer data)
{
    DepsPage *page = data;
    const char *name = gtk_editable_get_text(GTK_EDITABLE(page->entry));
    g_autofree char *script = NULL;
    g_autofree char *label = NULL;
    const char *argv[4];

    (void) button;
    if (name == NULL || *name == '\0')
        return;

    script = module_script_path(page->module_id);
    if (script == NULL || !g_file_test(script, G_FILE_TEST_EXISTS))
        return;

    argv[0] = script;
    argv[1] = "--install-package";
    argv[2] = name;
    argv[3] = NULL;
    label = g_strdup_printf("%s --install-package %s", page->module_id, name);

    /* Privileged, because installing is: imsisting_action_run routes it
       through pkexec, which the polkit rule in tools/49-imsisting.rules
       matches on the module path. */
    imsisting_action_run(page->state, page->module_id, label, page->status,
                         argv, TRUE);
    gtk_editable_set_text(GTK_EDITABLE(page->entry), "");

    if (page->refresh_source != 0)
        g_source_remove(page->refresh_source);
    page->refresh_source = g_timeout_add_seconds(4, deps_refresh_later, page);
}

static GtkWidget *
deps_create_row(DepsPage *page, const char *group, const char *tool,
                const char *package, const char *meta, gboolean installed)
{
    GtkWidget *row      = gtk_list_box_row_new();
    GtkWidget *content  = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    GtkWidget *identity = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *name     = gtk_label_new(tool);
    GtkWidget *group_lbl = gtk_label_new(group);
    GtkWidget *status   = gtk_label_new(installed ? "INSTALLED" : "MISSING");
    GtkWidget *install  = gtk_button_new_with_label("Install");
    DepsRow   *entry    = g_new0(DepsRow, 1);
    g_autofree char *meta_text = g_strdup_printf("package: %s%s%s",
        package, (meta != NULL && *meta != '\0') ? "  ·  " : "",
        (meta != NULL) ? meta : "");
    GtkWidget *package_lbl = gtk_label_new(meta_text);

    gtk_widget_add_css_class(row, "deps-row");
    gtk_widget_add_css_class(name, "deps-name");
    gtk_widget_add_css_class(package_lbl, "deps-package");
    gtk_widget_add_css_class(group_lbl, "deps-group");
    gtk_widget_add_css_class(group_lbl,
        g_strcmp0(group, "critical") == 0 ? "deps-critical"
                                          : "deps-optional");
    gtk_widget_add_css_class(status, "deps-status");
    gtk_widget_add_css_class(status, installed ? "installed" : "missing");
    gtk_widget_add_css_class(install, "deps-install");

    gtk_label_set_xalign(GTK_LABEL(name), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(package_lbl), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(group_lbl), 0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(package_lbl), PANGO_ELLIPSIZE_END);

    gtk_widget_set_hexpand(identity, TRUE);
    gtk_widget_set_halign(group_lbl, GTK_ALIGN_START);
    gtk_widget_set_valign(group_lbl, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(status, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(install, GTK_ALIGN_CENTER);
    gtk_widget_set_sensitive(install, !installed);

    gtk_box_append(GTK_BOX(identity), name);
    gtk_box_append(GTK_BOX(identity), package_lbl);

    gtk_box_append(GTK_BOX(content), group_lbl);
    gtk_box_append(GTK_BOX(content), identity);
    gtk_box_append(GTK_BOX(content), status);
    gtk_box_append(GTK_BOX(content), install);
    gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), content);

    entry->page      = page;
    entry->tool      = g_strdup(tool);
    entry->package   = g_strdup(package);
    entry->group     = g_strdup(group);
    entry->meta      = g_strdup(meta);
    entry->installed = installed;

    if (!installed) {
        g_object_set_data(G_OBJECT(install), "state", page->state);
        g_object_set_data(G_OBJECT(install), "module-id",
                          (gpointer) page->module_id);
        g_object_set_data(G_OBJECT(install), "status", page->status);
        g_object_set_data_full(G_OBJECT(install), "verb",
                               g_strdup("--install-package"), g_free);
        g_object_set_data_full(G_OBJECT(install), "args",
                               g_strdup(package), g_free);
        g_object_set_data(G_OBJECT(install), "privileged",
                          GINT_TO_POINTER(1));
        g_signal_connect(install, "clicked",
                         G_CALLBACK(group_verb_clicked), NULL);
        g_signal_connect(install, "clicked",
                         G_CALLBACK(deps_install_one_clicked), entry);
    }

    /* The row owns the record, not the install button: every row has to be
       filterable, and an installed row has no install button at all. Attaching
       it only in the !installed branch left installed rows with no record, so
       the search and the group toggles could not hide them. */
    g_object_set_data_full(G_OBJECT(row), "deps-row", entry, deps_row_free);
    return row;
}

static void
deps_refresh_finished(GObject *source, GAsyncResult *result, gpointer data)
{
    DepsPage *page = data;
    g_autoptr(GError) error = NULL;
    g_autofree char *out = NULL;
    gboolean ok;
    int total = 0, installed = 0, critical_missing = 0, optional_missing = 0;

    ok = g_subprocess_communicate_utf8_finish(G_SUBPROCESS(source), result,
                                              &out, NULL, &error);
    g_clear_object(&page->process);

    if (!ok || !g_subprocess_get_successful(G_SUBPROCESS(source))) {
        const char *why = error != NULL ? error->message
                       : (g_subprocess_get_if_exited(G_SUBPROCESS(source)) &&
                          g_subprocess_get_exit_status(G_SUBPROCESS(source)) != 0
                             ? "the dependency module refused the request"
                             : "the dependency module could not be run");
        g_autofree char *msg = g_strdup_printf("Dependency list failed: %s", why);
        if (page->summary != NULL)
            gtk_label_set_text(GTK_LABEL(page->summary), msg);
        append_event(page->state, msg);
        deps_set_busy(page, FALSE, NULL);
        return;
    }

    deps_clear_rows(page);

    if (out != NULL) {
        g_auto(GStrv) lines = g_strsplit(out, "\n", -1);

        for (guint i = 0; lines[i] != NULL; i++) {
            g_auto(GStrv) f = NULL;
            const char *tool, *level, *required, *state, *version, *package;
            gboolean is_installed;
            g_autofree char *meta = NULL;
            g_autofree char *group = NULL;

            if (*lines[i] == '\0' || strchr(lines[i], '\t') == NULL)
                continue;

            f = g_strsplit(lines[i], "\t", -1);
            if (g_strv_length(f) < 6)
                continue;

            tool     = deps_field(f, 0);
            level    = deps_field(f, 1);
            required = deps_field(f, 2);
            state    = deps_field(f, 3);
            version  = deps_field(f, 4);
            package  = deps_field(f, 5);

            is_installed = g_strcmp0(state, "installed") == 0;
            group = g_strdup(g_strcmp0(required, "yes") == 0 ? "critical"
                                                             : "optional");
            meta = (*version != '\0')
                     ? g_strdup_printf("%s  ·  %s", level, version)
                     : g_strdup(level);

            gtk_list_box_append(GTK_LIST_BOX(page->list),
                                deps_create_row(page, group, tool, package,
                                                meta, is_installed));

            total++;
            if (is_installed)
                installed++;
            else if (g_strcmp0(group, "critical") == 0)
                critical_missing++;
            else
                optional_missing++;
        }
    }

    if (page->summary != NULL) {
        g_autofree char *line = g_strdup_printf(
            "%d/%d installed  ·  %d critical missing  ·  %d optional missing",
            installed, total, critical_missing, optional_missing);
        gtk_label_set_text(GTK_LABEL(page->summary), line);
    }

    deps_set_busy(page, FALSE, NULL);
    deps_apply_filter(page);
}

static void
deps_refresh(DepsPage *page)
{
    g_autoptr(GError) error = NULL;
    g_autofree char *script = module_script_path(page->module_id);
    const char *argv[3];

    if (page->process != NULL)
        return;                         /* one read at a time */
    if (script == NULL || !g_file_test(script, G_FILE_TEST_EXISTS)) {
        gtk_label_set_text(GTK_LABEL(page->summary),
                           "The dependency module is not present in this tree.");
        return;
    }

    argv[0] = script;
    argv[1] = "--status-tsv";
    argv[2] = NULL;

    page->process = g_subprocess_newv(argv,
        G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_SILENCE,
        &error);
    if (page->process == NULL) {
        g_autofree char *msg = g_strdup_printf(
            "Dependency list failed: %s",
            error != NULL ? error->message : "could not start the module");
        gtk_label_set_text(GTK_LABEL(page->summary), msg);
        append_event(page->state, msg);
        return;
    }

    deps_set_busy(page, TRUE, "Inspecting installed tools…");
    g_subprocess_communicate_utf8_async(page->process, NULL, NULL,
                                        deps_refresh_finished, page);
}

static gboolean
deps_refresh_idle(gpointer data)
{
    deps_refresh(data);
    return G_SOURCE_REMOVE;
}

static void
deps_page_free(gpointer data)
{
    DepsPage *page = data;

    if (page->refresh_source != 0)
        g_source_remove(page->refresh_source);
    g_clear_object(&page->process);
    g_free(page);
}

static GtkWidget *
deps_build_packages(AppState *state, const char *module_id,
                    GtkWidget *status, GtkTextBuffer *out)
{
    GtkWidget *page    = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *scroll  = gtk_scrolled_window_new();
    GtkWidget *search  = gtk_search_entry_new();
    GtkWidget *critical = gtk_toggle_button_new_with_label("Critical");
    GtkWidget *optional = gtk_toggle_button_new_with_label("Optional");
    GtkWidget *refresh = gtk_button_new_with_label("Refresh");
    GtkWidget *summary = gtk_label_new("Dependency state not read yet.");
    GtkWidget *list    = gtk_list_box_new();
    GtkWidget *busy    = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *spinner = gtk_spinner_new();
    GtkWidget *busy_lbl = gtk_label_new("");
    GtkWidget *entry   = gtk_entry_new();
    GtkWidget *install = gtk_button_new_with_label("Install");
    DepsPage  *manager = g_new0(DepsPage, 1);

    (void) out;

    manager->state     = state;
    manager->module_id = module_id;
    manager->list      = list;
    manager->summary   = summary;
    manager->search    = search;
    manager->critical  = critical;
    manager->optional  = optional;
    manager->status    = status;
    manager->refresh   = refresh;
    manager->busy      = busy;
    manager->busy_label = busy_lbl;
    manager->entry     = entry;

    gtk_widget_add_css_class(page, "deps-page");
    gtk_widget_add_css_class(summary, "deps-summary");
    gtk_widget_add_css_class(busy_lbl, "deps-busy");
    gtk_widget_add_css_class(entry, "deps-entry");
    gtk_widget_add_css_class(install, "verb-button");
    gtk_widget_add_css_class(critical, "deps-filter");
    gtk_widget_add_css_class(optional, "deps-filter");

    gtk_label_set_xalign(GTK_LABEL(summary), 0.0f);
    gtk_widget_set_hexpand(search, TRUE);
    gtk_widget_set_hexpand(entry, TRUE);
    gtk_widget_set_vexpand(scroll, TRUE);

    gtk_search_entry_set_placeholder_text(GTK_SEARCH_ENTRY(search),
                                          "Filter tool or package…");
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry),
                                   "Install a package by name…");
    gtk_label_set_text(GTK_LABEL(busy_lbl), "Inspecting installed tools…");

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(critical), TRUE);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(optional), TRUE);
    gtk_widget_set_tooltip_text(critical, "Show the tools this toolkit needs");
    gtk_widget_set_tooltip_text(optional, "Show the tools it can use");

    gtk_list_box_set_selection_mode(GTK_LIST_BOX(list), GTK_SELECTION_NONE);
    gtk_list_box_set_show_separators(GTK_LIST_BOX(list), TRUE);
    gtk_list_box_set_filter_func(GTK_LIST_BOX(list), NULL, NULL, NULL);

    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), list);

    gtk_box_append(GTK_BOX(busy), spinner);
    gtk_box_append(GTK_BOX(busy), busy_lbl);
    gtk_widget_set_visible(busy, FALSE);

    gtk_box_append(GTK_BOX(page), search);
    {
        GtkWidget *controls = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        gtk_box_append(GTK_BOX(controls), critical);
        gtk_box_append(GTK_BOX(controls), optional);
        gtk_box_append(GTK_BOX(controls), refresh);
        gtk_box_append(GTK_BOX(page), controls);
    }
    gtk_box_append(GTK_BOX(page), summary);
    gtk_box_append(GTK_BOX(page), busy);
    gtk_box_append(GTK_BOX(page), scroll);
    {
        GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        gtk_box_append(GTK_BOX(row), entry);
        gtk_box_append(GTK_BOX(row), install);
        gtk_box_append(GTK_BOX(page), row);
    }

    g_object_set_data_full(G_OBJECT(list), "deps-page", manager,
                           deps_page_free);

    g_signal_connect(search, "search-changed",
                     G_CALLBACK(deps_filter_changed), manager);
    g_signal_connect(critical, "toggled",
                     G_CALLBACK(deps_filter_changed), manager);
    g_signal_connect(optional, "toggled",
                     G_CALLBACK(deps_filter_changed), manager);
    g_signal_connect(refresh, "clicked",
                     G_CALLBACK(deps_filter_changed), manager);
    g_signal_connect_swapped(refresh, "clicked",
                             G_CALLBACK(deps_refresh), manager);
    g_signal_connect(install, "clicked",
                     G_CALLBACK(deps_install_named_clicked), manager);
    g_signal_connect(entry, "activate",
                     G_CALLBACK(deps_install_named_clicked), manager);

    gtk_spinner_start(GTK_SPINNER(spinner));
    g_idle_add(deps_refresh_idle, manager);
    return page;
}

/* Each module lists its submenus in order. Entry 0 is always the Overview,
   whose spec becomes the QUICK ACTIONS row; the rest are themed groups of
   verbs drawn from the module's own vocabulary. Verbs that are plumbing
   (--menu, --selftest, --status-tsv, --yes, --quiet) are deliberately absent:
   they belong to the launcher and the test runner, not to a person clicking
   buttons. Spec syntax is documented on ModuleSubmenuEntry above. */

static ModuleSubmenuEntry deps_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      /* Split into a CHECK card and an INSTALL card: looking is safe and
         installing is privileged, and the page should say so rather than
         putting a read-only refresh next to three root actions.

         The three install buttons carry the '!' privilege marker BEFORE the
         colon, which is where the spec grammar expects it. They previously
         had it only on the end of the label ("Install Missing!"), so
         privileged was always false and the installs ran as the operator,
         failing on every write. With the marker here they go through
         `pkexec <script> <verb>`, which is what the polkit rule in
         tools/49-imsisting.rules matches on. */
      "#CHECK|--check-versions:Refresh|#INSTALL|--install-missing!:Install Missing!|--install-all!:Install Full Toolchain!|--install-pip!:Install Pipx Tools!|#AUDIT|--missing-only:Missing Only|--report:Report" },
    { "Packages",
      "system-software-install-symbolic",
      NULL,
      deps_build_packages },
    { "System",
      "preferences-system-symbolic",
      "--distro-info:Distro Info" },
};
/* Radio Bench: an operational workspace for selecting, tuning and recording. */
typedef struct {
    AppState *state;
    const char *module_id;
    GtkWidget *devices;
    GtkWidget *selection;
    GtkWidget *telemetry;
} RadioBench;

static void
radio_bench_clear(GtkWidget *list)
{
    GtkWidget *child = gtk_widget_get_first_child(list);
    while (child != NULL) {
        GtkWidget *next = gtk_widget_get_next_sibling(child);
        gtk_list_box_remove(GTK_LIST_BOX(list), child);
        child = next;
    }
}

static void
radio_bench_run_button(GtkWidget *button, AppState *state,
                       const char *module_id, GtkWidget *status,
                       const char *verb, const char *args)
{
    g_object_set_data(G_OBJECT(button), "state", state);
    g_object_set_data(G_OBJECT(button), "module-id", (gpointer) module_id);
    g_object_set_data(G_OBJECT(button), "status", status);
    g_object_set_data_full(G_OBJECT(button), "verb", g_strdup(verb), g_free);
    if (args != NULL)
        g_object_set_data_full(G_OBJECT(button), "args", g_strdup(args), g_free);
    g_signal_connect(button, "clicked", G_CALLBACK(group_verb_clicked), NULL);
}

static void
radio_bench_add_device(RadioBench *bench, char **f, int index,
                       GtkWidget *status)
{
    g_autofree char *summary = g_strdup_printf(
        "%s-%s MHz  |  %s-%s Msps  |  %s dB  |  %s",
        f[2] ? f[2] : "?", f[3] ? f[3] : "?", f[4] ? f[4] : "?",
        f[5] ? f[5] : "?", f[6] ? f[6] : "?", f[8] ? f[8] : "RX");
    g_autofree char *serial = g_strdup_printf("serial: %s", f[1] ? f[1] : "unknown");
    g_autofree char *select_arg = g_strdup_printf("%d", index);
    GtkWidget *row = gtk_list_box_row_new();
    GtkWidget *content = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    GtkWidget *text = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *top = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *name = gtk_label_new(f[0] ? f[0] : "SDR");
    GtkWidget *ident = gtk_label_new(serial);
    GtkWidget *meta = gtk_label_new(summary);
    GtkWidget *icon = imsisting_icon_image("network-wireless-symbolic");
    GtkWidget *select = gtk_button_new_with_label("Select");
    GtkWidget *caps = gtk_button_new_with_label("Capabilities");

    gtk_image_set_pixel_size(GTK_IMAGE(icon), 28);
    gtk_label_set_xalign(GTK_LABEL(name), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(ident), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(meta), 0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(meta), PANGO_ELLIPSIZE_END);
    gtk_widget_add_css_class(row, "radio-device-row");
    gtk_widget_add_css_class(name, "cell-name");
    gtk_widget_add_css_class(ident, "cell-ident");
    gtk_widget_add_css_class(meta, "cell-meta");
    gtk_widget_add_css_class(icon, "cell-icon");
    gtk_widget_add_css_class(select, "verb-button");
    gtk_widget_add_css_class(caps, "flat");
    gtk_widget_set_hexpand(text, TRUE);
    gtk_box_append(GTK_BOX(top), name);
    gtk_box_append(GTK_BOX(top), ident);
    gtk_box_append(GTK_BOX(text), top);
    gtk_box_append(GTK_BOX(text), meta);
    gtk_box_append(GTK_BOX(content), icon);
    gtk_box_append(GTK_BOX(content), text);
    gtk_box_append(GTK_BOX(content), caps);
    gtk_box_append(GTK_BOX(content), select);
    gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), content);
    radio_bench_run_button(select, bench->state, bench->module_id, status,
                           "--select", select_arg);
    radio_bench_run_button(caps, bench->state, bench->module_id, status,
                           "--caps-tsv", f[0]);
    gtk_list_box_append(GTK_LIST_BOX(bench->devices), row);
}

static void
radio_bench_fill(RadioBench *bench, GtkWidget *status)
{
    g_autofree char *script = module_script_path(bench->module_id);
    const char *status_argv[] = { script, "--status-tsv", NULL };
    const char *list_argv[] = { script, "--list-tsv", NULL };
    g_autofree char *current = run_capture(status_argv);
    g_autofree char *roster = run_capture(list_argv);
    g_autofree char *selected = current ? tsv_field(current, "selected_driver") : NULL;
    g_autofree char *freq = current ? tsv_field(current, "freq_hz") : NULL;
    g_autofree char *gain = current ? tsv_field(current, "gain_db") : NULL;
    g_autofree char *rate = current ? tsv_field(current, "rate_sps") : NULL;
    g_autofree char *lock = current ? tsv_field(current, "lock_state") : NULL;
    g_autofree char *selection = g_strdup_printf("SELECTED  %s",
        (selected && *selected) ? selected : "none");
    g_autofree char *telemetry = g_strdup_printf(
        "TUNE  %s Hz  |  %s dB  |  %s sps  /  LOCK  %s",
        (freq && *freq) ? freq : "not set", (gain && *gain) ? gain : "not set",
        (rate && *rate) ? rate : "not set", (lock && *lock) ? lock : "free");
    int count = 0;

    gtk_label_set_text(GTK_LABEL(bench->selection), selection);
    gtk_label_set_text(GTK_LABEL(bench->telemetry), telemetry);
    radio_bench_clear(bench->devices);
    if (roster != NULL && *roster != '\0') {
        g_auto(GStrv) lines = g_strsplit(roster, "\n", -1);
        for (guint i = 0; lines[i] != NULL; i++) {
            g_auto(GStrv) f = g_strsplit(lines[i], "\t", 10);
            if (g_strv_length(f) < 9 || g_strcmp0(f[0], "driver") == 0)
                continue;
            radio_bench_add_device(bench, f, count++, status);
        }
    }
    if (count == 0) {
        GtkWidget *row = gtk_list_box_row_new();
        GtkWidget *empty = gtk_label_new(
            "No SDRs detected - connect a supported radio, then Refresh.");
        gtk_widget_add_css_class(empty, "cell-empty");
        gtk_widget_set_margin_top(empty, 14);
        gtk_widget_set_margin_bottom(empty, 14);
        gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), empty);
        gtk_list_box_append(GTK_LIST_BOX(bench->devices), row);
    }
}

static void
radio_bench_refresh_clicked(GtkButton *button, gpointer user_data)
{
    RadioBench *bench = user_data;
    radio_bench_fill(bench, g_object_get_data(G_OBJECT(button), "status"));
}

static GtkWidget *
radio_bench_arg_action(AppState *state, const char *module_id,
                       GtkWidget *status, const char *label,
                       const char *placeholder, const char *verb,
                       const char *button_label)
{
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *caption = gtk_label_new(label);
    GtkWidget *entry = gtk_entry_new();
    GtkWidget *button = gtk_button_new_with_label(button_label);

    gtk_label_set_xalign(GTK_LABEL(caption), 0.0f);
    gtk_widget_set_size_request(caption, 112, -1);
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry), placeholder);
    gtk_widget_set_hexpand(entry, TRUE);
    gtk_widget_add_css_class(entry, "verb-arg-entry");
    gtk_widget_add_css_class(button, "verb-button");
    g_object_set_data(G_OBJECT(button), "state", state);
    g_object_set_data(G_OBJECT(button), "module-id", (gpointer) module_id);
    g_object_set_data(G_OBJECT(button), "status", status);
    g_object_set_data_full(G_OBJECT(button), "verb", g_strdup(verb), g_free);
    g_object_set_data(G_OBJECT(button), "arg-entry", entry);
    g_signal_connect(button, "clicked", G_CALLBACK(group_arg_clicked), NULL);
    gtk_box_append(GTK_BOX(row), caption);
    gtk_box_append(GTK_BOX(row), entry);
    gtk_box_append(GTK_BOX(row), button);
    return row;
}

static GtkWidget *
radio_build_bench(AppState *state, const char *module_id,
                  GtkWidget *status, GtkTextBuffer *out)
{
    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *inner = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    GtkWidget *hero = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *selection = gtk_label_new("SELECTED  checking...");
    GtkWidget *telemetry = gtk_label_new("TUNE  checking...");
    GtkWidget *refresh = gtk_button_new_with_label("Refresh hardware");
    GtkWidget *device_body;
    GtkWidget *device_card = verb_card("DEVICE INVENTORY", &device_body);
    GtkWidget *scroll = gtk_scrolled_window_new();
    GtkWidget *devices = gtk_list_box_new();
    GtkWidget *tune_body;
    GtkWidget *tune_card = verb_card("QUICK TUNE", &tune_body);
    GtkWidget *capture_body;
    GtkWidget *capture_card = verb_card("CAPTURE", &capture_body);
    RadioBench *bench = g_new0(RadioBench, 1);

    bench->state = state;
    bench->module_id = module_id;
    bench->devices = devices;
    bench->selection = selection;
    bench->telemetry = telemetry;
    gtk_widget_set_margin_top(inner, 16);
    gtk_widget_set_margin_bottom(inner, 16);
    gtk_widget_set_margin_start(inner, 16);
    gtk_widget_set_margin_end(inner, 16);
    gtk_widget_set_hexpand(inner, TRUE);
    gtk_widget_add_css_class(hero, "radio-bench-status");
    gtk_widget_add_css_class(selection, "radio-bench-selection");
    gtk_widget_add_css_class(telemetry, "radio-bench-telemetry");
    gtk_widget_add_css_class(refresh, "flat");
    gtk_label_set_xalign(GTK_LABEL(selection), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(telemetry), 0.0f);
    gtk_widget_set_hexpand(selection, TRUE);
    gtk_widget_set_hexpand(telemetry, TRUE);
    gtk_box_append(GTK_BOX(hero), selection);
    gtk_box_append(GTK_BOX(hero), telemetry);
    gtk_box_append(GTK_BOX(hero), refresh);
    gtk_box_append(GTK_BOX(inner), hero);

    gtk_list_box_set_selection_mode(GTK_LIST_BOX(devices), GTK_SELECTION_NONE);
    gtk_widget_add_css_class(devices, "cell-list");
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), devices);
    gtk_widget_set_size_request(scroll, -1, 230);
    gtk_box_append(GTK_BOX(device_body), scroll);
    gtk_box_append(GTK_BOX(inner), device_card);

    gtk_box_append(GTK_BOX(tune_body), radio_bench_arg_action(
        state, module_id, status, "Frequency", "MHz  e.g. 942", "--set-freq", "Apply"));
    gtk_box_append(GTK_BOX(tune_body), radio_bench_arg_action(
        state, module_id, status, "Gain", "dB  e.g. 40", "--set-gain", "Apply"));
    gtk_box_append(GTK_BOX(tune_body), radio_bench_arg_action(
        state, module_id, status, "Sample rate", "samples/s  e.g. 2000000", "--set-rate", "Apply"));
    gtk_box_append(GTK_BOX(inner), tune_card);

    gtk_box_append(GTK_BOX(capture_body), radio_bench_arg_action(
        state, module_id, status, "IQ capture", "seconds", "--record", "Record"));
    gtk_box_append(GTK_BOX(inner), capture_card);
    if (out != NULL)
        gtk_box_append(GTK_BOX(inner), build_output_card(out));

    g_object_set_data(G_OBJECT(refresh), "status", status);
    g_signal_connect(refresh, "clicked", G_CALLBACK(radio_bench_refresh_clicked), bench);
    g_object_set_data_full(G_OBJECT(inner), "radio-bench", bench, g_free);
    radio_bench_fill(bench, status);
    gtk_box_append(GTK_BOX(outer), inner);
    return outer;
}

static GtkWidget *
radio_view_shell(const char *title, const char *subtitle, GtkWidget **body_out)
{
    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *inner = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    GtkWidget *heading = gtk_label_new(title);
    GtkWidget *detail = gtk_label_new(subtitle);
    GtkWidget *body = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);

    gtk_widget_set_margin_top(inner, 16);
    gtk_widget_set_margin_bottom(inner, 16);
    gtk_widget_set_margin_start(inner, 16);
    gtk_widget_set_margin_end(inner, 16);
    gtk_widget_add_css_class(heading, "radio-view-title");
    gtk_widget_add_css_class(detail, "radio-view-subtitle");
    gtk_label_set_xalign(GTK_LABEL(heading), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(detail), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(detail), TRUE);
    gtk_box_append(GTK_BOX(inner), heading);
    gtk_box_append(GTK_BOX(inner), detail);
    gtk_box_append(GTK_BOX(inner), body);
    gtk_box_append(GTK_BOX(outer), inner);
    if (body_out != NULL) *body_out = body;
    return outer;
}

static char *
radio_status_summary(const char *module_id)
{
    g_autofree char *script = module_script_path(module_id);
    const char *argv[] = { script, "--status-tsv", NULL };
    g_autofree char *status = run_capture(argv);
    g_autofree char *driver = status ? tsv_field(status, "selected_driver") : NULL;
    g_autofree char *freq = status ? tsv_field(status, "freq_hz") : NULL;
    g_autofree char *gain = status ? tsv_field(status, "gain_db") : NULL;
    g_autofree char *rate = status ? tsv_field(status, "rate_sps") : NULL;
    return g_strdup_printf("ACTIVE PROFILE  %s  |  %s Hz  |  %s dB  |  %s sps",
        (driver && *driver) ? driver : "no device",
        (freq && *freq) ? freq : "not set", (gain && *gain) ? gain : "not set",
        (rate && *rate) ? rate : "not set");
}

static GtkWidget *
radio_build_tuning(AppState *state, const char *module_id,
                   GtkWidget *status, GtkTextBuffer *out)
{
    GtkWidget *body;
    GtkWidget *outer = radio_view_shell("TUNING CONSOLE",
        "Set the receiver profile deliberately. Select an SDR in Overview first; results are recorded below.",
        &body);
    g_autofree char *summary = radio_status_summary(module_id);
    GtkWidget *profile = gtk_label_new(summary);
    GtkWidget *tune_body;
    GtkWidget *tune = verb_card("RECEIVER SETTINGS", &tune_body);

    gtk_widget_add_css_class(profile, "radio-bench-status");
    gtk_widget_add_css_class(profile, "radio-bench-telemetry");
    gtk_label_set_xalign(GTK_LABEL(profile), 0.0f);
    gtk_box_append(GTK_BOX(body), profile);
    gtk_box_append(GTK_BOX(tune_body), radio_bench_arg_action(
        state, module_id, status, "Center frequency", "MHz  e.g. 942", "--set-freq", "Apply"));
    gtk_box_append(GTK_BOX(tune_body), radio_bench_arg_action(
        state, module_id, status, "Gain", "dB  e.g. 40", "--set-gain", "Apply"));
    gtk_box_append(GTK_BOX(tune_body), radio_bench_arg_action(
        state, module_id, status, "Sample rate", "samples/s  e.g. 2000000", "--set-rate", "Apply"));
    gtk_box_append(GTK_BOX(body), tune);
    if (out != NULL) gtk_box_append(GTK_BOX(body), build_output_card(out));
    return outer;
}

static GtkWidget *
radio_build_ownership(AppState *state, const char *module_id,
                      GtkWidget *status, GtkTextBuffer *out)
{
    GtkWidget *body;
    GtkWidget *outer = radio_view_shell("DEVICE OWNERSHIP",
        "An SDR is exclusive hardware. Claim it before a long operation, then release it when the work is complete.",
        &body);
    g_autofree char *script = module_script_path(module_id);
    const char *argv[] = { script, "--lock-status-tsv", NULL };
    g_autofree char *raw = run_capture(argv);
    g_autofree char *lock = raw ? tsv_field(raw, "state") : NULL;
    g_autofree char *owner = raw ? tsv_field(raw, "owner") : NULL;
    g_autofree char *owner_text = g_strdup_printf("LOCK  %s   |   OWNER  %s",
        (lock && *lock) ? lock : "unknown", (owner && *owner) ? owner : "none");
    GtkWidget *banner = gtk_label_new(owner_text);
    GtkWidget *control_body;
    GtkWidget *control = verb_card("LOCK CONTROL", &control_body);
    GtkWidget *recover = gtk_button_new_with_label("Recover stale lock");

    gtk_widget_add_css_class(banner, "radio-bench-status");
    gtk_widget_add_css_class(banner, "radio-bench-telemetry");
    gtk_label_set_xalign(GTK_LABEL(banner), 0.0f);
    gtk_box_append(GTK_BOX(body), banner);
    gtk_box_append(GTK_BOX(control_body), radio_bench_arg_action(
        state, module_id, status, "Owner name", "e.g. recon-session", "--lock-claim", "Claim"));
    gtk_box_append(GTK_BOX(control_body), radio_bench_arg_action(
        state, module_id, status, "Release owner", "exact owner name", "--lock-release", "Release"));
    gtk_widget_add_css_class(recover, "flat");
    radio_bench_run_button(recover, state, module_id, status, "--lock-recover", NULL);
    gtk_box_append(GTK_BOX(control_body), recover);
    gtk_box_append(GTK_BOX(body), control);
    if (out != NULL) gtk_box_append(GTK_BOX(body), build_output_card(out));
    return outer;
}

static GtkWidget *
radio_build_diagnostics(AppState *state, const char *module_id,
                        GtkWidget *status, GtkTextBuffer *out)
{
    GtkWidget *body;
    GtkWidget *outer = radio_view_shell("RADIO DIAGNOSTICS",
        "Check practical coverage and inspect processes that may have the SDR open before troubleshooting a failed run.",
        &body);
    GtkWidget *coverage_body;
    GtkWidget *coverage = verb_card("BAND COVERAGE", &coverage_body);
    GtkWidget *health_body;
    GtkWidget *health = verb_card("HARDWARE HEALTH", &health_body);
    GtkWidget *processes = gtk_button_new_with_label("Inspect SDR processes");
    GtkWidget *plan = gtk_button_new_with_label("Show control plan");

    gtk_box_append(GTK_BOX(coverage_body), radio_bench_arg_action(
        state, module_id, status, "Frequency", "MHz  e.g. 942", "--band-check", "Check coverage"));
    radio_bench_run_button(processes, state, module_id, status, "--processes-tsv", NULL);
    radio_bench_run_button(plan, state, module_id, status, "--plan", NULL);
    gtk_widget_add_css_class(processes, "verb-button");
    gtk_widget_add_css_class(plan, "flat");
    gtk_box_append(GTK_BOX(health_body), processes);
    gtk_box_append(GTK_BOX(health_body), plan);
    gtk_box_append(GTK_BOX(body), coverage);
    gtk_box_append(GTK_BOX(body), health);
    if (out != NULL) gtk_box_append(GTK_BOX(body), build_output_card(out));
    return outer;
}

static ModuleSubmenuEntry radio_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      NULL,
      radio_build_bench },
    { "Tuning",
      "preferences-system-symbolic",
      NULL,
      radio_build_tuning },
    { "Ownership",
      "channel-secure-symbolic",
      NULL,
      radio_build_ownership },
    { "Diagnostics",
      "utilities-terminal-symbolic",
      NULL,
      radio_build_diagnostics },
};
/* ── Cell Recon · Targets ───────────────────────────────────────────
   Laid out like wifisting's Wi-Fi Recon target list: a toolbar naming what
   is selected with Refresh / Export on the right, then one row per surveyed
   cell with a Set target action. Rows come from the module's --list-tsv.

   An empty store is drawn as an empty state, not as an error: "run a scan
   first" is information, and it belongs in the list rather than in a red
   dump in the output card. */
typedef struct {
    AppState   *state;
    const char *module_id;
    GtkWidget  *list;        /* GtkListBox holding the cells */
    GtkWidget  *selected;    /* toolbar label: current target */
} CrecTargets;

static void
crec_targets_clear(GtkWidget *list)
{
    GtkWidget *child = gtk_widget_get_first_child(list);
    while (child != NULL) {
        GtkWidget *next = gtk_widget_get_next_sibling(child);
        gtk_list_box_remove(GTK_LIST_BOX(list), child);
        child = next;
    }
}

static void
crec_targets_empty(GtkWidget *list, const char *text)
{
    GtkWidget *row = gtk_list_box_row_new();
    GtkWidget *lbl = gtk_label_new(text);

    gtk_widget_add_css_class(lbl, "cell-empty");
    gtk_label_set_xalign(GTK_LABEL(lbl), 0.0f);
    gtk_widget_set_margin_top(lbl, 14);
    gtk_widget_set_margin_bottom(lbl, 14);
    gtk_widget_set_margin_start(lbl, 6);
    gtk_widget_set_margin_end(lbl, 6);
    gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), lbl);
    gtk_list_box_row_set_activatable(GTK_LIST_BOX_ROW(row), FALSE);
    gtk_list_box_row_set_selectable(GTK_LIST_BOX_ROW(row), FALSE);
    gtk_list_box_append(GTK_LIST_BOX(list), row);
}

static void
crec_set_target_clicked(GtkButton *button, gpointer user_data)
{
    CrecTargets *t = user_data;
    const char *rat   = g_object_get_data(G_OBJECT(button), "cell-rat");
    const char *arfcn = g_object_get_data(G_OBJECT(button), "cell-arfcn");
    const char *plmn  = g_object_get_data(G_OBJECT(button), "cell-plmn");
    const char *cell  = g_object_get_data(G_OBJECT(button), "cell-id");

    if (t == NULL || t->selected == NULL) return;

    /* Handing it to the global panel is what makes Set target mean
       something: the panel is the writer for the shared target the cellular
       modules read, and it stays reachable from every page afterwards. */
    imsisting_target_offer(t->state, rat, arfcn, plmn, cell);

    if (rat != NULL && arfcn != NULL)
        gtk_label_set_text(GTK_LABEL(t->selected),
            g_strdup_printf("Target set: %s %s", rat, arfcn));
}

/* One surveyed cell, in the same order wifisting uses: what it is, then the
   identifiers, then the numbers worth comparing down the list. */
static void
crec_targets_add_row(CrecTargets *t, char **f)
{
    /* rat gen arfcn freq_mhz plmn mcc mnc operator country cell_id
       tac_lac band rsrp_dbm cipher source ts */
    const char *identity = (f[7] != NULL && *f[7] != '\0') ? f[7] : f[4];
    g_autofree char *sub = g_strdup_printf("(%s · ARFCN %s)",
                                           (f[9] && *f[9]) ? f[9] : "?",
                                           (f[2] && *f[2]) ? f[2] : "?");
    g_autofree char *meta =
        g_strdup_printf("%s %s  •  %s MHz  •  %s  •  %s dBm  •  %s",
                        (f[0] && *f[0]) ? f[0] : "cell",
                        (f[1] && *f[1]) ? f[1] : "",
                        (f[3] && *f[3]) ? f[3] : "?",
                        (f[11] && *f[11]) ? f[11] : "band ?",
                        (f[12] && *f[12]) ? f[12] : "?",
                        (f[13] && *f[13]) ? f[13] : "unknown");
    g_autofree char *full = g_strdup_printf("Target set: %s  %s", identity, sub);

    GtkWidget *row     = gtk_list_box_row_new();
    GtkWidget *content = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    GtkWidget *text    = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *top     = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *name    = gtk_label_new(identity);
    GtkWidget *ident   = gtk_label_new(sub);
    GtkWidget *metalbl = gtk_label_new(meta);
    GtkWidget *icon    = imsisting_icon_image("network-wireless-symbolic");
    GtkWidget *pick    = gtk_button_new_with_label("Set target");

    gtk_image_set_pixel_size(GTK_IMAGE(icon), 28);

    gtk_label_set_xalign(GTK_LABEL(name), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(ident), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(metalbl), 0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(name), PANGO_ELLIPSIZE_END);
    gtk_label_set_max_width_chars(GTK_LABEL(name), 38);

    gtk_widget_add_css_class(row,     "cell-row");
    gtk_widget_add_css_class(name,    "cell-name");
    gtk_widget_add_css_class(ident,   "cell-ident");
    gtk_widget_add_css_class(metalbl, "cell-meta");
    gtk_widget_add_css_class(pick,    "verb-button");
    gtk_widget_add_css_class(icon,    "cell-icon");

    gtk_widget_set_hexpand(text, TRUE);
    gtk_widget_set_valign(pick, GTK_ALIGN_CENTER);
    gtk_box_append(GTK_BOX(top), name);
    gtk_box_append(GTK_BOX(top), ident);
    gtk_box_append(GTK_BOX(text), top);
    gtk_box_append(GTK_BOX(text), metalbl);
    gtk_box_append(GTK_BOX(content), icon);
    gtk_box_append(GTK_BOX(content), text);
    gtk_box_append(GTK_BOX(content), pick);
    gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), content);

    g_object_set_data_full(G_OBJECT(pick), "cell-label", g_strdup(full), g_free);
    /* Carried on the button so Set target can hand the global panel a real
       target instead of only relabelling itself. */
    {
        g_autofree char *rat = g_ascii_strdown(f[0] != NULL ? f[0] : "", -1);
        g_object_set_data_full(G_OBJECT(pick), "cell-rat",
                               g_strdup(rat), g_free);
        g_object_set_data_full(G_OBJECT(pick), "cell-arfcn",
                               g_strdup(f[2] != NULL ? f[2] : ""), g_free);
        g_object_set_data_full(G_OBJECT(pick), "cell-plmn",
                               g_strdup(f[4] != NULL ? f[4] : ""), g_free);
        g_object_set_data_full(G_OBJECT(pick), "cell-id",
                               g_strdup(f[9] != NULL ? f[9] : ""), g_free);
    }
    g_signal_connect(pick, "clicked", G_CALLBACK(crec_set_target_clicked), t);

    gtk_list_box_append(GTK_LIST_BOX(t->list), row);
}

static void
crec_targets_fill(CrecTargets *t)
{
    g_autofree char *script = module_script_path(t->module_id);
    const char *argv[3] = { script, "--list-tsv", NULL };
    g_autofree char *out = NULL;
    int rows = 0;

    crec_targets_clear(t->list);

    out = run_capture(argv);
    if (out != NULL && *out != '\0') {
        g_auto(GStrv) lines = g_strsplit(out, "\n", -1);
        for (guint i = 0; lines[i] != NULL; i++) {
            g_auto(GStrv) f = g_strsplit(lines[i], "\t", 17);
            if (g_strv_length(f) < 16) continue;
            if (g_strcmp0(f[0], "rat") == 0) continue;   /* header row */
            crec_targets_add_row(t, f);
            rows++;
        }
    }
    if (rows == 0)
        crec_targets_empty(t->list,
            "No cells surveyed yet — run Start scan, then Refresh.");
}

static void
crec_targets_refresh_clicked(GtkButton *button, gpointer user_data)
{
    (void) button;
    crec_targets_fill((CrecTargets *) user_data);
}

static void
crec_targets_export_clicked(GtkButton *button, gpointer user_data)
{
    CrecTargets *t = user_data;
    g_autofree char *script = module_script_path(t->module_id);
    const char *argv[3] = { script, "--export", NULL };

    (void) button;
    append_event(t->state, "Exporting the cell survey…");
    run_capture(argv);
    crec_targets_fill(t);
}

static GtkWidget *
crec_build_targets(AppState *state, const char *module_id,
                   GtkWidget *status, GtkTextBuffer *out)
{
    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *inner = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    GtkWidget *bar   = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *selected = gtk_label_new("No target selected");
    GtkWidget *export_btn = gtk_button_new_with_label("Export CSV");
    GtkWidget *refresh   = gtk_button_new_with_label("Refresh");
    GtkWidget *scroll = gtk_scrolled_window_new();
    GtkWidget *list   = gtk_list_box_new();
    CrecTargets *t = g_new0(CrecTargets, 1);

    (void) status;

    t->state = state;
    t->module_id = module_id;
    t->list = list;
    t->selected = selected;

    gtk_widget_set_margin_top(inner, 16);
    gtk_widget_set_margin_bottom(inner, 16);
    gtk_widget_set_margin_start(inner, 16);
    gtk_widget_set_margin_end(inner, 16);
    gtk_widget_set_hexpand(inner, TRUE);

    gtk_label_set_xalign(GTK_LABEL(selected), 0.0f);
    gtk_widget_set_hexpand(selected, TRUE);
    gtk_widget_add_css_class(selected, "cell-selected");

    gtk_box_append(GTK_BOX(bar), selected);
    gtk_box_append(GTK_BOX(bar), export_btn);
    gtk_box_append(GTK_BOX(bar), refresh);
    gtk_box_append(GTK_BOX(inner), bar);

    gtk_list_box_set_selection_mode(GTK_LIST_BOX(list), GTK_SELECTION_NONE);
    gtk_widget_add_css_class(list, "cell-list");
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), list);
    gtk_widget_set_vexpand(scroll, TRUE);
    gtk_box_append(GTK_BOX(inner), scroll);

    if (out != NULL)
        gtk_box_append(GTK_BOX(inner), build_output_card(out));

    g_signal_connect(refresh, "clicked",
                     G_CALLBACK(crec_targets_refresh_clicked), t);
    g_signal_connect(export_btn, "clicked",
                     G_CALLBACK(crec_targets_export_clicked), t);
    g_object_set_data_full(G_OBJECT(inner), "crec-targets", t, g_free);

    crec_targets_fill(t);

    gtk_box_append(GTK_BOX(outer), inner);
    return outer;
}

static char *
crec_status_summary(const char *module_id)
{
    g_autofree char *script = module_script_path(module_id);
    const char *argv[] = { script, "--status-tsv", NULL };
    g_autofree char *raw = run_capture(argv);
    g_autofree char *cells = raw ? tsv_field(raw, "cells") : NULL;
    g_autofree char *sdr = raw ? tsv_field(raw, "sdr") : NULL;
    g_autofree char *gsm = raw ? tsv_field(raw, "gsm_scanner") : NULL;
    return g_strdup_printf("SURVEY STORE  %s cells   |   SDR  %s   |   GSM SCANNER  %s",
        (cells && *cells) ? cells : "0", (sdr && *sdr) ? sdr : "none",
        (gsm && *gsm) ? gsm : "unavailable");
}

static GtkWidget *
crec_build_overview(AppState *state, const char *module_id,
                    GtkWidget *status, GtkTextBuffer *out)
{
    GtkWidget *body;
    GtkWidget *outer = radio_view_shell("CELL SURVEY",
        "Start a focused survey, then inspect and promote discovered cells from Targets.", &body);
    g_autofree char *summary = crec_status_summary(module_id);
    GtkWidget *banner = gtk_label_new(summary);
    GtkWidget *scan_body;
    GtkWidget *scan = verb_card("SURVEY SOURCE", &scan_body);
    GtkWidget *gsm = gtk_button_new_with_label("Start GSM survey");
    GtkWidget *lte = gtk_button_new_with_label("Start LTE survey");

    gtk_widget_add_css_class(banner, "crec-survey-status");
    gtk_label_set_xalign(GTK_LABEL(banner), 0.0f);
    radio_bench_run_button(gsm, state, module_id, status, "--scan", "gsm");
    radio_bench_run_button(lte, state, module_id, status, "--scan", "lte");
    gtk_widget_add_css_class(gsm, "verb-button");
    gtk_widget_add_css_class(lte, "flat");
    gtk_box_append(GTK_BOX(scan_body), gsm);
    gtk_box_append(GTK_BOX(scan_body), lte);
    gtk_box_append(GTK_BOX(scan_body), radio_bench_arg_action(
        state, module_id, status, "Offline PCAP", "pcap / path/to/capture.pcap", "--scan", "Inspect"));
    gtk_box_append(GTK_BOX(body), banner);
    gtk_box_append(GTK_BOX(body), scan);
    if (out != NULL) gtk_box_append(GTK_BOX(body), build_output_card(out));
    return outer;
}

static GtkWidget *
crec_build_channel(AppState *state, const char *module_id,
                   GtkWidget *status, GtkTextBuffer *out)
{
    GtkWidget *body;
    GtkWidget *outer = radio_view_shell("CHANNEL INTELLIGENCE",
        "Translate GSM, LTE, or NR channel numbers into downlink frequencies before selecting a survey range.", &body);
    GtkWidget *card_body;
    GtkWidget *card = verb_card("ARFCN LOOKUP", &card_body);

    gtk_box_append(GTK_BOX(card_body), radio_bench_arg_action(
        state, module_id, status, "RAT + channel", "gsm 1  |  lte 6300  |  nr 620000", "--arfcn", "Resolve"));
    gtk_box_append(GTK_BOX(body), card);
    if (out != NULL) gtk_box_append(GTK_BOX(body), build_output_card(out));
    return outer;
}

static GtkWidget *
crec_build_network(AppState *state, const char *module_id,
                   GtkWidget *status, GtkTextBuffer *out)
{
    GtkWidget *body;
    GtkWidget *outer = radio_view_shell("NETWORK IDENTITY",
        "Resolve the MCC-MNC before correlating a surveyed cell with its operator and country.", &body);
    GtkWidget *card_body;
    GtkWidget *card = verb_card("PLMN RESOLUTION", &card_body);

    gtk_box_append(GTK_BOX(card_body), radio_bench_arg_action(
        state, module_id, status, "MCC-MNC", "e.g. 208-01", "--plmn", "Resolve"));
    gtk_box_append(GTK_BOX(body), card);
    if (out != NULL) gtk_box_append(GTK_BOX(body), build_output_card(out));
    return outer;
}

static GtkWidget *
crec_build_export(AppState *state, const char *module_id,
                  GtkWidget *status, GtkTextBuffer *out)
{
    GtkWidget *body;
    GtkWidget *outer = radio_view_shell("SURVEY HANDOFF",
        "Export the current survey into the case workspace, or clear the working store when a new collection begins.", &body);
    GtkWidget *card_body;
    GtkWidget *card = verb_card("DATA MANAGEMENT", &card_body);
    GtkWidget *export_btn = gtk_button_new_with_label("Export survey CSV");
    GtkWidget *clear = gtk_button_new_with_label("Clear survey store");

    radio_bench_run_button(export_btn, state, module_id, status, "--export", NULL);
    radio_bench_run_button(clear, state, module_id, status, "--clear", NULL);
    gtk_widget_add_css_class(export_btn, "verb-button");
    gtk_widget_add_css_class(clear, "flat");
    gtk_box_append(GTK_BOX(card_body), export_btn);
    gtk_box_append(GTK_BOX(card_body), clear);
    gtk_box_append(GTK_BOX(body), card);
    if (out != NULL) gtk_box_append(GTK_BOX(body), build_output_card(out));
    return outer;
}

static ModuleSubmenuEntry crec_entries[] = {
    /* Laid out like wifisting's Wi-Fi Recon page - the same job on a
       different radio. An Overview carrying the scan, then a view per
       question the operator asks: what is out there, which channel, which
       network, and how do I get the data out. The Overview splits into a
       CONTROLS card and a SURVEY card, the shape wifisting uses for
       "start it" versus "read the result". */
    { "Overview",
      "dialog-information-symbolic",
      NULL,
      crec_build_overview },
    /* The surveyed cells get their own list view, the way wifisting's Targets
       view does, instead of two buttons that print TSV into the output card. */
    { "Targets",
      "edit-find-symbolic",
      NULL,
      crec_build_targets },
    { "Channel",
      "network-wireless-symbolic",
      NULL,
      crec_build_channel },
    { "Network",
      "network-workgroup-symbolic",
      NULL,
      crec_build_network },
    { "Export",
      "document-save-symbolic",
      NULL,
      crec_build_export },
};
static ModuleSubmenuEntry gtap_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "#LIVE|--listen:Listen Live|#OFFLINE|--read={capture}|~--port|~--iface|~--pipe|~--forward" },
    { "Filter",
      "system-search-symbolic",
      "~--arfcn|~--channel|~--uplink|~--any-port|~--since|~--until" },
    { "Watchlist",
      "emblem-important-symbolic",
      "~--watchlist" },
    { "Decode",
      "document-open-symbolic",
      "--decode-tsv:Decoded TSV|--identities-tsv:Identities" },
    { "Headers",
      "utilities-terminal-symbolic",
      "--build-header:Build Header|--parse-header:Parse Header" },
    { "Export",
      "document-save-symbolic",
      "--export-pcap:Export PCAP" },
};
/* --------------------------------------------------------------------------
   04_tower_map — Tower Survey.
 *
 * Four views, cut by the question being asked rather than by verb: what the
 * receiver can hear, where it is, how the result leaves, and the one
 * destructive act. Three shapes of control, chosen per verb rather than by a
 * rule:
 *
 *   a survey needs a radio technology and a band   -> form row, hint under it
 *   gpsd needs a device                            -> form row, hint under it
 *   exporting is one act with a format choice      -> one row, one path, three
 *                                                     small buttons
 *   listing is not an act at all                   -> a list, refreshed
 *
 * The Export view is the reason this file exists: three identical full-width
 * pills reading "Export KML / Export CSV / Export GeoJSON" said nothing about
 * being one decision, and nothing about the destination they share.
   -------------------------------------------------------------------------- */

static GtkWidget *
tmap_build_overview(AppState *state, const char *module_id,
                    GtkWidget *status, GtkTextBuffer *out)
{
    GtkWidget *body;
    GtkWidget *outer = radio_view_shell("CELL SURVEY",
        "One record per cell, with or without a position fix. The store is "
        "written only when a survey pass runs.", &body);
    GtkWidget *survey_body, *read_body;
    GtkWidget *survey = verb_card("RUN A SURVEY PASS", &survey_body);
    GtkWidget *read = verb_card("RECORDED POINTS", &read_body);

        mod_card_begin(NULL);
    gtk_box_append(GTK_BOX(survey_body),
        mod_arg_row(state, module_id, status, "Start Survey",
            "--survey", "gsm GSM900", "Radio technology (gsm or lte), then a "
            "band for GSM. LTE takes a band list or nothing at all."));
    {
        GtkWidget *res = result_rect_new(state, NULL);
        mod_card_begin(res);
        gtk_box_append(GTK_BOX(survey_body), res);
    }
    gtk_box_append(GTK_BOX(survey_body), fkit_note(
        "A pass records one point per cell it decodes. A cell received without a "
        "position fix is still recorded; it appears in the without-fix count of "
        "the next card rather than as an error."));
    gtk_box_append(GTK_BOX(body), survey);

        mod_card_begin(NULL);
    gtk_box_append(GTK_BOX(read_body),
        mod_arg_row(state, module_id, status, "Read the Points",
            "--list-tsv", "", "Every recorded point, as stored."));
    {
        GtkWidget *res = result_rect_new(state, NULL);
        mod_card_begin(res);
        gtk_box_append(GTK_BOX(read_body), res);
    }
    gtk_box_append(GTK_BOX(read_body),
        mod_arg_row(state, module_id, status, "Count the Points",
            "--history", "", "How many points have a fix, how many do not, and "
            "how many distinct cells they describe."));
    gtk_box_append(GTK_BOX(body), read);
    mod_card_end();

    (void) out;
    return outer;
}

static GtkWidget *
tmap_build_gps(AppState *state, const char *module_id,
               GtkWidget *status, GtkTextBuffer *out)
{
    GtkWidget *body;
    GtkWidget *outer = radio_view_shell("POSITION FIX",
        "The receiver position. A survey record carries this position or it "
        "carries none.", &body);
    GtkWidget *daemon_body, *quality_body;
    GtkWidget *daemon = verb_card("GPS DAEMON", &daemon_body);
    GtkWidget *quality = verb_card("CURRENT FIX", &quality_body);

        mod_card_begin(NULL);
    gtk_box_append(GTK_BOX(daemon_body),
        mod_arg_row(state, module_id, status, "Start gpsd",
            "--start-gpsd", "/dev/ttyUSB0", "The serial device the GPS receiver "
            "is on. Left empty, the module uses /dev/ttyUSB0."));
    {
        GtkWidget *res = result_rect_new(state, NULL);
        mod_card_begin(res);
        gtk_box_append(GTK_BOX(daemon_body), res);
    }
    gtk_box_append(GTK_BOX(daemon_body), fkit_note(
        "A running daemon does not imply a position fix: gpsd may be running while "
        "still acquiring. The following card reports whether a fix exists."));
    gtk_box_append(GTK_BOX(body), daemon);

        mod_card_begin(NULL);
    gtk_box_append(GTK_BOX(quality_body),
        mod_arg_row(state, module_id, status, "Read the Fix",
            "--gps-quality-tsv", "", "Mode, satellites, accuracy and age of the "
            "last fix \u2014 or the single word \"no\"."));
    {
        GtkWidget *res = result_rect_new(state, NULL);
        mod_card_begin(res);
        gtk_box_append(GTK_BOX(quality_body), res);
    }
    gtk_box_append(GTK_BOX(body), quality);
    mod_card_end();

    (void) out;
    return outer;
}

static GtkWidget *
tmap_build_export(AppState *state, const char *module_id,
                  GtkWidget *status, GtkTextBuffer *out)
{
    GtkWidget *body;
    GtkWidget *outer = radio_view_shell("EXPORT",
        "The recorded survey in three interchange formats. Each file is "
        "written to this module's loot directory.", &body);
    GtkWidget *export_body, *clean_body;
    GtkWidget *export = verb_card("EXPORT THE SURVEY", &export_body);
    GtkWidget *clean = verb_card("CLEAR THE STORE", &clean_body);
    static const char *const verbs[] = {
        "--export-csv", "--export-kml", "--export-geojson"
    };
    static const char *const labels[] = { "CSV", "KML", "GeoJSON" };
    GtkWidget *choices;

    /* One row: the path, then the three formats as one choice. */
    choices = mod_arg_choices(state, module_id, status, "Destination",
        "optional path — left empty, the module names the file",
        "CSV carries the tabular data. KML carries only records with a position "
        "fix and opens in any KML viewer. GeoJSON is the web-map interchange "
        "format. All three describe the same records.",
        verbs, labels, 3);
    gtk_box_append(GTK_BOX(export_body), choices);
    {
        GtkWidget *res = result_rect_new(state, NULL);

        mod_card_begin(res);
        gtk_box_append(GTK_BOX(export_body), res);
    }
    gtk_box_append(GTK_BOX(body), export);

        mod_card_begin(NULL);
    gtk_box_append(GTK_BOX(clean_body),
        mod_arg_row(state, module_id, status, "Clear the Store",
            "--clear", "", "Removes every recorded point and cannot be undone. It is the only "
            "destructive operation on this page, and is therefore separated from "
            "the exporters."));
    {
        GtkWidget *res = result_rect_new(state, NULL);
        mod_card_begin(res);
        gtk_box_append(GTK_BOX(clean_body), res);
    }
    gtk_box_append(GTK_BOX(body), clean);
    mod_card_end();

    (void) out;
    return outer;
}

static ModuleSubmenuEntry tmap_entries[] = {
    { "Overview", "dialog-information-symbolic", NULL, tmap_build_overview },
    { "GPS", "find-location-symbolic", NULL, tmap_build_gps },
    { "Export", "document-save-symbolic", NULL, tmap_build_export },
};
/* --------------------------------------------------------------------------
   The field kit is a pre-flight instrument and an honesty check, so the page
   is laid out the way wifisting lays a module page out: the state of the
   machine first, then one view per job. The Emitter is a synthetic GSMTAP
   source, which is what makes Live Traffic testable with no radio attached at
   all; the guard matrix is the module's verdict on every radio-gated verb - a
   verb that returns success with nothing attached is the one failure the whole
   module exists to catch, so it belongs on screen rather than in a report file
   nobody opens.
   -------------------------------------------------------------------------- */

static const struct { const char *id; const char *label; } fkit_scenarios[] = {
    { "gsm-idle",     "GSM Idle" },
    { "gsm-attach",   "GSM Attach" },
    { "lte-attach",   "LTE Attach" },
    { "imsi-catcher", "IMSI Catcher" },
    { "mixed",        "Mixed" },
};

static char *
fkit_status_summary(const char *module_id)
{
    g_autofree char *script = module_script_path(module_id);
    const char *argv[] = { script, "--status-tsv", NULL };
    g_autofree char *raw = run_capture(argv);
    g_autofree char *sdr = raw ? tsv_field(raw, "sdr") : NULL;
    g_autofree char *serial = raw ? tsv_field(raw, "serial") : NULL;
    g_autofree char *guards = raw ? tsv_field(raw, "guards") : NULL;
    g_autofree char *port = raw ? tsv_field(raw, "port") : NULL;

    return g_strdup_printf("SDR  %s   |   serial  %s   |   GSMTAP  udp/%s",
        (sdr && *sdr) ? sdr : "none",
        (serial && *serial) ? serial : "none",
        (port && *port) ? port : "4729");
}

/* Rows of buttons, not columns of them: five scenarios are five buttons on one
   line, and they rewrap with the window instead of stretching a grid. */
static GtkWidget *
fkit_flow(void)
{
    GtkWidget *flow = gtk_flow_box_new();

    gtk_flow_box_set_selection_mode(GTK_FLOW_BOX(flow), GTK_SELECTION_NONE);
    gtk_flow_box_set_column_spacing(GTK_FLOW_BOX(flow), 8);
    gtk_flow_box_set_row_spacing(GTK_FLOW_BOX(flow), 8);
    gtk_flow_box_set_max_children_per_line(GTK_FLOW_BOX(flow), 6);
    return flow;
}

static void
fkit_flow_add(GtkWidget *flow, GtkWidget *button, const char *extra_class)
{
    GtkWidget *child = gtk_flow_box_child_new();

    gtk_widget_add_css_class(button, "verb-button");
    if (extra_class != NULL) gtk_widget_add_css_class(button, extra_class);
    gtk_flow_box_child_set_child(GTK_FLOW_BOX_CHILD(child), button);
    gtk_flow_box_append(GTK_FLOW_BOX(flow), child);
}

static GtkWidget *
fkit_note(const char *text)
{
    GtkWidget *label = gtk_label_new(text);

    gtk_widget_add_css_class(label, "fkit-note");
    gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(label), TRUE);
    return label;
}

/* The capability report, as the module prints it: key, tab, value. */
static void
fkit_fill_machine(GtkWidget *card_body)
{
    g_autofree char *script = module_script_path("05_field_kit");
    const char *argv[] = { script, "--capability", NULL };
    g_autofree char *text = run_capture(argv);
    g_auto(GStrv) lines = NULL;

    if (text == NULL || *text == '\0') {
        gtk_box_append(GTK_BOX(card_body), fkit_note("The module did not answer."));
        return;
    }
    lines = g_strsplit(text, "\n", -1);
    for (int i = 0; lines[i] != NULL; i++) {
        char *tab = strchr(lines[i], '\t');
        GtkWidget *row, *key, *value;

        if (tab == NULL) continue;
        *tab = '\0';
        row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
        key = gtk_label_new(lines[i]);
        value = gtk_label_new(tab + 1);
        gtk_widget_add_css_class(row, "fkit-kv-row");
        gtk_widget_add_css_class(key, "fkit-kv-key");
        gtk_widget_add_css_class(value, "fkit-kv-val");
        gtk_widget_set_size_request(key, 190, -1);
        gtk_label_set_xalign(GTK_LABEL(key), 0.0f);
        gtk_label_set_xalign(GTK_LABEL(value), 0.0f);
        gtk_label_set_selectable(GTK_LABEL(value), TRUE);
        gtk_widget_set_hexpand(value, TRUE);
        gtk_label_set_ellipsize(GTK_LABEL(value), PANGO_ELLIPSIZE_END);
        gtk_box_append(GTK_BOX(row), key);
        gtk_box_append(GTK_BOX(row), value);
        gtk_box_append(GTK_BOX(card_body), row);
    }
}

static GtkWidget *
fkit_build_overview(AppState *state, const char *module_id,
                    GtkWidget *status, GtkTextBuffer *out)
{
    GtkWidget *body;
    GtkWidget *outer = radio_view_shell("FIELD KIT",
        "RF pre-flight, the honesty check, and the synthetic source Live Traffic listens to.",
        &body);
    GtkWidget *machine_body;
    GtkWidget *checks_body;
    GtkWidget *machine = verb_card("THIS MACHINE", &machine_body);
    GtkWidget *checks = verb_card("CHECKS", &checks_body);
    GtkWidget *flow = fkit_flow();
    g_autofree char *summary = fkit_status_summary(module_id);
    GtkWidget *banner = gtk_label_new(summary);
    static const struct { const char *label; const char *verb; } probe[] = {
        { "Capability Report", "--capability" },
        { "Guard Check",       "--guard-check" },
        { "Selftest",          "--selftest" },
        { "Scenarios",         "--scenarios" },
    };

    fkit_fill_machine(machine_body);
    for (guint i = 0; i < G_N_ELEMENTS(probe); i++) {
        GtkWidget *button = gtk_button_new_with_label(probe[i].label);

        radio_bench_run_button(button, state, module_id, status, probe[i].verb, NULL);
        fkit_flow_add(flow, button, i == 0 ? "primary" : "flat");
    }
    gtk_box_append(GTK_BOX(checks_body), flow);
    gtk_box_append(GTK_BOX(checks_body),
        fkit_note("The guard check runs every radio-gated verb with nothing attached. "
                  "It fails honestly when a verb says what is missing, and it calls a verb "
                  "fabricated when it returns a success it cannot have earned."));
    gtk_widget_add_css_class(banner, "crec-survey-status");
    gtk_label_set_xalign(GTK_LABEL(banner), 0.0f);
    gtk_label_set_selectable(GTK_LABEL(banner), TRUE);
    gtk_box_append(GTK_BOX(body), banner);
    gtk_box_append(GTK_BOX(body), machine);
    gtk_box_append(GTK_BOX(body), checks);
    if (out != NULL) gtk_box_append(GTK_BOX(body), build_output_card(out));
    return outer;
}

/* A preset does not run anything: it writes the command into the field, so
   what is about to be sent is on screen and can be edited before it is. The
   module's own defaults are the interesting part, and they are worth reading
   before they fire. */
static void
fkit_preset_clicked(GtkButton *button, gpointer user_data)
{
    GtkWidget *entry = g_object_get_data(G_OBJECT(button), "preset-entry");
    const char *args = g_object_get_data(G_OBJECT(button), "preset-args");
    g_autofree char *expanded = NULL;

    (void) user_data;
    if (entry == NULL || args == NULL) return;
    /* {root} is expanded here rather than at run time, because the point of
       putting it in the field is to show the path that will be used. */
    if (strstr(args, "{root}") != NULL) {
        g_auto(GStrv) chunks = g_strsplit(args, "{root}", -1);
        expanded = g_strjoinv(IMSISTING_ROOT, chunks);
        args = expanded;
    }
    gtk_editable_set_text(GTK_EDITABLE(entry), args);
    gtk_editable_set_position(GTK_EDITABLE(entry), -1);
    gtk_widget_grab_focus(entry);
}

static GtkWidget *
fkit_preset_button(const char *label, const char *args, GtkWidget *entry)
{
    GtkWidget *button = gtk_button_new_with_label(label);

    g_object_set_data_full(G_OBJECT(button), "preset-args", g_strdup(args), g_free);
    g_object_set_data(G_OBJECT(button), "preset-entry", entry);
    g_signal_connect(button, "clicked", G_CALLBACK(fkit_preset_clicked), NULL);
    return button;
}

/* The command line a card's presets fill, and the button that runs it. Same
   shape as radio_bench_arg_action, except that the entry is handed back so the
   presets above can write into it, and the verb is named by the caller so a
   page other than the Field Kit can put its own verb behind the line. */
static GtkWidget *
fkit_composer_verb(AppState *state, const char *module_id, GtkWidget *status,
              GtkWidget **entry_out, const char *verb, const char *label,
              const char *placeholder, const char *button_label)
{
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *caption = gtk_label_new(label);
    GtkWidget *entry = gtk_entry_new();
    GtkWidget *button = gtk_button_new_with_label(button_label);

    gtk_label_set_xalign(GTK_LABEL(caption), 0.0f);
    gtk_widget_set_size_request(caption, 112, -1);
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry), placeholder);
    gtk_widget_set_hexpand(entry, TRUE);
    gtk_widget_add_css_class(entry, "verb-arg-entry");
    gtk_widget_add_css_class(button, "verb-button");
    gtk_widget_add_css_class(button, "primary");
    g_object_set_data(G_OBJECT(button), "state", state);
    g_object_set_data(G_OBJECT(button), "module-id", (gpointer) module_id);
    g_object_set_data(G_OBJECT(button), "status", status);
    g_object_set_data_full(G_OBJECT(button), "verb", g_strdup(verb), g_free);
    g_object_set_data(G_OBJECT(button), "arg-entry", entry);
    g_signal_connect(button, "clicked", G_CALLBACK(group_arg_clicked), NULL);
    gtk_box_append(GTK_BOX(row), caption);
    gtk_box_append(GTK_BOX(row), entry);
    gtk_box_append(GTK_BOX(row), button);
    *entry_out = entry;
    return row;
}

/* The Field Kit's own composer, whose every line runs --emit. */
static GtkWidget *
fkit_composer(AppState *state, const char *module_id, GtkWidget *status,
              GtkWidget **entry_out, const char *label, const char *placeholder,
              const char *button_label)
{
    return fkit_composer_verb(state, module_id, status, entry_out, "--emit",
                              label, placeholder, button_label);
}

static GtkWidget *
fkit_build_emitter(AppState *state, const char *module_id,
                   GtkWidget *status, GtkTextBuffer *out)
{
    GtkWidget *body;
    GtkWidget *outer = radio_view_shell("SYNTHETIC SOURCE",
        "Spec-shaped GSMTAP frames, so the decoder and the live view can be exercised with "
        "no radio, no antenna and no transmission licence.", &body);
    GtkWidget *live_body;
    GtkWidget *write_body;
    GtkWidget *live = verb_card("STREAM TO LIVE TRAFFIC", &live_body);
    GtkWidget *write = verb_card("WRITE A CAPTURE", &write_body);
    GtkWidget *live_entry = NULL;
    GtkWidget *write_entry = NULL;
    GtkWidget *live_flow = fkit_flow();
    GtkWidget *write_flow = fkit_flow();
    GtkWidget *live_line = fkit_composer(state, module_id, status, &live_entry,
        "Command", "mixed 12 0.25 udp", "Emit");
    GtkWidget *write_line = fkit_composer(state, module_id, status, &write_entry,
        "Command", "mixed 12 0.25 /path/to/capture.pcap", "Write");

    for (guint i = 0; i < G_N_ELEMENTS(fkit_scenarios); i++) {
        g_autofree char *stream = g_strdup_printf("%s 12 0.25 udp", fkit_scenarios[i].id);
        g_autofree char *file = g_strdup_printf("%s 12 0.25 {root}/captures/fieldkit_%s.pcap",
                                                fkit_scenarios[i].id, fkit_scenarios[i].id);
        fkit_flow_add(live_flow,
                      fkit_preset_button(fkit_scenarios[i].label, stream, live_entry), "flat");
        fkit_flow_add(write_flow,
                      fkit_preset_button(fkit_scenarios[i].label, file, write_entry), "flat");
    }
    gtk_box_append(GTK_BOX(live_body), live_flow);
    gtk_box_append(GTK_BOX(live_body),
        fkit_note("The count is how many times the scenario repeats, and the decimal is the gap "
                  "between frames - twelve of them is roughly ten seconds for Live Traffic to "
                  "watch. A preset fills the command line; Emit sends it. Open that page first, "
                  "because the emitter waits for nothing."));
    gtk_box_append(GTK_BOX(live_body), live_line);
    gtk_box_append(GTK_BOX(write_body), write_flow);
    gtk_box_append(GTK_BOX(write_body),
        fkit_note("Written as a real pcap - Ethernet, IPv4, UDP on 4729 - so tshark and "
                  "03_gsmtap.sh --decode read it, with the same frame spacing as the stream. "
                  "A file of that name is overwritten."));
    gtk_box_append(GTK_BOX(write_body), write_line);
    gtk_box_append(GTK_BOX(body), live);
    gtk_box_append(GTK_BOX(body), write);
    if (out != NULL) gtk_box_append(GTK_BOX(body), build_output_card(out));
    return outer;
}

/* The guard matrix, read back from the report the check writes. */
typedef struct {
    GtkWidget *list;
    GtkWidget *summary;
} FkitGuards;

static const char *
fkit_guard_class(const char *status)
{
    /* Green is the honest failure - non-zero, and it said why. */
    if (g_strcmp0(status, "honest-fail") == 0) return "fk-guard-ok";
    if (g_strcmp0(status, "silent-fail") == 0) return "fk-guard-bad";
    if (g_strcmp0(status, "FABRICATED") == 0) return "fk-guard-bad";
    return "fk-guard-warn";
}

static void
fkit_guards_fill(FkitGuards *guards)
{
    g_autofree char *path = g_build_filename(IMSISTING_ROOT, "loot", "field_kit",
                                             "guard-check.tsv", NULL);
    g_autofree char *text = NULL;
    g_autofree char *summary = NULL;
    GtkWidget *child;
    guint total = 0, honest = 0, silent = 0, fabricated = 0, other = 0;

    while ((child = gtk_widget_get_first_child(guards->list)) != NULL)
        gtk_list_box_remove(GTK_LIST_BOX(guards->list), child);

    if (g_file_get_contents(path, &text, NULL, NULL)) {
        g_auto(GStrv) lines = g_strsplit(text, "\n", -1);

        for (int i = 0; lines[i] != NULL; i++) {
            g_auto(GStrv) field = NULL;
            const char *status;
            GtkWidget *row, *box, *dot, *module, *verb, *detail;

            if (*lines[i] == '\0') continue;
            field = g_strsplit(lines[i], "\t", 4);
            status = field[2];
            if (g_strcmp0(field[0], "module") == 0) continue;   /* the header row */
            if (field[0] == NULL || field[1] == NULL || status == NULL) continue;
            total++;
            if (g_strcmp0(status, "honest-fail") == 0) honest++;
            else if (g_strcmp0(status, "silent-fail") == 0) silent++;
            else if (g_strcmp0(status, "FABRICATED") == 0) fabricated++;
            else other++;

            row = gtk_list_box_row_new();
            box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
            dot = gtk_label_new("\u25cf");
            module = gtk_label_new(field[0]);
            verb = gtk_label_new(field[1]);
            detail = gtk_label_new((field[3] != NULL && *field[3] != '\0') ? field[3] : status);
            gtk_widget_add_css_class(box, "fk-guard-row");
            gtk_widget_add_css_class(dot, "status-dot");
            gtk_widget_add_css_class(dot, fkit_guard_class(status));
            gtk_widget_add_css_class(module, "fk-guard-module");
            gtk_widget_add_css_class(verb, "fk-guard-verb");
            gtk_widget_add_css_class(detail, "fk-guard-detail");
            gtk_widget_set_size_request(module, 150, -1);
            gtk_widget_set_size_request(verb, 170, -1);
            gtk_label_set_xalign(GTK_LABEL(module), 0.0f);
            gtk_label_set_xalign(GTK_LABEL(verb), 0.0f);
            gtk_label_set_xalign(GTK_LABEL(detail), 0.0f);
            gtk_label_set_ellipsize(GTK_LABEL(detail), PANGO_ELLIPSIZE_END);
            gtk_label_set_selectable(GTK_LABEL(detail), TRUE);
            gtk_widget_set_hexpand(detail, TRUE);
            gtk_box_append(GTK_BOX(box), dot);
            gtk_box_append(GTK_BOX(box), module);
            gtk_box_append(GTK_BOX(box), verb);
            gtk_box_append(GTK_BOX(box), detail);
            gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), box);
            gtk_list_box_append(GTK_LIST_BOX(guards->list), row);
        }
    }

    if (total == 0) {
        summary = g_strdup("No report read yet - run the guard check.");
    } else {
        summary = g_strdup_printf("%u verbs:  %u failed honestly  |  %u failed silently  |  "
                                  "%u fabricated  |  %u other", total, honest, silent,
                                  fabricated, other);
    }
    gtk_label_set_text(GTK_LABEL(guards->summary), summary);
}

static void
fkit_guards_refresh(GtkWidget *widget, gpointer user_data)
{
    (void) widget;
    fkit_guards_fill(user_data);
}

static void
fkit_guards_status_changed(GObject *object, GParamSpec *pspec, gpointer user_data)
{
    (void) object;
    (void) pspec;
    fkit_guards_fill(user_data);
}

static GtkWidget *
fkit_build_guards(AppState *state, const char *module_id,
                  GtkWidget *status, GtkTextBuffer *out)
{
    GtkWidget *body;
    GtkWidget *outer = radio_view_shell("HONESTY CHECK",
        "Every radio-gated verb, run with nothing attached. Non-zero and naming what is "
        "missing is the honest answer; success is the failure this view exists to catch.",
        &body);
    GtkWidget *matrix_body;
    GtkWidget *matrix = verb_card("GUARD MATRIX", &matrix_body);
    GtkWidget *bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *summary = gtk_label_new(NULL);
    GtkWidget *run = gtk_button_new_with_label("Run guard check");
    GtkWidget *refresh = gtk_button_new_with_label("Refresh");
    GtkWidget *scroll = gtk_scrolled_window_new();
    GtkWidget *list = gtk_list_box_new();
    FkitGuards *guards = g_new0(FkitGuards, 1);

    guards->list = list;
    guards->summary = summary;
    g_object_set_data_full(G_OBJECT(list), "fkit-guards", guards, g_free);

    gtk_widget_set_hexpand(summary, TRUE);
    gtk_label_set_xalign(GTK_LABEL(summary), 0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(summary), PANGO_ELLIPSIZE_END);
    gtk_widget_add_css_class(summary, "fkit-note");
    gtk_widget_add_css_class(run, "verb-button");
    gtk_widget_add_css_class(run, "primary");
    gtk_widget_add_css_class(refresh, "flat");
    radio_bench_run_button(run, state, module_id, status, "--guard-check", NULL);
    g_signal_connect(refresh, "clicked", G_CALLBACK(fkit_guards_refresh), guards);
    /* The report is written by the run, so the list follows the status pill:
       while that reads Running the file is still being appended to, and when it
       settles the rows are there to be read. */
    g_signal_connect(status, "notify::label", G_CALLBACK(fkit_guards_status_changed), guards);

    gtk_list_box_set_selection_mode(GTK_LIST_BOX(list), GTK_SELECTION_NONE);
    gtk_list_box_set_show_separators(GTK_LIST_BOX(list), TRUE);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), list);
    gtk_widget_set_size_request(scroll, -1, 240);
    gtk_widget_set_vexpand(scroll, TRUE);
    gtk_widget_add_css_class(scroll, "fkit-guard-scroll");

    gtk_box_append(GTK_BOX(bar), summary);
    gtk_box_append(GTK_BOX(bar), run);
    gtk_box_append(GTK_BOX(bar), refresh);
    gtk_box_append(GTK_BOX(matrix_body), bar);
    gtk_box_append(GTK_BOX(matrix_body), scroll);
    gtk_box_append(GTK_BOX(body), matrix);
    if (out != NULL) gtk_box_append(GTK_BOX(body), build_output_card(out));
    fkit_guards_fill(guards);
    return outer;
}

static ModuleSubmenuEntry fkit_entries[] = {
    { "Overview", "dialog-information-symbolic", NULL, fkit_build_overview },
    { "Emitter",  "media-record-symbolic",       NULL, fkit_build_emitter },
    { "Guards",   "security-high-symbolic",      NULL, fkit_build_guards },
};
static ModuleSubmenuEntry gair_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--decode-pcap={capture}|--decode-si:Decode SI|--decode-sch:Decode SCH" },
    { "Cipher",
      "channel-secure-symbolic",
      "--cipher-audit:Cipher Audit|--a5-1-keystream:A5/1 Keystream" },
    { "Paging & Identity",
      "system-search-symbolic",
      "--paging-group=001010000000001|--imsi-exposure-tsv:IMSI Exposure|~--identity-exposure:Identity Exposure" },
};
static ModuleSubmenuEntry gatk_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--imsi-catcher-sequence:IMSI Catcher Sequence|--paging-race:Paging Race|--kc-recovery:Kc Recovery" },
    { "Vectors",
      "security-high-symbolic",
      "#TRANSMIT VECTORS|--vector-imsi-catcher:IMSI Catcher (O1)|--vector-a5-downgrade:A5/1 Downgrade|"
      "--vector-tmsi-deanon:TMSI De-anonymisation|--vector-kc-recovery:Kc Recovery|"
      "#TRANSMIT|~--transmit:Transmit BCCH Carrier|"
      "#TRANSMIT GATE|--tx-ack:Transmit Acknowledgement" },
    { "Air interface",
      "network-wireless-symbolic",
      "#BURSTS AND CHANNELS|--burst-layout:Burst Layout|--dummy-burst:C0 Idle Burst|"
      "--ccch-conf:CCCH_CONF|--sch-payload:SCH Payload|--fcch-facts:FCCH Facts|"
      "--multiframe-map:51-Frame Map|--ccch-blocks:CCCH Blocks|--rach-blocks:RACH Blocks|"
      "--sdcch-map:SDCCH Map|"
      "#TIMING|--frame-facts:Frame Facts|~--fn-split:Frame Split|~--fn-join:Frame Join|~--ta:Timing Advance|"
      "#PAGING|~--paging-schedule:Paging Schedule" },
    { "Identity",
      "auth-smartcard-symbolic",
      "#BUILD|--build-identity-request:Build Identity Request|--build-cipher-mode:Build Cipher Mode|"
      "--build-lu-accept:Build LU Accept|--build-tmsi-realloc:Build TMSI Realloc|"
      "--build-paging-request:Build Paging Request|"
      "--build-immediate-assignment:Build Immediate Assignment|~--mobile-identity:Mobile Identity|"
      "#CLASSMARK|--classmark|--classmark-downgrade:Classmark Downgrade|--classmark1|"
      "--classmark1-encode:Classmark 1 Encode|~--classmark3:Classmark 3 Decode|"
      "#LAPDM|--lapdm-ui:LAPDm UI Frame|--lapdm-fill:Fill Frame|--lapdm-bursts:LAPDm Bursts|"
      "--n201:N201 Limit" },
    { "Ciphers",
      "channel-secure-symbolic",
      "#A5 FAMILY|--a5-1-keystream:A5/1 Keystream|~--a5-count:A5/1 COUNT|--a5-2-keystream:A5/2 Keystream|"
      "--a5-3-keystream:A5/3 Keystream|--a5-4-keystream:A5/4 Keystream|"
      "#KGCORE|~--kasumi:KASUMI|~--f8-keystream:f8 Keystream|~--f9-mac:f9 MAC|--alg-name:Algorithm Name|"
      "#RECOVERY|~--kc-verify:Kc Verify|~--kc-search:Kc Search|~--kc-known-plaintext:Known Plaintext|"
      "~--decrypt:Decrypt" },
    { "TMSI store",
      "edit-find-symbolic",
      "--deanon-list:Recorded Pairings|~--deanon-lookup:TMSI Lookup|~--deanon-record:TMSI Record|"
      "~--deanon-confirm:TMSI Confirm" },
    { "C1",
      "preferences-system-symbolic",
      "--c1=-100 -90 33 5|--plan:Plan|--plan-tsv:Plan TSV" },
};
static ModuleSubmenuEntry uair_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--decode-pcap={capture}|--decode-sib:Decode SIB|--sib-fields:SIB Fields" },
    { "Integrity",
      "channel-secure-symbolic",
      "--aka-flow:AKA Flow|--count-i:COUNT-I|--integrity-tsv:Integrity TSV" },
    { "MAC",
      "network-receive-symbolic",
      "--mac-input:MAC Input|--sib6-carriers:SIB6 Carriers" },
    { "Frequencies",
      "preferences-system-symbolic",
      "--mhz=2140|--uarfcn=10700" },
};
static ModuleSubmenuEntry latt_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--decode-nas:Decode NAS|--encode-attach:Encode Attach|--ue-stack:UE Stack" },
    { "Identity",
      "auth-smartcard-symbolic",
      "--imsi-decode:Decode IMSI|--imsi-encode:Encode IMSI|~--identity-exposure:Identity Exposure" },
    { "GUTI",
      "network-wired-symbolic",
      "#CODEC|--decode-guti:Decode GUTI|--encode-guti:Encode GUTI|#ATTACH|--encode-attach-guti:Encode Attach (GUTI)" },
    { "Integrity",
      "channel-secure-symbolic",
      "#NAS-MAC|--nas-mac:NAS MAC|#DOWNLINK|--build-attach-accept:Build Attach Accept|--build-tau-accept:Build TAU Accept" },
};
static ModuleSubmenuEntry lair_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "#CONTROL|--start:Start|--stop:Stop|#STATUS|--status:Status" },
    { "Decode",
      "document-open-symbolic",
      "--decode-sib:Decode SIB|--decode-mib:Decode MIB|--paging-frame:Paging Frame" },
    /* X2AP is what two base stations say to each other, and it is the
       message a fake cell answers a real one with. It gets its own view
       because it is a different protocol from the air interface, not a
       filter on it. */
    { "X2",
      "network-transmit-receive-symbolic",
      "--x2-setup:Build X2 Setup|--x2-decode:Decode X2" },
    { "Tools",
      "preferences-system-symbolic",
      "--earfcn=6300|--power-ref:Power Reference|--gen-enb-conf:Generate eNB Config" },
    { "Transmit",
      "media-playback-start-symbolic",
      "--rrc-tx:Build and Transmit RRC" },
    /* The message builders. Each button carries a worked argument line so it
       demonstrates the encoder instead of printing a usage error, and none of
       them sends: the octets land in the output card and a file. */
    { "Messages",
      "document-send-symbolic",
      "--build-meas-report=--meas-id 1 --rsrp 60 --rsrq 20:Measure Report"
      "|--build-rrc-release=--tid 0 --release-cause other:RRC Release"
      "|--build-reest-reject:Re-est Reject"
      "|#PWS|--build-sib10=--message-id 4370 --serial 1 --warning-type 2A00:SIB10 Alert"
      "|--build-sib11=--message-id 4371 --serial 2 --segment-type lastSegment --segment-number 0 --payload 0001:SIB11 Segment"
      "|--build-sib12=--message-id 4372 --serial 3 --segment-type notLastSegment --segment-number 0 --payload 0001:SIB12 Segment"
      "|--enb-sib-schedule=--sib 10 --hex 0001:SIB Schedule" },
};
static ModuleSubmenuEntry lcore_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--decode-gtp-c:Decode GTP-C|--decode-gtp-u:Decode GTP-U|--decode-diameter:Decode Diameter" },
    { "Attacks",
      "security-high-symbolic",
      "#FORGE|--gtp-modify-bearer:Modify Bearer|--gtp-csr-forge:Forge CSR|--gtpc-send:Send to Core|--diameter-send:Send to HSS|#AUDIT|--gtpdoor-detect:Detect GTPdoor|--cdr-fraud-check:CDR Fraud Check|--fs20-audit:FS.20 Audit" },
    { "Build",
      "document-new-symbolic",
      "--build-air:Build AIR|--build-ulr:Build ULR|--build-clr:Build CLR|--s1ap" },
    { "Recon",
      "system-search-symbolic",
      "--surface:Surface|--require-core:Require Core|--plan:Plan" },
    /* The two builders that read the transport rather than the protocol: an
       outer GTPv1-U header carrying an inner GTP message, and an MBMS session
       with no GTP signaller above it. */
    { "Encapsulation",
      "network-transmit-receive-symbolic",
      "--gtp-in-gtp=--payload DEADBEEF --with-ip:GTP in GTP"
      "|--mbms-session=--mood:MBMS Session" },
};
static ModuleSubmenuEntry nair_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "#CONTROL|--start:Start|--stop:Stop|#STATUS|--status:Status|~--tx" },
    { "Decode",
      "document-open-symbolic",
      "--decode-mib:Decode MIB|--decode-sib1:Decode SIB1|--decode-rrc:Decode RRC" },
    { "Build",
      "security-high-symbolic",
      "#RRC|--build-rrc-reconfig:Build RRC Reconfig|--build-meas-report:Build Meas Report|#BEAM|--beam-sweep:Beam Sweep" },
    { "Signals",
      "network-wireless-symbolic",
      "--ssb:SSB|--prach:PRACH|--pci=0 0" },
    { "Tools",
      "preferences-system-symbolic",
      "--arfcn=640000|--gen-gnb-conf:Generate gNB Config|--gen-core-conf:Generate Core Config" },
    /* One SSB burst as baseband samples, which is the artefact the tree could
       not produce before: every other NR signal path here stops at coded bits. */
    { "Waveform",
      "media-playback-start-symbolic",
      "--ssb-waveform=/tmp/imsisting/nr_air/ssb.cf32:Write SSB Samples" },
};
static ModuleSubmenuEntry ncore_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--nf-list:List NFs|--nf-discovery=NRF|--ue-id-pair:UE Id Pair" },
    { "Decode",
      "document-open-symbolic",
      "#NAS|--decode-nas-5gs:Decode NAS-5GS|#NGAP|--decode-ngap:Decode NGAP|#PFCP|--decode-pfcp:Decode PFCP|#GTPU|--decode-gtpu:Decode GTP-U|--gtpu-header:GTP-U Header|#IDENTITY|--decode-5g-guti:Decode 5G-GUTI" },
    { "Crypto",
      "channel-secure-symbolic",
      "--aka-flow:AKA Flow|--kseaf:KSEAF" },
    { "Rules",
      "preferences-system-symbolic",
      "#BUILD|--pfcp-build:Build Session Request|#SEND|--pfcp-send:Send to UPF|--pfcp-rules:PFCP Rules|--plan:Plan" },
    { "Forge NGAP",
      "network-transmit-receive-symbolic",
      "#BUILD|--ngap-initial-ue:Initial UE Message|--ngap-downlink-nas:Downlink NAS|--ngap-paging:Page a Handset|--ngap-ngsetup:Open the Node|#SEND|--ngap-send:Send to AMF" },
    /* Xn is the interface between two NG-RAN nodes, so its setup message is
     * the same handshake as NG Setup addressed to a peer instead of a core.
     * Built here, not sent from here: Xn rides SCTP 38422 on PPID 61, and a
     * message sent with NGAP's PPID 60 is dissected as a different protocol
     * that reads every field differently. */
    { "Forge Xn",
      "network-transmit-receive-symbolic",
      "#BUILD|--xnap-setup:Open to the Peer|#READ|--xnap-decode:Decode Xn" },
};
static ModuleSubmenuEntry suci_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--parse-suci:Parse SUCI|--build-suci:Build SUCI|--audit:Audit" },
    { "Conceal",
      "channel-secure-symbolic",
      "#CONCEAL|--conceal:Conceal|~--deconceal|#CRYPTO|--genkey:Generate Key|--hkdf:HKDF|--verify-hnkey:Verify HN Key" },
    { "MSIN",
      "auth-smartcard-symbolic",
      "--msin-decode:Decode MSIN|--msin-encode:Encode MSIN" },
};
static ModuleSubmenuEntry dwn_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--detect:Detect|--path=steer-down|--causes:Causes" },
    { "Build",
      "security-high-symbolic",
      "#BUILD|--build-security-mode:Build Security Mode|--build-reject:Build Reject|--tx-reject:Transmit Reject|--build-sib1:Build SIB1|--null-cipher-table:Null Cipher Table|#PLAN|--reject-cause=22 EMM|--plan:Plan" },
};
static ModuleSubmenuEntry sim_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--parse-apdu:Parse APDU|--build-apdu:Build APDU|--get-response:Get Response" },
    { "Read",
      "document-open-symbolic",
      "#READ|--read-binary:Read Binary|--read-record:Read Record|#SELECT|--select-fid=3F00|--file-id" },
    { "Decode",
      "auth-smartcard-symbolic",
      "--decode-iccid:Decode ICCID|--decode-imsi:Decode IMSI|--decode-ad:Decode AD" },
    { "OTA",
      "document-send-symbolic",
      "#PARSE|--parse-ota:Parse OTA|#CONFIG|--spi=1|~--ota-key:OTA Key|--rsp:RSP|#PLAN|--plan:Plan" },
    { "Side channel",
      "auth-smartcard-symbolic",
      "#DPA (COMP128-1)|~--dpa-model:Leak Point (ki rand)|~--dpa-sim:Key Recovery (ki)|~--dpa-sweep:Sweeps (ki)|#PLAN|--plan=dpa-lab:DPA Rig" },
    /* The card's own authentication: the algorithms a SIM runs, checked against
       the standards' test vectors, and the ES9+ requests a profile download
       starts with. */
    { "Authentication",
      "security-high-symbolic",
      "--sim-auth-check=std:Check Standard Vectors"
      "|--sim-auth=milenage 465B5CE8B199B49FAA5F0A2EE238A6BC 23553CBE9637A89D218AE64D0E1759CF --op CDC202D526D4F5B6B7C0B69B3F4A5C47:Milenage Vector"
      "|--es9-plus=initiateAuthentication --smds smds.example.net:443:ES9+ Request" },
};
static ModuleSubmenuEntry pcap_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--summary={capture}|--list={capture}|--extract={capture} 1 1" },
    { "Flows",
      "network-transmit-receive-symbolic",
      "--conversations:Conversations|--hierarchy:Hierarchy" },
    { "Identity",
      "auth-smartcard-symbolic",
      "--identities:Identities|--ident-list:Identity List" },
    { "Manage",
      "preferences-system-symbolic",
      "#SAMPLE|--build-sample:Build Sample|#MANAGE|--clear:Clear" },
};
static ModuleSubmenuEntry imsi_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--audit:Audit|--report:Report|--harvest={capture}" },
    { "Analysis",
      "system-search-symbolic",
      "#CORRELATE|--cross:Cross-reference|--map:Map|#MARLIN|--marlin:Marlin|--marlin-msgs:Marlin Messages" },
    { "Identity",
      "auth-smartcard-symbolic",
      "--identities:Identities|--subscribers-tsv:Subscribers TSV|--exposure-tsv:Exposure TSV" },
    { "Manage",
      "preferences-system-symbolic",
      "--redact:Redact|--clear:Clear" },
};
static ModuleSubmenuEntry caud_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--from-pcap={capture}|--score:Score|--table:Table" },
    { "SMC",
      "channel-secure-symbolic",
      "--parse-smc:Parse SMC|--downgrade-check:Downgrade Check" },
    { "Sessions",
      "document-open-symbolic",
      "#LOAD|--sessions-load:Load Sessions|~--session|#MANAGE|--clear:Clear" },
    /* The failure side of authentication: the cause table says what a network
       tells an observer by answering one way rather than another, and the
       sequence-number verb recovers the counter a UE conceals in AUTS. Both
       take arguments, so both render as an entry and a Run button. */
    { "Authentication",
      "auth-smartcard-symbolic",
      "--auth-causes:Causes|~--auth-session:Session Outcomes|~--sqn-recover:Sequence Number" },
};
/* ── The CVE catalogue ───────────────────────────────────────────────────────

   All three catalogue modules publish the same five columns, so all three
   pages are built from one reader:

       id <TAB> kind <TAB> class <TAB> needs <TAB> what the vector is

   id is the CVE number the module keys its runs on; kind is "probe" (the module
   measures the target itself) or "handoff" (the far end has to be something
   this module does not drive); class is the view the vector is filed under; and
   needs is what has to be in the room. Every one of them is on the card,
   because a vector that cannot run here has to say what is missing before it is
   pressed rather than after.

   The LTE catalogue is fifty-six vectors, so the page is one view per class
   rather than one long scroll, and inside a view every vector is its own card,
   so the button that runs a vector belongs to that vector and not to a row in a
   table above it.
   -------------------------------------------------------------------------- */

typedef struct {
    char *id;
    char *kind;
    char *klass;
    char *needs;
    char *what;
} CveRow;

typedef struct {
    char *module_id;
    GPtrArray *rows;
} CveCatalogue;

/* --list-cves prints a heredoc, so it cannot change while the process runs; and
   GTK builds every view of a page the moment that page is opened, so without
   this the module would be spawned once per class view to print the same table
   over and over. One capture per module per process. */
static GPtrArray *cve_catalogues = NULL;

static void
cve_row_free(gpointer p)
{
    CveRow *r = p;

    g_free(r->id);
    g_free(r->kind);
    g_free(r->klass);
    g_free(r->needs);
    g_free(r->what);
    g_free(r);
}

static void
cve_catalogue_free(gpointer p)
{
    CveCatalogue *c = p;

    g_ptr_array_unref(c->rows);
    g_free(c->module_id);
    g_free(c);
}

static GPtrArray *
cve_rows(const char *module_id)
{
    g_autofree char *script = NULL;
    g_autofree char *text = NULL;
    g_auto(GStrv) lines = NULL;
    CveCatalogue *entry;
    GPtrArray *rows;

    if (cve_catalogues == NULL)
        cve_catalogues = g_ptr_array_new_with_free_func(cve_catalogue_free);
    for (guint i = 0; i < cve_catalogues->len; i++) {
        CveCatalogue *c = g_ptr_array_index(cve_catalogues, i);

        if (g_strcmp0(c->module_id, module_id) == 0)
            return c->rows;
    }

    /* Owned by the cache from here on: every path below - a module that did not
       answer included - has to leave an array behind, or the next view of the
       page spawns the module again to learn the same thing. */
    rows = g_ptr_array_new_with_free_func(cve_row_free);
    script = module_script_path(module_id);
    {
        const char *argv[] = { script, "--list-cves", NULL };
        text = run_capture(argv);
    }
    if (text != NULL) {
        lines = g_strsplit(text, "\n", -1);
        for (int i = 0; lines[i] != NULL; i++) {
            g_auto(GStrv) f = g_strsplit(lines[i], "\t", 5);
            CveRow *r;

            /* The first line names the columns; a line with fewer than five
               fields is a short read or a blank, and neither is a vector. */
            if (f[0] == NULL || f[1] == NULL || f[2] == NULL ||
                f[3] == NULL || f[4] == NULL)
                continue;
            if (g_strcmp0(f[0], "id") == 0)
                continue;
            r = g_new0(CveRow, 1);
            r->id = g_strdup(f[0]);
            r->kind = g_strdup(f[1]);
            r->klass = g_strdup(f[2]);
            r->needs = g_strdup(f[3]);
            r->what = g_strdup(f[4]);
            g_ptr_array_add(rows, r);
        }
    }

    entry = g_new0(CveCatalogue, 1);
    entry->module_id = g_strdup(module_id);
    entry->rows = rows;                 /* transfer: the cache owns it now */
    g_ptr_array_add(cve_catalogues, entry);
    return rows;
}

/* One KEY / value line, the way the Field Kit prints the machine it is on. */
static void
cve_fill_meta(GtkWidget *card_body, const char *key, const char *value)
{
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *k = gtk_label_new(key);
    GtkWidget *v = gtk_label_new(value);

    gtk_widget_add_css_class(row, "cve-kv-row");
    gtk_widget_add_css_class(k, "cve-kv-key");
    gtk_widget_add_css_class(v, "cve-kv-val");
    gtk_widget_set_size_request(k, 110, -1);
    gtk_label_set_xalign(GTK_LABEL(k), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(v), 0.0f);
    gtk_label_set_selectable(GTK_LABEL(v), TRUE);
    gtk_widget_set_hexpand(v, TRUE);
    gtk_label_set_wrap(GTK_LABEL(v), TRUE);
    gtk_box_append(GTK_BOX(row), k);
    gtk_box_append(GTK_BOX(row), v);
    gtk_box_append(GTK_BOX(card_body), row);
}

/* ── the result a card shows ──────────────────────────────────────────
   Every module answers in KEY<TAB>value lines, so a result is read as rows
   and not as a transcript - the same shape as the vector's own kind and needs
   rows, so a result and the vector it came from are read the same way.

   The card owns it. The raw output card this toolkit grew up with is being
   retired module by module, and a listing or a run belongs in the rectangle
   that started it rather than in a text view bolted to the bottom of the page.
   Wiring a button with cve_result_wire() gives it that card and keeps the
   command line out of everything the operator reads. */
typedef struct {
    GtkWidget *root;    /* what the run holds open until it reports */
    GtkWidget *body;    /* the rows */
    GtkWidget *idle;    /* shown until something runs */
} CveResult;

#define CVE_RESULT_ROWS 24

/* Clear the rows, keeping the idle note. It is a child of the body too, and
   removing it would leave res->idle pointing at a disposed widget - which is
   exactly how pressing a card's button a second time used to crash. */
static void
cve_result_rows_clear(CveResult *res)
{
    GtkWidget *child;

    if (res == NULL || res->body == NULL) return;
    child = gtk_widget_get_first_child(res->body);
    while (child != NULL) {
        GtkWidget *next = gtk_widget_get_next_sibling(child);

        if (child != res->idle) gtk_box_remove(GTK_BOX(res->body), child);
        child = next;
    }
}

/* A listing row is a record, not a sentence, but the three listings a CVE
   module answers with do not agree on their columns - --list-cves gives
   id/kind/class/needs/label, --runs-tsv id/status/target/evidence/ts, and
   --list-findings id/class/summary/reference. So the row is read as its anchor
   and then everything the module said after it: the id is a column, so records
   line up, and the rest is one wrapping line rather than four cells whose
   widths would have to be guessed per verb. */
static void
cve_result_wide(GtkWidget *body, const char *line)
{
    const char *tab = strchr(line, '\t');
    g_autofree char *id = g_strndup(line, (gsize)(tab - line));
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *k = gtk_label_new(id);
    GtkWidget *v = gtk_label_new(tab + 1);

    gtk_widget_add_css_class(row, "cve-kv-row");
    gtk_widget_add_css_class(k, "cve-kv-key");
    gtk_widget_add_css_class(v, "cve-kv-val");
    gtk_widget_set_size_request(k, 150, -1);
    gtk_label_set_xalign(GTK_LABEL(k), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(v), 0.0f);
    gtk_label_set_selectable(GTK_LABEL(v), TRUE);
    gtk_label_set_wrap(GTK_LABEL(v), TRUE);
    gtk_label_set_wrap_mode(GTK_LABEL(v), PANGO_WRAP_WORD_CHAR);
    gtk_widget_set_hexpand(v, TRUE);
    gtk_box_append(GTK_BOX(row), k);
    gtk_box_append(GTK_BOX(row), v);
    gtk_box_append(GTK_BOX(body), row);
}

static void
cve_result_fill(CveResult *res, const char *text, gboolean ok)
{
    g_auto(GStrv) lines = NULL;
    guint shown = 0, total = 0;

    if (res == NULL || res->body == NULL) return;

    cve_result_rows_clear(res);
    gtk_widget_set_visible(res->idle, FALSE);

    lines = g_strsplit(text != NULL ? text : "", "\n", -1);
    for (int i = 0; lines[i] != NULL; i++) {
        const char *line = lines[i];
        const char *tab;

        while (*line == ' ' || *line == '\t') line++;
        if (*line == '\0') continue;
        total++;
        if (shown >= CVE_RESULT_ROWS) continue;

        tab = strchr(line, '\t');
        /* A leading "id\tkind\t..." is the column header of a listing, not a
           row of one. */
        if (tab != NULL && g_str_has_prefix(line, "id\t")) continue;
        if (tab != NULL) {
            /* Three fields or more is a listing row; two is a key and a value,
               which is what --run-cve and --plan answer with. */
            if (strchr(tab + 1, '\t') != NULL)
                cve_result_wide(res->body, line);
            else {
                g_autofree char *key = g_strndup(line, (gsize)(tab - line));

                cve_fill_meta(res->body, key, tab + 1);
            }
        } else {
            gtk_box_append(GTK_BOX(res->body), fkit_note(line));
        }
        shown++;
    }

    if (shown == 0)
        gtk_box_append(GTK_BOX(res->body),
                       fkit_note(ok ? "The module reported nothing."
                                    : "The module failed without a message."));
    else if (total > shown) {
        g_autofree char *more = g_strdup_printf(
            "and %u more - the classes on the left list every one.",
            total - shown);

        gtk_box_append(GTK_BOX(res->body), fkit_note(more));
    }
}

static void
cve_result_done(const char *text, gboolean ok, int status, gpointer user_data)
{
    CveResult *res;

    (void) status;
    if (user_data == NULL) return;
    res = g_object_get_data(G_OBJECT(user_data), "cve-result");
    cve_result_fill(res, text, ok);
}

/* A press is answered at once: the card says it is working before the module
   has had time to. A composer with an empty field is not a press, though - it
   runs nothing, and says so itself. */
static void
cve_result_pressed(GtkButton *button, gpointer user_data)
{
    CveResult *res = user_data;

    if (res == NULL || res->body == NULL) return;
    if (button != NULL) {
        GtkWidget *entry = g_object_get_data(G_OBJECT(button), "arg-entry");

        if (entry != NULL) {
            const char *typed = gtk_editable_get_text(GTK_EDITABLE(entry));

            if (typed == NULL || *typed == '\0') return;
        }
    }
    cve_result_rows_clear(res);
    gtk_widget_set_visible(res->idle, FALSE);
    gtk_box_append(GTK_BOX(res->body), fkit_note("Running..."));
}

static GtkWidget *
cve_result_strip(CveResult **out)
{
    CveResult *res = g_new0(CveResult, 1);
    GtkWidget *root  = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    GtkWidget *head  = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *title = gtk_label_new("RESULT");
    GtkWidget *body  = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);

    res->root = root;
    res->body = body;
    res->idle = fkit_note("Not run yet.");

    gtk_widget_add_css_class(root,  "cve-result");
    gtk_widget_add_css_class(head,  "cve-result-head");
    gtk_widget_add_css_class(title, "cve-result-title");
    gtk_widget_add_css_class(body,  "cve-result-body");
    gtk_widget_set_halign(title, GTK_ALIGN_START);
    gtk_widget_set_hexpand(title, TRUE);
    gtk_box_append(GTK_BOX(head), title);
    gtk_box_append(GTK_BOX(body), res->idle);
    gtk_box_append(GTK_BOX(root), head);
    gtk_box_append(GTK_BOX(root), body);

    /* The run keeps a reference to root, so this survives until the run has
       reported - a page closed mid-run does not pull the ground away. */
    g_object_set_data_full(G_OBJECT(root), "cve-result", res, g_free);
    if (out != NULL) *out = res;
    return root;
}

/* Hand a button the card it should fill, and the words the operator will read
   afterwards. The label is spelled out here rather than derived from the verb,
   because the verb is a shell word and this is a sentence. */
static void
cve_result_wire(GtkWidget *button, CveResult *res, const char *label)
{
    if (res == NULL) return;
    g_object_set_data_full(G_OBJECT(button), "label", g_strdup(label), g_free);
    g_object_set_data(G_OBJECT(button), "done", (gpointer) cve_result_done);
    g_object_set_data(G_OBJECT(button), "done-owner", res->root);
    g_signal_connect(button, "clicked", G_CALLBACK(cve_result_pressed), res);
}

/* A button that lists rather than runs: the answer is already on this machine,
   so it is read at the press and shown in the card that asked for it. */
typedef struct {
    CveResult *res;
    char *module_id;
    char *verb;
} CveListing;

static void
cve_listing_free(gpointer p)
{
    CveListing *l = p;

    g_free(l->module_id);
    g_free(l->verb);
    g_free(l);
}

static void
cve_listing_clicked(GtkButton *button, gpointer user_data)
{
    CveListing *l = user_data;
    g_autofree char *script = module_script_path(l->module_id);
    const char *argv[] = { script, l->verb, NULL };
    g_autofree char *text = NULL;

    (void) button;
    cve_result_pressed(NULL, l->res);
    text = run_capture(argv);
    if (text == NULL) {
        if (l->res->body != NULL) {
            cve_result_rows_clear(l->res);
            gtk_widget_set_visible(l->res->idle, FALSE);
            gtk_box_append(GTK_BOX(l->res->body),
                           fkit_note("That listing could not be read."));
        }
        return;
    }
    cve_result_fill(l->res, text, TRUE);
}

static GtkWidget *
cve_listing_button(CveResult *res, const char *module_id, const char *label,
                  const char *verb, const char *extra_class)
{
    GtkWidget *button = gtk_button_new_with_label(label);
    CveListing *l = g_new0(CveListing, 1);

    l->res = res;
    l->module_id = g_strdup(module_id);
    l->verb = g_strdup(verb);
    g_signal_connect(button, "clicked", G_CALLBACK(cve_listing_clicked), l);
    g_object_set_data_full(G_OBJECT(button), "cve-listing", l, cve_listing_free);
    gtk_widget_add_css_class(button, "verb-button");
    if (extra_class != NULL)
        gtk_widget_add_css_class(button, extra_class);
    return button;
}

/* The composer is caption, entry, button, in that order, and the button is
   the only one of the three that can be told where its result goes. */
static GtkWidget *
cve_composer_button(GtkWidget *row)
{
    GtkWidget *last = row != NULL ? gtk_widget_get_last_child(row) : NULL;

    return (last != NULL && GTK_IS_BUTTON(last)) ? last : NULL;
}

/* One vector, in its own window. The CVE id is the heading because the id is
   what gets typed anywhere else - here, in a plan, on a command line - and the
   run the button starts is recorded against it. */
static void
cve_add_card(AppState *state, const char *module_id, const CveRow *r,
             GtkWidget *status, GtkWidget *body)
{
    GtkWidget *card_body;
    GtkWidget *card = verb_card(r->id, &card_body);
    GtkWidget *flow = fkit_flow();
    GtkWidget *run = gtk_button_new_with_label("Run This Vector");
    GtkWidget *plan = gtk_button_new_with_label("Add To Plan");
    CveResult *res = NULL;
    const char *kind = g_strcmp0(r->kind, "handoff") == 0
        ? "handoff - the far end has to be something this module does not drive"
        : "probe - measured against the target from here";

    cve_fill_meta(card_body, "kind", kind);
    cve_fill_meta(card_body, "needs", (r->needs != NULL && *r->needs != '\0')
                                      ? r->needs : "nothing beyond this machine");
    gtk_box_append(GTK_BOX(card_body), fkit_note(r->what));

    radio_bench_run_button(run, state, module_id, status, "--run-cve", r->id);
    fkit_flow_add(flow, run, "primary");
    radio_bench_run_button(plan, state, module_id, status, "--plan", r->id);
    fkit_flow_add(flow, plan, "flat");
    gtk_box_append(GTK_BOX(card_body), flow);

    /* The result lands here, in this vector's own window. */
    gtk_box_append(GTK_BOX(card_body), cve_result_strip(&res));
    {
        g_autofree char *rl = g_strdup_printf("Run vector %s", r->id);
        g_autofree char *pl = g_strdup_printf("Add %s to a plan", r->id);

        cve_result_wire(run, res, rl);
        cve_result_wire(plan, res, pl);
    }
    gtk_box_append(GTK_BOX(body), card);
}

/* One class: every vector the module files under it, in the order the module
   lists them, which is the order it wants them read in. */
static GtkWidget *
cve_build_class(AppState *state, const char *module_id, const char *klass,
                const char *title, const char *subtitle,
                GtkWidget *status, GtkTextBuffer *out)
{
    GtkWidget *body;
    GtkWidget *outer = radio_view_shell(title, subtitle, &body);
    GPtrArray *rows = cve_rows(module_id);
    g_autofree char *count = NULL;
    GtkWidget *label;
    guint shown = 0;

    for (guint i = 0; i < rows->len; i++) {
        CveRow *r = g_ptr_array_index(rows, i);

        if (g_strcmp0(r->klass, klass) != 0)
            continue;
        cve_add_card(state, module_id, r, status, body);
        shown++;
    }

    count = g_strdup_printf("%u VECTOR%s IN THIS CLASS", shown, shown == 1 ? "" : "S");
    label = gtk_label_new(count);
    gtk_widget_add_css_class(label, "cve-count");
    gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
    if (shown == 0)
        gtk_box_append(GTK_BOX(body),
            fkit_note("This module files no vector under this class. It is the "
                      "page's own reading of --list-cves, so an empty view means "
                      "the catalogue has nothing there - not that the reader "
                      "failed."));
    gtk_box_prepend(GTK_BOX(body), label);
    return outer;
}

/* A class view is the same builder with the class and its wording curried in;
   the page's entry table can only name a function, so each one gets a name. */
#define CVE_CLASS_VIEW(fn, klass, title, subtitle)                            \
    static GtkWidget *fn(AppState *state, const char *module_id,              \
                         GtkWidget *status, GtkTextBuffer *out)               \
    {                                                                         \
        return cve_build_class(state, module_id, klass, title, subtitle,      \
                               status, out);                                  \
    }

/* The catalogue itself: how much of it there is, the verbs that print it, the
   two that run one, and the module's own helpers. The helpers used to have a
   view of their own, which meant leaving the page to reach a verb that belongs
   to it just as much as the run buttons do. */
static GtkWidget *
cve_build_overview(AppState *state, const char *module_id,
                   const char *title, const char *subtitle,
                   const char *probe_verb, const char *sample_cve,
                   gboolean findings, const char *const *helpers,
                   GtkWidget *status, GtkTextBuffer *out)
{
    GtkWidget *body;
    GtkWidget *outer = radio_view_shell(title, subtitle, &body);
    GtkWidget *catalogue_body, *run_body, *helpers_body;
    GtkWidget *catalogue = verb_card("CATALOGUE", &catalogue_body);
    GtkWidget *one = verb_card("RUN ONE", &run_body);
    GtkWidget *helper_card = verb_card("HELPERS", &helpers_body);
    CveResult *cat_res = NULL, *one_res = NULL, *help_res = NULL;
    GtkWidget *cat_result, *one_result, *help_result;
    GtkWidget *banner;
    GPtrArray *rows = cve_rows(module_id);
    g_autofree char *script = module_script_path(module_id);
    g_autofree char *raw = NULL;
    g_autofree char *runs = NULL;
    g_autofree char *dir = NULL;
    g_autofree char *text = NULL;
    guint probe_n = 0, handoff_n = 0;

    for (guint i = 0; i < rows->len; i++) {
        CveRow *r = g_ptr_array_index(rows, i);

        if (g_strcmp0(r->kind, "handoff") == 0) handoff_n++;
        else probe_n++;
    }

    {
        const char *argv[] = { script, "--status-tsv", NULL };
        raw = run_capture(argv);
    }
    runs = raw ? tsv_field(raw, "runs") : NULL;
    dir = raw ? tsv_field(raw, "dir") : NULL;
    /* The loot directory is long and the only part that identifies it is the
       end, so it is shown relative to the project it lives in. */
    if (dir != NULL && g_str_has_prefix(dir, IMSISTING_ROOT "/"))
        memmove(dir, dir + strlen(IMSISTING_ROOT) + 1, strlen(dir + strlen(IMSISTING_ROOT) + 1) + 1);

    text = g_strdup_printf("%u VECTORS   |   %u PROBE / %u HANDOFF   |   %s RUNS RECORDED   |   %s",
        rows->len, probe_n, handoff_n,
        (runs != NULL && *runs != '\0') ? runs : "0",
        (dir != NULL && *dir != '\0') ? dir : "no loot directory");
    banner = gtk_label_new(text);
    gtk_widget_add_css_class(banner, "crec-survey-status");
    gtk_label_set_xalign(GTK_LABEL(banner), 0.0f);
    gtk_label_set_selectable(GTK_LABEL(banner), TRUE);
    gtk_box_append(GTK_BOX(body), banner);

    /* The three cards each own a result, and each strip is built before the
       buttons that fill it: it is created first and placed last. */
    cat_result  = cve_result_strip(&cat_res);
    one_result  = cve_result_strip(&one_res);
    help_result = cve_result_strip(&help_res);

    {
        /* Listings, and nothing else. Neither the selftest nor a named vector
           belongs here: the first is not an operator verb, and the second was
           a button because the module could be asked, not because an operator
           wanted to run CVE-2017-6975 in particular. */
        static const struct { const char *label; const char *verb; const char *cls; } whole[] = {
            { "List Every Vector", "--list-cves",     "primary" },
            { "Runs",              "--runs-tsv",      "flat" },
            { "Findings",          "--list-findings", "flat" },
        };
        GtkWidget *flow = fkit_flow();

        for (guint i = 0; i < G_N_ELEMENTS(whole); i++) {
            if (!findings && g_strcmp0(whole[i].verb, "--list-findings") == 0)
                continue;
            fkit_flow_add(flow, cve_listing_button(cat_res, module_id,
                            whole[i].label, whole[i].verb, whole[i].cls), NULL);
        }
        gtk_box_append(GTK_BOX(catalogue_body), flow);
    }
    gtk_box_append(GTK_BOX(catalogue_body), cat_result);
    gtk_box_append(GTK_BOX(catalogue_body),
        fkit_note("Every vector is a real run: it records to the runs table "
                  "against the id it used, and a vector whose needs cannot be "
                  "met fails honestly - non-zero, and it says what is missing."));

    {
        GtkWidget *row, *entry = NULL;

        row = fkit_composer_verb(state, module_id, status, &entry, "--run-cve",
                "CVE id", sample_cve, "Run Vector");
        gtk_box_append(GTK_BOX(run_body), row);
        cve_result_wire(cve_composer_button(row), one_res, "Run a vector");

        row = fkit_composer_verb(state, module_id, status, &entry, "--probe",
                "Probe", probe_verb, "Probe");
        gtk_box_append(GTK_BOX(run_body), row);
        cve_result_wire(cve_composer_button(row), one_res, "Run a probe");
    }
    gtk_box_append(GTK_BOX(run_body), one_result);
    gtk_box_append(GTK_BOX(run_body),
        fkit_note("The field takes one argument and the module splits it on "
                  "spaces, so a verb that wants two values takes them both here."));

    for (guint i = 0; helpers != NULL && helpers[i] != NULL; i++) {
        g_auto(GStrv) bits = g_strsplit(helpers[i], ":", 3);
        const char *verb = bits[0];
        const char *label = (bits[1] != NULL && *bits[1] != '\0') ? bits[1] : bits[0];
        /* The placeholder is what to type, never the verb that will be run:
           `--plmn` is a shell word, not something to read in a window. */
        const char *hint = (bits[2] != NULL && *bits[2] != '\0') ? bits[2] : label;
        GtkWidget *row, *entry = NULL;

        if (verb == NULL || *verb == '\0')
            continue;
        row = fkit_composer_verb(state, module_id, status, &entry, verb,
                label, hint, "Run");
        gtk_box_append(GTK_BOX(helpers_body), row);
        cve_result_wire(cve_composer_button(row), help_res, label);
    }
    gtk_box_append(GTK_BOX(helpers_body), help_result);

    gtk_box_append(GTK_BOX(body), catalogue);
    gtk_box_append(GTK_BOX(body), one);
    gtk_box_append(GTK_BOX(body), helper_card);
    return outer;
}

#define CVE_OVERVIEW_VIEW(fn, title, subtitle, probe_verb, sample, findings, helpers) \
    static GtkWidget *fn(AppState *state, const char *module_id,              \
                         GtkWidget *status, GtkTextBuffer *out)               \
    {                                                                         \
        return cve_build_overview(state, module_id, title, subtitle,          \
                                  probe_verb, sample, findings,              \
                                  helpers, status, out);                      \
    }

static const char *const gcve_helpers[] = {
    "--bcd:BCD:enc or dec, then a value",
    "--kc:Kc:two 32-digit hex keys, then v1, v2 or v3",
    "--plan:Plan:a CVE id",
    NULL
};
static const char *const lcve_helpers[] = {
    "--teid:TEID:a decimal TEID",
    "--plmn:PLMN:six hex digits, e.g. 02F801",
    "--plan:Plan:a CVE id",
    NULL
};
static const char *const ncve_helpers[] = {
    "--snssai:S-NSSAI:SST, or SST and SD, e.g. 010203",
    "--plan:Plan:a CVE id",
    NULL
};

CVE_OVERVIEW_VIEW(gcve_view_overview, "GSM CVE CATALOGUE",
    "Every catalogued GSM vulnerability, one card per vector, filed by the part "
    "of the network it lives in.",
    "IDENTITY", "CVE-2019-15962", TRUE, gcve_helpers)

CVE_CLASS_VIEW(gcve_view_baseband,  "baseband",     "GSM BASEBAND",
    "Vectors that reach the modem's own code rather than the network around it.")
CVE_CLASS_VIEW(gcve_view_femtocell, "femtocell",    "FEMTOCELL",
    "Vectors against the small cell that carries the operator's own traffic.")
CVE_CLASS_VIEW(gcve_view_gprs,      "gprs",         "GPRS",
    "Vectors in packet data, where a session exists before it is authenticated.")
CVE_CLASS_VIEW(gcve_view_cipher,    "gsm-cipher",   "GSM CIPHER",
    "Vectors against the A5 ciphering this module can already reason about.")
CVE_CLASS_VIEW(gcve_view_identity,  "identity",     "IDENTITY",
    "Vectors that make the network give up a subscriber's identity.")
CVE_CLASS_VIEW(gcve_view_sim_ota,   "sim-ota",      "SIM OTA",
    "Vectors delivered over the air to the card, not to the phone.")
CVE_CLASS_VIEW(gcve_view_sim_toolkit, "sim-toolkit", "SIM TOOLKIT",
    "Vectors in the card's own application toolkit.")
CVE_CLASS_VIEW(gcve_view_ss7_map,   "ss7-map",      "SS7 / MAP",
    "Vectors on the signalling network behind the radio.")

static ModuleSubmenuEntry gcve_entries[] = {
    { "Overview", "dialog-information-symbolic", NULL, gcve_view_overview },
    { "Baseband", "imsisting-35_baseband-symbolic", NULL, gcve_view_baseband },
    { "Femtocell", "imsisting-37_femtocell-symbolic", NULL, gcve_view_femtocell },
    { "GPRS", "imsisting-50_gprs-symbolic", NULL, gcve_view_gprs },
    { "GSM Cipher", "imsisting-19_cipher_audit-symbolic", NULL, gcve_view_cipher },
    { "Identity", "imsisting-18_imsi_exposure-symbolic", NULL, gcve_view_identity },
    { "SIM OTA", "imsisting-41_ota_sms-symbolic", NULL, gcve_view_sim_ota },
    { "SIM Toolkit", "imsisting-52_stk-symbolic", NULL, gcve_view_sim_toolkit },
    { "SS7 / MAP", "imsisting-26_ss7_map-symbolic", NULL, gcve_view_ss7_map },
};
CVE_OVERVIEW_VIEW(lcve_view_overview, "LTE CVE CATALOGUE",
    "Every catalogued LTE vulnerability, one card per vector, filed by the part "
    "of the network it lives in.",
    "RRC", "CVE-2017-6975", FALSE, lcve_helpers)

CVE_CLASS_VIEW(lcve_view_asn1, "asn1", "ASN.1",
    "Vectors in the decoders every other LTE interface is built on, so a fault "
    "here is reachable from more than one of them.")
CVE_CLASS_VIEW(lcve_view_baseband, "baseband", "LTE BASEBAND",
    "Vectors that reach the modem's own code rather than the network around it.")
CVE_CLASS_VIEW(lcve_view_diameter, "diameter", "DIAMETER",
    "Vectors on the signalling between the core and the subscriber database.")
CVE_CLASS_VIEW(lcve_view_epc, "epc", "EPC",
    "Vectors against the evolved packet core itself rather than the air around it.")
CVE_CLASS_VIEW(lcve_view_gtp, "gtp", "GTP",
    "Vectors in the tunnelling that carries user traffic once a session exists.")
CVE_CLASS_VIEW(lcve_view_lte_baseband, "lte-baseband", "LTE MODEM",
    "Vectors in the LTE stack a handset runs, reached from the network side.")
CVE_CLASS_VIEW(lcve_view_paging, "paging", "PAGING",
    "Vectors in the paging that reaches an idle handset.")
CVE_CLASS_VIEW(lcve_view_sib, "sib", "SIB",
    "Vectors in the system information a cell broadcasts to everyone.")
CVE_CLASS_VIEW(lcve_view_volte, "volte", "VOLTE",
    "Vectors in the IMS stack that carries voice over LTE.")

static ModuleSubmenuEntry lcve_entries[] = {
    { "Overview", "dialog-information-symbolic", NULL, lcve_view_overview },
    { "ASN.1", "imsisting-32_nas_signaling-symbolic", NULL, lcve_view_asn1 },
    { "LTE Baseband", "imsisting-35_baseband-symbolic", NULL, lcve_view_baseband },
    { "Diameter", "imsisting-11_lte_core-symbolic", NULL, lcve_view_diameter },
    { "EPC", "network-server-symbolic", NULL, lcve_view_epc },
    { "GTP", "imsisting-23_traffic_analysis-symbolic", NULL, lcve_view_gtp },
    { "LTE Modem", "imsisting-54_baseband_exploit-symbolic", NULL, lcve_view_lte_baseband },
    { "Paging", "imsisting-28_paging_track-symbolic", NULL, lcve_view_paging },
    { "SIB", "imsisting-10_lte_air-symbolic", NULL, lcve_view_sib },
    { "VoLTE", "imsisting-30_volte_ims-symbolic", NULL, lcve_view_volte },
};
CVE_OVERVIEW_VIEW(ncve_view_overview, "5G CVE CATALOGUE",
    "Every catalogued 5G vulnerability, one card per vector, filed by the part "
    "of the network it lives in.",
    "NRF", "CVE-2020-11197", TRUE, ncve_helpers)

CVE_CLASS_VIEW(ncve_view_asn1, "asn1", "ASN.1",
    "Vectors in the decoders every other 5G interface is built on, so a fault "
    "here is reachable from more than one of them.")
CVE_CLASS_VIEW(ncve_view_n2_n4, "n2-n4", "N2 / N4",
    "Vectors on the control and user plane between the radio and the core.")
CVE_CLASS_VIEW(ncve_view_nr_baseband, "nr-baseband", "NR BASEBAND",
    "Vectors that reach the modem's own code rather than the network around it.")
CVE_CLASS_VIEW(ncve_view_nr_rrc, "nr-rrc", "NR RRC",
    "Vectors in the radio resource control that runs before a session exists.")
CVE_CLASS_VIEW(ncve_view_nrf, "nrf", "NRF",
    "Vectors against the function registry every other core function trusts.")
CVE_CLASS_VIEW(ncve_view_sba_http2, "sba-http2", "SBA / HTTP2",
    "Vectors in the service-based interface itself rather than in a service.")
CVE_CLASS_VIEW(ncve_view_sepp, "sepp", "SEPP",
    "Vectors on the interconnect between one operator and the next.")
CVE_CLASS_VIEW(ncve_view_slicing, "slicing", "SLICING",
    "Vectors in the isolation that is supposed to keep one slice out of another.")
CVE_CLASS_VIEW(ncve_view_suci_privacy, "suci-privacy", "SUCI PRIVACY",
    "Vectors against the concealment of the subscriber's own identity.")
CVE_CLASS_VIEW(ncve_view_upf_pfcp, "upf-pfcp", "UPF / PFCP",
    "Vectors in the session management that programs the user plane function.")

static ModuleSubmenuEntry ncve_entries[] = {
    { "Overview", "dialog-information-symbolic", NULL, ncve_view_overview },
    { "ASN.1", "imsisting-32_nas_signaling-symbolic", NULL, ncve_view_asn1 },
    { "N2 / N4", "imsisting-13_nr_core-symbolic", NULL, ncve_view_n2_n4 },
    { "NR Baseband", "imsisting-55_nr_inject-symbolic", NULL, ncve_view_nr_baseband },
    { "NR RRC", "imsisting-12_nr_air-symbolic", NULL, ncve_view_nr_rrc },
    { "NRF", "imsisting-40_sba_pivot-symbolic", NULL, ncve_view_nrf },
    { "SBA / HTTP2", "network-workgroup-symbolic", NULL, ncve_view_sba_http2 },
    { "SEPP", "network-wired-symbolic", NULL, ncve_view_sepp },
    { "Slicing", "imsisting-34_slicing-symbolic", NULL, ncve_view_slicing },
    { "SUCI Privacy", "imsisting-14_suci-symbolic", NULL, ncve_view_suci_privacy },
    { "UPF / PFCP", "imsisting-23_traffic_analysis-symbolic", NULL, ncve_view_upf_pfcp },
};
static ModuleSubmenuEntry kchn_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "#INSPECT|--list-chains:List Chains|--show-chain=survey|#EXECUTE|--run=survey" },
    { "Execution",
      "media-playback-start-symbolic",
      "#RUN|--run-multi:Run Multiple|#OPTIONS|--dry-run:Dry Run|--keep-going:Keep Going|#STATUS|--run-status-tsv:Run Status" },
    { "Control",
      "preferences-system-symbolic",
      "--pause:Pause|--resume:Resume" },
    { "Authoring",
      "document-new-symbolic",
      "--add-chain:Add Chain|--runs-tsv:Runs TSV" },
};
static ModuleSubmenuEntry tana_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--flows={capture}|--classify={capture}|--features:Features" },
    { "Fingerprints",
      "system-search-symbolic",
      "#ADD|--fingerprint-add:Add Fingerprint|#REFS|--refs-tsv:References TSV|#MANAGE|--clear-refs:Clear References" },
    /* Calls is a separate view because it answers a separate question: which
       of these streams is one conversation, and who was in it. The table
       names the dialogue when the capture holds one and says so when it
       does not. */
    { "Calls",
      "call-start-symbolic",
      "--calls-tsv={capture}:Call Table" },
};
static ModuleSubmenuEntry rff_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--features:Features|--classify:Classify|~--csi-parse" },
    { "CSI",
      "network-wireless-symbolic",
      "--csi-motion:CSI Motion|--transient:Transient" },
    { "Signatures",
      "system-search-symbolic",
      "#ADD|--sig-add:Add Signature|#SIGS|--sigs-tsv:Signatures TSV|#MANAGE|--clear-sigs:Clear Signatures" },
};
static ModuleSubmenuEntry macl_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--decode-mac:Decode MAC|--rnti-track:Track RNTI|--sched-parse:Parse Scheduling" },
    { "Tables",
      "preferences-system-symbolic",
      "--lcid-table:LCID Table|--rnti-table:RNTI Table" },
    { "Analysis",
      "system-search-symbolic",
      "~--dci|--sched-pattern:Scheduling Pattern|--integrity-gap:Integrity Gap" },
};
static ModuleSubmenuEntry nasf_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--decode-nas:Decode NAS|--causes:Causes|--storm-profile:Storm Profile" },
    { "Model",
      "system-search-symbolic",
      "--cost-model:Cost Model|--procedure-mix:Procedure Mix|--rate={capture}" },
    /* The pre-authentication message builders. Each button runs a worked
       vector so the card shows a real message rather than a usage line; the
       module's own output carries the `limit` row that says what was not
       built (the NAS-MAC, the AUTN) and that nothing was sent. */
    { "Messages",
      "document-send-symbolic",
      "--build-nas=eps attach-reject --cause 15:Attach Reject"
      "|--build-nas=eps tau-reject --cause 12:TAU Reject"
      "|--build-nas=eps identity-request --identity imsi:Identity Request"
      "|--build-nas=eps auth-reject:Authentication Reject"
      "|--build-nas=eps security-mode-reject --cause 23:Security Mode Reject"
      "|--build-nas=5gs registration-reject --cause 22:Registration Reject" },
    { "Transmit",
      "media-playback-start-symbolic",
      "--transmit=00101 5:Write the Lab Plan" },
    { "Planning",
      "preferences-system-symbolic",
      "--plan:Plan" },
};
static ModuleSubmenuEntry ss7_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--surface:Surface|--grx-recon:GRX Recon|--detect:Detect" },
    { "Build",
      "document-new-symbolic",
      "--build-ati:Build ATI|--build-sri:Build SRI|--build-sri-sm:Build SRI-SM|--build-sai:Build SAI (auth vectors)|--build-psi:Build PSI|--build-ulr:Build ULR|--build-isd:Build ISD|--build-register-ss:Build RegisterSS|--build-activate-ss:Build ActivateSS|--build-m3ua:Wrap MSU in M3UA|--m3ua-send:Send to STP" },
    { "Decode",
      "document-open-symbolic",
      "--decode-map:Decode MAP|--decode-msu:Decode MSU|--decode-tcap:Decode TCAP|--decode-sigtran:Decode SIGTRAN" },
    { "Detection",
      "dialog-warning-symbolic",
      "--fallback-detect:Fallback Detect|--flow:Flow" },
    { "Options",
      "preferences-system-symbolic",
      "#PARAMS|--opcode=1|--ssn=6|#FORMAT|--pc-format:PC Format|#CHECKS|--require-stp:Require STP|--visited-plmn:Visited PLMN|#PLAN|--plan:Plan" },
};
static ModuleSubmenuEntry cdns_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--decode-dns:Decode DNS|--detect:Detect|--resolver-discovery:Resolver Discovery" },
    { "Build",
      "document-new-symbolic",
      "--build-query:Build Query|--build-response:Build Response|--alter" },
    { "Options",
      "preferences-system-symbolic",
      "--pco=8021|--plan:Plan" },
};
static ModuleSubmenuEntry pgt_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--detect:Detect|--paging-parse:Parse Paging|--piercer-correlate:Piercer Correlate" },
    { "Model",
      "system-search-symbolic",
      "--torpedo-model:Torpedo Model|--po=001010000000001 2 gsm|--plan:Plan" },
    { "Occasion",
      "preferences-system-symbolic",
      "~--edrx-occ|~--pei-occ|~--page-mode|~--paging-cause" },
    { "Attack",
      "security-high-symbolic",
      "#BUILD|~--build-paging-req|#TX|~--paging-tx|~--paging-storm|#HISTORY|~--paging-history|~--flapping-tsv" },
};
static ModuleSubmenuEntry vims_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--ims-registration:IMS Registration|--sip-parse:Parse SIP|~--sip-build|--detect-keystream-reuse:Keystream Reuse|~--calls|~--tag" },
    { "Attacks",
      "security-high-symbolic",
      "#FLOOD|--sip-flood:SIP Flood|#SPOOF|--register-spoof:Register Spoof|~--register-aka|~--call|~--sip-send|#EXPOSURE|--imei-leak:IMEI Leak|#DEMO|--revolte-demo:ReVoLTE Demo|~--i-have-a-lab-and-authorisation" },
    { "Keystream",
      "channel-secure-symbolic",
      "--keystream-recover:Recover Keystream|--imp4gt-model:IMP4GT Model" },
    { "Planning",
      "preferences-system-symbolic",
      "--plan:Plan" },
};
static ModuleSubmenuEntry simd_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--score:Score|--defence-checklist:Defence Checklist|--signals:Signals" },
    { "Inspection",
      "auth-smartcard-symbolic",
      "--ef-ad:EF AD|--esim-profile-parse:Parse eSIM Profile|--pin-state:PIN State" },
    /* The attack half. The group is named by what it produces, and no control
       here is named after a verb. */
    { "Attack Simulation",
      "security-high-symbolic",
      "--adm-apdu=6F07 082982608200002080 --key 1122334455667788:Card Write APDUs"
      "|--swap-artefacts:Port-out Artefacts|--swap-plan:Port-out Timeline" },
};
static void
mod_arg_clicked(GtkButton *button, gpointer user_data)
{
    AppState *state = g_object_get_data(G_OBJECT(button), "state");
    const char *module_id = g_object_get_data(G_OBJECT(button), "module-id");
    GtkWidget *status = g_object_get_data(G_OBJECT(button), "status");
    const char *verb = g_object_get_data(G_OBJECT(button), "verb");
    const char *label = g_object_get_data(G_OBJECT(button), "action-label");
    GtkWidget *entry = g_object_get_data(G_OBJECT(button), "arg-entry");
    g_autofree char *typed = g_strdup(
        entry != NULL ? gtk_editable_get_text(GTK_EDITABLE(entry)) : "");
    g_auto(GStrv) parts = g_strsplit(typed, " ", -1);
    g_autofree char *script = module_script_path(module_id);
    g_autoptr(GPtrArray) argv = g_ptr_array_new();

    (void) user_data;
    g_ptr_array_add(argv, script);
    g_ptr_array_add(argv, (gpointer) verb);
    for (int i = 0; parts[i] != NULL; i++)
        if (parts[i][0] != '\0') g_ptr_array_add(argv, parts[i]);
    g_ptr_array_add(argv, NULL);
    /* A hand-built card owns its own answer surface just as a spec card does:
       the button carries the card's result rect, this begins it, and
       action_run_unref ends it because result_rect_new has registered the
       buffer -> rect link. Without this the records went to the page buffer,
       which no longer has a card to draw them in. */
    {
        GtkWidget *holder = g_object_get_data(G_OBJECT(button), "result");

        if (holder != NULL) {
            ResultRect *rr = g_object_get_data(G_OBJECT(holder), "result-rect");

            if (rr != NULL) result_begin(state, rr);
        }
    }

    imsisting_action_run(state, module_id, label, status,
                         (const char *const *) argv->pdata, FALSE);
}

static void
mod_entry_activate(GtkEntry *entry, gpointer user_data)
{
    (void) entry;
    gtk_widget_activate(GTK_WIDGET(user_data));
}
/* One job: type the arguments, press the button, never see the verb.
   Shared by every page that answers with a module run rather than a fixed
   listing -- the small-cell page and the jamming page both grew one, and a
   second copy is where the two would drift apart. */
/* Which card is being filled right now. A page builder sets this before it
   appends its rows and clears it after, so every control in that card knows
   which result rect to report into without every call growing an argument. */
static GtkWidget *mod_card_result;

static void
mod_card_begin(GtkWidget *result) { mod_card_result = result; }
static void
mod_card_end(void) { mod_card_result = NULL; }

static GtkWidget *
mod_arg_row(AppState *state, const char *module_id, GtkWidget *status,
              const char *button_label, const char *verb,
              const char *placeholder, const char *hint)
{
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *entry = gtk_entry_new();
    GtkWidget *button = gtk_button_new_with_label(button_label);
    GtkWidget *column;

    gtk_entry_set_placeholder_text(GTK_ENTRY(entry), placeholder);
    gtk_widget_set_hexpand(entry, TRUE);
    gtk_widget_add_css_class(button, "verb-button");
    gtk_widget_add_css_class(button, "primary");

    g_object_set_data(G_OBJECT(button), "state", state);
    g_object_set_data(G_OBJECT(button), "module-id", (gpointer) module_id);
    g_object_set_data(G_OBJECT(button), "status", status);
    g_object_set_data(G_OBJECT(button), "verb", (gpointer) verb);
    g_object_set_data(G_OBJECT(button), "action-label", (gpointer) button_label);
    g_object_set_data(G_OBJECT(button), "arg-entry", entry);
    if (mod_card_result != NULL)
        g_object_set_data(G_OBJECT(button), "result", mod_card_result);
    g_signal_connect(button, "clicked", G_CALLBACK(mod_arg_clicked), NULL);
    g_signal_connect(entry, "activate", G_CALLBACK(mod_entry_activate), button);

    gtk_box_append(GTK_BOX(row), entry);
    gtk_box_append(GTK_BOX(row), button);
    if (hint == NULL) return row;

    column = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_box_append(GTK_BOX(column), row);
    gtk_box_append(GTK_BOX(column), fkit_note(hint));
    return column;
}

/* One row, several destinations.
 *
 * "Export KML | Export CSV | Export GeoJSON" as three identical pills is what
 * this replaces: three buttons that differ only in their last word, stacked
 * across the card, saying nothing about the fact that they are one act with a
 * choice of format. Here the choice is visible as a choice - one path to type
 * and one small button per format, in a single row - because the operator is
 * making one decision, not three.
 */
static GtkWidget *
mod_arg_choices(AppState *state, const char *module_id, GtkWidget *status,
                const char *caption, const char *placeholder, const char *hint,
                const char *const *verbs, const char *const *labels, int n)
{
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *entry = gtk_entry_new();
    GtkWidget *column;

    gtk_entry_set_placeholder_text(GTK_ENTRY(entry), placeholder);
    gtk_widget_set_hexpand(entry, TRUE);
    if (caption != NULL) {
        GtkWidget *cap = gtk_label_new(caption);
        gtk_widget_add_css_class(cap, "form-caption");
        gtk_widget_set_size_request(cap, 150, -1);
        gtk_label_set_xalign(GTK_LABEL(cap), 0.0f);
        gtk_box_append(GTK_BOX(row), cap);
    }
    gtk_box_append(GTK_BOX(row), entry);

    for (int i = 0; i < n; i++) {
        GtkWidget *button = gtk_button_new_with_label(labels[i]);

        gtk_widget_add_css_class(button, "verb-button");
        gtk_widget_add_css_class(button, "compact");
        if (i == 0) gtk_widget_add_css_class(button, "primary");
        g_object_set_data(G_OBJECT(button), "state", state);
        g_object_set_data(G_OBJECT(button), "module-id", (gpointer) module_id);
        g_object_set_data(G_OBJECT(button), "status", status);
        g_object_set_data(G_OBJECT(button), "verb", (gpointer) verbs[i]);
        g_object_set_data(G_OBJECT(button), "action-label", (gpointer) labels[i]);
        g_object_set_data(G_OBJECT(button), "arg-entry", entry);
        if (mod_card_result != NULL)
            g_object_set_data(G_OBJECT(button), "result", mod_card_result);
        g_signal_connect(button, "clicked", G_CALLBACK(mod_arg_clicked), NULL);
        gtk_box_append(GTK_BOX(row), button);
    }

    if (hint == NULL) return row;
    column = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_box_append(GTK_BOX(column), row);
    gtk_box_append(GTK_BOX(column), fkit_note(hint));
    return column;
}

/* --------------------------------------------------------------------------
   The jamming page, laid out the way the LTE CVE Kit page is: a named view
   with a subtitle, cards that each hold one job, and a result that lands in the
   card that asked for it. Three rules shape it.

   No control is named after a verb. A button says what it does -- "Construct
   the Waveform", "Read the Capture", "Whose Trouble Is It" -- and the verb
   stays in the C next to the argv, where check-gui-text.sh can see that it is
   not on screen. The one place a verb may appear is where the operator types
   the module's own command line, and even there it is pre-filled and left to
   the module to explain.

   Views are the categories of work, not one per verb: what the receiver sees,
   what it concludes, how it is written up, and -- last, and by itself -- the
   half that reaches for a radio. That last one gets its own view because the
   two halves are not the same kind of act and a page that filed them together
   would be lying about that.

   The transmit view prints the module's own warning at the top, read from the
   module rather than retyped here. A page with a copy of the caveat is a page
   whose copy can go stale; a page that asks the module is a page that cannot.
   -------------------------------------------------------------------------- */

/* What the overview banner says: the two halves, and whether the gate is
   shut. Read from the module so the page and the command line cannot drift. */
static char *
jamd_status_summary(const char *module_id)
{
    g_autofree char *script = module_script_path(module_id);
    const char *argv[] = { script, "--status-tsv", NULL };
    g_autofree char *raw = run_capture(argv);
    g_autofree char *tx = raw ? tsv_field(raw, "transmit_path") : NULL;
    g_autofree char *gate = raw ? tsv_field(raw, "tx_gate") : NULL;
    g_autofree char *branches = raw ? tsv_field(raw, "branches") : NULL;
    g_autofree char *dir = raw ? tsv_field(raw, "dir") : NULL;

    /* The loot path is long and the only part that identifies it is the end. */
    if (dir != NULL && g_str_has_prefix(dir, IMSISTING_ROOT "/"))
        memmove(dir, dir + strlen(IMSISTING_ROOT) + 1,
                strlen(dir + strlen(IMSISTING_ROOT) + 1) + 1);

    return g_strdup_printf(
        "DETECTION  %s   |   TRANSMIT  %s, GATE %s   |   %s   |   %s",
        (branches && *branches) ? branches : "no branches reported",
        (tx && *tx) ? tx : "unknown",
        (gate && *gate) ? gate : "unknown",
        (dir && *dir) ? dir : "no loot directory",
        "nothing is keyed unless the gate is armed");
}

/* The module's own warning, as the module prints it. jamd_tx_disclaimer writes
   to stderr on every transmit verb, so the same text the command line shows is
   the text this page shows -- one source, not two.

   The module hard-wraps at the terminal's width because that is where it is
   usually read. Re-broken here into one paragraph per blank-free run, so the
   box wraps to the card instead of inheriting a column width from a terminal
   this page is not. A wrapped line ending in nothing in particular joins the
   line after it; a line that had been left short on purpose ("that applies
   where you are: ...") still ends its paragraph, which is why the module's own
   structure survives the join. */
static void
jamd_append_disclaimer(GtkWidget *card_body, const char *module_id)
{
    g_autofree char *script = module_script_path(module_id);
    const char *argv[] = { script, "--tx-status", NULL };
    g_autofree char *raw = run_capture_stderr(argv);
    g_auto(GStrv) lines = NULL;
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GString *para = g_string_new(NULL);
    gboolean shown = FALSE;

    gtk_widget_add_css_class(box, "jamd-warning");
    lines = g_strsplit(raw != NULL ? raw : "", "\n", -1);
    for (int i = 0; lines[i] != NULL; i++) {
        const char *tab;

        if (!g_str_has_prefix(lines[i], "WARNING")) continue;
        tab = strchr(lines[i], '\t');
        if (tab == NULL || tab[1] == '\0') continue;
        if (para->len > 0) g_string_append_c(para, ' ');
        g_string_append(para, tab + 1);
    }
    if (para->len > 0) {
        gtk_box_append(GTK_BOX(box), fkit_note(para->str));
        shown = TRUE;
    }
    g_string_free(para, TRUE);
    if (!shown)
        gtk_box_append(GTK_BOX(box),
            fkit_note("The module did not print its warning. Until it does, "
                      "there is no reason to believe anything else it says."));
    gtk_box_append(GTK_BOX(card_body), box);
}

/* 1. Overview: the two halves, the state of the gate, and the honest frame
      for reading every number on the rest of the page. */
static GtkWidget *
jamd_build_overview(AppState *state, const char *module_id,
                    GtkWidget *status, GtkTextBuffer *out)
{
    GtkWidget *body;
    GtkWidget *outer = radio_view_shell("JAMMING DETECT",
        "Tell deliberate interference apart from congestion and from a hole in "
        "the coverage -- and, behind a gate, build what a shielded room needs "
        "to prove either half works.", &body);
    GtkWidget *halves_body, *first_body;
    GtkWidget *halves = verb_card("THE TWO HALVES", &halves_body);
    GtkWidget *first = verb_card("READ THIS BEFORE TRUSTING A NUMBER", &first_body);
    GtkWidget *flow = fkit_flow();
    g_autofree char *summary = jamd_status_summary(module_id);
    GtkWidget *banner = gtk_label_new(summary);
    GtkWidget *selftest = gtk_button_new_with_label("Verify the Maths");

    gtk_widget_add_css_class(banner, "crec-survey-status");
    gtk_label_set_xalign(GTK_LABEL(banner), 0.0f);
    gtk_label_set_selectable(GTK_LABEL(banner), TRUE);
    gtk_box_append(GTK_BOX(body), banner);

    gtk_box_append(GTK_BOX(halves_body), fkit_note(
        "Detection and measurement are the authority. Every verdict on this "
        "page comes from a capture: a Welch periodogram split in two halves, a "
        "noise floor read from the tenth percentile of each, affected band and "
        "peak excess, then a time-domain envelope over 512-sample windows for "
        "activity and transitions. The shape of that measurement is what "
        "separates a jammer from a busy cell."));
    gtk_box_append(GTK_BOX(halves_body), fkit_note(
        "The transmit half is gated, and it is gated by an explicit flag rather "
        "than by a prompt, because a prompt is something a script answers. It "
        "constructs a waveform on this machine with no radio attached, which is "
        "what makes it testable; only the last step reaches for a device."));
    radio_bench_run_button(selftest, state, module_id, status, "--selftest", NULL);
    fkit_flow_add(flow, selftest, "primary");
    gtk_box_append(GTK_BOX(halves_body), flow);
    gtk_box_append(GTK_BOX(halves_body), fkit_note(
        "The selftest is the honest one: it synthesises captures whose answer "
        "is known by construction, runs the real analyser over them, and "
        "asserts that the gate refuses an unarmed build and that no detection "
        "verb ever reaches a driver."));
    gtk_box_append(GTK_BOX(body), halves);

    gtk_box_append(GTK_BOX(first_body), fkit_note(
        "A capture is a claim about a place and a moment. Two captures taken "
        "an hour apart are two different experiments, and the floor shift "
        "between them is only meaningful if the receiver, the gain and the "
        "antenna did not move in between."));
    gtk_box_append(GTK_BOX(first_body), fkit_note(
        "An audible change in decode-failure rate is not evidence of jamming on "
        "its own: a congested cell fails to decode too, and so does one whose "
        "neighbour is stronger than its own serving cell. That is what the "
        "discrimination view is for, and it is why this module refuses to sign "
        "a jamming report for a profile that could be something else."));
    gtk_box_append(GTK_BOX(body), first);

    (void) out;
    return outer;
}

/* 2. The capture: look at it, before drawing anything from it. Two ways in --
      measure the band, or measure the noise floor over time. */
static GtkWidget *
jamd_build_capture(AppState *state, const char *module_id,
                   GtkWidget *status, GtkTextBuffer *out)
{
    GtkWidget *body;
    GtkWidget *outer = radio_view_shell("THE CAPTURE",
        "What the receiver heard: spectral occupancy, the noise floor, and "
        "whether anything moved.", &body);
    GtkWidget *measure_body, *floor_body;
    GtkWidget *measure = verb_card("MEASURE THE BAND", &measure_body);
    GtkWidget *floor_card = verb_card("WATCH THE FLOOR OVER TIME", &floor_body);

    gtk_box_append(GTK_BOX(measure_body),
        mod_arg_row(state, module_id, status, "Analyse the Capture",
            "--analyse",
            "capture.iq cf32 20000000",
            "Path, then the sample format cf32 / ci16 / cu8, then the sample "
            "rate in samples per second. The result is saved as this module's "
            "measurement record, which the next views read."));
    gtk_box_append(GTK_BOX(measure_body), fkit_note(
        "What it measures: the floor of each half of the capture and the shift "
        "between them, the fraction of the band more than 6 dB above the "
        "median, the peak excess over that median, and the fraction of 512-"
        "sample windows that are active together with how many times activity "
        "started or stopped."));
    gtk_box_append(GTK_BOX(body), measure);

    gtk_box_append(GTK_BOX(floor_body),
        mod_arg_row(state, module_id, status, "Read the Floor",
            "--noise-floor",
            "capture.iq cf32 20000000",
            "The same three arguments. Useful before and after a suspected "
            "event: a floor that rose by 6 dB and stayed there is barrage; one "
            "that moved only under a narrow slice is not."));
    gtk_box_append(GTK_BOX(floor_body), fkit_note(
        "A floor is only comparable to another floor taken with the same gain "
        "and the same antenna. Change either and the shift you are reading is "
        "your own change, not the air's."));
    gtk_box_append(GTK_BOX(body), floor_card);

    /* No capture of your own yet? The module can write one whose verdict is
       fixed by construction -- a clean band, a floor that lifts halfway
       through, or a 25 kHz carrier off centre -- and then has to reach that
       verdict through the same analyser it would run on a real capture. It is
       a sample-arithmetic file, not a recording, so nothing here is evidence
       about any band: it is how you find out whether the analyser is reading
       what it claims to read before you point it at something that matters. */
    GtkWidget *fx_body;
    GtkWidget *fx = verb_card("OR WRITE A CAPTURE WHOSE ANSWER IS KNOWN", &fx_body);
    gtk_box_append(GTK_BOX(fx_body),
        mod_arg_row(state, module_id, status, "Clean Band",
            "--fixture", "clean /tmp/imsisting/jamming_detect/capture.iq cf32 20000000 0.5",
            "A capture of nothing but noise. The analyser must call it clean; "
            "if it does not, every verdict it gives on a real file is suspect."));
    gtk_box_append(GTK_BOX(fx_body),
        mod_arg_row(state, module_id, status, "Floor Lifts Halfway",
            "--fixture", "raised /tmp/imsisting/jamming_detect/capture.iq cf32 20000000 0.5",
            "Noise whose floor rises by 9 dB at the halfway point: the shape a "
            "barrage jammer leaves. Run the Capture view on the file it writes."));
    gtk_box_append(GTK_BOX(fx_body),
        mod_arg_row(state, module_id, status, "Narrow Carrier Off Centre",
            "--fixture", "narrow /tmp/imsisting/jamming_detect/capture.iq cf32 20000000 0.5",
            "A 25 kHz carrier 200 kHz off centre over half the file: the shape a "
            "narrowband jammer leaves, and the one congestion does not."));
    gtk_box_append(GTK_BOX(fx_body), fkit_note(
        "The kind, then the output path, then format, sample rate and seconds. "
        "Writing samples keys no radio and needs no lab gate."));
    gtk_box_append(GTK_BOX(body), fx);

    (void) out;
    return outer;
}

/* 3. The profile: name what was heard. Narrowband or barrage, how wide, and
      whether it was on the whole time. */
static GtkWidget *
jamd_build_profile(AppState *state, const char *module_id,
                   GtkWidget *status, GtkTextBuffer *out)
{
    GtkWidget *body;
    GtkWidget *outer = radio_view_shell("THE PROFILE",
        "Narrowband or barrage, how much of the band it takes, and whether it "
        "was present the whole time or only part of it.", &body);
    GtkWidget *name_body, *call_body;
    GtkWidget *name = verb_card("NAME THE SHAPE", &name_body);
    GtkWidget *call = verb_card("PUT IT IN WORDS", &call_body);

    gtk_box_append(GTK_BOX(name_body),
        mod_arg_row(state, module_id, status, "Classify the Profile",
            "--characterise",
            "capture.iq cf32 20000000",
            "Path, format, sample rate, and optionally the centre frequency in "
            "MHz -- the last one turns the offset into a real frequency and "
            "names the EARFCN the interferer sits on."));
    gtk_box_append(GTK_BOX(name_body), fkit_note(
        "The three labels are earned, not asserted: clean needs both a floor "
        "shift under 6 dB and a peak excess under 12 dB; narrowband needs a "
        "peak excess of 12 dB or more occupying under a quarter of the band; "
        "barrage needs a floor shift of 6 dB or more. A capture that satisfies "
        "none of them is called indeterminate, and that is a real answer."));
    gtk_box_append(GTK_BOX(body), name);

    gtk_box_append(GTK_BOX(call_body),
        mod_arg_row(state, module_id, status, "Write the Description",
            "--characterise",
            "capture.iq cf32 20000000 2650",
            "The same arguments plus a centre frequency, which is what lets the "
            "description name a frequency instead of an offset."));
    gtk_box_append(GTK_BOX(call_body), fkit_note(
        "The duty pattern is read from activity transitions, so a signal "
        "observed for only part of the capture is reported as a step rather "
        "than being called pulsed -- the capture was too short to see the "
        "period, and the module says so instead of guessing one."));
    gtk_box_append(GTK_BOX(body), call);

    (void) out;
    return outer;
}

/* 4. Whose trouble is it: the whole point of the module. Congestion and a
      coverage hole both look like interference from the receiver's side. */
static GtkWidget *
jamd_build_discriminate(AppState *state, const char *module_id,
                        GtkWidget *status, GtkTextBuffer *out)
{
    GtkWidget *body;
    GtkWidget *outer = radio_view_shell("WHOSE TROUBLE IS IT",
        "Interference, load, or no coverage: three explanations for one set of "
        "bad numbers, separated by what the receiver was doing at the time.",
        &body);
    GtkWidget *verdict_body, *evidence_body;
    GtkWidget *verdict = verb_card("THE VERDICT", &verdict_body);
    GtkWidget *evidence = verb_card("WHERE THE EVIDENCE COMES FROM", &evidence_body);

    gtk_box_append(GTK_BOX(verdict_body),
        mod_arg_row(state, module_id, status, "Say Which One",
            "--discriminate",
            "leave empty for this module's saved record, or name another",
            "Reads the measurement record. Empty uses the one --analyse saved."));
    gtk_box_append(GTK_BOX(verdict_body), fkit_note(
        "The three branches are not a vote. Interference needs an unexplained "
        "floor or peak; congestion needs the load indicators to have moved "
        "with the failures; a coverage hole needs the reference signal to have "
        "collapsed without a handover to explain it. A record that supports "
        "none of them is reported as indeterminate rather than forced into the "
        "nearest one."));
    gtk_box_append(GTK_BOX(body), verdict);

    gtk_box_append(GTK_BOX(evidence_body), fkit_note(
        "The receiver counters are the half a spectrum capture cannot supply. "
        "A spectrum analyser sees that something is loud; it cannot see whether "
        "the scheduler was busy, whether the handover succeeded, or whether the "
        "uplink was failing. Those arrive as a file of key and value and are "
        "merged into the measurement record without overwriting what the "
        "capture already said."));
    gtk_box_append(GTK_BOX(evidence_body),
        mod_arg_row(state, module_id, status, "Add Receiver Counters",
            "--counters",
            "/path/to/counters.tsv",
            "A file of key and value, one per line: load indicator, PDCCH and "
            "PBCH decode-failure rates, RSRP and RSRQ deltas, handover success, "
            "uplink block error rate, RACH failure rate, and timestamps."));
    gtk_box_append(GTK_BOX(body), evidence);

    (void) out;
    return outer;
}

/* 5. The write-up: the artefact a security team or a regulator actually reads. */
static GtkWidget *
jamd_build_report(AppState *state, const char *module_id,
                  GtkWidget *status, GtkTextBuffer *out)
{
    GtkWidget *body;
    GtkWidget *outer = radio_view_shell("THE WRITE-UP",
        "A regulator-readable report, produced only when the profile actually "
        "supports one.", &body);
    GtkWidget *write_body;
    GtkWidget *write = verb_card("PRODUCE THE REPORT", &write_body);

    gtk_box_append(GTK_BOX(write_body),
        mod_arg_row(state, module_id, status, "Write the Report",
            "--report",
            "leave empty for this module's saved record, or name another",
            "The measurement log, the affected band and the verdict, as text."));
    gtk_box_append(GTK_BOX(write_body), fkit_note(
        "This refuses a clean profile and a coverage-hole profile. A module "
        "that will sign a jamming report for whatever it is handed is a module "
        "whose reports are worth nothing, and the refusal is asserted by the "
        "selftest rather than left to discipline."));
    gtk_box_append(GTK_BOX(write_body), fkit_note(
        "What the report is not: evidence of who did it. It records what was "
        "measured, where and when, and what the profile supports. Attribution "
        "is a different question that no spectrum capture answers."));
    gtk_box_append(GTK_BOX(body), write);

    (void) out;
    return outer;
}

/* 6. The constructor: build the samples, touch no radio. This is the view an
      operator reaches for when they need a test vector, and it is deliberately
      separate from the keying view below it. */
static GtkWidget *
jamd_build_waveform(AppState *state, const char *module_id,
                    GtkWidget *status, GtkTextBuffer *out)
{
    GtkWidget *body;
    GtkWidget *outer = radio_view_shell("BUILD A WAVEFORM",
        "Sample arithmetic on this machine. No radio is opened, no antenna is "
        "wired, and the file is the whole output.", &body);
    GtkWidget *make_body, *raster_body;
    GtkWidget *make = verb_card("CONSTRUCT THE SAMPLES", &make_body);
    GtkWidget *raster = verb_card("WHERE ON THE RASTER IT LANDS", &raster_body);

    jamd_append_disclaimer(make_body, module_id);
    gtk_box_append(GTK_BOX(make_body),
        mod_arg_row(state, module_id, status, "Construct the Waveform",
            "--tx-build",
            "--centre 2650MHz",
            "At minimum a centre frequency, as Hz or MHz or an EARFCN. The "
            "shape, mode, format, rate, duration and pulse timing have "
            "defaults that the module prints back when the build finishes."));
    gtk_box_append(GTK_BOX(make_body), fkit_note(
        "Two modes. Barrage fills the whole sample rate; narrowband fills one "
        "slice and is refused if that slice is narrower than the analyser can "
        "resolve, because a waveform the receiver cannot distinguish from noise "
        "is not a test of anything. Three shapes are built: wideband noise, a "
        "single tone, and a linear sweep."));
    gtk_box_append(GTK_BOX(make_body), fkit_note(
        "A pulse train is structural, not statistical: the gate is a block "
        "pattern multiplied into the samples, so the duty cycle is exactly what "
        "was asked for and the file says how many samples were gated. The "
        "waveform is normalised to the peak fraction asked for and then "
        "measured again, and the build fails if the measurement disagrees."));
    gtk_box_append(GTK_BOX(body), make);

    gtk_box_append(GTK_BOX(raster_body), fkit_note(
        "A centre frequency given in hertz moves to the sample file as given. "
        "A frequency on the LTE carrier raster is labelled with its EARFCN, "
        "because that is the number a receiver test is usually written in. The "
        "raster is a query here rather than a constraint: a receiver test is "
        "not always on a cellular carrier, so a frequency off the raster is "
        "labelled as off the raster and built anyway."));
    gtk_box_append(GTK_BOX(raster_body), fkit_note(
        "The band edges are read from one table, the same one the analyser "
        "reads, so a frequency cannot be legal in one view and not the other."));
    gtk_box_append(GTK_BOX(body), raster);

    (void) out;
    return outer;
}

/* 6b. The signal shapes: every reference signal the tree can now produce,
       reached through the module that consults the producer rather than
       reimplementing it. The list is a verb of its own because the interesting
       fact is which producer answers for which signal, and which are refused. */
static GtkWidget *
jamd_build_shapes(AppState *state, const char *module_id,
                  GtkWidget *status, GtkTextBuffer *out)
{
    GtkWidget *body;
    GtkWidget *outer = radio_view_shell("SIGNAL SHAPES",
        "One reference signal per shape, built by the tool that owns the "
        "sequence. The module consults a producer; it does not carry a second "
        "copy of the maths that could disagree with it.", &body);
    GtkWidget *list_body, *pss_body, *ssb_body;
    GtkWidget *list = verb_card("WHAT CAN BE BUILT, AND BY WHAT", &list_body);
    GtkWidget *pss = verb_card("AN LTE SYNC SIGNAL, AS SAMPLES", &pss_body);
    GtkWidget *ssb = verb_card("AN NR SSB BURST, AS SAMPLES", &ssb_body);

    gtk_box_append(GTK_BOX(list_body),
        mod_arg_row(state, module_id, status, "List the Shapes",
            "--shapes", "",
            "Every shape with the producer that answers for it, plus the shapes "
            "that are refused and why. Keys nothing and needs no gate."));
    gtk_box_append(GTK_BOX(list_body), fkit_note(
        "LTE sync signals are narrowband shapes: a reference signal occupies its "
        "own slice, so asking for it in barrage mode is refused rather than "
        "filling the band with a copy of it."));
    gtk_box_append(GTK_BOX(body), list);

    jamd_append_disclaimer(pss_body, module_id);
    gtk_box_append(GTK_BOX(pss_body),
        mod_arg_row(state, module_id, status, "PSS For a Given Cell",
            "--tx-build",
            "--mode narrowband --shape pss --centre 2650MHz --pci 42",
            "Physical cell identity 1..503: the PSS carries cell identity modulo "
            "three, and the SSS that goes with it carries the rest. The samples "
            "come from tools/lte_phy.py, the same functions the demodulator "
            "here uses."));
    gtk_box_append(GTK_BOX(body), pss);

    jamd_append_disclaimer(ssb_body, module_id);
    gtk_box_append(GTK_BOX(ssb_body),
        mod_arg_row(state, module_id, status, "One SSB Burst",
            "--tx-build",
            "--mode narrowband --shape nr-ssb --centre 2650MHz --ssb-waveform "
            "/tmp/imsisting/jamming_detect/ssb.cf32 --pci 42 --i-ssb 3",
            "An NR SSB is four OFDM symbols carrying PSS, SSS, PBCH and its "
            "DMRS. The burst is produced by 12_nr_air, which is the module that "
            "owns the NR waveform in this tree."));
    gtk_box_append(GTK_BOX(body), ssb);

    (void) out;
    return outer;
}

/* 7. The gate: what the module will and will not do, and what it needs before
      it does the second thing. The warning is the module's, not this page's. */
static GtkWidget *
jamd_build_gate(AppState *state, const char *module_id,
                GtkWidget *status, GtkTextBuffer *out)
{
    GtkWidget *body;
    GtkWidget *outer = radio_view_shell("THE GATE",
        "What this module refuses, what it accepts, and what has to be true "
        "about the room before the radio is opened.", &body);
    GtkWidget *state_body, *call_body;
    GtkWidget *state_card = verb_card("WHAT THE MODULE SAYS ABOUT ITSELF", &state_body);
    GtkWidget *call = verb_card("WHAT HAPPENS WHEN THE GATE IS ARMED", &call_body);
    GtkWidget *flow = fkit_flow();
    GtkWidget *status_btn = gtk_button_new_with_label("Read the Gate State");
    g_autofree char *script = module_script_path(module_id);
    const char *argv[] = { script, "--tx-status", NULL };
    g_autofree char *raw = run_capture(argv);
    g_auto(GStrv) lines = NULL;

    jamd_append_disclaimer(state_body, module_id);

    if (raw != NULL && *raw != '\0') {
        lines = g_strsplit(raw, "\n", -1);
        for (int i = 0; lines[i] != NULL; i++) {
            char *tab;

            if (!*lines[i]) continue;
            tab = strchr(lines[i], '\t');
            if (tab == NULL) {
                gtk_box_append(GTK_BOX(state_body), fkit_note(lines[i]));
                continue;
            }
            *tab = '\0';
            cve_fill_meta(state_body, lines[i], tab + 1);
        }
    }
    /* The state is read fresh: an operator may have armed the gate in a shell
       since this page was drawn, and a stale "closed" would be a lie. */
    radio_bench_run_button(status_btn, state, module_id, status, "--tx-status", NULL);
    fkit_flow_add(flow, status_btn, "flat");
    gtk_box_append(GTK_BOX(state_body), flow);
    gtk_box_append(GTK_BOX(body), state_card);

    gtk_box_append(GTK_BOX(call_body), fkit_note(
        "Keying is not on this page. The constructor above builds a file and "
        "stops; the step that opens a radio is reachable from the module's own "
        "command line, where an operator who has read the warning already is, "
        "and it is the only step that needs the authorisation flag. A button "
        "here would put that step one click from someone who arrived at this "
        "page by accident, and the flag would then have to be typed by someone "
        "who was not told what it means."));
    gtk_box_append(GTK_BOX(call_body), fkit_note(
        "With the flag set, the module still refuses to report success without "
        "a radio: it asks the driver, not the PATH, and a driver package "
        "installed is not a radio. Each driver is probed by its own tool, and a "
        "box with none of them fails with a non-zero exit and says which four "
        "were asked. Nothing is transmitted by a module that cannot see the "
        "device it claims to be transmitting with."));
    gtk_box_append(GTK_BOX(call_body), fkit_note(
        "There is one further refusal worth knowing: only one driver has a "
        "built-in transmit call. The others report what they would need rather "
        "than improvising a command line from a driver name."));
    gtk_box_append(GTK_BOX(body), call);

    (void) out;
    return outer;
}

static ModuleSubmenuEntry jamd_entries[] = {
    { "Overview", "dialog-information-symbolic", NULL, jamd_build_overview },
    { "Capture", "imsisting-01_radio-symbolic", NULL, jamd_build_capture },
    { "Profile", "imsisting-24_rf_fingerprint-symbolic", NULL, jamd_build_profile },
    { "Discriminate", "imsisting-23_traffic_analysis-symbolic", NULL, jamd_build_discriminate },
    { "Report", "document-save-symbolic", NULL, jamd_build_report },
    { "Waveform", "document-new-symbolic", NULL, jamd_build_waveform },
    { "Shapes", "network-wireless-symbolic", NULL, jamd_build_shapes },
    { "The Gate", "security-high-symbolic", NULL, jamd_build_gate },
};

static ModuleSubmenuEntry slic_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--nssai-parse:Parse NSSAI|--detect:Detect|--surface:Surface" },
    { "Encode / Decode",
      "document-open-symbolic",
      "#CODEC|--decode-s-nssai:Decode S-NSSAI|--encode-s-nssai:Encode S-NSSAI|#TABLE|--sst-table:SST Table|#NAS|--nas5gs:NAS 5GS" },
    { "Policy",
      "preferences-system-symbolic",
      "--isolation-check:Isolation Check|--selection:Selection|--plan:Plan" },
    /* QoS: the standardised 5QI table, the TSN parameters that ride in it, and
       the per-slice consistency check. */
    { "QoS",
      "preferences-system-symbolic",
      "--five-qi=1:5QI 1|--five-qi-table:5QI Table|~--tsn-config:TSN-QoS Config|~--slice-qos-check:Slice QoS Check" },
};
static ModuleSubmenuEntry bbnd_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--triage|--layers:Layers|--corpus:Corpus" },
    { "ASN.1",
      "document-open-symbolic",
      "--asn1-dec:ASN.1 Decode|--asn1-len:ASN.1 Length|--nas-hdr:NAS Header" },
    { "Fuzz",
      "security-high-symbolic",
      "--mutate:Mutate|--plan:Plan" },
    /* The offensive half. None of these keys a radio: the first encodes a DIAG
       frame through 56_baseband_diag, the second writes it to the port you name,
       and the rest write an artefact and print the handoff. */
    { "Modem Path",
      "network-transmit-receive-symbolic",
      "--diag-frame:DIAG Frame|--diag-send:Write to Modem|--rf-submit:Generator Commands" },
    { "Over the Air",
      "imsisting-01_radio-symbolic",
      "--transmit:Prepare Transmission|--send-payload:Mutate and Prepare" },
};
static ModuleSubmenuEntry vowi_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--walk:Walk|--epdg=001 01|--types:Types|~--payload|~--transform|~--id-type|~--notify|~--null-check" },
    { "IKE",
      "channel-secure-symbolic",
      "--ike-parse:Parse IKE|--ike-build:Build IKE" },
    { "EAP",
      "auth-smartcard-symbolic",
      "--eap-parse:Parse EAP|--eap-build:Build EAP|--nai=001010000000001 310 260|~--eap-attr" },
    { "Crypto",
      "security-high-symbolic",
      "--integrity:Integrity|--encr:Encryption|--plan:Plan|~--dh|~--esn" },
};
/* --------------------------------------------------------------------------
   The small-cell page, laid out the way the LTE CVE Kit page is: a named view
   with a subtitle, then cards that each hold one job, and a control per job.
   Two rules shape it.

   No control is named after a verb. A button says what it does -- "Decode
   CSG", "Ask the box", "Read the capture" -- and the verb stays in the C next
   to the argv, where check-gui-text.sh can see that it is not on screen.

   Views are the attack surface, not one per verb: closed cell, commissioning,
   management plane, identity of the cell (CSG/PCI), backhaul, and the stream
   of subscribers a relayed backhaul would produce. That is the same split the
   CVE kit uses (one card per part of the network, not one per CVE).
   -------------------------------------------------------------------------- */

static char *
scell_status_summary(const char *module_id)
{
    g_autofree char *script = module_script_path(module_id);
    const char *argv[] = { script, "--status-tsv", NULL };
    g_autofree char *raw = run_capture(argv);
    g_autofree char *target = raw ? tsv_field(raw, "TARGET") : NULL;
    g_autofree char *tx = raw ? tsv_field(raw, "TRANSMIT") : NULL;

    return g_strdup_printf("%s\n%s",
        (target && *target) ? target : "the module did not answer",
        (tx && *tx) ? tx : "transmit state unknown");
}



static GtkWidget *
scell_button(AppState *state, const char *module_id, GtkWidget *status,
             const char *button_label, const char *verb, const char *extra)
{
    GtkWidget *button = gtk_button_new_with_label(button_label);

    (void) extra;
    radio_bench_run_button(button, state, module_id, status, verb, NULL);
    return button;
}

/* 1. Overview: what this machine can prove right now, and the three ways in. */
static GtkWidget *
scell_build_overview(AppState *state, const char *module_id,
                     GtkWidget *status, GtkTextBuffer *out)
{
    GtkWidget *body;
    GtkWidget *outer = radio_view_shell("SMALL CELL / eNB",
        "A closed cell, the box that runs it, and the backhaul it hands traffic to.",
        &body);
    GtkWidget *state_body;
    GtkWidget *jobs_body;
    GtkWidget *jobs = verb_card("WHAT TO DO FIRST", &jobs_body);
    GtkWidget *flow = fkit_flow();
    g_autofree char *summary = scell_status_summary(module_id);
    GtkWidget *banner = gtk_label_new(summary);

    gtk_widget_add_css_class(banner, "crec-survey-status");
    gtk_label_set_xalign(GTK_LABEL(banner), 0.0f);
    gtk_label_set_selectable(GTK_LABEL(banner), TRUE);
    gtk_box_append(GTK_BOX(body), banner);

    gtk_box_append(GTK_BOX(body), verb_card("THE MODULE", &state_body));
    gtk_box_append(GTK_BOX(state_body), fkit_note(
        "27-bit CSG codec, SIB1/SIB9 over a real PER codec, PCI-confusion "
        "detection, and a TR-069/CWMP audit of a local management plane. "
        "Nothing here keys a transmitter."));
    gtk_box_append(GTK_BOX(state_body), fkit_note(
        "The Iuh backhaul reference and the lab handoff plan are in Backhaul. "
        "The S1 leg is not wired yet, and the plan says so."));

    fkit_flow_add(flow, scell_button(state, module_id, status,
        "Verify the Codec", "--selftest", "primary"), "primary");
    fkit_flow_add(flow, scell_button(state, module_id, status,
        "Read a Capture", "--detect", "flat"), "primary");
    fkit_flow_add(flow, scell_button(state, module_id, status,
        "Lab Plan", "--plan", "flat"), "primary");
    gtk_box_append(GTK_BOX(jobs_body), flow);
    gtk_box_append(GTK_BOX(jobs_body), fkit_note(
        "The selftest is the honest one: it writes a CSG SIB1, reads it back "
        "through the detector, and fails if the round trip disagrees."));
    gtk_box_append(GTK_BOX(body), jobs);

    (void) out;
    return outer;
}

/* 2. Closed cell: the one question a captured SIB1 answers on its own. */
static GtkWidget *
scell_build_detect(AppState *state, const char *module_id,
                   GtkWidget *status, GtkTextBuffer *out)
{
    GtkWidget *body;
    GtkWidget *outer = radio_view_shell("CLOSED CELL",
        "A cell that announces a closed subscriber group is a small cell by definition.",
        &body);
    GtkWidget *read_body;
    GtkWidget *read = verb_card("READ ONE", &read_body);

    gtk_box_append(GTK_BOX(read_body),
        mod_arg_row(state, module_id, status, "Read the Broadcast",
            "--detect",
            "SIB1 hex, or a file with one per line, or - for stdin",
            "One BCCH-DL-SCH-Message per line. Comments after # are ignored."));
    gtk_box_append(GTK_BOX(read_body), fkit_note(
        "The decode is tools/lte_asn1.py, whose SIB1 CSG fields are asserted "
        "against pycrate. Nothing here reads a bit layout of this tree's own."));
    gtk_box_append(GTK_BOX(body), read);

    gtk_box_append(GTK_BOX(body), fkit_note(
        "What the verdict means: a CSG bit is set, so the cell declares itself "
        "closed. What it does not mean: that an open cell is not small. A "
        "femtocell that broadcasts no CSG reads exactly like a macro here, and "
        "no amount of staring at SIB1 will separate them."));

    (void) out;
    return outer;
}

/* 3. Commissioning: the document a box needs, and the SIBs that carry it. */
static GtkWidget *
scell_build_commission(AppState *state, const char *module_id,
                       GtkWidget *status, GtkTextBuffer *out)
{
    GtkWidget *body;
    GtkWidget *outer = radio_view_shell("COMMISSIONING",
        "The settings a small cell is told to run, and the broadcasts that state them.",
        &body);
    GtkWidget *doc_body;
    GtkWidget *sib_body;
    GtkWidget *doc = verb_card("THE WHOLE PROFILE", &doc_body);
    GtkWidget *sib = verb_card("ONE BROADCAST AT A TIME", &sib_body);

    gtk_box_append(GTK_BOX(doc_body), mod_arg_row(state, module_id, status,
        "Write the Document", "--cell-profile",
        "mcc mnc band earfcn pci [csg-id] [name] [mme]",
        "The commissioning document: PLMN, band, EARFCN, PCI, CSG, plus both SIBs."));
    gtk_box_append(GTK_BOX(body), doc);

    gtk_box_append(GTK_BOX(sib_body), mod_arg_row(state, module_id, status,
        "Build SIB1", "--sib1", "mcc mnc tac-hex cellid-hex [csg-id]",
        "SIB1 carries cellAccessRelatedInfo, which is where a closed cell says so."));
    gtk_box_append(GTK_BOX(sib_body), mod_arg_row(state, module_id, status,
        "Build SIB9", "--sib9", "home eNodeB name",
        "SIB9's HNB-Name is an OCTET STRING, so the octets must be the text."));
    gtk_box_append(GTK_BOX(body), sib);

    (void) out;
    return outer;
}

/* 4. Management plane: read it, audit it, write to it. */
static GtkWidget *
scell_build_management(AppState *state, const char *module_id,
                       GtkWidget *status, GtkTextBuffer *out)
{
    GtkWidget *body;
    GtkWidget *outer = radio_view_shell("MANAGEMENT PLANE",
        "A residential box usually serves its own settings to whoever asks.",
        &body);
    GtkWidget *box_body;
    GtkWidget *audit_body;
    GtkWidget *box = verb_card("THE BOX", &box_body);
    GtkWidget *audit = verb_card("A CONFIG FILE", &audit_body);

    gtk_box_append(GTK_BOX(box_body), mod_arg_row(state, module_id, status,
        "Ask the Box", "--discover", "host [port]",
        "Reads the settings the box serves. Reports what answered, not what we hoped."));
    gtk_box_append(GTK_BOX(box_body), mod_arg_row(state, module_id, status,
        "Write the Profile", "--apply", "host [port]",
        "Builds a CWMP 1.2 SetParameterValues envelope and refuses when nothing answers."));
    gtk_box_append(GTK_BOX(box_body), fkit_note(
        "With nothing at the address this says nothing was written and exits "
        "non-zero, rather than reporting a write it did not make."));
    gtk_box_append(GTK_BOX(body), box);

    gtk_box_append(GTK_BOX(audit_body), mod_arg_row(state, module_id, status,
        "Audit It", "--tr069-audit", "/path/to/box.conf",
        "Key/value config. Flags default credentials, plaintext CWMP, exposed WAN "
        "management, optional TLS, a non-standard port."));
    gtk_box_append(GTK_BOX(body), audit);

    (void) out;
    return outer;
}

/* 5. Who the cell says it is: CSG id and PCI reuse. */
static GtkWidget *
scell_build_identity(AppState *state, const char *module_id,
                     GtkWidget *status, GtkTextBuffer *out)
{
    GtkWidget *body;
    GtkWidget *outer = radio_view_shell("CSG AND PCI",
        "The two numbers that decide who may attach, and who confuses whom.",
        &body);
    GtkWidget *csg_body;
    GtkWidget *pci_body;
    GtkWidget *csg = verb_card("CLOSED SUBSCRIBER GROUP", &csg_body);
    GtkWidget *pci = verb_card("PCI REUSE", &pci_body);

    gtk_box_append(GTK_BOX(csg_body), mod_arg_row(state, module_id, status,
        "Encode", "--csg-encode", "decimal id",
        "A CSG-Id is 27 bits (TS 36.413). Anything wider is refused, not truncated."));
    gtk_box_append(GTK_BOX(csg_body), mod_arg_row(state, module_id, status,
        "Decode", "--csg-decode", "hex",
        "Eight hex octets in, the decimal id out."));
    gtk_box_append(GTK_BOX(body), csg);

    gtk_box_append(GTK_BOX(pci_body), mod_arg_row(state, module_id, status,
        "Check a Cell List", "--pci-conflict", "/path/to/cells.tsv",
        "TSV with pci, earfcn and cell_id. Two cells on one PCI and one frequency "
        "is confusion; two on different frequencies is not, and it abstains."));
    gtk_box_append(GTK_BOX(body), pci);

    (void) out;
    return outer;
}

/* 6. Backhaul: where the traffic is already cleartext. */
static GtkWidget *
scell_build_backhaul(AppState *state, const char *module_id,
                     GtkWidget *status, GtkTextBuffer *out)
{
    GtkWidget *body;
    GtkWidget *outer = radio_view_shell("BACKHAUL",
        "Every other module in this tree attacks the air. This view is the other leg.",
        &body);
    GtkWidget *ref_body;
    GtkWidget *ref = verb_card("THE STACK", &ref_body);
    GtkWidget *flow = fkit_flow();

    fkit_flow_add(flow, scell_button(state, module_id, status,
        "Stack Reference", "--iuh", "primary"), "primary");
    fkit_flow_add(flow, scell_button(state, module_id, status,
        "Lab Plan", "--plan", "flat"), "primary");
    gtk_box_append(GTK_BOX(ref_body), flow);
    gtk_box_append(GTK_BOX(ref_body), fkit_note(
        "HNBAP / RUA / RANAP over SCTP on the Iuh is the 3G home-node stack. An "
        "LTE HeNB speaks S1AP over SCTP to the MME, GTP-U to the serving gateway, "
        "and IKEv2 to the security gateway. HNBAP registration is built below; "
        "RUA and RANAP are still a reference here."));
    gtk_box_append(GTK_BOX(ref_body), fkit_note(
        "There is no SCTP client in this tree, so nothing here registers with a "
        "core or relays a subscriber. The plan names the hardware and the "
        "software that would have to be on the bench first."));
    gtk_box_append(GTK_BOX(body), ref);

    GtkWidget *s1_body;
    GtkWidget *s1 = verb_card("S1 SETUP", &s1_body);
    gtk_box_append(GTK_BOX(s1_body), mod_arg_row(state, module_id, status,
        "Build S1 Setup", "--s1setup",
        "001 01 0xA1C01 LabHeNB 00f1",
        "MCC, MNC, macro eNB id, eNB name, TAC. S1AP is aligned PER where RRC "
        "is unaligned, so these octets come from their own codec, checked "
        "against pycrate and dissected by Wireshark."));
    gtk_box_append(GTK_BOX(s1_body), mod_arg_row(state, module_id, status,
        "Read an S1AP PDU", "--s1ap",
        "hex, or a file of it",
        "The same decoder in reverse: procedure, criticality and one row per "
        "information element."));
    gtk_box_append(GTK_BOX(s1_body), mod_arg_row(state, module_id, status,
        "Carry a NAS Message", "--s1ap-nas",
        "1 7 074100 ul",
        "MME UE id, eNB UE id, NAS hex, then ul or dl. This is the message that "
        "carries a handset's Attach through this box, which is what makes the "
        "IMSI ours rather than the carrier's."));
    gtk_box_append(GTK_BOX(s1_body), mod_arg_row(state, module_id, status,
        "Page a Handset", "--s1ap-paging",
        "0x01 0x0A0B0C0D",
        "MME code and M-TMSI. Release the context, page, and the handset "
        "re-attaches where the page came from."));
    gtk_box_append(GTK_BOX(s1_body), mod_arg_row(state, module_id, status,
        "Open the Association", "--s1-attach",
        "203.0.113.9 36412",
        "MME host, then an optional port and payload. The host path is the only "
        "one here that opens a socket, so it is armed: the module reports "
        "disarmed, exits 3 and names what it would have sent unless it is "
        "invoked with FEMT_S1_ARMED=1."));
    gtk_box_append(GTK_BOX(s1_body), fkit_note(
        "The three messages above need no network. The association does, and it "
        "is the only thing in this module that leaves the process: SCTP with PPID "
        "18, which is what an MME demultiplexes S1AP on. A wrong PPID establishes "
        "the association and then gets the payload silently dropped, so the "
        "report always carries the PPID it actually sent."));
    gtk_box_append(GTK_BOX(body), s1);

    GtkWidget *iuh_body;
    GtkWidget *iuh = verb_card("HNBAP AND RUA", &iuh_body);
    gtk_box_append(GTK_BOX(iuh_body), mod_arg_row(state, module_id, status,
        "Build HNB Register", "--iuh-register",
        "deadbeef 0xA1C0100",
        "HNB identity and the 28-bit cell identity. The octets come from their "
        "own codec, checked against pycrate and dissected by Wireshark on SCTP "
        "PPID 20, which is the payload id the Iuh uses for HNBAP."));
    gtk_box_append(GTK_BOX(iuh_body), mod_arg_row(state, module_id, status,
        "Build UE Register", "--ue-register",
        "3102601234567809 normal",
        "IMSI as BCD and a registration cause of emergency-call, normal or "
        "ue-relocation. This is the message a home node sends when a handset "
        "appears behind it."));
    gtk_box_append(GTK_BOX(iuh_body), mod_arg_row(state, module_id, status,
        "Read an HNBAP PDU", "--hnbap",
        "hex, or a file of it",
        "Procedure, criticality, one row per information element, and the "
        "identity fields the message carries."));
    gtk_box_append(GTK_BOX(iuh_body), mod_arg_row(state, module_id, status,
        "Open the Association", "--iuh-attach",
        "203.0.113.9 29169",
        "HNB-GW host, then an optional port and payload. Armed like the S1 one: "
        "PPID 20 is what the Iuh uses for HNBAP, and the report always names the "
        "PPID it sent."));
    gtk_box_append(GTK_BOX(iuh_body), mod_arg_row(state, module_id, status,
        "Build RUA Connect", "--rua-connect",
        "1 normal-call",
        "Context id, then the establishment cause. RUA is the half of Iuh that "
        "opens a signalling connection after HNBAP has registered the box, and "
        "the cause octet is what the core files the call as: 0x40 is a normal "
        "call, 0x20 reads as an emergency call."));
    gtk_box_append(GTK_BOX(iuh_body), mod_arg_row(state, module_id, status,
        "Build InitialUE-Message", "--ranap-initial-ue",
        "001 01 1 2 0741010b0000",
        "MCC, MNC, LAC, SAC and the subscriber's NAS message. This is the RANAP "
        "a rogue access point hands the core so it will serve that subscriber, "
        "and the domain octet in it is one bit: 0x80 asks for the packet core, "
        "0x00 asks for the circuit-switched one."));
    gtk_box_append(GTK_BOX(iuh_body), mod_arg_row(state, module_id, status,
        "Read a RANAP PDU", "--ranap-decode",
        "hex, or a file of it",
        "Procedure, one row per information element, and the PLMN, tracking "
        "area, service area and NAS message the message carries."));
    gtk_box_append(GTK_BOX(iuh_body), mod_arg_row(state, module_id, status,
        "Carry a RANAP", "--rua-transfer",
        "0x000102 0000000100",
        "A DirectTransfer frames RANAP hex you supply -- the octets from the "
        "row above, or a message from another tool. The frame is checked on its "
        "own; what it carries is only as good as what was put in it."));
    gtk_box_append(GTK_BOX(iuh_body), mod_arg_row(state, module_id, status,
        "Read a RUA PDU", "--rua-decode",
        "hex, or a file of it",
        "Procedure, criticality, one row per information element with its value: "
        "the context id, the establishment cause, or the RANAP octets it carried."));
    gtk_box_append(GTK_BOX(iuh_body), mod_arg_row(state, module_id, status,
        "Send the Transfer", "--iuh-rua",
        "203.0.113.9 1 0000000100",
        "HNB-GW host, context id, RANAP hex, then an optional port. Armed like "
        "the others: PPID 19 on 29169 is what the Iuh uses for RUA, and nothing "
        "leaves the process unless it is invoked with FEMT_S1_ARMED=1."));
    gtk_box_append(GTK_BOX(iuh_body), mod_arg_row(state, module_id, status,
        "Attach a Subscriber", "--iuh-ue",
        "203.0.113.9 001 01 1 2 0741010b0000",
        "HNB-GW host, then MCC, MNC, LAC, SAC and NAS: the whole leg in one "
        "call. RANAP is built, framed in a RUA DirectTransfer and sent on "
        "PPID 19, with each layer's octet count reported. Armed like the rest."));
    gtk_box_append(GTK_BOX(iuh_body), fkit_note(
        "Every message is byte-exact, and the selftest pins the octet strings "
        "so a codec change fails here rather than on a real gateway. Both "
        "codecs are checked against pycrate and dissected by tshark, HNBAP on "
        "PPID 20, RUA and RANAP on PPID 19. The association is armed for the "
        "same reason the S1 one is: a build should not be one typo away from a "
        "live socket."));
    gtk_box_append(GTK_BOX(body), iuh);

    gtk_box_append(GTK_BOX(body), fkit_note(
        "Why this leg matters: a home node's traffic is cleartext between the "
        "box and the security gateway. Attack the air and you get a phone; own "
        "the box and you get what the phone is carrying."));

    (void) out;
    return outer;
}

/* 7. Live subscribers: what a relayed backhaul would put on this page. */
/* The subscriber list, built the way the Wi-Fi recon Targets view is built: a
   summary strip over a scrollable list of composite rows, because nine columns
   squeezed side by side read worse than an identity with its own second line.
   Nothing here is a table model — the file is the model, and a refresh rereads
   it. */

typedef struct {
    GtkWidget *summary;
    GtkWidget *list;
    char      *path;
} ScellFeed;

static void
scell_feed_free(gpointer user_data)
{
    ScellFeed *feed = user_data;

    if (feed == NULL)
        return;
    g_free(feed->path);
    g_free(feed);
}

static void
scell_feed_copy_clicked(GtkButton *button, gpointer user_data)
{
    const char *text = g_object_get_data(G_OBJECT(button), "scell-line");
    GdkClipboard *cb;

    (void) user_data;
    if (text == NULL || *text == '\0')
        return;
    cb = gdk_display_get_clipboard(
        gtk_widget_get_display(GTK_WIDGET(button)));
    if (cb != NULL)
        gdk_clipboard_set_text(cb, text);
}

/* time frame kind identity source type arfcn channel uplink */
static void
scell_feed_add_row(GtkWidget *list, const char *line)
{
    g_auto(GStrv) f = g_strsplit(line, "\t", 9);
    const char *kind = f[2] != NULL ? f[2] : "";
    const char *icon;
    GtkWidget *row;
    GtkWidget *hbox;
    GtkWidget *left;
    GtkWidget *main_row;
    GtkWidget *badge;
    GtkWidget *glyph;
    GtkWidget *copy;
    g_autofree char *meta = NULL;

    if (g_strv_length(f) < 4)
        return;

    if (g_strcmp0(kind, "imsi") == 0)
        icon = "system-users-symbolic";
    else if (g_strcmp0(kind, "guti") == 0 || g_strcmp0(kind, "tmsi") == 0)
        icon = "dialog-password-symbolic";
    else
        icon = "network-cellular-symbolic";

    row = gtk_list_box_row_new();
    gtk_widget_add_css_class(row, "scell-feed-row");
    hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);

    glyph = gtk_image_new_from_icon_name(icon);
    gtk_image_set_pixel_size(GTK_IMAGE(glyph), 20);
    gtk_widget_set_valign(glyph, GTK_ALIGN_START);
    gtk_widget_add_css_class(glyph, "scell-feed-glyph");

    left = gtk_box_new(GTK_ORIENTATION_VERTICAL, 3);

    main_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    {
        GtkWidget *id = gtk_label_new(f[3]);
        gtk_label_set_xalign(GTK_LABEL(id), 0.0f);
        gtk_label_set_selectable(GTK_LABEL(id), TRUE);
        gtk_widget_add_css_class(id, "scell-feed-id");
        gtk_box_append(GTK_BOX(main_row), id);

        badge = gtk_label_new(kind);
        gtk_label_set_xalign(GTK_LABEL(badge), 0.5f);
        gtk_widget_add_css_class(badge, "scell-feed-badge");
        if (g_strcmp0(kind, "imsi") != 0)
            gtk_widget_add_css_class(badge, "closed");
        gtk_widget_set_valign(badge, GTK_ALIGN_CENTER);
        gtk_box_append(GTK_BOX(main_row), badge);
    }
    gtk_box_append(GTK_BOX(left), main_row);

    /* time . NAS type . ARFCN . channel . direction . which module saw it */
    meta = g_strdup_printf("%s  \u2022  %s  \u2022  ARFCN %s  \u2022  ch %s  \u2022  %s  \u2022  %s",
        f[0] != NULL && *f[0] != '\0' ? f[0] : "-",
        f[5] != NULL && *f[5] != '\0' ? f[5] : "unknown type",
        f[6] != NULL && *f[6] != '\0' ? f[6] : "-",
        f[7] != NULL && *f[7] != '\0' ? f[7] : "-",
        f[8] != NULL && *f[8] != '\0' ? f[8] : "-",
        f[4] != NULL && *f[4] != '\0' ? f[4] : "-");
    {
        GtkWidget *meta_label = gtk_label_new(meta);
        gtk_label_set_xalign(GTK_LABEL(meta_label), 0.0f);
        gtk_label_set_wrap(GTK_LABEL(meta_label), TRUE);
        gtk_widget_add_css_class(meta_label, "scell-feed-meta");
        gtk_box_append(GTK_BOX(left), meta_label);
    }
    gtk_widget_set_hexpand(left, TRUE);
    gtk_box_append(GTK_BOX(hbox), glyph);
    gtk_box_append(GTK_BOX(hbox), left);

    copy = gtk_button_new_with_label("Copy");
    gtk_widget_set_valign(copy, GTK_ALIGN_CENTER);
    gtk_widget_add_css_class(copy, "scell-feed-copy");
    gtk_widget_add_css_class(copy, "flat");
    g_object_set_data_full(G_OBJECT(copy), "scell-line", g_strdup(line), g_free);
    g_signal_connect(copy, "clicked",
        G_CALLBACK(scell_feed_copy_clicked), NULL);
    gtk_box_append(GTK_BOX(hbox), copy);

    gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), hbox);
    gtk_list_box_append(GTK_LIST_BOX(list), row);
}

/* Rebuild the list from the file. Returns the number of sightings drawn. */
static guint
scell_feed_reload(ScellFeed *feed)
{
    g_autofree char *text = NULL;
    g_autofree char *summary = NULL;
    guint rows = 0, imsi = 0, other = 0;

    for (GtkWidget *child = gtk_widget_get_first_child(feed->list);
         child != NULL; child = gtk_widget_get_first_child(feed->list))
        gtk_list_box_remove(GTK_LIST_BOX(feed->list), child);

    if (!g_file_get_contents(feed->path, &text, NULL, NULL) ||
        text == NULL || *text == '\0') {
        gtk_label_set_text(GTK_LABEL(feed->summary), "no table yet");
        return 0;
    }

    {
        g_auto(GStrv) lines = g_strsplit(text, "\n", -1);
        guint total = 0;

        for (guint i = 1; lines[i] != NULL; i++)
            if (*lines[i] != '\0')
                total++;

        /* Newest last in the file, newest first in the window: the reason to
           open this page is the attach that just happened. */
        for (guint i = 0; total > 0 && i < total; i++) {
            guint idx = total - i;
            g_auto(GStrv) f = g_strsplit(lines[idx], "\t", 9);

            if (g_strv_length(f) < 4)
                continue;
            if (rows >= 500)
                break;
            scell_feed_add_row(feed->list, lines[idx]);
            rows++;
            if (g_strcmp0(f[2], "imsi") == 0)
                imsi++;
            else
                other++;
        }
    }

    if (rows == 0) {
        gtk_label_set_text(GTK_LABEL(feed->summary),
            "table present, no identity sighting in it");
        return 0;
    }
    summary = g_strdup_printf("%u sighting%s  \u2022  %u IMSI  \u2022  %u other identity  \u2022  %s",
        rows, rows == 1 ? "" : "s", imsi, other, "newest first");
    gtk_label_set_text(GTK_LABEL(feed->summary), summary);
    return rows;
}

static void
scell_feed_refresh_clicked(GtkButton *button, gpointer user_data)
{
    ScellFeed *feed = user_data;

    (void) button;
    scell_feed_reload(feed);
}

static GtkWidget *
scell_build_live(AppState *state, const char *module_id,
                 GtkWidget *status, GtkTextBuffer *out)
{
    GtkWidget *body;
    GtkWidget *outer = radio_view_shell("LIVE SUBSCRIBERS",
        "What a relayed backhaul would show: who attached, through which box, when.",
        &body);
    GtkWidget *feed_body;
    GtkWidget *feed = verb_card("FEED", &feed_body);
    GtkWidget *list_head;
    GtkWidget *scroll;
    GtkWidget *list;
    GtkWidget *refresh;
    GtkWidget *window;
    GtkWidget *path_note;
    GtkWidget *entry = NULL;
    ScellFeed *sf;
    g_autofree char *root = imsisting_root();

    sf = g_new0(ScellFeed, 1);
    sf->path = g_strdup_printf("%s/loot/femtocell/subscribers.tsv", root);

    /* One field, because the module takes one: a number is a listen window on
       GSMTAP, anything else is a capture to read through the same join. */
    gtk_box_append(GTK_BOX(feed_body), fkit_composer_verb(state, module_id,
        status, &entry, "--live", "Feed",
        "seconds on UDP 4729, or a .pcap to read",
        "Read Feed"));
    gtk_box_append(GTK_BOX(feed_body), fkit_note(
        "The window listens on GSMTAP and hands every payload to the decoder "
        "that owns its format, so a capture read here and a capture read on "
        "Live Traffic produce the same rows. Nothing is decoded twice."));

    window = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_add_css_class(window, "scell-feed-window");

    list_head = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    sf->summary = gtk_label_new("no table yet");
    gtk_label_set_xalign(GTK_LABEL(sf->summary), 0.0f);
    gtk_widget_set_hexpand(sf->summary, TRUE);
    gtk_widget_add_css_class(sf->summary, "scell-feed-summary");
    refresh = gtk_button_new_with_label("Refresh");
    gtk_widget_set_valign(refresh, GTK_ALIGN_CENTER);
    gtk_widget_add_css_class(refresh, "flat");
    gtk_box_append(GTK_BOX(list_head), sf->summary);
    gtk_box_append(GTK_BOX(list_head), refresh);
    gtk_box_append(GTK_BOX(window), list_head);

    list = gtk_list_box_new();
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(list), GTK_SELECTION_NONE);
    gtk_widget_add_css_class(list, "scell-feed-list");
    scroll = gtk_scrolled_window_new();
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
        GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), list);
    gtk_widget_set_size_request(scroll, -1, 260);
    gtk_widget_add_css_class(scroll, "scell-feed-scroll");
    gtk_box_append(GTK_BOX(window), scroll);

    sf->list = list;
    g_signal_connect(refresh, "clicked",
        G_CALLBACK(scell_feed_refresh_clicked), sf);
    g_signal_connect_swapped(scroll, "destroy",
        G_CALLBACK(scell_feed_free), sf);

    path_note = fkit_note(sf->path);
    gtk_box_append(GTK_BOX(window), path_note);

    if (scell_feed_reload(sf) == 0)
        gtk_box_append(GTK_BOX(window), fkit_note(
            "A row is written only for an identity sighting, so an empty "
            "window means the feed carried no identity - not that the capture "
            "failed. Nothing invents a row."));

    gtk_box_append(GTK_BOX(body), feed);
    gtk_box_append(GTK_BOX(body), window);

    (void) out;
    return outer;
}

static ModuleSubmenuEntry femt_entries[] = {
    { "Overview", "dialog-information-symbolic", NULL, scell_build_overview },
    { "Closed Cell", "system-search-symbolic", NULL, scell_build_detect },
    { "Commissioning", "document-new-symbolic", NULL, scell_build_commission },
    { "Management Plane", "preferences-system-symbolic", NULL, scell_build_management },
    { "CSG and PCI", "network-server-symbolic", NULL, scell_build_identity },
    { "Backhaul", "network-wired-symbolic", NULL, scell_build_backhaul },
    { "Live Subscribers", "view-list-symbolic", NULL, scell_build_live },
};
static ModuleSubmenuEntry ussd_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--detect:Detect|--mmi=*#21#|--ss-codes:SS Codes" },
    { "Codec",
      "document-open-symbolic",
      "--pack:Pack|--unpack:Unpack|--build:Build" },
    { "Planning",
      "preferences-system-symbolic",
      "--plan:Plan" },
};
static ModuleSubmenuEntry tgeo_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--ta=1|--trilaterate:Trilaterate|--cells:Cells" },
    { "Planning",
      "preferences-system-symbolic",
      "--plan:Plan" },
};
static ModuleSubmenuEntry sbap_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--nf-paths:NF Paths|--nrf|--token-pivot:Token Pivot" },
    { "HTTP/2",
      "network-transmit-receive-symbolic",
      "--h2-parse:Parse HTTP/2|--h2-build:Build HTTP/2|--h2-types:HTTP/2 Types|--hpack:HPACK Decode|--sbi-send:Send to NF" },
    { "JWT",
      "channel-secure-symbolic",
      "--jwt|--jwt-audit:JWT Audit" },
    { "Attacks",
      "security-high-symbolic",
      "#ATTACK|--rapid-reset:Rapid Reset|~--scope|#OPTIONS|--settings:Settings|--plan:Plan" },
};
static ModuleSubmenuEntry otasm_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "~--parse-packet|--packet:Packet|--counter-check:Counter Check|"
      "~--packet-sms|~--parse-packet-sms|~--parse-resp-sms:Response Packet" },
    { "SPI",
      "auth-smartcard-symbolic",
      "--spi-build:Build SPI|~--spi|--plan:Plan" },
    { "TP layer",
      "mail-message-new-symbolic",
      "~--tpdu-parse:Parse TPDU|--tpdu-deliver:Build DELIVER|--tpdu-submit:Build SUBMIT|--smsc-wrap:Wrap SMSC"
      "|--tp-pid:TP-PID|--tp-dcs:TP-DCS|--tp-dcs-build:Build DCS|--tp-scts:TP-SCTS|--tp-scts-build:Build SCTS"
      "|--tp-addr:Address|--tp-addr-build:Build Address|--tp-fcs:TP-FCS|--tp-st:TP-ST|--plan-tp:Handoff" },
    { "Type 0",
      "dialog-warning-symbolic",
      "~--type0:Audit Type 0|--type0-build:Build Type 0|--tp-kat:Packing KAT|--tp-ud-build:Pack Text|--tp-ud-read:Unpack Text" },
    /* S@T push: the SIM Toolkit browser push as it really travels, as a
       (U)SIM Data download SMS. ~--wib-push is CLI-only on purpose: the verb
       refuses with rc 2 until the WIB leaf commands are sourced, and a button
       whose only possible answer is a refusal is not a control. */
    { "SAT push",
      "mail-message-new-symbolic",
      "--sat-push=+15551234567 +15559876543:S@T Browser Push|~--wib-push:WIB Push (refuses)" },
};
static ModuleSubmenuEntry lipr_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--interfaces:Interfaces|--architecture:Architecture|--score:Score" },
    { "Probe",
      "system-search-symbolic",
      "--iface=X1|--report:Report|--plan:Plan" },
    /* The encoder half: real bytes for the X1/HI1 and HI3 artefacts, and a
       handoff rather than a send. */
    { "Encode",
      "document-save-symbolic",
      "--provision-target:Provisioning Artefact|--activate:Activation Record|--intercept:Product Envelope" },
};
static ModuleSubmenuEntry rans_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "~--leak-check|--mode=mocn|--eplmn=001-01,001-02" },
    { "PLMN",
      "network-server-symbolic",
      "--plmn-decode:Decode PLMN|--plmn-encode:Encode PLMN|--plan:Plan" },
};
static ModuleSubmenuEntry capi_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--openapi:OpenAPI|--authz-matrix:Authz Matrix|--report:Report" },
    { "Attacks",
      "security-high-symbolic",
      "--stuffing:Credential Stuffing|--token-bucket:Token Bucket|--jwt-audit:JWT Audit" },
    { "Compare",
      "system-search-symbolic",
      "--diff:Diff|--plan:Plan" },
    /* Enumeration: the surface plan and the subscriber sequence. Both stop at
       the artefact -- the page says so. */
    { "Enumeration",
      "system-search-symbolic",
      "--enumerate:Map the Surface|--enumerate-subscribers:Subscriber Sequence" },
};
static ModuleSubmenuEntry iot_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      /* Both decoders are given a worked message rather than no argument.
         A button that only prints "usage:" teaches nothing, and these two are
         the ones whose answer is checkable: the MIB vector is the 34-bit
         broadcast block, and the SIB1-NB vector is a whole SystemInformation-
         BlockType1-NB. Either can be replaced by pasting bits from a capture
         on the command line. */
      "--decode-sib1=c30a8246815d5e6d058606e53b5073a801008008:Decode SIB1"
      "|--decode-mib=accac00000:Decode MIB"
      /* The two refusals are buttons on purpose: an operator who asks gets the
         reason, the clause that would settle it, and what to do instead. A
         hidden verb would leave the gap to be discovered by accident. */
      "|#LIMITS|--nprach:NPRACH Not In Tree|--to-mhz=0:NPRFCN Not In Tree"
      "|#SEQUENCES|--npss-nss=503:PCI 503 Split" },
};
static ModuleSubmenuEntry lpp_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--list-pids:List PIDs|--parse-position:Parse Position|--detect-forgery:Detect Forgery" },
    { "Build",
      "document-new-symbolic",
      "--build-header:Build Header|--forge-position:Forge Position|--decode-header:Decode Header" },
    /* Positioning procedures, encoded through the generated LPP table and
       checked against pycrate octet for octet. */
    { "Procedures",
      "system-search-symbolic",
      "--otdoa-assist:OTDOA Assistance|--otdoa-request:OTDOA Request"
      "|--utdoa-config=utdoa:UTDOA Fields|--prs-plan:PRS Schedule" },
};
static ModuleSubmenuEntry wifioff_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--auth-flow:Auth Flow|--lwa-config:LWA Config|--epdg-fqdn" },
    { "Certificates",
      "channel-secure-symbolic",
      "--cert-thumb:Cert Thumbprint|--validate-cert:Validate Cert" },
};
static ModuleSubmenuEntry oran_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--assess:Assess|--interfaces:Interfaces|--e2sm:E2SM" },
    { "Attacks",
      "security-high-symbolic",
      "#XAPP|--xapp-attack:xApp Attack|--xapp-authority:xApp Authority|#INTERFACE|--a1-put:A1 PUT|--e2-control:E2 Control" },
    { "Planning",
      "preferences-system-symbolic",
      "--plan:Plan" },
    /* A1 policy poisoning aimed at QoS rather than at admission: the body that
       asks the RIC to re-shape a slice's resources. */
    { "QoS Policy",
      "security-high-symbolic",
      "--qos-policy:A1 QoS Policy|~--qos-policy-check:QoS Policy Check" },
};
static ModuleSubmenuEntry ntn_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--sib19:SIB19|--doppler=1000 100 45|--range=500" },
    { "Link",
      "network-wireless-symbolic",
      "--feeder:Feeder|--koffset:K-Offset|--ta:TA" },
    { "Planning",
      "preferences-system-symbolic",
      "--plan:Plan" },
};
static ModuleSubmenuEntry gprs_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "#TABLE|--gea-table:GEA Table"
      "|#ATTACK|--gea-downgrade:GEA Downgrade"
      /* The demonstration carries a worked packet, so the button shows what
         GEA0 does to data instead of printing a usage line: the input Kc and
         IV are arbitrary, the plaintext is "Hello", and the answer is that
         five cleartext octets come back out. */
      "|--gea-crypt=0 0011223344556677 00000000 48656c6c6f:GEA0 Leaks Plaintext"
      "|#PARAMS|--gea=1" },
    { "APN",
      "network-server-symbolic",
      "--apn-decode:Decode APN|--apn-encode:Encode APN|--apn-ie:APN IE" },
    { "PDP",
      "preferences-system-symbolic",
      "--pdp-ie:PDP IE|--plan:Plan" },
};
static ModuleSubmenuEntry slnk_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--relay-check:Relay Check|--sci1a:SCI1-A Limits|--its" },
    { "Config",
      "preferences-system-symbolic",
      "#PARAMS|--l2id=000001|--pfi=1|#TABLES|--subchannels:Subchannels|--freq-bits:Frequency Bits" },
    { "Planning",
      "preferences-system-symbolic",
      "--plan:Plan" },
};
static ModuleSubmenuEntry stk_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--parse:Parse|--build:Build|--audit:Audit" },
    { "SAT",
      "auth-smartcard-symbolic",
      "--sat-audit:SAT Audit|--sat-cmds:SAT Commands|--simjacker-detect:Simjacker Detect" },
    { "Command",
      "document-send-symbolic",
      "#COMMAND|--cmd=21|--result=00|--device=81|#PLAN|--plan:Plan" },
};
static ModuleSubmenuEntry n3g_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--classify:Classify|--detect-note:Detect Note" },
    { "Radio",
      "network-wireless-symbolic",
      "#TETRA|--tetra:TETRA|--frame-math=255 2 4 36000:Derive TETRA Frame"
      "|#DMR|--dmr:DMR|--frame-math=132 2 2 9600 2.5:Derive DMR Frame"
      "|#RAIL|--gsmr:GSM-R|#LEGACY|--tdma:TDMA|--tea:TEA" },
    { "Planning",
      "preferences-system-symbolic",
      "--plan:Plan" },
};
static ModuleSubmenuEntry bexp_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--list-cves:List CVEs|--emulate:Emulate|--states:States" },
    { "Forge",
      "security-high-symbolic",
      "--forge-identity:Forge Identity|--forge-reg-accept:Forge Reg Accept|--forge-reg-reject:Forge Reg Reject" },
    { "Analysis",
      "system-search-symbolic",
      "#CVE|--cve=CVE-2023-33042|#CHECK|--cp-check:CP Check|#L2|--l2-case:L2 Case|--l2-corpus:L2 Corpus|~--l2-build" },
    { "Transmit",
      "network-transmit-receive-symbolic",
      "#FRAME|~--inject|#CASE|~--send" },
    { "Planning",
      "preferences-system-symbolic",
      "--plan:Plan" },
};
static ModuleSubmenuEntry nrj_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--exploits:Exploits|--exploit=rrc-setup-crash|--descramble:Descramble" },
    { "PHY",
      "network-wireless-symbolic",
      "#SEQUENCE|--gold=12345,84|#TRANSPORT|--tbs=9,52,12,0" },
    { "DCI",
      "utilities-terminal-symbolic",
      "--dci-parse=0A0F3C9001,1_0|~--dci-encode" },
    { "RAR",
      "document-new-symbolic",
      "--rar=33,128,4601,4026|--rar-backoff=20|~--rar-backoff-idx" },
    { "MAC",
      "network-receive-symbolic",
      "#DECODE|--mac-pdu:MAC PDU|--mac-sub:MAC Subheader|#LCID|--lcid=0|--lcid-table:LCID Table|#FRAME|~--frame" },
    { "RNTI",
      "preferences-system-symbolic",
      "#RNTI|--ra-rnti-nr:RA-RNTI NR|--ra-rnti-lte:RA-RNTI LTE|#DCI|--dci|#PLAN|--plan:Plan" },
    { "Transmit",
      "network-transmit-receive-symbolic",
      "#AUTH|~--auth-capture|--auth-replay:Auth Replay|#FRAME|~--inject" },
};

static ModuleSubmenuEntry bbdg_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--status:Status|--kat:Framing KATs|--cmd-name=38:Name Code|--plan:Handoff Plan" },
    { "Framing",
      "utilities-terminal-symbolic",
      "#CHECKSUM|--crc=313233343536373839:CRC 906E|#FRAME|--frame=0032:Frame|--unframe=7e000a6b6d000007000000000000007e:Unframe|~--demux|#CODEC|~--escape|~--unescape|--log-classify=10:Classify" },
    { "NV",
      "drive-harddisk-symbolic",
      "#BUILD|--nv-build=read 178:Build Read|--nv-read=178:Read NV178|--nv-write=178 00:Write NV178|#DECODE|~--nv-parse|--nv-scan:NV Scan" },
    { "Identity",
      "avatar-default-symbolic",
      "#REQUEST|--state-build=gsm:Build GSM|--state-info=gsm:State GSM|--state-info=wcdma:State WCDMA|--state-info=cm:State CM|~--state|#VERSION|--verno:Version Req|~--verno-parse|#BCD|--bcd=3035230506641263:Decode IMEI|--luhn=353325060462136:Luhn" },
    { "EFS",
      "folder-symbolic",
      "#OPEN|--efs-open=/nv/item_files/modem/mmode/ue_usage_setting read:Open RO|#READ|--efs-read=/nv/item_files/modem/mmode/ue_usage_setting:Read|#WRITE|--efs-write=/nv/item_files/modem/mmode/ue_usage_setting 00:Write|#STAT|--efs-stat=/nv:Stat|--efs-hello:Hello|#DECODE|~--efs-parse|--efs-walk=/nv:EFS Walk" },
    { "AT / Device",
      "network-wireless-symbolic",
      "#AT|--at=ATI:ATI|--at=AT+CGSN:CGSN|~--at-parse|#DEVICE|--ports:Ports|~--config|~--read|~--write-hex|--audit=7e000a6b6d000007000000000000007e:Audit" },
    { "Planning",
      "preferences-system-symbolic",
      "--guard-check:Guard Check|--plan:Plan" },
};

static void
register_all_modules(void)
{
    module_registry_register("00_deps", deps_entries,
                             G_N_ELEMENTS(deps_entries), NULL);
    module_registry_register("01_radio", radio_entries,
                             G_N_ELEMENTS(radio_entries), NULL);
    module_registry_register("02_cell_recon", crec_entries,
                             G_N_ELEMENTS(crec_entries), NULL);
    module_registry_register("03_gsmtap", gtap_entries,
                             G_N_ELEMENTS(gtap_entries), NULL);
    module_registry_register("04_tower_map", tmap_entries,
                             G_N_ELEMENTS(tmap_entries), NULL);
    module_registry_register("05_field_kit", fkit_entries,
                             G_N_ELEMENTS(fkit_entries), NULL);
    module_registry_register("06_gsm_air", gair_entries,
                             G_N_ELEMENTS(gair_entries), NULL);
    module_registry_register("07_gsm_attack", gatk_entries,
                             G_N_ELEMENTS(gatk_entries), NULL);
    module_registry_register("08_umts_air", uair_entries,
                             G_N_ELEMENTS(uair_entries), NULL);
    module_registry_register("09_lte_attach", latt_entries,
                             G_N_ELEMENTS(latt_entries), NULL);
    module_registry_register("10_lte_air", lair_entries,
                             G_N_ELEMENTS(lair_entries), NULL);
    module_registry_register("11_lte_core", lcore_entries,
                             G_N_ELEMENTS(lcore_entries), NULL);
    module_registry_register("12_nr_air", nair_entries,
                             G_N_ELEMENTS(nair_entries), NULL);
    module_registry_register("13_nr_core", ncore_entries,
                             G_N_ELEMENTS(ncore_entries), NULL);
    module_registry_register("14_suci", suci_entries,
                             G_N_ELEMENTS(suci_entries), NULL);
    module_registry_register("15_downgrade", dwn_entries,
                             G_N_ELEMENTS(dwn_entries), NULL);
    module_registry_register("16_sim", sim_entries,
                             G_N_ELEMENTS(sim_entries), NULL);
    module_registry_register("17_pcap_analysis", pcap_entries,
                             G_N_ELEMENTS(pcap_entries), NULL);
    module_registry_register("18_imsi_exposure", imsi_entries,
                             G_N_ELEMENTS(imsi_entries), NULL);
    module_registry_register("19_cipher_audit", caud_entries,
                             G_N_ELEMENTS(caud_entries), NULL);
    module_registry_register("20_gsm_cve", gcve_entries,
                             G_N_ELEMENTS(gcve_entries), NULL);
    module_registry_register("21_lte_cve", lcve_entries,
                             G_N_ELEMENTS(lcve_entries), NULL);
    module_registry_register("22_nr_cve", ncve_entries,
                             G_N_ELEMENTS(ncve_entries), NULL);
    module_registry_register("25_killchain", kchn_entries,
                             G_N_ELEMENTS(kchn_entries), NULL);
    module_registry_register("23_traffic_analysis", tana_entries,
                             G_N_ELEMENTS(tana_entries), NULL);
    module_registry_register("24_rf_fingerprint", rff_entries,
                             G_N_ELEMENTS(rff_entries), NULL);
    module_registry_register("29_mac_layer", macl_entries,
                             G_N_ELEMENTS(macl_entries), NULL);
    module_registry_register("32_nas_signaling", nasf_entries,
                             G_N_ELEMENTS(nasf_entries), NULL);
    module_registry_register("26_ss7_map", ss7_entries,
                             G_N_ELEMENTS(ss7_entries), NULL);
    module_registry_register("27_cellular_dns", cdns_entries,
                             G_N_ELEMENTS(cdns_entries), NULL);
    module_registry_register("28_paging_track", pgt_entries,
                             G_N_ELEMENTS(pgt_entries), NULL);
    module_registry_register("30_volte_ims", vims_entries,
                             G_N_ELEMENTS(vims_entries), NULL);
    module_registry_register("31_sim_defense", simd_entries,
                             G_N_ELEMENTS(simd_entries), NULL);
    module_registry_register("33_jamming_detect", jamd_entries,
                             G_N_ELEMENTS(jamd_entries), NULL);
    module_registry_register("34_slicing", slic_entries,
                             G_N_ELEMENTS(slic_entries), NULL);
    module_registry_register("45_iot", iot_entries,
                             G_N_ELEMENTS(iot_entries), NULL);
    module_registry_register("46_lpp", lpp_entries,
                             G_N_ELEMENTS(lpp_entries), NULL);
    module_registry_register("47_wifioff", wifioff_entries,
                             G_N_ELEMENTS(wifioff_entries), NULL);
    module_registry_register("35_baseband", bbnd_entries,
                             G_N_ELEMENTS(bbnd_entries), NULL);
    module_registry_register("36_vowifi", vowi_entries,
                             G_N_ELEMENTS(vowi_entries), NULL);
    module_registry_register("37_femtocell", femt_entries,
                             G_N_ELEMENTS(femt_entries), NULL);
    module_registry_register("38_ussd", ussd_entries,
                             G_N_ELEMENTS(ussd_entries), NULL);
    module_registry_register("39_ta_geoloc", tgeo_entries,
                             G_N_ELEMENTS(tgeo_entries), NULL);
    module_registry_register("40_sba_pivot", sbap_entries,
                             G_N_ELEMENTS(sbap_entries), NULL);
    module_registry_register("41_ota_sms", otasm_entries,
                             G_N_ELEMENTS(otasm_entries), NULL);
    module_registry_register("42_li_probe", lipr_entries,
                             G_N_ELEMENTS(lipr_entries), NULL);
    module_registry_register("43_ran_share", rans_entries,
                             G_N_ELEMENTS(rans_entries), NULL);
    module_registry_register("44_carrier_api", capi_entries,
                             G_N_ELEMENTS(capi_entries), NULL);
    module_registry_register("48_oran", oran_entries,
                             G_N_ELEMENTS(oran_entries), NULL);
    module_registry_register("49_ntn", ntn_entries,
                             G_N_ELEMENTS(ntn_entries), NULL);
    module_registry_register("50_gprs", gprs_entries,
                             G_N_ELEMENTS(gprs_entries), NULL);
    module_registry_register("51_sidelink", slnk_entries,
                             G_N_ELEMENTS(slnk_entries), NULL);
    module_registry_register("52_stk", stk_entries,
                             G_N_ELEMENTS(stk_entries), NULL);
    module_registry_register("53_non3gpp", n3g_entries,
                             G_N_ELEMENTS(n3g_entries), NULL);
    module_registry_register("54_baseband_exploit", bexp_entries,
                             G_N_ELEMENTS(bexp_entries), NULL);
    module_registry_register("55_nr_inject", nrj_entries,
                             G_N_ELEMENTS(nrj_entries), NULL);
    module_registry_register("56_baseband_diag", bbdg_entries,
                             G_N_ELEMENTS(bbdg_entries), NULL);
}
