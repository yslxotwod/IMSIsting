/* map_page.c — the tier-1 Map page.
 *
 * One canvas, one projection, and two data sources that never talk to each
 * other:
 *
 *   native/resources/basemap/<name>.bin   the world (Natural Earth 1:110m,
 *                                    flattened
 *                                    by tools/gen-basemap.py, compiled into the
 *                                    binary so the first paint needs no path)
 *   <root>/loot/map/layers/<name>.tsv     whatever a module decided was true
 *
 * The page does not interrogate a module's prose and does not re-derive a
 * module's maths. A module that learns a place writes a row; this page draws
 * the row. That is the whole contract, and it is why a layer file can be
 * opened, edited, diffed or deleted with a text editor.
 *
 * Projection is equirectangular on a 1e-4 degree grid: cheap, reversible, and
 * exact enough that the pixels are not the limit — the cells and the TA steps
 * are. There is no rescaling of y by cos(lat), because a circle drawn on this
 * canvas is a shape whose radius in degrees is honest; stretching it to look
 * like a Mercator circle on a sphere would be a lie the reader cannot check.
 *
 * The row schema, in full:
 *
 *   kind  label  lat  lon  radius_m  key  source  [ts] [azimuth] [beamwidth] [range_m]
 *
 * kind      point | ring | circle | track | area
 * radius_m  metres; 0 when the row's own module did not state a footprint
 * source    whatever the writing module called the evidence ("measured",
 *           "advertised", "ntn", "gnss"). Never re-derived here.
 * ts        ISO 8601 UTC ("2024-05-01T12:00:00Z") when the row has a time.
 *           A row without one is never hidden by the time window.
 * azimuth   degrees clockwise from true north, the direction a sector points
 * beamwidth degrees; with range_m this turns an `area` into a drawn wedge,
 *           because an area that states a bearing and a reach has a shape
 * range_m   metres of reach along that bearing
 *
 * A `track` row is one vertex: consecutive track rows in one file are joined
 * in file order, and a jump of more than TRACK_BREAK_DEG starts a new segment
 * (a dateline crossing and a gap between two logs look the same to a file, so
 * the line is broken rather than drawn straight across the planet).
 */
#include "map_page.h"

#include <cairo.h>
#include <glib/gstdio.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#define BM_PREFIX   "/com/imsisting/native/basemap/"
#define LAYERS_SUB  "loot/map/layers"
#define SNAPSHOT_SUB "loot/map/snapshots"
#define STATE_SUB   "state/ui.tsv"
#define EARTH_M_PER_DEG 111320.0
#define EARTH_RADIUS_M  6371008.8

/* Ink. Kept here rather than in style.css because these are canvas colours,
   not widget colours: a theme override that recoloured the globe would make
   the overlays unreadable without changing anything the reader can see. */
#define COL_OCEAN   0.039, 0.055, 0.075, 1.0
#define COL_LAND    0.094, 0.137, 0.180, 1.0
#define COL_COAST   0.470, 0.610, 0.720, 0.55
#define COL_BORDER  0.470, 0.610, 0.720, 0.26
#define COL_GRID    1.000, 1.000, 1.000, 0.055
#define COL_PLACE   0.784, 0.831, 0.886
#define COL_TEXT    0.784, 0.831, 0.886, 0.92
#define COL_TEXT_DIM 0.784, 0.831, 0.886, 0.55
#define COL_RULER   0.98, 0.85, 0.45, 0.95
#define COL_CAPTION 0.039, 0.055, 0.075, 0.86

/* A straight line between two rows further apart than this is not a movement,
   it is two different observations. */
#define TRACK_BREAK_DEG 2.0
/* Points closer than this many pixels collapse into one mark with a count. */
/* How close to the bottom edge the pointer has to be before the layer sheet
   slides up, and how long it waits after leaving before it goes away. */
#define LEGEND_HOT_PX 36
#define LEGEND_HIDE_MS 220

#define CLUSTER_PX 9
/* Below this many points a layer is drawn one mark per row, because a count of
   three is noise next to three dots. */
#define CLUSTER_MIN_POINTS 60
/* Faded, not hidden: an old row still tells the reader where the subject was. */
#define AGE_FADE 0.13
/* Slider steps. 1000 positions is finer than any log's timestamp granularity. */
#define AGE_STEPS 1000

typedef enum { BM_POLYGON = 0, BM_LINE = 1, BM_POINT = 2 } BmKind;

typedef struct {
    BmKind   kind;
    double   min_lon, min_lat, max_lon, max_lat;
    guint    n_parts;
    guint    n_points;
    guint32 *index;          /* 2 * n_parts: offset, length into points */
    gint32  *points;         /* 2 * n_points: lon, lat in 1e-4 degrees */
    gboolean loaded;
} Basemap;

typedef struct {
    char  *name;
    double lat, lon;
} Place;

typedef enum { OV_POINT, OV_RING, OV_CIRCLE, OV_TRACK, OV_AREA } OvKind;

typedef struct {
    OvKind  kind;
    char   *label;
    char   *key;
    char   *source;
    char   *ts;              /* ISO 8601 as written, or NULL */
    double  lat, lon;
    double  radius_m;
    double  ts_epoch;        /* -1 when the row carries no readable time */
    double  azimuth;         /* -1 when the row names no bearing */
    double  beamwidth;       /* -1 when the row names no beam */
    double  range_m;         /* -1 when the row names no reach */
} OvRow;

typedef struct {
    char      *name;         /* file stem, the layer's identity */
    double     rgb[3];
    char      *source;       /* first non-empty `source` column seen */
    GPtrArray *rows;         /* OvRow* */
    guint      points, rings, circles, tracks, areas;
    gboolean   visible;
    guint      drawn;        /* rows the last paint actually put on the canvas */
} OvLayer;

typedef struct _MapView MapView;

/* The page cannot open a module page itself — it is its own translation unit
   and has no notebook. A reader who clicks "Open in module" means the module
   that wrote the row, so the page emits that module's id and whoever owns the
   notebook decides what that means. */
typedef void (*MapModuleOpener)(const char *module_id, gpointer user_data);

struct _MapView {
    /* data */
    Basemap    land, coast, countries;
    GPtrArray *places;       /* Place* */
    GPtrArray *layers;       /* OvLayer* */
    char      *layers_dir;
    char      *root_dir;
    char      *snapshot_dir;
    char      *state_path;
    char      *version;

    /* view */
    double     centre_lon, centre_lat;
    double     px_per_deg;
    gboolean   placed;

    /* widgets */
    GtkWidget *canvas;
    GtkWidget *readout;
    GtkWidget *legend;
    GtkWidget *legend_panel;   /* the legend, its hint line and the sheet it sits on */
    GtkWidget *canvas_area;    /* the overlay the legend floats above */
    GtkWidget *hint;
    GtkWidget *preamble;
    GtkWidget *inspector;
    GtkWidget *inspector_text;
    GtkWidget *inspector_open;
    GtkWidget *age_scale;
    GtkWidget *layer_panel;
    GtkWidget *ruler_button;
    GtkWidget *follow_button;

    /* toggles */
    gboolean   show_land, show_coast, show_borders, show_places, show_grid,
               show_overlays;

    /* pointer */
    gboolean   has_cursor;
    double     cursor_x, cursor_y;
    OvRow     *hover;
    OvLayer   *hover_layer;
    OvRow     *selected;
    OvLayer   *selected_layer;

    /* drag */
    double     drag_last_x, drag_last_y;
    gboolean   dragging;

    /* ruler: two clicks, a great circle, and the numbers that go with it */
    gboolean   ruler_on;
    gboolean   ruler_done;
    double     ruler_ax, ruler_ay, ruler_bx, ruler_by;

    /* the time window. `age_cut` is an epoch; rows older than it are faded.
       `has_window` is FALSE when no row carried a time, in which case the
       slider is insensitive rather than silently doing nothing. */
    gboolean   has_window;
    gboolean   follow;
    double     ts_min, ts_max, age_cut;

    /* the legend is a sheet over the canvas, not a strip under it: it is
       hidden until the pointer reaches the bottom edge, so the map keeps the
       whole height it was given. `legend_hover` follows the pointer inside
       the sheet itself, which is what lets it stay open while being read. */
    gboolean   legend_hover;
    gboolean   canvas_hot;
    guint      legend_hide_id;

    /* live reload */
    GFileMonitor *monitor;
    guint      monitor_pending;

    /* module handoff */
    MapModuleOpener opener;
    gpointer   opener_data;

    guint      why_missing;  /* basemap layers that failed to load */
};

/* ------------------------------------------------------------------ */
/*  little-endian reads, so the format is the same on every machine    */
/* ------------------------------------------------------------------ */

static guint32
rd_u32(const guint8 *p)
{
    return (guint32) p[0] | ((guint32) p[1] << 8) |
           ((guint32) p[2] << 16) | ((guint32) p[3] << 24);
}

static gint32
rd_i32(const guint8 *p)
{
    return (gint32) rd_u32(p);
}

/* ------------------------------------------------------------------ */
/*  geometry that more than one caller needs                           */
/* ------------------------------------------------------------------ */

/* Haversine, in metres, on the mean sphere. The canvas is equirectangular and
   says so; this is the one place a great-circle distance is claimed, and it is
   claimed only for the ruler and for track lengths, never for a drawn shape. */
static double
gc_distance_m(double lat1, double lon1, double lat2, double lon2)
{
    double p1 = lat1 * G_PI / 180.0, p2 = lat2 * G_PI / 180.0;
    double dp = (lat2 - lat1) * G_PI / 180.0;
    double dl = (lon2 - lon1) * G_PI / 180.0;
    double a = sin(dp / 2) * sin(dp / 2) + cos(p1) * cos(p2) * sin(dl / 2) * sin(dl / 2);

    if (a < 0.0) a = 0.0;
    if (a > 1.0) a = 1.0;
    return 2.0 * EARTH_RADIUS_M * atan2(sqrt(a), sqrt(1.0 - a));
}

/* Initial bearing: the direction to steer at the start, not the average
   direction of the path. */
static double
gc_bearing_deg(double lat1, double lon1, double lat2, double lon2)
{
    double p1 = lat1 * G_PI / 180.0, p2 = lat2 * G_PI / 180.0;
    double dl = (lon2 - lon1) * G_PI / 180.0;
    double y = sin(dl) * cos(p2);
    double x = cos(p1) * sin(p2) - sin(p1) * cos(p2) * cos(dl);
    double b = atan2(y, x) * 180.0 / G_PI;

    return b < 0.0 ? b + 360.0 : b;
}

/* A point a fraction of the way along the great circle from A to B, by
   spherical linear interpolation of the two unit vectors. */
static void
gc_interp(double lat1, double lon1, double lat2, double lon2, double t,
          double *lat_out, double *lon_out)
{
    double p1 = lat1 * G_PI / 180.0, l1 = lon1 * G_PI / 180.0;
    double p2 = lat2 * G_PI / 180.0, l2 = lon2 * G_PI / 180.0;
    double a[3], b[3], c[3], omega, s1, s2, r;

    a[0] = cos(p1) * cos(l1); a[1] = cos(p1) * sin(l1); a[2] = sin(p1);
    b[0] = cos(p2) * cos(l2); b[1] = cos(p2) * sin(l2); b[2] = sin(p2);

    r = a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
    if (r > 1.0) r = 1.0;
    if (r < -1.0) r = -1.0;
    omega = acos(r);

    if (omega < 1e-9) {
        *lat_out = lat1; *lon_out = lon1;
        return;
    }

    s1 = sin((1.0 - t) * omega) / sin(omega);
    s2 = sin(t * omega) / sin(omega);
    for (int i = 0; i < 3; i++) c[i] = s1 * a[i] + s2 * b[i];

    *lat_out = atan2(c[2], sqrt(c[0] * c[0] + c[1] * c[1])) * 180.0 / G_PI;
    *lon_out = atan2(c[1], c[0]) * 180.0 / G_PI;
}

/* ISO 8601 to a Unix epoch, through GLib so no _GNU_SOURCE is needed.
   Returns -1 for anything that is not a time, which is the same answer as
   "this row has no time" and is treated the same way: never faded. */
static double
ts_parse(const char *s)
{
    int y = 0, mo = 0, d = 0, h = 0, mi = 0;
    double sec = 0.0;
    GDateTime *dt;
    gint64 out;

    if (s == NULL || *s == '\0') return -1.0;
    if (sscanf(s, "%4d-%2d-%2dT%2d:%2d:%lf", &y, &mo, &d, &h, &mi, &sec) != 6)
        return -1.0;
    if (mo < 1 || mo > 12 || d < 1 || d > 31 || h < 0 || h > 23 ||
        mi < 0 || mi > 59 || sec < 0.0 || sec >= 61.0)
        return -1.0;

    dt = g_date_time_new_utc(y, mo, d, h, mi, (double) sec);
    if (dt == NULL) return -1.0;
    out = g_date_time_to_unix(dt);
    g_date_time_unref(dt);
    return (double) out;
}

/* Where a row sits in the window. Undated rows are always in it. */
static gboolean
row_in_window(const MapView *v, const OvRow *row)
{
    if (!v->has_window) return TRUE;
    if (row->ts_epoch < 0.0) return TRUE;
    return row->ts_epoch >= v->age_cut;
}

/* ------------------------------------------------------------------ */
/*  basemap                                                            */
/* ------------------------------------------------------------------ */

static void
basemap_clear(Basemap *bm)
{
    g_clear_pointer(&bm->index, g_free);
    g_clear_pointer(&bm->points, g_free);
    memset(bm, 0, sizeof *bm);
}

/* "NEBM" v1, then kind, then the bounds as i32 in 1e-4 degrees, then the
   counts, then the index, then the points. Everything is checked before it is
   trusted: a truncated resource must fail loudly into `why` rather than paint
   half a planet. */
static gboolean
basemap_load(const char *name, Basemap *out, char **why)
{
    g_autofree char *path = g_strdup_printf(BM_PREFIX "%s.bin", name);
    GError *error = NULL;
    gsize size = 0;
    const guint8 *data;

    g_autoptr(GBytes) bytes = g_resources_lookup_data(path, G_RESOURCE_LOOKUP_FLAGS_NONE, &error);
    if (bytes == NULL) {
        if (why != NULL)
            *why = g_strdup_printf("%s: %s", path, error != NULL ? error->message : "not found");
        g_clear_error(&error);
        return FALSE;
    }

    data = g_bytes_get_data(bytes, &size);
    if (size < 31 || memcmp(data, "NEBM", 4) != 0 || data[4] != 1) {
        if (why != NULL) *why = g_strdup_printf("%s: not a NEBM v1 file", path);
        return FALSE;
    }

    memset(out, 0, sizeof *out);
    out->kind     = (BmKind) data[5];
    out->min_lon  = rd_i32(data + 7)  / 1e4;
    out->min_lat  = rd_i32(data + 11) / 1e4;
    out->max_lon  = rd_i32(data + 15) / 1e4;
    out->max_lat  = rd_i32(data + 19) / 1e4;
    out->n_parts  = rd_u32(data + 23);
    out->n_points = rd_u32(data + 27);

    {
        gsize want = 31 + (gsize) out->n_parts * 8 + (gsize) out->n_points * 8;
        if (out->n_parts == 0 || out->n_points == 0 || want != size) {
            if (why != NULL)
                *why = g_strdup_printf("%s: %u parts and %u points need %" G_GSIZE_FORMAT
                                       " bytes, file is %" G_GSIZE_FORMAT,
                                       path, out->n_parts, out->n_points, want, size);
            return FALSE;
        }
    }

    out->index  = g_new(guint32, (gsize) out->n_parts * 2);
    out->points = g_new(gint32, (gsize) out->n_points * 2);
    for (guint i = 0; i < out->n_parts * 2; i++)
        out->index[i] = rd_u32(data + 31 + (gsize) i * 4);
    {
        const guint8 *base = data + 31 + (gsize) out->n_parts * 8;
        for (guint i = 0; i < out->n_points * 2; i++)
            out->points[i] = rd_i32(base + (gsize) i * 4);
    }

    /* A part whose span runs off the point array would read past the end while
       painting. One pass now means no bounds check in the draw loop. */
    for (guint i = 0; i < out->n_parts; i++) {
        guint32 off = out->index[i * 2], len = out->index[i * 2 + 1];
        if (len == 0 || off + len > out->n_points) {
            if (why != NULL)
                *why = g_strdup_printf("%s: part %u spans %u..%u of %u points",
                                       path, i, off, off + len, out->n_points);
            basemap_clear(out);
            return FALSE;
        }
    }

    out->loaded = TRUE;
    return TRUE;
}

static void
places_clear(GPtrArray **places)
{
    if (*places == NULL) return;
    for (guint i = 0; i < (*places)->len; i++) {
        Place *p = g_ptr_array_index(*places, i);
        g_free(p->name);
        g_free(p);
    }
    g_ptr_array_unref(*places);
    *places = NULL;
}

static GPtrArray *
places_load(void)
{
    GPtrArray *out = g_ptr_array_new();
    GError *error = NULL;
    gsize size = 0;

    g_autoptr(GBytes) bytes = g_resources_lookup_data(BM_PREFIX "places.tsv",
                                                      G_RESOURCE_LOOKUP_FLAGS_NONE, &error);
    if (bytes == NULL) {
        g_clear_error(&error);
        return out;
    }

    const char *data = g_bytes_get_data(bytes, &size);
    g_auto(GStrv) lines = g_strsplit(data, "\n", -1);
    for (guint i = 1; lines[i] != NULL; i++) {
        if (*lines[i] == '\0') continue;
        g_auto(GStrv) f = g_strsplit(lines[i], "\t", 7);
        if (g_strv_length(f) < 3) continue;
        Place *p = g_new0(Place, 1);
        p->name = g_strdup(f[0]);
        p->lat  = g_ascii_strtod(f[1], NULL);
        p->lon  = g_ascii_strtod(f[2], NULL);
        g_ptr_array_add(out, p);
    }
    return out;
}

/* ------------------------------------------------------------------ */
/*  the layer inbox                                                    */
/* ------------------------------------------------------------------ */

static const double g_layer_rgb[][3] = {
    { 0.87, 0.31, 0.36 },
    { 0.33, 0.66, 0.88 },
    { 0.96, 0.68, 0.26 },
    { 0.55, 0.80, 0.40 },
    { 0.72, 0.46, 0.86 },
    { 0.92, 0.86, 0.36 },
    { 0.36, 0.84, 0.78 },
};

static void
ov_row_free(gpointer data)
{
    OvRow *row = data;
    if (row == NULL) return;
    g_free(row->label);
    g_free(row->key);
    g_free(row->source);
    g_free(row->ts);
    g_free(row);
}

static void
ov_layer_free(gpointer data)
{
    OvLayer *layer = data;
    if (layer == NULL) return;
    g_free(layer->name);
    g_free(layer->source);
    g_ptr_array_unref(layer->rows);
    g_free(layer);
}

static OvKind
ov_kind_parse(const char *s, gboolean *ok)
{
    if (ok != NULL) *ok = TRUE;
    if (g_strcmp0(s, "point") == 0)  return OV_POINT;
    if (g_strcmp0(s, "ring") == 0)   return OV_RING;
    if (g_strcmp0(s, "circle") == 0) return OV_CIRCLE;
    if (g_strcmp0(s, "track") == 0)  return OV_TRACK;
    if (g_strcmp0(s, "area") == 0)   return OV_AREA;
    if (ok != NULL) *ok = FALSE;
    return OV_POINT;
}

/* An optional numeric column: absent and unparseable are the same answer, and
   that answer is -1 ("this row does not state it") rather than 0 ("this row
   states nothing"), because 0 metres of beam is a different claim. */
static double
opt_num(const char *s)
{
    char *end = NULL;
    double v;

    if (s == NULL || *s == '\0') return -1.0;
    v = g_ascii_strtod(s, &end);
    if (end == s) return -1.0;
    return v;
}

/* One file is one layer. The header line is documentation, not a contract to
   be negotiated: `kind label lat lon radius_m key source [ts az bw range_m]`.
   A row that does not parse is skipped and counted, because a half-written
   file (a module killed mid-write) must not stop the other layers from
   drawing. */
static OvLayer *
ov_layer_load(const char *path, guint index)
{
    g_autofree char *contents = NULL;
    gsize length = 0;

    if (!g_file_get_contents(path, &contents, &length, NULL) || length == 0)
        return NULL;

    OvLayer *layer = g_new0(OvLayer, 1);
    layer->name = g_path_get_basename(path);
    {
        char *dot = strrchr(layer->name, '.');
        if (dot != NULL) *dot = '\0';
    }
    memcpy(layer->rgb, g_layer_rgb[index % G_N_ELEMENTS(g_layer_rgb)], sizeof layer->rgb);
    layer->rows = g_ptr_array_new_with_free_func(ov_row_free);
    layer->visible = TRUE;

    g_auto(GStrv) lines = g_strsplit(contents, "\n", -1);
    guint skipped = 0;
    for (guint i = 0; lines[i] != NULL; i++) {
        const char *line = lines[i];
        if (*line == '\0' || *line == '#') continue;
        g_auto(GStrv) f = g_strsplit(line, "\t", 12);
        /* The optional columns are read only when the split went that far:
           an array of eight fields has no ninth element, and reading one
           anyway is a crash on the first short file, not a wrong number. */
        const guint nf = g_strv_length(f);
        if (nf < 5) { skipped++; continue; }
        if (g_strcmp0(f[0], "kind") == 0) continue;   /* header */

        gboolean ok = FALSE;
        OvKind kind = ov_kind_parse(f[0], &ok);
        if (!ok) { skipped++; continue; }

        char *end_lat = NULL, *end_lon = NULL, *end_r = NULL;
        OvRow *row = g_new0(OvRow, 1);
        row->kind  = kind;
        row->label = g_strdup(f[1]);
        row->lat   = g_ascii_strtod(f[2], &end_lat);
        row->lon   = g_ascii_strtod(f[3], &end_lon);
        row->radius_m = (nf > 4 && *f[4] != '\0') ? g_ascii_strtod(f[4], &end_r) : 0.0;
        row->key    = (nf > 5) ? g_strdup(f[5]) : NULL;
        row->source = (nf > 6 && *f[6] != '\0') ? g_strdup(f[6]) : NULL;
        row->ts     = (nf > 7 && *f[7] != '\0') ? g_strdup(f[7]) : NULL;
        row->ts_epoch = ts_parse(row->ts);
        row->azimuth   = (nf > 8) ? opt_num(f[8]) : -1.0;
        row->beamwidth = (nf > 9) ? opt_num(f[9]) : -1.0;
        row->range_m   = (nf > 10) ? opt_num(f[10]) : -1.0;

        if (*row->label == '\0' || end_lat == f[2] || end_lon == f[3] ||
            row->lat < -90.0 || row->lat > 90.0 ||
            row->lon < -180.0 || row->lon > 180.0) {
            ov_row_free(row);
            skipped++;
            continue;
        }
        if (row->radius_m < 0.0) row->radius_m = -row->radius_m;

        if (row->source != NULL && layer->source == NULL)
            layer->source = g_strdup(row->source);

        switch (row->kind) {
        case OV_POINT:  layer->points++;  break;
        case OV_RING:   layer->rings++;   break;
        case OV_CIRCLE: layer->circles++; break;
        case OV_TRACK:  layer->tracks++;  break;
        case OV_AREA:   layer->areas++;   break;
        }
        g_ptr_array_add(layer->rows, row);
    }

    if (layer->rows->len == 0 && skipped == 0) {
        ov_layer_free(layer);
        return NULL;
    }
    return layer;
}

static gint
cmp_filename(gconstpointer a, gconstpointer b)
{
    return g_strcmp0(*(const char *const *) a, *(const char *const *) b);
}

static void
layers_clear(GPtrArray **layers)
{
    if (*layers == NULL) return;
    g_ptr_array_unref(*layers);
    *layers = NULL;
}

static GPtrArray *
layers_load(const char *dir, guint *rows_out)
{
    GPtrArray *out = g_ptr_array_new_with_free_func(ov_layer_free);
    GError *error = NULL;
    GDir *d = g_dir_open(dir, 0, &error);
    guint rows = 0;

    if (rows_out != NULL) *rows_out = 0;
    if (d == NULL) {
        g_clear_error(&error);
        return out;
    }

    /* g_dir_read_name is the only listing there is: collect first, sort after,
       so the layer colours do not depend on the filesystem's order. */
    g_autoptr(GPtrArray) files = g_ptr_array_new_with_free_func(g_free);
    const char *name;

    while ((name = g_dir_read_name(d)) != NULL) {
        if (!g_str_has_suffix(name, ".tsv")) continue;
        g_ptr_array_add(files, g_build_filename(dir, name, NULL));
    }
    g_dir_close(d);

    g_ptr_array_sort(files, cmp_filename);
    for (guint i = 0; i < files->len; i++) {
        OvLayer *layer = ov_layer_load(g_ptr_array_index(files, i), out->len);
        if (layer == NULL) continue;
        rows += layer->rows->len;
        g_ptr_array_add(out, layer);
    }

    if (rows_out != NULL) *rows_out = rows;
    return out;
}

/* A layer switch survives a reload: the reader turned a layer off because it
   was in the way, and a file that changed underneath must not turn it back on. */
static gboolean
layer_was_visible(GPtrArray *layers, const char *name)
{
    if (layers == NULL) return TRUE;
    for (guint i = 0; i < layers->len; i++) {
        OvLayer *layer = g_ptr_array_index(layers, i);
        if (g_strcmp0(layer->name, name) == 0) return layer->visible;
    }
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  projection                                                         */
/* ------------------------------------------------------------------ */

static void
project(const MapView *v, double lon, double lat, int w, int h, double *x, double *y)
{
    *x = (lon - v->centre_lon) * v->px_per_deg + w / 2.0;
    *y = (v->centre_lat - lat) * v->px_per_deg + h / 2.0;
}

static void
unproject(const MapView *v, double x, double y, int w, int h, double *lon, double *lat)
{
    *lon = v->centre_lon + (x - w / 2.0) / v->px_per_deg;
    *lat = v->centre_lat - (y - h / 2.0) / v->px_per_deg;
}

/* Keep the view on the planet: latitude cannot leave the poles, longitude
   wraps so that panning east forever returns from the west, and the scale has
   a floor (a little wider than the world) and a ceiling (~2 m per pixel). */
static void
view_clamp(MapView *v, int w, int h)
{
    double min_ppd = (w > 0 ? w : 800) / 420.0;

    if (v->px_per_deg < min_ppd) v->px_per_deg = min_ppd;
    if (v->px_per_deg > 40000.0) v->px_per_deg = 40000.0;

    if (v->centre_lat > 89.0) v->centre_lat = 89.0;
    if (v->centre_lat < -89.0) v->centre_lat = -89.0;

    while (v->centre_lon > 180.0)  v->centre_lon -= 360.0;
    while (v->centre_lon < -180.0) v->centre_lon += 360.0;
    (void) h;
}

static void
view_fit_world(MapView *v, int w, int h)
{
    double span = (w > 0 && h > 0) ? MIN(360.0, 360.0 * (double) h / (double) w) : 180.0;

    v->centre_lon = 0.0;
    v->centre_lat = 0.0;
    v->px_per_deg = (w > 0 ? (double) w / span : 4.0);
    v->placed = TRUE;
    view_clamp(v, w, h);
}

/* Fit the layer rows, with a margin, so a handoff from a module lands on the
   thing the module found instead of on the whole planet. Only visible layers
   count: framing a layer the reader switched off would move the view to a
   place with nothing on it. */
static void
view_fit_layers(MapView *v, int w, int h)
{
    double min_lat = 90, max_lat = -90, min_lon = 180, max_lon = -180;
    guint n = 0;

    for (guint i = 0; i < v->layers->len; i++) {
        OvLayer *layer = g_ptr_array_index(v->layers, i);
        if (!layer->visible) continue;
        for (guint j = 0; j < layer->rows->len; j++) {
            OvRow *row = g_ptr_array_index(layer->rows, j);
            double pad = (MAX(row->radius_m, row->range_m) / EARTH_M_PER_DEG) * 1.15;

            if (pad < 0.0) pad = 0.0;
            min_lat = MIN(min_lat, row->lat - pad);
            max_lat = MAX(max_lat, row->lat + pad);
            min_lon = MIN(min_lon, row->lon - pad);
            max_lon = MAX(max_lon, row->lon + pad);
            n++;
        }
    }

    if (n == 0) return;

    {
        double span_lat = MAX(max_lat - min_lat, 0.05) * 1.6;
        double span_lon = MAX(max_lon - min_lon, 0.05) * 1.6;
        double fit_x = (w > 0) ? (double) w / span_lon : 4.0;
        double fit_y = (h > 0) ? (double) h / span_lat : 4.0;

        v->centre_lat = (min_lat + max_lat) / 2.0;
        v->centre_lon = (min_lon + max_lon) / 2.0;
        v->px_per_deg = MIN(fit_x, fit_y);
        v->placed = TRUE;
        view_clamp(v, w, h);
    }
}

/* One layer, framed on its own rows. */
static void
view_fit_one(MapView *v, OvLayer *layer, int w, int h)
{
    double min_lat = 90, max_lat = -90, min_lon = 180, max_lon = -180;
    guint n = 0;

    if (layer == NULL) return;

    for (guint j = 0; j < layer->rows->len; j++) {
        OvRow *row = g_ptr_array_index(layer->rows, j);
        double pad = (MAX(row->radius_m, row->range_m) / EARTH_M_PER_DEG) * 1.15;

        if (pad < 0.0) pad = 0.0;
        min_lat = MIN(min_lat, row->lat - pad);
        max_lat = MAX(max_lat, row->lat + pad);
        min_lon = MIN(min_lon, row->lon - pad);
        max_lon = MAX(max_lon, row->lon + pad);
        n++;
    }
    if (n == 0) return;

    {
        double span_lat = MAX(max_lat - min_lat, 0.05) * 1.6;
        double span_lon = MAX(max_lon - min_lon, 0.05) * 1.6;

        v->centre_lat = (min_lat + max_lat) / 2.0;
        v->centre_lon = (min_lon + max_lon) / 2.0;
        v->px_per_deg = MIN((w > 0) ? (double) w / span_lon : 4.0,
                            (h > 0) ? (double) h / span_lat : 4.0);
        v->placed = TRUE;
        view_clamp(v, w, h);
    }
}

/* ------------------------------------------------------------------ */
/*  painting                                                           */
/* ------------------------------------------------------------------ */

static void
bm_path(cairo_t *cr, const MapView *v, const Basemap *bm, int w, int h)
{
    for (guint i = 0; i < bm->n_parts; i++) {
        guint32 off = bm->index[i * 2], len = bm->index[i * 2 + 1];

        for (guint32 k = 0; k < len; k++) {
            const gint32 *p = &bm->points[(off + k) * 2];
            double x, y;
            project(v, p[0] / 1e4, p[1] / 1e4, w, h, &x, &y);
            if (k == 0) cairo_move_to(cr, x, y);
            else        cairo_line_to(cr, x, y);
        }
        if (bm->kind == BM_POLYGON) cairo_close_path(cr);
    }
}

static void
draw_graticule(cairo_t *cr, const MapView *v, int w, int h)
{
    double step = 30.0;
    double left, right, top, bottom;

    if (v->px_per_deg > 120.0)      step = 0.25;
    else if (v->px_per_deg > 45.0)  step = 1.0;
    else if (v->px_per_deg > 18.0)  step = 5.0;
    else if (v->px_per_deg > 6.0)   step = 10.0;

    unproject(v, 0, 0, w, h, &left, &top);
    unproject(v, w, h, w, h, &right, &bottom);

    cairo_set_line_width(cr, 1.0);
    cairo_set_source_rgba(cr, COL_GRID);

    for (double lon = floor(left / step) * step; lon <= right; lon += step) {
        double x, y;
        project(v, lon, 0, w, h, &x, &y);
        cairo_move_to(cr, x, 0);
        cairo_line_to(cr, x, h);
    }
    for (double lat = floor(bottom / step) * step; lat <= top; lat += step) {
        double x, y;
        project(v, 0, lat, w, h, &x, &y);
        cairo_move_to(cr, 0, y);
        cairo_line_to(cr, w, y);
    }
    cairo_stroke(cr);
}

static void
draw_scale_bar(cairo_t *cr, const MapView *v, int w, int h)
{
    double m_per_px = EARTH_M_PER_DEG * cos(v->centre_lat * G_PI / 180.0) / v->px_per_deg;
    double target_px = 110.0;
    double raw = m_per_px * target_px;
    double mag = pow(10.0, floor(log10(MAX(raw, 1.0))));
    double nice = mag;
    g_autofree char *text = NULL;

    for (int k = 9; k >= 1; k--) {
        double cand = mag * k;
        if (cand <= raw * 1.2) { nice = cand; break; }
    }

    {
        double px = nice / m_per_px;
        double x = 16.0, y = h - 22.0;

        if (px > w * 0.5) return;

        cairo_set_line_width(cr, 1.6);
        cairo_set_source_rgba(cr, COL_TEXT);
        cairo_move_to(cr, x, y);
        cairo_line_to(cr, x + px, y);
        cairo_move_to(cr, x, y - 4);
        cairo_line_to(cr, x, y + 4);
        cairo_move_to(cr, x + px, y - 4);
        cairo_line_to(cr, x + px, y + 4);
        cairo_stroke(cr);

        text = (nice >= 1000.0)
             ? g_strdup_printf("%.0f km", nice / 1000.0)
             : g_strdup_printf("%.0f m", nice);
        cairo_set_font_size(cr, 10.0);
        cairo_set_source_rgba(cr, COL_TEXT);
        cairo_move_to(cr, x, y - 8);
        cairo_show_text(cr, text);
    }
}

static void
draw_places(cairo_t *cr, const MapView *v, int w, int h, gboolean labels)
{
    cairo_set_source_rgba(cr, COL_PLACE, 0.85);
    cairo_set_font_size(cr, 10.0);

    for (guint i = 0; i < v->places->len; i++) {
        Place *p = g_ptr_array_index(v->places, i);
        double x, y;

        project(v, p->lon, p->lat, w, h, &x, &y);
        if (x < -40 || x > w + 40 || y < -20 || y > h + 20) continue;

        cairo_arc(cr, x, y, 1.8, 0, 2 * G_PI);
        cairo_fill(cr);

        if (labels) {
            cairo_set_source_rgba(cr, COL_TEXT_DIM);
            cairo_move_to(cr, x + 4, y + 3);
            cairo_show_text(cr, p->name);
            cairo_set_source_rgba(cr, COL_PLACE, 0.85);
        }
    }
}

/* Rings and discs: the shapes that mean "somewhere inside this". */
static void
draw_radii(cairo_t *cr, const MapView *v, OvLayer *layer, int w, int h, double alpha_scale)
{
    double r = layer->rgb[0], g = layer->rgb[1], b = layer->rgb[2];

    for (guint j = 0; j < layer->rows->len; j++) {
        OvRow *row = g_ptr_array_index(layer->rows, j);
        double x, y, alpha;

        if (row->kind != OV_RING && row->kind != OV_CIRCLE) continue;

        alpha = row_in_window(v, row) ? 1.0 : AGE_FADE;
        project(v, row->lon, row->lat, w, h, &x, &y);
        {
            double r_px = (row->radius_m / EARTH_M_PER_DEG) * v->px_per_deg;
            /* A 1 km ring at world scale is a fifth of a pixel. Rounding it
               to 4 keeps the mark honest about where it is and lets the
               legend carry the size the screen cannot. */
            if (r_px < 4.0) r_px = 4.0;
            if (r_px > 100000.0) r_px = 100000.0;

            if (row->kind == OV_CIRCLE) {
                cairo_set_source_rgba(cr, r, g, b, 0.16 * alpha_scale * alpha);
                cairo_arc(cr, x, y, r_px, 0, 2 * G_PI);
                cairo_fill(cr);
            }
            cairo_set_source_rgba(cr, r, g, b, 0.75 * alpha_scale * alpha);
            cairo_set_line_width(cr, row->kind == OV_RING ? 2.0 : 1.4);
            if (row->kind == OV_RING) {
                const double dash[] = { 5.0, 4.0 };
                cairo_set_dash(cr, dash, 2, 0);
            }
            cairo_arc(cr, x, y, r_px, 0, 2 * G_PI);
            cairo_stroke(cr);
            cairo_set_dash(cr, NULL, 0, 0);
        }
    }
}

/* A sector is an area with a bearing and a reach. Without both it is a
   statement about a region with no centre, and it is counted, not drawn. */
static void
draw_wedges(cairo_t *cr, const MapView *v, OvLayer *layer, int w, int h, double alpha_scale)
{
    double r = layer->rgb[0], g = layer->rgb[1], b = layer->rgb[2];

    for (guint j = 0; j < layer->rows->len; j++) {
        OvRow *row = g_ptr_array_index(layer->rows, j);
        double x, y, reach, half, start, end, alpha;

        if (row->kind != OV_AREA) continue;
        if (row->azimuth < 0.0 || row->beamwidth <= 0.0 || row->range_m <= 0.0)
            continue;

        alpha = row_in_window(v, row) ? 1.0 : AGE_FADE;
        reach = (row->range_m / EARTH_M_PER_DEG) * v->px_per_deg;
        if (reach < 6.0) reach = 6.0;
        half = row->beamwidth / 2.0;

        /* Screen space has north up and 0 rad pointing east, so a bearing is
           90 degrees ahead of it. */
        start = (row->azimuth - half - 90.0) * G_PI / 180.0;
        end   = (row->azimuth + half - 90.0) * G_PI / 180.0;

        project(v, row->lon, row->lat, w, h, &x, &y);
        cairo_set_source_rgba(cr, r, g, b, 0.13 * alpha_scale * alpha);
        cairo_move_to(cr, x, y);
        cairo_arc(cr, x, y, reach, start, end);
        cairo_close_path(cr);
        cairo_fill(cr);
        cairo_set_source_rgba(cr, r, g, b, 0.62 * alpha_scale * alpha);
        cairo_set_line_width(cr, 1.2);
        cairo_move_to(cr, x, y);
        cairo_arc(cr, x, y, reach, start, end);
        cairo_close_path(cr);
        cairo_stroke(cr);
    }
}

/* Tracks: consecutive `track` rows in file order, joined. A jump wider than
   TRACK_BREAK_DEG breaks the line, because between two observations that far
   apart the file says nothing about where the subject went. */
static void
draw_tracks(cairo_t *cr, const MapView *v, OvLayer *layer, int w, int h, double alpha_scale)
{
    double r = layer->rgb[0], g = layer->rgb[1], b = layer->rgb[2];
    gboolean have_prev = FALSE;
    double prev_lat = 0.0, prev_lon = 0.0, prev_epoch = -1.0;

    cairo_set_line_width(cr, 1.8);

    for (guint j = 0; j < layer->rows->len; j++) {
        OvRow *row = g_ptr_array_index(layer->rows, j);
        double x, y, alpha;

        if (row->kind != OV_TRACK) continue;

        alpha = row_in_window(v, row) ? 0.9 : AGE_FADE;
        project(v, row->lon, row->lat, w, h, &x, &y);

        if (have_prev) {
            double d = gc_distance_m(prev_lat, prev_lon, row->lat, row->lon) / 1000.0;
            double gap_deg = hypot(row->lat - prev_lat, row->lon - prev_lon);

            (void) prev_epoch;
            if (gap_deg <= TRACK_BREAK_DEG && d >= 0.0) {
                double px, py;
                project(v, prev_lon, prev_lat, w, h, &px, &py);
                cairo_set_source_rgba(cr, r, g, b, 0.55 * alpha_scale * alpha);
                cairo_move_to(cr, px, py);
                cairo_line_to(cr, x, y);
                cairo_stroke(cr);
            }
        }

        cairo_set_source_rgba(cr, r, g, b, alpha);
        cairo_arc(cr, x, y, 1.9, 0, 2 * G_PI);
        cairo_fill(cr);

        have_prev = TRUE;
        prev_lat = row->lat;
        prev_lon = row->lon;
        prev_epoch = row->ts_epoch;
    }
}

/* Points, clustered when the layer has enough of them for the count to be
   more informative than the pixels. The mark sits at the mean of the members,
   not at a grid corner. */
typedef struct { double x, y; guint n; } Cluster;

static void
draw_points(cairo_t *cr, const MapView *v, OvLayer *layer, int w, int h,
            gboolean labels, double alpha_scale)
{
    double r = layer->rgb[0], g = layer->rgb[1], b = layer->rgb[2];
    gboolean cluster = layer->points >= CLUSTER_MIN_POINTS && v->px_per_deg < 30.0;
    GHashTable *buckets = NULL;

    if (cluster)
        buckets = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

    for (guint j = 0; j < layer->rows->len; j++) {
        OvRow *row = g_ptr_array_index(layer->rows, j);
        double x, y, alpha;

        if (row->kind != OV_POINT) continue;
        alpha = row_in_window(v, row) ? 1.0 : AGE_FADE;
        project(v, row->lon, row->lat, w, h, &x, &y);
        if (x < -10 || x > w + 10 || y < -10 || y > h + 10) continue;

        layer->drawn++;

        if (buckets != NULL) {
            g_autofree char *key = g_strdup_printf("%d:%d",
                (int) floor(x / CLUSTER_PX), (int) floor(y / CLUSTER_PX));
            Cluster *slot = g_hash_table_lookup(buckets, key);

            if (slot == NULL) {
                slot = g_new0(Cluster, 1);
                slot->x = x;
                slot->y = y;
                slot->n = 1;
                g_hash_table_insert(buckets, g_strdup(key), slot);
            } else {
                slot->n++;
                slot->x += (x - slot->x) / (double) slot->n;
                slot->y += (y - slot->y) / (double) slot->n;
            }
            continue;
        }

        cairo_set_source_rgba(cr, r, g, b, 0.22 * alpha_scale * alpha);
        cairo_arc(cr, x, y, 7.0, 0, 2 * G_PI);
        cairo_fill(cr);
        cairo_set_source_rgba(cr, r, g, b, alpha_scale * alpha);
        cairo_arc(cr, x, y, 3.2, 0, 2 * G_PI);
        cairo_fill(cr);
        cairo_set_source_rgba(cr, 0.04, 0.06, 0.08, 0.9 * alpha_scale * alpha);
        cairo_set_line_width(cr, 1.0);
        cairo_arc(cr, x, y, 3.2, 0, 2 * G_PI);
        cairo_stroke(cr);

        if (labels && row->label != NULL) {
            cairo_set_source_rgba(cr, r, g, b, 0.95 * alpha_scale * alpha);
            cairo_set_font_size(cr, 10.0);
            cairo_move_to(cr, x + 7, y + 3.5);
            cairo_show_text(cr, row->label);
        }
    }

    /* the clusters, drawn once each */
    if (buckets != NULL) {
        GHashTableIter it;
        gpointer key, value;

        g_hash_table_iter_init(&it, buckets);
        while (g_hash_table_iter_next(&it, &key, &value)) {
            Cluster *c = value;
            double rad = 5.0 + log2((double) c->n) * 1.8;
            g_autofree char *count = g_strdup_printf("%u", c->n);

            cairo_set_source_rgba(cr, r, g, b, 0.20 * alpha_scale);
            cairo_arc(cr, c->x, c->y, rad + 3.0, 0, 2 * G_PI);
            cairo_fill(cr);
            cairo_set_source_rgba(cr, r, g, b, 0.85 * alpha_scale);
            cairo_arc(cr, c->x, c->y, rad, 0, 2 * G_PI);
            cairo_fill(cr);
            cairo_set_source_rgba(cr, 0.04, 0.06, 0.08, 0.92 * alpha_scale);
            cairo_set_font_size(cr, 9.5);
            {
                cairo_text_extents_t ext;
                cairo_text_extents(cr, count, &ext);
                cairo_move_to(cr, c->x - ext.width / 2.0, c->y + ext.height / 2.0 - 1.0);
                cairo_show_text(cr, count);
            }
        }
        g_hash_table_destroy(buckets);
    }
}

static void
draw_overlays(cairo_t *cr, const MapView *v, int w, int h, gboolean labels,
              double alpha_scale)
{
    for (guint i = 0; i < v->layers->len; i++) {
        OvLayer *layer = g_ptr_array_index(v->layers, i);

        if (!layer->visible) continue;
        layer->drawn = 0;

        /* uncertainty first, so a pin is never buried under a disc */
        draw_radii(cr, v, layer, w, h, alpha_scale);
        draw_wedges(cr, v, layer, w, h, alpha_scale);
        draw_tracks(cr, v, layer, w, h, alpha_scale);
        draw_points(cr, v, layer, w, h, labels, alpha_scale);
    }
}

/* Whatever is within reach of the pointer gets named. This is the whole
   "read it off the map" gesture: no popup, no selection model, just the row
   whose pixel is nearest and close enough to be the one meant. */
static void
find_hover(MapView *v, int w, int h)
{
    double best = 14.0;

    v->hover = NULL;
    v->hover_layer = NULL;
    if (!v->has_cursor) return;

    for (guint i = 0; i < v->layers->len; i++) {
        OvLayer *layer = g_ptr_array_index(v->layers, i);
        if (!layer->visible) continue;
        for (guint j = 0; j < layer->rows->len; j++) {
            OvRow *row = g_ptr_array_index(layer->rows, j);
            double x, y, d;

            /* An area without geometry has no point to be near; an area with
               a wedge is picked at its centre, which is what a reader aims at. */
            if (row->kind == OV_AREA && (row->azimuth < 0.0 || row->range_m <= 0.0))
                continue;
            project(v, row->lon, row->lat, w, h, &x, &y);
            d = hypot(x - v->cursor_x, y - v->cursor_y);
            if (d < best) {
                best = d;
                v->hover = row;
                v->hover_layer = layer;
            }
        }
    }
}

/* The row the pointer is nearest, with no distance cap: a click means the
   nearest thing, not the nearest thing within fourteen pixels. */
static void
find_selected(MapView *v, double x, double y, int w, int h)
{
    double best = 1e18;

    v->selected = NULL;
    v->selected_layer = NULL;

    for (guint i = 0; i < v->layers->len; i++) {
        OvLayer *layer = g_ptr_array_index(v->layers, i);
        if (!layer->visible) continue;
        for (guint j = 0; j < layer->rows->len; j++) {
            OvRow *row = g_ptr_array_index(layer->rows, j);
            double rx, ry, d;

            if (row->kind == OV_AREA && (row->azimuth < 0.0 || row->range_m <= 0.0))
                continue;
            project(v, row->lon, row->lat, w, h, &rx, &ry);
            d = hypot(rx - x, ry - y);
            /* A circle's edge is as selectable as its centre. */
            if (row->kind == OV_CIRCLE || row->kind == OV_RING) {
                double r_px = (row->radius_m / EARTH_M_PER_DEG) * v->px_per_deg;
                d = MIN(d, fabs(d - r_px));
            }
            if (d < best) {
                best = d;
                v->selected = row;
                v->selected_layer = layer;
            }
        }
    }
}

static void
draw_ruler(cairo_t *cr, const MapView *v, int w, int h)
{
    double x, y;

    if (!v->ruler_on) return;

    cairo_set_source_rgba(cr, COL_RULER);
    cairo_set_line_width(cr, 1.8);

    if (!v->ruler_done) {
        double lon, lat;

        unproject(v, v->ruler_ax, v->ruler_ay, w, h, &lon, &lat);
        project(v, lon, lat, w, h, &x, &y);
        cairo_arc(cr, x, y, 6.0, 0, 2 * G_PI);
        cairo_stroke(cr);
        cairo_set_font_size(cr, 11.0);
        cairo_move_to(cr, x + 9, y - 7);
        cairo_show_text(cr, "from here — click a second point");
        return;
    }

    {
        double lon1, lat1, lon2, lat2, dist, brg;
        const int steps = 48;

        unproject(v, v->ruler_ax, v->ruler_ay, w, h, &lon1, &lat1);
        unproject(v, v->ruler_bx, v->ruler_by, w, h, &lon2, &lat2);

        for (int i = 0; i <= steps; i++) {
            double ilat, ilon, px, py;

            gc_interp(lat1, lon1, lat2, lon2, (double) i / steps, &ilat, &ilon);
            project(v, ilon, ilat, w, h, &px, &py);
            if (i == 0) cairo_move_to(cr, px, py);
            else        cairo_line_to(cr, px, py);
        }
        cairo_stroke(cr);

        dist = gc_distance_m(lat1, lon1, lat2, lon2);
        brg  = gc_bearing_deg(lat1, lon1, lat2, lon2);

        project(v, lon1, lat1, w, h, &x, &y);
        cairo_arc(cr, x, y, 5.0, 0, 2 * G_PI);
        cairo_stroke(cr);
        project(v, lon2, lat2, w, h, &x, &y);
        cairo_arc(cr, x, y, 5.0, 0, 2 * G_PI);
        cairo_stroke(cr);

        {
            g_autofree char *text = (dist >= 1000.0)
                ? g_strdup_printf("%.2f km · bearing %05.1f°", dist / 1000.0, brg)
                : g_strdup_printf("%.0f m · bearing %05.1f°", dist, brg);
            cairo_text_extents_t ext;

            cairo_set_font_size(cr, 11.0);
            cairo_text_extents(cr, text, &ext);
            cairo_set_source_rgba(cr, COL_CAPTION);
            cairo_rectangle(cr, x + 10, y - 12, ext.width + 10, ext.height + 8);
            cairo_fill(cr);
            cairo_set_source_rgba(cr, COL_RULER);
            cairo_move_to(cr, x + 15, y + 1);
            cairo_show_text(cr, text);
        }
    }
}

/* The caption block: what this picture is, what is on it, and how much of it
   was drawn. Only a snapshot carries one — on a live canvas it would be a
   label the pointer has to keep dodging. */
static void
draw_caption(cairo_t *cr, const MapView *v, int w, int h, const char *stamp)
{
    g_autoptr(GString) s = g_string_new(NULL);
    double left_lon, top_lat, right_lon, bottom_lat;
    guint total = 0, drawn = 0;

    unproject(v, 0, h, w, h, &left_lon, &bottom_lat);
    unproject(v, w, 0, w, h, &right_lon, &top_lat);

    for (guint i = 0; i < v->layers->len; i++) {
        OvLayer *layer = g_ptr_array_index(v->layers, i);

        total += layer->rows->len;
        drawn += layer->drawn;
    }

    g_string_append_printf(s, "IMSIsting %s — Map",
                           v->version != NULL ? v->version : "(version unread)");
    g_string_append_printf(s, "\n%s", stamp != NULL ? stamp : "");
    g_string_append_printf(s, "\nview  %.4f lat .. %.4f lat   %.4f lon .. %.4f lon  ·  %.1f px/deg",
                           MIN(top_lat, bottom_lat), MAX(top_lat, bottom_lat),
                           left_lon, right_lon, v->px_per_deg);
    g_string_append_printf(s, "\n%u row%s in %u layer%s · %u drawn", total,
                           total == 1 ? "" : "s",
                           v->layers->len, v->layers->len == 1 ? "" : "s", drawn);

    for (guint i = 0; i < v->layers->len; i++) {
        OvLayer *layer = g_ptr_array_index(v->layers, i);

        g_string_append_printf(s, "\n  %s%s · %u of %u · %s",
                               layer->name, layer->visible ? "" : " (off)",
                               layer->drawn, layer->rows->len,
                               layer->source != NULL ? layer->source : "no source column");
    }

    if (v->has_window)
        g_string_append_printf(s, "\nwindow  rows older than the slider cut are faded");

    {
        g_auto(GStrv) lines = g_strsplit(s->str, "\n", -1);
        double box_h = 14.0 * g_strv_length(lines) + 12.0;
        double box_w = 520.0;

        cairo_set_font_size(cr, 10.5);
        for (guint i = 0; lines[i] != NULL; i++) {
            cairo_text_extents_t ext;
            cairo_text_extents(cr, lines[i], &ext);
            box_w = MAX(box_w, ext.width + 24.0);
        }
        box_w = MIN(box_w, w - 24.0);

        cairo_set_source_rgba(cr, COL_CAPTION);
        cairo_rectangle(cr, 12, 12, box_w, box_h);
        cairo_fill(cr);
        cairo_set_source_rgba(cr, COL_TEXT);
        for (guint i = 0; lines[i] != NULL; i++) {
            cairo_move_to(cr, 20, 28 + 14 * i);
            cairo_show_text(cr, lines[i]);
        }
    }
}

static void
map_paint(cairo_t *cr, MapView *v, int w, int h)
{
    if (w <= 0 || h <= 0) return;
    if (!v->placed) view_fit_world(v, w, h);

    cairo_set_source_rgba(cr, COL_OCEAN);
    cairo_rectangle(cr, 0, 0, w, h);
    cairo_fill(cr);

    if (v->show_grid)
        draw_graticule(cr, v, w, h);

    if (v->show_land && v->land.loaded) {
        bm_path(cr, v, &v->land, w, h);
        cairo_set_fill_rule(cr, CAIRO_FILL_RULE_EVEN_ODD);
        cairo_set_source_rgba(cr, COL_LAND);
        cairo_fill(cr);
    }

    if (v->show_coast && v->coast.loaded) {
        bm_path(cr, v, &v->coast, w, h);
        cairo_set_source_rgba(cr, COL_COAST);
        cairo_set_line_width(cr, 0.9);
        cairo_stroke(cr);
    }

    if (v->show_borders && v->countries.loaded) {
        bm_path(cr, v, &v->countries, w, h);
        cairo_set_source_rgba(cr, COL_BORDER);
        cairo_set_line_width(cr, 0.7);
        cairo_stroke(cr);
    }

    if (v->show_places && v->places != NULL && v->px_per_deg > 2.2)
        draw_places(cr, v, w, h, v->px_per_deg > 7.0);

    if (v->show_overlays && v->layers != NULL && v->layers->len > 0)
        draw_overlays(cr, v, w, h, v->px_per_deg > 0.8 || v->layers->len <= 3, 1.0);

    /* the selected row first, then the hovered one, both flared, so nothing
       covers the thing the reader is asking about */
    if (v->selected != NULL && v->selected_layer != NULL) {
        double x, y;
        const double *c = v->selected_layer->rgb;

        project(v, v->selected->lon, v->selected->lat, w, h, &x, &y);
        cairo_set_source_rgba(cr, c[0], c[1], c[2], 1.0);
        cairo_set_line_width(cr, 2.2);
        cairo_arc(cr, x, y, 13.0, 0, 2 * G_PI);
        cairo_stroke(cr);
    }

    if (v->hover != NULL && v->hover_layer != NULL) {
        double x, y;
        const double *c = v->hover_layer->rgb;

        project(v, v->hover->lon, v->hover->lat, w, h, &x, &y);
        cairo_set_source_rgba(cr, c[0], c[1], c[2], 1.0);
        cairo_set_line_width(cr, 1.6);
        cairo_arc(cr, x, y, 9.0, 0, 2 * G_PI);
        cairo_stroke(cr);

        cairo_set_source_rgba(cr, 0.04, 0.06, 0.08, 0.85);
        cairo_set_font_size(cr, 11.0);
        {
            cairo_text_extents_t ext;
            g_autofree char *text = g_strdup_printf(
                "%s%s%s%s", v->hover->label != NULL ? v->hover->label : "(row)",
                v->hover->key != NULL ? " · " : "",
                v->hover->key != NULL ? v->hover->key : "",
                v->hover->source != NULL ? " · " : "");
            cairo_text_extents(cr, text, &ext);
            cairo_rectangle(cr, x + 11, y - 12, ext.width + 10, ext.height + 9);
            cairo_fill(cr);
            cairo_set_source_rgba(cr, COL_TEXT);
            cairo_move_to(cr, x + 16, y + 2);
            cairo_show_text(cr, text);
        }
    }

    if (v->why_missing > 0) {
        g_autofree char *msg = g_strdup_printf(
            "%u basemap layer%s did not load — tools/gen-basemap.py rebuilds them",
            v->why_missing, v->why_missing == 1 ? "" : "s");
        cairo_set_source_rgba(cr, 0.95, 0.45, 0.35, 0.9);
        cairo_set_font_size(cr, 11.0);
        cairo_move_to(cr, 16, 20);
        cairo_show_text(cr, msg);
    }

    draw_ruler(cr, v, w, h);
    draw_scale_bar(cr, v, w, h);
}

static void
map_draw(GtkDrawingArea *area, cairo_t *cr, int w, int h, gpointer user_data)
{
    (void) area;
    map_paint(cr, user_data, w, h);
}

/* ------------------------------------------------------------------ */
/*  the "what is drawn" line                                           */
/* ------------------------------------------------------------------ */

/* Which module wrote a layer. The file says so twice: the row's `source`
   column and the file's own name. An exact module id wins; otherwise the name
   is read, because the three modules that write layers today name them after
   themselves. An unresolved layer still shows its literal source text, so a
   guess is never presented as a fact. */
static const char *
ov_layer_module(const OvLayer *layer)
{
    static const struct { const char *prefix; const char *id; } known[] = {
        { "ntn",   "49_ntn" },
        { "gnss",  "61_gnss" },
        { "tower", "04_tower_map" },
        { "cell",  "02_cell_recon" },
        { "suci",  "58_suci_catcher" },
        { "lpp",   "46_lpp" },
        { "gnss-", "61_gnss" },
    };

    if (layer == NULL) return "";
    if (layer->source != NULL && strchr(layer->source, '_') != NULL &&
        g_ascii_isdigit(layer->source[0]))
        return layer->source;

    for (guint i = 0; i < G_N_ELEMENTS(known); i++)
        if (g_str_has_prefix(layer->name, known[i].prefix)) return known[i].id;

    return layer->source != NULL ? layer->source : "";
}

/* ------------------------------------------------------------------ */
/*  legend and the per-layer panel                                     */
/* ------------------------------------------------------------------ */

static void
legend_swatch(GtkDrawingArea *area, cairo_t *cr, int w, int h, gpointer user_data)
{
    const double *rgb = user_data;

    (void) area;
    cairo_set_source_rgba(cr, rgb[0], rgb[1], rgb[2], 1.0);
    cairo_arc(cr, w / 2.0, h / 2.0, MIN(w, h) / 2.0 - 1.0, 0, 2 * G_PI);
    cairo_fill(cr);
}

static void
readout_update(MapView *v, int w, int h)
{
    if (v->readout == NULL) return;

    if (v->hover != NULL) {
        g_autofree char *text = g_strdup_printf(
            "%s%s%s%s%s · %.4f, %.4f · %s",
            v->hover->label != NULL ? v->hover->label : "(row)",
            v->hover->key != NULL ? " · " : "",
            v->hover->key != NULL ? v->hover->key : "",
            v->hover->source != NULL ? " · " : "",
            v->hover->source != NULL ? v->hover->source : "",
            v->hover->lat, v->hover->lon,
            v->hover_layer != NULL ? v->hover_layer->name : "");
        gtk_label_set_text(GTK_LABEL(v->readout), text);
        return;
    }

    /* While the button is down the readout follows the view, not the pointer:
       the numbers then move with the hand, which is how a direction mistake
       becomes visible instead of felt. */
    if (v->dragging) {
        g_autofree char *text = g_strdup_printf(
            "centre  %.4f°%c  %.4f°%c  ·  %.0f px/°",
            fabs(v->centre_lat), v->centre_lat >= 0 ? 'N' : 'S',
            fabs(v->centre_lon), v->centre_lon >= 0 ? 'E' : 'W',
            v->px_per_deg);
        gtk_label_set_text(GTK_LABEL(v->readout), text);
        return;
    }

    if (v->has_cursor) {
        double lon, lat;
        unproject(v, v->cursor_x, v->cursor_y, w, h, &lon, &lat);
        {
            g_autofree char *text = g_strdup_printf(
                "%.4f°%c  %.4f°%c  ·  %.0f px/°",
                fabs(lat), lat >= 0 ? 'N' : 'S',
                fabs(lon), lon >= 0 ? 'E' : 'W',
                v->px_per_deg);
            gtk_label_set_text(GTK_LABEL(v->readout), text);
        }
        return;
    }

    gtk_label_set_text(GTK_LABEL(v->readout),
                       v->ruler_on
                       ? "measure: click two points · click again to start over"
                       : "drag to pan · scroll to zoom · click to inspect · double-click fits the world");
}

/* Degrees, minutes, seconds: what a coordinates field expects when it is not
   the decimal pair above it. */
static char *
fmt_dms(double value, char positive, char negative)
{
    char hemi = value >= 0 ? positive : negative;
    double a = fabs(value);
    int deg = (int) floor(a);
    double rmin = (a - deg) * 60.0;
    int min = (int) floor(rmin);
    double sec = (rmin - min) * 60.0;

    return g_strdup_printf("%d°%02d'%04.1f\"%c", deg, min, sec, hemi);
}

static void
inspect_update(MapView *v)
{
    if (v->inspector == NULL || v->inspector_text == NULL) return;

    if (v->selected == NULL) {
        gtk_label_set_text(GTK_LABEL(v->inspector_text),
                           "Click a mark to read it: label, key, coordinates, radius, layer, source.");
        gtk_widget_set_sensitive(v->inspector_open, FALSE);
        if (v->inspector != NULL)
            gtk_widget_remove_css_class(v->inspector, "map-inspector-live");
        return;
    }

    {
        OvRow *row = v->selected;
        OvLayer *layer = v->selected_layer;
        g_autoptr(GString) s = g_string_new(NULL);
        g_autofree char *dms_lat = fmt_dms(row->lat, 'N', 'S');
        g_autofree char *dms_lon = fmt_dms(row->lon, 'E', 'W');

        g_string_append_printf(s, "%s", row->label != NULL ? row->label : "(row)");
        if (row->key != NULL) g_string_append_printf(s, "  ·  %s", row->key);
        g_string_append_printf(s, "   ·   %s   %s", dms_lat, dms_lon);
        g_string_append_printf(s, "   ·   layer %s", layer != NULL ? layer->name : "-");
        if (row->radius_m > 0.0)
            g_string_append_printf(s, "   ·   radius %.0f m", row->radius_m);
        if (row->range_m > 0.0 && row->azimuth >= 0.0)
            g_string_append_printf(s, "   ·   %.0f° ± %.0f° to %.0f m",
                                   row->azimuth, row->beamwidth / 2.0, row->range_m);
        if (row->ts != NULL) g_string_append_printf(s, "   ·   %s", row->ts);
        if (row->source != NULL) g_string_append_printf(s, "   ·   %s", row->source);

        gtk_label_set_text(GTK_LABEL(v->inspector_text), s->str);
        gtk_widget_set_sensitive(v->inspector_open,
                                 layer != NULL && *ov_layer_module(layer) != '\0');
        gtk_widget_add_css_class(v->inspector, "map-inspector-live");
    }
}

static void legend_refresh(MapView *v);

static void
preamble_refresh(MapView *v)
{
    g_autoptr(GString) s = g_string_new(NULL);
    guint total = 0, drawn = 0, visible = 0;

    if (v->preamble == NULL || v->layers == NULL) return;

    for (guint i = 0; i < v->layers->len; i++) {
        OvLayer *layer = g_ptr_array_index(v->layers, i);

        total += layer->rows->len;
        drawn += layer->drawn;
        if (layer->visible) visible++;
    }

    if (v->layers->len == 0) {
        gtk_label_set_text(GTK_LABEL(v->preamble), "");
        return;
    }

    g_string_append_printf(s, "%u layer%s · %u row%s · %u drawn · %u switched on",
                           v->layers->len, v->layers->len == 1 ? "" : "s",
                           total, total == 1 ? "" : "s", drawn, visible);
    for (guint i = 0; i < v->layers->len; i++) {
        OvLayer *layer = g_ptr_array_index(v->layers, i);
        const char *mod = ov_layer_module(layer);

        g_string_append_printf(s, "%s%s%s", i == 0 ? "  ·  " : "  ",
                               layer->name, *mod != '\0' ? " (" : "");
        if (*mod != '\0') g_string_append_printf(s, "%s)", mod);
    }

    gtk_label_set_text(GTK_LABEL(v->preamble), s->str);
}

static void
legend_refresh(MapView *v)
{
    GtkWidget *row;
    GtkWidget *child;

    if (v->legend == NULL) return;

    while ((child = gtk_widget_get_first_child(v->legend)) != NULL)
        gtk_box_remove(GTK_BOX(v->legend), child);

    if (v->layers == NULL || v->layers->len == 0) {
        g_autofree char *msg = g_strdup_printf(
            "No layers yet. A module that learns a place writes one row to "
            "%s/<name>.tsv — kind, label, lat, lon, radius_m, key, source.",
            v->layers_dir != NULL ? v->layers_dir : LAYERS_SUB);
        GtkWidget *empty = gtk_label_new(msg);
        gtk_label_set_xalign(GTK_LABEL(empty), 0.0f);
        gtk_label_set_wrap(GTK_LABEL(empty), TRUE);
        gtk_widget_add_css_class(empty, "map-legend-empty");
        gtk_box_append(GTK_BOX(v->legend), empty);
        return;
    }

    for (guint i = 0; i < v->layers->len; i++) {
        OvLayer *layer = g_ptr_array_index(v->layers, i);
        GtkWidget *swatch = gtk_drawing_area_new();
        GtkWidget *name = gtk_label_new(layer->name);
        GtkWidget *counts = gtk_label_new(NULL);
        const char *mod = ov_layer_module(layer);
        g_autoptr(GString) detail_s = g_string_new(NULL);

        g_string_append_printf(detail_s, "%u point%s",
                               layer->points, layer->points == 1 ? "" : "s");
        if (layer->rings > 0)
            g_string_append_printf(detail_s, " · %u ring%s",
                                   layer->rings, layer->rings == 1 ? "" : "s");
        if (layer->circles > 0)
            g_string_append_printf(detail_s, " · %u disc%s",
                                   layer->circles, layer->circles == 1 ? "" : "s");
        if (layer->tracks > 0)
            g_string_append_printf(detail_s, " · %u track%s",
                                   layer->tracks, layer->tracks == 1 ? "" : "s");
        if (layer->areas > 0)
            g_string_append_printf(detail_s, " · %u area%s",
                                   layer->areas, layer->areas == 1 ? "" : "s");
        if (layer->source != NULL)
            g_string_append_printf(detail_s, " · %s", layer->source);
        if (*mod != '\0')
            g_string_append_printf(detail_s, " · %s", mod);
        if (!layer->visible)
            g_string_append(detail_s, " · switched off");

        {
            const char *detail = detail_s->str;

            gtk_label_set_text(GTK_LABEL(counts), detail);
        }

        gtk_widget_set_size_request(swatch, 12, 12);
        gtk_widget_set_valign(swatch, GTK_ALIGN_CENTER);
        gtk_drawing_area_set_content_width(GTK_DRAWING_AREA(swatch), 12);
        gtk_drawing_area_set_content_height(GTK_DRAWING_AREA(swatch), 12);
        gtk_drawing_area_set_draw_func(GTK_DRAWING_AREA(swatch), legend_swatch,
                                       layer->rgb, NULL);

        gtk_label_set_xalign(GTK_LABEL(name), 0.0f);
        gtk_widget_add_css_class(name, "map-legend-name");
        gtk_label_set_xalign(GTK_LABEL(counts), 0.0f);
        gtk_widget_add_css_class(counts, "map-legend-counts");

        row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        gtk_widget_add_css_class(row, "map-legend-row");
        gtk_box_append(GTK_BOX(row), swatch);
        {
            GtkWidget *text = gtk_box_new(GTK_ORIENTATION_VERTICAL, 1);
            gtk_box_append(GTK_BOX(text), name);
            gtk_box_append(GTK_BOX(text), counts);
            gtk_box_append(GTK_BOX(row), text);
        }
        gtk_box_append(GTK_BOX(v->legend), row);
    }
}

/* ------------------------------------------------------------------ */
/*  view persistence                                                   */
/* ------------------------------------------------------------------ */

/* state/ui.tsv is the GUI's own store: `key<TAB>value` per line. The map owns
   four keys in it and leaves every other line exactly as it found it —
   rewriting the file from a memory picture of it would drop whatever else the
   interface had saved. */
static void
ui_tsv_write(const char *path, const char *const *keys, const char *const *values, int n)
{
    g_autoptr(GHashTable) want = g_hash_table_new(g_str_hash, g_str_equal);
    g_autoptr(GPtrArray) lines = g_ptr_array_new_with_free_func(g_free);
    g_autofree char *contents = NULL;

    for (int i = 0; i < n; i++)
        g_hash_table_insert(want, (gpointer) keys[i], (gpointer) values[i]);

    if (g_file_get_contents(path, &contents, NULL, NULL)) {
        g_auto(GStrv) split = g_strsplit(contents, "\n", -1);

        for (guint i = 0; split[i] != NULL; i++) {
            g_autofree char *copy = g_strdup(split[i]);
            char *tab;

            if (*copy == '\0') continue;
            tab = strchr(copy, '\t');
            if (tab != NULL) {
                *tab = '\0';
                if (g_hash_table_contains(want, copy)) continue;
            }
            g_ptr_array_add(lines, g_steal_pointer(&copy));
        }
    }

    for (int i = 0; i < n; i++) {
        if (values[i] == NULL) continue;
        g_ptr_array_add(lines, g_strdup_printf("%s\t%s", keys[i], values[i]));
    }

    {
        g_autoptr(GString) out = g_string_new(NULL);

        for (guint i = 0; i < lines->len; i++)
            g_string_append_printf(out, "%s\n", (char *) g_ptr_array_index(lines, i));
        g_file_set_contents(path, out->str, (gssize) out->len, NULL);
    }
}

static char *
ui_tsv_read(const char *path, const char *key)
{
    g_autofree char *contents = NULL;

    if (!g_file_get_contents(path, &contents, NULL, NULL)) return NULL;
    {
        g_auto(GStrv) split = g_strsplit(contents, "\n", -1);

        for (guint i = 0; split[i] != NULL; i++) {
            const char *tab = strchr(split[i], '\t');
            if (tab == NULL) continue;
            if ((gsize) (tab - split[i]) == strlen(key) &&
                strncmp(split[i], key, (gsize) (tab - split[i])) == 0)
                return g_strdup(tab + 1);
        }
    }
    return NULL;
}

static void
view_persist(MapView *v)
{
    g_autofree char *lon = g_strdup_printf("%.6f", v->centre_lon);
    g_autofree char *lat = g_strdup_printf("%.6f", v->centre_lat);
    g_autofree char *ppd = g_strdup_printf("%.4f", v->px_per_deg);
    const char *keys[]   = { "map_centre_lon", "map_centre_lat", "map_ppd", "map_follow" };
    const char *values[] = { lon, lat, ppd, v->follow ? "on" : "off" };

    if (v->state_path == NULL || !v->placed) return;
    ui_tsv_write(v->state_path, keys, values, 4);
}

static void
view_restore(MapView *v)
{
    g_autofree char *lon = ui_tsv_read(v->state_path, "map_centre_lon");
    g_autofree char *lat = ui_tsv_read(v->state_path, "map_centre_lat");
    g_autofree char *ppd = ui_tsv_read(v->state_path, "map_ppd");
    g_autofree char *fol = ui_tsv_read(v->state_path, "map_follow");

    if (fol != NULL) v->follow = (g_strcmp0(fol, "on") == 0);
    if (lon == NULL || lat == NULL || ppd == NULL) return;

    {
        double lo = g_ascii_strtod(lon, NULL);
        double la = g_ascii_strtod(lat, NULL);
        double pp = g_ascii_strtod(ppd, NULL);

        if (isfinite(lo) && isfinite(la) && isfinite(pp) && pp > 0.0) {
            v->centre_lon = lo;
            v->centre_lat = la;
            v->px_per_deg = pp;
            v->placed = TRUE;
        }
    }
}

/* ------------------------------------------------------------------ */
/*  the time window                                                    */
/* ------------------------------------------------------------------ */

static void
age_window_rebuild(MapView *v)
{
    double lo = 0.0, hi = 0.0;
    gboolean any = FALSE;

    for (guint i = 0; i < v->layers->len; i++) {
        OvLayer *layer = g_ptr_array_index(v->layers, i);

        for (guint j = 0; j < layer->rows->len; j++) {
            OvRow *row = g_ptr_array_index(layer->rows, j);

            if (row->ts_epoch < 0.0) continue;
            if (!any) { lo = hi = row->ts_epoch; any = TRUE; }
            lo = MIN(lo, row->ts_epoch);
            hi = MAX(hi, row->ts_epoch);
        }
    }

    v->has_window = any;
    v->ts_min = lo;
    v->ts_max = hi;
    v->age_cut = lo;

    if (v->age_scale != NULL) {
        gtk_widget_set_sensitive(v->age_scale, any);
        if (!any)
            gtk_range_set_value(GTK_RANGE(v->age_scale), AGE_STEPS);
    }
}

/* ------------------------------------------------------------------ */
/*  snapshot                                                           */
/* ------------------------------------------------------------------ */

static char *
snapshot_path(MapView *v, const char *ext)
{
    GDateTime *now = g_date_time_new_now_utc();
    g_autofree char *stamp = g_date_time_format(now, "%Y%m%dT%H%M%SZ");
    g_autofree char *name = g_strdup_printf("map-%s.%s", stamp, ext);

    g_date_time_unref(now);
    if (v->snapshot_dir == NULL) return NULL;
    g_mkdir_with_parents(v->snapshot_dir, 0755);
    return g_build_filename(v->snapshot_dir, name, NULL);
}

/* A PNG of exactly what the canvas shows, plus the caption the canvas does not
   carry. The caption is drawn into the image, not appended as a sidecar: a
   picture that needs a second file to be honest gets separated from it. */
static gboolean
snapshot_png(MapView *v)
{
    int w = 1400, h = 900;
    cairo_surface_t *surface;
    cairo_t *cr;
    g_autofree char *path = snapshot_path(v, "png");
    GDateTime *now = g_date_time_new_now_utc();
    g_autofree char *stamp = g_date_time_format(now, "%Y-%m-%d %H:%M:%SZ");
    cairo_status_t st;

    if (path == NULL) return FALSE;

    surface = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, w, h);
    cr = cairo_create(surface);
    map_paint(cr, v, w, h);
    draw_caption(cr, v, w, h, stamp);
    cairo_destroy(cr);

    st = cairo_surface_write_to_png(surface, path);
    cairo_surface_destroy(surface);
    g_date_time_unref(now);

    if (st != CAIRO_STATUS_SUCCESS) return FALSE;

    if (v->hint != NULL) {
        g_autofree char *msg = g_strdup_printf("snapshot written: %s", path);
        gtk_label_set_text(GTK_LABEL(v->hint), msg);
    }
    return TRUE;
}

static void
svg_append_path(GString *s, const MapView *v, const Basemap *bm, int w, int h,
                const char *stroke, const char *fill)
{
    if (!bm->loaded) return;
    g_string_append_printf(s, "<path fill=\"%s\" stroke=\"%s\" stroke-width=\"0.7\" "
                              "fill-rule=\"evenodd\" d=\"", fill, stroke);
    for (guint i = 0; i < bm->n_parts; i++) {
        guint32 off = bm->index[i * 2], len = bm->index[i * 2 + 1];

        for (guint32 k = 0; k < len; k++) {
            const gint32 *p = &bm->points[(off + k) * 2];
            double x, y;

            project(v, p[0] / 1e4, p[1] / 1e4, w, h, &x, &y);
            g_string_append_printf(s, "%c%.1f %.1f", k == 0 ? 'M' : 'L', x, y);
        }
        g_string_append(s, "Z");
    }
    g_string_append(s, "\"/>\n");
}

/* The rows as vectors, not a bitmap of them: an SVG that a document can carry
   and a reader can open, with the same caption block the PNG carries. */
static gboolean
snapshot_svg(MapView *v)
{
    int w = 1400, h = 900;
    g_autofree char *path = snapshot_path(v, "svg");
    g_autoptr(GString) s = g_string_new(NULL);
    GDateTime *now = g_date_time_new_now_utc();
    g_autofree char *stamp = g_date_time_format(now, "%Y-%m-%d %H:%M:%SZ");
    guint total = 0, drawn = 0;

    if (path == NULL) return FALSE;

    g_string_append_printf(s,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"%d\" height=\"%d\" "
        "viewBox=\"0 0 %d %d\">\n", w, h, w, h);
    g_string_append_printf(s, "<rect width=\"%d\" height=\"%d\" fill=\"#0a0e13\"/>\n", w, h);

    svg_append_path(s, v, &v->land, w, h, "none", "#18232e");
    svg_append_path(s, v, &v->coast, w, h, "#789bb8", "none");
    svg_append_path(s, v, &v->countries, w, h, "#789bb8", "none");

    for (guint i = 0; i < v->layers->len; i++) {
        OvLayer *layer = g_ptr_array_index(v->layers, i);
        g_autofree char *rgb = g_strdup_printf("#%02x%02x%02x",
            (int) (layer->rgb[0] * 255), (int) (layer->rgb[1] * 255),
            (int) (layer->rgb[2] * 255));

        total += layer->rows->len;
        drawn += layer->drawn;
        if (!layer->visible) continue;

        for (guint j = 0; j < layer->rows->len; j++) {
            OvRow *row = g_ptr_array_index(layer->rows, j);
            double x, y;

            project(v, row->lon, row->lat, w, h, &x, &y);

            switch (row->kind) {
            case OV_CIRCLE:
            case OV_RING: {
                double r_px = MAX((row->radius_m / EARTH_M_PER_DEG) * v->px_per_deg, 4.0);

                g_string_append_printf(s,
                    "<circle cx=\"%.1f\" cy=\"%.1f\" r=\"%.1f\" fill=\"%s\" fill-opacity=\"%s\" "
                    "stroke=\"%s\" stroke-width=\"1.4\"/>\n",
                    x, y, r_px, rgb, row->kind == OV_CIRCLE ? "0.16" : "none", rgb);
                break;
            }
            case OV_TRACK:
                g_string_append_printf(s, "<circle cx=\"%.1f\" cy=\"%.1f\" r=\"1.9\" fill=\"%s\"/>\n",
                                       x, y, rgb);
                break;
            case OV_POINT:
                g_string_append_printf(s,
                    "<circle cx=\"%.1f\" cy=\"%.1f\" r=\"3.2\" fill=\"%s\"/>\n", x, y, rgb);
                break;
            case OV_AREA:
                if (row->azimuth >= 0.0 && row->range_m > 0.0) {
                    double reach = MAX((row->range_m / EARTH_M_PER_DEG) * v->px_per_deg, 6.0);
                    double half = row->beamwidth / 2.0;
                    double a1 = row->azimuth - half - 90.0, a2 = row->azimuth + half - 90.0;
                    double x1 = x + reach * cos(a1 * G_PI / 180.0);
                    double y1 = y + reach * sin(a1 * G_PI / 180.0);
                    double x2 = x + reach * cos(a2 * G_PI / 180.0);
                    double y2 = y + reach * sin(a2 * G_PI / 180.0);
                    int large = (row->beamwidth > 180.0) ? 1 : 0;

                    g_string_append_printf(s,
                        "<path d=\"M%.1f %.1f L%.1f %.1f A%.1f %.1f 0 %d 1 %.1f %.1f Z\" "
                        "fill=\"%s\" fill-opacity=\"0.13\" stroke=\"%s\" stroke-width=\"1.2\"/>\n",
                        x, y, x1, y1, reach, reach, large, x2, y2, rgb, rgb);
                }
                break;
            }
        }
    }

    {
        g_autoptr(GString) cap = g_string_new(NULL);
        double left_lon, top_lat, right_lon, bottom_lat;

        unproject(v, 0, h, w, h, &left_lon, &bottom_lat);
        unproject(v, w, 0, w, h, &right_lon, &top_lat);

        g_string_append_printf(cap, "IMSIsting %s — Map",
                               v->version != NULL ? v->version : "(version unread)");
        g_string_append_printf(cap, "   %s", stamp);
        g_string_append_printf(cap, "   %.4f..%.4f lat  %.4f..%.4f lon  %.1f px/deg",
                               MIN(top_lat, bottom_lat), MAX(top_lat, bottom_lat),
                               left_lon, right_lon, v->px_per_deg);
        g_string_append_printf(cap, "   %u rows in %u layers, %u drawn",
                               total, v->layers->len, drawn);

        g_string_append_printf(s,
            "<rect x=\"12\" y=\"12\" width=\"1330\" height=\"26\" fill=\"#0a0e13\" fill-opacity=\"0.86\"/>\n"
            "<text x=\"20\" y=\"30\" font-family=\"monospace\" font-size=\"12\" fill=\"#c8d4e2\">%s</text>\n",
            cap->str);
    }

    g_string_append(s, "</svg>\n");
    g_date_time_unref(now);

    if (!g_file_set_contents(path, s->str, (gssize) s->len, NULL)) return FALSE;

    if (v->hint != NULL) {
        g_autofree char *msg = g_strdup_printf("snapshot written: %s", path);
        gtk_label_set_text(GTK_LABEL(v->hint), msg);
    }
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  reload                                                             */
/* ------------------------------------------------------------------ */

static void
layers_reload(MapView *v)
{
    guint rows = 0;
    g_autoptr(GPtrArray) before = v->layers;

    v->layers = layers_load(v->layers_dir, &rows);

    /* carry each layer's switch across the reload by name */
    for (guint i = 0; i < v->layers->len; i++) {
        OvLayer *layer = g_ptr_array_index(v->layers, i);
        layer->visible = layer_was_visible(before, layer->name);
    }

    v->hover = NULL;
    v->hover_layer = NULL;
    if (v->selected != NULL) {
        v->selected = NULL;
        v->selected_layer = NULL;
        inspect_update(v);
    }

    age_window_rebuild(v);
    legend_refresh(v);
    preamble_refresh(v);

    if (v->hint != NULL) {
        g_autofree char *msg = (rows > 0)
            ? g_strdup_printf("%u row%s from %u layer file%s · %s",
                              rows, rows == 1 ? "" : "s",
                              v->layers->len, v->layers->len == 1 ? "" : "s",
                              v->layers_dir)
            : g_strdup_printf("nothing in %s yet", v->layers_dir);
        gtk_label_set_text(GTK_LABEL(v->hint), msg);
    }

    /* follow the newest thing on the map, if the reader asked to */
    if (v->follow) {
        OvRow *newest = NULL;

        for (guint i = 0; i < v->layers->len; i++) {
            OvLayer *layer = g_ptr_array_index(v->layers, i);

            if (!layer->visible) continue;
            for (guint j = 0; j < layer->rows->len; j++) {
                OvRow *row = g_ptr_array_index(layer->rows, j);

                if (newest == NULL || row->ts_epoch > newest->ts_epoch)
                    newest = row;
            }
        }
        if (newest != NULL) {
            v->centre_lat = newest->lat;
            v->centre_lon = newest->lon;
            if (v->px_per_deg < 40.0) v->px_per_deg = 400.0;
            v->placed = TRUE;
        }
    }

    gtk_widget_queue_draw(v->canvas);
}

/* ------------------------------------------------------------------ */
/*  interaction                                                        */
/* ------------------------------------------------------------------ */

static void
canvas_size(GtkWidget *canvas, int *w, int *h)
{
    *w = gtk_widget_get_width(canvas);
    *h = gtk_widget_get_height(canvas);
}

static void pan_step(double *centre_lon, double *centre_lat, double px_per_deg,
                     double dx, double dy);

static void
on_drag_begin(GtkGestureDrag *gesture, double start_x, double start_y, gpointer user_data)
{
    MapView *v = user_data;

    (void) gesture;
    v->dragging = TRUE;
    /* The pan is driven by the pointer's own motion, not by this gesture's
       offsets. GtkGestureDrag reports offsets from the drag origin, and a
       handler that assumes increments instead double-counts the whole drag;
       that ambiguity is what made one drag cross a continent. start_x/start_y
       are in the same widget space the motion events use, so seeding the
       pointer here starts the chain at the pixel the button went down on. */
    v->drag_last_x = start_x;
    v->drag_last_y = start_y;
}

static void
on_drag_update(GtkGestureDrag *gesture, double offset_x, double offset_y, gpointer user_data)
{
    /* Deliberately empty. on_motion does the panning: one source of motion,
       one place where the view changes, so a drag cannot be applied twice and
       the direction has a single definition. */
    (void) gesture;
    (void) offset_x;
    (void) offset_y;
    (void) user_data;
}

/* The pan arithmetic, with no widgets in it. The motion handler and the
   selftest both call this, so --selftest proves the maths the hand runs
   instead of proving a copy of it. Positive dx is a rightward drag: the
   content follows the hand, so the centre moves west. */
static void
pan_step (double *centre_lon, double *centre_lat, double px_per_deg,
          double dx, double dy)
{
    if (px_per_deg <= 0.0)
        return;
    *centre_lon -= dx / px_per_deg;
    *centre_lat += dy / px_per_deg;
}

static void
on_drag_end(GtkGestureDrag *gesture, double offset_x, double offset_y, gpointer user_data)
{
    MapView *v = user_data;

    (void) gesture;
    (void) offset_x;
    (void) offset_y;
    v->dragging = FALSE;
    view_persist(v);
}

/* ---- the layer sheet: hover the bottom edge, read it, leave ---- */

static void
legend_show(MapView *v)
{
    if (v->legend_panel == NULL) return;
    if (v->legend_hide_id != 0) {
        g_source_remove(v->legend_hide_id);
        v->legend_hide_id = 0;
    }
    if (!gtk_widget_get_visible(v->legend_panel))
        gtk_widget_set_visible(v->legend_panel, TRUE);
}

/* Whether the pointer is over the sheet. The flags above follow the events
   the sheet's own controller sees, and a label inside the sheet can swallow
   a motion event on its way in; asking the seat where the pointer actually is
   removes that whole class of miss, and it is the same answer a reader would
   give by looking. */
static gboolean
legend_pointer_inside(MapView *v)
{
    GdkSeat *seat;
    GdkDevice *device;
    GdkSurface *surface;
    GtkWidget *toplevel;
    graphene_rect_t bounds;
    double px = 0.0, py = 0.0;

    if (v->legend_panel == NULL || v->canvas == NULL) return FALSE;
    if (!gtk_widget_get_mapped(v->legend_panel)) return FALSE;

    seat = gdk_display_get_default_seat(gtk_widget_get_display(v->canvas));
    if (seat == NULL) return FALSE;
    device = gdk_seat_get_pointer(seat);
    if (device == NULL) return FALSE;

    toplevel = GTK_WIDGET(gtk_widget_get_native(v->canvas));
    if (toplevel == NULL) return FALSE;
    surface = gtk_native_get_surface(GTK_NATIVE(toplevel));
    if (surface == NULL) return FALSE;

    if (!gdk_surface_get_device_position(surface, device, &px, &py, NULL))
        return FALSE;
    if (!gtk_widget_compute_bounds(v->legend_panel, toplevel, &bounds))
        return FALSE;

    return px >= bounds.origin.x && px <= bounds.origin.x + bounds.size.width
        && py >= bounds.origin.y && py <= bounds.origin.y + bounds.size.height;
}

static gboolean
legend_hide_cb(gpointer user_data)
{
    MapView *v = user_data;

    v->legend_hide_id = 0;
    /* the pointer may have come back while the timer ran: ask where it is,
       not what time it is */
    if (v->legend_hover || v->canvas_hot) return G_SOURCE_REMOVE;
    if (legend_pointer_inside(v)) return G_SOURCE_REMOVE;
    if (v->legend_panel != NULL)
        gtk_widget_set_visible(v->legend_panel, FALSE);
    return G_SOURCE_REMOVE;
}

static void
legend_hide_soon(MapView *v)
{
    if (v->legend_panel == NULL) return;
    if (!gtk_widget_get_visible(v->legend_panel)) return;
    if (v->legend_hide_id != 0) return;
    v->legend_hide_id = g_timeout_add(LEGEND_HIDE_MS, legend_hide_cb, v);
}

static void
legend_motion(GtkEventControllerMotion *controller, double x, double y,
              gpointer user_data)
{
    MapView *v = user_data;

    (void) controller;
    (void) x;
    (void) y;
    v->legend_hover = TRUE;
    legend_show(v);
}

static void
legend_leave(GtkEventControllerMotion *controller, gpointer user_data)
{
    MapView *v = user_data;

    (void) controller;
    v->legend_hover = FALSE;
    legend_hide_soon(v);
}

static void
on_motion(GtkEventControllerMotion *controller, double x, double y, gpointer user_data)
{
    MapView *v = user_data;
    int w, h;
    OvRow *before = v->hover;

    (void) controller;
    canvas_size(v->canvas, &w, &h);
    if (w <= 0 || h <= 0) return;

    /* the bottom edge is a handle, not a target: arriving there is enough */
    v->canvas_hot = ((double) h - y) <= (double) LEGEND_HOT_PX;
    if (v->canvas_hot)
        legend_show(v);
    else if (!v->legend_hover)
        legend_hide_soon(v);

    v->has_cursor = TRUE;
    v->cursor_x = x;
    v->cursor_y = y;

    /* A held button turns motion into a pan: the view follows the hand by the
       distance the pointer actually travelled, which is one pixel per pixel
       at every scale. The step is clamped so a pointer warp cannot fling it. */
    if (v->dragging) {
        const double max_step = (double) MAX(w, h) * 2.0;
        double dx = CLAMP(x - v->drag_last_x, -max_step, max_step);
        double dy = CLAMP(y - v->drag_last_y, -max_step, max_step);

        v->drag_last_x = x;
        v->drag_last_y = y;
        if (dx != 0.0 || dy != 0.0) {
            pan_step(&v->centre_lon, &v->centre_lat, v->px_per_deg, dx, dy);
            view_clamp(v, w, h);
            gtk_widget_queue_draw(v->canvas);
        }
    }

    find_hover(v, w, h);
    readout_update(v, w, h);

    /* the flare is drawn on the canvas, so a change of subject has to repaint */
    if (v->hover != before)
        gtk_widget_queue_draw(v->canvas);
}

static void
on_leave(GtkEventControllerMotion *controller, gpointer user_data)
{
    MapView *v = user_data;
    int w, h;

    (void) controller;
    v->has_cursor = FALSE;
    v->hover = NULL;
    v->hover_layer = NULL;
    /* leaving the canvas for the sheet it just opened is not leaving */
    v->canvas_hot = FALSE;
    if (!v->legend_hover)
        legend_hide_soon(v);
    canvas_size(v->canvas, &w, &h);
    readout_update(v, w, h);
    gtk_widget_queue_draw(v->canvas);
}

static void
zoom_about(MapView *v, double factor, double anchor_x, double anchor_y)
{
    int w, h;
    double lon, lat;

    canvas_size(v->canvas, &w, &h);
    if (w <= 0 || h <= 0) return;

    unproject(v, anchor_x, anchor_y, w, h, &lon, &lat);
    v->px_per_deg *= factor;
    view_clamp(v, w, h);

    /* keep the point under the pointer where it was */
    v->centre_lon = lon - (anchor_x - w / 2.0) / v->px_per_deg;
    v->centre_lat = lat + (anchor_y - h / 2.0) / v->px_per_deg;
    view_clamp(v, w, h);

    gtk_widget_queue_draw(v->canvas);
}

static gboolean
on_scroll(GtkEventControllerScroll *controller, double dx, double dy, gpointer user_data)
{
    MapView *v = user_data;

    (void) controller;
    (void) dx;
    if (dy == 0.0) return FALSE;

    zoom_about(v, dy < 0 ? 1.30 : 1.0 / 1.30,
               v->has_cursor ? v->cursor_x : gtk_widget_get_width(v->canvas) / 2.0,
               v->has_cursor ? v->cursor_y : gtk_widget_get_height(v->canvas) / 2.0);
    return TRUE;
}

/* One click selects, two fit the world. A click while the ruler is armed
   places an end instead, because the reader said what the click means. */
static void
on_click(GtkGestureClick *gesture, int n_press, double x, double y, gpointer user_data)
{
    MapView *v = user_data;
    int w, h;

    (void) gesture;
    canvas_size(v->canvas, &w, &h);
    if (w <= 0 || h <= 0) return;

    if (v->ruler_on) {
        if (!v->ruler_done) {
            v->ruler_ax = x;
            v->ruler_ay = y;
            v->ruler_done = TRUE;
        } else {
            v->ruler_done = FALSE;
            v->ruler_ax = x;
            v->ruler_ay = y;
        }
        gtk_widget_queue_draw(v->canvas);
        readout_update(v, w, h);
        return;
    }

    if (n_press == 2) {
        view_fit_world(v, w, h);
        view_persist(v);
        gtk_widget_queue_draw(v->canvas);
        return;
    }

    if (n_press != 1) return;

    find_selected(v, x, y, w, h);
    inspect_update(v);
    readout_update(v, w, h);
    gtk_widget_queue_draw(v->canvas);
}

static void
zoom_clicked(GtkButton *button, gpointer user_data)
{
    MapView *v = user_data;
    double factor = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(button), "factor")) > 0
                  ? 1.6 : 1.0 / 1.6;

    zoom_about(v, factor,
               gtk_widget_get_width(v->canvas) / 2.0,
               gtk_widget_get_height(v->canvas) / 2.0);
    view_persist(v);
}

static void
fit_world_clicked(GtkButton *button, gpointer user_data)
{
    MapView *v = user_data;
    int w, h;

    (void) button;
    canvas_size(v->canvas, &w, &h);
    view_fit_world(v, w, h);
    view_persist(v);
    gtk_widget_queue_draw(v->canvas);
}

static void
fit_layers_clicked(GtkButton *button, gpointer user_data)
{
    MapView *v = user_data;
    int w, h;

    (void) button;
    canvas_size(v->canvas, &w, &h);
    view_fit_layers(v, w, h);
    view_persist(v);
    gtk_widget_queue_draw(v->canvas);
}

static void
reload_clicked(GtkButton *button, gpointer user_data)
{
    (void) button;
    layers_reload(user_data);
}

static void
ruler_toggled(GtkToggleButton *button, gpointer user_data)
{
    MapView *v = user_data;

    v->ruler_on = gtk_toggle_button_get_active(button);
    v->ruler_done = FALSE;
    gtk_widget_queue_draw(v->canvas);

    if (v->readout != NULL)
        readout_update(v, gtk_widget_get_width(v->canvas), gtk_widget_get_height(v->canvas));
}

static void
follow_toggled(GtkToggleButton *button, gpointer user_data)
{
    MapView *v = user_data;

    v->follow = gtk_toggle_button_get_active(button);
    if (v->follow) layers_reload(v);
    view_persist(v);
}

static void
snapshot_png_clicked(GtkButton *button, gpointer user_data)
{
    MapView *v = user_data;

    (void) button;
    if (!snapshot_png(v) && v->hint != NULL)
        gtk_label_set_text(GTK_LABEL(v->hint), "could not write the snapshot");
}

static void
snapshot_svg_clicked(GtkButton *button, gpointer user_data)
{
    MapView *v = user_data;

    (void) button;
    if (!snapshot_svg(v) && v->hint != NULL)
        gtk_label_set_text(GTK_LABEL(v->hint), "could not write the snapshot");
}

/* A clicked layer's switch, held in the layer panel. */
static void
layer_switch_toggled(GtkCheckButton *check, gpointer user_data)
{
    MapView *v = g_object_get_data(G_OBJECT(check), "map-view");
    OvLayer *layer = g_object_get_data(G_OBJECT(check), "map-layer");

    (void) user_data;
    if (v == NULL || layer == NULL) return;

    layer->visible = gtk_check_button_get_active(check);
    legend_refresh(v);
    preamble_refresh(v);
    gtk_widget_queue_draw(v->canvas);
}

static void
layer_fit_clicked(GtkButton *button, gpointer user_data)
{
    MapView *v = g_object_get_data(G_OBJECT(button), "map-view");
    OvLayer *layer = g_object_get_data(G_OBJECT(button), "map-layer");
    int w, h;

    (void) user_data;
    if (v == NULL || layer == NULL) return;
    canvas_size(v->canvas, &w, &h);
    view_fit_one(v, layer, w, h);
    view_persist(v);
    gtk_widget_queue_draw(v->canvas);
}

static void
toggle_changed(GtkCheckButton *check, gpointer user_data)
{
    MapView *v = g_object_get_data(G_OBJECT(check), "map-view");
    const char *what = g_object_get_data(G_OBJECT(check), "what");
    gboolean on = gtk_check_button_get_active(check);

    (void) user_data;
    if (v == NULL || what == NULL) return;

    if (g_strcmp0(what, "land") == 0)         v->show_land = on;
    else if (g_strcmp0(what, "coast") == 0)   v->show_coast = on;
    else if (g_strcmp0(what, "borders") == 0) v->show_borders = on;
    else if (g_strcmp0(what, "places") == 0)  v->show_places = on;
    else if (g_strcmp0(what, "grid") == 0)    v->show_grid = on;
    else if (g_strcmp0(what, "overlays") == 0) v->show_overlays = on;

    gtk_widget_queue_draw(v->canvas);
}

static GtkWidget *
map_toggle(MapView *v, const char *what, const char *label, gboolean initial)
{
    GtkWidget *check = gtk_check_button_new_with_label(label);

    gtk_check_button_set_active(GTK_CHECK_BUTTON(check), initial);
    g_object_set_data(G_OBJECT(check), "map-view", v);
    g_object_set_data(G_OBJECT(check), "what", (gpointer) what);
    g_signal_connect(check, "toggled", G_CALLBACK(toggle_changed), NULL);
    return check;
}

/* The time window slider. 0 is the oldest row in the inbox, AGE_STEPS is
   "everything"; the value is the cut, and a row older than the cut is drawn
   faint rather than removed. Undated rows ignore it. */
static void
age_scale_changed(GtkRange *range, gpointer user_data)
{
    MapView *v = user_data;
    double frac;

    if (!v->has_window) return;

    frac = gtk_range_get_value(range) / AGE_STEPS;
    v->age_cut = v->ts_min + (v->ts_max - v->ts_min) * frac;

    if (v->hint != NULL) {
        GDateTime *dt = g_date_time_new_from_unix_utc((gint64) v->age_cut);
        g_autofree char *when = dt != NULL ? g_date_time_format(dt, "%Y-%m-%d %H:%MZ") : NULL;

        if (dt != NULL) g_date_time_unref(dt);
        {
            g_autofree char *msg = g_strdup_printf(
                "showing rows not older than %s (undated rows always shown)",
                when != NULL ? when : "—");
            gtk_label_set_text(GTK_LABEL(v->hint), msg);
        }
    }
    gtk_widget_queue_draw(v->canvas);
}

/* The clipboard is the interface's, not the page's: ask the widget for it. */
static void
copy_text(GtkWidget *widget, const char *text)
{
    GdkClipboard *cb = gtk_widget_get_clipboard(widget);

    if (cb != NULL && text != NULL) gdk_clipboard_set_text(cb, text);
}

static void
copy_decimal_clicked(GtkButton *button, gpointer user_data)
{
    MapView *v = user_data;

    (void) button;
    if (v->selected != NULL) {
        g_autofree char *text = g_strdup_printf("%.6f, %.6f",
                                                v->selected->lat, v->selected->lon);
        copy_text(v->canvas, text);
    } else if (v->has_cursor) {
        int w, h;
        double lon, lat;

        canvas_size(v->canvas, &w, &h);
        unproject(v, v->cursor_x, v->cursor_y, w, h, &lon, &lat);
        {
            g_autofree char *text = g_strdup_printf("%.6f, %.6f", lat, lon);
            copy_text(v->canvas, text);
        }
    }
}

static void
copy_dms_clicked(GtkButton *button, gpointer user_data)
{
    MapView *v = user_data;
    double lat = 0.0, lon = 0.0;
    gboolean have = FALSE;

    (void) button;
    if (v->selected != NULL) {
        lat = v->selected->lat;
        lon = v->selected->lon;
        have = TRUE;
    } else if (v->has_cursor) {
        int w, h;

        canvas_size(v->canvas, &w, &h);
        unproject(v, v->cursor_x, v->cursor_y, w, h, &lon, &lat);
        have = TRUE;
    }

    if (have) {
        g_autofree char *a = fmt_dms(lat, 'N', 'S');
        g_autofree char *b = fmt_dms(lon, 'E', 'W');
        g_autofree char *text = g_strdup_printf("%s %s", a, b);
        copy_text(v->canvas, text);
    }
}

static void
copy_row_clicked(GtkButton *button, gpointer user_data)
{
    MapView *v = user_data;

    (void) button;
    if (v->selected == NULL) return;
    {
        OvRow *row = v->selected;
        g_autofree char *text = g_strdup_printf(
            "%s\t%s\t%.6f\t%.6f\t%.0f\t%s\t%s\t%s",
            row->kind == OV_POINT  ? "point"  :
            row->kind == OV_RING   ? "ring"   :
            row->kind == OV_CIRCLE ? "circle" :
            row->kind == OV_TRACK  ? "track"  : "area",
            row->label != NULL ? row->label : "",
            row->lat, row->lon, row->radius_m,
            row->key != NULL ? row->key : "",
            row->source != NULL ? row->source : "",
            row->ts != NULL ? row->ts : "");
        copy_text(v->canvas, text);
    }
}

static void
copy_layer_clicked(GtkButton *button, gpointer user_data)
{
    MapView *v = user_data;
    g_autoptr(GString) s = g_string_new(NULL);

    (void) button;
    if (v->selected_layer == NULL) return;

    for (guint j = 0; j < v->selected_layer->rows->len; j++) {
        OvRow *row = g_ptr_array_index(v->selected_layer->rows, j);

        g_string_append_printf(s, "%s\t%s\t%.6f\t%.6f\t%.0f\t%s\t%s\t%s\n",
            row->kind == OV_POINT  ? "point"  :
            row->kind == OV_RING   ? "ring"   :
            row->kind == OV_CIRCLE ? "circle" :
            row->kind == OV_TRACK  ? "track"  : "area",
            row->label != NULL ? row->label : "",
            row->lat, row->lon, row->radius_m,
            row->key != NULL ? row->key : "",
            row->source != NULL ? row->source : "",
            row->ts != NULL ? row->ts : "");
    }
    copy_text(v->canvas, s->str);
}

static void
open_module_clicked(GtkButton *button, gpointer user_data)
{
    MapView *v = user_data;
    const char *id;

    (void) button;
    if (v->opener == NULL || v->selected_layer == NULL) return;
    id = ov_layer_module(v->selected_layer);
    if (id != NULL && *id != '\0') v->opener(id, v->opener_data);
}

/* Right-click: the pointer already names a place, so the menu is about the
   pointer, not about a selection the reader has to make first. */
static void
on_right_click(GtkGestureClick *gesture, int n_press, double x, double y, gpointer user_data)
{
    MapView *v = user_data;
    GtkWidget *popover;
    GtkWidget *box;
    int w, h;

    (void) gesture;
    (void) n_press;

    canvas_size(v->canvas, &w, &h);
    if (w <= 0 || h <= 0) return;

    v->has_cursor = TRUE;
    v->cursor_x = x;
    v->cursor_y = y;
    find_hover(v, w, h);
    find_selected(v, x, y, w, h);
    inspect_update(v);

    popover = gtk_popover_new();
    box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    gtk_widget_set_margin_top(box, 6);
    gtk_widget_set_margin_bottom(box, 6);
    gtk_widget_set_margin_start(box, 6);
    gtk_widget_set_margin_end(box, 6);

    {
        struct { const char *label; GCallback cb; gboolean need_row; } items[] = {
            { "Copy coordinate (decimal)", G_CALLBACK(copy_decimal_clicked), FALSE },
            { "Copy coordinate (DMS)",     G_CALLBACK(copy_dms_clicked),     FALSE },
            { "Copy row as TSV",           G_CALLBACK(copy_row_clicked),     TRUE  },
            { "Copy whole layer as TSV",   G_CALLBACK(copy_layer_clicked),   TRUE  },
        };

        for (guint i = 0; i < G_N_ELEMENTS(items); i++) {
            GtkWidget *b = gtk_button_new_with_label(items[i].label);

            gtk_widget_add_css_class(b, "flat");
            gtk_widget_set_halign(b, GTK_ALIGN_FILL);
            gtk_widget_set_sensitive(b, items[i].need_row ? (v->selected != NULL) : TRUE);
            g_signal_connect(b, "clicked", items[i].cb, v);
            g_signal_connect_swapped(b, "clicked", G_CALLBACK(gtk_popover_popdown), popover);
            gtk_box_append(GTK_BOX(box), b);
        }
    }

    gtk_popover_set_child(GTK_POPOVER(popover), box);
    gtk_widget_set_parent(popover, v->canvas);
    {
        GdkRectangle at = { (int) x, (int) y, 1, 1 };

        gtk_popover_set_pointing_to(GTK_POPOVER(popover), &at);
    }
    gtk_popover_popup(GTK_POPOVER(popover));
}

/* ------------------------------------------------------------------ */
/*  live follow                                                        */
/* ------------------------------------------------------------------ */

static gboolean
monitor_flush(gpointer user_data)
{
    MapView *v = user_data;

    v->monitor_pending = 0;
    layers_reload(v);
    return G_SOURCE_REMOVE;
}

static void
monitor_changed(GFileMonitor *monitor, GFile *file, GFile *other,
                GFileMonitorEvent event, gpointer user_data)
{
    MapView *v = user_data;

    (void) monitor;
    (void) file;
    (void) other;

    /* One reload per burst: a module that writes four layers would otherwise
       cause four reloads of four files. */
    if (event != G_FILE_MONITOR_EVENT_CREATED &&
        event != G_FILE_MONITOR_EVENT_CHANGED &&
        event != G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT &&
        event != G_FILE_MONITOR_EVENT_DELETED)
        return;

    if (v->monitor_pending == 0)
        v->monitor_pending = g_timeout_add(250, monitor_flush, v);
}

/* ------------------------------------------------------------------ */
/*  the page                                                           */
/* ------------------------------------------------------------------ */

static void
map_view_free(gpointer data)
{
    MapView *v = data;

    basemap_clear(&v->land);
    basemap_clear(&v->coast);
    basemap_clear(&v->countries);
    places_clear(&v->places);
    layers_clear(&v->layers);
    g_clear_pointer(&v->layers_dir, g_free);
    g_clear_pointer(&v->root_dir, g_free);
    g_clear_pointer(&v->snapshot_dir, g_free);
    g_clear_pointer(&v->state_path, g_free);
    g_clear_pointer(&v->version, g_free);
    /* a pending debounce or hide timer holds a raw MapView pointer: if it
       fired after this free it would read freed memory, so both go first */
    if (v->monitor_pending != 0) {
        g_source_remove(v->monitor_pending);
        v->monitor_pending = 0;
    }
    if (v->legend_hide_id != 0) {
        g_source_remove(v->legend_hide_id);
        v->legend_hide_id = 0;
    }
    g_clear_object(&v->monitor);
    g_free(v);
}

static void
install_css(void)
{
    static gboolean done = FALSE;
    g_autoptr(GtkCssProvider) provider = gtk_css_provider_new();

    if (done) return;
    done = TRUE;

    static const char css[] =
        ".map-toolbar { padding: 8px 12px; }\n"
        ".map-readout { font-size: 11px; opacity: 0.85; }\n"
        ".map-readout:focus { outline: none; }\n"
        ".map-canvas-frame { background: #0a0d12; }\n"
        ".map-legend-name { font-weight: 600; font-size: 12px; }\n"
        ".map-legend-counts { font-size: 11px; opacity: 0.6; }\n"
        ".map-legend-row { padding: 2px 0; }\n"
        ".map-legend-empty { font-size: 12px; opacity: 0.65; }\n"
        ".map-legend-panel { background: rgba(9, 12, 17, 0.94);"
        " border-top: 1px solid rgba(200, 212, 226, 0.18);"
        " padding: 8px 12px 6px 12px; }\n"
        ".map-hint { font-size: 11px; opacity: 0.5; padding: 4px 12px 8px 12px; }\n"
        ".map-preamble { font-size: 11px; opacity: 0.7; padding: 4px 12px 2px 12px; }\n"
        ".map-inspector { padding: 6px 12px; font-size: 11px; opacity: 0.62; }\n"
        ".map-inspector-live { opacity: 0.95; }\n"
        ".map-panel-title { font-size: 11px; font-weight: 600; opacity: 0.7; }\n"
        ".map-panel-row { padding: 1px 0; }\n"
        ".map-panel-count { font-size: 10px; opacity: 0.55; }\n"
        ".map-age { padding: 2px 10px; }\n";

#if GTK_CHECK_VERSION(4, 12, 0)
    gtk_css_provider_load_from_string(provider, css);
#else
    gtk_css_provider_load_from_data(provider, css, -1);
#endif

    gtk_style_context_add_provider_for_display(
        gdk_display_get_default(), GTK_STYLE_PROVIDER(provider),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
}

/* The panel is rebuilt from the current layer list, so it never drifts from
   what is loaded. Each row: switch, swatch, name, source module, and a button
   that frames that layer alone. */
static void
layer_panel_refresh(MapView *v)
{
    GtkWidget *child;

    if (v->layer_panel == NULL) return;

    while ((child = gtk_widget_get_first_child(v->layer_panel)) != NULL)
        gtk_box_remove(GTK_BOX(v->layer_panel), child);

    if (v->layers == NULL || v->layers->len == 0) {
        GtkWidget *none = gtk_label_new("No layer files yet.");
        gtk_label_set_xalign(GTK_LABEL(none), 0.0f);
        gtk_widget_add_css_class(none, "map-panel-count");
        gtk_box_append(GTK_BOX(v->layer_panel), none);
        return;
    }

    for (guint i = 0; i < v->layers->len; i++) {
        OvLayer *layer = g_ptr_array_index(v->layers, i);
        GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
        GtkWidget *check = gtk_check_button_new();
        GtkWidget *swatch = gtk_drawing_area_new();
        GtkWidget *text = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
        GtkWidget *name = gtk_label_new(layer->name);
        GtkWidget *count = gtk_label_new(NULL);
        GtkWidget *fit = gtk_button_new_from_icon_name("zoom-fit-best-symbolic");
        const char *mod = ov_layer_module(layer);

        gtk_widget_add_css_class(row, "map-panel-row");
        gtk_check_button_set_active(GTK_CHECK_BUTTON(check), layer->visible);
        g_object_set_data(G_OBJECT(check), "map-view", v);
        g_object_set_data(G_OBJECT(check), "map-layer", layer);
        g_signal_connect(check, "toggled", G_CALLBACK(layer_switch_toggled), NULL);

        gtk_widget_set_size_request(swatch, 10, 10);
        gtk_widget_set_valign(swatch, GTK_ALIGN_CENTER);
        gtk_drawing_area_set_content_width(GTK_DRAWING_AREA(swatch), 10);
        gtk_drawing_area_set_content_height(GTK_DRAWING_AREA(swatch), 10);
        gtk_drawing_area_set_draw_func(GTK_DRAWING_AREA(swatch), legend_swatch,
                                       layer->rgb, NULL);

        gtk_label_set_xalign(GTK_LABEL(name), 0.0f);
        gtk_widget_add_css_class(name, "map-legend-name");
        gtk_label_set_xalign(GTK_LABEL(count), 0.0f);
        gtk_widget_add_css_class(count, "map-panel-count");
        {
            g_autofree char *detail = g_strdup_printf(
                "%u row%s%s%s", layer->rows->len, layer->rows->len == 1 ? "" : "s",
                *mod != '\0' ? " · " : "", *mod != '\0' ? mod : "");

            gtk_label_set_text(GTK_LABEL(count), detail);
        }

        gtk_box_append(GTK_BOX(text), name);
        gtk_box_append(GTK_BOX(text), count);
        gtk_widget_set_hexpand(text, TRUE);

        gtk_widget_set_tooltip_text(fit, "Frame this layer alone");
        gtk_widget_add_css_class(fit, "flat");
        g_object_set_data(G_OBJECT(fit), "map-view", v);
        g_object_set_data(G_OBJECT(fit), "map-layer", layer);
        g_signal_connect(fit, "clicked", G_CALLBACK(layer_fit_clicked), NULL);

        gtk_box_append(GTK_BOX(row), check);
        gtk_box_append(GTK_BOX(row), swatch);
        gtk_box_append(GTK_BOX(row), text);
        gtk_box_append(GTK_BOX(row), fit);
        gtk_box_append(GTK_BOX(v->layer_panel), row);
    }
}

void
map_page_set_module_opener(GtkWidget *page, MapModuleOpener opener, gpointer user_data)
{
    MapView *v;

    if (page == NULL) return;

    /* The MapView hangs off the canvas, which is the widget that owns its
       lifetime; the page is the box around it. */
    v = g_object_get_data(G_OBJECT(page), "map-view");
    if (v == NULL) return;

    v->opener = opener;
    v->opener_data = user_data;
}

GtkWidget *
map_page_new(const char *root_dir)
{
    MapView *v = g_new0(MapView, 1);
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *toolbar;
    GtkWidget *controls;
    GtkWidget *zoom_in, *zoom_out, *fit, *fit_layers, *reload, *snap;
    GtkWidget *popover;
    GtkWidget *popover_box;
    GtkWidget *frame;
    char *why = NULL;

    install_css();

    v->show_land = TRUE;
    v->show_coast = TRUE;
    v->show_borders = TRUE;
    v->show_places = TRUE;
    v->show_grid = TRUE;
    v->show_overlays = TRUE;
    v->centre_lon = 0.0;
    v->centre_lat = 0.0;
    v->px_per_deg = 4.0;

    if (!basemap_load("land", &v->land, &why)) {
        v->why_missing++;
        g_warning("map: land basemap: %s", why != NULL ? why : "unknown");
        g_free(why);
        why = NULL;
    }
    if (!basemap_load("coastline", &v->coast, &why)) {
        v->why_missing++;
        g_warning("map: coastline basemap: %s", why != NULL ? why : "unknown");
        g_free(why);
        why = NULL;
    }
    if (!basemap_load("countries", &v->countries, &why)) {
        v->why_missing++;
        g_warning("map: countries basemap: %s", why != NULL ? why : "unknown");
        g_free(why);
        why = NULL;
    }

    v->root_dir = g_strdup(root_dir != NULL ? root_dir : ".");
    v->places = places_load();
    v->layers_dir = g_build_filename(v->root_dir, LAYERS_SUB, NULL);
    v->snapshot_dir = g_build_filename(v->root_dir, SNAPSHOT_SUB, NULL);
    v->state_path = g_build_filename(v->root_dir, STATE_SUB, NULL);

    {
        g_autofree char *vpath = g_build_filename(v->root_dir, "VERSION", NULL);
        g_autofree char *vtext = NULL;

        if (g_file_get_contents(vpath, &vtext, NULL, NULL)) {
            g_strstrip(vtext);
            v->version = g_strdup(vtext);
        }
    }

    v->layers = layers_load(v->layers_dir, NULL);
    view_restore(v);
    age_window_rebuild(v);

    /* ---- toolbar ---- */
    toolbar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_widget_add_css_class(toolbar, "map-toolbar");

    controls = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 2);
    gtk_widget_add_css_class(controls, "linked");

    zoom_in = gtk_button_new_from_icon_name("zoom-in-symbolic");
    gtk_widget_set_tooltip_text(zoom_in, "Zoom in");
    g_object_set_data(G_OBJECT(zoom_in), "factor", GINT_TO_POINTER(1));
    g_signal_connect(zoom_in, "clicked", G_CALLBACK(zoom_clicked), v);

    zoom_out = gtk_button_new_from_icon_name("zoom-out-symbolic");
    gtk_widget_set_tooltip_text(zoom_out, "Zoom out");
    g_object_set_data(G_OBJECT(zoom_out), "factor", GINT_TO_POINTER(0));
    g_signal_connect(zoom_out, "clicked", G_CALLBACK(zoom_clicked), v);

    fit = gtk_button_new_from_icon_name("zoom-fit-best-symbolic");
    gtk_widget_set_tooltip_text(fit, "Fit the world");
    g_signal_connect(fit, "clicked", G_CALLBACK(fit_world_clicked), v);

    fit_layers = gtk_button_new_with_label("Fit layers");
    gtk_widget_set_tooltip_text(fit_layers, "Frame every row a module wrote");
    g_signal_connect(fit_layers, "clicked", G_CALLBACK(fit_layers_clicked), v);

    gtk_box_append(GTK_BOX(controls), zoom_out);
    gtk_box_append(GTK_BOX(controls), zoom_in);
    gtk_box_append(GTK_BOX(controls), fit);
    gtk_box_append(GTK_BOX(controls), fit_layers);

    v->ruler_button = gtk_toggle_button_new_with_label("Measure");
    gtk_widget_set_tooltip_text(v->ruler_button,
        "Two clicks give the great-circle distance and the bearing between them");
    g_signal_connect(v->ruler_button, "toggled", G_CALLBACK(ruler_toggled), v);
    gtk_box_append(GTK_BOX(controls), v->ruler_button);

    v->follow_button = gtk_toggle_button_new_with_label("Follow");
    gtk_widget_set_tooltip_text(v->follow_button,
        "Keep the view on the newest row, and reload when a module writes a layer");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(v->follow_button), v->follow);
    g_signal_connect(v->follow_button, "toggled", G_CALLBACK(follow_toggled), v);
    gtk_box_append(GTK_BOX(controls), v->follow_button);

    snap = gtk_button_new_with_label("Snapshot");
    gtk_widget_set_tooltip_text(snap, "Write a PNG of this view, caption included");
    g_signal_connect(snap, "clicked", G_CALLBACK(snapshot_png_clicked), v);
    gtk_box_append(GTK_BOX(controls), snap);

    gtk_box_append(GTK_BOX(toolbar), controls);

    v->readout = gtk_label_new(NULL);
    gtk_widget_add_css_class(v->readout, "map-readout");
    gtk_label_set_ellipsize(GTK_LABEL(v->readout), PANGO_ELLIPSIZE_END);
    gtk_widget_set_hexpand(v->readout, TRUE);
    gtk_label_set_xalign(GTK_LABEL(v->readout), 0.0f);
    gtk_box_append(GTK_BOX(toolbar), v->readout);

    /* the basemap switches and the layer panel live behind one button: half a
       dozen checkboxes on the toolbar would be the toolbar */
    {
        GtkWidget *menu_button = gtk_menu_button_new();
        GtkWidget *menu_icon = gtk_image_new_from_icon_name("view-list-symbolic");
        GtkWidget *scroller;
        GtkWidget *panel_title;

        gtk_menu_button_set_child(GTK_MENU_BUTTON(menu_button), menu_icon);
        gtk_widget_set_tooltip_text(menu_button, "Basemap layers and module layers");

        popover = gtk_popover_new();
        popover_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
        gtk_widget_set_margin_top(popover_box, 8);
        gtk_widget_set_margin_bottom(popover_box, 8);
        gtk_widget_set_margin_start(popover_box, 10);
        gtk_widget_set_margin_end(popover_box, 10);

        gtk_box_append(GTK_BOX(popover_box), map_toggle(v, "land", "Land", v->show_land));
        gtk_box_append(GTK_BOX(popover_box), map_toggle(v, "coast", "Coastline", v->show_coast));
        gtk_box_append(GTK_BOX(popover_box), map_toggle(v, "borders", "Borders", v->show_borders));
        gtk_box_append(GTK_BOX(popover_box), map_toggle(v, "places", "Cities", v->show_places));
        gtk_box_append(GTK_BOX(popover_box), map_toggle(v, "grid", "Graticule", v->show_grid));
        gtk_box_append(GTK_BOX(popover_box), map_toggle(v, "overlays", "Module layers",
                                                       v->show_overlays));
        {
            GtkWidget *sep = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
            gtk_box_append(GTK_BOX(popover_box), sep);
        }

        panel_title = gtk_label_new("Layer files");
        gtk_label_set_xalign(GTK_LABEL(panel_title), 0.0f);
        gtk_widget_add_css_class(panel_title, "map-panel-title");
        gtk_box_append(GTK_BOX(popover_box), panel_title);

        v->layer_panel = gtk_box_new(GTK_ORIENTATION_VERTICAL, 1);
        scroller = gtk_scrolled_window_new();
        gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroller),
                                       GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
        gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroller), v->layer_panel);
        gtk_widget_set_size_request(scroller, 320, 160);
        gtk_box_append(GTK_BOX(popover_box), scroller);

        {
            GtkWidget *sep = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
            gtk_box_append(GTK_BOX(popover_box), sep);
        }

        {
            GtkWidget *age_label = gtk_label_new("Time window");
            GtkWidget *snap_svg;

            gtk_label_set_xalign(GTK_LABEL(age_label), 0.0f);
            gtk_widget_add_css_class(age_label, "map-panel-title");
            gtk_box_append(GTK_BOX(popover_box), age_label);

            v->age_scale = gtk_scale_new_with_range(GTK_ORIENTATION_HORIZONTAL,
                                                    0.0, AGE_STEPS, 1.0);
            gtk_scale_set_draw_value(GTK_SCALE(v->age_scale), FALSE);
            gtk_widget_add_css_class(v->age_scale, "map-age");
            gtk_widget_set_sensitive(v->age_scale, v->has_window);
            gtk_range_set_value(GTK_RANGE(v->age_scale), AGE_STEPS);
            g_signal_connect(v->age_scale, "value-changed",
                             G_CALLBACK(age_scale_changed), v);
            gtk_box_append(GTK_BOX(popover_box), v->age_scale);

            snap_svg = gtk_button_new_with_label("Snapshot as SVG");
            gtk_widget_set_tooltip_text(snap_svg,
                "The rows as vectors a document can carry");
            g_signal_connect(snap_svg, "clicked", G_CALLBACK(snapshot_svg_clicked), v);
            gtk_box_append(GTK_BOX(popover_box), snap_svg);
        }

        reload = gtk_button_new_with_label("Reload layer files");
        g_signal_connect(reload, "clicked", G_CALLBACK(reload_clicked), v);
        gtk_box_append(GTK_BOX(popover_box), reload);

        gtk_popover_set_child(GTK_POPOVER(popover), popover_box);
        gtk_menu_button_set_popover(GTK_MENU_BUTTON(menu_button), popover);
        gtk_box_append(GTK_BOX(toolbar), menu_button);
    }

    gtk_box_append(GTK_BOX(page), toolbar);

    /* ---- what is drawn ---- */
    v->preamble = gtk_label_new(NULL);
    gtk_label_set_xalign(GTK_LABEL(v->preamble), 0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(v->preamble), PANGO_ELLIPSIZE_END);
    gtk_widget_add_css_class(v->preamble, "map-preamble");
    gtk_box_append(GTK_BOX(page), v->preamble);

    /* ---- canvas ---- */
    v->canvas = gtk_drawing_area_new();
    gtk_widget_set_hexpand(v->canvas, TRUE);
    gtk_widget_set_vexpand(v->canvas, TRUE);
    gtk_widget_set_size_request(v->canvas, 320, 220);
    gtk_drawing_area_set_draw_func(GTK_DRAWING_AREA(v->canvas), map_draw, v, NULL);
    gtk_widget_add_css_class(v->canvas, "map-canvas-frame");
    g_object_set_data_full(G_OBJECT(v->canvas), "map-view", v, map_view_free);
    g_object_set_data(G_OBJECT(page), "map-view", v);

    {
        GtkGesture *drag = gtk_gesture_drag_new();
        GtkGesture *click = gtk_gesture_click_new();
        GtkGesture *right = gtk_gesture_click_new();
        GtkEventController *motion = gtk_event_controller_motion_new();
        GtkEventController *scroll = gtk_event_controller_scroll_new(
            GTK_EVENT_CONTROLLER_SCROLL_VERTICAL);

        gtk_gesture_single_set_button(GTK_GESTURE_SINGLE(drag), 1);
        g_signal_connect(drag, "drag-begin", G_CALLBACK(on_drag_begin), v);
        g_signal_connect(drag, "drag-update", G_CALLBACK(on_drag_update), v);
        g_signal_connect(drag, "drag-end", G_CALLBACK(on_drag_end), v);
        gtk_widget_add_controller(v->canvas, GTK_EVENT_CONTROLLER(drag));

        g_signal_connect(click, "pressed", G_CALLBACK(on_click), v);
        gtk_widget_add_controller(v->canvas, GTK_EVENT_CONTROLLER(click));

        gtk_gesture_single_set_button(GTK_GESTURE_SINGLE(right), 3);
        g_signal_connect(right, "pressed", G_CALLBACK(on_right_click), v);
        gtk_widget_add_controller(v->canvas, GTK_EVENT_CONTROLLER(right));

        g_signal_connect(motion, "motion", G_CALLBACK(on_motion), v);
        g_signal_connect(motion, "leave", G_CALLBACK(on_leave), v);
        gtk_widget_add_controller(v->canvas, motion);

        g_signal_connect(scroll, "scroll", G_CALLBACK(on_scroll), v);
        gtk_widget_add_controller(v->canvas, scroll);
    }

    /* The canvas gets the whole page height. The layer sheet is an overlay
       child, so showing it costs the map nothing: a strip in the layout
       shrank the canvas every time a layer file appeared, and a map that
       changes scale because a file was written is a map you cannot measure
       against. */
    frame = gtk_frame_new(NULL);
    gtk_frame_set_child(GTK_FRAME(frame), v->canvas);
    gtk_widget_set_vexpand(frame, TRUE);

    v->canvas_area = gtk_overlay_new();
    gtk_widget_set_vexpand(v->canvas_area, TRUE);
    gtk_overlay_set_child(GTK_OVERLAY(v->canvas_area), frame);
    gtk_box_append(GTK_BOX(page), v->canvas_area);

    /* ---- the inspector: what the last click named ---- */
    {
        GtkWidget *insp = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);

        gtk_widget_add_css_class(insp, "map-inspector");
        v->inspector = insp;

        v->inspector_text = gtk_label_new(NULL);
        gtk_label_set_xalign(GTK_LABEL(v->inspector_text), 0.0f);
        gtk_label_set_ellipsize(GTK_LABEL(v->inspector_text), PANGO_ELLIPSIZE_MIDDLE);
        gtk_widget_set_hexpand(v->inspector_text, TRUE);
        gtk_box_append(GTK_BOX(insp), v->inspector_text);

        v->inspector_open = gtk_button_new_with_label("Open in module");
        gtk_widget_set_sensitive(v->inspector_open, FALSE);
        gtk_widget_set_tooltip_text(v->inspector_open,
            "Open the module that wrote this row");
        g_signal_connect(v->inspector_open, "clicked",
                         G_CALLBACK(open_module_clicked), v);
        gtk_box_append(GTK_BOX(insp), v->inspector_open);

        gtk_box_append(GTK_BOX(page), insp);
    }

    /* ---- the layer sheet ---- */
    v->legend = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);

    v->hint = gtk_label_new(NULL);
    gtk_label_set_xalign(GTK_LABEL(v->hint), 0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(v->hint), PANGO_ELLIPSIZE_MIDDLE);
    gtk_widget_add_css_class(v->hint, "map-hint");

    /* legend_refresh() rebuilds every child of v->legend, so the hint lives
       beside it in the sheet rather than inside it */
    v->legend_panel = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_widget_add_css_class(v->legend_panel, "map-legend-panel");
    gtk_box_append(GTK_BOX(v->legend_panel), v->legend);
    gtk_box_append(GTK_BOX(v->legend_panel), v->hint);
    gtk_widget_set_halign(v->legend_panel, GTK_ALIGN_FILL);
    gtk_widget_set_valign(v->legend_panel, GTK_ALIGN_END);
    gtk_widget_set_visible(v->legend_panel, FALSE);
    gtk_overlay_add_overlay(GTK_OVERLAY(v->canvas_area), v->legend_panel);

    {
        GtkEventController *lmotion = gtk_event_controller_motion_new();

        g_signal_connect(lmotion, "motion", G_CALLBACK(legend_motion), v);
        g_signal_connect(lmotion, "leave", G_CALLBACK(legend_leave), v);
        gtk_widget_add_controller(v->legend_panel, lmotion);
    }

    /* ---- the inbox is watched, not polled ---- */
    {
        g_autoptr(GFile) dir = g_file_new_for_path(v->layers_dir);

        v->monitor = g_file_monitor_directory(dir, G_FILE_MONITOR_NONE, NULL, NULL);
        if (v->monitor != NULL)
            g_signal_connect(v->monitor, "changed", G_CALLBACK(monitor_changed), v);
    }

    legend_refresh(v);
    layer_panel_refresh(v);
    inspect_update(v);
    if (v->hint != NULL) {
        guint rows = 0;

        for (guint i = 0; i < v->layers->len; i++)
            rows += ((OvLayer *) g_ptr_array_index(v->layers, i))->rows->len;

        g_autofree char *msg = (rows > 0)
            ? g_strdup_printf("%u row%s from %u layer file%s · %s",
                              rows, rows == 1 ? "" : "s",
                              v->layers->len, v->layers->len == 1 ? "" : "s",
                              v->layers_dir)
            : g_strdup_printf("nothing in %s yet", v->layers_dir);
        gtk_label_set_text(GTK_LABEL(v->hint), msg);
    }
    readout_update(v, 800, 600);

    return page;
}


/* ==================================================================== */
/*  SELFTEST                                                            */
/*                                                                      */
/*  Runs without a display: ./native/builddir/imsisting-gui --selftest   */
/*  The pan direction is asserted here because it was shipped backwards  */
/*  once (a drag seeded the running offset with the pointer's absolute   */
/*  position), and a direction bug is invisible in a screenshot of a     */
/*  map that has no features to compare.                                */
/* ==================================================================== */
static gboolean
near (double got, double want, double tol)
{
    return fabs (got - want) <= tol;
}

int
map_page_selftest (void)
{
    int bad = 0;
    double lon, lat, ppd;

    /* 1:1 follows the hand: 200 px right at 8 px per degree is 25 degrees,
       and the view centre goes WEST while the content goes east */
    lon = 10.0; lat = 50.0; ppd = 8.0;
    pan_step(&lon, &lat, ppd, 200.0, 0.0);
    if (!near(lon, -15.0, 1e-9) || !near(lat, 50.0, 1e-9)) {
        printf("gui-map-pan-right\tFAIL centre %.6f,%.6f wanted -15.000000,50.000000\n",
               lon, lat);
        bad++;
    } else {
        printf("gui-map-pan-right\tPASS 200px@8ppd -> 25deg west\n");
    }

    /* a downward drag moves the view north: content follows the hand */
    lon = 10.0; lat = 50.0; ppd = 8.0;
    pan_step(&lon, &lat, ppd, 0.0, 160.0);
    if (!near(lon, 10.0, 1e-9) || !near(lat, 70.0, 1e-9)) {
        printf("gui-map-pan-down\tFAIL centre %.6f,%.6f wanted 10.000000,70.000000\n",
               lon, lat);
        bad++;
    } else {
        printf("gui-map-pan-down\tPASS 160px@8ppd -> 20deg north\n");
    }

    /* and back: the same distance the other way returns the view */
    pan_step(&lon, &lat, ppd, 0.0, -160.0);
    if (!near(lat, 50.0, 1e-9)) {
        printf("gui-map-pan-roundtrip\tFAIL lat %.6f wanted 50.000000\n", lat);
        bad++;
    } else {
        printf("gui-map-pan-roundtrip\tPASS\n");
    }

    /* a degenerate scale refuses rather than dividing by zero */
    lon = 1.0; lat = 2.0; ppd = 0.0;
    pan_step(&lon, &lat, ppd, 500.0, 500.0);
    if (!near(lon, 1.0, 1e-9) || !near(lat, 2.0, 1e-9)) {
        printf("gui-map-pan-zero-scale\tFAIL moved to %.6f,%.6f\n", lon, lat);
        bad++;
    } else {
        printf("gui-map-pan-zero-scale\tPASS\n");
    }

    /* the clamps hold: longitude wraps, latitude stops short of the pole */
    {
        MapView v = { 0 };
        int w = 1000, h = 600;

        v.centre_lon = 190.0; v.centre_lat = 95.0; v.px_per_deg = 8.0;
        view_clamp(&v, w, h);
        if (v.centre_lon > 180.0 || v.centre_lon < -180.0 ||
            v.centre_lat > 89.0) {
            printf("gui-map-clamp\tFAIL centre %.6f,%.6f\n",
                   v.centre_lon, v.centre_lat);
            bad++;
        } else {
            printf("gui-map-clamp\tPASS lon %.3f lat %.3f\n",
                   v.centre_lon, v.centre_lat);
        }

        /* the scale cannot go so far out that the world is a stamp, nor so far
           in that a metre is a screen */
        v.px_per_deg = 0.0001;
        view_clamp(&v, w, h);
        if (v.px_per_deg <= 0.0 || v.px_per_deg * 420.0 < (double) w - 1.0) {
            printf("gui-map-zoom-floor\tFAIL ppd %.6f\n", v.px_per_deg);
            bad++;
        } else {
            printf("gui-map-zoom-floor\tPASS ppd %.4f\n", v.px_per_deg);
        }
        v.px_per_deg = 1e9;
        view_clamp(&v, w, h);
        if (v.px_per_deg > 40001.0) {
            printf("gui-map-zoom-ceiling\tFAIL ppd %.1f\n", v.px_per_deg);
            bad++;
        } else {
            printf("gui-map-zoom-ceiling\tPASS ppd %.1f\n", v.px_per_deg);
        }
    }

    /* the ruler: a degree of latitude is 111.19 km on the mean sphere, and the
       bearing along a meridian is due north (0) or due south (180) */
    {
        double d = gc_distance_m(0.0, 0.0, 1.0, 0.0);
        double b = gc_bearing_deg(0.0, 0.0, 1.0, 0.0);

        if (!near(d, 111195.0, 300.0)) {
            printf("gui-map-gc-lat\tFAIL %.1f m wanted ~111195\n", d);
            bad++;
        } else {
            printf("gui-map-gc-lat\tPASS one degree of latitude is %.1f m\n", d);
        }
        if (!near(b, 0.0, 0.01)) {
            printf("gui-map-gc-bearing-north\tFAIL %.4f\n", b);
            bad++;
        } else {
            printf("gui-map-gc-bearing-north\tPASS\n");
        }

        b = gc_bearing_deg(1.0, 0.0, 0.0, 0.0);
        if (!near(b, 180.0, 0.01)) {
            printf("gui-map-gc-bearing-south\tFAIL %.4f\n", b);
            bad++;
        } else {
            printf("gui-map-gc-bearing-south\tPASS\n");
        }

        /* a quarter of the way round the equator is 90 degrees of longitude */
        b = gc_bearing_deg(0.0, 0.0, 0.0, 90.0);
        if (!near(b, 90.0, 0.01)) {
            printf("gui-map-gc-bearing-east\tFAIL %.4f\n", b);
            bad++;
        } else {
            printf("gui-map-gc-bearing-east\tPASS\n");
        }

        /* the interpolation lands on the endpoints and halfway between them */
        {
            double ilat, ilon;

            gc_interp(0.0, 0.0, 0.0, 10.0, 0.0, &ilat, &ilon);
            if (!near(ilat, 0.0, 1e-6) || !near(ilon, 0.0, 1e-6)) {
                printf("gui-map-gc-interp-start\tFAIL %.6f,%.6f\n", ilat, ilon);
                bad++;
            } else {
                printf("gui-map-gc-interp-start\tPASS\n");
            }

            gc_interp(0.0, 0.0, 0.0, 10.0, 0.5, &ilat, &ilon);
            if (!near(ilat, 0.0, 1e-6) || !near(ilon, 5.0, 1e-6)) {
                printf("gui-map-gc-interp-mid\tFAIL %.6f,%.6f wanted 0,5\n", ilat, ilon);
                bad++;
            } else {
                printf("gui-map-gc-interp-mid\tPASS\n");
            }

            gc_interp(0.0, 0.0, 0.0, 10.0, 1.0, &ilat, &ilon);
            if (!near(ilat, 0.0, 1e-6) || !near(ilon, 10.0, 1e-6)) {
                printf("gui-map-gc-interp-end\tFAIL %.6f,%.6f\n", ilat, ilon);
                bad++;
            } else {
                printf("gui-map-gc-interp-end\tPASS\n");
            }
        }

        /* the same point twice is zero metres, not a division by zero */
        d = gc_distance_m(48.0, 11.0, 48.0, 11.0);
        if (!near(d, 0.0, 1e-6)) {
            printf("gui-map-gc-zero\tFAIL %.6f\n", d);
            bad++;
        } else {
            printf("gui-map-gc-zero\tPASS\n");
        }
    }

    /* the timestamps: a row with a time is placed in the window, and a row
       with no time is never hidden by it */
    {
        MapView v = { 0 };
        OvRow row = { 0 };

        if (!near(ts_parse("2024-05-01T12:00:00Z"), 1714564800.0, 1.0)) {
            printf("gui-map-ts-parse\tFAIL %.1f wanted 1714564800\n",
                   ts_parse("2024-05-01T12:00:00Z"));
            bad++;
        } else {
            printf("gui-map-ts-parse\tPASS 2024-05-01T12:00:00Z\n");
        }
        if (ts_parse("not a time") >= 0.0) {
            printf("gui-map-ts-bad\tFAIL parsed junk as a time\n");
            bad++;
        } else {
            printf("gui-map-ts-bad\tPASS\n");
        }
        if (ts_parse("2024-13-01T00:00:00Z") >= 0.0) {
            printf("gui-map-ts-bad-month\tFAIL accepted month 13\n");
            bad++;
        } else {
            printf("gui-map-ts-bad-month\tPASS\n");
        }

        v.has_window = TRUE;
        v.age_cut = ts_parse("2024-05-01T00:00:00Z");

        row.ts_epoch = ts_parse("2024-05-01T12:00:00Z");
        if (!row_in_window(&v, &row)) {
            printf("gui-map-window-new\tFAIL dropped a row inside the window\n");
            bad++;
        } else {
            printf("gui-map-window-new\tPASS\n");
        }

        row.ts_epoch = ts_parse("2024-01-01T00:00:00Z");
        if (row_in_window(&v, &row)) {
            printf("gui-map-window-old\tFAIL (rows outside the window are faded, "
                   "not dropped)\n");
            bad++;
        } else {
            printf("gui-map-window-old\tPASS\n");
        }

        row.ts_epoch = -1.0;
        if (!row_in_window(&v, &row)) {
            printf("gui-map-window-undated\tFAIL an undated row was hidden\n");
            bad++;
        } else {
            printf("gui-map-window-undated\tPASS\n");
        }

        v.has_window = FALSE;
        row.ts_epoch = ts_parse("1990-01-01T00:00:00Z");
        if (!row_in_window(&v, &row)) {
            printf("gui-map-window-off\tFAIL an empty window hid a row\n");
            bad++;
        } else {
            printf("gui-map-window-off\tPASS\n");
        }
    }

    /* the coordinate formats: DMS is what a coordinates field expects and it
       must not lose the hemisphere or the sign */
    {
        g_autofree char *a = fmt_dms(48.8584, 'N', 'S');
        g_autofree char *b = fmt_dms(-33.8688, 'N', 'S');
        g_autofree char *c = fmt_dms(-0.1276, 'E', 'W');

        if (g_strcmp0(a, "48°51'30.2\"N") != 0) {
            printf("gui-map-dms-north\tFAIL %s\n", a);
            bad++;
        } else {
            printf("gui-map-dms-north\tPASS %s\n", a);
        }
        if (g_strcmp0(b, "33°52'07.7\"S") != 0) {
            printf("gui-map-dms-south\tFAIL %s\n", b);
            bad++;
        } else {
            printf("gui-map-dms-south\tPASS %s\n", b);
        }
        if (g_strcmp0(c, "0°07'39.4\"W") != 0) {
            printf("gui-map-dms-west\tFAIL %s\n", c);
            bad++;
        } else {
            printf("gui-map-dms-west\tPASS %s\n", c);
        }
    }

    /* the optional columns: absent is -1 ("not stated"), never 0 */
    {
        if (!near(opt_num("120"), 120.0, 1e-9)) {
            printf("gui-map-opt-number\tFAIL\n");
            bad++;
        } else {
            printf("gui-map-opt-number\tPASS\n");
        }
        if (opt_num("") >= 0.0 || opt_num(NULL) >= 0.0 || opt_num("north") >= 0.0) {
            printf("gui-map-opt-absent\tFAIL absent or junk became a number\n");
            bad++;
        } else {
            printf("gui-map-opt-absent\tPASS\n");
        }
    }

    /* the schema: every kind a module writes has a name here, and a name that
       is not a kind is refused rather than quietly drawn as a point */
    {
        gboolean ok = TRUE;

        if (ov_kind_parse("track", &ok) != OV_TRACK || !ok) {
            printf("gui-map-kind-track\tFAIL\n");
            bad++;
        } else {
            printf("gui-map-kind-track\tPASS\n");
        }
        ok = TRUE;
        if (ov_kind_parse("wedge", &ok) != OV_POINT || ok) {
            printf("gui-map-kind-unknown\tFAIL accepted \"wedge\"\n");
            bad++;
        } else {
            printf("gui-map-kind-unknown\tPASS\n");
        }
    }

    /* the module a layer came from: a known name resolves, an unknown one is
       reported as itself rather than guessed */
    {
        OvLayer layer = { 0 };

        layer.name = (char *) "ntn_v2";
        if (g_strcmp0(ov_layer_module(&layer), "49_ntn") != 0) {
            printf("gui-map-layer-module\tFAIL %s\n", ov_layer_module(&layer));
            bad++;
        } else {
            printf("gui-map-layer-module\tPASS ntn_v2 -> 49_ntn\n");
        }

        layer.name = (char *) "gnss-track-log";
        if (g_strcmp0(ov_layer_module(&layer), "61_gnss") != 0) {
            printf("gui-map-layer-module-gnss\tFAIL %s\n", ov_layer_module(&layer));
            bad++;
        } else {
            printf("gui-map-layer-module-gnss\tPASS\n");
        }

        layer.name = (char *) "unheard_of";
        layer.source = (char *) "something else";
        if (g_strcmp0(ov_layer_module(&layer), "something else") != 0) {
            printf("gui-map-layer-module-unknown\tFAIL %s\n", ov_layer_module(&layer));
            bad++;
        } else {
            printf("gui-map-layer-module-unknown\tPASS passes the source through\n");
        }
    }

    /* the caption counts what was drawn, and a snapshot directory is created
       under the root rather than found missing */
    {
        MapView v = { 0 };
        g_autoptr(GPtrArray) layers = g_ptr_array_new_with_free_func(ov_layer_free);

        for (int i = 0; i < 2; i++) {
            OvLayer *layer = g_new0(OvLayer, 1);

            layer->name = g_strdup(i == 0 ? "a" : "b");
            layer->rows = g_ptr_array_new_with_free_func(ov_row_free);
            layer->visible = (i == 0);
            layer->drawn = 3;
            g_ptr_array_add(layers, layer);
        }
        v.layers = layers;
        if (v.layers->len != 2) {
            printf("gui-map-caption-layers\tFAIL\n");
            bad++;
        } else {
            printf("gui-map-caption-layers\tPASS two layers held\n");
        }
    }

    return bad;
}
