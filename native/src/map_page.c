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
 */
#include "map_page.h"

#include <cairo.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#define BM_PREFIX   "/com/imsisting/native/basemap/"
#define LAYERS_SUB  "loot/map/layers"
#define EARTH_M_PER_DEG 111320.0

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

typedef enum { OV_POINT, OV_RING, OV_CIRCLE, OV_AREA } OvKind;

typedef struct {
    OvKind  kind;
    char   *label;
    char   *key;
    char   *source;
    double  lat, lon;
    double  radius_m;
} OvRow;

typedef struct {
    char      *name;         /* file stem, the layer's identity */
    double     rgb[3];
    char      *source;       /* first non-empty `source` column seen */
    GPtrArray *rows;         /* OvRow* */
    guint      points, rings, circles, areas;
} OvLayer;

typedef struct {
    /* data */
    Basemap    land, coast, countries;
    GPtrArray *places;       /* Place* */
    GPtrArray *layers;       /* OvLayer* */
    char      *layers_dir;

    /* view */
    double     centre_lon, centre_lat;
    double     px_per_deg;
    gboolean   placed;

    /* widgets */
    GtkWidget *canvas;
    GtkWidget *readout;
    GtkWidget *legend;
    GtkWidget *hint;

    /* toggles */
    gboolean   show_land, show_coast, show_borders, show_places, show_grid,
               show_overlays;

    /* pointer */
    gboolean   has_cursor;
    double     cursor_x, cursor_y;
    OvRow     *hover;
    OvLayer   *hover_layer;

    /* drag */
    double     drag_last_x, drag_last_y;
    gboolean   dragging;

    guint      why_missing;  /* basemap layers that failed to load */
} MapView;

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
    if (g_strcmp0(s, "area") == 0)   return OV_AREA;
    if (ok != NULL) *ok = FALSE;
    return OV_POINT;
}

/* One file is one layer. The header line is documentation, not a contract to
   be negotiated: `kind label lat lon radius_m key source`. A row that does not
   parse is skipped and counted, because a half-written file (a module killed
   mid-write) must not stop the other layers from drawing. */
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

    g_auto(GStrv) lines = g_strsplit(contents, "\n", -1);
    guint skipped = 0;
    for (guint i = 0; lines[i] != NULL; i++) {
        const char *line = lines[i];
        if (*line == '\0' || *line == '#') continue;
        g_auto(GStrv) f = g_strsplit(line, "\t", 8);
        if (g_strv_length(f) < 5) { skipped++; continue; }
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
        row->radius_m = (f[4] != NULL && *f[4] != '\0') ? g_ascii_strtod(f[4], &end_r) : 0.0;
        row->key    = (f[5] != NULL) ? g_strdup(f[5]) : NULL;
        row->source = (f[6] != NULL && *f[6] != '\0') ? g_strdup(f[6]) : NULL;

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
   thing the module found instead of on the whole planet. */
static void
view_fit_layers(MapView *v, int w, int h)
{
    double min_lat = 90, max_lat = -90, min_lon = 180, max_lon = -180;
    guint n = 0;

    for (guint i = 0; i < v->layers->len; i++) {
        OvLayer *layer = g_ptr_array_index(v->layers, i);
        for (guint j = 0; j < layer->rows->len; j++) {
            OvRow *row = g_ptr_array_index(layer->rows, j);
            double pad = (row->radius_m / EARTH_M_PER_DEG) * 1.15;
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

static void
draw_overlays(cairo_t *cr, const MapView *v, int w, int h, gboolean labels)
{
    for (guint i = 0; i < v->layers->len; i++) {
        OvLayer *layer = g_ptr_array_index(v->layers, i);
        double r = layer->rgb[0], g = layer->rgb[1], b = layer->rgb[2];

        /* uncertainty first, so a pin is never buried under a disc */
        for (guint j = 0; j < layer->rows->len; j++) {
            OvRow *row = g_ptr_array_index(layer->rows, j);
            double x, y;

            if (row->kind != OV_RING && row->kind != OV_CIRCLE) continue;

            project(v, row->lon, row->lat, w, h, &x, &y);
            {
                double r_px = (row->radius_m / EARTH_M_PER_DEG) * v->px_per_deg;
                /* A 1 km ring at world scale is a fifth of a pixel. Rounding it
                   to 4 keeps the mark honest about where it is and lets the
                   legend carry the size the screen cannot. */
                if (r_px < 4.0) r_px = 4.0;
                if (r_px > 100000.0) r_px = 100000.0;

                if (row->kind == OV_CIRCLE) {
                    cairo_set_source_rgba(cr, r, g, b, 0.16);
                    cairo_arc(cr, x, y, r_px, 0, 2 * G_PI);
                    cairo_fill(cr);
                }
                cairo_set_source_rgba(cr, r, g, b, 0.75);
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

        for (guint j = 0; j < layer->rows->len; j++) {
            OvRow *row = g_ptr_array_index(layer->rows, j);
            double x, y;

            if (row->kind != OV_POINT) continue;
            project(v, row->lon, row->lat, w, h, &x, &y);
            if (x < -10 || x > w + 10 || y < -10 || y > h + 10) continue;

            cairo_set_source_rgba(cr, r, g, b, 0.22);
            cairo_arc(cr, x, y, 7.0, 0, 2 * G_PI);
            cairo_fill(cr);
            cairo_set_source_rgba(cr, r, g, b, 1.0);
            cairo_arc(cr, x, y, 3.2, 0, 2 * G_PI);
            cairo_fill(cr);
            cairo_set_source_rgba(cr, 0.04, 0.06, 0.08, 0.9);
            cairo_set_line_width(cr, 1.0);
            cairo_arc(cr, x, y, 3.2, 0, 2 * G_PI);
            cairo_stroke(cr);

            if (labels && row->label != NULL) {
                cairo_set_source_rgba(cr, r, g, b, 0.95);
                cairo_set_font_size(cr, 10.0);
                cairo_move_to(cr, x + 7, y + 3.5);
                cairo_show_text(cr, row->label);
            }
        }
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
        for (guint j = 0; j < layer->rows->len; j++) {
            OvRow *row = g_ptr_array_index(layer->rows, j);
            double x, y, d;

            if (row->kind == OV_AREA) continue;
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

static void
map_draw(GtkDrawingArea *area, cairo_t *cr, int w, int h, gpointer user_data)
{
    MapView *v = user_data;

    (void) area;

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
        draw_overlays(cr, v, w, h, v->px_per_deg > 0.8 || v->layers->len <= 3);

    /* the hovered row, drawn last and flared, so nothing covers it */
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

    draw_scale_bar(cr, v, w, h);
}

/* ------------------------------------------------------------------ */
/*  legend                                                             */
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
                       "drag to pan · scroll to zoom · double-click to fit the world");
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
        g_autofree char *detail = g_strdup_printf(
            "%u point%s · %u ring%s · %u disc%s%s%s%s%s",
            layer->points,  layer->points == 1 ? "" : "s",
            layer->rings,   layer->rings == 1 ? "" : "s",
            layer->circles, layer->circles == 1 ? "" : "s",
            layer->areas > 0 ? " · " : "",
            layer->areas > 0 ? "area rows not drawn (an area has no centre)" : "",
            layer->source != NULL ? " · " : "",
            layer->source != NULL ? layer->source : "");

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
        gtk_label_set_text(GTK_LABEL(counts), detail);

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

static void
layers_reload(MapView *v)
{
    guint rows = 0;

    layers_clear(&v->layers);
    v->layers = layers_load(v->layers_dir, &rows);
    v->hover = NULL;
    v->hover_layer = NULL;
    legend_refresh(v);
    if (v->hint != NULL) {
        g_autofree char *msg = (rows > 0)
            ? g_strdup_printf("%u row%s from %u layer file%s · %s",
                              rows, rows == 1 ? "" : "s",
                              v->layers->len, v->layers->len == 1 ? "" : "s",
                              v->layers_dir)
            : g_strdup_printf("nothing in %s yet", v->layers_dir);
        gtk_label_set_text(GTK_LABEL(v->hint), msg);
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

static void
on_click(GtkGestureClick *gesture, int n_press, double x, double y, gpointer user_data)
{
    MapView *v = user_data;
    int w, h;

    (void) gesture;
    (void) x;
    (void) y;
    if (n_press != 2) return;

    canvas_size(v->canvas, &w, &h);
    view_fit_world(v, w, h);
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
}

static void
fit_world_clicked(GtkButton *button, gpointer user_data)
{
    MapView *v = user_data;
    int w, h;

    (void) button;
    canvas_size(v->canvas, &w, &h);
    view_fit_world(v, w, h);
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
    gtk_widget_queue_draw(v->canvas);
}

static void
reload_clicked(GtkButton *button, gpointer user_data)
{
    (void) button;
    layers_reload(user_data);
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
        ".map-hint { font-size: 11px; opacity: 0.5; padding: 4px 12px 8px 12px; }\n";

#if GTK_CHECK_VERSION(4, 12, 0)
    gtk_css_provider_load_from_string(provider, css);
#else
    gtk_css_provider_load_from_data(provider, css, -1);
#endif

    gtk_style_context_add_provider_for_display(
        gdk_display_get_default(), GTK_STYLE_PROVIDER(provider),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
}

GtkWidget *
map_page_new(const char *root_dir)
{
    MapView *v = g_new0(MapView, 1);
    GtkWidget *page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *toolbar;
    GtkWidget *body;
    GtkWidget *controls;
    GtkWidget *zoom_in, *zoom_out, *fit, *fit_layers, *reload;
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

    v->places = places_load();
    v->layers_dir = g_build_filename(root_dir != NULL ? root_dir : ".",
                                     LAYERS_SUB, NULL);
    v->layers = layers_load(v->layers_dir, NULL);

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

    gtk_box_append(GTK_BOX(toolbar), controls);

    v->readout = gtk_label_new(NULL);
    gtk_widget_add_css_class(v->readout, "map-readout");
    gtk_label_set_ellipsize(GTK_LABEL(v->readout), PANGO_ELLIPSIZE_END);
    gtk_widget_set_hexpand(v->readout, TRUE);
    gtk_label_set_xalign(GTK_LABEL(v->readout), 0.0f);
    gtk_box_append(GTK_BOX(toolbar), v->readout);

    /* the layer switches live behind one button: six checkboxes on the
       toolbar would be the toolbar */
    {
        GtkWidget *menu_button = gtk_menu_button_new();
        GtkWidget *menu_icon = gtk_image_new_from_icon_name("view-list-symbolic");

        gtk_menu_button_set_child(GTK_MENU_BUTTON(menu_button), menu_icon);
        gtk_widget_set_tooltip_text(menu_button, "Basemap layers");

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
        reload = gtk_button_new_with_label("Reload layer files");
        g_signal_connect(reload, "clicked", G_CALLBACK(reload_clicked), v);
        gtk_box_append(GTK_BOX(popover_box), reload);

        gtk_popover_set_child(GTK_POPOVER(popover), popover_box);
        gtk_menu_button_set_popover(GTK_MENU_BUTTON(menu_button), popover);
        gtk_box_append(GTK_BOX(toolbar), menu_button);
    }

    gtk_box_append(GTK_BOX(page), toolbar);

    /* ---- canvas ---- */
    v->canvas = gtk_drawing_area_new();
    gtk_widget_set_hexpand(v->canvas, TRUE);
    gtk_widget_set_vexpand(v->canvas, TRUE);
    gtk_widget_set_size_request(v->canvas, 320, 220);
    gtk_drawing_area_set_draw_func(GTK_DRAWING_AREA(v->canvas), map_draw, v, NULL);
    gtk_widget_add_css_class(v->canvas, "map-canvas-frame");
    g_object_set_data_full(G_OBJECT(v->canvas), "map-view", v, map_view_free);

    {
        GtkGesture *drag = gtk_gesture_drag_new();
        GtkGesture *click = gtk_gesture_click_new();
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

        g_signal_connect(motion, "motion", G_CALLBACK(on_motion), v);
        g_signal_connect(motion, "leave", G_CALLBACK(on_leave), v);
        gtk_widget_add_controller(v->canvas, motion);

        g_signal_connect(scroll, "scroll", G_CALLBACK(on_scroll), v);
        gtk_widget_add_controller(v->canvas, scroll);
    }

    frame = gtk_frame_new(NULL);
    gtk_frame_set_child(GTK_FRAME(frame), v->canvas);
    gtk_widget_set_vexpand(frame, TRUE);
    gtk_box_append(GTK_BOX(page), frame);

    /* ---- legend ---- */
    body = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_widget_set_margin_top(body, 6);
    gtk_widget_set_margin_bottom(body, 2);
    gtk_widget_set_margin_start(body, 12);
    gtk_widget_set_margin_end(body, 12);

    v->legend = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    gtk_box_append(GTK_BOX(body), v->legend);
    gtk_box_append(GTK_BOX(page), body);

    v->hint = gtk_label_new(NULL);
    gtk_label_set_xalign(GTK_LABEL(v->hint), 0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(v->hint), PANGO_ELLIPSIZE_MIDDLE);
    gtk_widget_add_css_class(v->hint, "map-hint");
    gtk_box_append(GTK_BOX(page), v->hint);

    legend_refresh(v);
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

    return bad;
}
