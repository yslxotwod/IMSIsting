/* The Stats page's two pictures: capsule bars and a share ring.

   Why cairo and not widgets. The same information as eleven GtkProgressBars
   was already on the page and it read as a list of thin lines: no per-category
   hue, no share of the whole, and a count column that could only be aligned by
   nesting a box per row. A drawing area gets all three in one pass, plus the
   rounded caps, the 1px baselines and the hover highlight that make the shape
   of the toolkit legible at a glance.

   Nothing here invents data. The ring and the bars are two readings of one
   array -- absolute count and share of the total -- and the centre of the ring
   answers "which one is this" on hover rather than adding a legend too small
   to read. */
#include "stats_chart.h"

#include <math.h>
#include <string.h>

#define CHART_PI 3.14159265358979323846

typedef struct {
    GtkWidget *area;
    StatsChartItem *items;
    guint n;
    double max;
    double total;
    int kind;              /* 0 bars, 1 ring: the pointer has to know the shape */
    int hover;
    char *centre_value;
    char *centre_label;
} ChartData;

static void
set_paint(cairo_t *cr, double r, double g, double b, double a)
{
    cairo_set_source_rgba(cr,
                          CLAMP(r, 0.0, 1.0),
                          CLAMP(g, 0.0, 1.0),
                          CLAMP(b, 0.0, 1.0), a);
}

/* A bar with round ends: two arcs and the straight sides between them. */
static void
capsule(cairo_t *cr, double x, double y, double w, double h)
{
    double r;

    if (w <= 0.0 || h <= 0.0)
        return;

    r = MIN(h / 2.0, w / 2.0);
    cairo_new_sub_path(cr);
    cairo_arc(cr, x + w - r, y + r, r, -CHART_PI / 2.0,  CHART_PI / 2.0);
    cairo_arc(cr, x + r,     y + r, r,  CHART_PI / 2.0,  3.0 * CHART_PI / 2.0);
    cairo_close_path(cr);
}

static PangoLayout *
chart_layout(GtkWidget *widget, const char *text, double points,
             PangoWeight weight, gboolean mono)
{
    PangoFontDescription *desc;
    PangoLayout *layout = gtk_widget_create_pango_layout(widget, text);

    desc = pango_font_description_copy(
        pango_context_get_font_description(gtk_widget_get_pango_context(widget)));
    pango_font_description_set_size(desc, (int) (points * PANGO_SCALE));
    pango_font_description_set_weight(desc, weight);
    if (mono)
        pango_font_description_set_family(desc, "monospace");
    pango_layout_set_font_description(layout, desc);
    pango_font_description_free(desc);
    return layout;
}

static void
text_at(cairo_t *cr, PangoLayout *layout, double x, double y)
{
    cairo_move_to(cr, x, y);
    pango_cairo_show_layout(cr, layout);
}

static void
text_right(cairo_t *cr, PangoLayout *layout, double right, double y)
{
    int w = 0, h = 0;

    pango_layout_get_pixel_size(layout, &w, &h);
    cairo_move_to(cr, right - w, y);
    pango_cairo_show_layout(cr, layout);
    (void) h;
}

static void
text_centre(cairo_t *cr, PangoLayout *layout, double cx, double y)
{
    int w = 0, h = 0;

    pango_layout_get_pixel_size(layout, &w, &h);
    cairo_move_to(cr, cx - w / 2.0, y);
    pango_cairo_show_layout(cr, layout);
    (void) h;
}

static void
chart_data_free(gpointer data)
{
    ChartData *d = data;

    if (d == NULL)
        return;
    for (guint i = 0; i < d->n; i++)
        g_free((char *) d->items[i].label);
    g_free(d->items);
    g_free(d->centre_value);
    g_free(d->centre_label);
    g_free(d);
}

static ChartData *
chart_data_new(GtkWidget *area, const StatsChartItem *items, guint n)
{
    ChartData *d = g_new0(ChartData, 1);

    d->area = area;
    d->n = n;
    d->hover = -1;
    d->items = g_new0(StatsChartItem, n > 0 ? n : 1);
    for (guint i = 0; i < n; i++) {
        d->items[i].label = g_strdup(items[i].label != NULL ? items[i].label : "");
        d->items[i].value = items[i].value;
        d->items[i].r = items[i].r;
        d->items[i].g = items[i].g;
        d->items[i].b = items[i].b;
        d->total += items[i].value;
        if (items[i].value > d->max)
            d->max = items[i].value;
    }
    return d;
}

/* ── bars ─────────────────────────────────────────────────────────────── */

#define BAR_ROW_H   26.0
#define BAR_PAD     12.0
#define BAR_LABEL_W 150.0
#define BAR_COUNT_W 56.0
#define BAR_PCT_W   50.0

static void
draw_bars(GtkDrawingArea *area, cairo_t *cr, int width, int height,
          gpointer user_data)
{
    ChartData *d = user_data;
    GtkWidget *w = GTK_WIDGET(area);
    double bar_x0 = BAR_PAD + BAR_LABEL_W;
    double count_right = width - BAR_PAD - BAR_PCT_W - 12.0;
    double bar_x1 = MAX(bar_x0 + 8.0, count_right - BAR_COUNT_W - 12.0);
    double bar_w = bar_x1 - bar_x0;

    (void) height;

    for (guint i = 0; i < d->n; i++) {
        const StatsChartItem *it = &d->items[i];
        gboolean hot = (int) i == d->hover;
        g_autofree char *count = g_strdup_printf("%.0f", it->value);
        g_autofree char *pct = g_strdup_printf("%.0f%%",
            d->total > 0.0 ? 100.0 * it->value / d->total : 0.0);
        double top = BAR_PAD + (double) i * BAR_ROW_H;
        double frac = d->max > 0.0 ? it->value / d->max : 0.0;
        double fill = MAX(4.0, bar_w * frac);
        double bar_y = top + (BAR_ROW_H - 8.0) / 2.0;
        PangoLayout *name = chart_layout(w, it->label, 9.5,
                                         PANGO_WEIGHT_SEMIBOLD, FALSE);
        PangoLayout *num = chart_layout(w, count, 11.0, PANGO_WEIGHT_BOLD, TRUE);
        PangoLayout *share = chart_layout(w, pct, 9.5,
                                          PANGO_WEIGHT_NORMAL, TRUE);
        int nh = 0, ch = 0, sh = 0;

        pango_layout_get_pixel_size(name, NULL, &nh);
        pango_layout_get_pixel_size(num, NULL, &ch);
        pango_layout_get_pixel_size(share, NULL, &sh);

        if (hot) {
            set_paint(cr, 1.0, 1.0, 1.0, 0.045);
            capsule(cr, BAR_PAD - 6.0, top + 1.0, width - 2.0 * BAR_PAD + 12.0,
                    BAR_ROW_H - 2.0);
            cairo_fill(cr);
        }

        /* Name in its own hue: the bars answer "which category", so the label
           carries the same colour the drawer and the cards already taught. */
        set_paint(cr, it->r, it->g, it->b, hot ? 1.0 : 0.82);
        text_at(cr, name, BAR_PAD, top + (BAR_ROW_H - nh) / 2.0);

        /* Trough first: an empty category still shows its slot. */
        set_paint(cr, 1.0, 1.0, 1.0, 0.055);
        capsule(cr, bar_x0, bar_y, bar_w, 8.0);
        cairo_fill(cr);

        if (frac > 0.0) {
            cairo_pattern_t *grad = cairo_pattern_create_linear(bar_x0, 0.0,
                                                               bar_x0 + fill, 0.0);

            cairo_pattern_add_color_stop_rgba(grad, 0.0,
                MIN(1.0, it->r * 1.10 + 0.06), MIN(1.0, it->g * 1.10 + 0.06),
                MIN(1.0, it->b * 1.10 + 0.06), hot ? 1.0 : 0.9);
            cairo_pattern_add_color_stop_rgba(grad, 1.0,
                it->r * 0.72, it->g * 0.72, it->b * 0.72, hot ? 1.0 : 0.82);
            capsule(cr, bar_x0, bar_y, fill, 8.0);
            cairo_set_source(cr, grad);
            cairo_fill(cr);
            cairo_pattern_destroy(grad);
        }

        set_paint(cr, 0.92, 0.96, 1.0, hot ? 1.0 : 0.9);
        text_right(cr, num, count_right, top + (BAR_ROW_H - ch) / 2.0);
        set_paint(cr, 0.44, 0.48, 0.55, 1.0);
        text_right(cr, share, width - BAR_PAD, top + (BAR_ROW_H - sh) / 2.0);

        g_object_unref(name);
        g_object_unref(num);
        g_object_unref(share);
    }
}

/* ── ring ─────────────────────────────────────────────────────────────── */

static void
draw_donut(GtkDrawingArea *area, cairo_t *cr, int width, int height,
           gpointer user_data)
{
    ChartData *d = user_data;
    GtkWidget *w = GTK_WIDGET(area);
    double cx = width / 2.0;
    double cy = height / 2.0;
    double outer = MIN(width, height) / 2.0 - 8.0;
    double thickness = MAX(14.0, outer * 0.30);
    double radius = outer - thickness / 2.0;
    double angle = -CHART_PI / 2.0;
    const char *big = d->centre_value;
    const char *small = d->centre_label;
    g_autofree char *hover_big = NULL;
    g_autofree char *hover_small = NULL;

    if (outer <= 8.0)
        return;

    /* The slot the ring lives in, so an empty category still reads as a slot
       and not as a broken drawing. */
    cairo_set_line_width(cr, thickness);
    set_paint(cr, 1.0, 1.0, 1.0, 0.045);
    cairo_arc(cr, cx, cy, radius, 0.0, 2.0 * CHART_PI);
    cairo_stroke(cr);

    cairo_set_line_cap(cr, CAIRO_LINE_CAP_ROUND);

    for (guint i = 0; i < d->n; i++) {
        const StatsChartItem *it = &d->items[i];
        double span = d->total > 0.0 ? (it->value / d->total) * 2.0 * CHART_PI : 0.0;
        double a0 = angle;
        double a1 = angle + span;
        gboolean hot = (int) i == d->hover;
        double gap = 0.030;

        angle += span;
        if (span <= 0.0)
            continue;

        /* A gap between neighbours costs the rounded caps their overlap; a
           slice too thin for its own gap keeps a hair of it so it stays
           visible instead of vanishing. */
        if (span > gap * 2.0) {
            a0 += gap / 2.0;
            a1 -= gap / 2.0;
        } else if (span > gap) {
            a0 += gap / 4.0;
            a1 -= gap / 4.0;
        }

        set_paint(cr, it->r, it->g, it->b, hot ? 1.0 : 0.86);
        cairo_set_line_width(cr, hot ? thickness + 5.0 : thickness);
        cairo_arc(cr, cx, cy, radius, a0, a1);
        cairo_stroke(cr);

        if (hot) {
            hover_big = g_strdup_printf("%.0f", it->value);
            hover_small = g_strdup(it->label);
        }
    }

    if (hover_big != NULL) {
        big = hover_big;
        small = hover_small;
    }

    {
        PangoLayout *v = chart_layout(w, big != NULL ? big : "",
                                      26.0, PANGO_WEIGHT_BOLD, TRUE);
        PangoLayout *l = chart_layout(w, small != NULL ? small : "",
                                      8.0, PANGO_WEIGHT_BOLD, FALSE);
        int vh = 0, lh = 0;
        double block, top;

        pango_layout_get_pixel_size(v, NULL, &vh);
        pango_layout_get_pixel_size(l, NULL, &lh);
        block = (double) (vh + lh) + 2.0;
        top = cy - block / 2.0;

        set_paint(cr, 0.92, 0.96, 1.0, 1.0);
        text_centre(cr, v, cx, top);
        set_paint(cr, 0.44, 0.48, 0.55, 1.0);
        text_centre(cr, l, cx, top + (double) vh + 2.0);
        g_object_unref(v);
        g_object_unref(l);
    }
}

/* ── the pointer ──────────────────────────────────────────────────────── */

static int
bars_index(ChartData *d, double x, double y, int width)
{
    int idx;

    if (x < BAR_PAD - 6.0 || x > width - BAR_PAD + 6.0)
        return -1;

    idx = (int) ((y - BAR_PAD) / BAR_ROW_H);
    return (idx >= 0 && (guint) idx < d->n) ? idx : -1;
}

static int
donut_index(ChartData *d, double x, double y, int width, int height)
{
    double cx = width / 2.0;
    double cy = height / 2.0;
    double outer = MIN(width, height) / 2.0 - 8.0;
    double thickness = MAX(14.0, outer * 0.30);
    double radius = outer - thickness / 2.0;
    double dx = x - cx;
    double dy = y - cy;
    double r = sqrt(dx * dx + dy * dy);
    double a;
    double walked = 0.0;

    if (outer <= 8.0 || r < radius - thickness / 2.0 - 4.0 ||
        r > radius + thickness / 2.0 + 4.0)
        return -1;

    a = atan2(dy, dx) + CHART_PI / 2.0;         /* 0 at twelve o'clock */
    if (a < 0.0)
        a += 2.0 * CHART_PI;

    for (guint i = 0; i < d->n; i++) {
        double span = d->total > 0.0
                    ? (d->items[i].value / d->total) * 2.0 * CHART_PI : 0.0;

        walked += span;
        if (a <= walked && span > 0.0)
            return (int) i;
    }
    return -1;
}

static void
chart_motion(GtkEventControllerMotion *controller, double x, double y,
             gpointer user_data)
{
    ChartData *d = user_data;
    int width, height, idx;

    (void) controller;
    if (d->area == NULL)
        return;

    width = gtk_widget_get_width(d->area);
    height = gtk_widget_get_height(d->area);

    /* The two shapes answer the same question with different geometry, so the
       widget carries which one it is rather than guessing from its data. */
    idx = d->kind == 1 ? donut_index(d, x, y, width, height)
                       : bars_index(d, x, y, width);

    if (idx != d->hover) {
        d->hover = idx;
        gtk_widget_queue_draw(d->area);
    }
}

static void
chart_leave(GtkEventControllerMotion *controller, gpointer user_data)
{
    ChartData *d = user_data;

    (void) controller;
    if (d->hover != -1) {
        d->hover = -1;
        if (d->area != NULL)
            gtk_widget_queue_draw(d->area);
    }
}

static void
chart_attach_pointer(GtkWidget *area, ChartData *data)
{
    GtkEventController *motion = gtk_event_controller_motion_new();

    g_signal_connect(motion, "motion", G_CALLBACK(chart_motion), data);
    g_signal_connect(motion, "leave", G_CALLBACK(chart_leave), data);
    gtk_widget_add_controller(area, motion);
}

/* ── constructors ─────────────────────────────────────────────────────── */

GtkWidget *
stats_chart_bars_new(const StatsChartItem *items, guint n)
{
    GtkWidget *area = gtk_drawing_area_new();
    ChartData *data;

    if (items == NULL || n == 0)
        return area;

    data = chart_data_new(area, items, n);
    data->kind = 0;
    gtk_drawing_area_set_content_height(GTK_DRAWING_AREA(area),
                                        (int) (BAR_PAD * 2.0 + n * BAR_ROW_H));
    gtk_drawing_area_set_draw_func(GTK_DRAWING_AREA(area), draw_bars, data,
                                  chart_data_free);
    gtk_widget_set_hexpand(area, TRUE);
    chart_attach_pointer(area, data);
    return area;
}

GtkWidget *
stats_chart_donut_new(const StatsChartItem *items, guint n,
                      const char *centre_value, const char *centre_label)
{
    GtkWidget *area = gtk_drawing_area_new();
    ChartData *data;

    if (items == NULL || n == 0)
        return area;

    data = chart_data_new(area, items, n);
    data->kind = 1;
    data->centre_value = g_strdup(centre_value);
    data->centre_label = g_strdup(centre_label);
    gtk_drawing_area_set_content_width(GTK_DRAWING_AREA(area), 208);
    gtk_drawing_area_set_content_height(GTK_DRAWING_AREA(area), 208);
    gtk_drawing_area_set_draw_func(GTK_DRAWING_AREA(area), draw_donut, data,
                                   chart_data_free);
    gtk_widget_set_halign(area, GTK_ALIGN_START);
    gtk_widget_set_valign(area, GTK_ALIGN_CENTER);
    chart_attach_pointer(area, data);
    return area;
}
