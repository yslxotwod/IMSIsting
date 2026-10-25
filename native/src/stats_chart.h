/* Two pictures for the Stats page.

   Both take the same array: a label, a count, and the hue the rest of the UI
   already uses for that category. The widgets own their copy of the array --
   the caller's buffer can die the moment the constructor returns. */
#ifndef IMSISTING_STATS_CHART_H
#define IMSISTING_STATS_CHART_H

#include <gtk/gtk.h>

typedef struct {
    const char *label;   /* row name, drawn in its own hue */
    double value;        /* count: bar length is value/max, arc is value/total */
    double r, g, b;      /* 0..1 hue, the same one .cat-* paints with */
} StatsChartItem;

/* Horizontal capsule bars: name, bar, count, share of the total. */
GtkWidget *stats_chart_bars_new(const StatsChartItem *items, guint n);

/* Ring of the same shares with a live centre that follows the pointer. */
GtkWidget *stats_chart_donut_new(const StatsChartItem *items, guint n,
                                 const char *centre_value,
                                 const char *centre_label);

#endif /* IMSISTING_STATS_CHART_H */
