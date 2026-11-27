/* map_page.h — the Map page's only door.
 *
 * Its own translation unit for the same reason help_page.c has one: a page
 * that answers one question out of one body of data, and needs nothing from
 * the rest of the interface. The page takes a project root and reads two
 * things under it:
 *
 *   native/resources/basemap/<name>.bin   the world, compiled into the binary
 *   <root>/loot/map/layers/<name>.tsv     whatever the modules put on the map
 *
 * It never calls a module and never parses a module's prose. A layer is a
 * file that the module wrote; the page draws the file.
 */
#ifndef IMSISTING_MAP_PAGE_H
#define IMSISTING_MAP_PAGE_H

#include <gtk/gtk.h>

/* Build the permanent Map page. `root_dir` is the checkout root, used for the
   loot/map/layers inbox; it is not copied, so it must outlive the widget. */
GtkWidget *map_page_new(const char *root_dir);

/* A layer row knows which module wrote it, and a reader who clicks a mark
   usually wants that module open. The page has no notebook of its own, so it
   hands the module id back to whoever does. */
typedef void (*MapModuleOpener)(const char *module_id, gpointer user_data);

void map_page_set_module_opener(GtkWidget *page, MapModuleOpener opener,
                                gpointer user_data);

/* Display-free checks, called from the GUI's --selftest: pan direction, the
   clamps, the zoom floor. Returns the number of failed assertions. */
int map_page_selftest(void);

#endif /* IMSISTING_MAP_PAGE_H */
