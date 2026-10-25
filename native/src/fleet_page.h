/* fleet_page.h -- the fleet view: every remote node, what it can do, and what
   it has been hearing.

   A page of its own rather than a corner of the Casebook because the question
   is different: the Casebook answers "what is in this case", and this answers
   "which of my boxes is awake and what can each one do".  It reads the same
   nodes.tsv the Casebook writes -- there is one node registry, not two. */

#ifndef IMSISTING_FLEET_PAGE_H
#define IMSISTING_FLEET_PAGE_H

#include <gtk/gtk.h>

/* root_dir is IMSISTING_ROOT: the page runs <root>/tools/casebook.py and reads
   nothing else.  It never parses a module's prose. */
GtkWidget *fleet_page_new(const char *root_dir);

/* Headless checks of the table reader, the age words and the status tones. */
int fleet_page_selftest(void);

#endif
