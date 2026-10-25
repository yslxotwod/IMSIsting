/* target_posture — the target panel's answer to "what is wrong with this cell".

   Six chips, one per dimension, every one of them a fact another module has
   already written to disk. This file reads those stores and nothing else: it
   never calls a module, never parses prose, and never upgrades a missing
   observation into a pass.

     <root>/loot/cipher_audit/sessions.tsv     the cipher a session negotiated  19
     <root>/loot/cell_recon/cells.tsv          the cipher the cell advertises  02
     <root>/loot/imsi_exposure/identities.tsv  identities seen in the clear    18
     <root>/loot/gsm_air/si.tsv                the cell's broadcast was read   06
     <root>/loot/lte_attach/identities.tsv     identities the network asked    09

   It lives in its own translation unit for the same reason map_page.c does:
   main1.c is a quarter of a megabyte of unrelated panels and this one has a
   contract that can be tested headlessly (see target_posture_selftest). */

#ifndef IMSISTING_TARGET_POSTURE_H
#define IMSISTING_TARGET_POSTURE_H

#include <gtk/gtk.h>

/* A widget holding the whole posture read-out: the row of chips, the verdict
   sentence and the line naming which modules spoke. `root_dir` is the toolkit
   root (IMSISTING_ROOT); nothing outside it is read. */
GtkWidget *target_posture_new(const char *root_dir);

/* Re-read every store and redraw. `plmn` may be "262-01" or "26201"; `cell`
   and `chan` may be NULL or empty, in which case the network is matched on
   its own and the chip says so. Safe to call on a NULL widget. */
void target_posture_refresh(GtkWidget *posture, const char *plmn,
                            const char *cell, const char *chan);

/* Headless checks of the parts that are not drawing: the algorithm
   vocabulary, the TSV reader and the network/cell matching. Prints
   `gui-posture-<name>\tPASS|FAIL\t<detail>` rows and returns the failure
   count, the same contract as the other GUI selftests. */
int target_posture_selftest(void);

#endif /* IMSISTING_TARGET_POSTURE_H */
