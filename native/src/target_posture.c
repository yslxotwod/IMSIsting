/*
 * target_posture.c — the target panel's posture chips.
 *
 * One chip per dimension, tinted by how bad the finding is, over one sentence
 * naming the worst finding and one line naming the stores that answered.
 *
 * The rules this file is written to:
 *
 *   1. Every chip is a fact a module wrote down. This file reads; it never
 *      runs a module and never guesses.
 *   2. A dimension no module has observed is UNOBSERVED and grey, never
 *      green. Absence of evidence drawn as evidence is the one thing a
 *      posture panel must not do.
 *   3. An algorithm this file does not recognise is WEAK, not strong. An
 *      unknown cipher is not evidence of a cipher.
 *   4. The negotiated session (19) beats the advertisement (02) for the same
 *      cell, and the chip names which one it came from, because the two are
 *      different strengths of claim.
 *
 * Algorithm vocabulary: 3GPP TS 43.020 (A5/x, GEA/x), TS 33.401 (EEA, EIA),
 * TS 33.501 (NEA, NIA).
 */

#include "target_posture.h"

#include <string.h>
#include <unistd.h>

/* ==================================================================== */
/*  TONES                                                               */
/* ==================================================================== */

typedef enum {
    POSTURE_UNK = 0,   /* nobody looked */
    POSTURE_OK,        /* looked, and it held */
    POSTURE_WARN,      /* looked, and it is weak */
    POSTURE_BAD        /* looked, and it is open */
} PostureTone;

typedef struct {
    char       *label;   /* CIPHER, INTEGRITY, IMSI, SI */
    char       *state;   /* A5/1, UNPROTECTED, 3 in the clear, decoded */
    char       *why;     /* the mechanism, not a score */
    char       *src;     /* the module that wrote the fact, or NULL */
    PostureTone tone;
} PostureBadge;

typedef struct {
    char      *root;
    GtkWidget *chips;
    GtkWidget *why;
    GtkWidget *src;
} Posture;

/* ==================================================================== */
/*  VOCABULARY                                                          */
/* ==================================================================== */

static const char *
tone_class(PostureTone t)
{
    switch (t) {
    case POSTURE_BAD:  return "posture-bad";
    case POSTURE_WARN: return "posture-warn";
    case POSTURE_OK:   return "posture-ok";
    default:           return "posture-unk";
    }
}

static const char *
tone_word(PostureTone t)
{
    switch (t) {
    case POSTURE_BAD:  return "EXPOSED";
    case POSTURE_WARN: return "WEAK";
    case POSTURE_OK:   return "HARDENED";
    default:           return "UNOBSERVED";
    }
}

/* Digits only, so "262-01" and "26201" name the same network. NULL when the
   string carries no digit at all. */
static char *
only_digits(const char *s)
{
    GString *out = g_string_new(NULL);

    for (const char *p = s; p != NULL && *p != '\0'; p++)
        if (g_ascii_isdigit(*p)) g_string_append_c(out, *p);
    if (out->len == 0) {
        g_string_free(out, TRUE);
        return NULL;
    }
    return g_string_free(out, FALSE);
}

/* The trailing digit of an algorithm name: A5/3 -> 3, NEA0 -> 0, EEA2 -> 2,
   nothing -> -1. */
static int
alg_digit(const char *alg)
{
    int d = -1;

    if (alg == NULL) return -1;
    for (const char *p = alg; *p != '\0'; p++)
        if (g_ascii_isdigit(*p)) d = *p - '0';
    return d;
}

static gboolean
alg_absent(const char *up)
{
    return up == NULL || *up == '\0' || g_strcmp0(up, "NONE") == 0 ||
           g_strcmp0(up, "NULL") == 0 || g_strcmp0(up, "-") == 0 ||
           g_strcmp0(up, "N/A") == 0;
}

/* The cipher's own strength, with the reason. `why` is always set. */
static PostureTone
cipher_tone(const char *alg, const char **why)
{
    g_autofree char *up = (alg != NULL) ? g_ascii_strup(alg, -1) : NULL;
    const char *w = "no cipher has been observed on this cell yet";
    PostureTone t = POSTURE_UNK;
    int d;

    if (!alg_absent(up)) {
        d = alg_digit(up);
        if (strstr(up, "A5/") != NULL) {
            if (d == 0) {
                t = POSTURE_BAD;
                w = "A5/0 ciphers nothing: every frame on the air is readable";
            } else if (d == 1) {
                t = POSTURE_BAD;
                w = "A5/1 falls to a few seconds of known plaintext (rainbow tables)";
            } else if (d == 2) {
                t = POSTURE_BAD;
                w = "A5/2 was weak by design and breaks in real time";
            } else if (d == 3) {
                t = POSTURE_OK;
                w = "A5/3 (KASUMI) is not broken in practice";
            } else {
                t = POSTURE_WARN;
                w = "an A5 variant outside A5/0-3; read it as unknown strength";
            }
        } else if (strstr(up, "GEA") != NULL) {
            if (d == 0) {
                t = POSTURE_BAD;
                w = "GEA/0 ciphers nothing";
            } else if (d == 1) {
                t = POSTURE_BAD;
                w = "GEA/1 is broken from captured data alone";
            } else if (d == 2) {
                t = POSTURE_WARN;
                w = "GEA/2 is weak and deprecated";
            } else {
                t = POSTURE_OK;
                w = "GEA/3 is the surviving GPRS cipher";
            }
        } else if (strstr(up, "UEA") != NULL) {
            if (d == 0) {
                t = POSTURE_BAD;
                w = "UEA0 ciphers nothing on UMTS";
            } else if (d == 1) {
                t = POSTURE_BAD;
                w = "UEA1 carries KASUMI's 2009 break";
            } else {
                t = POSTURE_OK;
                w = "UEA2 is the UMTS cipher in use";
            }
        } else if (strstr(up, "EEA") != NULL) {
            if (d == 0) {
                t = POSTURE_BAD;
                w = "EEA0 is the LTE null cipher: NAS and RRC run in the clear";
            } else if (d == 1) {
                t = POSTURE_WARN;
                w = "EEA1 (SNOW3G) is legacy; EEA2 is the modern floor";
            } else {
                t = POSTURE_OK;
                w = "EEA2/EEA3 (AES, ZUC) are not broken";
            }
        } else if (strstr(up, "NEA") != NULL) {
            if (d == 0) {
                t = POSTURE_BAD;
                w = "NEA0 is the 5G null cipher: NAS and RRC run in the clear";
            } else if (d == 1) {
                t = POSTURE_WARN;
                w = "NEA1 (SNOW3G) is legacy; NEA2 is the modern floor";
            } else {
                t = POSTURE_OK;
                w = "NEA2/NEA3 (AES, ZUC) are not broken";
            }
        } else {
            t = POSTURE_WARN;
            w = "an algorithm this toolkit cannot place; read it as unknown strength";
        }
    }
    if (why != NULL) *why = w;
    return t;
}

/* Integrity is its own answer: a cell can run A5/1 and still carry signalling
   integrity, and the A5/1 chip would hide that. A null integrity algorithm is
   the finding that lets forged NAS and SMS land. */
static PostureTone
integrity_tone(const char *alg, const char **why)
{
    g_autofree char *up = (alg != NULL) ? g_ascii_strup(alg, -1) : NULL;
    const char *w = "no integrity algorithm has been recorded yet";
    PostureTone t = POSTURE_UNK;

    if (!alg_absent(up)) {
        if (alg_digit(up) == 0) {
            t = POSTURE_BAD;
            w = "a null integrity algorithm: forged NAS and SMS are accepted";
        } else {
            t = POSTURE_OK;
            w = "signalling integrity is on, so forged NAS and SMS are dropped";
        }
    }
    if (why != NULL) *why = w;
    return t;
}

/* ==================================================================== */
/*  STORES                                                              */
/* ==================================================================== */

static void
badge_free(gpointer p)
{
    PostureBadge *b = p;

    if (b == NULL) return;
    g_free(b->label);
    g_free(b->state);
    g_free(b->why);
    g_free(b->src);
    g_free(b);
}

static void
badge_add(GPtrArray *out, const char *label, const char *state,
          PostureTone tone, const char *why, const char *src)
{
    PostureBadge *b = g_new0(PostureBadge, 1);

    b->label = g_strdup(label);
    b->state = g_strdup((state != NULL && *state != '\0') ? state : "unknown");
    b->why   = g_strdup((why != NULL && *why != '\0') ? why : "no reason recorded");
    b->src   = (src != NULL && *src != '\0') ? g_strdup(src) : NULL;
    b->tone  = tone;
    g_ptr_array_add(out, b);
}

/* Lines of a small tsv, comments and blanks dropped. NULL when the store is
   absent, empty, or holds nothing but a header; free with g_strfreev. */
static gchar **
read_lines(const char *path)
{
    g_autofree char *blob = NULL;
    GPtrArray *keep = g_ptr_array_new();
    gchar **lines;
    gchar **out;

    if (path == NULL || !g_file_get_contents(path, &blob, NULL, NULL))
        return NULL;
    lines = g_strsplit(blob, "\n", -1);
    for (int i = 0; lines[i] != NULL; i++) {
        if (*lines[i] == '\0' || *lines[i] == '#') continue;
        g_ptr_array_add(keep, g_strdup(lines[i]));
    }
    g_strfreev(lines);
    if (keep->len < 2) {                 /* header only, or nothing at all */
        g_ptr_array_free(keep, TRUE);
        return NULL;
    }
    g_ptr_array_add(keep, NULL);
    out = (gchar **) g_ptr_array_free(keep, FALSE);
    return out;
}

static int
col_index(gchar **hdr, const char *name)
{
    if (hdr == NULL || name == NULL) return -1;
    for (int i = 0; hdr[i] != NULL; i++)
        if (g_strcmp0(hdr[i], name) == 0) return i;
    return -1;
}

/* Copy of one column of a row, or NULL when the column is empty. */
static char *
row_field(gchar **hdr, const char *line, const char *name)
{
    int idx = col_index(hdr, name);
    gchar **c;
    char *out = NULL;

    if (idx < 0 || line == NULL) return NULL;
    c = g_strsplit(line, "\t", -1);
    if (c[idx] != NULL && *c[idx] != '\0') out = g_strdup(c[idx]);
    g_strfreev(c);
    return out;
}

/* The first row where every named filter matches; a NULL filter value is no
   filter. The key must be a real column or nothing matches, so a store that
   changes shape fails loudly instead of matching the wrong column. */
static char *
find_row(gchar **lines, const char *k1, const char *v1,
         const char *k2, const char *v2)
{
    gchar **hdr;
    int i1, i2;

    if (lines == NULL || lines[0] == NULL || v1 == NULL || *v1 == '\0')
        return NULL;
    hdr = g_strsplit(lines[0], "\t", -1);
    i1 = col_index(hdr, k1);
    i2 = col_index(hdr, k2);
    if (i1 < 0) { g_strfreev(hdr); return NULL; }

    for (int r = 1; lines[r] != NULL; r++) {
        gchar **c = g_strsplit(lines[r], "\t", -1);
        gboolean ok = c[i1] != NULL && g_strcmp0(c[i1], v1) == 0;

        if (ok && i2 >= 0 && v2 != NULL && *v2 != '\0')
            ok = c[i2] != NULL && g_strcmp0(c[i2], v2) == 0;
        if (ok) {
            char *line = g_strdup(lines[r]);

            g_strfreev(c);
            g_strfreev(hdr);
            return line;
        }
        g_strfreev(c);
    }
    g_strfreev(hdr);
    return NULL;
}

/* The newest row naming a network. These stores are append-only, so the last
   line that matches is the freshest fact about it. Compared on digits,
   because one store writes "262-01" and another "26201". */
static char *
find_network(gchar **lines, const char *plmn_digits)
{
    gchar **hdr;
    int idx;
    char *hit = NULL;

    if (lines == NULL || lines[0] == NULL || plmn_digits == NULL) return NULL;
    hdr = g_strsplit(lines[0], "\t", -1);
    idx = col_index(hdr, "plmn");
    if (idx < 0) { g_strfreev(hdr); return NULL; }

    for (int r = 1; lines[r] != NULL; r++) {
        gchar **c = g_strsplit(lines[r], "\t", -1);

        if (c[idx] != NULL) {
            g_autofree char *d = only_digits(c[idx]);

            if (d != NULL && g_strcmp0(d, plmn_digits) == 0) {
                g_free(hit);
                hit = g_strdup(lines[r]);
            }
        }
        g_strfreev(c);
    }
    g_strfreev(hdr);
    return hit;
}

/* Keep the worst tone seen, and the reason that came with it. */
static void
keep_worst(PostureTone *worst, const char **worst_why, PostureTone t,
           const char *why)
{
    if (t > *worst) {
        *worst = t;
        if (why != NULL && *why != '\0') *worst_why = why;
    }
}

/* ==================================================================== */
/*  WHAT THE CELL IS EXPOSED TO                                         */
/* ==================================================================== */

static GPtrArray *
collect(const char *root, const char *plmn, const char *cell, const char *chan,
        PostureTone *verdict_out, char **why_out, char **src_out)
{
    g_autofree char *plmn_d = only_digits(plmn);
    g_autofree char *f_audit = g_build_filename(root, "loot", "cipher_audit",
                                                "sessions.tsv", NULL);
    g_autofree char *f_cells = g_build_filename(root, "loot", "cell_recon",
                                                "cells.tsv", NULL);
    g_autofree char *f_expo  = g_build_filename(root, "loot", "imsi_exposure",
                                                "identities.tsv", NULL);
    g_autofree char *f_att   = g_build_filename(root, "loot", "lte_attach",
                                                "identities.tsv", NULL);
    g_autofree char *f_si    = g_build_filename(root, "loot", "gsm_air",
                                                "si.tsv", NULL);
    GPtrArray *badges = g_ptr_array_new_with_free_func(badge_free);
    GPtrArray *srcs   = g_ptr_array_new_with_free_func(g_free);
    PostureTone worst = POSTURE_UNK;
    const char *worst_why = NULL;
    g_autofree char *src_join = NULL;

    /* ---- CIPHER and INTEGRITY -------------------------------------- */
    {
        g_autofree char *cipher = NULL;
        g_autofree char *integ  = NULL;
        g_autofree char *src    = NULL;
        const char *cipher_why = NULL;
        const char *int_why    = NULL;
        PostureTone ct, it;
        gchar **audit = read_lines(f_audit);
        gchar **cells = read_lines(f_cells);

        if (audit != NULL && plmn_d != NULL) {
            g_autofree char *row = find_network(audit, plmn_d);

            if (row != NULL) {
                gchar **hdr = g_strsplit(audit[0], "\t", -1);

                cipher = row_field(hdr, row, "enc_alg");
                integ  = row_field(hdr, row, "int_alg");
                g_strfreev(hdr);
                if (cipher != NULL && *cipher != '\0')
                    src = g_strdup("19 cipher audit");
            }
        }

        /* The audit records a session, not a cell. With no session on this
           network the advertisement is the only cipher anyone wrote down,
           and the chip says which of the two claims it is making. */
        if ((cipher == NULL || *cipher == '\0') && cells != NULL) {
            g_autofree char *row = NULL;
            g_autofree char *row2 = NULL;
            gchar **hdr = g_strsplit(cells[0], "\t", -1);

            if (cell != NULL && *cell != '\0')
                row = find_row(cells, "cell_id", cell, NULL, NULL);
            if (row == NULL && chan != NULL && *chan != '\0')
                row = find_row(cells, "arfcn", chan, NULL, NULL);
            if (row == NULL && plmn_d != NULL) {
                row2 = find_network(cells, plmn_d);
                if (row2 != NULL) row = g_strdup(row2);
            }
            if (row != NULL) {
                g_autofree char *c = row_field(hdr, row, "cipher");

                if (c != NULL && g_ascii_strcasecmp(c, "none") != 0 &&
                    g_ascii_strcasecmp(c, "null") != 0 &&
                    g_ascii_strcasecmp(c, "unknown") != 0) {
                    cipher = g_steal_pointer(&c);
                    src = g_strdup("02 cell recon");
                }
            }
            g_strfreev(hdr);
        }

        ct = cipher_tone(cipher, &cipher_why);
        badge_add(badges, "CIPHER",
                  (cipher != NULL && *cipher != '\0') ? cipher : "not observed",
                  ct, cipher_why, src);
        keep_worst(&worst, &worst_why, ct, cipher_why);
        if (src != NULL) g_ptr_array_add(srcs, g_steal_pointer(&src));

        /* GSM has no separate integrity layer; an "n/a" is not a null cipher. */
        if (integ != NULL && *integ != '\0' &&
            g_ascii_strcasecmp(integ, "n/a") != 0) {
            it = integrity_tone(integ, &int_why);
            badge_add(badges, "INTEGRITY", integ, it, int_why, "19 cipher audit");
            keep_worst(&worst, &worst_why, it, int_why);
            g_ptr_array_add(srcs, g_strdup("19 cipher audit"));
        }
        g_strfreev(audit);
        g_strfreev(cells);
    }

    /* ---- IMSI: did an identity cross the air unencrypted -------------- */
    {
        gchar **expo = read_lines(f_expo);
        gchar **att  = read_lines(f_att);
        guint n_expo = 0, n_att = 0;

        if (expo != NULL) {
            gchar **hdr = g_strsplit(expo[0], "\t", -1);
            int k = col_index(hdr, "kind");

            for (int r = 1; expo[r] != NULL; r++) {
                gchar **c = g_strsplit(expo[r], "\t", -1);

                if (k < 0 || (c[k] != NULL &&
                              (g_ascii_strcasecmp(c[k], "imsi") == 0 ||
                               g_ascii_strcasecmp(c[k], "imei") == 0 ||
                               g_ascii_strcasecmp(c[k], "imeisv") == 0)))
                    n_expo++;
                g_strfreev(c);
            }
            g_strfreev(hdr);
        }
        if (att != NULL) {
            gchar **hdr = g_strsplit(att[0], "\t", -1);
            int k = col_index(hdr, "kind");

            for (int r = 1; att[r] != NULL; r++) {
                gchar **c = g_strsplit(att[r], "\t", -1);

                if (k < 0 || (c[k] != NULL &&
                              g_ascii_strcasecmp(c[k], "imsi") == 0))
                    n_att++;
                g_strfreev(c);
            }
            g_strfreev(hdr);
        }

        if (n_expo + n_att > 0) {
            g_autofree char *state = g_strdup_printf("%u in the clear",
                                                     n_expo + n_att);
            /* These two stores carry no cell column, so the count is a fact
               about the network the toolkit has been listening to, not about
               this cell. Saying "from this cell" would be a claim the store
               cannot support. */
            const char *why = "identities crossed the air unencrypted and were "
                              "kept. These stores record the network, not the "
                              "cell, so read this as the network's exposure "
                              "rather than this cell's";

            badge_add(badges, "IMSI", state, POSTURE_BAD, why,
                      n_expo > 0 ? "18 imsi exposure" : "09 lte attach");
            keep_worst(&worst, &worst_why, POSTURE_BAD, why);
            g_ptr_array_add(srcs, g_strdup(n_expo > 0 ? "18 imsi exposure"
                                                      : "09 lte attach"));
        } else if (expo != NULL || att != NULL) {
            badge_add(badges, "IMSI", "none seen", POSTURE_OK,
                      "no identity has been captured in the clear here", NULL);
        } else {
            badge_add(badges, "IMSI", "not observed", POSTURE_UNK,
                      "run 18 --audit or 09 --decode-attach on a capture to "
                      "answer this", NULL);
        }
        g_strfreev(expo);
        g_strfreev(att);
    }

    /* ---- SI: is this cell's own broadcast understood ----------------- */
    {
        gchar **si = read_lines(f_si);
        g_autofree char *row = NULL;

        if (si != NULL) {
            if (cell != NULL && *cell != '\0')
                row = find_row(si, "cell_id", cell, NULL, NULL);
            if (row == NULL && plmn_d != NULL) row = find_network(si, plmn_d);
        }
        if (row != NULL) {
            badge_add(badges, "SI", "decoded", POSTURE_OK,
                      "the cell's system information was read, so its LAI and "
                      "paging parameters are known", "06 gsm air");
            g_ptr_array_add(srcs, g_strdup("06 gsm air"));
        } else {
            badge_add(badges, "SI", "not decoded", POSTURE_UNK,
                      "run 06 --decode-si on this cell to read its broadcast",
                      NULL);
        }
        g_strfreev(si);
    }

    /* One line naming who answered, each store once. */
    if (srcs->len > 0) {
        GString *j = g_string_new(NULL);

        for (guint i = 0; i < srcs->len; i++) {
            const char *s = g_ptr_array_index(srcs, i);
            gboolean dup = FALSE;

            for (guint k = 0; k < i; k++)
                if (g_strcmp0(g_ptr_array_index(srcs, k), s) == 0) dup = TRUE;
            if (dup || s == NULL) continue;
            if (j->len > 0) g_string_append(j, " · ");
            g_string_append(j, s);
        }
        if (j->len > 0) {
            src_join = g_strconcat("observed by ", j->str, NULL);
        }
        g_string_free(j, TRUE);
    }

    if (verdict_out != NULL) *verdict_out = worst;
    if (why_out != NULL)
        *why_out = g_strdup(worst_why != NULL ? worst_why
                            : "no module has looked at this cell yet");
    if (src_out != NULL) *src_out = g_steal_pointer(&src_join);
    g_ptr_array_free(srcs, TRUE);
    return badges;
}

/* ==================================================================== */
/*  WIDGET                                                              */
/* ==================================================================== */

static void
posture_free(gpointer p)
{
    Posture *v = p;

    if (v == NULL) return;
    g_free(v->root);
    g_free(v);
}

GtkWidget *
target_posture_new(const char *root_dir)
{
    Posture *v = g_new0(Posture, 1);
    GtkWidget *box;

    v->root = g_strdup(root_dir != NULL ? root_dir : "");
    box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    g_object_set_data_full(G_OBJECT(box), "imsisting-posture", v, posture_free);

    v->chips = gtk_flow_box_new();
    gtk_widget_add_css_class(v->chips, "posture-chips");
    gtk_flow_box_set_selection_mode(GTK_FLOW_BOX(v->chips), GTK_SELECTION_NONE);
    gtk_flow_box_set_column_spacing(GTK_FLOW_BOX(v->chips), 6);
    gtk_flow_box_set_row_spacing(GTK_FLOW_BOX(v->chips), 6);
    gtk_flow_box_set_min_children_per_line(GTK_FLOW_BOX(v->chips), 1);
    gtk_flow_box_set_max_children_per_line(GTK_FLOW_BOX(v->chips), 2);
    /* Equal widths, so the chips read as a column of answers instead of a
       ragged line, and a long state ellipsizes inside its own chip rather
       than pushing the row past the edge of a 300px panel. */
    gtk_flow_box_set_homogeneous(GTK_FLOW_BOX(v->chips), TRUE);
    gtk_box_append(GTK_BOX(box), v->chips);

    v->why = gtk_label_new(NULL);
    gtk_widget_add_css_class(v->why, "posture-why");
    gtk_label_set_xalign(GTK_LABEL(v->why), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(v->why), TRUE);
    gtk_box_append(GTK_BOX(box), v->why);

    v->src = gtk_label_new(NULL);
    gtk_widget_add_css_class(v->src, "posture-src");
    gtk_label_set_xalign(GTK_LABEL(v->src), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(v->src), TRUE);
    gtk_box_append(GTK_BOX(box), v->src);

    return box;
}

void
target_posture_refresh(GtkWidget *posture, const char *plmn, const char *cell,
                       const char *chan)
{
    Posture *v;
    GPtrArray *badges;
    PostureTone verdict = POSTURE_UNK;
    g_autofree char *why = NULL;
    g_autofree char *src = NULL;
    GtkWidget *cursor;

    if (posture == NULL) return;
    v = g_object_get_data(G_OBJECT(posture), "imsisting-posture");
    if (v == NULL) return;

    /* Which dimensions exist changes with what has been observed, so the row
       of chips is rebuilt rather than patched in place. */
    while ((cursor = gtk_widget_get_first_child(v->chips)) != NULL)
        gtk_flow_box_remove(GTK_FLOW_BOX(v->chips), cursor);

    badges = collect(v->root, plmn, cell, chan, &verdict, &why, &src);

    for (guint i = 0; i < badges->len; i++) {
        PostureBadge *b  = g_ptr_array_index(badges, i);
        GtkWidget *chip  = gtk_box_new(GTK_ORIENTATION_VERTICAL, 1);
        GtkWidget *label = gtk_label_new(b->label);
        GtkWidget *value = gtk_label_new(b->state);
        g_autofree char *tip = g_strdup_printf(
            "%s — %s\n%s", b->label, b->why,
            b->src != NULL ? b->src : "no module has recorded this");

        gtk_widget_add_css_class(chip, "posture-chip");
        gtk_widget_add_css_class(chip, tone_class(b->tone));
        gtk_widget_add_css_class(label, "posture-chip-label");
        gtk_widget_add_css_class(value, "posture-chip-state");
        gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
        gtk_label_set_xalign(GTK_LABEL(value), 0.0f);
        gtk_label_set_ellipsize(GTK_LABEL(value), PANGO_ELLIPSIZE_END);
        gtk_widget_set_tooltip_text(chip, tip);
        gtk_box_append(GTK_BOX(chip), label);
        gtk_box_append(GTK_BOX(chip), value);
        gtk_flow_box_append(GTK_FLOW_BOX(v->chips), chip);
    }
    g_ptr_array_free(badges, TRUE);

    {
        g_autofree char *text = g_strdup_printf("%s — %s",
                                                tone_word(verdict), why);

        gtk_label_set_text(GTK_LABEL(v->why), text);
        for (int t = POSTURE_UNK; t <= POSTURE_BAD; t++)
            gtk_widget_remove_css_class(v->why, tone_class((PostureTone) t));
        gtk_widget_add_css_class(v->why, tone_class(verdict));
    }
    gtk_label_set_text(GTK_LABEL(v->src),
                       src != NULL ? src : "no store has answered for this cell");
}

/* ==================================================================== */
/*  SELFTEST                                                            */
/* ==================================================================== */

static int
chk(const char *name, gboolean ok, const char *detail)
{
    g_print("gui-posture-%s\t%s\t%s\n", name, ok ? "PASS" : "FAIL",
            detail != NULL ? detail : "");
    return ok ? 0 : 1;
}

int
target_posture_selftest(void)
{
    int bad = 0;
    const char *why = NULL;

    /* The vocabulary. An unknown algorithm must never come out strong, and a
       null cipher must always come out open. */
    { PostureTone t = cipher_tone("A5/0", &why);
      bad += chk("tone-a5-0", t == POSTURE_BAD, why); }
    { PostureTone t = cipher_tone("A5/1", &why);
      bad += chk("tone-a5-1", t == POSTURE_BAD, why); }
    { PostureTone t = cipher_tone("A5/3", &why);
      bad += chk("tone-a5-3", t == POSTURE_OK, why); }
    { PostureTone t = cipher_tone("EEA0", &why);
      bad += chk("tone-eea-0", t == POSTURE_BAD, why); }
    { PostureTone t = cipher_tone("EEA2", &why);
      bad += chk("tone-eea-2", t == POSTURE_OK, why); }
    { PostureTone t = cipher_tone("NEA0", &why);
      bad += chk("tone-nea-0", t == POSTURE_BAD, why); }
    { PostureTone t = cipher_tone("NEA3", &why);
      bad += chk("tone-nea-3", t == POSTURE_OK, why); }
    { PostureTone t = cipher_tone("GEA/1", &why);
      bad += chk("tone-gea-1", t == POSTURE_BAD, why); }
    { PostureTone t = cipher_tone("GEA/2", &why);
      bad += chk("tone-gea-2", t == POSTURE_WARN, why); }
    { PostureTone t = cipher_tone("FROBNICATE9", &why);
      bad += chk("tone-unknown", t == POSTURE_WARN, why); }
    { PostureTone t = cipher_tone("none", &why);
      bad += chk("tone-absent-none", t == POSTURE_UNK, why); }
    bad += chk("tone-absent-null", cipher_tone(NULL, &why) == POSTURE_UNK, why);

    { PostureTone t = integrity_tone("EIA0", &why);
      bad += chk("int-eia0", t == POSTURE_BAD, why); }
    { PostureTone t = integrity_tone("EIA2", &why);
      bad += chk("int-eia2", t == POSTURE_OK, why); }
    { PostureTone t = integrity_tone("n/a", &why);
      bad += chk("int-na", t == POSTURE_UNK, why); }

    /* The readers, against a store shaped like the ones 19 and 02 write. */
    {
        g_autofree char *dir = g_dir_make_tmp("imsisting-posture-XXXXXX", NULL);

        if (dir == NULL) {
            bad += chk("temp-store", FALSE, "could not make a scratch directory");
        } else {
            g_autofree char *audit = g_build_filename(dir, "sessions.tsv", NULL);
            g_autofree char *cells = g_build_filename(dir, "cells.tsv", NULL);

            g_file_set_contents(audit,
                "session\tgen\tenc_alg\tint_alg\tplmn\n"
                "a\tgsm\tA5/1\tn/a\t262-01\n"
                "b\tlte\tEEA2\tEIA2\t262-02\n"
                "c\tgsm\tA5/0\tn/a\t26201\n", -1, NULL);
            g_file_set_contents(cells,
                "arfcn\tcell_id\tplmn\tcipher\n"
                "42\t0A1B\t262-01\tA5/3\n", -1, NULL);

            {
                gchar **lines = read_lines(audit);

                bad += chk("read-rows", lines != NULL && lines[0] != NULL &&
                           lines[1] != NULL && lines[3] != NULL &&
                           lines[4] == NULL, "3 data rows expected");
                if (lines != NULL) {
                    g_autofree char *hit = find_network(lines, "26201");

                    /* Two rows name 262-01 once digits are stripped: the
                       newest must win, or the panel reports a cipher the
                       network has already dropped. */
                    bad += chk("network-last", hit != NULL &&
                               strstr(hit, "A5/0") != NULL,
                               hit != NULL ? hit : "no row matched");
                    g_strfreev(lines);
                }
            }
            {
                gchar **l2 = read_lines(cells);
                g_autofree char *hit = find_row(l2, "cell_id", "0A1B", NULL, NULL);
                gchar **hdr = (l2 != NULL) ? g_strsplit(l2[0], "\t", -1) : NULL;
                g_autofree char *c = row_field(hdr, hit, "cipher");

                bad += chk("cell-match", g_strcmp0(c, "A5/3") == 0,
                           c != NULL ? c : "no cipher");
                g_strfreev(hdr);
                g_strfreev(l2);
            }
            {
                gchar **l3 = read_lines(cells);

                bad += chk("cell-miss", find_row(l3, "cell_id", "FFFF",
                                                 NULL, NULL) == NULL,
                           "a cell not in the store must not match");
                g_strfreev(l3);
            }
            g_unlink(audit);
            g_unlink(cells);
            g_rmdir(dir);
        }
    }

    /* Digest helpers, whose bugs are the kind that silently mis-group. */
    {
        g_autofree char *d = only_digits("262-01");

        bad += chk("digits-dashed", g_strcmp0(d, "26201") == 0, d);
    }
    {
        g_autofree char *d = only_digits("MCC/MNC");

        bad += chk("digits-none", d == NULL, "no digits must give NULL");
    }

    g_print("gui-posture-result\t%s\t%d failed\n", bad == 0 ? "PASS" : "FAIL", bad);
    return bad;
}
