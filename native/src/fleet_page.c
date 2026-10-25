/* fleet_page.c -- every remote node, what each one can do, and what it has
   been hearing.

   Design notes worth keeping, because each one was a choice:

   - The node registry is the Casebook's `nodes.tsv`.  This page reads it and
     runs the same `casebook.py` verbs the CLI uses.  A second registry would
     drift the day someone adds a node from the other surface.
   - A node nobody has probed is UNKNOWN, never ONLINE.  "I have not asked" and
     "it answered" are different states and the dot colours say so.
   - Every action here is a subprocess the operator could have run by hand, and
     its stdout is shown verbatim below the table.  A page that summarised the
     answer would be a second parser of the same rows.
   - The stream column reads the node's own spool cursor, so "rows 42, 8 min
     ago" means this side really has those rows, not that the node is alive. */

#include "fleet_page.h"

#include <string.h>

/* ── small pure helpers (the selftest covers these) ───────────────────── */

/* Column index of `name` in a TSV header line, or -1.  Header lookup by name
   rather than position, because nodes.tsv grew four columns in one release and
   will grow again. */
static int
fleet_col(const char *header, const char *name)
{
    if (header == NULL || name == NULL) return -1;
    gchar **cells = g_strsplit(header, "\t", -1);
    int found = -1;
    for (int i = 0; cells[i] != NULL; i++) {
        if (g_strcmp0(g_strstrip(cells[i]), name) == 0) {
            found = i;
            break;
        }
    }
    g_strfreev(cells);
    return found;
}

/* Field `col` of a TSV line as a newly allocated string; "" when the column is
   absent or the row is short.  A short row must not crash the page: a file
   half-written by another process is a normal thing to read. */
static char *
fleet_field(const char *line, int col)
{
    if (line == NULL || col < 0) return g_strdup("");
    gchar **cells = g_strsplit(line, "\t", -1);
    char *out = g_strdup(col < (int) g_strv_length(cells) ? cells[col] : "");
    g_strfreev(cells);
    return out;
}

/* 0 ok, 1 warn, 2 bad, 3 unknown.  An unrecognised status is a warning, not a
   success: a row this page cannot read is not evidence that a node is up. */
static int
fleet_status_tone(const char *status)
{
    if (status == NULL || status[0] == 0) return 3;
    if (g_ascii_strcasecmp(status, "ONLINE") == 0) return 0;
    if (g_ascii_strcasecmp(status, "OFFLINE") == 0) return 2;
    if (g_ascii_strcasecmp(status, "UNKNOWN") == 0) return 3;
    if (g_ascii_strcasecmp(status, "-") == 0) return 3;
    return 1;
}

static const char *
fleet_tone_class(int tone)
{
    switch (tone) {
    case 0:  return "fleet-dot-ok";
    case 2:  return "fleet-dot-bad";
    case 1:  return "fleet-dot-warn";
    default: return "fleet-dot-unk";
    }
}

/* How long ago, in the words an operator uses.  A future timestamp is "just
   now" rather than a negative age, because clock skew between a node and this
   box is common and "-3 min" reads like a bug in the reader. */
static char *
fleet_age_word(gint64 when, gint64 now)
{
    if (when <= 0) return g_strdup("never");
    gint64 delta = now - when;
    if (delta < 60) return g_strdup("just now");
    if (delta < 3600) return g_strdup_printf("%" G_GINT64_FORMAT " min", delta / 60);
    if (delta < 86400) return g_strdup_printf("%" G_GINT64_FORMAT " h", delta / 3600);
    return g_strdup_printf("%" G_GINT64_FORMAT " d", delta / 86400);
}

/* Elapsed seconds as a short word, for the stream lag column. */
static char *
fleet_lag_word(gint64 lag_s)
{
    if (lag_s < 0) return g_strdup("no stream");
    if (lag_s < 120) return g_strdup("live");
    if (lag_s < 3600) return g_strdup_printf("%" G_GINT64_FORMAT " min stale", lag_s / 60);
    if (lag_s < 86400) return g_strdup_printf("%" G_GINT64_FORMAT " h stale", lag_s / 3600);
    return g_strdup_printf("%" G_GINT64_FORMAT " d stale", lag_s / 86400);
}

/* A capability list is long by nature; the table shows the first few and the
   tooltip carries the rest, because truncation without a way back is a lie. */
static char *
fleet_short_caps(const char *caps, guint keep, gboolean *more)
{
    if (caps == NULL || caps[0] == 0 || g_strcmp0(caps, "-") == 0) {
        if (more != NULL) *more = FALSE;
        return g_strdup("none measured");
    }
    gchar **parts = g_strsplit(caps, ",", -1);
    guint n = g_strv_length(parts);
    GString *out = g_string_new(NULL);
    for (guint i = 0; i < n; i++) {
        if (i == keep) break;
        if (i > 0) g_string_append(out, ", ");
        g_string_append(out, parts[i]);
    }
    if (more != NULL) *more = n > keep;
    if (n > keep) g_string_append_printf(out, " +%u", n - keep);
    g_strfreev(parts);
    return g_string_free(out, FALSE);
}

/* ISO 8601 stamp -> epoch seconds; 0 when the field is not a stamp. */
static gint64
fleet_epoch(const char *stamp)
{
    if (stamp == NULL || stamp[0] == 0 || g_strcmp0(stamp, "-") == 0) return 0;
    GDateTime *when = g_date_time_new_from_iso8601(stamp, NULL);
    if (when == NULL) return 0;
    gint64 epoch = g_date_time_to_unix(when);
    g_date_time_unref(when);
    return epoch;
}

/* ── the view ─────────────────────────────────────────────────────────── */

typedef struct {
    char *name;
    char *host;
    char *transport;
    char *class_name;
    char *role;
    char *caps;
    char *status;
    char *detail;
    char *last_seen;
    gint64 seen_epoch;
    gint64 stream_rows;
    gint64 stream_lag;
    gboolean streamed;
} FleetNode;

typedef struct {
    char *root;
    char *tool;

    GtkWidget *page;
    GtkWidget *list;
    GtkWidget *empty;
    GtkWidget *log_view;
    GtkTextBuffer *log;
    GtkWidget *busy;

    GtkWidget *chip_nodes;
    GtkWidget *chip_online;
    GtkWidget *chip_unreached;
    GtkWidget *chip_streamed;

    GtkWidget *detail_title;
    GtkWidget *detail_sub;
    GtkWidget *detail_caps;
    GtkWidget *detail_store;
    GtkWidget *module_entry;
    GtkWidget *verb_entry;

    GPtrArray *nodes;
    char *selected;
    GtkSizeGroup *columns[5];
    guint running;
} FleetView;

static void fleet_refresh(FleetView *view);
static void fleet_log(FleetView *view, const char *title, const char *body);
static void fleet_page_reveal_bottom(FleetView *view);

static void
fleet_node_free(gpointer data)
{
    FleetNode *node = data;
    if (node == NULL) return;
    g_free(node->name); g_free(node->host); g_free(node->transport);
    g_free(node->class_name); g_free(node->role); g_free(node->caps);
    g_free(node->status); g_free(node->detail); g_free(node->last_seen);
    g_free(node);
}

static FleetNode *
fleet_node_for(FleetView *view, const char *name)
{
    if (name == NULL || view->nodes == NULL) return NULL;
    for (guint i = 0; i < view->nodes->len; i++) {
        FleetNode *node = g_ptr_array_index(view->nodes, i);
        if (g_strcmp0(node->name, name) == 0) return node;
    }
    return NULL;
}

/* GSubprocess does not search PATH (G_SPAWN_SEARCH_PATH is not one of its
   flags), so "python3" would fork and die with an empty stdout -- an action
   that appears to succeed and says nothing.  Resolve the interpreter once. */
static const char *
fleet_python(void)
{
    static char *cached = NULL;
    if (cached == NULL)
        cached = g_find_program_in_path("python3");
    return cached != NULL ? cached : "python3";
}

/* Run the Casebook and keep what it printed.  Synchronous is right here: this
   is a file read behind a python start, not a network wait, and a fleet of a
   dozen nodes is nothing.  The actions that do touch the network are async. */
static char *
fleet_casebook(FleetView *view, const char *const *argv, int *status)
{
    const char *base[8];
    guint n = 0;
    base[n++] = fleet_python();
    base[n++] = view->tool;
    for (guint i = 0; argv[i] != NULL && n < G_N_ELEMENTS(base) - 1; i++) base[n++] = argv[i];
    base[n] = NULL;

    char *stdout_text = NULL;
    char *stderr_text = NULL;
    GError *error = NULL;
    gint wait_status = 0;
    /* stderr is captured, not discarded: G_SPAWN_STDERR_TO_DEV_NULL and a
       stderr buffer are mutually exclusive, and the failure of the first
       version was silent -- a page claiming "No nodes yet" because the spawn
       itself failed. The text is shown in the log instead of being dropped. */
    if (!g_spawn_sync(NULL, (gchar **) base, NULL, G_SPAWN_SEARCH_PATH, NULL, NULL,
                      &stdout_text, &stderr_text, &wait_status, &error)) {
        if (status != NULL) *status = -1;
        g_clear_error(&error);
        g_free(stdout_text);
        g_free(stderr_text);
        return NULL;
    }
    if (status != NULL)
        *status = g_spawn_check_wait_status(wait_status, NULL) ? 0 : 1;
    if (stderr_text != NULL && stderr_text[0] != 0 && view->log != NULL &&
        (stdout_text == NULL || stdout_text[0] == 0)) {
        g_autofree char *line = g_strdup(stderr_text);
        fleet_log(view, "casebook", line);
    }
    g_free(stderr_text);
    return stdout_text;
}

static void
fleet_load_nodes(FleetView *view)
{
    g_ptr_array_set_size(view->nodes, 0);
    const char *argv[] = { "--node-list-tsv", NULL };
    char *text = fleet_casebook(view, argv, NULL);
    if (text == NULL) return;

    gchar **lines = g_strsplit(text, "\n", -1);
    if (lines[0] == NULL || lines[0][0] == 0) {
        g_strfreev(lines);
        g_free(text);
        return;
    }
    const char *header = lines[0];
    int c_name = fleet_col(header, "name");
    int c_host = fleet_col(header, "host");
    int c_transport = fleet_col(header, "transport");
    int c_class = fleet_col(header, "class");
    int c_role = fleet_col(header, "role");
    int c_caps = fleet_col(header, "caps");
    int c_status = fleet_col(header, "status");
    int c_detail = fleet_col(header, "detail");
    int c_seen = fleet_col(header, "last_seen");

    for (guint i = 1; lines[i] != NULL; i++) {
        if (lines[i][0] == 0) continue;
        FleetNode *node = g_new0(FleetNode, 1);
        node->name = fleet_field(lines[i], c_name);
        if (node->name[0] == 0) {
            fleet_node_free(node);
            continue;
        }
        node->host = fleet_field(lines[i], c_host);
        node->transport = fleet_field(lines[i], c_transport);
        node->class_name = fleet_field(lines[i], c_class);
        node->role = fleet_field(lines[i], c_role);
        node->caps = fleet_field(lines[i], c_caps);
        node->status = fleet_field(lines[i], c_status);
        node->detail = fleet_field(lines[i], c_detail);
        node->last_seen = fleet_field(lines[i], c_seen);
        node->seen_epoch = fleet_epoch(node->last_seen);
        node->stream_lag = -1;
        g_ptr_array_add(view->nodes, node);
    }
    g_strfreev(lines);
    g_free(text);
}

/* Fold the stream report into the nodes already loaded.  A node with no spool
   keeps stream_lag -1, which the table reads as "no stream" rather than zero
   seconds of silence. */
static void
fleet_load_streams(FleetView *view)
{
    const char *argv[] = { "node-stream-status", NULL };
    char *text = fleet_casebook(view, argv, NULL);
    if (text == NULL) return;
    gchar **lines = g_strsplit(text, "\n", -1);
    if (lines[0] != NULL && lines[0][0] != 0) {
        int c_node = fleet_col(lines[0], "node");
        int c_rows = fleet_col(lines[0], "rows");
        int c_lag = fleet_col(lines[0], "lag_s");
        for (guint i = 1; lines[i] != NULL; i++) {
            if (lines[i][0] == 0) continue;
            char *name = fleet_field(lines[i], c_node);
            FleetNode *node = fleet_node_for(view, name);
            if (node != NULL) {
                char *rows = fleet_field(lines[i], c_rows);
                char *lag = fleet_field(lines[i], c_lag);
                node->stream_rows = g_ascii_strtoll(rows, NULL, 10);
                node->stream_lag = lag[0] == 0 || g_strcmp0(lag, "-") == 0
                    ? -1 : g_ascii_strtoll(lag, NULL, 10);
                node->streamed = TRUE;
                g_free(rows);
                g_free(lag);
            }
            g_free(name);
        }
    }
    g_strfreev(lines);
    g_free(text);
}

/* ── the detail pane ──────────────────────────────────────────────────── */

static void
fleet_detail_show(FleetView *view, const char *name)
{
    FleetNode *node = fleet_node_for(view, name);
    if (node == NULL) {
        gtk_label_set_text(GTK_LABEL(view->detail_title), "No node selected");
        gtk_label_set_text(GTK_LABEL(view->detail_sub),
                           "Pick a row above. Every field here was measured by a probe or "
                           "written by the node itself, so an empty field means nobody asked.");
        gtk_label_set_text(GTK_LABEL(view->detail_caps), "");
        gtk_label_set_text(GTK_LABEL(view->detail_store), "");
        return;
    }
    gboolean more = FALSE;
    g_autofree char *caps = fleet_short_caps(node->caps, 12, &more);
    g_autofree char *seen = fleet_age_word(node->seen_epoch, g_get_real_time() / G_USEC_PER_SEC);
    g_autofree char *title = g_strdup_printf("%s", node->name);
    g_autofree char *sub = g_strdup_printf(
        "%s · %s · %s · %s\nlast seen %s · stream %s",
        node->class_name[0] ? node->class_name : "unprobed class",
        node->transport[0] ? node->transport : "no transport",
        node->role[0] ? node->role : "no role",
        node->host[0] ? node->host : "no host",
        seen,
        node->streamed ? fleet_lag_word(node->stream_lag) : "never collected");
    gtk_label_set_text(GTK_LABEL(view->detail_title), title);
    gtk_label_set_text(GTK_LABEL(view->detail_sub), sub);
    gtk_label_set_text(GTK_LABEL(view->detail_caps), caps);
    if (node->streamed) {
        g_autofree char *store = g_strdup_printf(
            "%" G_GINT64_FORMAT " rows in this side's spool · %s",
            node->stream_rows, node->detail[0] ? node->detail : "no probe detail");
        gtk_label_set_text(GTK_LABEL(view->detail_store), store);
    } else {
        gtk_label_set_text(GTK_LABEL(view->detail_store),
                           node->detail[0] ? node->detail : "no probe has reported on this node");
    }
    gtk_widget_set_tooltip_text(view->detail_caps, node->caps);
}

/* ── actions ──────────────────────────────────────────────────────────── */

typedef struct {
    FleetView *view;
    char *title;
    GSubprocess *proc;
} FleetJob;

static void
fleet_log(FleetView *view, const char *title, const char *body)
{
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(view->log, &end);
    g_autofree char *stamp = g_strdup_printf("── %s\n", title);
    gtk_text_buffer_insert(view->log, &end, stamp, -1);
    if (body != NULL && body[0] != 0)
        gtk_text_buffer_insert(view->log, &end, body, -1);
    if (body == NULL || body[0] == 0 || body[strlen(body) - 1] != '\n')
        gtk_text_buffer_insert(view->log, &end, "\n", -1);
    gtk_text_buffer_get_end_iter(view->log, &end);
    GtkTextMark *mark = gtk_text_buffer_create_mark(view->log, NULL, &end, FALSE);
    gtk_text_view_scroll_to_mark(GTK_TEXT_VIEW(view->log_view), mark, 0.0, TRUE, 0.0, 1.0);
}

static void
fleet_job_done(GObject *source, GAsyncResult *result, gpointer user_data)
{
    FleetJob *job = user_data;
    FleetView *view = job->view;
    char *stdout_text = NULL;
    char *stderr_text = NULL;
    GError *error = NULL;
    g_subprocess_communicate_utf8_finish(G_SUBPROCESS(source), result,
                                         &stdout_text, &stderr_text, &error);
    if (error != NULL) {
        g_autofree char *line = g_strdup_printf("could not run: %s", error->message);
        fleet_log(view, job->title, line);
        g_clear_error(&error);
    } else {
        GString *body = g_string_new(NULL);
        if (stdout_text != NULL) g_string_append(body, stdout_text);
        if (stderr_text != NULL && stderr_text[0] != 0) {
            if (body->len > 0 && body->str[body->len - 1] != '\n') g_string_append_c(body, '\n');
            g_string_append(body, stderr_text);
        }
        fleet_log(view, job->title, body->str);
        g_string_free(body, TRUE);
    }
    g_free(stdout_text);
    g_free(stderr_text);
    if (view->running > 0) view->running--;
    if (view->running == 0 && view->busy != NULL)
        gtk_label_set_text(GTK_LABEL(view->busy), "");
    fleet_refresh(view);
    fleet_page_reveal_bottom(view);
    g_clear_object(&job->proc);
    g_free(job->title);
    g_free(job);
}

/* The page is taller than a small window, so the log -- where an action's own
   output lands -- can sit below the fold.  Bringing the bottom of the page into
   view after a job finishes is the difference between "the button did nothing"
   and reading the answer it produced. */
static void
fleet_page_reveal_bottom(FleetView *view)
{
    if (view->page == NULL || !GTK_IS_SCROLLED_WINDOW(view->page)) return;
    GtkAdjustment *adj = gtk_scrolled_window_get_vadjustment(GTK_SCROLLED_WINDOW(view->page));
    if (adj == NULL) return;
    gdouble bottom = gtk_adjustment_get_upper(adj) - gtk_adjustment_get_page_size(adj);
    gtk_adjustment_set_value(adj, MAX(bottom, gtk_adjustment_get_lower(adj)));
}

/* Every action is one of these: the argv a person would have typed, run
   detached so the window keeps painting, and its output pasted into the log. */
static void
fleet_spawn(FleetView *view, const char *title, const char *const *arguments)
{
    const char *argv[12];
    guint n = 0;
    argv[n++] = fleet_python();
    argv[n++] = view->tool;
    for (guint i = 0; arguments[i] != NULL && n < G_N_ELEMENTS(argv) - 1; i++) argv[n++] = arguments[i];
    argv[n] = NULL;

    GError *error = NULL;
    GSubprocess *proc = g_subprocess_newv((const gchar *const *) argv,
                                          G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_PIPE,
                                          &error);
    if (proc == NULL) {
        g_autofree char *line = g_strdup_printf("could not start the casebook: %s",
                                                error != NULL ? error->message : "unknown error");
        fleet_log(view, title, line);
        g_clear_error(&error);
        return;
    }
    FleetJob *job = g_new0(FleetJob, 1);
    job->view = view;
    job->title = g_strdup(title);
    view->running++;
    if (view->busy != NULL)
        gtk_label_set_text(GTK_LABEL(view->busy), title);
    /* The callback keeps the subprocess alive: GTask holds the source object
       weakly, so unref'ing here would finalise the piped process mid-flight
       and communicate_finish() would hand back two NULL strings — an action
       that ran and said nothing.  Drop our ref in the completion instead. */
    job->proc = proc;
    g_subprocess_communicate_utf8_async(proc, NULL, NULL, fleet_job_done, job);
}

static const char *
fleet_selected_name(FleetView *view)
{
    if (view->selected != NULL && view->selected[0] != 0) return view->selected;
    if (view->nodes != NULL && view->nodes->len > 0)
        return ((FleetNode *) g_ptr_array_index(view->nodes, 0))->name;
    return "";
}

static void
fleet_action_selected(FleetView *view, const char *verb, const char *title)
{
    const char *name = fleet_selected_name(view);
    if (name[0] == 0) {
        fleet_log(view, title, "no node to act on\n");
        return;
    }
    const char *args[] = { verb, name, NULL };
    fleet_spawn(view, title, args);
}

static void
on_survey(GtkButton *button, gpointer user_data)
{
    (void) button;
    fleet_action_selected(user_data, "node-probe", "Survey node");
}

static void
on_stream(GtkButton *button, gpointer user_data)
{
    (void) button;
    fleet_action_selected(user_data, "node-stream", "Collect one stream window");
}

static void
on_collect(GtkButton *button, gpointer user_data)
{
    (void) button;
    fleet_action_selected(user_data, "node-collect", "Collect node into case");
}

static void
on_dispatch(GtkButton *button, gpointer user_data)
{
    (void) button;
    FleetView *view = user_data;
    const char *name = fleet_selected_name(view);
    const char *module = gtk_editable_get_text(GTK_EDITABLE(view->module_entry));
    const char *verb = gtk_editable_get_text(GTK_EDITABLE(view->verb_entry));
    if (name[0] == 0) {
        fleet_log(view, "Dispatch", "no node to act on\n");
        return;
    }
    if (module[0] == 0 || verb[0] == 0) {
        fleet_log(view, "Dispatch", "dispatch needs a module and a verb, e.g. 06 and --selftest\n");
        return;
    }
    const char *args[] = { "node-dispatch", name, module, verb, NULL };
    fleet_spawn(view, "Dispatch to node", args);
}

static void
on_refresh(GtkButton *button, gpointer user_data)
{
    (void) button;
    fleet_refresh(user_data);
}

static void
fleet_selection_changed(GtkListBox *box, GtkListBoxRow *row, gpointer user_data)
{
    (void) box;
    FleetView *view = user_data;
    if (row == NULL) return;
    const char *name = g_object_get_data(G_OBJECT(row), "node-name");
    g_free(view->selected);
    view->selected = g_strdup(name != NULL ? name : "");
    fleet_detail_show(view, view->selected);
}

/* ── the table ────────────────────────────────────────────────────────── */

static GtkWidget *
fleet_column_label(const char *text, const char *css, int width)
{
    GtkWidget *label = gtk_label_new(text);
    gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(label), PANGO_ELLIPSIZE_END);
    if (width > 0) gtk_widget_set_size_request(label, width, -1);
    if (css != NULL) gtk_widget_add_css_class(label, css);
    return label;
}

static GtkWidget *
fleet_row_new(FleetView *view, FleetNode *node)
{
    GtkWidget *row = gtk_list_box_row_new();
    gtk_widget_add_css_class(row, "fleet-row");
    g_object_set_data_full(G_OBJECT(row), "node-name", g_strdup(node->name), g_free);

    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_column_spacing(GTK_GRID(grid), 14);
    gtk_widget_set_margin_start(grid, 12);
    gtk_widget_set_margin_end(grid, 12);
    gtk_widget_set_margin_top(grid, 7);
    gtk_widget_set_margin_bottom(grid, 7);

    /* status: a dot and the word, because colour alone is not a label */
    GtkWidget *state = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *dot = gtk_label_new("●");
    gtk_widget_add_css_class(dot, "fleet-dot");
    gtk_widget_add_css_class(dot, fleet_tone_class(fleet_status_tone(node->status)));
    gtk_box_append(GTK_BOX(state), dot);
    gtk_box_append(GTK_BOX(state),
                   fleet_column_label(node->status[0] ? node->status : "UNKNOWN",
                                      "fleet-status", 78));

    GtkWidget *name = fleet_column_label(node->name, "fleet-name", 150);
    GtkWidget *klass = fleet_column_label(node->class_name[0] ? node->class_name : "unprobed",
                                          "fleet-class", 110);
    g_autofree char *where = g_strdup_printf("%s · %s",
                                             node->transport[0] ? node->transport : "-",
                                             node->role[0] ? node->role : "-");
    GtkWidget *route = fleet_column_label(where, "fleet-meta", 150);
    g_autofree char *seen = fleet_age_word(node->seen_epoch, g_get_real_time() / G_USEC_PER_SEC);
    GtkWidget *age = fleet_column_label(seen, "fleet-meta", 84);

    g_autofree char *stream = node->streamed
        ? g_strdup_printf("%" G_GINT64_FORMAT " rows · %s", node->stream_rows,
                          fleet_lag_word(node->stream_lag))
        : g_strdup("no stream");
    GtkWidget *heard = fleet_column_label(stream, "fleet-meta", 150);

    gboolean more = FALSE;
    g_autofree char *caps = fleet_short_caps(node->caps, 3, &more);
    GtkWidget *capcell = fleet_column_label(caps, "fleet-meta", 0);
    gtk_widget_set_hexpand(capcell, TRUE);
    gtk_widget_set_tooltip_text(capcell, node->caps[0] ? node->caps : "no capability has been measured");

    gtk_grid_attach(GTK_GRID(grid), state, 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), name, 1, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), klass, 2, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), route, 3, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), age, 4, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), heard, 5, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), capcell, 6, 0, 1, 1);

    if (view->columns[0] != NULL) {
        gtk_size_group_add_widget(view->columns[0], state);
        gtk_size_group_add_widget(view->columns[1], name);
        gtk_size_group_add_widget(view->columns[2], klass);
        gtk_size_group_add_widget(view->columns[3], route);
        gtk_size_group_add_widget(view->columns[4], age);
    }
    gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), grid);
    return row;
}

static GtkWidget *
fleet_header_row(FleetView *view)
{
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_column_spacing(GTK_GRID(grid), 14);
    gtk_widget_set_margin_start(grid, 12);
    gtk_widget_set_margin_end(grid, 12);
    gtk_widget_set_margin_top(grid, 2);
    gtk_widget_set_margin_bottom(grid, 6);
    const char *titles[] = { "STATUS", "NODE", "CLASS", "TRANSPORT · ROLE", "LAST SEEN", "STREAM", "CAPABILITIES" };
    for (int i = 0; i < 7; i++) {
        GtkWidget *label = fleet_column_label(titles[i], "fleet-head", i == 0 ? 96 : 0);
        if (i == 6) gtk_widget_set_hexpand(label, TRUE);
        gtk_grid_attach(GTK_GRID(grid), label, i, 0, 1, 1);
        if (i < 5 && view->columns[i] != NULL)
            gtk_size_group_add_widget(view->columns[i], label);
    }
    return grid;
}

static GtkWidget *
fleet_chip(FleetView *view, const char *label, GtkWidget **out)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 1);
    gtk_widget_add_css_class(box, "fleet-chip");
    GtkWidget *value = gtk_label_new("0");
    gtk_label_set_xalign(GTK_LABEL(value), 0.0f);
    gtk_widget_add_css_class(value, "fleet-chip-value");
    GtkWidget *caption = gtk_label_new(label);
    gtk_label_set_xalign(GTK_LABEL(caption), 0.0f);
    gtk_widget_add_css_class(caption, "fleet-chip-label");
    gtk_box_append(GTK_BOX(box), value);
    gtk_box_append(GTK_BOX(box), caption);
    if (out != NULL) *out = value;
    (void) view;
    return box;
}

/* ── the page ─────────────────────────────────────────────────────────── */

static void
fleet_rebuild_rows(FleetView *view)
{
    GtkWidget *child;
    while ((child = gtk_widget_get_first_child(view->list)) != NULL)
        gtk_list_box_remove(GTK_LIST_BOX(view->list), child);

    for (guint i = 0; i < view->nodes->len; i++) {
        FleetNode *node = g_ptr_array_index(view->nodes, i);
        gtk_list_box_append(GTK_LIST_BOX(view->list), fleet_row_new(view, node));
    }
    gtk_widget_set_visible(view->empty, view->nodes->len == 0);
    gtk_widget_set_visible(view->list, view->nodes->len > 0);

    /* keep the selection across a refresh: an action must not move the
       operator's attention to a different node when the list is redrawn */
    if (view->selected != NULL && view->selected[0] != 0) {
        for (GtkWidget *row = gtk_widget_get_first_child(view->list);
             row != NULL; row = gtk_widget_get_next_sibling(row)) {
            const char *name = g_object_get_data(G_OBJECT(row), "node-name");
            if (g_strcmp0(name, view->selected) == 0) {
                gtk_list_box_select_row(GTK_LIST_BOX(view->list), GTK_LIST_BOX_ROW(row));
                break;
            }
        }
    }
    fleet_detail_show(view, view->selected);
}

static void
fleet_refresh(FleetView *view)
{
    fleet_load_nodes(view);
    fleet_load_streams(view);
    fleet_rebuild_rows(view);

    gint online = 0, unreached = 0, streamed = 0;
    for (guint i = 0; i < view->nodes->len; i++) {
        FleetNode *node = g_ptr_array_index(view->nodes, i);
        if (fleet_status_tone(node->status) == 0) online++;
        else if (fleet_status_tone(node->status) == 2) unreached++;
        if (node->streamed) streamed++;
    }
    g_autofree char *n = g_strdup_printf("%u", view->nodes->len);
    g_autofree char *o = g_strdup_printf("%d", online);
    g_autofree char *u = g_strdup_printf("%d", unreached);
    g_autofree char *s = g_strdup_printf("%d", streamed);
    gtk_label_set_text(GTK_LABEL(view->chip_nodes), n);
    gtk_label_set_text(GTK_LABEL(view->chip_online), o);
    gtk_label_set_text(GTK_LABEL(view->chip_unreached), u);
    gtk_label_set_text(GTK_LABEL(view->chip_streamed), s);
}

static void
fleet_view_free(gpointer data)
{
    FleetView *view = data;
    if (view == NULL) return;
    if (view->nodes != NULL) g_ptr_array_free(view->nodes, TRUE);
    g_free(view->selected);
    g_free(view->tool);
    g_free(view->root);
    g_free(view);
}

GtkWidget *
fleet_page_new(const char *root_dir)
{
    FleetView *view = g_new0(FleetView, 1);
    view->root = g_strdup(root_dir != NULL ? root_dir : "");
    view->tool = g_build_filename(view->root, "tools", "casebook.py", NULL);
    view->nodes = g_ptr_array_new_with_free_func(fleet_node_free);
    for (int i = 0; i < 5; i++) view->columns[i] = gtk_size_group_new(GTK_SIZE_GROUP_HORIZONTAL);

    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_add_css_class(outer, "fleet-page");

    /* header: what the fleet is, and four numbers about it */
    GtkWidget *top = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_add_css_class(top, "fleet-top");
    GtkWidget *titlerow = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    GtkWidget *chiprow = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    GtkWidget *titles = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *title = gtk_label_new("Fleet");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_widget_add_css_class(title, "fleet-title");
    GtkWidget *sub = gtk_label_new("Remote nodes, measured capabilities, captured events.");
    gtk_label_set_xalign(GTK_LABEL(sub), 0.0f);
    gtk_widget_add_css_class(sub, "fleet-sub");
    gtk_box_append(GTK_BOX(titles), title);
    gtk_box_append(GTK_BOX(titles), sub);
    gtk_widget_set_hexpand(titles, TRUE);
    GtkWidget *refresh = gtk_button_new_with_label("Refresh");
    gtk_widget_set_valign(refresh, GTK_ALIGN_CENTER);
    g_signal_connect(refresh, "clicked", G_CALLBACK(on_refresh), view);
    gtk_box_append(GTK_BOX(titlerow), titles);
    gtk_box_append(GTK_BOX(titlerow), refresh);
    gtk_box_append(GTK_BOX(chiprow), fleet_chip(view, "NODES", &view->chip_nodes));
    gtk_box_append(GTK_BOX(chiprow), fleet_chip(view, "ONLINE", &view->chip_online));
    gtk_box_append(GTK_BOX(chiprow), fleet_chip(view, "UNREACHABLE", &view->chip_unreached));
    gtk_box_append(GTK_BOX(chiprow), fleet_chip(view, "STREAMED", &view->chip_streamed));
    gtk_box_append(GTK_BOX(top), titlerow);
    gtk_box_append(GTK_BOX(top), chiprow);
    gtk_box_append(GTK_BOX(outer), top);

    /* the table */
    GtkWidget *table_card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_add_css_class(table_card, "fleet-card");
    GtkWidget *scroller = gtk_scrolled_window_new();
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroller),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_vexpand(scroller, TRUE);
    /* enough height to show a handful of nodes without scrolling: the table
       is the page, and a table that shows two rows of eight is a teaser */
    gtk_widget_set_size_request(scroller, -1, 170);

    view->list = gtk_list_box_new();
    gtk_widget_add_css_class(view->list, "fleet-table");
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(view->list), GTK_SELECTION_SINGLE);
    g_signal_connect(view->list, "row-selected", G_CALLBACK(fleet_selection_changed), view);

    GtkWidget *stack = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_box_append(GTK_BOX(stack), fleet_header_row(view));
    gtk_box_append(GTK_BOX(stack), view->list);

    view->empty = gtk_label_new(
        "No nodes yet. Add one from Casebook → Nodes, or with the command line:\n"
        "tools/casebook.py --node-add <name> <host> ssh sensor\n"
        "Then survey it here and the class, capabilities and last-seen appear.");
    gtk_label_set_xalign(GTK_LABEL(view->empty), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(view->empty), TRUE);
    gtk_widget_add_css_class(view->empty, "fleet-empty");
    gtk_widget_set_visible(view->empty, FALSE);
    gtk_box_append(GTK_BOX(stack), view->empty);

    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroller), stack);
    gtk_box_append(GTK_BOX(table_card), scroller);
    gtk_box_append(GTK_BOX(outer), table_card);

    /* detail + actions */
    GtkWidget *detail_card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_add_css_class(detail_card, "fleet-detail");
    view->detail_title = gtk_label_new("No node selected");
    gtk_label_set_xalign(GTK_LABEL(view->detail_title), 0.0f);
    gtk_widget_add_css_class(view->detail_title, "fleet-detail-title");
    view->detail_sub = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(view->detail_sub), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(view->detail_sub), TRUE);
    gtk_widget_add_css_class(view->detail_sub, "fleet-meta");
    view->detail_caps = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(view->detail_caps), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(view->detail_caps), TRUE);
    gtk_widget_add_css_class(view->detail_caps, "fleet-caps");
    view->detail_store = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(view->detail_store), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(view->detail_store), TRUE);
    gtk_widget_add_css_class(view->detail_store, "fleet-meta");
    gtk_box_append(GTK_BOX(detail_card), view->detail_title);
    gtk_box_append(GTK_BOX(detail_card), view->detail_sub);
    gtk_box_append(GTK_BOX(detail_card), view->detail_caps);
    gtk_box_append(GTK_BOX(detail_card), view->detail_store);

    GtkWidget *actions = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *acts = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_add_css_class(acts, "fleet-actions");
    GtkWidget *survey = gtk_button_new_with_label("Survey node");
    GtkWidget *stream = gtk_button_new_with_label("Collect stream window");
    GtkWidget *collect = gtk_button_new_with_label("Copy to case");
    gtk_widget_add_css_class(survey, "primary");
    gtk_widget_set_tooltip_text(survey,
        "Runs casebook.py node-probe: class, capabilities and last-seen for this node. "
        "It asks the node, so an unreachable box becomes OFFLINE rather than staying UNKNOWN.");
    gtk_widget_set_tooltip_text(stream,
        "Runs casebook.py node-stream once: drains the node's own spool from where this side "
        "stopped, so a link that dropped an hour ago still yields the traffic it missed.");
    gtk_widget_set_tooltip_text(collect,
        "Runs casebook.py node-collect: copies the node's artefacts into the active case as evidence.");
    g_signal_connect(survey, "clicked", G_CALLBACK(on_survey), view);
    g_signal_connect(stream, "clicked", G_CALLBACK(on_stream), view);
    g_signal_connect(collect, "clicked", G_CALLBACK(on_collect), view);
    gtk_box_append(GTK_BOX(acts), survey);
    gtk_box_append(GTK_BOX(acts), stream);
    gtk_box_append(GTK_BOX(acts), collect);
    gtk_box_append(GTK_BOX(actions), acts);

    /* dispatch: a module and a verb, run there, rows kept here */
    GtkWidget *dispatch = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *dlabel = gtk_label_new("Run module");
    gtk_widget_add_css_class(dlabel, "fleet-chip-label");
    view->module_entry = gtk_entry_new();
    view->verb_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(view->module_entry), "06 or 06_gsm_air");
    gtk_entry_set_placeholder_text(GTK_ENTRY(view->verb_entry), "--selftest");
    gtk_widget_set_size_request(view->module_entry, 120, -1);
    gtk_widget_set_size_request(view->verb_entry, 150, -1);
    GtkWidget *run = gtk_button_new_with_label("Dispatch");
    gtk_widget_set_tooltip_text(run,
        "Runs casebook.py node-dispatch: the module executes on the node and its rows are kept "
        "under state/nodes/dispatch. A node with no toolkit is a handoff (exit 3), not a result.");
    g_signal_connect(run, "clicked", G_CALLBACK(on_dispatch), view);
    gtk_box_append(GTK_BOX(dispatch), dlabel);
    gtk_box_append(GTK_BOX(dispatch), view->module_entry);
    gtk_box_append(GTK_BOX(dispatch), view->verb_entry);
    gtk_box_append(GTK_BOX(dispatch), run);
    gtk_box_append(GTK_BOX(actions), dispatch);
    gtk_box_append(GTK_BOX(detail_card), actions);

    view->busy = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(view->busy), 0.0f);
    gtk_widget_add_css_class(view->busy, "fleet-busy");
    gtk_box_append(GTK_BOX(detail_card), view->busy);

    /* the log: the command's own rows, verbatim */
    GtkWidget *log_scroll = gtk_scrolled_window_new();
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(log_scroll),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_size_request(log_scroll, -1, 140);
    view->log_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(view->log_view), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(view->log_view), TRUE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(view->log_view), GTK_WRAP_WORD_CHAR);
    gtk_widget_add_css_class(view->log_view, "fleet-log");
    view->log = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view->log_view));
    gtk_text_buffer_set_text(view->log,
        "Nothing run yet. Survey a node to learn what it is, then stream it to hear what it hears.\n",
        -1);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(log_scroll), view->log_view);
    gtk_box_append(GTK_BOX(detail_card), log_scroll);
    gtk_box_append(GTK_BOX(outer), detail_card);

    /* The page is taller than a small window: the table wants room and the log
       wants room, and a window cannot grow for both.  One scroller around the
       whole page means nothing is ever unreachable, and the table keeps its own
       scroller so a long fleet does not push the actions off the page. */
    GtkWidget *scroll = gtk_scrolled_window_new();
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), outer);

    g_object_set_data_full(G_OBJECT(scroll), "fleet-view", view, fleet_view_free);
    view->page = scroll;
    fleet_refresh(view);
    return scroll;
}

/* ── selftest ─────────────────────────────────────────────────────────── */

static gboolean
fleet_near(gint64 got, gint64 want)
{
    return got == want;
}

int
fleet_page_selftest(void)
{
    int failed = 0;
    gint64 now = 1755000000;

    struct { const char *what; const char *header; const char *want_col; int want; } cols[] = {
        { "fleet-col-name",     "name\thost\ttransport\tclass\trole\tcaps\tadded\tlast_seen\tstatus\tdetail", "class", 3 },
        { "fleet-col-port",     "name\thost\tport\ttransport\tclass", "port", 2 },
        { "fleet-col-missing",  "name\thost\ttransport", "caps", -1 },
        { "fleet-col-empty",    "", "name", -1 },
    };
    for (guint i = 0; i < G_N_ELEMENTS(cols); i++) {
        int got = fleet_col(cols[i].header, cols[i].want_col);
        if (fleet_near(got, cols[i].want)) g_print("%s\tPASS\tcolumn %d\n", cols[i].what, got);
        else { g_print("%s\tFAIL\tgot %d want %d\n", cols[i].what, got, cols[i].want); failed++; }
    }

    {
        const char *row = "desk\tlocalhost\t\tlocal\tsdr\tsensor\tshell,at\t2026-01-01T00:00:00Z\t2026-10-25T08:00:00Z\tONLINE\thost=lab";
        g_autofree char *name = fleet_field(row, 0);
        g_autofree char *empty = fleet_field(row, 2);
        g_autofree char *past_end = fleet_field(row, 40);
        if (g_strcmp0(name, "desk") == 0) g_print("fleet-field-name\tPASS\t%s\n", name);
        else { g_print("fleet-field-name\tFAIL\t%s\n", name); failed++; }
        if (empty[0] == 0) g_print("fleet-field-empty\tPASS\tempty column stays empty\n");
        else { g_print("fleet-field-empty\tFAIL\t%s\n", empty); failed++; }
        if (past_end[0] == 0) g_print("fleet-field-short-row\tPASS\tshort row reads empty, not crash\n");
        else { g_print("fleet-field-short-row\tFAIL\t%s\n", past_end); failed++; }
    }

    struct { const char *what; const char *status; int tone; } tones[] = {
        { "fleet-tone-online",  "ONLINE",  0 },
        { "fleet-tone-offline", "OFFLINE", 2 },
        { "fleet-tone-unknown", "UNKNOWN", 3 },
        { "fleet-tone-empty",   "",        3 },
        { "fleet-tone-dash",    "-",       3 },
        { "fleet-tone-odd",     "PENDING", 1 },
    };
    for (guint i = 0; i < G_N_ELEMENTS(tones); i++) {
        int got = fleet_status_tone(tones[i].status);
        if (got == tones[i].tone) g_print("%s\tPASS\ttone %d\n", tones[i].what, got);
        else { g_print("%s\tFAIL\tgot %d want %d\n", tones[i].what, got, tones[i].tone); failed++; }
    }

    struct { const char *what; gint64 when; const char *want; } ages[] = {
        { "fleet-age-never",   0,             "never" },
        { "fleet-age-now",     now - 5,       "just now" },
        { "fleet-age-minutes", now - 300,     "5 min" },
        { "fleet-age-hours",   now - 7200,    "2 h" },
        { "fleet-age-days",    now - 3*86400, "3 d" },
        { "fleet-age-future",  now + 600,     "just now" },
    };
    for (guint i = 0; i < G_N_ELEMENTS(ages); i++) {
        g_autofree char *got = fleet_age_word(ages[i].when, now);
        if (g_strcmp0(got, ages[i].want) == 0) g_print("%s\tPASS\t%s\n", ages[i].what, got);
        else { g_print("%s\tFAIL\tgot %s want %s\n", ages[i].what, got, ages[i].want); failed++; }
    }

    {
        g_autofree char *live = fleet_lag_word(30);
        g_autofree char *stale = fleet_lag_word(600);
        g_autofree char *none = fleet_lag_word(-1);
        if (g_strcmp0(live, "live") == 0) g_print("fleet-lag-live\tPASS\t%s\n", live);
        else { g_print("fleet-lag-live\tFAIL\t%s\n", live); failed++; }
        if (g_strcmp0(stale, "10 min stale") == 0) g_print("fleet-lag-stale\tPASS\t%s\n", stale);
        else { g_print("fleet-lag-stale\tFAIL\t%s\n", stale); failed++; }
        if (g_strcmp0(none, "no stream") == 0) g_print("fleet-lag-none\tPASS\t%s\n", none);
        else { g_print("fleet-lag-none\tFAIL\t%s\n", none); failed++; }
    }

    {
        gboolean more = TRUE;
        g_autofree char *short_caps = fleet_short_caps("at,qmi,mbim,modem,gps", 3, &more);
        g_autofree char *blank = fleet_short_caps("", 3, NULL);
        g_autofree char *dash = fleet_short_caps("-", 3, NULL);
        if (g_strcmp0(short_caps, "at, qmi, mbim +2") == 0 && more)
            g_print("fleet-caps-short\tPASS\t%s\n", short_caps);
        else { g_print("fleet-caps-short\tFAIL\t%s\n", short_caps); failed++; }
        if (g_strcmp0(blank, "none measured") == 0) g_print("fleet-caps-blank\tPASS\t%s\n", blank);
        else { g_print("fleet-caps-blank\tFAIL\t%s\n", blank); failed++; }
        if (g_strcmp0(dash, "none measured") == 0) g_print("fleet-caps-dash\tPASS\t%s\n", dash);
        else { g_print("fleet-caps-dash\tFAIL\t%s\n", dash); failed++; }
    }

    {
        gint64 stamp = fleet_epoch("2026-10-25T08:00:00Z");
        gint64 not_stamp = fleet_epoch("-");
        gint64 empty = fleet_epoch("");
        if (stamp == 1792915200) g_print("fleet-epoch-iso\tPASS\t%" G_GINT64_FORMAT "\n", stamp);
        else { g_print("fleet-epoch-iso\tFAIL\t%" G_GINT64_FORMAT "\n", stamp); failed++; }
        if (not_stamp == 0 && empty == 0) g_print("fleet-epoch-empty\tPASS\tno stamp reads as never\n");
        else { g_print("fleet-epoch-empty\tFAIL\t%" G_GINT64_FORMAT "/%" G_GINT64_FORMAT "\n",
                       not_stamp, empty); failed++; }
    }

    g_print("RESULT\t%s\n", failed == 0 ? "PASS" : "FAIL");
    return failed;
}
