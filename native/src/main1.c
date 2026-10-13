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
#include <fcntl.h>
#include <sys/stat.h>

#ifdef HAVE_VTE
#include <vte/vte.h>
#endif

#include "config.h"

/* The generated module index. tools/gen-module-index.sh rewrites this file;
   it is included rather than linked so the GUI always agrees with the tree. */
#include "module_index.c"

#ifndef IMSISTING_VERSION
#define IMSISTING_VERSION "0.1"
#endif

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
static const char *
category_class(const char *cat)
{
    if (cat == NULL) return "cat-system";
    if (g_strcmp0(cat, "RECON") == 0)        return "cat-recon";
    if (g_strcmp0(cat, "AIR INTERFACE") == 0) return "cat-air";
    if (g_strcmp0(cat, "CORE NETWORK") == 0) return "cat-core";
    if (g_strcmp0(cat, "SIM / IDENTITY") == 0) return "cat-sim";
    if (g_strcmp0(cat, "ATTACKS") == 0)      return "cat-attacks";
    if (g_strcmp0(cat, "ANALYSIS") == 0)     return "cat-analysis";
    if (g_strcmp0(cat, "RF / TRACKING") == 0) return "cat-rf";
    return "cat-system";
}

typedef struct {
    const char *name;
    const char *icon;
    GtkWidget *(*build_page)(AppState *state, gpointer module_data);
} ModuleSubmenuEntry;

typedef struct {
    AppState *state;
    const ModuleDefinition *module;
    GtkWidget *page;
    GtkWidget *submenu_list;
    GtkWidget *stack;
    GtkWidget *header_box;
    GtkWidget *status_pill;
    gpointer module_data;
    ModuleSubmenuEntry *entries;
    int n_entries;
} ModulePage;

struct _AppState {
    GtkApplication *application;
    GtkWidget *window;
    GtkWidget *sidebar;
    GtkWidget *notebook;
    GtkWidget *event_drawer;
    GtkWidget *event_revealer;
    GtkTextBuffer *event_buffer;
    GtkWidget *toast_box;

    /* Diagnostics: stderr is redirected here and polled into the drawer. */
    int stderr_fd;
    off_t stderr_pos;

    GPtrArray *running;

    /* Permanent-tab and status-strip widgets. */
    GtkWidget *sidebar_paned;
    GtkWidget *sidebar_toggle;
    GtkWidget *status_sdr, *status_tx, *status_cells, *status_gps, *status_freq;
    GtkWidget *loot_list;
    GtkWidget *stats_view;
    GtkWidget *settings_ids_switch;
    guint      status_source;

    /* Live GSMTAP feed. */
    GtkWidget     *live_view;          /* the GtkColumnView */
    GtkWidget     *live_status;
    GtkWidget     *live_button;
    GtkWidget     *live_filter_entry;
    GtkWidget     *live_summary;       /* count / rate chip */
    GtkWidget     *live_empty;         /* empty-state box */
    GSocket       *live_socket;
    GListStore    *live_store;         /* what the view shows */
    GPtrArray     *live_msgs;          /* retained, filtered into the store */
    char          *live_filter;
    guint          live_poll;          /* timer that drains the socket */
    guint          live_count;
    guint          live_hint;

    /* Event drawer chrome. */
    GtkWidget     *event_filter_entry;
    GtkWidget     *event_badge;
    GtkWidget     *event_button;
    gboolean       event_autoscroll;
    gboolean       event_errors_only;
    guint          event_errors;

    /* Loot preview pane. */
    GtkWidget     *loot_preview;
    GtkTextBuffer *loot_preview_buf;
    char          *loot_preview_path;
};

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
} ActionRun;

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
      "system-software-install-symbolic",
      "Checks the cellular toolchain against a per-distro table and installs what is missing." },
    { "01_radio",            "SDR / Radio Manager",  "SYSTEM",
      "radio-symbolic",
      "Enumerates SDRs, reports driver, serial and range, and flags receive-only devices." },
    { "05_field_kit",        "Field Kit",            "SYSTEM",
      "preferences-system-symbolic",
      "RF pre-flight, honesty verification of every radio verb, and a synthetic GSMTAP source." },
    { "30_killchain",        "Cellular Killchain",   "SYSTEM",
      "media-playback-start-symbolic",
      "Chains module verbs into repeatable runs from a TSV chain file." },

    /* RECON — survey and passive observation */
    { "02_cell_recon",       "Cell Recon",           "RECON",
      "network-wireless-symbolic",
      "ARFCN/EARFCN/NR-ARFCN to frequency, PLMN to operator, and a cell survey from an SDR or capture." },
    { "03_gsmtap",           "GSMTAP Passive",       "RECON",
      "network-receive-symbolic",
      "GSMTAP header codec and pcap I/O; listens for gr-gsm and srsRAN traffic." },
    { "04_tower_map",        "Tower Survey",         "RECON",
      "mark-location-symbolic",
      "GPS-tagged cell survey with CSV, KML and GeoJSON export." },
    { "54_ntn",              "5G NTN / Satellite",   "RECON",
      "network-cellular-5g-symbolic",
      "Non-terrestrial access: Doppler, round-trip delay, TA, k_offset and the SIB19 fields." },
    { "58_non3gpp",          "TETRA / DMR / GSM-R",  "RECON",
      "radio-symbolic",
      "Non-3GPP land mobile radio: TETRA, DMR and GSM-R structure, ciphers and band classification." },

    /* AIR INTERFACE — per-RAT decoding and encoding */
    { "10_gsm_air",          "GSM Air Interface",    "AIR INTERFACE",
      "network-cellular-2g-symbolic",
      "GSM system information, paging, cipher audit and A5/1 keystream, proved against the BGW vector." },
    { "12_umts_air",         "UMTS Air Interface",   "AIR INTERFACE",
      "network-cellular-3g-symbolic",
      "UMTS UARFCN, SIB decode, RRC integrity (UIA1/UIA2) and the AKA relay flow." },
    { "14_lte_air",          "LTE Air Interface",    "AIR INTERFACE",
      "network-wireless-symbolic",
      "LTE EARFCN, RRC/SIB decode, paging maths and srsRAN eNB orchestration." },
    { "16_nr_air",           "5G NR Air Interface",  "AIR INTERFACE",
      "network-cellular-5g-symbolic",
      "NR-ARFCN, MIB/SIB1 decode, PCI, PRACH occasions and gNB config generation." },
    { "50_iot",              "NB-IoT / Cat-M1",      "AIR INTERFACE",
      "network-cellular-2g-symbolic",
      "NB-IoT and Cat-M1: NPRACH, NPSS/NSSS, SIB1-NB and NPRFCN." },
    { "55_gprs",             "GPRS / EDGE",          "AIR INTERFACE",
      "network-cellular-2g-symbolic",
      "GPRS/EDGE packet-switched: GEA ciphering, APN coding, PDP context and downgrade detection." },
    { "56_sidelink",         "NR Sidelink / V2X",    "AIR INTERFACE",
      "network-wireless-symbolic",
      "NR sidelink on PC5: resource pools, SCI-1A, ITS certificates and relay checks." },

    /* CORE NETWORK — attach, core, interconnect and roaming */
    { "13_lte_attach",       "LTE Attach / NAS",     "CORE NETWORK",
      "network-cellular-4g-symbolic",
      "NAS EMM/ESM encode-decode, BCD IMSI/IMEI, attach forge and identity-exposure detection." },
    { "15_lte_core",         "LTE Core (EPC)",       "CORE NETWORK",
      "network-server-symbolic",
      "Diameter S6a/S6d, GTP-C/GTP-U and S1AP; decodes the EPC core and forges registration moves." },
    { "17_nr_core",          "5G Core (SBA)",        "CORE NETWORK",
      "network-server-symbolic",
      "5G SBA: NGAP, 5GS NAS, 5G-GUTI, PFCP rules and 5G-AKA." },
    { "31_ss7_map",          "SS7 / MAP / GRX",      "CORE NETWORK",
      "network-server-symbolic",
      "MTP3/SCCP/TCAP/MAP decode, SRI/ATI/PSI flows and GRX reachability." },
    { "32_cellular_dns",     "DNS over Cellular",    "CORE NETWORK",
      "network-wired-symbolic",
      "DNS encode-decode, the aLTEr redirection sequence and response-tampering detection." },
    { "39_slicing",          "Network Slicing",      "CORE NETWORK",
      "network-cellular-5g-symbolic",
      "S-NSSAI encode-decode, slice selection and cross-slice isolation testing." },
    { "41_vowifi",           "VoWiFi / ePDG",        "CORE NETWORK",
      "network-wired-symbolic",
      "IKEv2 over SWu, EAP-AKA, the SWu NAI and an encryption/integrity transform audit." },
    { "42_femtocell",        "Femtocell / HeNB",     "CORE NETWORK",
      "network-server-symbolic",
      "HeNB assessment: CSG/PCI conflicts, the Iuh stack and a TR-069 management audit." },
    { "43_ussd",             "USSD",                 "CORE NETWORK",
      "network-cellular-2g-symbolic",
      "USSD/MMI parsing, 7-bit packing and USSD/STK injection detection." },
    { "45_sba_pivot",        "5G SBA Pivot",         "CORE NETWORK",
      "network-server-symbolic",
      "HTTP/2 SBI framing, NRF discovery and OAuth2 token audit." },
    { "48_ran_share",        "RAN Sharing",          "CORE NETWORK",
      "network-wired-symbolic",
      "PLMN coding, MOCN/MORAN/GWCN classification and cross-operator leakage detection." },
    { "52_wifioff",          "Wi-Fi Offload / LWA",  "CORE NETWORK",
      "network-wired-symbolic",
      "Wi-Fi offload and LWA: ePDG FQDN, certificate validation and LWA configuration." },

    /* SIM / IDENTITY — the subscription and its keys */
    { "18_suci",             "SUCI / SUPI",          "SIM / IDENTITY",
      "channel-secure-symbolic",
      "SUCI conceal/deconceal (ECIES profile A/B), HKDF and the null-scheme audit." },
    { "20_sim",              "SIM / eSIM / OTA",     "SIM / IDENTITY",
      "auth-smartcard-symbolic",
      "ISO-7816 APDU, USIM files, EF_AD in both layouts, OTA parsing and eSIM profiles." },
    { "36_sim_defense",      "SIM Swap Defence",     "SIM / IDENTITY",
      "channel-secure-symbolic",
      "Detection and defence for a SIM port in flight, plus eSIM profile integrity." },
    { "46_ota_sms",          "OTA Binary SMS",       "SIM / IDENTITY",
      "auth-smartcard-symbolic",
      "TS 23.048 OTA command-packet construction with an SPI/counter/key audit. Own-SIM and lab." },
    { "57_stk",              "SIM Toolkit (STK)",    "SIM / IDENTITY",
      "auth-smartcard-symbolic",
      "TS 31.111 proactive commands: build, parse and audit for silent off-device actions." },

    /* ATTACKS — offensive vectors and CVE kits */
    { "11_gsm_attack",       "GSM Attack",           "ATTACKS",
      "security-high-symbolic",
      "IMSI-catcher sequence, A5/1 downgrade, TMSI de-anonymisation and Kc recovery." },
    { "19_downgrade",        "Downgrade Attacks",    "ATTACKS",
      "go-down-symbolic",
      "Reject causes, null-cipher tables, Security Mode Command and downgrade detection." },
    { "24_gsm_cve",          "GSM/UMTS CVE Kit",     "ATTACKS",
      "application-x-executable-symbolic",
      "Per-CVE probes and handoffs for 2G/3G stack bugs." },
    { "25_lte_cve",          "LTE CVE Kit",          "ATTACKS",
      "application-x-executable-symbolic",
      "LTE stack CVEs: baseband, NAS, ASN.1 and Diameter." },
    { "26_nr_cve",           "5G CVE Kit",           "ATTACKS",
      "application-x-executable-symbolic",
      "5G NR, SBA and SUCI CVEs." },
    { "35_volte_ims",        "VoLTE / IMS",          "ATTACKS",
      "audio-input-microphone-symbolic",
      "VoLTE keystream reuse (ReVoLTE), IMP4GT identity mapping and SIP/IMS analysis." },
    { "40_baseband",         "Baseband Research",    "ATTACKS",
      "application-x-executable-symbolic",
      "Baseband research scaffolding: ASN.1 mutation, corpus generation and crash triage." },
    { "53_oran",             "O-RAN / Open RAN",     "ATTACKS",
      "network-server-symbolic",
      "O-RAN interfaces, deployment assessment and xApp-authority modelling." },
    { "59_baseband_exploit", "Baseband Exploits",    "ATTACKS",
      "application-x-executable-symbolic",
      "L1/L2 malformed-PDU construction, 5G control-plane forgery, and the baseband CVE catalogue." },
    { "60_nr_inject",        "5G NR Injection",      "ATTACKS",
      "network-cellular-5g-symbolic",
      "NR RNTI tracking, MAC-NR framing, descrambling and the injection exploit set." },

    /* ANALYSIS — captures, identities and signalling */
    { "21_pcap_analysis",    "Capture Analysis",     "ANALYSIS",
      "document-open-symbolic",
      "From-scratch pcap reader that dissects GSMTAP, Diameter, NGAP, S1AP, GTP, PFCP and RTP." },
    { "22_imsi_exposure",    "IMSI Exposure Audit",  "ANALYSIS",
      "dialog-warning-symbolic",
      "TMSI/GUTI to IMSI correlation, cross-capture audit and per-subscriber exposure scoring." },
    { "23_cipher_audit",     "Cipher Audit",         "ANALYSIS",
      "channel-secure-symbolic",
      "Scores negotiated ciphers per session across 2G-5G and finds null or downgraded bearers." },
    { "27_traffic_analysis", "Traffic Analysis",     "ANALYSIS",
      "network-wireless-symbolic",
      "Flow and burst analysis, website fingerprinting and padding/shaping detection." },
    { "34_mac_layer",        "MAC Layer",            "ANALYSIS",
      "network-receive-symbolic",
      "LTE MAC PDU decode, RNTI tracking, scheduling-pattern inference and DCI/MCS mapping." },
    { "37_nas_signaling",    "NAS Signalling",       "ANALYSIS",
      "network-cellular-4g-symbolic",
      "NAS message-rate measurement, procedure mix and signalling-storm detection." },
    { "47_li_probe",         "LI Discovery",         "ANALYSIS",
      "dialog-warning-symbolic",
      "Lawful-interception interfaces and interception-posture signals. Detection only." },
    { "49_carrier_api",      "Carrier API Audit",    "ANALYSIS",
      "channel-secure-symbolic",
      "Carrier API surface, authorisation-boundary testing and token/rate-limit audit." },

    /* RF / TRACKING — interference and position */
    { "28_rf_fingerprint",   "RF Fingerprint / CSI", "RF / TRACKING",
      "radio-symbolic",
      "IQ fingerprinting (CFO, IRR, transients) and CSI side-channel extraction." },
    { "33_paging_track",     "Paging / Torpedo",     "RF / TRACKING",
      "network-cellular-2g-symbolic",
      "Paging occasion maths, paging capture, and the Torpedo/Piercer models." },
    { "38_jamming_detect",   "Jamming Detection",    "RF / TRACKING",
      "dialog-warning-symbolic",
      "Measures interference and discriminates jamming from congestion or a coverage hole." },
    { "44_ta_geoloc",        "TA Geolocation",       "RF / TRACKING",
      "mark-location-symbolic",
      "Timing-advance ranging and multi-cell trilateration from TA measurements." },
    { "51_lpp",              "LPP Positioning",      "RF / TRACKING",
      "mark-location-symbolic",
      "LTE Positioning Protocol: procedure codes, header codec and position-forgery detection." },
};

#define N_MODULES ((int) G_N_ELEMENTS(modules))

/* ==================================================================== */
/*  FORWARD DECLARATIONS                                                */
/* ==================================================================== */

static void append_event(AppState *state, const char *message);
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

static AppState *g_app_state = NULL;

/* --tab N opens the GUI on the Nth permanent tab (0 Dashboard, 1 Live
   Traffic, 2 Loot, 3 Stats, 4 Help, 5 Settings). -1 leaves the default. */
static int g_start_tab = -1;

/* --module <id> opens that module's page at startup. */
static const char *g_start_module = NULL;

/* ==================================================================== */
/*  SMALL HELPERS                                                       */
/* ==================================================================== */

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
   in the events drawer instead of on a terminal nobody is watching. */

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

static void
toast_close_clicked(GtkButton *button, gpointer user_data)
{
    GtkWidget *toast = user_data;
    GtkWidget *parent = gtk_widget_get_parent(toast);
    if (parent != NULL)
        gtk_box_remove(GTK_BOX(parent), toast);
    (void) button;
}

static void
show_toast_full(AppState *state, const char *title,
                const char *message, const char *severity)
{
    if (state == NULL || state->toast_box == NULL) return;

    GtkWidget *toast = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_widget_add_css_class(toast, "toast");
    if (g_strcmp0(severity, "error") == 0)
        gtk_widget_add_css_class(toast, "toast-error");
    else if (g_strcmp0(severity, "ok") == 0)
        gtk_widget_add_css_class(toast, "toast-ok");

    g_autofree char *text = NULL;
    if (title != NULL && *title != '\0')
        text = g_strdup_printf("<b>%s</b>\n%s", title, message ? message : "");
    else
        text = g_strdup(message ? message : "");

    GtkWidget *label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(label), text);
    gtk_label_set_wrap(GTK_LABEL(label), TRUE);
    gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
    gtk_widget_set_hexpand(label, TRUE);

    GtkWidget *close = gtk_button_new_from_icon_name("window-close-symbolic");
    gtk_widget_add_css_class(close, "flat");
    g_signal_connect(close, "clicked", G_CALLBACK(toast_close_clicked), toast);

    gtk_box_append(GTK_BOX(toast), label);
    gtk_box_append(GTK_BOX(toast), close);
    gtk_box_append(GTK_BOX(state->toast_box), toast);
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
    if (css != NULL)
        gtk_widget_add_css_class(label, css);
}

static void action_read_line(ActionRun *run, gboolean is_err);

static void
action_run_unref(ActionRun *run)
{
    if (run == NULL) return;
    if (--run->refs > 0) return;

    if (run->state->running != NULL &&
        g_ptr_array_find(run->state->running, run, NULL))
        g_ptr_array_remove(run->state->running, run);

    g_clear_object(&run->proc);
    g_clear_object(&run->out);
    g_clear_object(&run->err);
    if (run->captured != NULL) g_string_free(run->captured, TRUE);
    g_free(run->module_id);
    g_free(run->label);
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

    /* A module that prints ERROR, or that exits non-zero, is a failure even
       when the spawn itself succeeded. Reporting "done" here would be the
       exact bug this toolkit exists to avoid. */
    if (!ok || status != 0 || run->saw_error) {
        g_autofree char *m = g_strdup_printf("%s: failed (exit %d)",
                                             run->label, status);
        append_event(state, m);
        show_toast_full(state, run->label, m, "error");
        status_label_set(run->status_label, "Error", "status-error");
    } else {
        g_autofree char *m = g_strdup_printf("%s: done", run->label);
        append_event(state, m);
        status_label_set(run->status_label, "Done", "status-ok");
    }

    action_run_unref(run);
}

static void
imsisting_action_run(AppState *state, const char *module_id,
                     const char *label, GtkWidget *status_label,
                     const char *const *argv, gboolean privileged)
{
    g_autoptr(GError) error = NULL;
    GSubprocess *proc;

    if (state == NULL || argv == NULL || argv[0] == NULL) return;

    append_event(state, label);
    status_label_set(status_label, "Running", "status-running");

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

/* Run a module verb with one extra literal argument. */
static void
run_module_verb_arg(AppState *state, const char *module_id, const char *verb,
                    const char *arg, const char *label,
                    GtkWidget *status_label, gboolean privileged)
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

    const char *argv[4] = { script, verb, arg, NULL };
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

/* A row of buttons, each running one verb. This is what most modules use;
   a module with a bespoke view registers its own builder instead. */
typedef struct {
    const char *verb;
    const char *label;
    gboolean privileged;
} VerbButton;

/* Run an arbitrary verb typed into the page's run box. The buttons cover the
 * common case; this box is the guarantee that no verb a module implements is
 * locked out of the GUI just because its page did not list it. */
static void
verb_any_run_clicked(GtkButton *button, gpointer user_data)
{
    AppState *state = g_object_get_data(G_OBJECT(button), "state");
    const char *module_id = g_object_get_data(G_OBJECT(button), "module-id");
    GtkWidget *status = g_object_get_data(G_OBJECT(button), "status");
    GtkWidget *entry = g_object_get_data(G_OBJECT(button), "arg-entry");

    const char *text = gtk_editable_get_text(GTK_EDITABLE(entry));
    if (text == NULL || *text == '\0') {
        show_toast_full(state, module_id, "enter a verb, e.g. --status-tsv", "error");
        return;
    }

    g_autofree char *script = module_script_path(module_id);
    if (!g_file_test(script, G_FILE_TEST_IS_EXECUTABLE)) {
        g_autofree char *m = g_strdup_printf(
            "module %s is not executable at %s", module_id, script);
        append_event(state, m);
        show_toast_full(state, module_id, m, "error");
        status_label_set(status, "Missing", "status-error");
        return;
    }

    g_auto(GStrv) tokens = g_strsplit_set(text, " \t", -1);
    GPtrArray *argv = g_ptr_array_new();
    g_ptr_array_add(argv, script);
    for (int i = 0; tokens[i] != NULL; i++) {
        if (*tokens[i] == '\0') continue;
        g_ptr_array_add(argv, tokens[i]);
    }
    g_ptr_array_add(argv, NULL);

    g_autofree char *label = g_strdup_printf("%s %s", module_id, text);
    imsisting_action_run(state, module_id, label, status,
                         (const char *const *) argv->pdata, FALSE);
    g_ptr_array_unref(argv);

    GtkWidget *lastrun = g_object_get_data(G_OBJECT(button), "last-run");
    if (lastrun != NULL) {
        GDateTime *now = g_date_time_new_now_local();
        g_autofree char *t = g_date_time_format(now, "%H:%M:%S");
        g_autofree char *m = g_strdup_printf("last run %s · output in Events", t);
        gtk_label_set_text(GTK_LABEL(lastrun), m);
        g_date_time_unref(now);
    }
    (void) user_data;
}

/* Copy the typed verb as a shell command, so the GUI and the terminal agree. */
static void
verb_copy_clicked(GtkButton *button, gpointer user_data)
{
    const char *module_id = g_object_get_data(G_OBJECT(button), "module-id");
    GtkWidget *entry = g_object_get_data(G_OBJECT(button), "arg-entry");
    const char *text = entry ? gtk_editable_get_text(GTK_EDITABLE(entry)) : "";
    g_autofree char *cmd = g_strdup_printf("modules/%s.sh %s",
                                           module_id ? module_id : "", text ? text : "");
    gdk_clipboard_set_text(gtk_widget_get_clipboard(GTK_WIDGET(button)), cmd);
    (void) user_data;
}

static void
verb_button_clicked(GtkButton *button, gpointer user_data)
{
    AppState *state = g_object_get_data(G_OBJECT(button), "state");
    const char *module_id = g_object_get_data(G_OBJECT(button), "module-id");
    const VerbButton *vb = user_data;
    GtkWidget *status = g_object_get_data(G_OBJECT(button), "status");

    g_autofree char *label = g_strdup_printf("%s %s", module_id, vb->verb);
    run_module_verb(state, module_id, vb->verb, label, status, vb->privileged);
}

static void
verb_arg_button_clicked(GtkButton *button, gpointer user_data)
{
    AppState *state = g_object_get_data(G_OBJECT(button), "state");
    const char *module_id = g_object_get_data(G_OBJECT(button), "module-id");
    const VerbButton *vb = user_data;
    GtkWidget *status = g_object_get_data(G_OBJECT(button), "status");
    GtkWidget *entry = g_object_get_data(G_OBJECT(button), "arg-entry");

    const char *arg = gtk_editable_get_text(GTK_EDITABLE(entry));
    if (arg == NULL || *arg == '\0') {
        show_toast_full(state, vb->verb, "this action needs an argument", "error");
        return;
    }

    g_autofree char *label = g_strdup_printf("%s %s %s", module_id, vb->verb, arg);
    run_module_verb_arg(state, module_id, vb->verb, arg, label, status, vb->privileged);
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

/* Build a page from a verb table. `with_arg` names the one verb that
   takes a free-text argument, so it gets an entry box. */
static GtkWidget *
build_verb_page(AppState *state, const char *module_id,
                const VerbButton *verbs, int n_verbs,
                const char *with_arg)
{
    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 14);
    GtkWidget *inner = gtk_box_new(GTK_ORIENTATION_VERTICAL, 14);
    GtkWidget *status = gtk_label_new("Idle");

    gtk_widget_add_css_class(status, "status-pill");
    gtk_widget_add_css_class(status, "status-idle");
    gtk_widget_set_halign(status, GTK_ALIGN_START);

    gtk_widget_set_margin_top(inner, 16);
    gtk_widget_set_margin_bottom(inner, 16);
    gtk_widget_set_margin_start(inner, 16);
    gtk_widget_set_margin_end(inner, 16);
    gtk_widget_set_hexpand(inner, TRUE);
    gtk_box_append(GTK_BOX(outer), inner);

    /* ---- STATUS ---- */
    {
        GtkWidget *body;
        GtkWidget *card = verb_card("STATUS", &body);
        GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
        GtkWidget *note = gtk_label_new(
            "Runs appear in the Events drawer. Verbs that need a radio say so "
            "and name the hardware.");
        gtk_widget_add_css_class(note, "card-note");
        gtk_label_set_wrap(GTK_LABEL(note), TRUE);
        gtk_widget_set_hexpand(note, TRUE);
        gtk_label_set_xalign(GTK_LABEL(note), 0.0f);
        gtk_box_append(GTK_BOX(row), status);
        gtk_box_append(GTK_BOX(row), note);
        gtk_box_append(GTK_BOX(body), row);
        gtk_box_append(GTK_BOX(inner), card);
    }

    /* ---- ACTIONS ---- */
    {
        GtkWidget *body;
        GtkWidget *card = verb_card("ACTIONS", &body);
        GtkWidget *flow = gtk_flow_box_new();
        GtkWidget *arg_entry = NULL;
        gboolean wants_arg = (with_arg != NULL && *with_arg != '\0');

        if (wants_arg) {
            GtkWidget *argrow = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
            GtkWidget *lab = gtk_label_new(with_arg);
            gtk_widget_add_css_class(lab, "mono");
            gtk_widget_add_css_class(lab, "dim");
            arg_entry = gtk_entry_new();
            gtk_entry_set_placeholder_text(GTK_ENTRY(arg_entry),
                "argument for that verb");
            gtk_widget_set_hexpand(arg_entry, TRUE);
            gtk_box_append(GTK_BOX(argrow), lab);
            gtk_box_append(GTK_BOX(argrow), arg_entry);
            gtk_box_append(GTK_BOX(body), argrow);
        }

        gtk_flow_box_set_selection_mode(GTK_FLOW_BOX(flow), GTK_SELECTION_NONE);
        gtk_flow_box_set_max_children_per_line(GTK_FLOW_BOX(flow), 4);
        gtk_flow_box_set_min_children_per_line(GTK_FLOW_BOX(flow), 2);
        gtk_flow_box_set_column_spacing(GTK_FLOW_BOX(flow), 8);
        gtk_flow_box_set_row_spacing(GTK_FLOW_BOX(flow), 8);

        for (int i = 0; i < n_verbs; i++) {
            GtkWidget *btn = gtk_button_new_with_label(verbs[i].label);
            gtk_widget_add_css_class(btn, "verb-button");
            gtk_widget_set_tooltip_text(btn, verbs[i].verb);
            gtk_widget_set_hexpand(btn, TRUE);

            g_object_set_data(G_OBJECT(btn), "state", state);
            g_object_set_data(G_OBJECT(btn), "module-id", (gpointer) module_id);
            g_object_set_data(G_OBJECT(btn), "status", status);

            if (wants_arg && arg_entry != NULL &&
                g_strcmp0(verbs[i].verb, with_arg) == 0) {
                g_object_set_data(G_OBJECT(btn), "arg-entry", arg_entry);
                g_signal_connect(btn, "clicked",
                    G_CALLBACK(verb_arg_button_clicked), (gpointer) &verbs[i]);
            } else {
                g_signal_connect(btn, "clicked",
                    G_CALLBACK(verb_button_clicked), (gpointer) &verbs[i]);
            }

            GtkWidget *child = gtk_flow_box_child_new();
            gtk_flow_box_child_set_child(GTK_FLOW_BOX_CHILD(child), btn);
            gtk_flow_box_append(GTK_FLOW_BOX(flow), child);
        }

        gtk_box_append(GTK_BOX(body), flow);

        gtk_box_append(GTK_BOX(inner), card);
    }

    /* ---- RUN ANY VERB ---- */
    {
        GtkWidget *body;
        GtkWidget *card = verb_card("RUN ANY VERB", &body);
        GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        GtkWidget *entry = gtk_entry_new();
        GtkWidget *go = gtk_button_new_with_label("Run");
        GtkWidget *note = gtk_label_new(
            "Every verb this module implements is reachable here, with "
            "arguments — even ones this page has no button for.");

        gtk_entry_set_placeholder_text(GTK_ENTRY(entry),
            "--status-tsv    --decode-si <hex>    --selftest");
        gtk_widget_set_hexpand(entry, TRUE);
        gtk_widget_add_css_class(go, "verb-button");
        gtk_widget_add_css_class(go, "primary");
        gtk_widget_set_tooltip_text(go, "run the typed verb");

        GtkWidget *copy = gtk_button_new_from_icon_name("edit-copy-symbolic");
        gtk_widget_set_tooltip_text(copy, "copy the shell command");
        g_object_set_data(G_OBJECT(copy), "module-id", (gpointer) module_id);
        g_object_set_data(G_OBJECT(copy), "arg-entry", entry);
        g_signal_connect(copy, "clicked", G_CALLBACK(verb_copy_clicked), NULL);

        g_object_set_data(G_OBJECT(go), "state", state);
        g_object_set_data(G_OBJECT(go), "module-id", (gpointer) module_id);
        g_object_set_data(G_OBJECT(go), "status", status);
        g_object_set_data(G_OBJECT(go), "arg-entry", entry);
        g_signal_connect(go, "clicked", G_CALLBACK(verb_any_run_clicked), NULL);

        GtkWidget *lastrun = gtk_label_new("");
        gtk_widget_add_css_class(lastrun, "last-run");
        gtk_label_set_xalign(GTK_LABEL(lastrun), 0.0f);
        g_object_set_data(G_OBJECT(go), "last-run", lastrun);

        gtk_box_append(GTK_BOX(row), entry);
        gtk_box_append(GTK_BOX(row), copy);
        gtk_box_append(GTK_BOX(row), go);
        gtk_box_append(GTK_BOX(body), row);

        gtk_widget_add_css_class(note, "card-note");
        gtk_label_set_wrap(GTK_LABEL(note), TRUE);
        gtk_label_set_xalign(GTK_LABEL(note), 0.0f);
        gtk_box_append(GTK_BOX(body), note);
        gtk_box_append(GTK_BOX(body), lastrun);
        gtk_box_append(GTK_BOX(inner), card);
    }

    return outer;
}

/* A module with no registered entries still gets a page that lists what the
   shell side can do, so nothing is invisible. */
static GtkWidget *
create_placeholder_page(AppState *state, const ModuleDefinition *module)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_set_margin_top(box, 16);
    gtk_widget_set_margin_start(box, 16);
    gtk_widget_set_margin_end(box, 16);

    GtkWidget *title = gtk_label_new(module->name);
    gtk_widget_add_css_class(title, "module-header-title");
    gtk_widget_set_halign(title, GTK_ALIGN_START);

    GtkWidget *id = gtk_label_new(module->id);
    gtk_widget_add_css_class(id, "mono");
    gtk_widget_add_css_class(id, "dim");
    gtk_widget_set_halign(id, GTK_ALIGN_START);

    GtkWidget *note = gtk_label_new(NULL);
    gtk_label_set_wrap(GTK_LABEL(note), TRUE);
    gtk_label_set_xalign(GTK_LABEL(note), 0.0f);
    gtk_widget_add_css_class(note, "dim");
    gtk_label_set_markup(GTK_LABEL(note),
        "This module has no registered GUI view yet. Its verbs are listed "
        "below and can be run from a terminal.");

    GtkWidget *desc = gtk_label_new(module->desc ? module->desc : "");
    gtk_widget_add_css_class(desc, "module-header-desc");
    gtk_label_set_xalign(GTK_LABEL(desc), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(desc), TRUE);

    gtk_box_append(GTK_BOX(box), title);
    gtk_box_append(GTK_BOX(box), desc);
    gtk_box_append(GTK_BOX(box), id);
    gtk_box_append(GTK_BOX(box), note);

    /* Pull the verb list out of the generated index. */
    for (int i = 0; i < MODULE_INDEX_N; i++) {
        if (g_strcmp0(module_index[i].id, module->id) != 0) continue;

        GtkWidget *verbs = gtk_label_new(NULL);
        gtk_label_set_wrap(GTK_LABEL(verbs), TRUE);
        gtk_label_set_xalign(GTK_LABEL(verbs), 0.0f);
        gtk_label_set_selectable(GTK_LABEL(verbs), TRUE);
        gtk_widget_add_css_class(verbs, "mono");

        g_autofree char *esc = g_markup_escape_text(
            module_index[i].verbs ? module_index[i].verbs : "(none)", -1);
        g_autofree char *mk = g_strdup_printf("<b>verbs</b>\n%s", esc);
        gtk_label_set_markup(GTK_LABEL(verbs), mk);
        gtk_box_append(GTK_BOX(box), verbs);

        if (module_index[i].info != NULL && *module_index[i].info != '\0') {
            GtkWidget *info = gtk_label_new(NULL);
            gtk_label_set_wrap(GTK_LABEL(info), TRUE);
            gtk_label_set_xalign(GTK_LABEL(info), 0.0f);
            gtk_label_set_selectable(GTK_LABEL(info), TRUE);
            gtk_widget_add_css_class(info, "mono");
            g_autofree char *esc2 = g_markup_escape_text(module_index[i].info, -1);
            gtk_label_set_markup(GTK_LABEL(info), esc2);
            gtk_box_append(GTK_BOX(box), info);
        }
        break;
    }

    /* And a real run box, so the page is useful rather than decorative. */
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry), "--status-tsv");
    gtk_widget_set_hexpand(entry, TRUE);
    GtkWidget *go = gtk_button_new_with_label("Run");
    GtkWidget *status = gtk_label_new("Idle");
    gtk_widget_add_css_class(status, "status-pill");
    gtk_widget_add_css_class(status, "status-idle");

    g_object_set_data(G_OBJECT(go), "state", state);
    g_object_set_data(G_OBJECT(go), "module-id", (gpointer) module->id);
    g_object_set_data(G_OBJECT(go), "status", status);
    g_object_set_data(G_OBJECT(go), "arg-entry", entry);
    {
        static VerbButton vb = { "--status-tsv", "Run", FALSE };
        g_signal_connect(go, "clicked", G_CALLBACK(verb_arg_button_clicked), &vb);
    }

    gtk_box_append(GTK_BOX(row), entry);
    gtk_box_append(GTK_BOX(row), go);
    gtk_box_append(GTK_BOX(row), status);
    gtk_box_append(GTK_BOX(box), row);

    return box;
}

/* ==================================================================== */
/*  MODULE PAGE                                                         */
/* ==================================================================== */

static void
module_page_submenu_row_activated(GtkListBox *list, GtkListBoxRow *row,
                                  gpointer user_data)
{
    ModulePage *mp = user_data;
    int index = gtk_list_box_row_get_index(row);
    if (index >= 0 && index < mp->n_entries) {
        gtk_stack_set_visible_child_name(GTK_STACK(mp->stack),
                                         mp->entries[index].name);
        gtk_list_box_select_row(list, row);
    }
}

static GtkWidget *
module_page_build_submenu(ModulePage *mp)
{
    GtkWidget *list = gtk_list_box_new();
    gtk_widget_add_css_class(list, "module-menu");
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(list), GTK_SELECTION_SINGLE);
    gtk_list_box_set_activate_on_single_click(GTK_LIST_BOX(list), TRUE);

    for (int i = 0; i < mp->n_entries; i++) {
        GtkWidget *row = gtk_list_box_row_new();
        GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        GtkWidget *icon = gtk_image_new_from_icon_name(mp->entries[i].icon);
        GtkWidget *label = gtk_label_new(mp->entries[i].name);
        gtk_image_set_pixel_size(GTK_IMAGE(icon), 14);
        gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
        gtk_widget_set_hexpand(label, TRUE);
        gtk_box_append(GTK_BOX(box), icon);
        gtk_box_append(GTK_BOX(box), label);
        gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), box);
        gtk_list_box_append(GTK_LIST_BOX(list), row);
    }

    g_signal_connect(list, "row-activated",
                     G_CALLBACK(module_page_submenu_row_activated), mp);

    if (mp->n_entries > 0)
        gtk_list_box_select_row(GTK_LIST_BOX(list),
            gtk_list_box_get_row_at_index(GTK_LIST_BOX(list), 0));

    GtkWidget *scrolled = gtk_scrolled_window_new();
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), list);
    gtk_widget_set_size_request(scrolled, 200, -1);
    gtk_widget_set_vexpand(scrolled, TRUE);

    /* A heading over the menu, so the column reads as navigation. */
    GtkWidget *col = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *hdr = gtk_label_new("VIEWS");
    gtk_widget_add_css_class(col, "module-menu");
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

static GtkWidget *
create_module_page(AppState *state, const ModuleDefinition *module,
                   ModuleSubmenuEntry *entries, int n_entries,
                   gpointer module_data)
{
    ModulePage *mp = g_new0(ModulePage, 1);
    mp->state = state;
    mp->module = module;
    mp->entries = entries;
    mp->n_entries = n_entries;
    mp->module_data = module_data;

    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_add_css_class(outer, "module-page");
    gtk_widget_set_vexpand(outer, TRUE);

    /* Header: icon, name, category, status pill, then the module's one-line
       description beneath them. */
    GtkWidget *header = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *hrow   = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *hicon = gtk_image_new_from_icon_name(module->icon);
    GtkWidget *htitle = gtk_label_new(module->name);
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

    gtk_image_set_pixel_size(GTK_IMAGE(hicon), 18);
    gtk_widget_set_hexpand(htitle, TRUE);
    gtk_label_set_ellipsize(GTK_LABEL(htitle), PANGO_ELLIPSIZE_END);
    gtk_label_set_xalign(GTK_LABEL(hdesc), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(hdesc), TRUE);

    gtk_box_append(GTK_BOX(hrow), hicon);
    gtk_box_append(GTK_BOX(hrow), htitle);
    gtk_box_append(GTK_BOX(hrow), hcat);
    gtk_box_append(GTK_BOX(hrow), pill);
    gtk_box_append(GTK_BOX(header), hrow);
    if (module->desc != NULL && *module->desc != '\0')
        gtk_box_append(GTK_BOX(header), hdesc);
    mp->header_box = header;
    mp->status_pill = pill;

    /* Body: submenu + stack of views. */
    GtkWidget *body = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    GtkWidget *stack = gtk_stack_new();
    gtk_stack_set_transition_type(GTK_STACK(stack),
                                  GTK_STACK_TRANSITION_TYPE_CROSSFADE);
    mp->stack = stack;

    for (int i = 0; i < n_entries; i++) {
        GtkWidget *view = NULL;
        if (entries[i].build_page != NULL)
            view = entries[i].build_page(state, module_data);
        if (view == NULL) {
            GtkWidget *lbl = gtk_label_new("this view could not be built");
            gtk_widget_add_css_class(lbl, "dim");
            view = lbl;
        }
        GtkWidget *scrolled = gtk_scrolled_window_new();
        gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),
                                       GTK_POLICY_NEVER,
                                       GTK_POLICY_AUTOMATIC);
        gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), view);
        gtk_stack_add_named(GTK_STACK(stack), scrolled, entries[i].name);
    }

    if (n_entries > 0)
        gtk_stack_set_visible_child_name(GTK_STACK(stack), entries[0].name);

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
    GtkWidget *existing = find_module_page(state, module->id);
    if (existing != NULL) {
        int index = gtk_notebook_page_num(GTK_NOTEBOOK(state->notebook), existing);
        gtk_notebook_set_current_page(GTK_NOTEBOOK(state->notebook), index);
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

    GtkWidget *tab = create_closable_tab_label(module->name, page, state);
    int index = gtk_notebook_append_page(GTK_NOTEBOOK(state->notebook), page, tab);
    gtk_notebook_set_current_page(GTK_NOTEBOOK(state->notebook), index);

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
    if (module != NULL)
        open_module(state, module);
    (void) list;
}

/* Filter the sidebar by name, id or description; a group with no surviving
   row is hidden, and a searched group auto-expands so hits are visible. */
static void
sidebar_apply_filter(GtkWidget *content, const char *q)
{
    g_autofree char *needle = (q && *q) ? g_ascii_strdown(q, -1) : NULL;
    gboolean searching = needle != NULL && *needle != '\0';

    for (GtkWidget *child = gtk_widget_get_first_child(content);
         child != NULL; child = gtk_widget_get_next_sibling(child)) {
        if (!GTK_IS_EXPANDER(child)) continue;
        GtkWidget *list = gtk_expander_get_child(GTK_EXPANDER(child));
        if (list == NULL) continue;
        gboolean any = FALSE;
        for (GtkWidget *row = gtk_widget_get_first_child(list);
             row != NULL; row = gtk_widget_get_next_sibling(row)) {
            const ModuleDefinition *m = g_object_get_data(G_OBJECT(row), "module");
            if (m == NULL) continue;
            gboolean show = TRUE;
            if (searching) {
                g_autofree char *joined = g_strdup_printf(
                    "%s %s %s", m->name, m->id, m->desc ? m->desc : "");
                g_autofree char *hay = g_ascii_strdown(joined, -1);
                show = g_strrstr(hay, needle) != NULL;
            }
            gtk_widget_set_visible(row, show);
            if (show) any = TRUE;
        }
        gtk_widget_set_visible(child, searching ? any : TRUE);
        gtk_expander_set_expanded(GTK_EXPANDER(child), searching ? any : TRUE);
    }
}

static void
sidebar_search_changed(GtkEditable *e, gpointer user_data)
{
    sidebar_apply_filter(GTK_WIDGET(user_data), gtk_editable_get_text(e));
}

static GtkWidget *
build_sidebar(AppState *state)
{
    GtkWidget *content = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    gtk_widget_add_css_class(content, "sidebar");

    GtkWidget *search = gtk_search_entry_new();
    gtk_widget_add_css_class(search, "sidebar-search");
    gtk_search_entry_set_placeholder_text(GTK_SEARCH_ENTRY(search),
        "Search modules…");
    gtk_box_append(GTK_BOX(content), search);
    g_signal_connect(search, "search-changed",
                     G_CALLBACK(sidebar_search_changed), content);

    const char *last_category = NULL;
    GtkWidget *list = NULL;

    for (int i = 0; i < N_MODULES; i++) {
        if (g_strcmp0(last_category, modules[i].category) != 0) {
            int count = 0;
            for (int j = 0; j < N_MODULES; j++)
                if (g_strcmp0(modules[j].category, modules[i].category) == 0) count++;

            GtkWidget *hdr = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
            GtkWidget *cat = gtk_label_new(modules[i].category);
            GtkWidget *cnt = gtk_label_new(NULL);
            g_autofree char *cs = g_strdup_printf("%d", count);

            gtk_widget_add_css_class(cat, "sidebar-category");
            gtk_widget_add_css_class(cat, category_class(modules[i].category));
            gtk_widget_add_css_class(cnt, "sidebar-cat-count");
            gtk_label_set_xalign(GTK_LABEL(cat), 0.0f);
            gtk_widget_set_hexpand(cat, TRUE);
            gtk_label_set_text(GTK_LABEL(cnt), cs);
            gtk_box_append(GTK_BOX(hdr), cat);
            gtk_box_append(GTK_BOX(hdr), cnt);

            list = gtk_list_box_new();
            gtk_widget_add_css_class(list, "sidebar-list");
            gtk_list_box_set_selection_mode(GTK_LIST_BOX(list), GTK_SELECTION_SINGLE);
            gtk_list_box_set_activate_on_single_click(GTK_LIST_BOX(list), TRUE);
            g_signal_connect(list, "row-activated",
                             G_CALLBACK(module_row_activated), state);

            GtkWidget *exp = gtk_expander_new(NULL);
            gtk_expander_set_label_widget(GTK_EXPANDER(exp), hdr);
            gtk_expander_set_expanded(GTK_EXPANDER(exp), TRUE);
            gtk_expander_set_child(GTK_EXPANDER(exp), list);
            gtk_box_append(GTK_BOX(content), exp);

            last_category = modules[i].category;
        }

        GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        GtkWidget *icon = gtk_image_new_from_icon_name(modules[i].icon);
        GtkWidget *label = gtk_label_new(modules[i].name);
        GtkWidget *id = gtk_label_new(modules[i].id);

        gtk_image_set_pixel_size(GTK_IMAGE(icon), 16);
        gtk_widget_add_css_class(icon, category_class(modules[i].category));
        gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
        gtk_widget_set_hexpand(label, TRUE);
        gtk_label_set_ellipsize(GTK_LABEL(label), PANGO_ELLIPSIZE_END);
        gtk_widget_add_css_class(id, "module-id");

        /* A module whose script is missing is dimmed, not hidden: an absent
           module is information, not something to conceal. */
        if (!module_script_exists(modules[i].id)) {
            gtk_widget_add_css_class(label, "module-offline");
            gtk_widget_set_tooltip_text(label, "module script not found");
        } else {
            gtk_widget_set_tooltip_text(label,
                modules[i].desc ? modules[i].desc : modules[i].id);
        }

        gtk_box_append(GTK_BOX(box), icon);
        gtk_box_append(GTK_BOX(box), label);
        gtk_box_append(GTK_BOX(box), id);

        GtkWidget *row = gtk_list_box_row_new();
        gtk_widget_add_css_class(row, category_class(modules[i].category));
        gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), box);
        g_object_set_data(G_OBJECT(row), "module", (gpointer) &modules[i]);
        gtk_list_box_append(GTK_LIST_BOX(list), row);
    }

    GtkWidget *scrolled = gtk_scrolled_window_new();
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), content);
    gtk_widget_set_size_request(scrolled, 272, -1);

    return scrolled;
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
/*  BUILT-IN PAGES                                                      */
/* ==================================================================== */

static GtkWidget *
page_deps(AppState *state, gpointer module_data)
{
    static const VerbButton verbs[] = {
        { "--check-versions",  "Check versions",  FALSE },
        { "--missing-only",    "Missing only",    FALSE },
        { "--distro-info",     "Distro info",     FALSE },
        { "--install-missing", "Install missing", TRUE  },
        { "--status-tsv",      "Status",          FALSE },
    };
    (void) module_data;
    return build_verb_page(state, "00_deps", verbs,
                           G_N_ELEMENTS(verbs), NULL);
}

static GtkWidget *
page_radio(AppState *state, gpointer module_data)
{
    static const VerbButton verbs[] = {
        { "--list-tsv",     "List SDRs",     FALSE },
        { "--caps-tsv",     "Capabilities",  FALSE },
        { "--status-tsv",   "Status",        FALSE },
        { "--record",       "Record IQ",     FALSE },
        { "--band-check",   "Band check",    FALSE },
    };
    (void) module_data;
    return build_verb_page(state, "01_radio", verbs,
                           G_N_ELEMENTS(verbs), "--band-check");
}

static GtkWidget *
page_cell_recon(AppState *state, gpointer module_data)
{
    static const VerbButton verbs[] = {
        { "--scan",       "Scan (gsm)",   FALSE },
        { "--list",       "List cells",   FALSE },
        { "--list-tsv",   "List as TSV",  FALSE },
        { "--arfcn",      "ARFCN decode", FALSE },
        { "--plmn",       "PLMN lookup",  FALSE },
        { "--export",     "Export",       FALSE },
        { "--clear",      "Clear survey", FALSE },
        { "--status-tsv", "Status",       FALSE },
    };
    (void) module_data;
    return build_verb_page(state, "02_cell_recon", verbs,
                           G_N_ELEMENTS(verbs), "--arfcn");
}

static GtkWidget *
page_gsmtap(AppState *state, gpointer module_data)
{
    static const VerbButton verbs[] = {
        { "--listen",         "Listen live",    FALSE },
        { "--read",           "Read a capture",  FALSE },
        { "--decode-tsv",     "Decoded TSV",     FALSE },
        { "--identities-tsv", "Identities",      FALSE },
        { "--export-pcap",    "Export pcap",     FALSE },
        { "--status-tsv",     "Status",          FALSE },
    };
    (void) module_data;
    return build_verb_page(state, "03_gsmtap", verbs,
                           G_N_ELEMENTS(verbs), "--read");
}

static GtkWidget *
page_tower_map(AppState *state, gpointer module_data)
{
    static const VerbButton verbs[] = {
        { "--survey",      "Start survey", FALSE },
        { "--list-tsv",    "Sessions",     FALSE },
        { "--export-kml",  "Export KML",   FALSE },
        { "--export-csv",  "Export CSV",   FALSE },
        { "--status-tsv",  "Status",       FALSE },
    };
    (void) module_data;
    return build_verb_page(state, "04_tower_map", verbs,
                           G_N_ELEMENTS(verbs), NULL);
}

static GtkWidget *
page_pcap(AppState *state, gpointer module_data)
{
    static const VerbButton verbs[] = {
        { "--summary",       "Summary",       FALSE },
        { "--list",          "List frames",   FALSE },
        { "--hierarchy",     "Hierarchy",     FALSE },
        { "--conversations", "Conversations", FALSE },
        { "--identities",    "Identities",    FALSE },
        { "--status-tsv",    "Status",        FALSE },
    };
    (void) module_data;
    return build_verb_page(state, "21_pcap_analysis", verbs,
                           G_N_ELEMENTS(verbs), "--summary");
}

static GtkWidget *
page_cve(AppState *state, const char *module_id, gpointer module_data)
{
    static const VerbButton verbs[] = {
        { "--run-cve",    "Run a CVE probe", FALSE },
        { "--status-tsv", "Status",          FALSE },
    };
    (void) module_data;
    return build_verb_page(state, module_id, verbs,
                           G_N_ELEMENTS(verbs), "--run-cve");
}

static GtkWidget *
page_gsm_cve(AppState *state, gpointer d) { return page_cve(state, "24_gsm_cve", d); }
static GtkWidget *
page_lte_cve(AppState *state, gpointer d) { return page_cve(state, "25_lte_cve", d); }
static GtkWidget *
page_nr_cve(AppState *state, gpointer d)  { return page_cve(state, "26_nr_cve", d); }

/* Generic page builder for modules that only need their common verbs. */
#define GENERIC_PAGE_FN(fname, modid)                                          \
    static GtkWidget *fname(AppState *state, gpointer module_data)             \
    {                                                                          \
        static const VerbButton verbs[] = {                                    \
            { "--status-tsv", "Status",    FALSE },                            \
            { "--selftest",   "Self-test", FALSE },                            \
        };                                                                     \
        (void) module_data;                                                    \
        return build_verb_page(state, modid, verbs, G_N_ELEMENTS(verbs), NULL);\
    }

GENERIC_PAGE_FN(page_gsm_air,    "10_gsm_air")
GENERIC_PAGE_FN(page_gsm_attack, "11_gsm_attack")
GENERIC_PAGE_FN(page_umts_air,   "12_umts_air")
GENERIC_PAGE_FN(page_lte_attach, "13_lte_attach")
GENERIC_PAGE_FN(page_lte_air,    "14_lte_air")
GENERIC_PAGE_FN(page_lte_core,   "15_lte_core")
GENERIC_PAGE_FN(page_nr_air,     "16_nr_air")
GENERIC_PAGE_FN(page_nr_core,    "17_nr_core")
GENERIC_PAGE_FN(page_suci,       "18_suci")
GENERIC_PAGE_FN(page_downgrade,  "19_downgrade")
GENERIC_PAGE_FN(page_sim,        "20_sim")
GENERIC_PAGE_FN(page_imsi,       "22_imsi_exposure")
GENERIC_PAGE_FN(page_cipher,     "23_cipher_audit")
GENERIC_PAGE_FN(page_killchain,  "30_killchain")
GENERIC_PAGE_FN(page_tana, "27_traffic_analysis")
GENERIC_PAGE_FN(page_rff, "28_rf_fingerprint")
GENERIC_PAGE_FN(page_macl, "34_mac_layer")
GENERIC_PAGE_FN(page_nasf, "37_nas_signaling")
GENERIC_PAGE_FN(page_ss7, "31_ss7_map")
GENERIC_PAGE_FN(page_cdns, "32_cellular_dns")
GENERIC_PAGE_FN(page_pgt, "33_paging_track")
GENERIC_PAGE_FN(page_vims, "35_volte_ims")
GENERIC_PAGE_FN(page_simd, "36_sim_defense")
GENERIC_PAGE_FN(page_jamd, "38_jamming_detect")
GENERIC_PAGE_FN(page_slic, "39_slicing")
GENERIC_PAGE_FN(page_iot, "50_iot")
GENERIC_PAGE_FN(page_lpp, "51_lpp")
GENERIC_PAGE_FN(page_wifioff, "52_wifioff")
GENERIC_PAGE_FN(page_bbnd, "40_baseband")
GENERIC_PAGE_FN(page_vowi, "41_vowifi")
GENERIC_PAGE_FN(page_femt, "42_femtocell")
GENERIC_PAGE_FN(page_ussd, "43_ussd")
GENERIC_PAGE_FN(page_tgeo, "44_ta_geoloc")
GENERIC_PAGE_FN(page_sbap, "45_sba_pivot")
GENERIC_PAGE_FN(page_otasm, "46_ota_sms")
GENERIC_PAGE_FN(page_lipr, "47_li_probe")
GENERIC_PAGE_FN(page_rans, "48_ran_share")
GENERIC_PAGE_FN(page_capi, "49_carrier_api")
GENERIC_PAGE_FN(page_oran, "53_oran")
GENERIC_PAGE_FN(page_ntn, "54_ntn")
GENERIC_PAGE_FN(page_gprs, "55_gprs")
GENERIC_PAGE_FN(page_slnk, "56_sidelink")
GENERIC_PAGE_FN(page_stk, "57_stk")
GENERIC_PAGE_FN(page_n3g, "58_non3gpp")
GENERIC_PAGE_FN(page_bexp, "59_baseband_exploit")
GENERIC_PAGE_FN(page_nrj, "60_nr_inject")

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

    const char *classes[] = { "status-ok", "status-warn", "status-dim", NULL };
    for (int i = 0; classes[i] != NULL; i++)
        gtk_widget_remove_css_class(label, classes[i]);
    if (css != NULL)
        gtk_widget_add_css_class(label, css);
}

static gboolean
status_poll(gpointer user_data)
{
    AppState *state = user_data;
    if (state->window == NULL) return G_SOURCE_CONTINUE;

    /* Radio: device, transmit capability, tuned frequency. */
    g_autofree char *radio = module_status("01_radio");
    if (radio != NULL) {
        g_autofree char *drv = tsv_field(radio, "selected_driver");
        g_autofree char *sel = tsv_field(radio, "selected");
        g_autofree char *tx  = tsv_field(radio, "can_tx");
        g_autofree char *hz  = tsv_field(radio, "freq_hz");

        const char *shown = (sel && *sel) ? sel : drv;
        gboolean present = shown && *shown && g_strcmp0(shown, "none") != 0;
        status_set(state->status_sdr, present ? shown : "none",
                   present ? "status-ok" : "status-dim");

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
        gboolean fixing = g_strcmp0(gps, "running") == 0;
        status_set(state->status_gps, gps, fixing ? "status-ok" : "status-warn");
    } else {
        status_set(state->status_gps, NULL, "status-dim");
    }

    return G_SOURCE_CONTINUE;
}

static GtkWidget *
status_cell(const char *key, GtkWidget **value_out)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *k = gtk_label_new(key);
    GtkWidget *v = gtk_label_new("—");

    gtk_widget_add_css_class(box, "status-cell");
    gtk_widget_add_css_class(k, "status-key");
    gtk_widget_add_css_class(v, "status-value");
    gtk_widget_add_css_class(v, "status-dim");
    gtk_label_set_xalign(GTK_LABEL(k), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(v), 0.0f);

    gtk_box_append(GTK_BOX(box), k);
    gtk_box_append(GTK_BOX(box), v);
    *value_out = v;
    return box;
}

static GtkWidget *
build_status_strip(AppState *state)
{
    GtkWidget *strip = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 22);
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

    return strip;
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

static GtkWidget *
make_module_card(AppState *state, const ModuleDefinition *mod)
{
    GtkWidget *button = gtk_button_new();
    GtkWidget *card   = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    GtkWidget *top    = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    GtkWidget *cat    = gtk_label_new(mod->category);
    GtkWidget *icon   = gtk_image_new_from_icon_name(mod->icon);
    GtkWidget *iconwrap = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *name   = gtk_label_new(mod->name);
    gboolean offline  = !module_script_exists(mod->id);

    gtk_widget_add_css_class(button, "module-card");
    gtk_widget_add_css_class(card,   "module-card-inner");
    gtk_widget_add_css_class(top,    "module-card-toprow");
    gtk_widget_add_css_class(cat,    "module-card-category");
    gtk_widget_add_css_class(cat,    category_class(mod->category));
    gtk_widget_add_css_class(icon,   "module-card-icon");
    gtk_widget_add_css_class(name,   "module-card-title");
    if (offline)
        gtk_widget_add_css_class(icon, "module-card-offline");

    gtk_image_set_pixel_size(GTK_IMAGE(icon), 40);
    gtk_widget_set_halign(iconwrap, GTK_ALIGN_CENTER);
    gtk_widget_add_css_class(iconwrap, "module-card-iconwrap");
    gtk_widget_add_css_class(iconwrap, category_class(mod->category));
    gtk_widget_set_size_request(iconwrap, 56, 56);
    gtk_widget_set_vexpand(iconwrap, TRUE);
    gtk_box_append(GTK_BOX(iconwrap), icon);

    gtk_label_set_xalign(GTK_LABEL(cat), 0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(cat), PANGO_ELLIPSIZE_END);
    gtk_widget_set_hexpand(cat, TRUE);

    gtk_label_set_ellipsize(GTK_LABEL(name), PANGO_ELLIPSIZE_END);
    gtk_label_set_width_chars(GTK_LABEL(name), 13);
    gtk_label_set_xalign(GTK_LABEL(name), 0.5f);
    gtk_label_set_justify(GTK_LABEL(name), GTK_JUSTIFY_CENTER);

    gtk_widget_set_size_request(button, 178, 126);
    gtk_widget_set_hexpand(button, FALSE);
    gtk_widget_set_halign(button, GTK_ALIGN_START);
    gtk_widget_set_valign(button, GTK_ALIGN_START);

    gtk_widget_set_tooltip_text(button,
        offline ? "module script not found" : mod->id);

    gtk_box_append(GTK_BOX(top), cat);
    gtk_box_append(GTK_BOX(card), top);
    gtk_box_append(GTK_BOX(card), iconwrap);
    gtk_box_append(GTK_BOX(card), name);
    gtk_button_set_child(GTK_BUTTON(button), card);

    g_object_set_data(G_OBJECT(button), "module", (gpointer) mod);
    g_signal_connect(button, "clicked", G_CALLBACK(module_card_clicked), state);
    return button;
}

#define DASH_COLS 7

/* Sort modes for the single dashboard grid. */
enum { DASH_SORT_WORKFLOW = 0, DASH_SORT_NAME, DASH_SORT_CATEGORY };
static int g_dash_sort = DASH_SORT_WORKFLOW;
static const char *dash_sort_names[] = {
    "Workflow", "Name (A–Z)", "Category", NULL
};

static int
dash_cmp(const void *pa, const void *pb)
{
    int a = *(const int *) pa, b = *(const int *) pb;
    switch (g_dash_sort) {
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

/* Rebuild the flow for a given sort mode. */
static void
dash_fill(AppState *state, GtkWidget *flow, int mode)
{
    GtkWidget *child;
    int idx[N_MODULES];

    while ((child = gtk_widget_get_first_child(flow)) != NULL)
        gtk_flow_box_remove(GTK_FLOW_BOX(flow), child);

    g_dash_sort = mode;
    for (int i = 0; i < N_MODULES; i++) idx[i] = i;
    qsort(idx, N_MODULES, sizeof idx[0], dash_cmp);

    for (int k = 0; k < N_MODULES; k++)
        gtk_flow_box_append(GTK_FLOW_BOX(flow),
                            make_module_card(state, &modules[idx[k]]));
}

/* Show only the cards matching a query, over name, id, category and the
   module's own one-line description. */
static void
dash_apply_filter(GtkWidget *flow, const char *q)
{
    g_autofree char *needle = (q && *q) ? g_ascii_strdown(q, -1) : NULL;
    gboolean searching = needle != NULL && *needle != '\0';

    for (GtkWidget *c = gtk_widget_get_first_child(flow);
         c != NULL; c = gtk_widget_get_next_sibling(c)) {
        const ModuleDefinition *m = g_object_get_data(G_OBJECT(c), "module");
        if (m == NULL) continue;
        gboolean show = TRUE;
        if (searching) {
            g_autofree char *joined = g_strdup_printf("%s %s %s %s",
                m->name, m->id, m->category, m->desc ? m->desc : "");
            g_autofree char *hay = g_ascii_strdown(joined, -1);
            show = g_strrstr(hay, needle) != NULL;
        }
        gtk_widget_set_visible(c, show);
    }
}

static void
dash_sort_changed(GObject *dd, GParamSpec *pspec, gpointer user_data)
{
    GtkWidget *flow   = g_object_get_data(dd, "grid");
    GtkWidget *search = g_object_get_data(dd, "search");
    AppState  *state  = g_object_get_data(dd, "state");
    guint sel = gtk_drop_down_get_selected(GTK_DROP_DOWN(dd));
    dash_fill(state, flow, (int) sel);
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
    GtkWidget *head     = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *title    = gtk_label_new("Command Dashboard");
    GtkWidget *sub      = gtk_label_new(
        "Every module on one flow. Search or sort, then click a card to open it.");
    GtkWidget *bar      = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *sortlab  = gtk_label_new("Sort");
    GtkWidget *dd       = gtk_drop_down_new_from_strings(dash_sort_names);
    GtkWidget *search   = gtk_search_entry_new();
    GtkWidget *flow     = gtk_flow_box_new();

    gtk_widget_add_css_class(title, "page-title");
    gtk_widget_add_css_class(sub,   "page-subtitle");
    gtk_widget_add_css_class(sortlab, "dim");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(sub),   0.0f);
    gtk_box_append(GTK_BOX(head), title);
    gtk_box_append(GTK_BOX(head), sub);
    gtk_widget_set_margin_top(head, 14);
    gtk_widget_set_margin_start(head, 16);
    gtk_widget_set_margin_end(head, 16);
    gtk_box_append(GTK_BOX(body), head);

    gtk_search_entry_set_placeholder_text(GTK_SEARCH_ENTRY(search),
        "Search name, id or purpose…");
    gtk_widget_set_hexpand(search, TRUE);
    gtk_box_append(GTK_BOX(bar), sortlab);
    gtk_box_append(GTK_BOX(bar), dd);
    gtk_box_append(GTK_BOX(bar), search);
    gtk_widget_set_margin_start(bar, 16);
    gtk_widget_set_margin_end(bar, 16);
    gtk_widget_set_margin_top(bar, 4);
    gtk_box_append(GTK_BOX(body), bar);

    /* A responsive flow instead of a fixed grid: columns follow the width. */
    gtk_flow_box_set_selection_mode(GTK_FLOW_BOX(flow), GTK_SELECTION_NONE);
    gtk_flow_box_set_homogeneous(GTK_FLOW_BOX(flow), TRUE);
    gtk_flow_box_set_max_children_per_line(GTK_FLOW_BOX(flow), 8);
    gtk_flow_box_set_min_children_per_line(GTK_FLOW_BOX(flow), 2);
    gtk_flow_box_set_column_spacing(GTK_FLOW_BOX(flow), 10);
    gtk_flow_box_set_row_spacing(GTK_FLOW_BOX(flow), 10);
    gtk_widget_set_halign(flow, GTK_ALIGN_FILL);
    gtk_widget_set_margin_start(flow, 16);
    gtk_widget_set_margin_end(flow, 16);
    gtk_widget_set_margin_top(flow, 6);
    gtk_box_append(GTK_BOX(body), flow);

    g_object_set_data(G_OBJECT(dd), "grid",   flow);
    g_object_set_data(G_OBJECT(dd), "search", search);
    g_object_set_data(G_OBJECT(dd), "state",  state);
    g_signal_connect(dd, "notify::selected", G_CALLBACK(dash_sort_changed), NULL);
    g_signal_connect(search, "search-changed",
                     G_CALLBACK(dash_search_changed), flow);

    dash_fill(state, flow, DASH_SORT_WORKFLOW);

    gtk_widget_set_margin_bottom(body, 18);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
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
    GtkWidget *ic  = gtk_image_new_from_icon_name(icon);
    GtkWidget *t   = gtk_label_new(title);
    GtkWidget *h   = gtk_label_new(hint);

    gtk_widget_add_css_class(box, "empty-state");
    gtk_widget_add_css_class(ic,  "empty-icon");
    gtk_widget_add_css_class(t,   "empty-title");
    gtk_widget_add_css_class(h,   "empty-hint");
    gtk_image_set_pixel_size(GTK_IMAGE(ic), 56);
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
    if (n < 1024)           return g_strdup_printf("%llu B", (unsigned long long) n);
    if (n < 1024 * 1024)    return g_strdup_printf("%.1f KB", n / 1024.0);
    return g_strdup_printf("%.1f MB", n / (1024.0 * 1024.0));
}

/* Selecting a module shows its directory and a preview of the newest file. */
static void
loot_row_selected(GtkListBox *lb, GtkListBoxRow *row, gpointer user_data)
{
    AppState *state = user_data;
    const char *dir = row ? g_object_get_data(G_OBJECT(row), "loot-dir") : NULL;
    if (state->loot_preview_buf == NULL) return;
    if (dir == NULL) { gtk_text_buffer_set_text(state->loot_preview_buf, "", -1); return; }

    g_autoptr(GString) out = g_string_new(NULL);
    g_string_append_printf(out, "%s\n\n", dir);

    g_autofree char *newest = NULL;
    guint64 newest_t = 0;
    g_autoptr(GDir) d = g_dir_open(dir, 0, NULL);
    if (d != NULL) {
        const char *fn;
        while ((fn = g_dir_read_name(d)) != NULL) {
            g_autofree char *fp = g_build_filename(dir, fn, NULL);
            GStatBuf st;
            if (g_stat(fp, &st) != 0 || !S_ISREG(st.st_mode)) continue;
            g_string_append_printf(out, "  %s\n", fn);
            if ((guint64) st.st_mtime >= newest_t) {
                newest_t = (guint64) st.st_mtime;
                g_free(newest); newest = g_strdup(fp);
            }
        }
    }

    if (newest != NULL) {
        g_autofree char *body = NULL;
        gsize len = 0;
        if (g_file_get_contents(newest, &body, &len, NULL)) {
            if (len > 4000) { body[4000] = '\0'; }
            g_string_append_printf(out, "\n── %s ──\n%s\n",
                                   g_path_get_basename(newest), body);
        }
    } else {
        g_string_append(out, "\n(no files yet)\n");
    }
    gtk_text_buffer_set_text(state->loot_preview_buf, out->str, -1);
    (void) lb;
}

static void
loot_refresh(AppState *state)
{
    GtkWidget *child;

    if (state->loot_list == NULL) return;
    while ((child = gtk_widget_get_first_child(state->loot_list)) != NULL)
        gtk_list_box_remove(GTK_LIST_BOX(state->loot_list), child);

    g_autofree char *root = g_build_filename(IMSISTING_ROOT, "loot", NULL);
    g_autoptr(GDir) d = g_dir_open(root, 0, NULL);
    guint rows = 0;

    if (d != NULL) {
        const char *name;
        while ((name = g_dir_read_name(d)) != NULL) {
            g_autofree char *sub = g_build_filename(root, name, NULL);
            if (!g_file_test(sub, G_FILE_TEST_IS_DIR)) continue;

            guint n = 0;
            guint64 bytes = 0, newest = 0;
            g_autoptr(GDir) sd = g_dir_open(sub, 0, NULL);
            if (sd != NULL) {
                const char *fn;
                while ((fn = g_dir_read_name(sd)) != NULL) {
                    g_autofree char *fp = g_build_filename(sub, fn, NULL);
                    GStatBuf st;
                    if (g_stat(fp, &st) != 0 || !S_ISREG(st.st_mode)) continue;
                    n++;
                    bytes += (guint64) st.st_size;
                    if ((guint64) st.st_mtime > newest) newest = (guint64) st.st_mtime;
                }
            }

            GtkWidget *row  = gtk_list_box_row_new();
            GtkWidget *box  = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
            GtkWidget *mod  = gtk_label_new(name);
            GtkWidget *meta = gtk_label_new(NULL);
            GtkWidget *cnt  = gtk_label_new(NULL);
            g_autofree char *sz = loot_fmt_size(bytes);
            g_autofree char *when = NULL;
            if (newest > 0) {
                GDateTime *dt = g_date_time_new_from_unix_local((gint64) newest);
                when = g_date_time_format(dt, "%m-%d %H:%M");
                g_date_time_unref(dt);
            } else {
                when = g_strdup("—");
            }
            g_autofree char *txt = g_strdup_printf(
                n == 0 ? "empty" : "%u file%s · %s", n, n == 1 ? "" : "s", sz);

            gtk_widget_add_css_class(mod, "loot-module");
            gtk_widget_add_css_class(meta, "loot-count");
            gtk_widget_add_css_class(cnt, "loot-count");
            gtk_label_set_xalign(GTK_LABEL(mod), 0.0f);
            gtk_widget_set_hexpand(mod, TRUE);
            gtk_label_set_text(GTK_LABEL(meta), when);
            gtk_label_set_text(GTK_LABEL(cnt), txt);
            gtk_label_set_xalign(GTK_LABEL(cnt), 1.0f);

            gtk_box_append(GTK_BOX(box), mod);
            gtk_box_append(GTK_BOX(box), meta);
            gtk_box_append(GTK_BOX(box), cnt);
            gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), box);
            g_object_set_data_full(G_OBJECT(row), "loot-dir", g_strdup(sub), g_free);
            gtk_list_box_append(GTK_LIST_BOX(state->loot_list), row);
            rows++;
        }
    }

    if (rows == 0) {
        GtkWidget *row = gtk_list_box_row_new();
        GtkWidget *empty = empty_state("folder-symbolic", "Loot is empty",
            "run a module that collects something, then Refresh");
        gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), empty);
        gtk_list_box_row_set_selectable(GTK_LIST_BOX_ROW(row), FALSE);
        gtk_list_box_row_set_activatable(GTK_LIST_BOX_ROW(row), FALSE);
        gtk_list_box_append(GTK_LIST_BOX(state->loot_list), row);
    }
    if (state->loot_preview_buf != NULL)
        gtk_text_buffer_set_text(state->loot_preview_buf, "", -1);
}

static void
loot_refresh_clicked(GtkButton *b, gpointer user_data)
{
    (void) b;
    loot_refresh(user_data);
}

static GtkWidget *
create_loot_page(AppState *state)
{
    GtkWidget *outer  = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *head   = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *box    = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *title  = gtk_label_new("Loot");
    GtkWidget *sub    = gtk_label_new(NULL);
    GtkWidget *list   = gtk_list_box_new();
    GtkWidget *refresh = gtk_button_new_with_label("Refresh");
    GtkWidget *paned  = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
    GtkWidget *lscroll = gtk_scrolled_window_new();
    GtkWidget *preview_scroll = gtk_scrolled_window_new();
    GtkWidget *preview = gtk_text_view_new();
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

    gtk_widget_add_css_class(list, "loot-list");
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(list), GTK_SELECTION_SINGLE);
    state->loot_list = list;
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(lscroll), list);

    gtk_text_view_set_editable(GTK_TEXT_VIEW(preview), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(preview), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(preview), TRUE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(preview), GTK_WRAP_WORD_CHAR);
    gtk_widget_add_css_class(preview, "loot-preview");
    state->loot_preview = preview;
    state->loot_preview_buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(preview));
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(preview_scroll), preview);

    gtk_paned_set_start_child(GTK_PANED(paned), lscroll);
    gtk_paned_set_end_child(GTK_PANED(paned), preview_scroll);
    gtk_paned_set_position(GTK_PANED(paned), 380);
    gtk_widget_set_vexpand(paned, TRUE);
    gtk_box_append(GTK_BOX(outer), paned);

    g_signal_connect(refresh, "clicked", G_CALLBACK(loot_refresh_clicked), state);
    g_signal_connect(list, "row-selected", G_CALLBACK(loot_row_selected), state);
    loot_refresh(state);
    return outer;
}

/* ==================================================================== */
/*  STATS / HELP / SETTINGS                                             */
/* ==================================================================== */

static GtkWidget *
text_page(const char *title, const char *subtitle, const char *body_text,
          GtkWidget **view_out)
{
    GtkWidget *outer  = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *head   = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *t      = gtk_label_new(title);
    GtkWidget *sub    = gtk_label_new(subtitle);
    GtkWidget *scroll = gtk_scrolled_window_new();
    GtkWidget *view   = gtk_text_view_new();

    gtk_widget_add_css_class(t,   "page-title");
    gtk_widget_add_css_class(sub, "page-subtitle");
    gtk_label_set_xalign(GTK_LABEL(t),   0.0f);
    gtk_label_set_xalign(GTK_LABEL(sub), 0.0f);
    gtk_box_append(GTK_BOX(head), t);
    gtk_box_append(GTK_BOX(head), sub);
    gtk_widget_set_margin_top(head, 14);
    gtk_widget_set_margin_start(head, 16);
    gtk_widget_set_margin_end(head, 16);
    gtk_widget_add_css_class(outer, "doc-page");
    gtk_box_append(GTK_BOX(outer), head);

    gtk_text_view_set_editable(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(view), GTK_WRAP_WORD_CHAR);
    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(view), 28);
    gtk_text_view_set_right_margin(GTK_TEXT_VIEW(view), 28);
    gtk_widget_add_css_class(view, "page-text");
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(view)),
                             body_text ? body_text : "", -1);

    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), view);
    gtk_widget_set_vexpand(scroll, TRUE);
    gtk_box_append(GTK_BOX(outer), scroll);

    if (view_out != NULL) *view_out = view;
    return outer;
}

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

    (void) state;

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
        if (!module_script_exists(modules[i].id)) offline++;
    }
    for (int i = 0; i < MODULE_INDEX_N; i++)
        if (module_index[i].has_selftest) selftests++;

    {
        g_autofree char *loot = g_build_filename(IMSISTING_ROOT, "loot", NULL);
        g_autoptr(GDir) d = g_dir_open(loot, 0, NULL);
        const char *name;
        if (d != NULL) {
            while ((name = g_dir_read_name(d)) != NULL) {
                g_autofree char *p = g_build_filename(loot, name, NULL);
                if (g_file_test(p, G_FILE_TEST_IS_DIR)) {
                    loot_dirs++; loot_files += count_files(p);
                }
            }
        }
    }

    {
        g_autofree char *v = g_strdup_printf("%d", N_MODULES);
        gtk_box_append(GTK_BOX(tiles), stat_tile(v, "MODULES"));
    }
    {
        g_autofree char *v = g_strdup_printf("%u", selftests);
        gtk_box_append(GTK_BOX(tiles), stat_tile(v, "WITH SELFTEST"));
    }
    {
        g_autofree char *v = g_strdup_printf("%u", loot_dirs);
        gtk_box_append(GTK_BOX(tiles), stat_tile(v, "LOOT DIRS"));
    }
    {
        g_autofree char *v = g_strdup_printf("%u", loot_files);
        gtk_box_append(GTK_BOX(tiles), stat_tile(v, "LOOT FILES"));
    }
    {
        g_autofree char *v = g_strdup_printf("%u", offline);
        gtk_box_append(GTK_BOX(tiles), stat_tile(v, "OFFLINE"));
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
    return outer;
}
static const char *HELP_TEXT =
"IMSIsting — cellular security research toolkit\n"
"2G/GSM · 3G/UMTS · 4G/LTE · 5G/NR\n"
"\n"
"WHAT THIS IS\n"
"  A GTK4 view over standalone shell modules. Nothing is locked behind the\n"
"  interface: every action a button takes is also a command you can run.\n"
"\n"
"  ./modules/02_cell_recon.sh --plmn 208-01\n"
"  ./modules/21_pcap_analysis.sh --summary capture.pcap\n"
"  ./modules/15_lte_core.sh --decode-diameter <hex>\n"
"\n"
"GETTING AROUND\n"
"  Dashboard   every module as a card on one grid; sort with the control\n"
"  Modules     the sidebar list; toggle it from the header bar\n"
"  Loot        what every module has collected so far\n"
"  Stats       module and collection counts\n"
"  Settings    environment facts and maintenance actions\n"
"\n"
"  Open a module card (or a sidebar row) and it appears as its own tab.\n"
"  Module tabs close; Dashboard/Loot/Stats/Help/Settings do not.\n"
"\n"
"RUNNING A VERB\n"
"  Each module page lists its common verbs as buttons, and carries a\n"
"  free-text run box. Anything a module implements can be run there:\n"
"\n"
"      --status-tsv        --decode-si <hex>        --selftest\n"
"\n"
"  Every verb a module documents is reachable this way. Verbs that need\n"
"  hardware say so and name the radio; they do not report a clean result\n"
"  without one.\n"
"\n"
"WHEN SOMETHING LOOKS WRONG\n"
"  Run the module's --selftest first. It works with no radio attached and\n"
"  usually names the problem.\n"
"\n"
"  ./tools/run-selftests.sh        every module\n"
"  ./tools/check-paths.sh          paths and table entries resolve\n"
"  ./tools/check-verbs.sh          verbs reachable from this GUI\n"
"\n"
"TARGET STATE\n"
"  Modules share scratch state under tmp/: the selected SDR, the target\n"
"  ARFCN, the target PLMN. The header strip reads those, so what it shows\n"
"  is what the modules are actually working against.\n"
"\n"
"HARDWARE\n"
"  Nothing in this tree has been tested against a real radio. Every\n"
"  over-the-air path is written and reviewed, not verified. The README\n"
"  splits tested from untested in detail — read it before filing a bug.\n"
"\n"
"LEGAL\n"
"  Use this on networks you own or have written permission to test.\n"
"  Transmitting on licensed spectrum is regulated everywhere.\n";

static GtkWidget *
create_settings_page(AppState *state)
{
    GtkWidget *outer  = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *head   = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *t      = gtk_label_new("Settings");
    GtkWidget *sub    = gtk_label_new("Environment and maintenance");
    GtkWidget *scroll = gtk_scrolled_window_new();
    GtkWidget *view   = gtk_text_view_new();
    GtkWidget *actions = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    g_autoptr(GtkCssProvider) css = NULL;
    g_autofree char *body = NULL;

    (void) css;

    gtk_widget_add_css_class(t,   "page-title");
    gtk_widget_add_css_class(sub, "page-subtitle");
    gtk_label_set_xalign(GTK_LABEL(t),   0.0f);
    gtk_label_set_xalign(GTK_LABEL(sub), 0.0f);
    gtk_box_append(GTK_BOX(head), t);
    gtk_box_append(GTK_BOX(head), sub);
    gtk_widget_set_margin_top(head, 14);
    gtk_widget_set_margin_start(head, 16);
    gtk_widget_add_css_class(outer, "doc-page");
    gtk_box_append(GTK_BOX(outer), head);

    body = g_strdup_printf(
        "Project root      %s\n"
        "Module directory  %s/modules\n"
        "Loot directory    %s/loot\n"
        "Captures          %s/captures\n"
        "Scratch           /tmp/imsisting\n"
        "\n"
        "GTK               %u.%u.%u\n"
        "GLib              %u.%u.%u\n"
        "Modules           %d\n"
        "Index entries     %d\n"
        "\n"
        "Privileged actions run through pkexec, per action rather than once\n"
        "at startup. A module invoked without root reports the failure\n"
        "instead of silently doing nothing.\n",
        IMSISTING_ROOT, IMSISTING_ROOT, IMSISTING_ROOT, IMSISTING_ROOT,
        gtk_get_major_version(), gtk_get_minor_version(), gtk_get_micro_version(),
        glib_major_version, glib_minor_version, glib_micro_version,
        N_MODULES, MODULE_INDEX_N);

    gtk_text_view_set_editable(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(view), GTK_WRAP_WORD_CHAR);
    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(view), 28);
    gtk_text_view_set_right_margin(GTK_TEXT_VIEW(view), 28);
    gtk_widget_add_css_class(view, "page-text");
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(view)),
                             body, -1);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), view);
    gtk_widget_set_vexpand(scroll, TRUE);
    gtk_box_append(GTK_BOX(outer), scroll);

    {
        /* Real actions, wired to the modules rather than to nothing. */
        GtkWidget *deps  = gtk_button_new_with_label("Check dependencies");
        GtkWidget *radio = gtk_button_new_with_label("Probe SDRs");
        GtkWidget *st    = gtk_label_new("Idle");

        gtk_widget_add_css_class(st, "status-pill");
        gtk_widget_add_css_class(st, "status-idle");

        static const VerbButton vb_deps  =
            { "--check-versions", "Check dependencies", FALSE };
        static const VerbButton vb_radio =
            { "--list-tsv", "Probe SDRs", FALSE };

        g_object_set_data(G_OBJECT(deps), "state", state);
        g_object_set_data(G_OBJECT(deps), "module-id", (gpointer) "00_deps");
        g_object_set_data(G_OBJECT(deps), "status", st);
        g_signal_connect(deps, "clicked", G_CALLBACK(verb_button_clicked),
                         (gpointer) &vb_deps);

        g_object_set_data(G_OBJECT(radio), "state", state);
        g_object_set_data(G_OBJECT(radio), "module-id", (gpointer) "01_radio");
        g_object_set_data(G_OBJECT(radio), "status", st);
        g_signal_connect(radio, "clicked", G_CALLBACK(verb_button_clicked),
                         (gpointer) &vb_radio);

        gtk_box_append(GTK_BOX(actions), deps);
        gtk_box_append(GTK_BOX(actions), radio);
        gtk_box_append(GTK_BOX(actions), st);
    }
    gtk_widget_set_margin_start(actions, 16);
    gtk_widget_set_margin_end(actions, 16);
    gtk_widget_set_margin_bottom(actions, 14);
    gtk_box_append(GTK_BOX(outer), actions);
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
static void live_start(AppState *state);
static void live_stop(AppState *state);

#define LIVE_TAB_INDEX 1

static void
notebook_page_switched(GtkNotebook *nb, GtkWidget *child, guint page,
                       gpointer user_data)
{
    AppState *state = user_data;
    (void) nb; (void) child;

    if (state->live_view == NULL) return;

    if ((int) page == LIVE_TAB_INDEX) {
        if (state->live_socket == NULL) live_start(state);
    } else if (state->live_socket != NULL) {
        live_stop(state);
    }
}

/* ---- a decoded GSMTAP message, one per row ---- */
#define LIVE_TYPE_MSG (live_msg_get_type())
G_DECLARE_FINAL_TYPE(LiveMsg, live_msg, LIVE, MSG, GObject)

struct _LiveMsg {
    GObject parent;
    guint   seq, arfcn, ts, len;
    gint    sig;
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
    default: s = g_strdup(m->payload);              break;
    }
    gtk_label_set_text(GTK_LABEL(l), s ? s : "");
    gboolean right = (which == 4 || which == 5 || which == 6 || which == 8);
    gtk_label_set_xalign(GTK_LABEL(l), right ? 1.0f : 0.0f);
    if (which == 7) {
        gtk_widget_remove_css_class(l, "dir-ul");
        if (g_strcmp0(m->dir, "UL") == 0)
            gtk_widget_add_css_class(l, "dir-ul");
    }
    (void) f;
}

static gboolean
live_matches(AppState *state, LiveMsg *m)
{
    if (state->live_filter == NULL || *state->live_filter == '\0') return TRUE;
    return (m->type && strstr(m->type, state->live_filter) != NULL) ||
           (m->ch   && strstr(m->ch,   state->live_filter) != NULL) ||
           (m->payload && strstr(m->payload, state->live_filter) != NULL);
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
    if (css != NULL)
        gtk_widget_add_css_class(state->live_status, css);
}

/* Keep the count chip and the empty state in step with the feed. */
static void
live_update_summary(AppState *state)
{
    if (state->live_summary != NULL) {
        g_autofree char *s = g_strdup_printf("%u msg%s",
            state->live_count, state->live_count == 1 ? "" : "s");
        gtk_label_set_text(GTK_LABEL(state->live_summary), s);
    }
    if (state->live_empty != NULL)
        gtk_widget_set_visible(state->live_empty, state->live_count == 0);
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
    live_update_summary(state);
}

static gboolean
live_poll_cb(gpointer user_data)
{
    AppState *state = user_data;
    guint8 buf[2048];
    gssize n;

    if (state->live_socket == NULL) return G_SOURCE_CONTINUE;

    while ((n = g_socket_receive(state->live_socket, (gchar *) buf,
                                 sizeof buf, NULL, NULL)) > 0) {
        if (n < 16) continue;

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
        if (gsmtap_is_gsm(type)) {
            guint8 c = sub;
            if (c == 0) c = (guint8) ((arf >> 8) & 0xff);
            ch = gsmtap_channel_name(c);
        }

        GDateTime *now = g_date_time_new_now_local();
        g_autofree char *t = now ? g_date_time_format(now, "%H:%M:%S") : NULL;
        if (now) g_date_time_unref(now);

        GString *pay = g_string_new(NULL);
        for (guint i = 0; i < paylen && i < 14; i++)
            g_string_append_printf(pay, "%02x", buf[hdr_bytes + i]);
        if (paylen > 14) g_string_append(pay, "..");

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
        m->payload = g_string_free(pay, FALSE);

        live_add_msg(state, m);   /* live_add_msg takes the reference */
    }

    if (state->live_count > 0) {
        g_autofree char *m = g_strdup_printf("%u message%s",
            state->live_count, state->live_count == 1 ? "" : "s");
        live_set_status(state, m, "status-ok");
    }
    return G_SOURCE_CONTINUE;
}

static gboolean
live_hint_cb(gpointer user_data)
{
    AppState *state = user_data;
    state->live_hint = 0;
    if (state->live_count == 0 && state->live_socket != NULL)
        live_set_status(state,
            "listening — no emitter yet. Start grgsm_livemon, or an eNB/gNB "
            "with GSMTAP enabled.", "status-error");
    return G_SOURCE_REMOVE;
}

static void
live_stop(AppState *state)
{
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
}

static void
live_start(AppState *state)
{
    g_autoptr(GError) error = NULL;
    GSocketAddress *addr;

    state->live_socket = g_socket_new(G_SOCKET_FAMILY_IPV4,
                                      G_SOCKET_TYPE_DATAGRAM,
                                      G_SOCKET_PROTOCOL_UDP, &error);
    if (state->live_socket == NULL) {
        live_set_status(state, error ? error->message : "socket failed",
                        "status-error");
        return;
    }

    addr = g_inet_socket_address_new_from_string("0.0.0.0", LIVE_PORT);
    if (!g_socket_bind(state->live_socket, addr, TRUE, &error)) {
        g_autofree char *m = g_strdup_printf("cannot bind udp/%d — %s",
            LIVE_PORT, error ? error->message : "in use");
        live_set_status(state, m, "status-error");
        g_object_unref(addr);
        g_clear_object(&state->live_socket);
        return;
    }
    g_object_unref(addr);

    g_socket_set_blocking(state->live_socket, FALSE);
    state->live_poll = g_timeout_add(120, live_poll_cb, state);

    if (state->live_button != NULL)
        gtk_button_set_label(GTK_BUTTON(state->live_button), "Stop");
    live_set_status(state, "listening on udp/4729", "status-running");
    state->live_hint = g_timeout_add(3000, live_hint_cb, state);
}

static void
live_toggle_clicked(GtkButton *b, gpointer user_data)
{
    AppState *state = user_data;
    (void) b;
    if (state->live_socket != NULL) live_stop(state);
    else                            live_start(state);
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
    live_update_summary(state);
    live_set_status(state, state->live_socket ? "listening on udp/4729"
                                              : "stopped",
                    state->live_socket ? "status-running" : "status-idle");
}

static void
live_filter_changed(GtkEditable *e, gpointer user_data)
{
    AppState *state = user_data;
    g_free(state->live_filter);
    state->live_filter = g_strdup(gtk_editable_get_text(e));
    live_refilter(state);
}

static void
live_filter_cleared(GtkButton *b, gpointer user_data)
{
    AppState *state = user_data;
    (void) b;
    if (state->live_filter_entry != NULL)
        gtk_editable_set_text(GTK_EDITABLE(state->live_filter_entry), "");
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
    GtkWidget *bar    = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *flabel = gtk_label_new("Filter");
    GtkWidget *fentry = gtk_entry_new();
    GtkWidget *fclear = gtk_button_new_with_label("Reset");
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
    gtk_widget_add_css_class(view,   "live-table");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(sub),   0.0f);
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

    /* ---- toolbar ---- */
    gtk_entry_set_placeholder_text(GTK_ENTRY(fentry),
        "type, channel or payload substring");
    gtk_widget_set_hexpand(fentry, TRUE);
    gtk_box_append(GTK_BOX(bar), flabel);
    gtk_box_append(GTK_BOX(bar), fentry);
    gtk_box_append(GTK_BOX(bar), fclear);
    gtk_widget_set_margin_start(bar, 16);
    gtk_widget_set_margin_end(bar, 16);
    gtk_widget_set_margin_bottom(bar, 8);
    gtk_box_append(GTK_BOX(outer), bar);

    /* ---- table ---- */
    state->live_store = g_list_store_new(LIVE_TYPE_MSG);
    gtk_column_view_set_model(GTK_COLUMN_VIEW(view),
        GTK_SELECTION_MODEL(gtk_no_selection_new(
            G_LIST_MODEL(g_object_ref(state->live_store)))));
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
    gtk_box_append(GTK_BOX(outer), overlay);

    state->live_view         = view;
    state->live_status       = status;
    state->live_button       = start;
    state->live_filter_entry = fentry;
    state->live_summary      = summary;
    state->live_empty        = empty;
    state->live_count        = 0;
    state->live_socket       = NULL;
    state->live_poll         = 0;
    state->live_hint         = 0;
    state->live_msgs         = NULL;
    state->live_filter       = NULL;

    g_signal_connect(start,  "clicked", G_CALLBACK(live_toggle_clicked), state);
    g_signal_connect(clear,  "clicked", G_CALLBACK(live_clear_clicked), state);
    g_signal_connect(fentry, "changed", G_CALLBACK(live_filter_changed), state);
    g_signal_connect(fclear, "clicked", G_CALLBACK(live_filter_cleared), state);
    return outer;
}

/* ==================================================================== */
/*  SIDEBAR COLLAPSE                                                    */
/* ==================================================================== */

static void
sidebar_toggle_toggled(GtkToggleButton *button, gpointer user_data)
{
    AppState *state = user_data;
    gboolean show = gtk_toggle_button_get_active(button);

    if (state->sidebar == NULL) return;
    gtk_widget_set_visible(state->sidebar, show);
    gtk_widget_set_visible(gtk_paned_get_start_child(
        GTK_PANED(state->sidebar_paned)), show);
    if (show)
        gtk_paned_set_position(GTK_PANED(state->sidebar_paned), 272);
}

static void
on_activate(GtkApplication *app, gpointer user_data)
{
    AppState *state = user_data;

    if (state->window != NULL) {
        gtk_window_present(GTK_WINDOW(state->window));
        return;
    }

    state->window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(state->window), "IMSIsting");
    gtk_window_set_default_size(GTK_WINDOW(state->window), 1180, 760);

    g_autoptr(GtkCssProvider) css = gtk_css_provider_new();
    gtk_css_provider_load_from_resource(css, "/com/imsisting/native/style.css");
    gtk_style_context_add_provider_for_display(
        gdk_display_get_default(), GTK_STYLE_PROVIDER(css),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);

    GtkWidget *root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);

    /* Header bar. */
    GtkWidget *header = gtk_header_bar_new();
    GtkWidget *titlebox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *title = gtk_label_new("IMSIsting");
    GtkWidget *subtitle = gtk_label_new("2G · 3G · 4G · 5G cellular research toolkit");
    gtk_widget_add_css_class(title, "title");
    gtk_widget_add_css_class(subtitle, "app-subtitle");
    gtk_widget_set_halign(title, GTK_ALIGN_START);
    gtk_widget_set_halign(subtitle, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(titlebox), title);
    gtk_box_append(GTK_BOX(titlebox), subtitle);
    gtk_header_bar_set_title_widget(GTK_HEADER_BAR(header), titlebox);

    /* Modules toggle — the sidebar collapses so a module page gets the
       full width when it needs it. */
    GtkWidget *modules_btn = gtk_toggle_button_new_with_label("Modules");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(modules_btn), TRUE);
    gtk_widget_set_tooltip_text(modules_btn, "show or hide the module list");
    g_signal_connect(modules_btn, "toggled",
                     G_CALLBACK(sidebar_toggle_toggled), state);
    gtk_header_bar_pack_start(GTK_HEADER_BAR(header), modules_btn);
    state->sidebar_toggle = modules_btn;

    GtkWidget *events_btn = gtk_toggle_button_new_with_label("Events");
    gtk_widget_set_tooltip_text(events_btn,
        "show the event drawer — module output and diagnostics");
    g_signal_connect(events_btn, "toggled",
                     G_CALLBACK(event_drawer_toggle), state);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(header), events_btn);
    state->event_button = events_btn;
    gtk_window_set_titlebar(GTK_WINDOW(state->window), header);

    /* Live cellular state, read from the modules themselves. */
    gtk_box_append(GTK_BOX(root), build_status_strip(state));

    /* Body: sidebar | notebook. */
    GtkWidget *paned = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_paned_set_position(GTK_PANED(paned), 272);
    state->sidebar_paned = paned;

    state->sidebar = build_sidebar(state);
    gtk_paned_set_start_child(GTK_PANED(paned), state->sidebar);
    /* Keep the sidebar at its width when the window grows. */
    gtk_paned_set_shrink_start_child(GTK_PANED(paned), FALSE);

    state->notebook = gtk_notebook_new();
    gtk_notebook_set_scrollable(GTK_NOTEBOOK(state->notebook), TRUE);
    gtk_notebook_set_show_border(GTK_NOTEBOOK(state->notebook), FALSE);
    gtk_paned_set_end_child(GTK_PANED(paned), state->notebook);

    gtk_widget_set_vexpand(paned, TRUE);
    gtk_box_append(GTK_BOX(root), paned);

    /* ---- permanent tabs, in order, before any module page ----
       These carry a bare label rather than a closable tab, so they cannot be
       closed. Module pages are appended after them and do close. */
    gtk_notebook_append_page(GTK_NOTEBOOK(state->notebook),
        create_dashboard_page(state), gtk_label_new("Dashboard"));
    gtk_notebook_append_page(GTK_NOTEBOOK(state->notebook),
        create_live_traffic_page(state), gtk_label_new("Live Traffic"));
    gtk_notebook_append_page(GTK_NOTEBOOK(state->notebook),
        create_loot_page(state), gtk_label_new("Loot"));
    gtk_notebook_append_page(GTK_NOTEBOOK(state->notebook),
        create_stats_page(state), gtk_label_new("Stats"));
    gtk_notebook_append_page(GTK_NOTEBOOK(state->notebook),
        text_page("Help", "How this is put together", HELP_TEXT, NULL),
        gtk_label_new("Help"));
    gtk_notebook_append_page(GTK_NOTEBOOK(state->notebook),
        create_settings_page(state), gtk_label_new("Settings"));

    g_signal_connect(state->notebook, "switch-page",
                     G_CALLBACK(notebook_page_switched), state);

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

    gtk_window_set_child(GTK_WINDOW(state->window), root);

    report_index_drift(state);
    append_event(state, "IMSIsting started — modules are standalone scripts "
                        "in modules/; the GUI is a view over them.");

    /* Poll the live status strip. Cheap: every value is a --status-tsv verb
       that returns in well under 100 ms. */
    status_poll(state);
    state->status_source = g_timeout_add_seconds(3, status_poll, state);

    gtk_window_present(GTK_WINDOW(state->window));
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
        live_stop(state);
}

int
main(int argc, char **argv)
{
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

/* Pages are registered after the builders are defined, because the table
   references them. Each module lists its submenu entries; a module with none
   falls back to create_placeholder_page(). */

static ModuleSubmenuEntry deps_entries[] = {
    { "Dependencies", "system-software-install-symbolic", page_deps },
};
static ModuleSubmenuEntry radio_entries[] = {
    { "Devices",   "radio-symbolic",              page_radio },
};
static ModuleSubmenuEntry crec_entries[] = {
    { "Survey",    "network-wireless-symbolic",   page_cell_recon },
};
static ModuleSubmenuEntry gtap_entries[] = {
    { "Capture",   "network-receive-symbolic",    page_gsmtap },
};
static GtkWidget *
page_fkit(AppState *state, gpointer module_data)
{
    static const VerbButton verbs[] = {
        { "--capability",  "Capability",  FALSE },
        { "--guard-check", "Guard check", FALSE },
        { "--scenarios",   "Scenarios",   FALSE },
        { "--status-tsv",  "Status",      FALSE },
        { "--selftest",    "Self-test",   FALSE },
    };
    (void) module_data;
    return build_verb_page(state, "05_field_kit", verbs, G_N_ELEMENTS(verbs),
                           NULL);
}

static ModuleSubmenuEntry fkit_entries[] = {
    { "Field Kit", "preferences-system-symbolic", page_fkit },
};

static ModuleSubmenuEntry tmap_entries[] = {
    { "Survey",    "mark-location-symbolic",      page_tower_map },
};
static ModuleSubmenuEntry pcap_entries[] = {
    { "Analysis",  "document-open-symbolic",      page_pcap },
};
static ModuleSubmenuEntry gcve_entries[] = {
    { "Probes",    "application-x-executable-symbolic", page_gsm_cve },
};
static ModuleSubmenuEntry lcve_entries[] = {
    { "Probes",    "application-x-executable-symbolic", page_lte_cve },
};
static ModuleSubmenuEntry ncve_entries[] = {
    { "Probes",    "application-x-executable-symbolic", page_nr_cve },
};

static ModuleSubmenuEntry gair_entries[] = {
    { "Decode",    "network-cellular-2g-symbolic", page_gsm_air },
};
static ModuleSubmenuEntry gatk_entries[] = {
    { "Vectors",   "security-high-symbolic",       page_gsm_attack },
};
static ModuleSubmenuEntry uair_entries[] = {
    { "Decode",    "network-cellular-3g-symbolic", page_umts_air },
};
static ModuleSubmenuEntry latt_entries[] = {
    { "NAS",       "network-cellular-4g-symbolic", page_lte_attach },
};
static ModuleSubmenuEntry lair_entries[] = {
    { "Air",       "network-wireless-symbolic",    page_lte_air },
};
static ModuleSubmenuEntry lcore_entries[] = {
    { "Core",      "network-server-symbolic",      page_lte_core },
};
static ModuleSubmenuEntry nair_entries[] = {
    { "Air",       "network-cellular-5g-symbolic", page_nr_air },
};
static ModuleSubmenuEntry ncore_entries[] = {
    { "Core",      "network-server-symbolic",      page_nr_core },
};
static ModuleSubmenuEntry suci_entries[] = {
    { "Privacy",   "channel-secure-symbolic",      page_suci },
};
static ModuleSubmenuEntry dwn_entries[] = {
    { "Downgrade", "go-down-symbolic",             page_downgrade },
};
static ModuleSubmenuEntry sim_entries[] = {
    { "SIM",       "auth-smartcard-symbolic",      page_sim },
};
static ModuleSubmenuEntry imsi_entries[] = {
    { "Exposure",  "dialog-warning-symbolic",      page_imsi },
};
static ModuleSubmenuEntry caud_entries[] = {
    { "Ciphers",   "channel-secure-symbolic",      page_cipher },
};
static ModuleSubmenuEntry kchn_entries[] = {
    { "Chains",    "media-playback-start-symbolic", page_killchain },
};
static ModuleSubmenuEntry tana_entries[] = {
    { "Traffic Analysis", "network-wireless-symbolic", page_tana },
};
static ModuleSubmenuEntry rff_entries[] = {
    { "RF Fingerprint", "radio-symbolic", page_rff },
};
static ModuleSubmenuEntry macl_entries[] = {
    { "MAC Layer", "network-receive-symbolic", page_macl },
};
static ModuleSubmenuEntry nasf_entries[] = {
    { "NAS Signalling", "network-cellular-4g-symbolic", page_nasf },
};
static ModuleSubmenuEntry ss7_entries[] = {
    { "SS7", "network-server-symbolic", page_ss7 },
};
static ModuleSubmenuEntry cdns_entries[] = {
    { "DNS over Cellular", "network-wired-symbolic", page_cdns },
};
static ModuleSubmenuEntry pgt_entries[] = {
    { "Paging", "network-cellular-2g-symbolic", page_pgt },
};
static ModuleSubmenuEntry vims_entries[] = {
    { "VoLTE", "audio-input-microphone-symbolic", page_vims },
};
static ModuleSubmenuEntry simd_entries[] = {
    { "SIM Swap Defence", "channel-secure-symbolic", page_simd },
};
static ModuleSubmenuEntry jamd_entries[] = {
    { "Jamming Detection", "dialog-warning-symbolic", page_jamd },
};
static ModuleSubmenuEntry slic_entries[] = {
    { "Network Slicing", "network-cellular-5g-symbolic", page_slic },
};
static ModuleSubmenuEntry iot_entries[] = {
    { "NB-IoT / Cat-M1", "network-cellular-2g-symbolic", page_iot },
};
static ModuleSubmenuEntry lpp_entries[] = {
    { "LPP Positioning", "mark-location-symbolic", page_lpp },
};
static ModuleSubmenuEntry wifioff_entries[] = {
    { "Wi-Fi Offload / LWA", "network-wired-symbolic", page_wifioff },
};
static ModuleSubmenuEntry bbnd_entries[] = {
    { "Baseband Research", "application-x-executable-symbolic", page_bbnd },
};
static ModuleSubmenuEntry vowi_entries[] = {
    { "VoWiFi / ePDG", "network-wired-symbolic", page_vowi },
};
static ModuleSubmenuEntry femt_entries[] = {
    { "Femtocell / HeNB", "network-server-symbolic", page_femt },
};
static ModuleSubmenuEntry ussd_entries[] = {
    { "USSD", "network-cellular-2g-symbolic", page_ussd },
};
static ModuleSubmenuEntry tgeo_entries[] = {
    { "TA Geolocation", "mark-location-symbolic", page_tgeo },
};
static ModuleSubmenuEntry sbap_entries[] = {
    { "5G SBA Pivot", "network-server-symbolic", page_sbap },
};
static ModuleSubmenuEntry otasm_entries[] = {
    { "OTA Binary SMS", "auth-smartcard-symbolic", page_otasm },
};
static ModuleSubmenuEntry lipr_entries[] = {
    { "LI Discovery", "dialog-warning-symbolic", page_lipr },
};
static ModuleSubmenuEntry rans_entries[] = {
    { "RAN Sharing", "network-wired-symbolic", page_rans },
};
static ModuleSubmenuEntry capi_entries[] = {
    { "Carrier API Audit", "channel-secure-symbolic", page_capi },
};
static ModuleSubmenuEntry oran_entries[] = {
    { "O-RAN / Open RAN", "network-server-symbolic", page_oran },
};
static ModuleSubmenuEntry ntn_entries[] = {
    { "5G NTN / Satellite", "network-cellular-5g-symbolic", page_ntn },
};
static ModuleSubmenuEntry gprs_entries[] = {
    { "GPRS / EDGE", "network-cellular-2g-symbolic", page_gprs },
};
static ModuleSubmenuEntry slnk_entries[] = {
    { "NR Sidelink / V2X", "network-wireless-symbolic", page_slnk },
};
static ModuleSubmenuEntry stk_entries[] = {
    { "SIM Toolkit (STK)", "auth-smartcard-symbolic", page_stk },
};
static ModuleSubmenuEntry n3g_entries[] = {
    { "TETRA / DMR / GSM-R", "radio-symbolic", page_n3g },
};
static ModuleSubmenuEntry bexp_entries[] = {
    { "Baseband Exploits", "application-x-executable-symbolic", page_bexp },
};
static ModuleSubmenuEntry nrj_entries[] = {
    { "5G NR Injection", "network-cellular-5g-symbolic", page_nrj },
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
    module_registry_register("10_gsm_air", gair_entries,
                             G_N_ELEMENTS(gair_entries), NULL);
    module_registry_register("11_gsm_attack", gatk_entries,
                             G_N_ELEMENTS(gatk_entries), NULL);
    module_registry_register("12_umts_air", uair_entries,
                             G_N_ELEMENTS(uair_entries), NULL);
    module_registry_register("13_lte_attach", latt_entries,
                             G_N_ELEMENTS(latt_entries), NULL);
    module_registry_register("14_lte_air", lair_entries,
                             G_N_ELEMENTS(lair_entries), NULL);
    module_registry_register("15_lte_core", lcore_entries,
                             G_N_ELEMENTS(lcore_entries), NULL);
    module_registry_register("16_nr_air", nair_entries,
                             G_N_ELEMENTS(nair_entries), NULL);
    module_registry_register("17_nr_core", ncore_entries,
                             G_N_ELEMENTS(ncore_entries), NULL);
    module_registry_register("18_suci", suci_entries,
                             G_N_ELEMENTS(suci_entries), NULL);
    module_registry_register("19_downgrade", dwn_entries,
                             G_N_ELEMENTS(dwn_entries), NULL);
    module_registry_register("20_sim", sim_entries,
                             G_N_ELEMENTS(sim_entries), NULL);
    module_registry_register("21_pcap_analysis", pcap_entries,
                             G_N_ELEMENTS(pcap_entries), NULL);
    module_registry_register("22_imsi_exposure", imsi_entries,
                             G_N_ELEMENTS(imsi_entries), NULL);
    module_registry_register("23_cipher_audit", caud_entries,
                             G_N_ELEMENTS(caud_entries), NULL);
    module_registry_register("24_gsm_cve", gcve_entries,
                             G_N_ELEMENTS(gcve_entries), NULL);
    module_registry_register("25_lte_cve", lcve_entries,
                             G_N_ELEMENTS(lcve_entries), NULL);
    module_registry_register("26_nr_cve", ncve_entries,
                             G_N_ELEMENTS(ncve_entries), NULL);
    module_registry_register("30_killchain", kchn_entries,
                             G_N_ELEMENTS(kchn_entries), NULL);
    module_registry_register("27_traffic_analysis", tana_entries,
                             G_N_ELEMENTS(tana_entries), NULL);
    module_registry_register("28_rf_fingerprint", rff_entries,
                             G_N_ELEMENTS(rff_entries), NULL);
    module_registry_register("34_mac_layer", macl_entries,
                             G_N_ELEMENTS(macl_entries), NULL);
    module_registry_register("37_nas_signaling", nasf_entries,
                             G_N_ELEMENTS(nasf_entries), NULL);
    module_registry_register("31_ss7_map", ss7_entries,
                             G_N_ELEMENTS(ss7_entries), NULL);
    module_registry_register("32_cellular_dns", cdns_entries,
                             G_N_ELEMENTS(cdns_entries), NULL);
    module_registry_register("33_paging_track", pgt_entries,
                             G_N_ELEMENTS(pgt_entries), NULL);
    module_registry_register("35_volte_ims", vims_entries,
                             G_N_ELEMENTS(vims_entries), NULL);
    module_registry_register("36_sim_defense", simd_entries,
                             G_N_ELEMENTS(simd_entries), NULL);
    module_registry_register("38_jamming_detect", jamd_entries,
                             G_N_ELEMENTS(jamd_entries), NULL);
    module_registry_register("39_slicing", slic_entries,
                             G_N_ELEMENTS(slic_entries), NULL);
    module_registry_register("50_iot", iot_entries,
                             G_N_ELEMENTS(iot_entries), NULL);
    module_registry_register("51_lpp", lpp_entries,
                             G_N_ELEMENTS(lpp_entries), NULL);
    module_registry_register("52_wifioff", wifioff_entries,
                             G_N_ELEMENTS(wifioff_entries), NULL);
    module_registry_register("40_baseband", bbnd_entries,
                             G_N_ELEMENTS(bbnd_entries), NULL);
    module_registry_register("41_vowifi", vowi_entries,
                             G_N_ELEMENTS(vowi_entries), NULL);
    module_registry_register("42_femtocell", femt_entries,
                             G_N_ELEMENTS(femt_entries), NULL);
    module_registry_register("43_ussd", ussd_entries,
                             G_N_ELEMENTS(ussd_entries), NULL);
    module_registry_register("44_ta_geoloc", tgeo_entries,
                             G_N_ELEMENTS(tgeo_entries), NULL);
    module_registry_register("45_sba_pivot", sbap_entries,
                             G_N_ELEMENTS(sbap_entries), NULL);
    module_registry_register("46_ota_sms", otasm_entries,
                             G_N_ELEMENTS(otasm_entries), NULL);
    module_registry_register("47_li_probe", lipr_entries,
                             G_N_ELEMENTS(lipr_entries), NULL);
    module_registry_register("48_ran_share", rans_entries,
                             G_N_ELEMENTS(rans_entries), NULL);
    module_registry_register("49_carrier_api", capi_entries,
                             G_N_ELEMENTS(capi_entries), NULL);
    module_registry_register("53_oran", oran_entries,
                             G_N_ELEMENTS(oran_entries), NULL);
    module_registry_register("54_ntn", ntn_entries,
                             G_N_ELEMENTS(ntn_entries), NULL);
    module_registry_register("55_gprs", gprs_entries,
                             G_N_ELEMENTS(gprs_entries), NULL);
    module_registry_register("56_sidelink", slnk_entries,
                             G_N_ELEMENTS(slnk_entries), NULL);
    module_registry_register("57_stk", stk_entries,
                             G_N_ELEMENTS(stk_entries), NULL);
    module_registry_register("58_non3gpp", n3g_entries,
                             G_N_ELEMENTS(n3g_entries), NULL);
    module_registry_register("59_baseband_exploit", bexp_entries,
                             G_N_ELEMENTS(bexp_entries), NULL);
    module_registry_register("60_nr_inject", nrj_entries,
                             G_N_ELEMENTS(nrj_entries), NULL);
}
