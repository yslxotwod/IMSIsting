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

/* Module icons resolve by name from the hicolor theme: the symbolic SVGs in
   native/resources/icons/symbolic are installed there by the launcher and
   looked up as "imsisting-<id>-symbolic". The accessors below are the single
   place that maps a module id to its icon/name, the way wifisting does. */

typedef struct {
    const char *name;
    const char *icon;
    /* The buttons a submenu holds, as "verb[:Label][!]" entries separated by
       '|'.  ! = needs root. A leading '~' marks a verb that needs an argument,
       which is kept on the command line rather than put behind a button.
       Sections may be named with a leading '#': "#CONTROLS|--a|#STATUS|--b".
       Ignored when `build` is set. */
    const char *spec;
    /* Optional module-specific view, used when a view is a LIST with per-row
       actions rather than a row of buttons - Cell Recon's surveyed cells, the
       way wifisting's Targets view works. Signature mirrors
       build_group_view() so it can produce the same output card. */
    GtkWidget *(*build)(struct _AppState *state, const char *module_id,
                        GtkWidget *status, GtkTextBuffer *out);
} ModuleSubmenuEntry;

/* One row in a module's left-hand menu, in display order. The registered
   entries are wrapped with an Overview at the top and the full command list at
   the bottom, so every module's menu reads the same way. */
typedef struct {
    const char *name;
    const char *icon;
    GtkWidget *page;
} ModuleView;

typedef struct {
    AppState *state;
    const ModuleDefinition *module;
    GtkWidget *page;
    GtkWidget *submenu_list;
    GtkWidget *stack;
    GtkWidget *header_box;
    GtkWidget *status_pill;
    gpointer module_data;
    ModuleView *views;
    int n_views;
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
    /* Live station band on the dashboard: case-scoped facts the status strip
       does not carry (case, targets, evidence, alerts). */
    GtkWidget *dash_case, *dash_targets, *dash_evidence, *dash_alerts;
    /* Dashboard grid handle + the pin/recent sets behind the card cues. */
    GtkWidget *dash_flow, *dash_search;
    GHashTable *pins, *recent;
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
    GtkTextBuffer *live_inspector_buf; /* full detail for the selected row */
    GtkWidget     *live_pause_button;
    GtkWidget     *live_scroll;        /* scroller, for Follow */
    gboolean       live_follow;
    GSocket       *live_socket;
    GListStore    *live_store;         /* what the view shows */
    GPtrArray     *live_msgs;          /* retained, filtered into the store */
    char          *live_filter;
    guint          live_poll;          /* timer that drains the socket */
    guint          live_count;
    guint          live_hint;
    gboolean       live_paused;

    /* Event drawer chrome. */
    GtkWidget     *event_filter_entry;
    GtkWidget     *event_badge;
    GtkWidget     *event_button;
    gboolean       event_autoscroll;
    gboolean       event_errors_only;
    guint          event_errors;

    /* Casebook workspace. Evidence retains the original loot preview. */
    GtkWidget     *loot_preview;
    GtkTextBuffer *loot_preview_buf;
    char          *loot_preview_path;
    GtkTextBuffer *casebook_overview;   /* Overview still a dump; converted next */
    /* Records, not text: these were monospace TSV dumps, which is what made
       the Casebook tabs look like a terminal sitting in the window. */
    GtkWidget *casebook_captures_list;
    GtkWidget *casebook_timeline_list;
    GtkWidget *casebook_alerts_list;
    GtkWidget *casebook_nodes_list;
    GtkWidget *casebook_reports_list;
    GtkWidget *casebook_brief_case, *casebook_brief_target;
    GtkWidget *casebook_brief_evidence, *casebook_brief_alerts;
    GtkWidget *casebook_brief_scope, *casebook_brief_auth, *casebook_brief_alert;
    GtkWidget *case_name_entry, *case_scope_entry, *case_auth_entry;
    GtkWidget *case_select_entry;
    /* The radio target, reachable from every page through the header. Kept
       apart from the Casebook target_*_entry widgets above: those describe a
       case, this one is what the cellular modules tune to. */
    GtkWidget *rtarget_revealer, *rtarget_button, *rtarget_state_lbl;
    GtkWidget *rtarget_rat, *rtarget_arfcn, *rtarget_plmn, *rtarget_cell;
    GtkWidget *node_name_entry, *node_host_entry, *node_transport_entry;

    /* Output buffer of the module page on screen, or NULL on a non-module
       tab. A run started while a module page is visible writes into it, so
       the result shows next to the button that was pressed. Held with a
       ref: a run in flight can outlive the page it started from. */
    GtkTextBuffer *active_output;
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
    GtkTextBuffer *output;  /* page output card to echo into, or NULL */
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
      "imsisting-00_deps-symbolic",
      "Checks the cellular toolchain against a per-distro table and installs what is missing." },
    { "01_radio",            "SDR / Radio Manager",  "SYSTEM",
      "imsisting-01_radio-symbolic",
      "Enumerates SDRs, reports driver, serial and range, and flags receive-only devices." },
    { "05_field_kit",        "Field Kit",            "SYSTEM",
      "imsisting-05_field_kit-symbolic",
      "RF pre-flight, honesty verification of every radio verb, and a synthetic GSMTAP source." },
    { "30_killchain",        "Cellular Killchain",   "SYSTEM",
      "imsisting-30_killchain-symbolic",
      "Chains module verbs into repeatable runs from a TSV chain file." },

    /* RECON — survey and passive observation */
    { "02_cell_recon",       "Cell Recon",           "RECON",
      "imsisting-02_cell_recon-symbolic",
      "ARFCN/EARFCN/NR-ARFCN to frequency, PLMN to operator, and a cell survey from an SDR or capture." },
    { "03_gsmtap",           "GSMTAP Passive",       "RECON",
      "imsisting-03_gsmtap-symbolic",
      "GSMTAP header codec and pcap I/O; listens for gr-gsm and srsRAN traffic." },
    { "04_tower_map",        "Tower Survey",         "RECON",
      "imsisting-04_tower_map-symbolic",
      "GPS-tagged cell survey with CSV, KML and GeoJSON export." },
    { "54_ntn",              "5G NTN / Satellite",   "RECON",
      "imsisting-54_ntn-symbolic",
      "Non-terrestrial access: Doppler, round-trip delay, TA, k_offset and the SIB19 fields." },
    { "58_non3gpp",          "TETRA / DMR / GSM-R",  "RECON",
      "imsisting-58_non3gpp-symbolic",
      "Non-3GPP land mobile radio: TETRA, DMR and GSM-R structure, ciphers and band classification." },

    /* AIR INTERFACE — per-RAT decoding and encoding */
    { "10_gsm_air",          "GSM Air Interface",    "AIR INTERFACE",
      "imsisting-10_gsm_air-symbolic",
      "GSM system information, paging, cipher audit and A5/1 keystream, proved against the BGW vector." },
    { "12_umts_air",         "UMTS Air Interface",   "AIR INTERFACE",
      "imsisting-12_umts_air-symbolic",
      "UMTS UARFCN, SIB decode, RRC integrity (UIA1/UIA2) and the AKA relay flow." },
    { "14_lte_air",          "LTE Air Interface",    "AIR INTERFACE",
      "imsisting-14_lte_air-symbolic",
      "LTE EARFCN, RRC/SIB decode, paging maths and srsRAN eNB orchestration." },
    { "16_nr_air",           "5G NR Air Interface",  "AIR INTERFACE",
      "imsisting-16_nr_air-symbolic",
      "NR-ARFCN, MIB/SIB1 decode, PCI, PRACH occasions and gNB config generation." },
    { "50_iot",              "NB-IoT / Cat-M1",      "AIR INTERFACE",
      "imsisting-50_iot-symbolic",
      "NB-IoT and Cat-M1: NPRACH, NPSS/NSSS, SIB1-NB and NPRFCN." },
    { "55_gprs",             "GPRS / EDGE",          "AIR INTERFACE",
      "imsisting-55_gprs-symbolic",
      "GPRS/EDGE packet-switched: GEA ciphering, APN coding, PDP context and downgrade detection." },
    { "56_sidelink",         "NR Sidelink / V2X",    "AIR INTERFACE",
      "imsisting-56_sidelink-symbolic",
      "NR sidelink on PC5: resource pools, SCI-1A, ITS certificates and relay checks." },

    /* CORE NETWORK — attach, core, interconnect and roaming */
    { "13_lte_attach",       "LTE Attach / NAS",     "CORE NETWORK",
      "imsisting-13_lte_attach-symbolic",
      "NAS EMM/ESM encode-decode, BCD IMSI/IMEI, attach forge and identity-exposure detection." },
    { "15_lte_core",         "LTE Core (EPC)",       "CORE NETWORK",
      "imsisting-15_lte_core-symbolic",
      "Diameter S6a/S6d, GTP-C/GTP-U and S1AP; decodes the EPC core and forges registration moves." },
    { "17_nr_core",          "5G Core (SBA)",        "CORE NETWORK",
      "imsisting-17_nr_core-symbolic",
      "5G SBA: NGAP, 5GS NAS, 5G-GUTI, PFCP rules and 5G-AKA." },
    { "31_ss7_map",          "SS7 / MAP / GRX",      "CORE NETWORK",
      "imsisting-31_ss7_map-symbolic",
      "MTP3/SCCP/TCAP/MAP decode, SRI/ATI/PSI flows and GRX reachability." },
    { "32_cellular_dns",     "DNS over Cellular",    "CORE NETWORK",
      "imsisting-32_cellular_dns-symbolic",
      "DNS encode-decode, the aLTEr redirection sequence and response-tampering detection." },
    { "39_slicing",          "Network Slicing",      "CORE NETWORK",
      "imsisting-39_slicing-symbolic",
      "S-NSSAI encode-decode, slice selection and cross-slice isolation testing." },
    { "41_vowifi",           "VoWiFi / ePDG",        "CORE NETWORK",
      "imsisting-41_vowifi-symbolic",
      "IKEv2 over SWu, EAP-AKA, the SWu NAI and an encryption/integrity transform audit." },
    { "42_femtocell",        "Femtocell / HeNB",     "CORE NETWORK",
      "imsisting-42_femtocell-symbolic",
      "HeNB assessment: CSG/PCI conflicts, the Iuh stack and a TR-069 management audit." },
    { "43_ussd",             "USSD",                 "CORE NETWORK",
      "imsisting-43_ussd-symbolic",
      "USSD/MMI parsing, 7-bit packing and USSD/STK injection detection." },
    { "45_sba_pivot",        "5G SBA Pivot",         "CORE NETWORK",
      "imsisting-45_sba_pivot-symbolic",
      "HTTP/2 SBI framing, NRF discovery and OAuth2 token audit." },
    { "48_ran_share",        "RAN Sharing",          "CORE NETWORK",
      "imsisting-48_ran_share-symbolic",
      "PLMN coding, MOCN/MORAN/GWCN classification and cross-operator leakage detection." },
    { "52_wifioff",          "Wi-Fi Offload / LWA",  "CORE NETWORK",
      "imsisting-52_wifioff-symbolic",
      "Wi-Fi offload and LWA: ePDG FQDN, certificate validation and LWA configuration." },

    /* SIM / IDENTITY — the subscription and its keys */
    { "18_suci",             "SUCI / SUPI",          "SIM / IDENTITY",
      "imsisting-18_suci-symbolic",
      "SUCI conceal/deconceal (ECIES profile A/B), HKDF and the null-scheme audit." },
    { "20_sim",              "SIM / eSIM / OTA",     "SIM / IDENTITY",
      "imsisting-20_sim-symbolic",
      "ISO-7816 APDU, USIM files, EF_AD in both layouts, OTA parsing and eSIM profiles." },
    { "36_sim_defense",      "SIM Swap Defence",     "SIM / IDENTITY",
      "imsisting-36_sim_defense-symbolic",
      "Detection and defence for a SIM port in flight, plus eSIM profile integrity." },
    { "46_ota_sms",          "OTA Binary SMS",       "SIM / IDENTITY",
      "imsisting-46_ota_sms-symbolic",
      "TS 23.048 OTA command-packet construction with an SPI/counter/key audit. Own-SIM and lab." },
    { "57_stk",              "SIM Toolkit (STK)",    "SIM / IDENTITY",
      "imsisting-57_stk-symbolic",
      "TS 31.111 proactive commands: build, parse and audit for silent off-device actions." },

    /* ATTACKS — offensive vectors and CVE kits */
    { "11_gsm_attack",       "GSM Attack",           "ATTACKS",
      "imsisting-11_gsm_attack-symbolic",
      "IMSI-catcher sequence, A5/1 downgrade, TMSI de-anonymisation and Kc recovery." },
    { "19_downgrade",        "Downgrade Attacks",    "ATTACKS",
      "imsisting-19_downgrade-symbolic",
      "Reject causes, null-cipher tables, Security Mode Command and downgrade detection." },
    { "24_gsm_cve",          "GSM/UMTS CVE Kit",     "ATTACKS",
      "imsisting-24_gsm_cve-symbolic",
      "Per-CVE probes and handoffs for 2G/3G stack bugs." },
    { "25_lte_cve",          "LTE CVE Kit",          "ATTACKS",
      "imsisting-25_lte_cve-symbolic",
      "LTE stack CVEs: baseband, NAS, ASN.1 and Diameter." },
    { "26_nr_cve",           "5G CVE Kit",           "ATTACKS",
      "imsisting-26_nr_cve-symbolic",
      "5G NR, SBA and SUCI CVEs." },
    { "35_volte_ims",        "VoLTE / IMS",          "ATTACKS",
      "imsisting-35_volte_ims-symbolic",
      "VoLTE keystream reuse (ReVoLTE), IMP4GT identity mapping and SIP/IMS analysis." },
    { "40_baseband",         "Baseband Research",    "ATTACKS",
      "imsisting-40_baseband-symbolic",
      "Baseband research scaffolding: ASN.1 mutation, corpus generation and crash triage." },
    { "53_oran",             "O-RAN / Open RAN",     "ATTACKS",
      "imsisting-53_oran-symbolic",
      "O-RAN interfaces, deployment assessment and xApp-authority modelling." },
    { "59_baseband_exploit", "Baseband Exploits",    "ATTACKS",
      "imsisting-59_baseband_exploit-symbolic",
      "L1/L2 malformed-PDU construction, 5G control-plane forgery, and the baseband CVE catalogue." },
    { "60_nr_inject",        "5G NR Injection",      "ATTACKS",
      "imsisting-60_nr_inject-symbolic",
      "NR RNTI tracking, MAC-NR framing, descrambling and the injection exploit set." },

    /* ANALYSIS — captures, identities and signalling */
    { "21_pcap_analysis",    "Capture Analysis",     "ANALYSIS",
      "imsisting-21_pcap_analysis-symbolic",
      "From-scratch pcap reader that dissects GSMTAP, Diameter, NGAP, S1AP, GTP, PFCP and RTP." },
    { "22_imsi_exposure",    "IMSI Exposure Audit",  "ANALYSIS",
      "imsisting-22_imsi_exposure-symbolic",
      "TMSI/GUTI to IMSI correlation, cross-capture audit and per-subscriber exposure scoring." },
    { "23_cipher_audit",     "Cipher Audit",         "ANALYSIS",
      "imsisting-23_cipher_audit-symbolic",
      "Scores negotiated ciphers per session across 2G-5G and finds null or downgraded bearers." },
    { "27_traffic_analysis", "Traffic Analysis",     "ANALYSIS",
      "imsisting-27_traffic_analysis-symbolic",
      "Flow and burst analysis, website fingerprinting and padding/shaping detection." },
    { "34_mac_layer",        "MAC Layer",            "ANALYSIS",
      "imsisting-34_mac_layer-symbolic",
      "LTE MAC PDU decode, RNTI tracking, scheduling-pattern inference and DCI/MCS mapping." },
    { "37_nas_signaling",    "NAS Signalling",       "ANALYSIS",
      "imsisting-37_nas_signaling-symbolic",
      "NAS message-rate measurement, procedure mix and signalling-storm detection." },
    { "47_li_probe",         "LI Discovery",         "ANALYSIS",
      "imsisting-47_li_probe-symbolic",
      "Lawful-interception interfaces and interception-posture signals. Detection only." },
    { "49_carrier_api",      "Carrier API Audit",    "ANALYSIS",
      "imsisting-49_carrier_api-symbolic",
      "Carrier API surface, authorisation-boundary testing and token/rate-limit audit." },

    /* RF / TRACKING — interference and position */
    { "28_rf_fingerprint",   "RF Fingerprint / CSI", "RF / TRACKING",
      "imsisting-28_rf_fingerprint-symbolic",
      "IQ fingerprinting (CFO, IRR, transients) and CSI side-channel extraction." },
    { "33_paging_track",     "Paging / Torpedo",     "RF / TRACKING",
      "imsisting-33_paging_track-symbolic",
      "Paging occasion maths, paging capture, and the Torpedo/Piercer models." },
    { "38_jamming_detect",   "Jamming Detection",    "RF / TRACKING",
      "imsisting-38_jamming_detect-symbolic",
      "Measures interference and discriminates jamming from congestion or a coverage hole." },
    { "44_ta_geoloc",        "TA Geolocation",       "RF / TRACKING",
      "imsisting-44_ta_geoloc-symbolic",
      "Timing-advance ranging and multi-cell trilateration from TA measurements." },
    { "51_lpp",              "LPP Positioning",      "RF / TRACKING",
      "imsisting-51_lpp-symbolic",
      "LTE Positioning Protocol: procedure codes, header codec and position-forgery detection." },
};

static const char *
module_icon_for(const char *module_id)
{
    for (guint i = 0; i < G_N_ELEMENTS(modules); i++)
        if (g_strcmp0(modules[i].id, module_id) == 0)
            return modules[i].icon;
    return "dialog-information-symbolic";
}

static const char *
module_name_for(const char *module_id)
{
    for (guint i = 0; i < G_N_ELEMENTS(modules); i++)
        if (g_strcmp0(modules[i].id, module_id) == 0)
            return modules[i].name;
    return (module_id && *module_id) ? module_id : "imsisting";
}

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
static char *casebook_call(const char *const *args, gboolean *ok_out);
static void casebook_home_refresh(AppState *state);
static void casebook_refresh(AppState *state);

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
/* Defined with the module output card further down; the action runner
   writes into a page's output buffer as lines arrive. */
static void console_append(GtkTextBuffer *buf, const char *text);

static void
action_run_unref(ActionRun *run)
{
    if (run == NULL) return;
    if (--run->refs > 0) return;

    if (run->state->running != NULL &&
        g_ptr_array_find(run->state->running, run, NULL))
        g_ptr_array_remove(run->state->running, run);

    g_clear_object(&run->output);
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
        console_append(run->output, line);
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

    /* Close the output card with the same verdict as the Events drawer, so
       a run reads as finished where it was started. */
    if (run->output != NULL) {
        g_autofree char *sum = (!ok || status != 0 || run->saw_error)
            ? g_strdup_printf("-- failed (exit %d)", status)
            : g_strdup("-- done (exit 0)");
        console_append(run->output, sum);
    }

    /* If a Casebook is active, preserve the result as a correlated event.
       No evidence is hashed automatically: indexing large IQ files remains an
       explicit operator action in Casebook > Captures. */
    const char *severity = (!ok || status != 0 || run->saw_error) ? "HIGH" : "INFO";
    const char *outcome = (!ok || status != 0 || run->saw_error) ? "failed" : "completed";
    g_autofree char *message = g_strdup_printf("%s: %s (exit %d)",
                                               run->label, outcome, status);
    const char *cb_args[] = { "--timeline-add", severity, "module-run",
                              run->module_id, message, "-", NULL };
    gboolean cb_ok = FALSE;
    g_autofree char *cb_out = casebook_call(cb_args, &cb_ok);
    (void) cb_out; /* no active case is normal and intentionally silent */
    if (cb_ok && state->casebook_timeline_list != NULL)
        casebook_refresh(state);

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

    /* Mark the module recent so its dashboard cue reflects use. */
    if (state->recent != NULL && module_id != NULL)
        g_hash_table_add(state->recent, g_strdup(module_id));

    append_event(state, label);
    status_label_set(status_label, "Running", "status-running");

    /* Surface the output. A module's stdout/stderr goes to the Events
       drawer, and a drawer the operator has to open themselves makes a
       button look like it did nothing - which is exactly the complaint
       this fixes. Opening it here means the result of the press is on
       screen from the first line. */
    if (state->event_revealer != NULL &&
        !gtk_revealer_get_reveal_child(GTK_REVEALER(state->event_revealer))) {
        if (state->event_button != NULL)
            gtk_toggle_button_set_active(
                GTK_TOGGLE_BUTTON(state->event_button), TRUE);
        else
            gtk_revealer_set_reveal_child(
                GTK_REVEALER(state->event_revealer), TRUE);
    }

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

    /* Echo the run into the output card of the page that is on screen. The
       run keeps its own reference, so closing the page mid-run is safe. */
    a->output = state->active_output != NULL
        ? g_object_ref(state->active_output) : NULL;
    if (a->output != NULL) {
        g_autofree char *hdr = g_strdup_printf("$ %s", label);
        console_append(a->output, hdr);
    }

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

/* Fallback handler for the placeholder page, used only by a module that has no
   registered submenu at all. Its buttons are derived from the generated index,
   so even an unregistered module is not frozen. */
static void
verb_button_dyn_clicked(GtkButton *button, gpointer user_data)
{
    AppState *state = g_object_get_data(G_OBJECT(button), "state");
    const char *module_id = g_object_get_data(G_OBJECT(button), "module-id");
    const char *verb = g_object_get_data(G_OBJECT(button), "verb");
    GtkWidget *status = g_object_get_data(G_OBJECT(button), "status");

    if (module_id == NULL || verb == NULL)
        return;
    g_autofree char *label = g_strdup_printf("%s %s", module_id, verb);
    run_module_verb(state, module_id, verb, label, status, FALSE);
    (void) user_data;
}

/* The newest file in captures/, used as the default for the verbs that read a
   capture: the button works on the most recent one without a prompt. */
static char *
newest_capture(void)
{
    g_autofree char *dir = g_build_filename(IMSISTING_ROOT, "captures", NULL);
    g_autoptr(GDir) d = g_dir_open(dir, 0, NULL);
    const char *name;
    GStatBuf best;
    g_autofree char *best_path = NULL;

    if (d == NULL)
        return NULL;
    while ((name = g_dir_read_name(d)) != NULL) {
        g_autofree char *p = g_build_filename(dir, name, NULL);
        GStatBuf st;
        if (g_stat(p, &st) != 0 || !S_ISREG(st.st_mode))
            continue;
        if (best_path == NULL || st.st_mtime > best.st_mtime) {
            g_free(best_path);
            best_path = g_strdup(p);
            best = st;
        }
    }
    return g_steal_pointer(&best_path);
}

/* One button in a curated module group. The verb, its privilege and its
   default arguments are attached to the button; one click runs it. A token of
   "{capture}" resolves to the newest capture so file verbs work untouched. */
static void
group_verb_clicked(GtkButton *button, gpointer user_data)
{
    AppState *state = g_object_get_data(G_OBJECT(button), "state");
    const char *module_id = g_object_get_data(G_OBJECT(button), "module-id");
    const char *verb = g_object_get_data(G_OBJECT(button), "verb");
    const char *argspec = g_object_get_data(G_OBJECT(button), "args");
    GtkWidget *status = g_object_get_data(G_OBJECT(button), "status");
    gboolean privileged =
        GPOINTER_TO_INT(g_object_get_data(G_OBJECT(button), "privileged"));
    g_autofree char *script = NULL;
    g_autofree char *cap = NULL;
    g_autofree char *label = NULL;
    /* Function scope on purpose: argv holds pointers INTO these strings, so
       they must outlive imsisting_action_run() below. Declared inside the
       'if' they were freed the moment that block closed, and argv pointed at
       released memory - which usually still held the text, so it went
       unnoticed until something allocated in between (the label build) and
       reused the block. The verb then ran with a clobbered argument. */
    g_auto(GStrv) parts = NULL;
    const char *argv[12];
    int n = 0;

    if (module_id == NULL || verb == NULL)
        return;

    script = module_script_path(module_id);
    if (!g_file_test(script, G_FILE_TEST_EXISTS)) {
        g_autofree char *m = g_strdup_printf(
            "module %s is not present at %s", module_id, script);
        append_event(state, m);
        show_toast_full(state, verb, m, "error");
        return;
    }

    argv[n++] = script;
    argv[n++] = verb;

    if (argspec != NULL && *argspec != '\0') {
        parts = g_strsplit_set(argspec, " \t", -1);
        for (int i = 0; parts[i] != NULL && n < 11; i++) {
            if (*parts[i] == '\0')
                continue;
            if (g_strcmp0(parts[i], "{capture}") == 0) {
                cap = newest_capture();
                if (cap == NULL) {
                    show_toast_full(state, verb,
                        "no capture found in captures/", "error");
                    return;
                }
                argv[n++] = cap;
            } else {
                argv[n++] = parts[i];
            }
        }
    }
    argv[n] = NULL;

    /* Show the arguments too. The output card echoes this label, so without
       them a run that used the wrong value - or none - looks identical to one
       that used the right one. */
    label = (argspec != NULL && *argspec != '\0')
        ? g_strdup_printf("%s %s %s", module_id, verb, argspec)
        : g_strdup_printf("%s %s", module_id, verb);
    imsisting_action_run(state, module_id, label, status, argv, privileged);
    (void) user_data;
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

/* Turn a verb into a label when the layout does not give one:
   --decode-sib becomes "Decode SIB". */
static char *
verb_label(const char *verb)
{
    static const char *const acronyms[] = {
        "sib","mib","sib1","sib6","sib19","nas","5gs","gtp","gtpu","gtpc",
        "ngap","pfcp","s1ap","ss7","map","tcap","msu","ati","sri","sm",
        "imsi","suci","supi","msin","impi","apdu","ota","ussd","mmi","sba",
        "nrf","jwt","h2","oran","e2","e2sm","a1","ntn","gprs","gea","pdp",
        "apn","tetra","dmr","gsmr","tea","tdma","lpp","pids","ta","csi","rf",
        "cve","nr","lte","gsm","umts","vowifi","ike","eap","nai","epdg",
        "tr069","sst","snssai","nssai","prach","ssb","pci","arfcn","earfcn",
        "nprach","npss","nss","kc","a5","csg","iuh","lcid","dci","mac","rnti",
        "ra","pfi","sci1a","l2id","its","stk","sat","sim","spi","ad","ef",
        "tmsi","guti","pco","po","lwa","ip","id","api","xml","csv","tsv",
        "kml","pcap","ue","enb","gnb","c1","c0","esim","usim","aka","kseaf",
        "grx","stp","ssn","pc","plmn","eplmn","simjacker","henb","5g","4g",
        "2g","3g","s1","ng","x2",
    };
    g_autofree char *work = g_strdup(verb);
    char *s = work;
    while (*s == '-') s++;
    g_auto(GStrv) parts = g_strsplit(s, "-", -1);
    GString *out = g_string_new(NULL);

    for (int i = 0; parts[i] != NULL; i++) {
        const char *p = parts[i];
        gboolean up = FALSE;
        if (*p == '\0') continue;
        for (guint a = 0; a < G_N_ELEMENTS(acronyms); a++)
            if (g_ascii_strcasecmp(p, acronyms[a]) == 0) { up = TRUE; break; }
        if (out->len > 0) g_string_append_c(out, ' ');
        if (up) {
            g_autofree char *U = g_ascii_strup(p, -1);
            g_string_append(out, U);
        } else {
            g_autofree char *T = g_ascii_strdown(p, -1);
            if (T[0] != '\0') T[0] = g_ascii_toupper(T[0]);
            g_string_append(out, T);
        }
    }
    return g_string_free(out, FALSE);
}

/* ── verbs that need a typed argument ───────────────────────────────────
   A '~' verb cannot be defaulted, so it cannot be a plain button. Leaving it
   out of the GUI entirely - which is what used to happen - makes the action
   unreachable: six modules declared one and the operator had no way to run
   any of them. wifisting puts an entry next to the button for the same case
   (its WPA3 RECON "capture.pcap or wlan0" field), so this does that. */

static void
group_arg_clicked(GtkButton *button, gpointer user_data)
{
    GtkWidget *entry = g_object_get_data(G_OBJECT(button), "arg-entry");
    const char *text = entry != NULL
        ? gtk_editable_get_text(GTK_EDITABLE(entry)) : "";
    AppState *state = g_object_get_data(G_OBJECT(button), "state");

    (void) user_data;

    if (text == NULL || *text == '\0') {
        const char *verb = g_object_get_data(G_OBJECT(button), "verb");
        show_toast_full(state, verb != NULL ? verb : "argument",
                        "type a value first", "error");
        return;
    }

    /* group_verb_clicked already knows how to turn verb + args into a process,
       so hand it what was typed rather than duplicating that here. */
    g_object_set_data_full(G_OBJECT(button), "args", g_strdup(text), g_free);
    group_verb_clicked(button, user_data);
}

/* One entry + Run pair for a single '~' verb, in the same grammar as a
   button: verb [!] [:label]. */
static void
group_arg_row(AppState *state, const char *module_id, const char *spec,
              GtkWidget *status, GtkWidget *body)
{
    g_autofree char *item = g_strdup(spec);
    g_autofree char *verb = NULL;
    g_autofree char *auto_lab = NULL;
    const char *label = NULL;
    gboolean privileged = FALSE;
    char *colon;
    char *eq;
    char *bang;
    GtkWidget *row;
    GtkWidget *entry;
    GtkWidget *btn;

    if (item == NULL) return;

    colon = strchr(item, ':');
    if (colon != NULL) { *colon = '\0'; label = colon + 1; }
    eq = strchr(item, '=');
    if (eq != NULL) *eq = '\0';          /* any declared default is unused */
    bang = strchr(item, '!');
    if (bang != NULL) { privileged = TRUE; *bang = '\0'; }

    verb = g_strdup(item);
    g_strstrip(verb);
    if (*verb == '\0') return;

    auto_lab = verb_label(verb);
    if (label == NULL || *label == '\0') label = auto_lab;

    row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    entry = gtk_entry_new();
    btn = gtk_button_new_with_label(label);

    /* The placeholder names the verb the field feeds, so an empty form still
       says what it is for. */
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry), verb);
    gtk_widget_set_hexpand(entry, TRUE);
    gtk_widget_add_css_class(entry, "verb-arg-entry");
    gtk_widget_add_css_class(btn, "verb-button");

    g_object_set_data(G_OBJECT(btn), "state", state);
    g_object_set_data(G_OBJECT(btn), "module-id", (gpointer) module_id);
    g_object_set_data(G_OBJECT(btn), "status", status);
    g_object_set_data(G_OBJECT(btn), "privileged", GINT_TO_POINTER(privileged));
    g_object_set_data_full(G_OBJECT(btn), "verb", g_strdup(verb), g_free);
    g_object_set_data(G_OBJECT(btn), "arg-entry", entry);

    g_signal_connect(btn, "clicked", G_CALLBACK(group_arg_clicked), NULL);
    /* Enter runs it: a one-field form should submit on Enter. */
    g_signal_connect(entry, "activate", G_CALLBACK(group_arg_clicked), NULL);

    gtk_box_append(GTK_BOX(row), entry);
    gtk_box_append(GTK_BOX(row), btn);
    gtk_box_append(GTK_BOX(body), row);
}

/* Fill a card body with one button per verb in the spec, in one click. A verb
   prefixed with '~' needs an argument and gets an entry of its own. */
static gboolean
spec_has_buttons(const char *spec)
{
    g_auto(GStrv) items = NULL;
    if (spec == NULL) return FALSE;
    items = g_strsplit(spec, "|", -1);
    /* A '~' verb counts as content: it renders as an entry + Run instead of
       being skipped, so a card holding only one is not empty. Treating it as
       empty hid such cards, and any entry made only of them, entirely. */
    for (int i = 0; items[i] != NULL; i++)
        if (items[i][0] != '\0')
            return TRUE;
    return FALSE;
}

static void
group_fill(AppState *state, const char *module_id, const char *spec,
           GtkWidget *status, GtkWidget *body, gboolean primary_first)
{
    GtkWidget *flow = gtk_flow_box_new();
    gboolean primary_done = FALSE;
    /* '~' verbs collected during the pass, built after the flow so they sit
       under the buttons rather than above them. */
    GPtrArray *arg_specs = g_ptr_array_new_with_free_func(g_free);

    gtk_flow_box_set_selection_mode(GTK_FLOW_BOX(flow), GTK_SELECTION_NONE);
    gtk_flow_box_set_column_spacing(GTK_FLOW_BOX(flow), 8);
    gtk_flow_box_set_row_spacing(GTK_FLOW_BOX(flow), 8);
    gtk_flow_box_set_max_children_per_line(GTK_FLOW_BOX(flow), 4);

    if (spec != NULL) {
        g_auto(GStrv) items = g_strsplit(spec, "|", -1);
        for (int i = 0; items[i] != NULL; i++) {
            g_autofree char *item = NULL;
            g_autofree char *verb = NULL;
            g_autofree char *def = NULL;
            g_autofree char *auto_lab = NULL;
            const char *label = NULL;
            const char *lab_ptr = NULL;
            gboolean privileged = FALSE;
            GtkWidget *btn;
            GtkWidget *child;
            char *colon;
            char *eq;
            char *bang;

            if (*items[i] == '\0') continue;
            /* A leading '~' marks a verb whose value cannot be defaulted
               safely. It gets an entry of its own after the buttons, rather
               than being dropped from the GUI entirely. */
            if (*items[i] == '~') {
                g_ptr_array_add(arg_specs, g_strdup(items[i] + 1));
                continue;
            }

            /* Entry grammar: verb [!] [=default] [:label]. The default may
               hold several space-separated arguments. */
            item = g_strdup(items[i]);
            colon = strchr(item, ':');
            if (colon != NULL) { *colon = '\0'; lab_ptr = colon + 1; }
            eq = strchr(item, '=');
            if (eq != NULL) { *eq = '\0'; def = g_strdup(eq + 1); }
            bang = strchr(item, '!');
            if (bang != NULL) { privileged = TRUE; *bang = '\0'; }

            verb = g_strdup(item);
            g_strstrip(verb);
            auto_lab = verb_label(verb);
            label = (lab_ptr != NULL && *lab_ptr != '\0') ? lab_ptr : auto_lab;

            btn = gtk_button_new_with_label(label);
            gtk_widget_add_css_class(btn, "verb-button");
            if (primary_first && !primary_done) {
                gtk_widget_add_css_class(btn, "primary");
                primary_done = TRUE;
            }
            gtk_widget_set_tooltip_text(btn, verb);
            g_object_set_data(G_OBJECT(btn), "state", state);
            g_object_set_data(G_OBJECT(btn), "module-id", (gpointer) module_id);
            g_object_set_data(G_OBJECT(btn), "status", status);
            g_object_set_data(G_OBJECT(btn), "privileged",
                              GINT_TO_POINTER(privileged));
            g_object_set_data_full(G_OBJECT(btn), "verb", g_strdup(verb), g_free);
            if (def != NULL)
                g_object_set_data_full(G_OBJECT(btn), "args",
                                       g_strdup(def), g_free);
            g_signal_connect(btn, "clicked",
                             G_CALLBACK(group_verb_clicked), NULL);

            child = gtk_flow_box_child_new();
            gtk_flow_box_child_set_child(GTK_FLOW_BOX_CHILD(child), btn);
            gtk_flow_box_append(GTK_FLOW_BOX(flow), child);
        }
    }

    gtk_box_append(GTK_BOX(body), flow);

    /* The verbs that needed an argument, each with its own entry. */
    for (guint i = 0; i < arg_specs->len; i++)
        group_arg_row(state, module_id, g_ptr_array_index(arg_specs, i),
                      status, body);
    g_ptr_array_unref(arg_specs);
}

/* Build a group as one or more titled cards.
 *
 * A spec may name sections with a leading '#':
 *     "#CONTROLS|--scan:Start scan|--stop:Stop scan|#SURVEY|--list:List Cells"
 * Each section becomes its own card, which is how wifisting's module pages
 * read: a card per job - controls, then status, then results - rather than
 * one undifferentiated row of buttons. Modules differ in how many jobs they
 * have, so that belongs in the data, not in per-module C.
 *
 * A spec with no '#' keeps the old shape exactly: a single card titled with
 * the group's own name, which is already the submenu entry's name. */
static GtkWidget *
build_group_cards(AppState *state, const char *module_id, const char *title,
                  const char *spec, GtkWidget *status, gboolean primary_first)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    g_auto(GStrv) sections = g_strsplit(spec != NULL ? spec : "", "#", -1);
    gboolean any = FALSE;

    for (int s = 0; sections[s] != NULL; s++) {
        const char *text = sections[s];
        const char *heading = title;
        g_autofree char *named = NULL;

        if (s == 0) {
            /* Anything before the first '#': the group's own card. Usually
               empty for a sectioned spec, so it is skipped. */
            if (!spec_has_buttons(text)) continue;
        } else {
            /* "#Name|items" - the name runs up to the first '|'. */
            const char *bar = strchr(text, '|');
            if (bar == NULL) continue;
            named = g_strndup(text, (gsize)(bar - text));
            g_strstrip(named);
            if (*named != '\0') heading = named;
            text = bar + 1;
            if (!spec_has_buttons(text)) continue;
        }

        GtkWidget *body;
        GtkWidget *card = verb_card(heading, &body);
        group_fill(state, module_id, text, status, body,
                   primary_first && !any);
        gtk_box_append(GTK_BOX(box), card);
        any = TRUE;
    }

    return box;
}

static GtkWidget *
build_group_card(AppState *state, const char *module_id, const char *title,
                 const char *spec, GtkWidget *status, gboolean primary_first)
{
    GtkWidget *body;
    GtkWidget *card = verb_card(title, &body);
    group_fill(state, module_id, spec, status, body, primary_first);
    return card;
}

/* ---- module output card -------------------------------------------
   Every module view carries one of these under its buttons, so a run's
   stdout/stderr appears next to the control that started it instead of
   only in the app-wide Events drawer - which is off-screen on a short
   window and made working buttons look broken.
   One buffer per page is shared by the cards in each view, so switching
   views keeps the output visible. The card lives INSIDE the view's
   scrolled content: a strip appended to the page itself got squeezed to
   zero height, because a module page's content does not shrink. */
static GtkTextBuffer *
output_buffer_new(void)
{
    return gtk_text_buffer_new(NULL);
}

/* Append a line and keep every on-screen card for this buffer pinned to
   the bottom. One buffer feeds one card per view (Overview, Packages,
   System...); scrolling only the most recently built card left the card
   the operator was actually looking at frozen at the top, so fresh output
   sat below the fold and the button read as doing nothing. */
/* Pin the card to its newest line. */
static void
console_scroll_bottom(GtkWidget *list)
{
    GtkWidget *sw = gtk_widget_get_ancestor(list, GTK_TYPE_SCROLLED_WINDOW);
    GtkAdjustment *adj;

    if (sw == NULL) return;
    adj = gtk_scrolled_window_get_vadjustment(GTK_SCROLLED_WINDOW(sw));
    if (adj == NULL) return;
    gtk_adjustment_set_value(adj,
        gtk_adjustment_get_upper(adj) - gtk_adjustment_get_page_size(adj));
}

/* One line of output, as a row rather than a line of monospace text.
 *
 * The card used to be a GtkTextView in a monospace font, which made every
 * module look like it was dumping to a terminal - at odds with the rest of
 * the interface, where nothing else is monospace and nothing else is a black
 * box. Severity is carried by a coloured marker and the message is set in
 * the interface font, so a run reads as activity rather than as a console.
 *
 * The one thing that stays monospace is the command echo, because that IS a
 * command line and should look like one. */
static void
console_row_append(GtkWidget *list, const char *text)
{
    const char *cls = "log-note";
    const char *marker = "\u25cf";     /* a dot, as in the status strip */
    const char *body = text;
    GtkWidget *row, *glyph, *msg;

    if (text == NULL || *text == '\0') return;

    if (g_str_has_prefix(text, "$ ")) {
        cls = "log-cmd"; marker = "$"; body = text + 2;
    } else if (g_str_has_prefix(text, "ERROR")) {
        cls = "log-error"; body = text + 5;
    } else if (g_str_has_prefix(text, "[err]")) {
        cls = "log-error"; body = text + 5;
    } else if (g_str_has_prefix(text, "[warn]")) {
        cls = "log-warn"; body = text + 6;
    } else if (g_str_has_prefix(text, "[ok]")) {
        cls = "log-ok"; body = text + 4;
    } else if (g_str_has_prefix(text, "[info]")) {
        cls = "log-info"; body = text + 6;
    } else if (g_str_has_prefix(text, "-- failed")) {
        cls = "log-error";
    } else if (g_str_has_prefix(text, "-- done")) {
        cls = "log-ok";
    }
    while (*body == ' ' || *body == '\t') body++;

    row   = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    glyph = gtk_label_new(marker);
    msg   = gtk_label_new(body);

    gtk_widget_add_css_class(row, "log-row");
    gtk_widget_add_css_class(row, cls);
    gtk_widget_add_css_class(glyph, "log-glyph");
    gtk_widget_add_css_class(msg, "log-msg");

    gtk_label_set_xalign(GTK_LABEL(glyph), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(msg), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(msg), TRUE);
    gtk_label_set_wrap_mode(GTK_LABEL(msg), PANGO_WRAP_WORD_CHAR);
    gtk_label_set_selectable(GTK_LABEL(msg), TRUE);
    gtk_widget_set_valign(glyph, GTK_ALIGN_START);
    gtk_widget_set_size_request(glyph, 14, -1);
    gtk_widget_set_hexpand(msg, TRUE);

    gtk_box_append(GTK_BOX(row), glyph);
    gtk_box_append(GTK_BOX(row), msg);
    gtk_box_append(GTK_BOX(list), row);
}

static void
console_append(GtkTextBuffer *buf, const char *text)
{
    GtkTextIter end;
    GPtrArray *views;
    g_auto(GStrv) lines = NULL;

    if (buf == NULL || text == NULL) return;

    /* The buffer stays the handle every caller already passes around, and
       still accumulates the text, but the cards render rows built here. */
    gtk_text_buffer_get_end_iter(buf, &end);
    gtk_text_buffer_insert(buf, &end, text, -1);
    gtk_text_buffer_insert(buf, &end, "\n", -1);

    views = g_object_get_data(G_OBJECT(buf), "output-views");
    if (views == NULL) return;

    lines = g_strsplit(text, "\n", -1);
    for (guint i = 0; i < views->len; i++) {
        GtkWidget *list = g_ptr_array_index(views, i);
        if (list == NULL) continue;
        for (guint j = 0; lines[j] != NULL; j++) {
            if (*lines[j] == '\0') continue;
            console_row_append(list, lines[j]);
        }
        /* Append whether or not the page is on screen - the text has to be
           there when it is shown - but only scroll what is visible. */
        if (gtk_widget_get_mapped(list))
            console_scroll_bottom(list);
    }
}

static void
console_clear_clicked(GtkButton *button, gpointer user_data)
{
    GPtrArray *views;

    (void) button;
    if (user_data == NULL) return;
    gtk_text_buffer_set_text(GTK_TEXT_BUFFER(user_data), "", -1);

    views = g_object_get_data(G_OBJECT(user_data), "output-views");
    if (views == NULL) return;
    for (guint i = 0; i < views->len; i++) {
        GtkWidget *list = g_ptr_array_index(views, i);
        GtkWidget *child;
        if (list == NULL) continue;
        child = gtk_widget_get_first_child(list);
        while (child != NULL) {
            GtkWidget *next = gtk_widget_get_next_sibling(child);
            gtk_box_remove(GTK_BOX(list), child);
            child = next;
        }
    }
}

static void
console_view_destroyed(GtkWidget *view, gpointer buf)
{
    GPtrArray *views;
    if (buf == NULL) return;
    views = g_object_get_data(G_OBJECT(buf), "output-views");
    if (views != NULL)
        g_ptr_array_remove(views, view);
}

static GtkWidget *
build_output_card(GtkTextBuffer *buf)
{
    GtkWidget *card   = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *head   = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *title  = gtk_label_new("OUTPUT");
    GtkWidget *clear  = gtk_button_new_with_label("Clear");
    GtkWidget *scroll = gtk_scrolled_window_new();
    GtkWidget *view   = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);

    gtk_widget_add_css_class(card,  "output-card");
    gtk_widget_add_css_class(head,  "output-card-head");
    gtk_widget_add_css_class(title, "output-card-title");
    gtk_widget_add_css_class(clear, "flat");
    gtk_widget_add_css_class(view,  "output-log");

    gtk_widget_set_halign(title, GTK_ALIGN_START);
    gtk_widget_set_hexpand(title, TRUE);
    gtk_box_append(GTK_BOX(head), title);
    gtk_box_append(GTK_BOX(head), clear);

    gtk_widget_set_margin_top(view, 8);
    gtk_widget_set_margin_bottom(view, 8);
    gtk_widget_set_margin_start(view, 10);
    gtk_widget_set_margin_end(view, 10);
    gtk_widget_set_valign(view, GTK_ALIGN_START);
    gtk_widget_set_size_request(scroll, -1, 150);

    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), view);

    gtk_box_append(GTK_BOX(card), head);
    gtk_box_append(GTK_BOX(card), scroll);

    g_object_set_data(G_OBJECT(buf), "output-view", view);
    {
        GPtrArray *views = g_object_get_data(G_OBJECT(buf), "output-views");
        if (views == NULL) {
            views = g_ptr_array_new();
            g_object_set_data_full(G_OBJECT(buf), "output-views", views,
                                   (GDestroyNotify) g_ptr_array_unref);
        }
        g_ptr_array_add(views, view);
    }
    g_signal_connect(view, "destroy",
                     G_CALLBACK(console_view_destroyed), buf);
    g_signal_connect(clear, "clicked",
                     G_CALLBACK(console_clear_clicked), buf);
    return card;
}

static GtkWidget *
build_group_view(AppState *state, const char *module_id, const char *title,
                 const char *spec, GtkWidget *status, GtkTextBuffer *out)
{
    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *inner = gtk_box_new(GTK_ORIENTATION_VERTICAL, 14);

    gtk_widget_set_margin_top(inner, 16);
    gtk_widget_set_margin_bottom(inner, 16);
    gtk_widget_set_margin_start(inner, 16);
    gtk_widget_set_margin_end(inner, 16);
    gtk_widget_set_hexpand(inner, TRUE);
    gtk_box_append(GTK_BOX(inner),
        build_group_cards(state, module_id, title, spec, status, FALSE));
    if (out != NULL)
        gtk_box_append(GTK_BOX(inner), build_output_card(out));
    gtk_box_append(GTK_BOX(outer), inner);
    return outer;
}

/* A module with no registered entries still gets a page that lists what the
   shell side can do, so nothing is invisible. */
static GtkWidget *
create_placeholder_page(AppState *state, const ModuleDefinition *module)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    GtkWidget *title = gtk_label_new(module->name);
    GtkWidget *id = gtk_label_new(module->id);
    GtkWidget *note = gtk_label_new(NULL);
    GtkWidget *desc = gtk_label_new(module->desc ? module->desc : "");
    GtkWidget *status = gtk_label_new("Idle");
    GtkWidget *flow = gtk_flow_box_new();

    gtk_widget_set_margin_top(box, 16);
    gtk_widget_set_margin_start(box, 16);
    gtk_widget_set_margin_end(box, 16);
    gtk_widget_set_margin_bottom(box, 16);
    gtk_widget_add_css_class(title, "module-header-title");
    gtk_widget_set_halign(title, GTK_ALIGN_START);
    gtk_widget_add_css_class(id, "mono");
    gtk_widget_add_css_class(id, "dim");
    gtk_widget_set_halign(id, GTK_ALIGN_START);
    gtk_label_set_wrap(GTK_LABEL(note), TRUE);
    gtk_label_set_xalign(GTK_LABEL(note), 0.0f);
    gtk_widget_add_css_class(note, "dim");
    gtk_label_set_markup(GTK_LABEL(note),
        "This module has no registered GUI view. Its verbs are listed below.");
    gtk_widget_add_css_class(desc, "module-header-desc");
    gtk_label_set_xalign(GTK_LABEL(desc), 0.5f);
    gtk_label_set_justify(GTK_LABEL(desc), GTK_JUSTIFY_CENTER);
    gtk_label_set_wrap(GTK_LABEL(desc), TRUE);
    gtk_widget_add_css_class(status, "status-pill");
    gtk_widget_add_css_class(status, "status-idle");
    gtk_widget_set_halign(status, GTK_ALIGN_START);
    gtk_flow_box_set_selection_mode(GTK_FLOW_BOX(flow), GTK_SELECTION_NONE);
    gtk_flow_box_set_column_spacing(GTK_FLOW_BOX(flow), 6);
    gtk_flow_box_set_row_spacing(GTK_FLOW_BOX(flow), 6);

    for (int i = 0; i < MODULE_INDEX_N; i++) {
        if (g_strcmp0(module_index[i].id, module->id) != 0) continue;
        g_auto(GStrv) words = g_strsplit_set(module_index[i].verbs, " \t\n", -1);
        for (int wi = 0; words[wi] != NULL; wi++) {
            const char *v = words[wi];
            GtkWidget *btn;
            GtkWidget *child;
            if (!g_str_has_prefix(v, "--")) continue;
            if (g_strcmp0(v, "--menu") == 0 || g_strcmp0(v, "--selftest") == 0 ||
                g_strcmp0(v, "--status-tsv") == 0)
                continue;
            btn = gtk_button_new_with_label(v);
            gtk_widget_add_css_class(btn, "verb-button");
            gtk_widget_set_tooltip_text(btn, v);
            g_object_set_data(G_OBJECT(btn), "state", state);
            g_object_set_data(G_OBJECT(btn), "module-id", (gpointer) module->id);
            g_object_set_data(G_OBJECT(btn), "status", status);
            g_object_set_data_full(G_OBJECT(btn), "verb", g_strdup(v), g_free);
            g_signal_connect(btn, "clicked",
                G_CALLBACK(verb_button_dyn_clicked), NULL);
            child = gtk_flow_box_child_new();
            gtk_flow_box_child_set_child(GTK_FLOW_BOX_CHILD(child), btn);
            gtk_flow_box_append(GTK_FLOW_BOX(flow), child);
        }
        break;
    }

    gtk_box_append(GTK_BOX(box), title);
    gtk_box_append(GTK_BOX(box), desc);
    gtk_box_append(GTK_BOX(box), id);
    gtk_box_append(GTK_BOX(box), note);
    gtk_box_append(GTK_BOX(box), status);
    gtk_box_append(GTK_BOX(box), flow);
    {
        GtkTextBuffer *out = output_buffer_new();
        gtk_box_append(GTK_BOX(box), build_output_card(out));
        g_object_set_data(G_OBJECT(box), "output-buffer", out);
    }
    return box;
}

static void
module_page_submenu_row_activated(GtkListBox *list, GtkListBoxRow *row,
                                  gpointer user_data)
{
    ModulePage *mp = user_data;
    int index = gtk_list_box_row_get_index(row);
    if (index >= 0 && index < mp->n_views) {
        gtk_stack_set_visible_child_name(GTK_STACK(mp->stack),
                                         mp->views[index].name);
        gtk_list_box_select_row(list, row);

        /* Output goes to the submenu on screen. The page's record is kept in
           step so switching tabs away and back retargets correctly. */
        if (mp->state != NULL) {
            GtkTextBuffer *vb = g_object_get_data(
                G_OBJECT(mp->views[index].page), "output-buffer");
            if (vb != NULL) {
                mp->state->active_output = vb;
                if (mp->page != NULL)
                    g_object_set_data(G_OBJECT(mp->page), "output-buffer", vb);
            }
        }
    }
}

static GtkWidget *
module_page_build_submenu(ModulePage *mp)
{
    GtkWidget *list = gtk_list_box_new();
    GtkWidget *col = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *scrolled = gtk_scrolled_window_new();
    GtkWidget *hdr = gtk_label_new("VIEWS");

    gtk_widget_add_css_class(list, "module-menu");
    gtk_widget_add_css_class(col, "module-menu");
    gtk_widget_add_css_class(col, category_class(mp->module->category));
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(list), GTK_SELECTION_SINGLE);
    gtk_list_box_set_activate_on_single_click(GTK_LIST_BOX(list), TRUE);

    for (int i = 0; i < mp->n_views; i++) {
        GtkWidget *row = gtk_list_box_row_new();
        GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
        GtkWidget *icon = gtk_image_new_from_icon_name(mp->views[i].icon);
        GtkWidget *label = gtk_label_new(mp->views[i].name);
        gtk_widget_add_css_class(row, "module-menu-row");
        gtk_image_set_pixel_size(GTK_IMAGE(icon), 20);
        gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
        gtk_widget_set_hexpand(label, TRUE);
        gtk_box_append(GTK_BOX(box), icon);
        gtk_box_append(GTK_BOX(box), label);
        gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), box);
        gtk_list_box_append(GTK_LIST_BOX(list), row);
    }

    g_signal_connect(list, "row-activated",
                     G_CALLBACK(module_page_submenu_row_activated), mp);

    if (mp->n_views > 0)
        gtk_list_box_select_row(GTK_LIST_BOX(list),
            gtk_list_box_get_row_at_index(GTK_LIST_BOX(list), 0));

    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), list);
    gtk_widget_set_size_request(scrolled, 250, -1);
    gtk_widget_set_vexpand(scrolled, TRUE);

    /* A heading over the menu, so the column reads as navigation. */
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

/* A key/value line for the Overview card. */
static GtkWidget *
overview_row(const char *key, const char *value)
{
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *k = gtk_label_new(key);
    GtkWidget *v = gtk_label_new(value != NULL ? value : "");
    gtk_widget_add_css_class(k, "overview-key");
    gtk_widget_add_css_class(v, "overview-value");
    gtk_label_set_xalign(GTK_LABEL(k), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(v), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(v), TRUE);
    gtk_label_set_selectable(GTK_LABEL(v), TRUE);
    gtk_widget_set_size_request(k, 110, -1);
    gtk_widget_set_hexpand(v, TRUE);
    gtk_box_append(GTK_BOX(row), k);
    gtk_box_append(GTK_BOX(row), v);
    return row;
}

static GtkWidget *
workflow_step(const char *number, const char *title, const char *detail)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *n = gtk_label_new(number);
    GtkWidget *t = gtk_label_new(title);
    GtkWidget *d = gtk_label_new(detail);
    gtk_widget_add_css_class(box, "workflow-step");
    gtk_widget_add_css_class(n, "workflow-number");
    gtk_widget_add_css_class(t, "workflow-title");
    gtk_widget_add_css_class(d, "workflow-detail");
    gtk_label_set_xalign(GTK_LABEL(n), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(t), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(d), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(d), TRUE);
    return box;
}

/* The Overview view: what this module is (ABOUT) and the handful of actions
   that make sense to reach immediately (QUICK ACTIONS). */
static GtkWidget *
build_overview_view(AppState *state, const ModuleDefinition *module,
                    const char *quick_spec, GtkWidget *status,
                    GtkTextBuffer *out)
{
    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *inner = gtk_box_new(GTK_ORIENTATION_VERTICAL, 14);
    const ModuleIndexEntry *idx = NULL;

    gtk_widget_set_margin_top(inner, 16);
    gtk_widget_set_margin_bottom(inner, 16);
    gtk_widget_set_margin_start(inner, 16);
    gtk_widget_set_margin_end(inner, 16);
    gtk_widget_set_hexpand(inner, TRUE);

    {
        GtkWidget *flow = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
        gtk_widget_add_css_class(flow, "workflow-ribbon");
        gtk_box_set_homogeneous(GTK_BOX(flow), TRUE);
        gtk_box_append(GTK_BOX(flow), workflow_step("01", "CONTEXT",
            "Review the target and module scope."));
        gtk_box_append(GTK_BOX(flow), workflow_step("02", "RUN",
            "Choose a focused action below."));
        gtk_box_append(GTK_BOX(flow), workflow_step("03", "REVIEW",
            "Read the result in Events and preserve evidence."));
        gtk_box_append(GTK_BOX(inner), flow);
    }

    for (int i = 0; i < MODULE_INDEX_N; i++)
        if (g_strcmp0(module_index[i].id, module->id) == 0) {
            idx = &module_index[i];
            break;
        }

    /* 01 · CONTEXT — what this module is and what it can do. */
    {
        GtkWidget *body;
        GtkWidget *card = verb_card("01 · CONTEXT", &body);
        gtk_box_append(GTK_BOX(body), overview_row("Id", module->id));
        gtk_box_append(GTK_BOX(body), overview_row("Category", module->category));
        if (module->desc != NULL && *module->desc != '\0')
            gtk_box_append(GTK_BOX(body), overview_row("Summary", module->desc));
        if (idx != NULL) {
            int nv = 0;
            g_auto(GStrv) words = g_strsplit_set(idx->verbs, " \t\n", -1);
            g_autofree char *nvs = NULL;
            for (int w = 0; words[w] != NULL; w++)
                if (g_str_has_prefix(words[w], "--"))
                    nv++;
            nvs = g_strdup_printf("%d", nv);
            gtk_box_append(GTK_BOX(body), overview_row("Verbs", nvs));
            if (idx->info != NULL && *idx->info != '\0')
                gtk_box_append(GTK_BOX(body), overview_row("Notes", idx->info));
        }
        gtk_box_append(GTK_BOX(inner), card);
    }

    /* 02 · RUN — the primary action leads; the rest sit beside it. */
    if (spec_has_buttons(quick_spec))
        gtk_box_append(GTK_BOX(inner),
            build_group_card(state, module->id, "02 · RUN NOW",
                             quick_spec, status, TRUE));

    /* 03 · EVIDENCE — where the output goes and how it is preserved. */
    {
        GtkWidget *body;
        GtkWidget *card = verb_card("03 · EVIDENCE", &body);
        GtkWidget *note = gtk_label_new(
            "Every run is logged in the Events drawer and, when a case is "
            "open, appended to its timeline. Index captures under Casebook > "
            "Captures to preserve them as evidence.");
        gtk_widget_add_css_class(note, "card-note");
        gtk_label_set_wrap(GTK_LABEL(note), TRUE);
        gtk_label_set_xalign(GTK_LABEL(note), 0.0f);
        gtk_box_append(GTK_BOX(body), note);
        gtk_box_append(GTK_BOX(inner), card);
    }

    if (out != NULL)
        gtk_box_append(GTK_BOX(inner), build_output_card(out));

    gtk_box_append(GTK_BOX(outer), inner);
    return outer;
}

static GtkWidget *
create_module_page(AppState *state, const ModuleDefinition *module,
                   ModuleSubmenuEntry *entries, int n_entries,
                   gpointer module_data)
{
    ModulePage *mp = g_new0(ModulePage, 1);
    mp->state = state;
    mp->module = module;
    mp->module_data = module_data;

    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_add_css_class(outer, "module-page");
    gtk_widget_set_vexpand(outer, TRUE);

    /* Header: icon, name, category, status pill, then the module's one-line
       description beneath them. */
    GtkWidget *header = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *hrow   = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *hicon = gtk_image_new_from_icon_name(module_icon_for(module->id));
    gtk_image_set_pixel_size(GTK_IMAGE(hicon), 34);
    GtkWidget *htitle = gtk_label_new(module_name_for(module->id));
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

    gtk_widget_set_hexpand(htitle, TRUE);
    gtk_label_set_ellipsize(GTK_LABEL(htitle), PANGO_ELLIPSIZE_END);
    gtk_label_set_xalign(GTK_LABEL(hdesc), 0.5f);
    gtk_label_set_justify(GTK_LABEL(hdesc), GTK_JUSTIFY_CENTER);
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
    /* One output buffer for the whole page; every view's card shows it, so
       a result stays on screen when the operator switches views. */
    GtkTextBuffer *out = output_buffer_new();
    gtk_stack_set_transition_type(GTK_STACK(stack),
                                  GTK_STACK_TRANSITION_TYPE_CROSSFADE);
    /* Not homogeneous: a GtkStack defaults to sizing itself to its LARGEST
       child, so one tall view (a long Packages or System list) set the
       minimum height of the whole page. That minimum was bigger than the
       window, which squeezed the output console at the bottom of the page
       down to nothing. Only the visible view should claim height. */
    gtk_stack_set_vhomogeneous(GTK_STACK(stack), FALSE);
    gtk_stack_set_hhomogeneous(GTK_STACK(stack), FALSE);
    mp->stack = stack;

    /* Every registered entry becomes its own view, named and grouped by the
       module itself - Overview, Packages, Decode, Headers, Export. Entry 0
       used to be forced through a generic "01 CONTEXT / 02 RUN NOW / 03
       EVIDENCE" template, which made every module in the toolkit render as
       the same page whatever that module actually needed. The module's own
       grouping is the part that has a reason behind it, so it drives the
       layout instead of being poured into a fixed shell. */
    mp->views = g_new0(ModuleView, n_entries > 0 ? n_entries : 1);
    {
        int k = 0;
        for (int i = 0; i < n_entries; i++) {
            /* A custom view brings its own content, so it is never skipped
               for having no buttons in its spec. */
            if (entries[i].build == NULL &&
                !spec_has_buttons(entries[i].spec))
                continue;
            /* One buffer per VIEW, not one per page. A page-wide buffer
               meant the result of a run followed you into every other
               submenu: press Start scan in Overview, switch to Channel, and
               the scan's output was still sitting there. */
            GtkTextBuffer *vout = output_buffer_new();
            mp->views[k].name = entries[i].name;
            mp->views[k].icon = entries[i].icon;
            mp->views[k].page = entries[i].build != NULL
                ? entries[i].build(state, module->id, pill, vout)
                : build_group_view(state, module->id, entries[i].name,
                                   entries[i].spec, pill, vout);
            g_object_set_data_full(G_OBJECT(mp->views[k].page),
                                   "output-buffer", vout, g_object_unref);
            k++;
        }
        if (k == 0) {
            /* Nothing module-specific to draw: no registry entry, or every
               group needs typed arguments and so has no buttons. Only then
               fall back to the generated page. */
            mp->views[0].name = "Overview";
            mp->views[0].icon = "dialog-information-symbolic";
            {
                GtkTextBuffer *vout = output_buffer_new();
                mp->views[0].page = build_overview_view(state, module, NULL,
                                                        pill, vout);
                g_object_set_data_full(G_OBJECT(mp->views[0].page),
                                       "output-buffer", vout, g_object_unref);
            }
            k = 1;
        }
        mp->n_views = k;
    }

    for (int i = 0; i < mp->n_views; i++) {
        GtkWidget *view = mp->views[i].page;
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
        gtk_stack_add_named(GTK_STACK(stack), scrolled, mp->views[i].name);
    }

    if (mp->n_views > 0)
        gtk_stack_set_visible_child_name(GTK_STACK(stack), mp->views[0].name);

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
    /* notebook_page_switched() reads this to aim a run's output at the page
       on screen. The page owns the buffer through its text views. */
    g_object_set_data(G_OBJECT(outer), "output-buffer", out);

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
        gtk_image_set_pixel_size(GTK_IMAGE(icon), 32);
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

/* Pull KEY's value out of the first data row of a keyboard-style TSV whose
   first line is a header (e.g. casebook's target-current). */
static char *
tsv_row_field(const char *text, const char *key)
{
    g_auto(GStrv) head = NULL;
    g_auto(GStrv) row = NULL;
    int col = -1;
    if (text == NULL || key == NULL) return NULL;
    head = g_strsplit(text, "\n", -1);
    if (head[0] == NULL || head[1] == NULL) return NULL;
    g_auto(GStrv) cols = g_strsplit(head[0], "\t", -1);
    for (int i = 0; cols[i] != NULL; i++)
        if (g_strcmp0(cols[i], key) == 0) { col = i; break; }
    if (col < 0) return NULL;
    row = g_strsplit(head[1], "\t", -1);
    return (row[col] != NULL) ? g_strdup(row[col]) : NULL;
}

/* Same, but the last data row (the newest alert). */
static char *
tsv_last_field(const char *text, const char *key)
{
    g_auto(GStrv) lines = NULL;
    int col = -1, last;
    if (text == NULL || key == NULL) return NULL;
    lines = g_strsplit(text, "\n", -1);
    if (lines[0] == NULL) return NULL;
    for (last = 0; lines[last] != NULL; last++) ;
    /* drop a trailing empty line */
    while (last > 1 && lines[last - 1][0] == '\0') last--;
    if (last < 2) return NULL;
    g_auto(GStrv) cols = g_strsplit(lines[0], "\t", -1);
    for (int i = 0; cols[i] != NULL; i++)
        if (g_strcmp0(cols[i], key) == 0) { col = i; break; }
    if (col < 0) return NULL;
    g_auto(GStrv) row = g_strsplit(lines[last - 1], "\t", -1);
    return (row[col] != NULL) ? g_strdup(row[col]) : NULL;
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

    /* Every state the stylesheet can paint, or a cell can be left holding a
       stale one: status-running existed in CSS but was never cleared here,
       so it could not be used on the strip at all. */
    const char *classes[] = { "status-ok", "status-warn", "status-dim",
                              "status-running", "status-idle", NULL };
    GtkWidget *cell = gtk_widget_get_parent(label);
    for (int i = 0; classes[i] != NULL; i++) {
        gtk_widget_remove_css_class(label, classes[i]);
        if (cell != NULL)
            gtk_widget_remove_css_class(cell, classes[i]);
    }
    if (css != NULL) {
        gtk_widget_add_css_class(label, css);
        if (cell != NULL)
            gtk_widget_add_css_class(cell, css);
    }
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
                   present ? "status-ok" : "status-warn");

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
        /* gpsd up without a fix yet is working, not healthy - the strip has
           a running state and this is what it is for. */
        status_set(state->status_gps, gps,
                   (g_strcmp0(gps, "running") == 0) ? "status-running"
                                                    : "status-warn");
    } else {
        status_set(state->status_gps, NULL, "status-dim");
    }

    /* Case-scoped facts for the dashboard band: the case, and how much it
       holds. The strip already carries the radio, so the band does not. */
    if (state->dash_case != NULL) {
        gboolean cb_ok = FALSE;
        const char *cb_args[] = { "status", NULL };
        g_autofree char *cb = casebook_call(cb_args, &cb_ok);
        g_autofree char *act   = cb_ok ? tsv_field(cb, "active_case") : NULL;
        g_autofree char *tgt   = cb_ok ? tsv_field(cb, "targets") : NULL;
        g_autofree char *ev    = cb_ok ? tsv_field(cb, "evidence") : NULL;
        g_autofree char *al    = cb_ok ? tsv_field(cb, "alerts") : NULL;
        gboolean none = (act == NULL || *act == '\0' ||
                         g_strcmp0(act, "none") == 0);
        int nt = (tgt && *tgt) ? atoi(tgt) : 0;
        int ne = (ev && *ev) ? atoi(ev) : 0;
        int na = (al && *al) ? atoi(al) : 0;
        g_autofree char *st = g_strdup_printf("%d", nt);
        g_autofree char *se = g_strdup_printf("%d", ne);
        g_autofree char *sa = g_strdup_printf("%d", na);

        status_set(state->dash_case, none ? "not set" : act,
                   none ? "status-warn" : "status-ok");
        status_set(state->dash_targets, st, nt > 0 ? "status-ok" : "status-dim");
        status_set(state->dash_evidence, se, ne > 0 ? "status-ok" : "status-dim");
        status_set(state->dash_alerts, sa, na > 0 ? "status-warn" : "status-dim");
    }

    return G_SOURCE_CONTINUE;
}

static GtkWidget *
status_cell(const char *key, GtkWidget **value_out)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *head = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *dot = gtk_label_new("●");
    GtkWidget *k = gtk_label_new(key);
    GtkWidget *v = gtk_label_new("—");

    gtk_widget_add_css_class(box, "status-cell");
    gtk_widget_add_css_class(box, "status-dim");
    gtk_widget_add_css_class(head, "status-cell-head");
    gtk_widget_add_css_class(dot, "status-dot");
    gtk_widget_add_css_class(k, "status-key");
    gtk_widget_add_css_class(v, "status-value");
    gtk_widget_add_css_class(v, "status-dim");
    gtk_label_set_xalign(GTK_LABEL(k), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(v), 0.0f);

    gtk_box_append(GTK_BOX(head), dot);
    gtk_box_append(GTK_BOX(head), k);
    gtk_box_append(GTK_BOX(box), head);
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


static const ModuleDefinition *
dashboard_module(const char *id)
{
    for (int i = 0; i < N_MODULES; i++)
        if (g_strcmp0(modules[i].id, id) == 0)
            return &modules[i];
    return NULL;
}

static void
dashboard_tab_clicked(GtkButton *button, gpointer user_data)
{
    AppState *state = user_data;
    int tab = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(button), "dashboard-tab"));
    if (state != NULL && state->notebook != NULL)
        gtk_notebook_set_current_page(GTK_NOTEBOOK(state->notebook), tab);
}

static GtkWidget *
dashboard_shortcut(AppState *state, const char *eyebrow, const char *title,
                   const char *detail, const char *icon,
                   const ModuleDefinition *module, int tab)
{
    GtkWidget *button = gtk_button_new();
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GtkWidget *top = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *label = gtk_label_new(eyebrow);
    GtkWidget *image = gtk_image_new_from_icon_name(icon);
    GtkWidget *name = gtk_label_new(title);
    GtkWidget *note = gtk_label_new(detail);
    gtk_image_set_pixel_size(GTK_IMAGE(image), 28);
    gtk_widget_add_css_class(button, "mission-shortcut");
    gtk_widget_add_css_class(box, "mission-shortcut-inner");
    gtk_widget_add_css_class(label, "mission-shortcut-eyebrow");
    gtk_widget_add_css_class(name, "mission-shortcut-title");
    gtk_widget_add_css_class(note, "mission-shortcut-note");
    gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(name), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(note), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(note), TRUE);
    gtk_widget_set_hexpand(label, TRUE);
    gtk_box_append(GTK_BOX(top), label);
    gtk_box_append(GTK_BOX(top), image);
    gtk_box_append(GTK_BOX(box), top);
    gtk_box_append(GTK_BOX(box), name);
    gtk_box_append(GTK_BOX(box), note);
    gtk_button_set_child(GTK_BUTTON(button), box);
    if (module != NULL) {
        g_object_set_data(G_OBJECT(button), "module", (gpointer) module);
        g_signal_connect(button, "clicked", G_CALLBACK(module_card_clicked), state);
    } else {
        g_object_set_data(G_OBJECT(button), "dashboard-tab", GINT_TO_POINTER(tab));
        g_signal_connect(button, "clicked", G_CALLBACK(dashboard_tab_clicked), state);
    }
    return button;
}

/* Card cues and favourites. The grid helpers that use these live below. */
static void pin_toggled(GtkButton *button, gpointer user_data);
static AppState *g_dash_state = NULL;   /* set by dash_fill, read by dash_cmp */

static GtkWidget *
make_module_card(AppState *state, const ModuleDefinition *mod)
{
    GtkWidget *button = gtk_button_new();
    GtkWidget *card   = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    GtkWidget *top    = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    GtkWidget *cat    = gtk_label_new(mod->category);
    GtkWidget *icon   = gtk_image_new_from_icon_name(mod->icon);
    gboolean offline  = !module_script_exists(mod->id);
    gboolean pinned   = state->pins != NULL &&
                        g_hash_table_contains(state->pins, mod->id);
    gboolean recent   = state->recent != NULL &&
                        g_hash_table_contains(state->recent, mod->id);
    GtkWidget *chip   = gtk_label_new(
        offline ? "OFFLINE" : pinned ? "PINNED" : recent ? "RECENT" : "READY");
    gtk_image_set_pixel_size(GTK_IMAGE(icon), 64);
    gtk_widget_add_css_class(icon, category_class(mod->category));
    GtkWidget *name   = gtk_label_new(mod->name);
    GtkWidget *desc   = gtk_label_new(mod->desc ? mod->desc : "");
    GtkWidget *id     = gtk_label_new(mod->id);

    gtk_widget_add_css_class(button, "module-card");
    gtk_widget_add_css_class(card,   "module-card-inner");
    gtk_widget_add_css_class(card,   category_class(mod->category));
    gtk_widget_add_css_class(top,    "module-card-toprow");
    gtk_widget_add_css_class(cat,    "module-card-category");
    gtk_widget_add_css_class(chip,  "module-card-state");
    gtk_widget_add_css_class(chip, offline ? "module-card-offline" : "module-card-ready");
    if (!offline && pinned)
        gtk_widget_add_css_class(chip, "module-card-pinned");
    else if (!offline && recent)
        gtk_widget_add_css_class(chip, "module-card-recent");
    gtk_widget_add_css_class(cat,    category_class(mod->category));
    gtk_widget_add_css_class(icon,   "module-card-icon");
    gtk_widget_add_css_class(name,   "module-card-title");
    gtk_widget_add_css_class(desc,   "module-card-desc");
    gtk_widget_add_css_class(id,     "module-card-id");
    if (offline)
        gtk_widget_add_css_class(icon, "module-card-offline");

    gtk_widget_set_halign(icon, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(icon, GTK_ALIGN_CENTER);
    gtk_widget_set_vexpand(icon, TRUE);

    gtk_label_set_xalign(GTK_LABEL(cat), 0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(cat), PANGO_ELLIPSIZE_END);
    gtk_widget_set_hexpand(cat, TRUE);
    gtk_widget_set_margin_end(chip, 20);   /* clear the pin overlay */

    gtk_label_set_ellipsize(GTK_LABEL(name), PANGO_ELLIPSIZE_END);
    gtk_label_set_xalign(GTK_LABEL(name), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(desc), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(desc), TRUE);
    gtk_label_set_lines(GTK_LABEL(desc), 2);
    gtk_label_set_ellipsize(GTK_LABEL(desc), PANGO_ELLIPSIZE_END);
    gtk_label_set_xalign(GTK_LABEL(id), 0.0f);

    /* Bound each label's NATURAL width - it is what decides how many tiles
       a row holds. For the wrapping description the effective property is
       max_width_chars, not width_chars: a wrapping label reports the width
       of its whole unwrapped text as its natural width, and width_chars
       does not cap that. Left uncapped, one description asked for ~500px,
       the flow box could only fit one tile per row, and each row drew a
       single enormous card. The label still wraps, two lines, ellipsized;
       it just reports the width it will actually be drawn at. */
    gtk_label_set_width_chars(GTK_LABEL(name), 18);
    gtk_label_set_width_chars(GTK_LABEL(desc), 22);
    gtk_label_set_max_width_chars(GTK_LABEL(desc), 22);

    /* Tile size lives in style.css (button.module-card) so there is one
       place to change it; the old 218x188 request fought the stylesheet
       and produced a different card size on every screen. */
    gtk_widget_set_hexpand(button, FALSE);
    gtk_widget_set_halign(button, GTK_ALIGN_START);
    gtk_widget_set_valign(button, GTK_ALIGN_START);

    gtk_widget_set_tooltip_text(button,
        offline ? "module script not found" : mod->id);

    gtk_box_append(GTK_BOX(top), cat);
    gtk_box_append(GTK_BOX(card), top);
    gtk_box_append(GTK_BOX(top), chip);
    gtk_box_append(GTK_BOX(card), icon);
    gtk_box_append(GTK_BOX(card), name);
    gtk_button_set_child(GTK_BUTTON(button), card);
    gtk_box_append(GTK_BOX(card), desc);
    gtk_box_append(GTK_BOX(card), id);

    g_object_set_data(G_OBJECT(button), "module", (gpointer) mod);
    g_signal_connect(button, "clicked", G_CALLBACK(module_card_clicked), state);

    /* The pin rides an overlay layer above the card, so tapping it does not
       also open the module the way a nested button would. */
    {
        GtkWidget *overlay = gtk_overlay_new();
        GtkWidget *star = gtk_button_new_with_label(pinned ? "★" : "☆");
        gtk_widget_add_css_class(star, "flat");
        gtk_widget_add_css_class(star, "card-pin");
        gtk_widget_set_tooltip_text(star,
            pinned ? "unpin this module" : "pin this module");
        gtk_widget_set_halign(star, GTK_ALIGN_END);
        gtk_widget_set_valign(star, GTK_ALIGN_START);
        gtk_widget_set_margin_top(star, 6);
        gtk_widget_set_margin_end(star, 6);
        g_object_set_data(G_OBJECT(star), "state", state);
        g_object_set_data(G_OBJECT(star), "module-id", (gpointer) mod->id);
        g_signal_connect(star, "clicked", G_CALLBACK(pin_toggled), NULL);
        gtk_overlay_set_child(GTK_OVERLAY(overlay), button);
        gtk_overlay_add_overlay(GTK_OVERLAY(overlay), star);
        g_object_set_data(G_OBJECT(overlay), "module", (gpointer) mod);
        return overlay;
    }
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
    gboolean pin_a = g_dash_state != NULL && g_dash_state->pins != NULL &&
                     g_hash_table_contains(g_dash_state->pins, modules[a].id);
    gboolean pin_b = g_dash_state != NULL && g_dash_state->pins != NULL &&
                     g_hash_table_contains(g_dash_state->pins, modules[b].id);
    if (pin_a != pin_b) return pin_a ? -1 : 1;   /* pinned cards lead */
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

    g_dash_state = state;
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

/* ---- Favourites ------------------------------------------------------ */

static char *
pins_path(void)
{
    return g_build_filename(IMSISTING_ROOT, "state", "pins.tsv", NULL);
}

static void
pins_load(AppState *state)
{
    g_autofree char *path = pins_path();
    g_autofree char *data = NULL;
    g_auto(GStrv) lines = NULL;
    if (!g_file_get_contents(path, &data, NULL, NULL))
        return;
    lines = g_strsplit(data, "\n", -1);
    for (int i = 0; lines[i] != NULL; i++) {
        g_strstrip(lines[i]);
        if (*lines[i] != '\0')
            g_hash_table_insert(state->pins, g_strdup(lines[i]),
                                GINT_TO_POINTER(1));
    }
}

static void
pins_save(AppState *state)
{
    g_autofree char *path = pins_path();
    GString *out = g_string_new(NULL);
    GHashTableIter it;
    gpointer k;
    g_hash_table_iter_init(&it, state->pins);
    while (g_hash_table_iter_next(&it, &k, NULL))
        g_string_append_printf(out, "%s\n", (const char *) k);
    g_file_set_contents(path, out->str, -1, NULL);
    g_string_free(out, TRUE);
}

static void
dash_refresh(AppState *state)
{
    if (state->dash_flow == NULL) return;
    dash_fill(state, state->dash_flow, g_dash_sort);
    if (state->dash_search != NULL)
        dash_apply_filter(state->dash_flow,
            gtk_editable_get_text(GTK_EDITABLE(state->dash_search)));
}

static void
pin_toggled(GtkButton *button, gpointer user_data)
{
    AppState *state = g_object_get_data(G_OBJECT(button), "state");
    const char *id = g_object_get_data(G_OBJECT(button), "module-id");
    if (state == NULL || id == NULL) return;
    if (g_hash_table_contains(state->pins, id))
        g_hash_table_remove(state->pins, id);
    else
        g_hash_table_insert(state->pins, g_strdup(id), GINT_TO_POINTER(1));
    pins_save(state);
    dash_refresh(state);
    (void) user_data;
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
    GtkWidget *mission = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *mission_head = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *mission_title = gtk_label_new("Start here");
    GtkWidget *mission_sub = gtk_label_new(
        "Set the case, verify the bench, then move into collection.");
    GtkWidget *mission_grid = gtk_flow_box_new();
    gtk_widget_add_css_class(mission, "mission-panel");
    gtk_widget_add_css_class(mission_title, "mission-title");
    gtk_widget_add_css_class(mission_sub, "mission-subtitle");
    gtk_label_set_xalign(GTK_LABEL(mission_title), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(mission_sub), 1.0f);
    gtk_widget_set_hexpand(mission_title, TRUE);
    gtk_flow_box_set_selection_mode(GTK_FLOW_BOX(mission_grid), GTK_SELECTION_NONE);
    gtk_flow_box_set_homogeneous(GTK_FLOW_BOX(mission_grid), TRUE);
    gtk_flow_box_set_max_children_per_line(GTK_FLOW_BOX(mission_grid), 4);
    gtk_flow_box_set_min_children_per_line(GTK_FLOW_BOX(mission_grid), 2);
    gtk_flow_box_set_column_spacing(GTK_FLOW_BOX(mission_grid), 8);
    gtk_flow_box_set_row_spacing(GTK_FLOW_BOX(mission_grid), 8);
    gtk_flow_box_append(GTK_FLOW_BOX(mission_grid),
        dashboard_shortcut(state, "01 · CASEBOOK", "Define the operation",
            "Scope, target and evidence ledger", "book-open-symbolic", NULL, 2));
    gtk_flow_box_append(GTK_FLOW_BOX(mission_grid),
        dashboard_shortcut(state, "02 · BENCH", "Check the field kit",
            "Confirm hardware and capture readiness", "imsisting-05_field_kit-symbolic",
            dashboard_module("05_field_kit"), -1));
    gtk_flow_box_append(GTK_FLOW_BOX(mission_grid),
        dashboard_shortcut(state, "03 · RECON", "Survey the cell layer",
            "Identify the carrier before deeper work", "imsisting-02_cell_recon-symbolic",
            dashboard_module("02_cell_recon"), -1));
    gtk_flow_box_append(GTK_FLOW_BOX(mission_grid),
        dashboard_shortcut(state, "04 · LIVE", "Watch traffic",
            "Inspect the GSMTAP feed as it arrives", "network-receive-symbolic", NULL, 1));
    gtk_box_append(GTK_BOX(mission_head), mission_title);
    gtk_box_append(GTK_BOX(mission_head), mission_sub);
    gtk_box_append(GTK_BOX(mission), mission_head);
    {
        /* The station: case, radio and transmit state, read at a glance
           before the operator picks an action. Kept live by status_poll(). */
        GtkWidget *station = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 26);
        gtk_widget_add_css_class(station, "station-band");
        gtk_box_append(GTK_BOX(station), status_cell("CASE", &state->dash_case));
        gtk_box_append(GTK_BOX(station), status_cell("TARGETS", &state->dash_targets));
        gtk_box_append(GTK_BOX(station), status_cell("EVIDENCE", &state->dash_evidence));
        gtk_box_append(GTK_BOX(station), status_cell("ALERTS", &state->dash_alerts));
        gtk_box_append(GTK_BOX(mission), station);
    }
    gtk_box_append(GTK_BOX(mission), mission_grid);
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
    gtk_widget_set_margin_start(mission, 16);
    gtk_widget_set_margin_end(mission, 16);
    gtk_widget_set_margin_top(mission, 12);
    gtk_box_append(GTK_BOX(body), mission);

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

    /* A responsive flow instead of a fixed grid: columns follow the width.
       Not homogeneous: with it on, every row stretched its children to
       fill the line, so a row of four and a row of two drew different
       sized cards. Tiles now keep one size and simply pack. */
    gtk_flow_box_set_selection_mode(GTK_FLOW_BOX(flow), GTK_SELECTION_NONE);
    gtk_flow_box_set_homogeneous(GTK_FLOW_BOX(flow), FALSE);
    gtk_flow_box_set_max_children_per_line(GTK_FLOW_BOX(flow), 8);
    gtk_flow_box_set_min_children_per_line(GTK_FLOW_BOX(flow), 1);
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

    if (state->pins == NULL) {
        state->pins = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
        pins_load(state);
    }
    if (state->recent == NULL)
        state->recent = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    state->dash_flow = flow;
    state->dash_search = search;

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
create_evidence_page(AppState *state)
{
    GtkWidget *outer  = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *head   = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *box    = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *title  = gtk_label_new("Evidence Browser");
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
/*  CASEBOOK — CASES, EVIDENCE, ALERTS AND REPORTS                      */
/* ==================================================================== */

/* Casebook operations are small local state reads/writes. They never need
 * privilege. Capture and module execution remain asynchronous elsewhere. */
static char *
casebook_call(const char *const *args, gboolean *ok_out)
{
    g_autofree char *tool = g_build_filename(IMSISTING_ROOT, "tools",
                                             "casebook.py", NULL);
    GPtrArray *argv = g_ptr_array_new();
    g_autoptr(GError) error = NULL;
    g_autoptr(GSubprocess) proc = NULL;
    g_autofree char *out = NULL;
    g_autofree char *errout = NULL;

    g_ptr_array_add(argv, tool);
    for (guint i = 0; args != NULL && args[i] != NULL; i++)
        g_ptr_array_add(argv, (gpointer) args[i]);
    g_ptr_array_add(argv, NULL);
    proc = g_subprocess_newv((const char *const *) argv->pdata,
        G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_PIPE,
        &error);
    g_ptr_array_unref(argv);
    if (proc == NULL) {
        if (ok_out != NULL) *ok_out = FALSE;
        return g_strdup(error != NULL ? error->message : "could not launch Casebook");
    }

    gboolean sent = g_subprocess_communicate_utf8(proc, NULL, NULL,
                                                   &out, &errout, &error);
    gboolean ok = sent && g_subprocess_get_successful(proc);
    if (ok_out != NULL) *ok_out = ok;
    if (!sent)
        return g_strdup(error != NULL ? error->message : "Casebook command failed");
    if (ok)
        return g_steal_pointer(&out);
    if (errout != NULL && *errout != 0)
        return g_steal_pointer(&errout);
    return g_steal_pointer(&out);
}

static void
casebook_list_clear(GtkWidget *list)
{
    GtkWidget *child = gtk_widget_get_first_child(list);
    while (child != NULL) {
        GtkWidget *next = gtk_widget_get_next_sibling(child);
        gtk_list_box_remove(GTK_LIST_BOX(list), child);
        child = next;
    }
}

/* A note row: used for both "nothing recorded" and "no active case". The
   latter is the common state, not an error, so it reads as information. */
static void
casebook_list_note(GtkWidget *list, const char *title, const char *hint)
{
    GtkWidget *row = gtk_list_box_row_new();
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *t = gtk_label_new(title != NULL ? title : "");
    GtkWidget *h = gtk_label_new(hint != NULL ? hint : "");

    gtk_widget_add_css_class(t, "cell-name");
    gtk_widget_add_css_class(h, "cell-meta");
    gtk_label_set_xalign(GTK_LABEL(t), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(h), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(t), TRUE);
    gtk_label_set_wrap(GTK_LABEL(h), TRUE);
    if (hint == NULL || *hint == '\0') gtk_widget_set_visible(h, FALSE);
    gtk_widget_set_margin_top(box, 12);
    gtk_widget_set_margin_bottom(box, 12);
    gtk_widget_set_margin_start(box, 6);
    gtk_box_append(GTK_BOX(box), t);
    gtk_box_append(GTK_BOX(box), h);
    gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), box);
    gtk_list_box_row_set_activatable(GTK_LIST_BOX_ROW(row), FALSE);
    gtk_list_box_row_set_selectable(GTK_LIST_BOX_ROW(row), FALSE);
    gtk_list_box_append(GTK_LIST_BOX(list), row);
}

/* One record: icon, title with an optional right-hand badge, a monospace
   identifier line, then the facts worth comparing down the list. */
static GtkWidget *
casebook_row_new(const char *icon_name, const char *title, const char *ident,
                 const char *meta, const char *badge, const char *badge_class)
{
    GtkWidget *row = gtk_list_box_row_new();
    GtkWidget *content = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    GtkWidget *text = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *top = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *icon = gtk_image_new_from_icon_name(icon_name);
    GtkWidget *t = gtk_label_new(title != NULL ? title : "");
    GtkWidget *i = gtk_label_new(ident != NULL ? ident : "");
    GtkWidget *m = gtk_label_new(meta != NULL ? meta : "");

    gtk_image_set_pixel_size(GTK_IMAGE(icon), 26);
    gtk_widget_add_css_class(row, "cell-row");
    gtk_widget_add_css_class(icon, "cell-icon");
    gtk_widget_add_css_class(t, "cell-name");
    gtk_widget_add_css_class(i, "cell-ident");
    gtk_widget_add_css_class(m, "cell-meta");

    gtk_label_set_xalign(GTK_LABEL(t), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(i), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(m), 0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(t), PANGO_ELLIPSIZE_END);
    gtk_label_set_ellipsize(GTK_LABEL(i), PANGO_ELLIPSIZE_END);
    gtk_label_set_ellipsize(GTK_LABEL(m), PANGO_ELLIPSIZE_END);
    /* Without a bound a long sha256 or ssh detail forces the whole list to
       scroll sideways, which is most of what looked wrong before. */
    gtk_label_set_max_width_chars(GTK_LABEL(t), 40);
    gtk_label_set_max_width_chars(GTK_LABEL(i), 40);
    gtk_label_set_max_width_chars(GTK_LABEL(m), 48);

    gtk_widget_set_hexpand(text, TRUE);
    gtk_box_append(GTK_BOX(top), t);
    if (badge != NULL && *badge != '\0') {
        GtkWidget *b = gtk_label_new(badge);
        gtk_widget_add_css_class(b, "status-pill");
        gtk_widget_add_css_class(b, badge_class != NULL ? badge_class : "status-dim");
        gtk_widget_set_halign(b, GTK_ALIGN_END);
        gtk_widget_set_valign(b, GTK_ALIGN_CENTER);
        gtk_box_append(GTK_BOX(top), b);
    }
    gtk_box_append(GTK_BOX(text), top);
    gtk_box_append(GTK_BOX(text), i);
    gtk_box_append(GTK_BOX(text), m);
    gtk_box_append(GTK_BOX(content), icon);
    gtk_box_append(GTK_BOX(content), text);
    gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), content);
    return row;
}

/* Column lookup by name rather than by position: the table's fields are
   declared in the tool, and a positional parser silently shifts the day one
   is inserted. */
static int
casebook_col(gchar **header, const char *name)
{
    for (int i = 0; header != NULL && header[i] != NULL; i++)
        if (g_strcmp0(header[i], name) == 0) return i;
    return -1;
}

static const char *
casebook_f(gchar **f, int idx)
{
    if (idx < 0 || f == NULL || f[idx] == NULL) return "";
    return f[idx];
}

static const char *
casebook_size(const char *bytes)
{
    static char buf[32];
    guint64 n = (bytes != NULL && *bytes != '\0')
        ? g_ascii_strtoull(bytes, NULL, 10) : 0;
    g_autofree char *s = loot_fmt_size(n);
    g_strlcpy(buf, s, sizeof buf);
    return buf;
}

static const char *
casebook_base(const char *path)
{
    const char *slash;
    if (path == NULL || *path == '\0') return "";
    slash = strrchr(path, '/');
    return (slash != NULL) ? slash + 1 : path;
}

static const char *
casebook_sev_class(const char *sev)
{
    if (sev == NULL) return "status-dim";
    if (g_ascii_strcasecmp(sev, "CRITICAL") == 0 ||
        g_ascii_strcasecmp(sev, "HIGH") == 0)   return "status-error";
    if (g_ascii_strcasecmp(sev, "MEDIUM") == 0 ||
        g_ascii_strcasecmp(sev, "WARN") == 0)   return "status-warn";
    if (g_ascii_strcasecmp(sev, "LOW") == 0 ||
        g_ascii_strcasecmp(sev, "INFO") == 0)   return "status-ok";
    return "status-dim";
}

typedef void (*CasebookRowFn)(GtkWidget *list, gchar **header, gchar **f);

static void
cb_row_capture(GtkWidget *list, gchar **h, gchar **f)
{
    const char *kind = casebook_f(f, casebook_col(h, "kind"));
    g_autofree char *ident = g_strdup_printf("%s  ·  %s",
        casebook_f(f, casebook_col(h, "module")), kind);
    g_autofree char *sha = g_strndup(casebook_f(f, casebook_col(h, "sha256")), 12);
    g_autofree char *meta = g_strdup_printf("%s  ·  %s  ·  %s  ·  %s",
        casebook_size(casebook_f(f, casebook_col(h, "bytes"))),
        casebook_f(f, casebook_col(h, "added")),
        sha, casebook_f(f, casebook_col(h, "tags")));
    const char *icon = (g_strcmp0(kind, "pcap") == 0)
        ? "network-wireless-symbolic"
        : (g_strcmp0(kind, "iq") == 0) ? "audio-input-microphone-symbolic"
                                       : "text-x-generic-symbolic";

    gtk_list_box_append(GTK_LIST_BOX(list), casebook_row_new(icon,
        casebook_base(casebook_f(f, casebook_col(h, "path"))),
        ident, meta, kind, "status-dim"));
}

static void
cb_row_timeline(GtkWidget *list, gchar **h, gchar **f)
{
    const char *sev = casebook_f(f, casebook_col(h, "severity"));
    g_autofree char *ident = g_strdup_printf("%s  ·  %s",
        casebook_f(f, casebook_col(h, "type")),
        casebook_f(f, casebook_col(h, "source")));
    g_autofree char *meta = g_strdup_printf("%s  ·  %s",
        casebook_f(f, casebook_col(h, "time")),
        casebook_base(casebook_f(f, casebook_col(h, "reference"))));

    gtk_list_box_append(GTK_LIST_BOX(list), casebook_row_new(
        "document-open-recent-symbolic",
        casebook_f(f, casebook_col(h, "message")), ident, meta,
        sev, casebook_sev_class(sev)));
}

static void
cb_row_alert(GtkWidget *list, gchar **h, gchar **f)
{
    const char *sev = casebook_f(f, casebook_col(h, "severity"));
    g_autofree char *ident = g_strdup_printf("%s  ·  %s",
        casebook_f(f, casebook_col(h, "kind")),
        casebook_f(f, casebook_col(h, "source")));
    g_autofree char *meta = g_strdup_printf("%s  ·  %s  ·  %s",
        casebook_f(f, casebook_col(h, "time")),
        casebook_base(casebook_f(f, casebook_col(h, "evidence"))),
        casebook_f(f, casebook_col(h, "status")));

    gtk_list_box_append(GTK_LIST_BOX(list), casebook_row_new(
        "dialog-warning-symbolic",
        casebook_f(f, casebook_col(h, "message")), ident, meta,
        sev, casebook_sev_class(sev)));
}

static void
cb_row_node(GtkWidget *list, gchar **h, gchar **f)
{
    const char *st = casebook_f(f, casebook_col(h, "status"));
    g_autofree char *ident = g_strdup_printf("%s  ·  %s  ·  %s",
        casebook_f(f, casebook_col(h, "host")),
        casebook_f(f, casebook_col(h, "transport")),
        casebook_f(f, casebook_col(h, "role")));
    g_autofree char *meta = g_strdup_printf("%s  ·  %s",
        casebook_f(f, casebook_col(h, "last_seen")),
        casebook_f(f, casebook_col(h, "detail")));
    const char *cls = (g_ascii_strcasecmp(st, "ONLINE") == 0)  ? "status-ok"
                    : (g_ascii_strcasecmp(st, "OFFLINE") == 0) ? "status-error"
                                                              : "status-dim";

    gtk_list_box_append(GTK_LIST_BOX(list), casebook_row_new(
        "network-server-symbolic",
        casebook_f(f, casebook_col(h, "name")), ident, meta, st, cls));
}

static void
cb_row_report(GtkWidget *list, gchar **h, gchar **f)
{
    const char *path = casebook_f(f, casebook_col(h, "path"));
    const char *base = casebook_base(path);
    const char *dot = strrchr(base, '.');
    g_autofree char *fmt = g_strdup(dot != NULL ? dot + 1 : "");
    g_autofree char *fmt_up = g_ascii_strup(fmt, -1);
    g_autofree char *when = NULL;
    const char *mt = casebook_f(f, casebook_col(h, "mtime"));
    g_autofree char *ident = NULL;

    if (mt != NULL && *mt != '\0') {
        GDateTime *dt = g_date_time_new_from_unix_local(
            (gint64) g_ascii_strtoll(mt, NULL, 10));
        if (dt != NULL) {
            when = g_date_time_format(dt, "%m-%d %H:%M");
            g_date_time_unref(dt);
        }
    }
    ident = g_strdup_printf("%s  ·  %s", fmt_up,
                            when != NULL ? when : "");

    gtk_list_box_append(GTK_LIST_BOX(list), casebook_row_new(
        "x-office-document-symbolic", base, ident,
        casebook_size(casebook_f(f, casebook_col(h, "bytes"))),
        fmt_up, "status-dim"));
}

/* Run a TSV verb and render one row per record. An empty table arrives as a
   header line with nothing under it, so "one line" means empty. */
static void
casebook_list_fill(GtkWidget *list, const char *command, CasebookRowFn row_fn,
                   const char *empty_title, const char *empty_hint)
{
    const char *args[] = { command, NULL };
    gboolean ok = FALSE;
    g_autofree char *text = NULL;
    g_auto(GStrv) lines = NULL;
    g_auto(GStrv) header = NULL;
    int rows = 0;

    if (list == NULL) return;
    casebook_list_clear(list);

    text = casebook_call(args, &ok);
    if (!ok) {
        /* No active case is the common state, not a record to render: the
           tool's stderr line is context, not data. */
        g_autofree char *first = NULL;
        if (text != NULL) {
            g_auto(GStrv) l = g_strsplit(text, "\n", 2);
            g_autofree char *raw = g_strdup(l[0] != NULL ? l[0] : "");
            g_strstrip(raw);
            /* The tool prefixes its refusal with "ERROR\t", which under a
               heading that already says "No active case" is just noise. */
            first = g_str_has_prefix(raw, "ERROR")
                ? g_strdup(g_strstrip(raw + 5))
                : g_strdup(raw);
        }
        casebook_list_note(list, "No active case",
            (first != NULL && *first != '\0')
                ? first : "Create or select a case in Overview.");
        return;
    }
    if (text == NULL || *text == '\0') {
        casebook_list_note(list, empty_title, empty_hint);
        return;
    }

    lines = g_strsplit(text, "\n", -1);
    header = g_strsplit(lines[0], "\t", -1);
    for (guint i = 1; lines[i] != NULL; i++) {
        g_auto(GStrv) f = NULL;
        if (*lines[i] == '\0') continue;
        f = g_strsplit(lines[i], "\t", -1);
        row_fn(list, header, f);
        rows++;
    }
    if (rows == 0)
        casebook_list_note(list, empty_title, empty_hint);
}

/* The Casebook home: the facts an investigator wants before touching a tab —
   the case, its scope and authorization, the current target, how much evidence
   and how many alerts it holds, and the latest alert line. Refreshed by
   casebook_home_refresh(), which runs with Refresh All. */
static GtkWidget *
build_casebook_home(AppState *state)
{
    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *row  = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 26);
    GtkWidget *alert = gtk_label_new(
        "No active case. Create or select one to begin.");

    gtk_widget_add_css_class(card, "case-home");
    gtk_widget_add_css_class(row, "station-band");
    gtk_widget_add_css_class(alert, "case-home-alert");
    gtk_label_set_xalign(GTK_LABEL(alert), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(alert), TRUE);

    gtk_box_append(GTK_BOX(row), status_cell("CASE", &state->casebook_brief_case));
    gtk_box_append(GTK_BOX(row), status_cell("SCOPE", &state->casebook_brief_scope));
    gtk_box_append(GTK_BOX(row), status_cell("AUTHORIZATION", &state->casebook_brief_auth));
    gtk_box_append(GTK_BOX(row), status_cell("TARGET", &state->casebook_brief_target));
    gtk_box_append(GTK_BOX(row), status_cell("EVIDENCE", &state->casebook_brief_evidence));
    gtk_box_append(GTK_BOX(row), status_cell("ALERTS", &state->casebook_brief_alerts));
    state->casebook_brief_alert = alert;
    gtk_box_append(GTK_BOX(card), row);
    gtk_box_append(GTK_BOX(card), alert);
    return card;
}

static void
casebook_home_refresh(AppState *state)
{
    gboolean ok = FALSE;
    const char *status_args[] = { "--status-tsv", NULL };
    const char *show_args[]   = { "--case-show-tsv", NULL };
    const char *tgt_args[]    = { "--target-current-tsv", NULL };
    const char *alert_args[]  = { "--alerts-tsv", NULL };
    g_autofree char *status = NULL, *show = NULL, *tgt = NULL, *al = NULL;
    g_autofree char *name = NULL, *cstat = NULL, *scope = NULL, *auth = NULL;
    g_autofree char *evc = NULL, *alc = NULL, *rat = NULL, *plmn = NULL;
    g_autofree char *cell = NULL, *asev = NULL, *amsg = NULL, *tstr = NULL;
    gboolean none;

    if (state->casebook_brief_case == NULL) return;

    status = casebook_call(status_args, &ok);
    if (ok) {
        show = casebook_call(show_args, NULL);
        tgt  = casebook_call(tgt_args, NULL);
        al   = casebook_call(alert_args, NULL);
    }
    name  = show ? tsv_field(show, "name") : NULL;
    cstat = show ? tsv_field(show, "status") : NULL;
    scope = show ? tsv_field(show, "scope") : NULL;
    auth  = show ? tsv_field(show, "authorization") : NULL;
    evc   = status ? tsv_field(status, "evidence") : NULL;
    alc   = status ? tsv_field(status, "alerts") : NULL;
    rat   = tgt ? tsv_row_field(tgt, "rat") : NULL;
    plmn  = tgt ? tsv_row_field(tgt, "plmn") : NULL;
    cell  = tgt ? tsv_row_field(tgt, "cell_id") : NULL;
    asev  = al ? tsv_last_field(al, "severity") : NULL;
    amsg  = al ? tsv_last_field(al, "message") : NULL;

    none = (name == NULL || *name == '\0');

    if (none)
        status_set(state->casebook_brief_case, "not set", "status-warn");
    else {
        g_autofree char *cs = g_strdup_printf("%s · %s", name,
            (cstat && *cstat) ? cstat : "OPEN");
        status_set(state->casebook_brief_case, cs, "status-ok");
    }
    status_set(state->casebook_brief_scope,
        (scope && *scope) ? scope : "—",
        (scope && *scope) ? "" : "status-dim");
    status_set(state->casebook_brief_auth,
        (auth && *auth) ? auth : "—",
        (auth && *auth) ? "" : "status-dim");

    tstr = (rat || plmn || cell)
        ? g_strdup_printf("%s%s%s%s%s",
            (rat && *rat) ? rat : "", (rat && *rat) ? " " : "",
            (plmn && *plmn) ? plmn : "", (plmn && *plmn) ? " " : "",
            (cell && *cell) ? cell : "")
        : NULL;
    status_set(state->casebook_brief_target,
        (tstr && *tstr) ? tstr : "none",
        (tstr && *tstr) ? "status-ok" : "status-dim");

    {
        int ne = (evc && *evc) ? atoi(evc) : 0;
        int na = (alc && *alc) ? atoi(alc) : 0;
        g_autofree char *se = g_strdup_printf("%d", ne);
        g_autofree char *sa = g_strdup_printf("%d", na);
        status_set(state->casebook_brief_evidence, se,
                   ne > 0 ? "status-ok" : "status-dim");
        status_set(state->casebook_brief_alerts, sa,
                   na > 0 ? "status-warn" : "status-dim");
    }

    if (asev && amsg && *amsg)
        gtk_label_set_text(GTK_LABEL(state->casebook_brief_alert),
                           g_strdup_printf("Latest alert · %s — %s", asev, amsg));
    else
        gtk_label_set_text(GTK_LABEL(state->casebook_brief_alert),
            none ? "No active case. Create or select one to begin."
                 : "No alerts recorded for this case.");
}

static void
casebook_refresh(AppState *state)
{
    /* Overview combines the summary, active case and current target. */
    if (state->casebook_overview != NULL) {
        gboolean ok = FALSE;
        const char *status_args[] = { "--status-tsv", NULL };
        const char *case_args[] = { "--case-show-tsv", NULL };
        const char *target_args[] = { "--target-current-tsv", NULL };
        g_autofree char *status = casebook_call(status_args, &ok);
        g_autofree char *details = ok ? casebook_call(case_args, NULL) : NULL;
        g_autofree char *target = ok ? casebook_call(target_args, NULL) : NULL;
        g_autofree char *all = g_strdup_printf(
            "CASEBOOK STATUS\n%s\nACTIVE CASE\n%s\nCURRENT TARGET\n%s",
            status != NULL ? status : "", details != NULL ? details : "No active case.\n",
            target != NULL ? target : "No target selected.\n");
        gtk_text_buffer_set_text(state->casebook_overview, all, -1);
    }
    casebook_list_fill(state->casebook_captures_list, "--captures-tsv",
        cb_row_capture, "No captures indexed.",
        "Index Files, then Refresh.");
    casebook_list_fill(state->casebook_timeline_list, "--timeline-tsv",
        cb_row_timeline, "No timeline events.",
        "Index captures, then Correlate Evidence.");
    casebook_list_fill(state->casebook_alerts_list, "--alerts-tsv",
        cb_row_alert, "No alerts recorded.",
        "Build Baseline writes the reference snapshot to compare against.");
    casebook_list_fill(state->casebook_nodes_list, "--node-list-tsv",
        cb_row_node, "No remote sensor nodes configured.",
        "Add a sensor above.");
    casebook_list_fill(state->casebook_reports_list, "--reports-tsv",
        cb_row_report, "No reports exported.",
        "Export HTML or JSON from the toolbar.");
    casebook_home_refresh(state);
}

static gboolean
casebook_run(AppState *state, const char *title, const char *const *args)
{
    gboolean ok = FALSE;
    g_autofree char *text = casebook_call(args, &ok);
    if (text != NULL && *text != 0) append_event(state, text);
    show_toast_full(state, title,
        ok ? "Done" : (text != NULL ? text : "Failed"), ok ? "ok" : "error");
    casebook_refresh(state);
    return ok;
}

static const char *
casebook_entry(GtkWidget *entry)
{
    return entry != NULL ? gtk_editable_get_text(GTK_EDITABLE(entry)) : "";
}

static void
casebook_refresh_clicked(GtkButton *button, gpointer user_data)
{
    (void) button;
    casebook_refresh(user_data);
}

static void
casebook_simple_clicked(GtkButton *button, gpointer user_data)
{
    AppState *state = user_data;
    const char *command = g_object_get_data(G_OBJECT(button), "casebook-command");
    const char *args[] = { command, NULL };
    if (command != NULL && casebook_run(state, gtk_button_get_label(button), args) &&
        g_strcmp0(command, "--index") == 0)
        loot_refresh(state);
}

static GtkWidget *
casebook_action(AppState *state, const char *label, const char *command)
{
    GtkWidget *button = gtk_button_new_with_label(label);
    g_object_set_data(G_OBJECT(button), "casebook-command", (gpointer) command);
    g_signal_connect(button, "clicked", G_CALLBACK(casebook_simple_clicked), state);
    return button;
}

static void
casebook_create_clicked(GtkButton *button, gpointer user_data)
{
    AppState *state = user_data;
    const char *name = casebook_entry(state->case_name_entry);
    if (*name == 0) {
        show_toast_full(state, "Create Case", "A case name is required", "error");
        return;
    }
    const char *args[] = { "--case-create", name,
        casebook_entry(state->case_scope_entry),
        casebook_entry(state->case_auth_entry), NULL };
    if (casebook_run(state, "Create Case", args))
        gtk_editable_set_text(GTK_EDITABLE(state->case_name_entry), "");
    (void) button;
}

static void
casebook_select_clicked(GtkButton *button, gpointer user_data)
{
    AppState *state = user_data;
    const char *id = casebook_entry(state->case_select_entry);
    if (*id == 0) {
        show_toast_full(state, "Select Case", "Enter an existing case ID", "error");
        return;
    }
    const char *args[] = { "--case-select", id, NULL };
    casebook_run(state, "Select Case", args);
    (void) button;
}

static void
casebook_node_add_clicked(GtkButton *button, gpointer user_data)
{
    AppState *state = user_data;
    const char *name = casebook_entry(state->node_name_entry);
    const char *host = casebook_entry(state->node_host_entry);
    const char *transport = casebook_entry(state->node_transport_entry);
    if (*name == 0 || *host == 0) {
        show_toast_full(state, "Add Sensor", "Name and host are required", "error");
        return;
    }
    if (*transport == 0) transport = "ssh";
    const char *args[] = { "--node-add", name, host, transport, "sensor", NULL };
    casebook_run(state, "Add Sensor", args);
    (void) button;
}

static void
casebook_node_probe_clicked(GtkButton *button, gpointer user_data)
{
    AppState *state = user_data;
    const char *name = casebook_entry(state->node_name_entry);
    if (*name == 0) {
        show_toast_full(state, "Probe Sensor", "Enter the sensor name", "error");
        return;
    }
    const char *args[] = { "--node-probe", name, NULL };
    casebook_run(state, "Probe Sensor", args);
    (void) button;
}

static GtkWidget *
casebook_text_view(GtkTextBuffer **buffer_out, const char *placeholder)
{
    GtkWidget *scroll = gtk_scrolled_window_new();
    GtkWidget *view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(view), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(view), TRUE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(view), GTK_WRAP_NONE);
    gtk_widget_add_css_class(view, "casebook-text");
    *buffer_out = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));
    gtk_text_buffer_set_text(*buffer_out, placeholder, -1);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), view);
    gtk_widget_set_vexpand(scroll, TRUE);
    return scroll;
}

static GtkWidget *
casebook_shell(GtkWidget *toolbar, GtkWidget *content)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_margin_top(box, 12);
    gtk_widget_set_margin_bottom(box, 12);
    gtk_widget_set_margin_start(box, 14);
    gtk_widget_set_margin_end(box, 14);
    if (toolbar != NULL) {
        gtk_widget_add_css_class(toolbar, "casebook-toolbar");
        gtk_box_append(GTK_BOX(box), toolbar);
    }
    gtk_widget_set_vexpand(content, TRUE);
    gtk_box_append(GTK_BOX(box), content);
    return box;
}

static GtkWidget *
create_casebook_overview(AppState *state)
{
    GtkWidget *body = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *create_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *select_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *create = gtk_button_new_with_label("Create Case");
    GtkWidget *select = gtk_button_new_with_label("Select Case");
    GtkWidget *hint = gtk_label_new(
        "Targets are set from the Target panel in the header, so the target "
        "stays reachable from every page - and is recorded into the case.");

    state->case_name_entry = gtk_entry_new();
    state->case_scope_entry = gtk_entry_new();
    state->case_auth_entry = gtk_entry_new();
    state->case_select_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(state->case_name_entry), "Case name");
    gtk_entry_set_placeholder_text(GTK_ENTRY(state->case_scope_entry), "Scope / owned lab");
    gtk_entry_set_placeholder_text(GTK_ENTRY(state->case_auth_entry), "Authorization reference");
    gtk_entry_set_placeholder_text(GTK_ENTRY(state->case_select_entry), "Existing case ID");
    gtk_widget_add_css_class(create, "primary");
    gtk_widget_add_css_class(hint, "casebook-hint");
    gtk_label_set_xalign(GTK_LABEL(hint), 0.0f);
    gtk_label_set_wrap(GTK_LABEL(hint), TRUE);
    g_signal_connect(create, "clicked", G_CALLBACK(casebook_create_clicked), state);
    g_signal_connect(select, "clicked", G_CALLBACK(casebook_select_clicked), state);

    gtk_box_append(GTK_BOX(create_row), state->case_name_entry);
    gtk_box_append(GTK_BOX(create_row), state->case_scope_entry);
    gtk_box_append(GTK_BOX(create_row), state->case_auth_entry);
    gtk_box_append(GTK_BOX(create_row), create);
    gtk_box_append(GTK_BOX(select_row), state->case_select_entry);
    gtk_box_append(GTK_BOX(select_row), select);
    gtk_box_append(GTK_BOX(select_row), casebook_action(state, "Close Active", "--case-close"));
    gtk_box_append(GTK_BOX(body), create_row);
    gtk_box_append(GTK_BOX(body), select_row);
    gtk_box_append(GTK_BOX(body), hint);
    gtk_box_append(GTK_BOX(body), casebook_text_view(&state->casebook_overview,
        "No active case. Create or select one above."));
    return casebook_shell(NULL, body);
}

static GtkWidget *
create_casebook_listing(AppState *state, GtkWidget **list_out,
                        const char *placeholder, const char *label1,
                        const char *command1, const char *label2,
                        const char *command2, const char *label3,
                        const char *command3)
{
    GtkWidget *toolbar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *refresh = gtk_button_new_with_label("Refresh");
    GtkWidget *scroll = gtk_scrolled_window_new();
    GtkWidget *list = gtk_list_box_new();

    (void) placeholder;
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(list), GTK_SELECTION_NONE);
    gtk_widget_add_css_class(list, "cell-list");
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), list);
    gtk_widget_set_vexpand(scroll, TRUE);
    *list_out = list;

    g_signal_connect(refresh, "clicked", G_CALLBACK(casebook_refresh_clicked), state);
    gtk_box_append(GTK_BOX(toolbar), refresh);
    if (label1 != NULL) gtk_box_append(GTK_BOX(toolbar), casebook_action(state, label1, command1));
    if (label2 != NULL) gtk_box_append(GTK_BOX(toolbar), casebook_action(state, label2, command2));
    if (label3 != NULL) gtk_box_append(GTK_BOX(toolbar), casebook_action(state, label3, command3));
    return casebook_shell(toolbar, scroll);
}

static GtkWidget *
create_casebook_nodes(AppState *state)
{
    GtkWidget *body = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkWidget *toolbar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *add = gtk_button_new_with_label("Add Sensor");
    GtkWidget *probe = gtk_button_new_with_label("Probe");
    GtkWidget *refresh = gtk_button_new_with_label("Refresh");
    state->node_name_entry = gtk_entry_new();
    state->node_host_entry = gtk_entry_new();
    state->node_transport_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(state->node_name_entry), "Node name");
    gtk_entry_set_placeholder_text(GTK_ENTRY(state->node_host_entry), "user@host or localhost");
    gtk_entry_set_placeholder_text(GTK_ENTRY(state->node_transport_entry), "ssh or local");
    gtk_widget_add_css_class(add, "primary");
    g_signal_connect(add, "clicked", G_CALLBACK(casebook_node_add_clicked), state);
    g_signal_connect(probe, "clicked", G_CALLBACK(casebook_node_probe_clicked), state);
    g_signal_connect(refresh, "clicked", G_CALLBACK(casebook_refresh_clicked), state);
    gtk_box_append(GTK_BOX(toolbar), state->node_name_entry);
    gtk_box_append(GTK_BOX(toolbar), state->node_host_entry);
    gtk_box_append(GTK_BOX(toolbar), state->node_transport_entry);
    gtk_box_append(GTK_BOX(toolbar), add);
    gtk_box_append(GTK_BOX(toolbar), probe);
    gtk_box_append(GTK_BOX(toolbar), refresh);
    gtk_box_append(GTK_BOX(body), toolbar);
    {
        GtkWidget *scroll = gtk_scrolled_window_new();
        GtkWidget *list = gtk_list_box_new();
        gtk_list_box_set_selection_mode(GTK_LIST_BOX(list), GTK_SELECTION_NONE);
        gtk_widget_add_css_class(list, "cell-list");
        gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                       GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
        gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), list);
        gtk_widget_set_vexpand(scroll, TRUE);
        state->casebook_nodes_list = list;
        gtk_box_append(GTK_BOX(body), scroll);
    }
    return casebook_shell(NULL, body);
}

static GtkWidget *
create_casebook_page(AppState *state)
{
    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *head = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *titles = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *title = gtk_label_new("Casebook");
    GtkWidget *sub = gtk_label_new(
        "Cases, targets, evidence, captures, alerts, sensors and reports");
    GtkWidget *refresh = gtk_button_new_with_label("Refresh All");
    GtkWidget *tabs = gtk_notebook_new();

    gtk_widget_add_css_class(outer, "casebook");
    gtk_widget_add_css_class(title, "page-title");
    gtk_widget_add_css_class(sub, "page-subtitle");
    gtk_widget_add_css_class(tabs, "casebook-tabs");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(sub), 0.0f);
    gtk_widget_set_hexpand(titles, TRUE);
    gtk_box_append(GTK_BOX(titles), title);
    gtk_box_append(GTK_BOX(titles), sub);
    gtk_box_append(GTK_BOX(head), titles);
    gtk_box_append(GTK_BOX(head), refresh);
    gtk_widget_set_margin_top(head, 14);
    gtk_widget_set_margin_bottom(head, 8);
    gtk_widget_set_margin_start(head, 16);
    gtk_widget_set_margin_end(head, 16);
    gtk_box_append(GTK_BOX(outer), head);
    {
        GtkWidget *home = build_casebook_home(state);
        gtk_widget_set_margin_start(home, 16);
        gtk_widget_set_margin_end(home, 16);
        gtk_widget_set_margin_bottom(home, 8);
        gtk_box_append(GTK_BOX(outer), home);
    }
    gtk_widget_set_vexpand(tabs, TRUE);
    gtk_box_append(GTK_BOX(outer), tabs);
    g_signal_connect(refresh, "clicked", G_CALLBACK(casebook_refresh_clicked), state);

    gtk_notebook_append_page(GTK_NOTEBOOK(tabs), create_casebook_overview(state),
                             gtk_label_new("Overview"));
    gtk_notebook_append_page(GTK_NOTEBOOK(tabs), create_evidence_page(state),
                             gtk_label_new("Evidence"));
    gtk_notebook_append_page(GTK_NOTEBOOK(tabs),
        create_casebook_listing(state, &state->casebook_captures_list,
            "No captures indexed.", "Index Files", "--index",
            NULL, NULL, NULL, NULL), gtk_label_new("Captures"));
    gtk_notebook_append_page(GTK_NOTEBOOK(tabs),
        create_casebook_listing(state, &state->casebook_timeline_list,
            "No timeline events.", "Correlate Evidence", "--correlate",
            NULL, NULL, NULL, NULL), gtk_label_new("Timeline"));
    gtk_notebook_append_page(GTK_NOTEBOOK(tabs),
        create_casebook_listing(state, &state->casebook_alerts_list,
            "No alerts.", "Build Baseline", "--baseline-build",
            "Clear Alerts", "--alerts-clear", NULL, NULL), gtk_label_new("Alerts"));
    gtk_notebook_append_page(GTK_NOTEBOOK(tabs), create_casebook_nodes(state),
                             gtk_label_new("Nodes"));
    gtk_notebook_append_page(GTK_NOTEBOOK(tabs),
        create_casebook_listing(state, &state->casebook_reports_list,
            "No reports exported.", "Export HTML", "--report-html",
            "Export JSON", "--report-json", "Export TSV", "--report-tsv"),
            gtk_label_new("Reports"));
    casebook_refresh(state);
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
"  Casebook    cases, targets, evidence, alerts, sensors and reports\n"
"  Stats       module and collection counts\n"
"  Settings    environment facts and maintenance actions\n"
"\n"
"  Open a module card (or a sidebar row) and it appears as its own tab.\n"
"  Module tabs close; Dashboard/Casebook/Stats/Help/Settings do not.\n"
"\n"
"RUNNING A VERB\n"
"  Each module page lists common verbs as buttons. The generated verb\n"
"  selector exposes every documented verb; enter only its arguments.\n"
"  Copy shows the matching terminal command before it is run.\n"
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
"TARGET AND CASE STATE\n"
"  Casebook owns persistent cases, selected cells, evidence hashes, alerts,\n"
"  sensors and reports. Modules still share live SDR state under tmp/; each\n"
"  completed run is added to the active case timeline automatically.\n"
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

        g_object_set_data(G_OBJECT(deps), "state", state);
        g_object_set_data(G_OBJECT(deps), "module-id", (gpointer) "00_deps");
        g_object_set_data(G_OBJECT(deps), "status", st);
        g_object_set_data_full(G_OBJECT(deps), "verb",
                               g_strdup("--check-versions"), g_free);
        g_signal_connect(deps, "clicked", G_CALLBACK(group_verb_clicked), NULL);

        g_object_set_data(G_OBJECT(radio), "state", state);
        g_object_set_data(G_OBJECT(radio), "module-id", (gpointer) "01_radio");
        g_object_set_data(G_OBJECT(radio), "status", st);
        g_object_set_data_full(G_OBJECT(radio), "verb",
                               g_strdup("--list-tsv"), g_free);
        g_signal_connect(radio, "clicked", G_CALLBACK(group_verb_clicked), NULL);

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
    GtkTextBuffer *buf;
    (void) nb;

    /* Aim output at the console of whichever page is on screen. Non-module
       tabs carry no "output-buffer", which clears the target so a run can
       never write into a page that is no longer visible. */
    buf = child != NULL
        ? g_object_get_data(G_OBJECT(child), "output-buffer") : NULL;
    if (state->active_output != buf) {
        g_clear_object(&state->active_output);
        state->active_output = buf != NULL ? g_object_ref(buf) : NULL;
    }

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
        gtk_widget_remove_css_class(l, "dir-dl");
        if (g_strcmp0(m->dir, "UL") == 0)
            gtk_widget_add_css_class(l, "dir-ul");
        else
            gtk_widget_add_css_class(l, "dir-dl");
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
        g_autofree char *s = g_strdup_printf("%u msg%s%s", state->live_count,
            state->live_count == 1 ? "" : "s", state->live_paused ? " · paused" : "");
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

    if (state->live_paused) return G_SOURCE_CONTINUE;
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
live_follow_toggled(GtkToggleButton *b, gpointer user_data)
{
    AppState *state = user_data;
    state->live_follow = gtk_toggle_button_get_active(b);
}

/* Keep the newest row in view while Follow is on. */
static void
live_items_changed(GListModel *model, guint pos, guint removed, guint added,
                   gpointer user_data)
{
    AppState *state = user_data;
    GtkAdjustment *adj;
    if (!state->live_follow || state->live_scroll == NULL) return;
    adj = gtk_scrolled_window_get_vadjustment(
        GTK_SCROLLED_WINDOW(state->live_scroll));
    if (adj != NULL)
        gtk_adjustment_set_value(adj,
            gtk_adjustment_get_upper(adj) - gtk_adjustment_get_page_size(adj));
    (void) model; (void) pos; (void) removed; (void) added;
}

static void
live_pause_clicked(GtkButton *button, gpointer user_data)
{
    AppState *state = user_data;
    state->live_paused = !state->live_paused;
    gtk_button_set_label(button, state->live_paused ? "Resume" : "Pause");
    live_update_summary(state);
    live_set_status(state, state->live_paused ? "feed paused" : "listening on udp/4729",
                    state->live_paused ? "status-idle" : "status-running");
}

static void
live_selection_changed(GObject *selection, GParamSpec *pspec, gpointer user_data)
{
    AppState *state = user_data;
    guint pos = gtk_single_selection_get_selected(GTK_SINGLE_SELECTION(selection));
    if (state->live_inspector_buf == NULL) return;
    if (pos == GTK_INVALID_LIST_POSITION) {
        gtk_text_buffer_set_text(state->live_inspector_buf,
            "Select a row to inspect its decoded GSMTAP fields.", -1);
        return;
    }
    LiveMsg *m = g_list_model_get_item(G_LIST_MODEL(selection), pos);
    if (m == NULL) return;
    g_autofree char *detail = g_strdup_printf(
        "PACKET %u\n\nTime      %s\nType      %s\nChannel   %s\nARFCN     %u\nTimeslot  %u\nSignal    %d dBm\nDirection %s\nLength    %u bytes\n\nPAYLOAD\n%s",
        m->seq, m->time, m->type, m->ch, m->arfcn, m->ts, m->sig, m->dir,
        m->len, m->payload);
    gtk_text_buffer_set_text(state->live_inspector_buf, detail, -1);
    g_object_unref(m);
    (void) pspec;
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
    GtkWidget *pause  = gtk_button_new_with_label("Pause");
    GtkWidget *follow = gtk_toggle_button_new_with_label("Follow");
    GtkWidget *paned  = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
    GtkWidget *inspector_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GtkWidget *inspector_title = gtk_label_new("PACKET INSPECTOR");
    GtkWidget *inspector = gtk_text_view_new();
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
    gtk_widget_add_css_class(pause,  "verb-button");
    gtk_widget_add_css_class(follow, "verb-button");
    gtk_widget_add_css_class(inspector_box, "live-inspector");
    gtk_widget_add_css_class(inspector_title, "live-inspector-title");
    gtk_widget_add_css_class(view,   "live-table");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(sub),   0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(sub), PANGO_ELLIPSIZE_END);
    gtk_label_set_ellipsize(GTK_LABEL(status), PANGO_ELLIPSIZE_END);
    gtk_label_set_max_width_chars(GTK_LABEL(status), 26);
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
    gtk_box_append(GTK_BOX(head), pause);
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(follow), TRUE);
    gtk_widget_set_tooltip_text(follow, "keep the newest packet in view");
    gtk_box_append(GTK_BOX(head), follow);
    g_signal_connect(follow, "toggled", G_CALLBACK(live_follow_toggled), state);

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
    state->live_scroll = scroll;
    state->live_follow = TRUE;
    g_signal_connect(state->live_store, "items-changed",
                     G_CALLBACK(live_items_changed), state);
    GtkSingleSelection *selection = gtk_single_selection_new(
        G_LIST_MODEL(g_object_ref(state->live_store)));
    gtk_column_view_set_model(GTK_COLUMN_VIEW(view), GTK_SELECTION_MODEL(selection));
    g_signal_connect(selection, "notify::selected",
                     G_CALLBACK(live_selection_changed), state);
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
    gtk_text_view_set_editable(GTK_TEXT_VIEW(inspector), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(inspector), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(inspector), TRUE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(inspector), GTK_WRAP_WORD_CHAR);
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(inspector)),
        "Select a row to inspect its decoded GSMTAP fields.", -1);
    gtk_box_append(GTK_BOX(inspector_box), inspector_title);
    gtk_box_append(GTK_BOX(inspector_box), inspector);
    gtk_paned_set_start_child(GTK_PANED(paned), overlay);
    gtk_paned_set_end_child(GTK_PANED(paned), inspector_box);
    gtk_paned_set_position(GTK_PANED(paned), 850);
    gtk_box_append(GTK_BOX(outer), paned);

    state->live_view         = view;
    state->live_status       = status;
    state->live_button       = start;
    state->live_filter_entry = fentry;
    state->live_summary      = summary;
    state->live_empty        = empty;
    state->live_count        = 0;
    state->live_pause_button = pause;
    state->live_inspector_buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(inspector));
    state->live_paused       = FALSE;
    state->live_socket       = NULL;
    state->live_poll         = 0;
    state->live_hint         = 0;
    state->live_msgs         = NULL;
    state->live_filter       = NULL;

    g_signal_connect(start,  "clicked", G_CALLBACK(live_toggle_clicked), state);
    g_signal_connect(clear,  "clicked", G_CALLBACK(live_clear_clicked), state);
    g_signal_connect(fentry, "changed", G_CALLBACK(live_filter_changed), state);
    g_signal_connect(pause,  "clicked", G_CALLBACK(live_pause_clicked), state);
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

/* ── global radio target ────────────────────────────────────────────────
   wifisting keeps its target in the header, reachable from any page, and
   that is what the panel below is. IMSIsting had the state without a home:
   the cellular modules read $TMP_DIR/target_arfcn and target_plmn, nothing
   ever wrote them, and the only target fields sat inside Casebook where
   they describe a case rather than the radio. So the target was invisible
   and unsettable from anywhere else. */

static void
rtarget_fill_from_state(AppState *state, const char *rat, const char *arfcn,
                        const char *plmn)
{
    /* Only fills gaps: never overwrites something the operator has typed. */
    if (rat != NULL && *rat != '\0' &&
        *casebook_entry(state->rtarget_rat) == '\0')
        gtk_editable_set_text(GTK_EDITABLE(state->rtarget_rat), rat);
    if (arfcn != NULL && *arfcn != '\0' &&
        *casebook_entry(state->rtarget_arfcn) == '\0')
        gtk_editable_set_text(GTK_EDITABLE(state->rtarget_arfcn), arfcn);
    if (plmn != NULL && *plmn != '\0' &&
        *casebook_entry(state->rtarget_plmn) == '\0')
        gtk_editable_set_text(GTK_EDITABLE(state->rtarget_plmn), plmn);
}

static void
rtarget_refresh(AppState *state)
{
    const char *argv[3];
    g_autofree char *script = NULL;
    g_autofree char *out = NULL;
    g_autofree char *rat = NULL;
    g_autofree char *arfcn = NULL;
    g_autofree char *plmn = NULL;
    g_autofree char *text = NULL;

    if (state == NULL || state->rtarget_state_lbl == NULL) return;

    script = module_script_path("02_cell_recon");
    argv[0] = script;
    argv[1] = "--target-tsv";
    argv[2] = NULL;
    out = run_capture(argv);

    if (out != NULL) {
        g_auto(GStrv) lines = g_strsplit(out, "\n", -1);
        for (guint i = 0; lines[i] != NULL; i++) {
            g_auto(GStrv) kv = g_strsplit(lines[i], "\t", 2);
            if (g_strv_length(kv) != 2) continue;
            if (g_strcmp0(kv[0], "rat") == 0)        rat   = g_strdup(kv[1]);
            else if (g_strcmp0(kv[0], "arfcn") == 0) arfcn = g_strdup(kv[1]);
            else if (g_strcmp0(kv[0], "plmn") == 0)  plmn  = g_strdup(kv[1]);
        }
    }

    if (rat == NULL && arfcn == NULL && plmn == NULL) {
        gtk_label_set_text(GTK_LABEL(state->rtarget_state_lbl), "No target set");
        gtk_widget_remove_css_class(state->rtarget_state_lbl, "target-set");
        return;
    }

    text = g_strdup_printf("%s %s%s%s",
                           rat   != NULL ? rat   : "cell",
                           arfcn != NULL ? arfcn : "?",
                           plmn  != NULL ? "  ·  " : "",
                           plmn  != NULL ? plmn : "");
    gtk_label_set_text(GTK_LABEL(state->rtarget_state_lbl), text);
    gtk_widget_add_css_class(state->rtarget_state_lbl, "target-set");
    rtarget_fill_from_state(state, rat, arfcn, plmn);
}

/* Is a case open? Only then does Apply record the target into the case: a
   casebook target lives in a per-case targets.tsv, so there is nothing to
   write to otherwise and the call would fail noisily on every Apply. */
static gboolean
rtarget_case_active(AppState *state)
{
    const char *args[] = { "status", NULL };
    gboolean ok = FALSE;
    g_autofree char *cb = casebook_call(args, &ok);
    g_autofree char *act = ok ? tsv_field(cb, "active_case") : NULL;

    (void) state;
    return act != NULL && *act != '\0' && g_strcmp0(act, "none") != 0;
}

static void rtarget_clear(AppState *state);

static void
rtarget_apply(AppState *state)
{
    const char *rat   = casebook_entry(state->rtarget_rat);
    const char *arfcn = casebook_entry(state->rtarget_arfcn);
    const char *plmn  = casebook_entry(state->rtarget_plmn);
    const char *cell  = casebook_entry(state->rtarget_cell);
    const char *argv[6];
    g_autofree char *script = NULL;
    g_autofree char *out = NULL;

    if (state == NULL || state->rtarget_state_lbl == NULL) return;

    /* Empty arfcn with a RAT is a half-filled form, not a clear. Both empty
       means the operator wants the target gone. */
    if (*arfcn == '\0' && *rat == '\0' && *plmn == '\0') {
        rtarget_clear(state);
        return;
    }
    if (*rat == '\0' || *arfcn == '\0') {
        gtk_label_set_text(GTK_LABEL(state->rtarget_state_lbl),
                           "RAT and ARFCN are both required");
        gtk_widget_remove_css_class(state->rtarget_state_lbl, "target-set");
        return;
    }

    script = module_script_path("02_cell_recon");
    argv[0] = script;
    argv[1] = "--set-target";
    argv[2] = rat;
    argv[3] = arfcn;
    argv[4] = plmn;
    argv[5] = NULL;
    out = run_capture(argv);

    /* A rejected target (an ARFCN out of range, a RAT the converter does not
       know) must not be dressed up as success. */
    if (out != NULL && g_strstr_len(out, -1, "ERROR") != NULL) {
        g_autofree char *line = g_strdup(out);
        g_strstrip(line);
        gtk_label_set_text(GTK_LABEL(state->rtarget_state_lbl), line);
        gtk_widget_remove_css_class(state->rtarget_state_lbl, "target-set");
        append_event(state, line);
        return;
    }

    /* One place to set a target, so one place that records it. The case keeps
       the target it will be reported against; the files above are what the
       modules actually tune to. */
    if (rtarget_case_active(state)) {
        const char *cb_args[] = { "--target-set", rat, plmn, arfcn,
                                  (*cell != '\0') ? cell : "-", NULL };
        gboolean cb_ok = FALSE;
        g_autofree char *cb_out = casebook_call(cb_args, &cb_ok);
        if (cb_out != NULL && *cb_out != '\0') append_event(state, cb_out);
        casebook_refresh(state);
    }

    rtarget_refresh(state);
    append_event(state, "Radio target updated");
}

static void
rtarget_clear(AppState *state)
{
    const char *argv[6];
    g_autofree char *script = NULL;

    if (state == NULL) return;

    gtk_editable_set_text(GTK_EDITABLE(state->rtarget_rat), "");
    gtk_editable_set_text(GTK_EDITABLE(state->rtarget_arfcn), "");
    gtk_editable_set_text(GTK_EDITABLE(state->rtarget_plmn), "");
    gtk_editable_set_text(GTK_EDITABLE(state->rtarget_cell), "");

    /* Remove the stored target too, or the panel would say "no target" while
       every cellular module still read the old one. */
    script = module_script_path("02_cell_recon");
    argv[0] = script;
    argv[1] = "--set-target";
    argv[2] = "";
    argv[3] = "";
    argv[4] = "";
    argv[5] = NULL;
    run_capture(argv);

    /* Forget it in the case too, or the case would keep reporting a target
       the radio no longer has. */
    if (rtarget_case_active(state)) {
        const char *cb_args[] = { "--target-clear", NULL };
        gboolean cb_ok = FALSE;
        g_autofree char *cb_out = casebook_call(cb_args, &cb_ok);
        if (cb_out != NULL && *cb_out != '\0') append_event(state, cb_out);
        casebook_refresh(state);
    }

    if (state->rtarget_state_lbl != NULL) {
        gtk_label_set_text(GTK_LABEL(state->rtarget_state_lbl), "No target set");
        gtk_widget_remove_css_class(state->rtarget_state_lbl, "target-set");
    }
}

static void
rtarget_apply_clicked(GtkButton *button, gpointer user_data)
{
    (void) button;
    rtarget_apply((AppState *) user_data);
}

static void
rtarget_clear_clicked(GtkButton *button, gpointer user_data)
{
    (void) button;
    rtarget_clear((AppState *) user_data);
}

static void
rtarget_toggled(GtkToggleButton *button, gpointer user_data)
{
    AppState *state = user_data;
    gboolean on = gtk_toggle_button_get_active(button);

    if (state == NULL || state->rtarget_revealer == NULL) return;
    if (on) rtarget_refresh(state);
    gtk_revealer_set_reveal_child(GTK_REVEALER(state->rtarget_revealer), on);
}

/* Open the panel from anywhere and put a target in it - what the Targets
   list's Set target does. */
void
imsisting_target_offer(AppState *state, const char *rat, const char *arfcn,
                       const char *plmn, const char *cell)
{
    if (state == NULL) return;

    if (state->rtarget_rat != NULL)
        gtk_editable_set_text(GTK_EDITABLE(state->rtarget_rat), rat ? rat : "");
    if (state->rtarget_arfcn != NULL)
        gtk_editable_set_text(GTK_EDITABLE(state->rtarget_arfcn), arfcn ? arfcn : "");
    if (state->rtarget_plmn != NULL)
        gtk_editable_set_text(GTK_EDITABLE(state->rtarget_plmn), plmn ? plmn : "");
    if (state->rtarget_cell != NULL)
        gtk_editable_set_text(GTK_EDITABLE(state->rtarget_cell), cell ? cell : "");

    rtarget_apply(state);

    if (state->rtarget_button != NULL)
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(state->rtarget_button), TRUE);
}

static GtkWidget *
build_target_panel(AppState *state)
{
    GtkWidget *revealer = gtk_revealer_new();
    GtkWidget *panel = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *title = gtk_label_new("TARGET");
    GtkWidget *apply = gtk_button_new_with_label("Apply");
    GtkWidget *clear = gtk_button_new_with_label("Clear");

    state->rtarget_rat = gtk_entry_new();
    state->rtarget_arfcn = gtk_entry_new();
    state->rtarget_plmn = gtk_entry_new();
    state->rtarget_cell = gtk_entry_new();
    state->rtarget_state_lbl = gtk_label_new("No target set");

    gtk_entry_set_placeholder_text(GTK_ENTRY(state->rtarget_rat), "RAT");
    gtk_entry_set_placeholder_text(GTK_ENTRY(state->rtarget_arfcn), "ARFCN");
    gtk_entry_set_placeholder_text(GTK_ENTRY(state->rtarget_plmn), "PLMN");
    gtk_entry_set_placeholder_text(GTK_ENTRY(state->rtarget_cell), "Cell ID");
    gtk_entry_set_max_length(GTK_ENTRY(state->rtarget_rat), 6);
    gtk_entry_set_max_length(GTK_ENTRY(state->rtarget_arfcn), 12);
    gtk_entry_set_max_length(GTK_ENTRY(state->rtarget_plmn), 10);
    gtk_entry_set_max_length(GTK_ENTRY(state->rtarget_cell), 24);
    gtk_widget_set_size_request(state->rtarget_rat, 110, -1);
    gtk_widget_set_size_request(state->rtarget_arfcn, 90, -1);
    gtk_widget_set_size_request(state->rtarget_plmn, 100, -1);
    gtk_widget_set_size_request(state->rtarget_cell, 110, -1);

    gtk_widget_add_css_class(panel, "target-panel");
    gtk_widget_add_css_class(title, "target-title");
    gtk_widget_add_css_class(state->rtarget_state_lbl, "target-value");
    gtk_widget_add_css_class(apply, "verb-button");
    gtk_widget_add_css_class(apply, "primary");
    gtk_widget_add_css_class(clear, "verb-button");

    gtk_label_set_xalign(GTK_LABEL(state->rtarget_state_lbl), 0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(state->rtarget_state_lbl),
                            PANGO_ELLIPSIZE_END);
    gtk_widget_set_hexpand(state->rtarget_state_lbl, TRUE);
    gtk_widget_set_valign(state->rtarget_state_lbl, GTK_ALIGN_CENTER);

    gtk_box_append(GTK_BOX(panel), title);
    gtk_box_append(GTK_BOX(panel), state->rtarget_rat);
    gtk_box_append(GTK_BOX(panel), state->rtarget_arfcn);
    gtk_box_append(GTK_BOX(panel), state->rtarget_plmn);
    gtk_box_append(GTK_BOX(panel), state->rtarget_cell);
    gtk_box_append(GTK_BOX(panel), apply);
    gtk_box_append(GTK_BOX(panel), clear);
    gtk_box_append(GTK_BOX(panel), state->rtarget_state_lbl);

    g_signal_connect(apply, "clicked", G_CALLBACK(rtarget_apply_clicked), state);
    g_signal_connect(clear, "clicked", G_CALLBACK(rtarget_clear_clicked), state);

    gtk_revealer_set_transition_type(GTK_REVEALER(revealer),
                                     GTK_REVEALER_TRANSITION_TYPE_SLIDE_DOWN);
    gtk_revealer_set_transition_duration(GTK_REVEALER(revealer), 180);
    gtk_revealer_set_child(GTK_REVEALER(revealer), panel);
    state->rtarget_revealer = revealer;

    return revealer;
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
    /* The layout's measured floor is ~448px plus the 52px titlebar. Without a
       minimum the window manager lets the user shrink past it, and the Events
       drawer - the last child of a box that cannot scroll - is then allocated
       below the bottom edge instead of the page shrinking. The drawer carries
       a 170px minimum of its own plus its toolbar; this is the cheap guard
       that keeps it reachable. */
    gtk_widget_set_size_request(state->window, -1, 500);

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

    /* Packed after Events, so it lands to its left: Target then Events, the
       order wifisting uses. Reachable from every page, which is the whole
       point of putting the target here. */
    GtkWidget *rtarget_btn = gtk_toggle_button_new_with_label("Target");
    gtk_widget_set_tooltip_text(rtarget_btn,
        "the radio target the cellular modules tune to — accessible from any page");
    g_signal_connect(rtarget_btn, "toggled",
                     G_CALLBACK(rtarget_toggled), state);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(header), rtarget_btn);
    state->rtarget_button = rtarget_btn;

    gtk_window_set_titlebar(GTK_WINDOW(state->window), header);

    /* Live cellular state, read from the modules themselves. */
    gtk_box_append(GTK_BOX(root), build_status_strip(state));
    gtk_box_append(GTK_BOX(root), build_target_panel(state));

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
    /* Kept as a box child: an overlay child was tried and never rendered
       (the revealer reported its revealed height but GtkOverlay allocated it
       nothing), so the drawer vanished while its header toggle showed as
       active. The window's own minimum height below is what keeps it on
       screen instead. */
    gtk_box_append(GTK_BOX(root), paned);

    /* ---- permanent tabs, in order, before any module page ----
       These carry a bare label rather than a closable tab, so they cannot be
       closed. Module pages are appended after them and do close. */
    gtk_notebook_append_page(GTK_NOTEBOOK(state->notebook),
        create_dashboard_page(state), gtk_label_new("Dashboard"));
    gtk_notebook_append_page(GTK_NOTEBOOK(state->notebook),
        create_live_traffic_page(state), gtk_label_new("Live Traffic"));
    gtk_notebook_append_page(GTK_NOTEBOOK(state->notebook),
        create_casebook_page(state), gtk_label_new("Casebook"));
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

/* Each module lists its submenus in order. Entry 0 is always the Overview,
   whose spec becomes the QUICK ACTIONS row; the rest are themed groups of
   verbs drawn from the module's own vocabulary. Verbs that are plumbing
   (--menu, --selftest, --status-tsv, --yes, --quiet) are deliberately absent:
   they belong to the launcher and the test runner, not to a person clicking
   buttons. Spec syntax is documented on ModuleSubmenuEntry above. */

static ModuleSubmenuEntry deps_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      /* Split into a CHECK card and an INSTALL card: looking is safe and
         installing is privileged, and the page should say so rather than
         putting a read-only refresh next to three root actions.

         The three install buttons carry the '!' privilege marker BEFORE the
         colon, which is where the spec grammar expects it. They previously
         had it only on the end of the label ("Install Missing!"), so
         privileged was always false and the installs ran as the operator,
         failing on every write. With the marker here they go through
         `pkexec <script> <verb>`, which is what the polkit rule in
         tools/49-imsisting.rules matches on. */
      "#CHECK|--check-versions:Refresh|#INSTALL|--install-missing!:Install Missing!|--install-all!:Install Full Toolchain!|--install-pip!:Install Pipx Tools!" },
    { "Packages",
      "system-software-install-symbolic",
      "#INSTALL|~--install-package!:Install Package|#AUDIT|--missing-only:Missing Only|--report:Report" },
    { "System",
      "preferences-system-symbolic",
      "--distro-info:Distro Info" },
};
static ModuleSubmenuEntry radio_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "#DEVICE|--list-tsv:List SDRs|--caps-tsv:Capabilities|#CAPTURE|--record:Record IQ" },
    { "Tuning",
      "preferences-system-symbolic",
      "#DEVICE|--select=0|#TUNING|--set-freq=942|--set-gain=40|--set-rate=2000000" },
    { "Ownership",
      "channel-secure-symbolic",
      "#STATUS|--lock-status-tsv:Lock Status|#CONTROL|--lock-claim:Claim|--lock-release:Release|--lock-recover:Recover Stale" },
    { "Diagnostics",
      "utilities-terminal-symbolic",
      "#PROCESSES|--processes-tsv:SDR Processes|#PLAN|--band-check=942|--plan:Plan" },
};
/* ── Cell Recon · Targets ───────────────────────────────────────────
   Laid out like wifisting's Wi-Fi Recon target list: a toolbar naming what
   is selected with Refresh / Export on the right, then one row per surveyed
   cell with a Set target action. Rows come from the module's --list-tsv.

   An empty store is drawn as an empty state, not as an error: "run a scan
   first" is information, and it belongs in the list rather than in a red
   dump in the output card. */
typedef struct {
    AppState   *state;
    const char *module_id;
    GtkWidget  *list;        /* GtkListBox holding the cells */
    GtkWidget  *selected;    /* toolbar label: current target */
} CrecTargets;

static void
crec_targets_clear(GtkWidget *list)
{
    GtkWidget *child = gtk_widget_get_first_child(list);
    while (child != NULL) {
        GtkWidget *next = gtk_widget_get_next_sibling(child);
        gtk_list_box_remove(GTK_LIST_BOX(list), child);
        child = next;
    }
}

static void
crec_targets_empty(GtkWidget *list, const char *text)
{
    GtkWidget *row = gtk_list_box_row_new();
    GtkWidget *lbl = gtk_label_new(text);

    gtk_widget_add_css_class(lbl, "cell-empty");
    gtk_label_set_xalign(GTK_LABEL(lbl), 0.0f);
    gtk_widget_set_margin_top(lbl, 14);
    gtk_widget_set_margin_bottom(lbl, 14);
    gtk_widget_set_margin_start(lbl, 6);
    gtk_widget_set_margin_end(lbl, 6);
    gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), lbl);
    gtk_list_box_row_set_activatable(GTK_LIST_BOX_ROW(row), FALSE);
    gtk_list_box_row_set_selectable(GTK_LIST_BOX_ROW(row), FALSE);
    gtk_list_box_append(GTK_LIST_BOX(list), row);
}

static void
crec_set_target_clicked(GtkButton *button, gpointer user_data)
{
    CrecTargets *t = user_data;
    const char *rat   = g_object_get_data(G_OBJECT(button), "cell-rat");
    const char *arfcn = g_object_get_data(G_OBJECT(button), "cell-arfcn");
    const char *plmn  = g_object_get_data(G_OBJECT(button), "cell-plmn");
    const char *cell  = g_object_get_data(G_OBJECT(button), "cell-id");

    if (t == NULL || t->selected == NULL) return;

    /* Handing it to the global panel is what makes Set target mean
       something: the panel is the writer for the shared target the cellular
       modules read, and it stays reachable from every page afterwards. */
    imsisting_target_offer(t->state, rat, arfcn, plmn, cell);

    if (rat != NULL && arfcn != NULL)
        gtk_label_set_text(GTK_LABEL(t->selected),
            g_strdup_printf("Target set: %s %s", rat, arfcn));
}

/* One surveyed cell, in the same order wifisting uses: what it is, then the
   identifiers, then the numbers worth comparing down the list. */
static void
crec_targets_add_row(CrecTargets *t, char **f)
{
    /* rat gen arfcn freq_mhz plmn mcc mnc operator country cell_id
       tac_lac band rsrp_dbm cipher source ts */
    const char *identity = (f[7] != NULL && *f[7] != '\0') ? f[7] : f[4];
    g_autofree char *sub = g_strdup_printf("(%s · ARFCN %s)",
                                           (f[9] && *f[9]) ? f[9] : "?",
                                           (f[2] && *f[2]) ? f[2] : "?");
    g_autofree char *meta =
        g_strdup_printf("%s %s  •  %s MHz  •  %s  •  %s dBm  •  %s",
                        (f[0] && *f[0]) ? f[0] : "cell",
                        (f[1] && *f[1]) ? f[1] : "",
                        (f[3] && *f[3]) ? f[3] : "?",
                        (f[11] && *f[11]) ? f[11] : "band ?",
                        (f[12] && *f[12]) ? f[12] : "?",
                        (f[13] && *f[13]) ? f[13] : "unknown");
    g_autofree char *full = g_strdup_printf("Target set: %s  %s", identity, sub);

    GtkWidget *row     = gtk_list_box_row_new();
    GtkWidget *content = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    GtkWidget *text    = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *top     = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *name    = gtk_label_new(identity);
    GtkWidget *ident   = gtk_label_new(sub);
    GtkWidget *metalbl = gtk_label_new(meta);
    GtkWidget *icon    = gtk_image_new_from_icon_name("network-wireless-symbolic");
    GtkWidget *pick    = gtk_button_new_with_label("Set target");

    gtk_image_set_pixel_size(GTK_IMAGE(icon), 28);

    gtk_label_set_xalign(GTK_LABEL(name), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(ident), 0.0f);
    gtk_label_set_xalign(GTK_LABEL(metalbl), 0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(name), PANGO_ELLIPSIZE_END);
    gtk_label_set_max_width_chars(GTK_LABEL(name), 38);

    gtk_widget_add_css_class(row,     "cell-row");
    gtk_widget_add_css_class(name,    "cell-name");
    gtk_widget_add_css_class(ident,   "cell-ident");
    gtk_widget_add_css_class(metalbl, "cell-meta");
    gtk_widget_add_css_class(pick,    "verb-button");
    gtk_widget_add_css_class(icon,    "cell-icon");

    gtk_widget_set_hexpand(text, TRUE);
    gtk_widget_set_valign(pick, GTK_ALIGN_CENTER);
    gtk_box_append(GTK_BOX(top), name);
    gtk_box_append(GTK_BOX(top), ident);
    gtk_box_append(GTK_BOX(text), top);
    gtk_box_append(GTK_BOX(text), metalbl);
    gtk_box_append(GTK_BOX(content), icon);
    gtk_box_append(GTK_BOX(content), text);
    gtk_box_append(GTK_BOX(content), pick);
    gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), content);

    g_object_set_data_full(G_OBJECT(pick), "cell-label", g_strdup(full), g_free);
    /* Carried on the button so Set target can hand the global panel a real
       target instead of only relabelling itself. */
    {
        g_autofree char *rat = g_ascii_strdown(f[0] != NULL ? f[0] : "", -1);
        g_object_set_data_full(G_OBJECT(pick), "cell-rat",
                               g_strdup(rat), g_free);
        g_object_set_data_full(G_OBJECT(pick), "cell-arfcn",
                               g_strdup(f[2] != NULL ? f[2] : ""), g_free);
        g_object_set_data_full(G_OBJECT(pick), "cell-plmn",
                               g_strdup(f[4] != NULL ? f[4] : ""), g_free);
        g_object_set_data_full(G_OBJECT(pick), "cell-id",
                               g_strdup(f[9] != NULL ? f[9] : ""), g_free);
    }
    g_signal_connect(pick, "clicked", G_CALLBACK(crec_set_target_clicked), t);

    gtk_list_box_append(GTK_LIST_BOX(t->list), row);
}

static void
crec_targets_fill(CrecTargets *t)
{
    g_autofree char *script = module_script_path(t->module_id);
    const char *argv[3] = { script, "--list-tsv", NULL };
    g_autofree char *out = NULL;
    int rows = 0;

    crec_targets_clear(t->list);

    out = run_capture(argv);
    if (out != NULL && *out != '\0') {
        g_auto(GStrv) lines = g_strsplit(out, "\n", -1);
        for (guint i = 0; lines[i] != NULL; i++) {
            g_auto(GStrv) f = g_strsplit(lines[i], "\t", 17);
            if (g_strv_length(f) < 16) continue;
            if (g_strcmp0(f[0], "rat") == 0) continue;   /* header row */
            crec_targets_add_row(t, f);
            rows++;
        }
    }
    if (rows == 0)
        crec_targets_empty(t->list,
            "No cells surveyed yet — run Start scan, then Refresh.");
}

static void
crec_targets_refresh_clicked(GtkButton *button, gpointer user_data)
{
    (void) button;
    crec_targets_fill((CrecTargets *) user_data);
}

static void
crec_targets_export_clicked(GtkButton *button, gpointer user_data)
{
    CrecTargets *t = user_data;
    g_autofree char *script = module_script_path(t->module_id);
    const char *argv[3] = { script, "--export", NULL };

    (void) button;
    append_event(t->state, "Exporting the cell survey…");
    run_capture(argv);
    crec_targets_fill(t);
}

static GtkWidget *
crec_build_targets(AppState *state, const char *module_id,
                   GtkWidget *status, GtkTextBuffer *out)
{
    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *inner = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    GtkWidget *bar   = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *selected = gtk_label_new("No target selected");
    GtkWidget *export_btn = gtk_button_new_with_label("Export CSV");
    GtkWidget *refresh   = gtk_button_new_with_label("Refresh");
    GtkWidget *scroll = gtk_scrolled_window_new();
    GtkWidget *list   = gtk_list_box_new();
    CrecTargets *t = g_new0(CrecTargets, 1);

    (void) status;

    t->state = state;
    t->module_id = module_id;
    t->list = list;
    t->selected = selected;

    gtk_widget_set_margin_top(inner, 16);
    gtk_widget_set_margin_bottom(inner, 16);
    gtk_widget_set_margin_start(inner, 16);
    gtk_widget_set_margin_end(inner, 16);
    gtk_widget_set_hexpand(inner, TRUE);

    gtk_label_set_xalign(GTK_LABEL(selected), 0.0f);
    gtk_widget_set_hexpand(selected, TRUE);
    gtk_widget_add_css_class(selected, "cell-selected");

    gtk_box_append(GTK_BOX(bar), selected);
    gtk_box_append(GTK_BOX(bar), export_btn);
    gtk_box_append(GTK_BOX(bar), refresh);
    gtk_box_append(GTK_BOX(inner), bar);

    gtk_list_box_set_selection_mode(GTK_LIST_BOX(list), GTK_SELECTION_NONE);
    gtk_widget_add_css_class(list, "cell-list");
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), list);
    gtk_widget_set_vexpand(scroll, TRUE);
    gtk_box_append(GTK_BOX(inner), scroll);

    if (out != NULL)
        gtk_box_append(GTK_BOX(inner), build_output_card(out));

    g_signal_connect(refresh, "clicked",
                     G_CALLBACK(crec_targets_refresh_clicked), t);
    g_signal_connect(export_btn, "clicked",
                     G_CALLBACK(crec_targets_export_clicked), t);
    g_object_set_data_full(G_OBJECT(inner), "crec-targets", t, g_free);

    crec_targets_fill(t);

    gtk_box_append(GTK_BOX(outer), inner);
    return outer;
}

static ModuleSubmenuEntry crec_entries[] = {
    /* Laid out like wifisting's Wi-Fi Recon page - the same job on a
       different radio. An Overview carrying the scan, then a view per
       question the operator asks: what is out there, which channel, which
       network, and how do I get the data out. The Overview splits into a
       CONTROLS card and a SURVEY card, the shape wifisting uses for
       "start it" versus "read the result". */
    { "Overview",
      "dialog-information-symbolic",
      "#CONTROLS|--scan:Start scan" },
    /* The surveyed cells get their own list view, the way wifisting's Targets
       view does, instead of two buttons that print TSV into the output card. */
    { "Targets",
      "edit-find-symbolic",
      NULL,
      crec_build_targets },
    { "Channel",
      "network-wireless-symbolic",
      "#CHANNEL|--arfcn=gsm 1" },
    { "Network",
      "network-workgroup-symbolic",
      "#NETWORK|--plmn=001-01" },
    { "Export",
      "document-save-symbolic",
      "#EXPORT|--export:Export|--clear:Clear Survey" },
};
static ModuleSubmenuEntry gtap_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "#LIVE|--listen:Listen Live|#OFFLINE|--read={capture}" },
    { "Decode",
      "document-open-symbolic",
      "--decode-tsv:Decoded TSV|--identities-tsv:Identities" },
    { "Headers",
      "utilities-terminal-symbolic",
      "--build-header:Build Header|--parse-header:Parse Header" },
    { "Export",
      "document-save-symbolic",
      "--export-pcap:Export PCAP" },
};
static ModuleSubmenuEntry tmap_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "#SURVEY|--survey:Start Survey|#SESSIONS|--list-tsv:Sessions|--history:History" },
    { "GPS",
      "find-location-symbolic",
      "--start-gpsd:Start gpsd|--gps-quality-tsv:GPS Quality" },
    { "Export",
      "document-save-symbolic",
      "--export-kml:Export KML|--export-csv:Export CSV|--export-geojson:Export GeoJSON" },
    { "Manage",
      "preferences-system-symbolic",
      "--clear:Clear" },
};
static ModuleSubmenuEntry fkit_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--capability:Capability|--guard-check:Guard Check|--scenarios:Scenarios" },
    { "Emitter",
      "media-record-symbolic",
      "--emit:Emit Sample" },
};
static ModuleSubmenuEntry gair_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--decode-pcap={capture}|--decode-si:Decode SI|--decode-sch:Decode SCH" },
    { "Cipher",
      "channel-secure-symbolic",
      "--cipher-audit:Cipher Audit|--a5-1-keystream:A5/1 Keystream" },
    { "Paging & Identity",
      "system-search-symbolic",
      "--paging-group=001010000000001|--imsi-exposure-tsv:IMSI Exposure" },
};
static ModuleSubmenuEntry gatk_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--imsi-catcher-sequence:IMSI Catcher Sequence|--paging-race:Paging Race|--kc-recovery:Kc Recovery" },
    { "Identity",
      "auth-smartcard-symbolic",
      "--build-identity-request:Build Identity Request|--classmark|--classmark-downgrade:Classmark Downgrade" },
    { "C1",
      "preferences-system-symbolic",
      "--c1=-100 -90 33 5|--plan:Plan|--plan-tsv:Plan TSV" },
};
static ModuleSubmenuEntry uair_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--decode-pcap={capture}|--decode-sib:Decode SIB|--sib-fields:SIB Fields" },
    { "Integrity",
      "channel-secure-symbolic",
      "--aka-flow:AKA Flow|--count-i:COUNT-I|--integrity-tsv:Integrity TSV" },
    { "MAC",
      "network-receive-symbolic",
      "--mac-input:MAC Input|--sib6-carriers:SIB6 Carriers" },
    { "Frequencies",
      "preferences-system-symbolic",
      "--mhz=2140|--uarfcn=10700" },
};
static ModuleSubmenuEntry latt_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--decode-nas:Decode NAS|--encode-attach:Encode Attach|--ue-stack:UE Stack" },
    { "Identity",
      "auth-smartcard-symbolic",
      "--imsi-decode:Decode IMSI|--imsi-encode:Encode IMSI|--identity-exposure:Identity Exposure" },
};
static ModuleSubmenuEntry lair_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "#CONTROL|--start:Start|--stop:Stop|#STATUS|--status:Status" },
    { "Decode",
      "document-open-symbolic",
      "--decode-sib:Decode SIB|--paging-frame:Paging Frame" },
    { "Tools",
      "preferences-system-symbolic",
      "--earfcn=6300|--power-ref:Power Reference|--gen-enb-conf:Generate eNB Config" },
};
static ModuleSubmenuEntry lcore_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--decode-gtp-c:Decode GTP-C|--decode-gtp-u:Decode GTP-U|--decode-diameter:Decode Diameter" },
    { "Attacks",
      "security-high-symbolic",
      "#FORGE|--gtp-modify-bearer:Modify Bearer|--gtp-csr-forge:Forge CSR|#AUDIT|--gtpdoor-detect:Detect GTPdoor|--cdr-fraud-check:CDR Fraud Check|--fs20-audit:FS.20 Audit" },
    { "Build",
      "document-new-symbolic",
      "--build-air:Build AIR|--build-ulr:Build ULR|--s1ap" },
    { "Recon",
      "system-search-symbolic",
      "--surface:Surface|--require-core:Require Core|--plan:Plan" },
};
static ModuleSubmenuEntry nair_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "#CONTROL|--start:Start|--stop:Stop|#STATUS|--status:Status" },
    { "Decode",
      "document-open-symbolic",
      "--decode-mib:Decode MIB|--decode-sib1:Decode SIB1" },
    { "Signals",
      "network-wireless-symbolic",
      "--ssb:SSB|--prach:PRACH|--pci=0 0" },
    { "Tools",
      "preferences-system-symbolic",
      "--arfcn=640000|--gen-gnb-conf:Generate gNB Config|--gen-core-conf:Generate Core Config" },
};
static ModuleSubmenuEntry ncore_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--nf-list:List NFs|--nf-discovery=NRF|--ue-id-pair:UE Id Pair" },
    { "Decode",
      "document-open-symbolic",
      "#NAS|--decode-nas-5gs:Decode NAS-5GS|#NGAP|--decode-ngap:Decode NGAP|#PFCP|--decode-pfcp:Decode PFCP|#GTPU|--decode-gtpu:Decode GTP-U|--gtpu-header:GTP-U Header|#IDENTITY|--decode-5g-guti:Decode 5G-GUTI" },
    { "Crypto",
      "channel-secure-symbolic",
      "--aka-flow:AKA Flow|--kseaf:KSEAF" },
    { "Rules",
      "preferences-system-symbolic",
      "--pfcp-rules:PFCP Rules|--plan:Plan" },
};
static ModuleSubmenuEntry suci_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--parse-suci:Parse SUCI|--build-suci:Build SUCI|--audit:Audit" },
    { "Conceal",
      "channel-secure-symbolic",
      "--conceal:Conceal|~--deconceal|--genkey:Generate Key|--hkdf:HKDF" },
    { "MSIN",
      "auth-smartcard-symbolic",
      "--msin-decode:Decode MSIN|--msin-encode:Encode MSIN" },
};
static ModuleSubmenuEntry dwn_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--detect:Detect|--path=steer-down|--causes:Causes" },
    { "Build",
      "security-high-symbolic",
      "--build-security-mode:Build Security Mode|--null-cipher-table:Null Cipher Table|--reject-cause=22 EMM|--plan:Plan" },
};
static ModuleSubmenuEntry sim_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--parse-apdu:Parse APDU|--build-apdu:Build APDU|--get-response:Get Response" },
    { "Read",
      "document-open-symbolic",
      "--read-binary:Read Binary|--read-record:Read Record|--select-fid=3F00|--file-id" },
    { "Decode",
      "auth-smartcard-symbolic",
      "--decode-iccid:Decode ICCID|--decode-imsi:Decode IMSI|--decode-ad:Decode AD" },
    { "OTA",
      "document-send-symbolic",
      "--parse-ota:Parse OTA|--spi=1|--rsp:RSP|--plan:Plan" },
};
static ModuleSubmenuEntry pcap_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--summary={capture}|--list={capture}|--extract={capture} 1 1" },
    { "Flows",
      "network-transmit-receive-symbolic",
      "--conversations:Conversations|--hierarchy:Hierarchy" },
    { "Identity",
      "auth-smartcard-symbolic",
      "--identities:Identities|--ident-list:Identity List" },
    { "Manage",
      "preferences-system-symbolic",
      "#SAMPLE|--build-sample:Build Sample|#MANAGE|--clear:Clear" },
};
static ModuleSubmenuEntry imsi_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--audit:Audit|--report:Report|--harvest={capture}" },
    { "Analysis",
      "system-search-symbolic",
      "--cross:Cross-reference|--map:Map|--marlin:Marlin|--marlin-msgs:Marlin Messages" },
    { "Identity",
      "auth-smartcard-symbolic",
      "--identities:Identities|--subscribers-tsv:Subscribers TSV|--exposure-tsv:Exposure TSV" },
    { "Manage",
      "preferences-system-symbolic",
      "--redact:Redact|--clear:Clear" },
};
static ModuleSubmenuEntry caud_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--from-pcap={capture}|--score:Score|--table:Table" },
    { "SMC",
      "channel-secure-symbolic",
      "--parse-smc:Parse SMC|--downgrade-check:Downgrade Check" },
    { "Sessions",
      "document-open-symbolic",
      "#LOAD|--sessions-load:Load Sessions|~--session|#MANAGE|--clear:Clear" },
};
static ModuleSubmenuEntry gcve_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--list-cves:List CVEs|--probe=IDENTITY|--run-cve=CVE-2019-15962" },
    { "Results",
      "x-office-document-symbolic",
      "--list-findings:List Findings|--runs-tsv:Runs TSV" },
    { "Helpers",
      "preferences-system-symbolic",
      "--bcd:BCD|--kc:Kc|--plan:Plan" },
};
static ModuleSubmenuEntry lcve_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--list-cves:List CVEs|--probe=RRC|--run-cve=CVE-2017-6975" },
    { "Results",
      "x-office-document-symbolic",
      "--runs-tsv:Runs TSV" },
    { "Helpers",
      "preferences-system-symbolic",
      "--teid=1|--plmn=001-01|--plan:Plan" },
};
static ModuleSubmenuEntry ncve_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--list-cves:List CVEs|--probe=NRF|--run-cve=CVE-2020-11197" },
    { "Results",
      "x-office-document-symbolic",
      "--list-findings:List Findings|--runs-tsv:Runs TSV" },
    { "Helpers",
      "preferences-system-symbolic",
      "--snssai=010203|--plan:Plan" },
};
static ModuleSubmenuEntry kchn_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "#INSPECT|--list-chains:List Chains|--show-chain=survey|#EXECUTE|--run=survey" },
    { "Execution",
      "media-playback-start-symbolic",
      "--run-multi:Run Multiple|--dry-run:Dry Run|--keep-going:Keep Going|--run-status-tsv:Run Status" },
    { "Control",
      "preferences-system-symbolic",
      "--pause:Pause|--resume:Resume" },
    { "Authoring",
      "document-new-symbolic",
      "--add-chain:Add Chain|--runs-tsv:Runs TSV" },
};
static ModuleSubmenuEntry tana_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--flows={capture}|--classify={capture}|--features:Features" },
    { "Fingerprints",
      "system-search-symbolic",
      "#ADD|--fingerprint-add:Add Fingerprint|#REFS|--refs-tsv:References TSV|#MANAGE|--clear-refs:Clear References" },
};
static ModuleSubmenuEntry rff_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--features:Features|--classify:Classify|~--csi-parse" },
    { "CSI",
      "network-wireless-symbolic",
      "--csi-motion:CSI Motion|--transient:Transient" },
    { "Signatures",
      "system-search-symbolic",
      "#ADD|--sig-add:Add Signature|#SIGS|--sigs-tsv:Signatures TSV|#MANAGE|--clear-sigs:Clear Signatures" },
};
static ModuleSubmenuEntry macl_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--decode-mac:Decode MAC|--rnti-track:Track RNTI|--sched-parse:Parse Scheduling" },
    { "Tables",
      "preferences-system-symbolic",
      "--lcid-table:LCID Table|--rnti-table:RNTI Table" },
    { "Analysis",
      "system-search-symbolic",
      "~--dci|--sched-pattern:Scheduling Pattern|--integrity-gap:Integrity Gap" },
};
static ModuleSubmenuEntry nasf_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--decode-nas:Decode NAS|--causes:Causes|--storm-profile:Storm Profile" },
    { "Model",
      "system-search-symbolic",
      "--cost-model:Cost Model|--procedure-mix:Procedure Mix|--rate={capture}" },
    { "Transmit",
      "media-playback-start-symbolic",
      "--transmit:Transmit|--i-have-a-lab-and-authorisation:Lab Authorisation" },
    { "Planning",
      "preferences-system-symbolic",
      "--plan:Plan" },
};
static ModuleSubmenuEntry ss7_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--surface:Surface|--grx-recon:GRX Recon|--detect:Detect" },
    { "Build",
      "document-new-symbolic",
      "--build-ati:Build ATI|--build-sri:Build SRI|--build-sri-sm:Build SRI-SM" },
    { "Decode",
      "document-open-symbolic",
      "--decode-map:Decode MAP|--decode-msu:Decode MSU|--decode-tcap:Decode TCAP" },
    { "Detection",
      "dialog-warning-symbolic",
      "--fallback-detect:Fallback Detect|--flow:Flow" },
    { "Options",
      "preferences-system-symbolic",
      "#PARAMS|--opcode=1|--ssn=6|#FORMAT|--pc-format:PC Format|#CHECKS|--require-stp:Require STP|--visited-plmn:Visited PLMN|#PLAN|--plan:Plan" },
};
static ModuleSubmenuEntry cdns_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--decode-dns:Decode DNS|--detect:Detect|--resolver-discovery:Resolver Discovery" },
    { "Build",
      "document-new-symbolic",
      "--build-query:Build Query|--build-response:Build Response|--alter" },
    { "Options",
      "preferences-system-symbolic",
      "--pco=8021|--plan:Plan" },
};
static ModuleSubmenuEntry pgt_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--detect:Detect|--paging-parse:Parse Paging|--piercer-correlate:Piercer Correlate" },
    { "Model",
      "system-search-symbolic",
      "--torpedo-model:Torpedo Model|--po=001010000000001 2 gsm|--plan:Plan" },
};
static ModuleSubmenuEntry vims_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--ims-registration:IMS Registration|--sip-parse:Parse SIP|--detect-keystream-reuse:Keystream Reuse" },
    { "Attacks",
      "security-high-symbolic",
      "#FLOOD|--sip-flood:SIP Flood|#SPOOF|--register-spoof:Register Spoof|#EXPOSURE|--imei-leak:IMEI Leak|#DEMO|--revolte-demo:ReVoLTE Demo" },
    { "Keystream",
      "channel-secure-symbolic",
      "--keystream-recover:Recover Keystream|--imp4gt-model:IMP4GT Model" },
    { "Planning",
      "preferences-system-symbolic",
      "--plan:Plan" },
};
static ModuleSubmenuEntry simd_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--score:Score|--defence-checklist:Defence Checklist|--signals:Signals" },
    { "Inspection",
      "auth-smartcard-symbolic",
      "--ef-ad:EF AD|--esim-profile-parse:Parse eSIM Profile|--pin-state:PIN State" },
};
static ModuleSubmenuEntry jamd_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "~--analyse|--counters:Counters|--report:Report" },
    { "Analysis",
      "system-search-symbolic",
      "--characterise:Characterise|--discriminate:Discriminate|~--noise-floor" },
};
static ModuleSubmenuEntry slic_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--nssai-parse:Parse NSSAI|--detect:Detect|--surface:Surface" },
    { "Encode / Decode",
      "document-open-symbolic",
      "--decode-s-nssai:Decode S-NSSAI|--encode-s-nssai:Encode S-NSSAI|--sst-table:SST Table|--nas5gs:NAS 5GS" },
    { "Policy",
      "preferences-system-symbolic",
      "--isolation-check:Isolation Check|--selection:Selection|--plan:Plan" },
};
static ModuleSubmenuEntry bbnd_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--triage|--layers:Layers|--corpus:Corpus" },
    { "ASN.1",
      "document-open-symbolic",
      "--asn1-dec:ASN.1 Decode|--asn1-len:ASN.1 Length|--nas-hdr:NAS Header" },
    { "Fuzz",
      "security-high-symbolic",
      "--mutate:Mutate|--plan:Plan" },
};
static ModuleSubmenuEntry vowi_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--walk:Walk|--epdg=001 01|--types:Types" },
    { "IKE",
      "channel-secure-symbolic",
      "--ike-parse:Parse IKE|--ike-build:Build IKE" },
    { "EAP",
      "auth-smartcard-symbolic",
      "--eap-parse:Parse EAP|--eap-build:Build EAP|--nai=001010000000001 310 260" },
    { "Crypto",
      "security-high-symbolic",
      "--integrity:Integrity|--encr:Encryption|--plan:Plan" },
};
static ModuleSubmenuEntry femt_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "~--pci-conflict|--iuh:IuH|--tr069-audit:TR-069 Audit" },
    { "CSG",
      "network-server-symbolic",
      "--csg-decode:Decode CSG|--csg-encode:Encode CSG|--plan:Plan" },
};
static ModuleSubmenuEntry ussd_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--detect:Detect|--mmi=*#21#|--ss-codes:SS Codes" },
    { "Codec",
      "document-open-symbolic",
      "--pack:Pack|--unpack:Unpack|--build:Build" },
    { "Planning",
      "preferences-system-symbolic",
      "--plan:Plan" },
};
static ModuleSubmenuEntry tgeo_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--ta=1|--trilaterate:Trilaterate|--cells:Cells" },
    { "Planning",
      "preferences-system-symbolic",
      "--plan:Plan" },
};
static ModuleSubmenuEntry sbap_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--nf-paths:NF Paths|--nrf|--token-pivot:Token Pivot" },
    { "HTTP/2",
      "network-transmit-receive-symbolic",
      "--h2-parse:Parse HTTP/2|--h2-build:Build HTTP/2|--h2-types:HTTP/2 Types" },
    { "JWT",
      "channel-secure-symbolic",
      "--jwt|--jwt-audit:JWT Audit" },
    { "Attacks",
      "security-high-symbolic",
      "#ATTACK|--rapid-reset:Rapid Reset|~--scope|#OPTIONS|--settings:Settings|--plan:Plan" },
};
static ModuleSubmenuEntry otasm_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "~--parse-packet|--packet:Packet|--counter-check:Counter Check" },
    { "SPI",
      "auth-smartcard-symbolic",
      "--spi-build:Build SPI|~--spi|--plan:Plan" },
};
static ModuleSubmenuEntry lipr_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--interfaces:Interfaces|--architecture:Architecture|--score:Score" },
    { "Probe",
      "system-search-symbolic",
      "--iface=X1|--report:Report|--plan:Plan" },
};
static ModuleSubmenuEntry rans_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "~--leak-check|--mode=mocn|--eplmn=001-01,001-02" },
    { "PLMN",
      "network-server-symbolic",
      "--plmn-decode:Decode PLMN|--plmn-encode:Encode PLMN|--plan:Plan" },
};
static ModuleSubmenuEntry capi_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--openapi:OpenAPI|--authz-matrix:Authz Matrix|--report:Report" },
    { "Attacks",
      "security-high-symbolic",
      "--stuffing:Credential Stuffing|--token-bucket:Token Bucket|--jwt-audit:JWT Audit" },
    { "Compare",
      "system-search-symbolic",
      "--diff:Diff|--plan:Plan" },
};
static ModuleSubmenuEntry iot_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--decode-sib1:Decode SIB1|--nprach:NPRACH|--npss-nss:NPSS/NSS" },
    { "Tools",
      "preferences-system-symbolic",
      "--to-mhz=0" },
};
static ModuleSubmenuEntry lpp_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--list-pids:List PIDs|--parse-position:Parse Position|--detect-forgery:Detect Forgery" },
    { "Build",
      "document-new-symbolic",
      "--build-header:Build Header|--build-position:Build Position|--decode-header:Decode Header" },
};
static ModuleSubmenuEntry wifioff_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--auth-flow:Auth Flow|--lwa-config:LWA Config|--epdg-fqdn" },
    { "Certificates",
      "channel-secure-symbolic",
      "--cert-thumb:Cert Thumbprint|--validate-cert:Validate Cert" },
};
static ModuleSubmenuEntry oran_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--assess:Assess|--interfaces:Interfaces|--e2sm:E2SM" },
    { "Attacks",
      "security-high-symbolic",
      "#XAPP|--xapp-attack:xApp Attack|--xapp-authority:xApp Authority|#INTERFACE|--a1-put:A1 PUT|--e2-control:E2 Control" },
    { "Planning",
      "preferences-system-symbolic",
      "--plan:Plan" },
};
static ModuleSubmenuEntry ntn_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--sib19:SIB19|--doppler=1000 100 45|--range=500" },
    { "Link",
      "network-wireless-symbolic",
      "--feeder:Feeder|--koffset:K-Offset|--ta:TA" },
    { "Planning",
      "preferences-system-symbolic",
      "--plan:Plan" },
};
static ModuleSubmenuEntry gprs_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "#TABLE|--gea-table:GEA Table|#ATTACK|--gea-downgrade:GEA Downgrade|#PARAMS|--gea=1" },
    { "APN",
      "network-server-symbolic",
      "--apn-decode:Decode APN|--apn-encode:Encode APN|--apn-ie:APN IE" },
    { "PDP",
      "preferences-system-symbolic",
      "--pdp-ie:PDP IE|--plan:Plan" },
};
static ModuleSubmenuEntry slnk_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--relay-check:Relay Check|--sci1a:SCI1-A|--its" },
    { "Config",
      "preferences-system-symbolic",
      "--l2id=000001|--pfi=1|--subchannels:Subchannels|--freq-bits:Frequency Bits" },
    { "Planning",
      "preferences-system-symbolic",
      "--plan:Plan" },
};
static ModuleSubmenuEntry stk_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--parse:Parse|--build:Build|--audit:Audit" },
    { "SAT",
      "auth-smartcard-symbolic",
      "--sat-audit:SAT Audit|--sat-cmds:SAT Commands|--simjacker-detect:Simjacker Detect" },
    { "Command",
      "document-send-symbolic",
      "--cmd=21|--result=00|--device=81|--plan:Plan" },
};
static ModuleSubmenuEntry n3g_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--classify:Classify|--detect-note:Detect Note" },
    { "Radio",
      "network-wireless-symbolic",
      "--tetra:TETRA|--dmr:DMR|--gsmr:GSM-R|--tdma:TDMA|--tea:TEA" },
    { "Planning",
      "preferences-system-symbolic",
      "--plan:Plan" },
};
static ModuleSubmenuEntry bexp_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--list-cves:List CVEs|--emulate:Emulate|--states:States" },
    { "Forge",
      "security-high-symbolic",
      "--forge-identity:Forge Identity|--forge-reg-accept:Forge Reg Accept|--forge-reg-reject:Forge Reg Reject" },
    { "Analysis",
      "system-search-symbolic",
      "--cve=CVE-2023-33042|--cp-check:CP Check|--l2-case:L2 Case|--l2-corpus:L2 Corpus" },
    { "Planning",
      "preferences-system-symbolic",
      "--plan:Plan" },
};
static ModuleSubmenuEntry nrj_entries[] = {
    { "Overview",
      "dialog-information-symbolic",
      "--exploits:Exploits|--exploit=rrc-setup-crash|--descramble:Descramble" },
    { "MAC",
      "network-receive-symbolic",
      "#DECODE|--mac-pdu:MAC PDU|--mac-sub:MAC Subheader|#LCID|--lcid=0|--lcid-table:LCID Table" },
    { "RNTI",
      "preferences-system-symbolic",
      "--ra-rnti-nr:RA-RNTI NR|--ra-rnti-lte:RA-RNTI LTE|--dci|--plan:Plan" },
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
