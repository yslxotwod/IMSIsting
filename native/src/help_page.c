/* ==================================================================== *
 *  help_page.c — the Help page.
 *
 *  A subject list down the left, and for each subject a column of
 *  sections down the right. A section is a centred title above a card —
 *  the same rectangle a module page groups its content in — so a Help
 *  subject is read the way a module's own page is read.
 *
 *  It replaced a single static string, HELP_TEXT, that main1.c rendered
 *  through text_page(): one 79-line scroll, which meant the answer to
 *  "where does loot/ go" and the answer to "what does exit code 3 mean"
 *  were the same scroll position and neither was findable without reading
 *  the whole thing.
 *
 *  The section/card split is not decoration. Prose and a list want
 *  different rhythm: a paragraph is a block of sentences to be read
 *  through, while a list of folders or exit codes is scanned, and giving
 *  both the same line spacing makes the list unreadable. So the body of a
 *  section is written as blocks in one string, and the renderer decides
 *  per block whether it is prose, a term/definition list, a bullet list or
 *  verbatim output — then spaces it accordingly. The block syntax is at
 *  help_render_block() below; it is the only thing to know when editing
 *  the text in this file.
 *
 *  This lives in its own translation unit rather than in main1.c because
 *  main1.c is the file every change to this interface lands in, and a body
 *  of reference text that changes for unrelated reasons should not sit in
 *  the middle of it. Nothing here reads the rest of the interface: no
 *  AppState, no module registry, no output console.
 *
 *  Nothing here is generated and nothing here is read from disk. If a fact
 *  below stops being true of the tree, this file is the bug.
 * ==================================================================== */

#include <gtk/gtk.h>
#include <string.h>

/* One section: a title that sits above a card, and the bodies inside it. */
typedef struct {
    const char *title;
    const char *body;
} HelpSection;

/* One subject in the left-hand list. */
typedef struct {
    const char *name;
    const char *icon;
    const char *lead;              /* one line under the header, optional */
    const HelpSection *sections;
    int n_sections;
} HelpView;

/* ─────────────────────────── the text ─────────────────────────── *
 *
 *  In a body:
 *
 *    blank line        ends a block
 *    - item            a bullet list, one line per item
 *    | line            verbatim: commands, paths, output
 *    term  definition  a term/definition list, the two separated by two
 *                      or more spaces. A following line with no such gap
 *                      continues the definition above it.
 *    anything else     prose. Lines are joined into one paragraph and
 *                      re-wrapped to the window, so hard-wrapping the
 *                      source costs the reader nothing.
 *
 *  Terms should stay under about 30 characters; past that the definition
 *  column gets squeezed and the list stops being scannable.
 */

static const HelpSection OVERVIEW_SECTIONS[] = {
    { "WHAT IT IS",
      "A GTK4 view over standalone shell modules. The interface never owns\n"
      "an action: every button in this window is a shell command you could\n"
      "have typed yourself, and the button shows you that command before it\n"
      "runs it. Nothing is locked behind the GUI and nothing is hidden by\n"
      "it." },

    { "WHERE THINGS LIVE",
      "modules/          61 shell modules. Each is a complete CLI and runs\n"
      "                  on its own, with no GUI and no daemon.\n"
      "native/           this interface: main1.c, help_page.c, meson.build,\n"
      "                  and resources/ for the icons and the stylesheet\n"
      "tools/            shared Python, and the gates that check the tree\n"
      "module_index.tsv  the generated catalogue: what the sidebar, the\n"
      "                  search and the verb checker all read\n"
      "docs/             the roadmap and the per-module notes\n"
      "cases/            one directory per case, with its timeline\n"
      "loot/             per-module output, indexed by the Casebook\n"
      "tmp/              live SDR caches, shared between modules mid-run\n"
      "logs/             one log per run\n"
      "captures/         baseband captures: IQ files and pcaps\n"
      "state/            what survives a restart: pins, recent, ui, settings" },

    { "THE CONTRACT EVERY MODULE KEEPS",
      "A module is finished when all four of these are true. They are not\n"
      "aspirational: the guard report in Settings measures them.\n"
      "\n"
      "- The protocol construction is real: spec-derived, and asserted\n"
      "  either against a published vector or against an independent\n"
      "  implementation. Never against the module's own output.\n"
      "- The transmit path is written: waveform, timing, burst structure,\n"
      "  the SDR calls. Not a paragraph describing them.\n"
      "- With no radio attached it fails honestly: non-zero exit, names the\n"
      "  missing device, prints no success line.\n"
      "- The guard reports it honest. Never silent, never fabricated.\n"
      "\n"
      "A module that cannot meet the last two is reported as such rather\n"
      "than quietly returning a clean-looking empty result. When a module\n"
      "refuses, that refusal is the feature working." },

    { "WHERE TO GO NEXT",
      "Getting around     how the window is laid out\n"
      "Modules            what a module page is made of\n"
      "Running a verb     how a command runs, and where its output goes\n"
      "Radio & transmit   what the TX bar means, and why modules refuse\n"
      "Casebook           cases, targets, evidence and hashing\n"
      "Troubleshooting    what to run when a module misbehaves" },
};

static const HelpSection NAV_SECTIONS[] = {
    { "THE TEN PAGES",
      "Dashboard       every module as a card on one grid, by category\n"
      "Live Traffic    what the sensors are seeing right now\n"
      "Casebook        cases, targets, evidence, alerts, sensors, reports\n"
      "Map             cells and observations on one plane\n"
      "Fleet           the remote nodes, and what each one can do\n"
      "Stats           module and collection counts\n"
      "Notifications   events raised by modules and by the Casebook\n"
      "Help            this page\n"
      "Settings        what the toolkit does by default, in six views\n"
      "Workflows       twelve questions, each opened into the steps" },

    { "THE DRAWER",
      "Move the pointer to the left edge of the window and it slides out,\n"
      "over the page rather than beside it. The top of the drawer lists the\n"
      "ten pages in the order above; below that, the module catalogue.\n"
      "Choosing a row switches page and closes the drawer. Moving the\n"
      "pointer away closes it too.\n"
      "\n"
      "The drawer is an overlay on purpose. If it took width from the page,\n"
      "the page would resize every time it opened and every card would\n"
      "reflow: the drawer would be felt as a layout change rather than as\n"
      "navigation." },

    { "THE TARGET PANEL",
      "The right-hand panel, toggled from the header. It holds the current\n"
      "target and the case counters. Like the drawer it floats over the\n"
      "page rather than narrowing it.\n"
      "\n"
      "A target set here is what modules default to when they are asked for\n"
      "an MCC/MNC, a cell, or a subscriber." },

    { "SEARCH",
      "Ctrl+K focuses the header field. It matches across every page,\n"
      "module, verb and category, and Enter opens the first match. Escape\n"
      "closes the results if they are open." },

    { "PANELS, NOT PAGES",
      "Opening a module raises it as a panel over the dashboard rather than\n"
      "replacing it. The dashboard stays underneath, and Escape — or the\n"
      "panel's close button — returns to it.\n"
      "\n"
      "That is why there is no tab strip and no back button: there is\n"
      "nothing to go back to, because nothing was left behind." },

    { "KEYBOARD",
      "Ctrl+K   focus the search field\n"
      "Enter    open the first search match\n"
      "Escape   close the search results, then the open module panel\n"
      "Click    a single click on a dashboard card opens that module" },
};

static const HelpSection MODULE_SECTIONS[] = {
    { "THE ELEVEN CATEGORIES",
      "RECON                what is on the air and in range\n"
      "RADIO                the air interfaces, 2G through 5G\n"
      "ACCESS               getting onto a network: attach, registration\n"
      "CORE NETWORK         the network behind the RAN, and its interfaces\n"
      "SIM / IDENTITY       the card, its applets, and the identifiers\n"
      "BASEBAND / DEVICE    the modem itself, its firmware and its buses\n"
      "TRACKING             following a subscriber or a device\n"
      "ANALYSIS             decoding and correlating what was captured\n"
      "EXPLOIT KITS         ready-made attack chains\n"
      "INTERCEPT / CARRIER  lawful-intercept and carrier-API surfaces\n"
      "SYSTEM               the toolkit's own plumbing\n"
      "\n"
      "A module's category is not decoration: it sets the colour of the\n"
      "module's card, its header and its menu, so it is visible at a glance\n"
      "which part of the stack a page belongs to." },

    { "ANATOMY OF A MODULE PAGE",
      "Header    the module's icon, name, category and a status pill. The\n"
      "          pill reads Idle, Running, Done, Error or Missing, and it\n"
      "          reflects the last run rather than a guess.\n"
      "Views     the left-hand column. Every module declares its own list:\n"
      "          Overview, Air interface, Identity, Ciphers, and so on. It\n"
      "          is the module's own grouping, not a fixed template poured\n"
      "          over every module alike.\n"
      "Content   the stack on the right. Switching a view swaps the whole\n"
      "          content area, and each view keeps its own output buffer, so\n"
      "          a result does not follow you into an unrelated view.\n"
      "Output    the console at the bottom, shared by every view of that\n"
      "          page, so a result stays on screen while you navigate.\n"
      "\n"
      "Where a view is a list with per-row actions — Cell Recon's surveyed\n"
      "cells, for instance — the module supplies its own builder instead of\n"
      "a row of buttons." },

    { "VERBS",
      "A module's actions are its verbs: --scan, --decode-sib, --transmit.\n"
      "Each is a real command-line flag, not a GUI invention. A view groups\n"
      "the common ones as buttons under named headings: #CONTROLS, #STATUS,\n"
      "#TRANSMIT, and so on.\n"
      "\n"
      "A verb marked with a tilde in the module's own list needs an\n"
      "argument, so it is not given a plain button. It lives in the\n"
      "generated verb selector instead, where you supply the arguments.\n"
      "\n"
      "If a verb exists in a module but is not reachable from this window,\n"
      "that is a bug in the interface, not a hidden feature.\n"
      "./tools/check-verbs.sh finds them and names them UNPLACED." },
};

static const HelpSection RUN_SECTIONS[] = {
    { "WHAT A RUN IS",
      "A subprocess of the module's own shell script. The interface adds\n"
      "nothing to the command line and passes no argument you did not\n"
      "supply:\n"
      "\n"
      "| <repo>/modules/<module>.sh <verb> [arguments]\n"
      "\n"
      "A button's tooltip is the verb it will pass, so hovering tells you the\n"
      "flag without running anything. The console echoes the run as one `$`\n"
      "line naming the module, the verb and the arguments the button\n"
      "supplied — not the script's full path. {capture} in that line has\n"
      "already been replaced by the newest file in captures/, and {root} by\n"
      "the project directory, both resolved at press time.\n"
      "\n"
      "To see the exact argv, run the module yourself in a terminal. Nothing\n"
      "is rewritten on the way through." },

    { "BUTTONS AND ENTRIES",
      "A view's preset buttons come from the module's own table. Each carries\n"
      "a verb, the arguments it passes, and a label.\n"
      "\n"
      "Underneath them, every documented verb that does not already have a\n"
      "button is given one, taken from the generated module index. A verb\n"
      "whose argument cannot be defaulted is marked with a leading ~ in the\n"
      "module's own spec, and those render as an argument entry beside a Run\n"
      "button rather than as a plain button — that is why a verb like\n"
      "--transmit has somewhere to put its ARFCN.\n"
      "\n"
      "This is the guarantee that no documented capability is unreachable\n"
      "from the GUI. If one is, it is a bug, and tools/check-verbs.sh names\n"
      "it UNPLACED." },

    { "WHERE OUTPUT GOES",
      "Into the page's output console, which is a text view rather than a\n"
      "terminal: selectable, copyable, and never lost by scrolling away from\n"
      "it.\n"
      "\n"
      "When the subprocess ends the console gets a closing line, `-- done\n"
      "(exit 0)` or `-- failed (exit N)`, and the run is written to the\n"
      "active case's timeline as an INFO or HIGH event when a case is open.\n"
      "With no case open nothing is recorded, silently and on purpose.\n"
      "\n"
      "No evidence is hashed automatically. Indexing a large IQ file stays an\n"
      "explicit action in the Casebook, because hashing means reading the\n"
      "whole file." },

    { "WHAT THE STATUS PILL MEANS",
      "Idle       nothing has run on this page yet\n"
      "Running    the subprocess is alive\n"
      "Done       it exited 0\n"
      "Error      it exited non-zero\n"
      "Missing    the module or the verb was not found" },

    { "EXIT CODES",
      "0   success\n"
      "1   the module rejected its arguments, or the operation failed\n"
      "2   usage error: an unknown verb, or a missing required argument\n"
      "3   a required device is absent. This is the honest-failure code:\n"
      "    the module names the device and prints no success line.\n"
      "\n"
      "An exit code of 3 is a correct result, not a malfunction. It means\n"
      "the computation was done and the radio was not there to receive it." },

    { "STOPPING A RUN",
      "Closing the module panel does not kill the subprocess. The module\n"
      "finishes and its output is kept.\n"
      "\n"
      "Long captures are meant to outlive the window being open, so closing\n"
      "the panel is a view action, not a cancel." },
};

static const HelpSection RADIO_SECTIONS[] = {
    { "WHAT ACTUALLY STOPS A TRANSMISSION",
      "Two things, and it is worth being exact about which of them is\n"
      "enforcement.\n"
      "\n"
      "- The device probe is enforcement. A verb that would key a radio\n"
      "  asks the radio a question first, and exits 3 if nothing answers.\n"
      "  Nothing is transmitted and no success line is printed.\n"
      "- --tx-ack is a record, not a gate. The verb prints the operator's\n"
      "  acknowledgement: the licence statement, the acceptance that these\n"
      "  vectors are indistinguishable to a network or a regulator from a\n"
      "  real attack, and the admission that they have never been fired\n"
      "  against a radio. Nothing in the tree reads it, and no code path\n"
      "  checks that it was printed.\n"
      "\n"
      "There is no arming step and no confirmation dialog anywhere in this\n"
      "window. --tx-ack is what its own output calls it: the record that the\n"
      "decision was made, written down where the case timeline can keep it.\n"
      "A transmit verb that refuses is refusing because the radio did not\n"
      "answer, not because the acknowledgement is missing." },

    { "THE VECTOR VERBS",
      "The four vector verbs — --vector-imsi-catcher, --vector-a5-downgrade,\n"
      "--vector-tmsi-deanon and --vector-kc-recovery — compute and print a\n"
      "full TSV plan: every message, burst, frame and channel. They drive no\n"
      "radio and they require no acknowledgement. Their output carries a\n"
      "`gated` label saying the schedule is computed rather than keyed, and\n"
      "that label describes what the verb did rather than refusing to do\n"
      "it: the verb succeeds, and the plan is the deliverable.\n"
      "\n"
      "That is why a transmit view is useful with no radio attached at all.\n"
      "The schedule, the frame numbers and the burst contents are computed,\n"
      "printed, and checked against the specifications they cite." },

    { "HONEST FAILURE",
      "With no transmit-capable SDR, a transmit verb exits 3, names the\n"
      "device it wanted, and prints no success line. It does not silently\n"
      "return an empty result, and it does not print a plausible fake one.\n"
      "\n"
      "| ERROR  no transmit-capable SDR is attached\n"
      "| FOUND  the hackrf tools are installed, but hackrf_info reports no\n"
      "|        device: No HackRF boards found.\n"
      "\n"
      "The run then ends with a NOTRANSMITTED line: the waveform was built\n"
      "and written to loot/, but nothing was keyed." },

    { "THE GUARD CLASSES",
      "honest-fail      a non-zero exit, or an explicit ERROR or MISSING\n"
      "                 line. Exit 0 with an error line is still honest.\n"
      "silent-fail      a non-zero exit, and it says nothing at all\n"
      "FABRICATED       exit 0 with no error line: it claims a success it\n"
      "                 cannot have had\n"
      "timeout          it did not finish inside its budget\n"
      "module-missing   the module or the verb does not exist\n"
      "\n"
      "The guard in Settings sorts every gated verb into one of these and\n"
      "prints the totals. Only the first is acceptable: the bar is zero\n"
      "fabricated and zero silent, and a classifier that always answered\n"
      "honest-fail would be as useless as one that never did, so the\n"
      "module's own selftest checks it in both directions." },

    { "THE INDEPENDENT-ASSERTION RULE",
      "A transmit chain is checked against something that is not this tree:\n"
      "a published specification, a captured vector, or another\n"
      "implementation's decoder run over this tree's waveform.\n"
      "\n"
      "Asserting a codec against its own output proves only that it is\n"
      "self-consistent. Where a construction is unverified, the module says\n"
      "so in its own output rather than leaving you to discover it: a\n"
      "module that prints an unverified reading of a specification is\n"
      "telling you exactly how far its confidence goes, which is the useful\n"
      "part." },
};

static const HelpSection CASEBOOK_SECTIONS[] = {
    { "CASES",
      "A case is a directory under cases/ with an id, a title and a\n"
      "timeline. Every completed run is appended to the active case's\n"
      "timeline automatically, with the module, the verb, the arguments,\n"
      "the exit code and the time. Opening a case makes it active, and\n"
      "modules write into it from then on." },

    { "TARGETS",
      "Operators, subscribers, cells and devices a case is about. The\n"
      "target panel in the header edits the current one.\n"
      "\n"
      "Modules that take an MCC/MNC, a cell id or a subscriber default to\n"
      "the active target rather than to a placeholder." },

    { "EVIDENCE",
      "Every file under loot/ is indexed. Search matches the file name and\n"
      "the module that produced it; Sort orders by Name, Size, Newest or\n"
      "Module. Open — or a double click — opens the file as a closable tab\n"
      "inside the Casebook rather than in an external application, so a\n"
      "capture stays next to the run that produced it.\n"
      "\n"
      "The index is rebuilt from disk on every refresh. An entry never\n"
      "outlives the scan that found it, so a deleted file disappears from\n"
      "the list instead of pointing at nothing." },

    { "HASHES",
      "Evidence files can be hashed into the case record. The hash is what\n"
      "makes a capture defensible later: it ties the bytes in loot/ to the\n"
      "timeline entry that says where they came from, and it survives the\n"
      "file being moved or renamed." },

    { "ALERTS AND SENSORS",
      "Alerts are raised by modules and by the sensors. A sensor is a\n"
      "long-running listener — a paging tracker, an air-interface monitor —\n"
      "that feeds the Notifications page and the case timeline while it\n"
      "runs. The Live Traffic page shows what the sensors currently see." },

    { "REPORTS",
      "A case can be written out as a report: the timeline, the evidence\n"
      "index with its hashes, and the targets.\n"
      "\n"
      "Reports are files in the case directory, not rows in a separate\n"
      "database, so a case can be handed over by copying one directory." },
};

static const HelpSection FILES_SECTIONS[] = {
    { "DIRECTORIES",
      "loot/<module>/    every module writes its own output here, in its\n"
      "                  own subdirectory. This is what the Casebook\n"
      "                  indexes as evidence.\n"
      "tmp/              live caches, shared between modules during a run:\n"
      "                  the last scan, the current cell list, an open SDR\n"
      "                  handle.\n"
      "logs/             one log per run, named by module and time. The\n"
      "                  output console shows the current run; the log is\n"
      "                  the whole thing, including what scrolled past.\n"
      "captures/         baseband captures: IQ files and pcaps. The large\n"
      "                  artifacts.\n"
      "state/            the only directory deliberately persistent across\n"
      "                  restarts.\n"
      "module_index.tsv  a generated file. Do not hand-edit it.\n"
      "assets/           icons, and the wordlists modules use.\n"
      "\n"
      "tmp/ is scratch. Nothing in it is evidence and nothing in it is\n"
      "expected to survive: two modules reading the same SDR coordinate\n"
      "through here, rather than both opening it and fighting over it." },

    { "WHAT SURVIVES A RESTART",
      "ui.tsv         window and view preferences\n"
      "recent.tsv     recently opened modules\n"
      "pins.tsv       starred modules\n"
      "settings.tsv   environment overrides\n"
      "casebook/      case records and the evidence index\n"
      "killchain/     chain run state\n"
      "ss7_map/       SS7 map state\n"
      "\n"
      "All of it lives under state/. Deleting state/ resets the interface\n"
      "to defaults without touching any evidence." },

    { "module_index.tsv",
      "A generated file. Do not hand-edit it: tools/gen-module-index.sh\n"
      "rebuilds it from each module's own --__index_probe__ output, which\n"
      "is why the sidebar, the search and the verb checker all agree about\n"
      "what a module can do.\n"
      "\n"
      "If it looks stale, regenerate rather than patch." },
};

static const HelpSection CLI_SECTIONS[] = {
    { "RUNNING A MODULE",
      "| ./modules/07_gsm_attack.sh --vector-imsi-catcher 262 01\n"
      "| ./modules/10_lte_air.sh --decode-sib <hex>\n"
      "| ./modules/05_field_kit.sh --guard-check\n"
      "\n"
      "Each module answers --help with its verbs, --selftest with its own\n"
      "checks, and --status-tsv with a machine-readable summary of what is\n"
      "implemented versus handed off." },

    { "THE GATES",
      "run-selftests.sh      run every module's --selftest. --all also\n"
      "                      lists modules without one; passing 02 13\n"
      "                      restricts to those numbers;\n"
      "                      SELFTEST_TIMEOUT=600 raises the budget for\n"
      "                      the slow ones.\n"
      "check-paths.sh        every path and table entry resolves\n"
      "check-verbs.sh        every documented verb is reachable. --json\n"
      "                      for machines, --list to see where each verb\n"
      "                      is reached from\n"
      "gen-module-index.sh   regenerate module_index.tsv\n"
      "\n"
      "All of them live under tools/." },

    { "SHARED PYTHON",
      "gsm_crypto.py       COMP128, TUAK, A5/1-4, MILENAGE, DPA\n"
      "gsm_mod.py          GSM channel coding and GMSK modulation\n"
      "casebook.py         the case store the GUI and the CLIs both read\n"
      "gen-module-icons.py icon generation for the module pages\n"
      "img2ansi.py         image to ANSI conversion\n"
      "gen-banner.sh       the ASCII banner\n"
      "\n"
      "All of them live under tools/, and each is an ordinary file you can\n"
      "read." },

    { "BUILDING THE GUI",
      "| cd native && meson setup builddir && ninja -C builddir\n"
      "\n"
      "Then run ./imsisting.sh, which sets up the icon theme and the paths\n"
      "the interface expects. The binary is not standalone: it needs the\n"
      "launcher's environment to find its icons and its modules." },

    { "READING A REFUSAL",
      "A module that exits 3 is telling you which device is missing. A\n"
      "module that exits 2 is telling you which argument you got wrong.\n"
      "\n"
      "Neither is a crash, and both are exact — which is the point of the\n"
      "contract." },
};

static const HelpSection HW_SECTIONS[] = {
    { "SDRS",
      "The tree drives what the installed stack can see, and captures raw\n"
      "IQ only where the vendor CLI can write it: hackrf_transfer for a\n"
      "HackRF, rtl_sdr for an RTL-SDR, bladeRF-cli, LimeUtil, uhd for a\n"
      "USRP, and iio_readdev for a PlutoSDR over USB or Ethernet. SoapySDR\n"
      "is enumerated because a board that speaks it should be visible, but\n"
      "SoapySDRUtil cannot capture to a file, so no capture runs through it.\n"
      "gr-gsm's own transceiver is the GSM path.\n"
      "modules/00_deps.sh reports what is present on this machine, and\n"
      "Settings shows the same facts rather than a second opinion.\n"
      "\n"
      "Full-duplex transmit needs a full-duplex radio. Several modules say\n"
      "so explicitly: one radio cannot transmit and receive the same ARFCN\n"
      "at once, so a receive-and-inject attack wants two radios, or one\n"
      "with a duplexer." },

    { "TOOLS THE TREE USES",
      "gr-gsm        grgsm_scanner, grgsm_livemon, grgsm_decode,\n"
      "              grgsm_trx\n"
      "GNU Radio     the DSP blocks behind the decoders\n"
      "libosmocore   installed at runtime; some modules assert against its\n"
      "              encoders as an independent implementation, which is\n"
      "              what makes those assertions worth anything\n"
      "srsRAN        LTE cell search and decoding\n"
      "Wireshark     pcap interpretation\n"
      "osmocom       the SIM and core-network side" },

    { "WHAT IS TESTED",
      "Nothing in this tree has been verified against a real radio on a\n"
      "real network. Every over-the-air path is written and reviewed, not\n"
      "proven.\n"
      "\n"
      "What has been verified is narrower and is stated exactly where it\n"
      "applies: codecs against published vectors or against another\n"
      "implementation's encoders, and protocol constructions against the\n"
      "specifications they cite.\n"
      "\n"
      "The README splits tested from untested in detail. Read it before\n"
      "filing a bug: a module refusing for want of a radio is working as\n"
      "designed." },

    { "NO-RADIO MODE",
      "Most of the tree is useful without hardware. Decoding, analysis, the\n"
      "ciphers, the protocol builders, the vector plans and the selftests\n"
      "all run on a laptop.\n"
      "\n"
      "The modules that cannot are the ones that refuse, and they name what\n"
      "they wanted." },
};

static const HelpSection TROUBLE_SECTIONS[] = {
    { "1. RUN THE MODULE'S OWN SELFTEST",
      "| ./modules/<module>.sh --selftest\n"
      "\n"
      "It works with no radio attached and usually names the problem\n"
      "itself. A selftest failure is a bug in the tree, not in your setup." },

    { "2. RUN THE WHOLE SUITE",
      "| ./tools/run-selftests.sh\n"
      "\n"
      "If a module reports rc=124, that is timeout's exit code, not a logic\n"
      "failure: the module was slower than its budget. Re-run it with\n"
      "SELFTEST_TIMEOUT=600 before treating it as broken." },

    { "3. CHECK THE GATES",
      "| ./tools/check-paths.sh\n"
      "| ./tools/check-verbs.sh\n"
      "\n"
      "check-paths finds a moved file or a stale table entry. check-verbs\n"
      "finds a verb no longer reachable from the GUI: if it names one\n"
      "UNPLACED, the verb exists in the module but no view exposes it,\n"
      "which is a real gap in the interface." },

    { "4. READ THE OUTPUT CONSOLE",
      "A module that refuses prints ERROR and FOUND lines naming what is\n"
      "missing.\n"
      "\n"
      "A module that exits 3 without a radio is doing exactly what the\n"
      "contract requires, and there is nothing to fix." },

    { "5. CONFIRM THE DEPENDENCIES",
      "| ./modules/00_deps.sh\n"
      "\n"
      "The first thing a module checks is whether its tools exist. A\n"
      "missing binary is reported by name." },

    { "THE COMMON NON-PROBLEMS",
      "The module exited 3       a device is absent. Correct behaviour.\n"
      "Nothing was transmitted   the TX acknowledgement is absent, or no\n"
      "                          radio is attached. The plan is still the\n"
      "                          output, and it is complete.\n"
      "A capture is empty        check whether the module needs to be told\n"
      "                          which band to scan before it can find\n"
      "                          anything.\n"
      "The dashboard is stale    the module list is generated. Rebuild it\n"
      "                          with tools/gen-module-index.sh." },

    { "IF THE INTERFACE ITSELF LOOKS WRONG",
      "Delete state/ui.tsv to reset the layout. That file holds only view\n"
      "preferences; no evidence lives in it.\n"
      "\n"
      "If the window opens and no module list appears, module_index.tsv is\n"
      "missing or unreadable. Regenerate it rather than editing it." },
};

static const HelpSection LEGAL_SECTIONS[] = {
    { "THE SHORT VERSION",
      "Intercept and transmit only on networks you own or have written\n"
      "permission to test. Receiving is regulated too: in most\n"
      "jurisdictions, intercepting a communication you are not a party to\n"
      "is an offence whether or not you transmit anything." },

    { "WHY THE TRANSMIT PATHS ARE RECORDED",
      "The honest-failure contract and the guard report are not ceremony:\n"
      "they exist so that a module cannot report a success it did not have,\n"
      "and so that a module which cannot reach hardware has to say which\n"
      "device is missing instead of returning an empty result.\n"
      "\n"
      "The acknowledgement is a different kind of thing, and it is a weaker\n"
      "one. It does not block anything: printing it is a deliberate act, and\n"
      "nothing checks that it happened. Its value is that reading it forces\n"
      "the decision to be made explicitly and gives the case timeline a\n"
      "record of when it was.\n"
      "\n"
      "Nothing here can tell whether you are authorised to be on a\n"
      "frequency. That is the operator's, and the toolkit is built on the\n"
      "assumption that it was settled before anything was run." },

    { "WHAT THE TOOLKIT DOES NOT DO FOR YOU",
      "It does not check whether you are allowed to be on a frequency. It\n"
      "does not know which network you are pointed at. It does not obtain\n"
      "consent.\n"
      "\n"
      "Those are yours, before you run anything on the air." },

    { "GOOD PRACTICE",
      "- Use a faraday cage or a shielded box with your own test network.\n"
      "- Use a test PLMN — MCC 001, or your regulator's test allocation —\n"
      "  rather than an operator's.\n"
      "- Keep the radio's power at the minimum that reaches your own test\n"
      "  equipment. Jamming a live network is a different offence from\n"
      "  intercepting it, and it is much easier for the operator to notice.\n"
      "- Record what you did and when. The Casebook exists partly for this:\n"
      "  a timeline with hashed evidence is what makes an authorised test\n"
      "  defensible afterwards.\n"
      "\n"
      "docs/ carries the roadmap and the per-module notes, including what\n"
      "is verified versus what is written but untested." },
};

#define N_SECTIONS(a) ((int)G_N_ELEMENTS(a))

static const HelpView HELP_VIEWS[] = {
    { "Overview", "dialog-information-symbolic",
      "A cellular security research toolkit: 2G/GSM, 3G/UMTS, 4G/LTE and\n"
      "5G/NR, plus the core network, the SIM, and the carrier-side\n"
      "interfaces around them. 61 modules in 11 categories.",
      OVERVIEW_SECTIONS, N_SECTIONS(OVERVIEW_SECTIONS) },

    { "Getting around", "view-grid-symbolic",
      "The window is a notebook of ten pages, a drawer that lists them\n"
      "plus every module, and two panels that float over the page.",
      NAV_SECTIONS, N_SECTIONS(NAV_SECTIONS) },

    { "Modules", "system-software-install-symbolic",
      "61 modules, each a self-contained shell script with its own CLI, its\n"
      "own --selftest and its own --status-tsv. This window is a view over\n"
      "them, never a wrapper that hides them.",
      MODULE_SECTIONS, N_SECTIONS(MODULE_SECTIONS) },

    { "Running a verb", "media-playback-start-symbolic",
      "Every run in this window is a subprocess of the module's own shell\n"
      "script, with the arguments the button or the selector supplied.",
      RUN_SECTIONS, N_SECTIONS(RUN_SECTIONS) },

    { "Radio & transmit", "network-wireless-symbolic",
      "Anything that puts energy on the air is treated differently from\n"
      "anything that only listens, and the difference is visible in the\n"
      "interface rather than buried in a convention.",
      RADIO_SECTIONS, N_SECTIONS(RADIO_SECTIONS) },

    { "Casebook & evidence", "folder-symbolic",
      "The Casebook is the persistent half of the toolkit: it owns\n"
      "everything that must survive a restart and be attributable later.",
      CASEBOOK_SECTIONS, N_SECTIONS(CASEBOOK_SECTIONS) },

    { "Files & state", "drive-harddisk-symbolic",
      "Everything the toolkit knows is a file in the tree. There is no\n"
      "database to migrate and no daemon to restart.",
      FILES_SECTIONS, N_SECTIONS(FILES_SECTIONS) },

    { "Command line", "utilities-terminal-symbolic",
      "The GUI is optional. Every module runs standalone, and the gates\n"
      "that keep the tree honest are ordinary scripts you can read.",
      CLI_SECTIONS, N_SECTIONS(CLI_SECTIONS) },

    { "Hardware", "network-transmit-receive-symbolic",
      "What the tree expects, and what has actually been tried. The second\n"
      "part is shorter than the first, deliberately.",
      HW_SECTIONS, N_SECTIONS(HW_SECTIONS) },

    { "Troubleshooting", "dialog-warning-symbolic",
      "Most problems are one of a handful of things. In this order:",
      TROUBLE_SECTIONS, N_SECTIONS(TROUBLE_SECTIONS) },

    { "Legal & ethics", "channel-secure-symbolic",
      "This is a research toolkit for cellular networks. What it does is\n"
      "regulated nearly everywhere, and the regulation is about the\n"
      "transmission, not the software.",
      LEGAL_SECTIONS, N_SECTIONS(LEGAL_SECTIONS) },
};

#define HELP_N_VIEWS ((int)G_N_ELEMENTS(HELP_VIEWS))

/* ───────────────────────── the renderer ───────────────────────── */

/* Themed icons resolve by name. main1.c's imsisting_icon_image() also
   looks for a module icon bundled in the gresource first; nothing on this
   page is a module, so every name here is a stock themed icon and the
   fallback branch is the only one that can apply. */
static GtkWidget *
help_icon(const char *name)
{
    return gtk_image_new_from_icon_name(
        (name != NULL && *name != '\0') ? name : "dialog-information-symbolic");
}

static const char *
skip_space(const char *p)
{
    while (*p == ' ' || *p == '\t') p++;
    return p;
}

/* A term line is "<term><two or more spaces><definition>". The term has to
   stay short: past that the definition column is squeezed and the list
   stops being scannable, so a long first field is treated as prose. */
static gboolean
line_is_row(const char *line, const char **def_out)
{
    const char *p = skip_space(line);
    const char *sep = NULL;

    if (*p == '\0')
        return FALSE;
    for (int i = 0; p[i] != '\0'; i++)
        if (p[i] == ' ' && p[i + 1] == ' ') { sep = p + i; break; }
    if (sep == NULL || sep - p > 34)
        return FALSE;
    if (def_out != NULL)
        *def_out = sep;
    return TRUE;
}

/* A joined paragraph: the source is hard-wrapped for editing, the label
   re-wraps for the window. */
static GtkWidget *
help_prose(char **lines, int n)
{
    GString *out = g_string_new(NULL);
    GtkWidget *label;

    for (int i = 0; i < n; i++) {
        const char *p = skip_space(lines[i]);
        if (*p == '\0') continue;
        if (out->len) g_string_append_c(out, ' ');
        g_string_append(out, p);
    }
    label = gtk_label_new(out->str);
    g_string_free(out, TRUE);

    gtk_label_set_wrap(GTK_LABEL(label), TRUE);
    gtk_label_set_wrap_mode(GTK_LABEL(label), PANGO_WRAP_WORD_CHAR);
    gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
    gtk_label_set_selectable(GTK_LABEL(label), TRUE);
    gtk_widget_set_hexpand(label, TRUE);
    gtk_widget_add_css_class(label, "help-prose");
    return label;
}

/* g_string_free() takes two arguments and returns something, so it cannot
   be handed to g_ptr_array_new_with_free_func() without a cast that
   -Wcast-function-type rejects. Wrap it instead. */
static void
help_gstring_free(gpointer p)
{
    g_string_free((GString *) p, TRUE);
}

/* A term/definition list. The definition wraps; the term does not, so the
   column stays aligned and the eye can run down it. A line with no gap
   continues the definition above rather than starting a row. */
static GtkWidget *
help_rows(char **lines, int n)
{
    GtkWidget *grid = gtk_grid_new();
    GPtrArray *terms = g_ptr_array_new_with_free_func(g_free);
    GPtrArray *defs = g_ptr_array_new_with_free_func(help_gstring_free);
    int row = 0;

    for (int i = 0; i < n; i++) {
        const char *p = skip_space(lines[i]);
        const char *sep = NULL;

        if (*p == '\0') continue;
        if (line_is_row(lines[i], &sep)) {
            GString *def = g_string_new(skip_space(sep));
            g_ptr_array_add(terms, g_strndup(p, sep - p));
            g_ptr_array_add(defs, def);
        } else if (defs->len > 0) {
            GString *def = g_ptr_array_index(defs, defs->len - 1);
            if (def->len) g_string_append_c(def, ' ');
            g_string_append(def, p);
        }
    }

    gtk_grid_set_row_spacing(GTK_GRID(grid), 14);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 22);
    gtk_widget_set_hexpand(grid, TRUE);

    for (guint i = 0; i < terms->len; i++) {
        const char *term = g_ptr_array_index(terms, i);
        GString *def = g_ptr_array_index(defs, i);
        GtkWidget *key = gtk_label_new(term);
        GtkWidget *val = gtk_label_new(def->str);

        gtk_widget_add_css_class(key, "help-row-key");
        gtk_label_set_xalign(GTK_LABEL(key), 0.0f);
        gtk_widget_set_valign(key, GTK_ALIGN_START);

        gtk_widget_add_css_class(val, "help-row-val");
        gtk_label_set_wrap(GTK_LABEL(val), TRUE);
        gtk_label_set_wrap_mode(GTK_LABEL(val), PANGO_WRAP_WORD_CHAR);
        gtk_label_set_xalign(GTK_LABEL(val), 0.0f);
        gtk_label_set_selectable(GTK_LABEL(val), TRUE);
        gtk_widget_set_hexpand(val, TRUE);

        gtk_grid_attach(GTK_GRID(grid), key, 0, row, 1, 1);
        gtk_grid_attach(GTK_GRID(grid), val, 1, row, 1, 1);
        row++;
    }

    g_ptr_array_unref(terms);
    g_ptr_array_unref(defs);
    return grid;
}

/* A bullet list. As with the rows above, a line that does not itself open
   a bullet continues the one before it — otherwise an item written over
   two source lines silently loses its second half. */
static GtkWidget *
help_bullets(char **lines, int n)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    GPtrArray *items = g_ptr_array_new_with_free_func(help_gstring_free);

    for (int i = 0; i < n; i++) {
        const char *p = skip_space(lines[i]);

        if (*p == '\0')
            continue;
        if (p[0] == '-' && p[1] == ' ') {
            g_ptr_array_add(items, g_string_new(skip_space(p + 1)));
        } else if (items->len > 0) {
            GString *it = g_ptr_array_index(items, items->len - 1);
            if (it->len) g_string_append_c(it, ' ');
            g_string_append(it, p);
        }
    }

    for (guint i = 0; i < items->len; i++) {
        GString *it = g_ptr_array_index(items, i);
        GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
        GtkWidget *dot = gtk_label_new("•");
        GtkWidget *text = gtk_label_new(it->str);

        gtk_widget_add_css_class(dot, "help-item");
        gtk_widget_add_css_class(text, "help-item");
        gtk_label_set_xalign(GTK_LABEL(dot), 0.0f);
        gtk_widget_set_valign(dot, GTK_ALIGN_START);
        gtk_label_set_wrap(GTK_LABEL(text), TRUE);
        gtk_label_set_wrap_mode(GTK_LABEL(text), PANGO_WRAP_WORD_CHAR);
        gtk_label_set_xalign(GTK_LABEL(text), 0.0f);
        gtk_label_set_selectable(GTK_LABEL(text), TRUE);
        gtk_widget_set_hexpand(text, TRUE);
        gtk_box_append(GTK_BOX(row), dot);
        gtk_box_append(GTK_BOX(row), text);
        gtk_box_append(GTK_BOX(box), row);
    }

    g_ptr_array_unref(items);
    return box;
}

/* Verbatim lines: commands and output. Wrapped rather than scrolled, so a
   long command stays readable in a narrow window. */
static GtkWidget *
help_mono(char **lines, int n)
{
    GString *out = g_string_new(NULL);
    GtkWidget *label;

    for (int i = 0; i < n; i++) {
        const char *p = skip_space(lines[i]);
        if (*p == '|') { p++; if (*p == ' ') p++; }
        if (out->len) g_string_append_c(out, '\n');
        g_string_append(out, p);
    }
    label = gtk_label_new(out->str);
    g_string_free(out, TRUE);

    gtk_label_set_wrap(GTK_LABEL(label), TRUE);
    gtk_label_set_wrap_mode(GTK_LABEL(label), PANGO_WRAP_WORD_CHAR);
    gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
    gtk_label_set_selectable(GTK_LABEL(label), TRUE);
    gtk_widget_set_hexpand(label, TRUE);
    gtk_widget_add_css_class(label, "help-mono");
    return label;
}

static GtkWidget *
help_render_block(const char *block)
{
    g_auto(GStrv) lines = g_strsplit(block, "\n", -1);
    int n = g_strv_length(lines);
    const char *first = n > 0 ? skip_space(lines[0]) : "";

    if (n > 0 && first[0] == '-' && first[1] == ' ')
        return help_bullets(lines, n);
    if (n > 0 && first[0] == '|')
        return help_mono(lines, n);
    if (n > 0 && line_is_row(lines[0], NULL))
        return help_rows(lines, n);
    return help_prose(lines, n);
}

/* The body of one section: its blocks, spaced so that a list is not run
   together with the paragraph above it. */
static GtkWidget *
help_render_body(const char *body)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 18);
    const char *p = body;

    while (*p != '\0') {
        const char *end = strstr(p, "\n\n");
        g_autofree char *block = end != NULL ? g_strndup(p, end - p)
                                             : g_strdup(p);
        if (*skip_space(block) != '\0')
            gtk_box_append(GTK_BOX(box), help_render_block(block));
        if (end == NULL) break;
        p = end + 2;
    }
    return box;
}

/* One section: a centred title, then the card it labels. The title is
   outside the rectangle so the card reads as the section's field rather
   than as a titled box. */
static GtkWidget *
help_section_widget(const HelpSection *s)
{
    GtkWidget *sec = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    GtkWidget *title = gtk_label_new(s->title);
    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *inner = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);

    gtk_widget_add_css_class(title, "help-sec-title");
    gtk_label_set_xalign(GTK_LABEL(title), 0.5f);
    gtk_widget_set_halign(title, GTK_ALIGN_CENTER);

    gtk_widget_add_css_class(card, "card");
    gtk_widget_add_css_class(inner, "help-card-body");
    gtk_box_append(GTK_BOX(inner), help_render_body(s->body));
    gtk_box_append(GTK_BOX(card), inner);

    gtk_box_append(GTK_BOX(sec), title);
    gtk_box_append(GTK_BOX(sec), card);
    return sec;
}

static void
help_view_row_activated(GtkListBox *list, GtkListBoxRow *row,
                        gpointer user_data)
{
    GtkStack *stack = GTK_STACK(user_data);
    int index = gtk_list_box_row_get_index(row);
    (void)list;
    if (index >= 0 && index < HELP_N_VIEWS)
        gtk_stack_set_visible_child_name(stack, HELP_VIEWS[index].name);
}

/* One subject's column, scrolled. The horizontal policy is NEVER so the
   viewport width is imposed on the child: that is what makes the labels
   wrap to the window instead of asking for their unwrapped width and
   bringing a horizontal scrollbar with them. */
static GtkWidget *
help_body_view(const HelpView *v)
{
    GtkWidget *scroll = gtk_scrolled_window_new();
    GtkWidget *col = gtk_box_new(GTK_ORIENTATION_VERTICAL, 30);
    GtkWidget *lead = gtk_label_new(v->lead);

    gtk_label_set_wrap(GTK_LABEL(lead), TRUE);
    gtk_label_set_wrap_mode(GTK_LABEL(lead), PANGO_WRAP_WORD_CHAR);
    gtk_label_set_xalign(GTK_LABEL(lead), 0.0f);
    gtk_label_set_selectable(GTK_LABEL(lead), TRUE);
    gtk_widget_set_hexpand(lead, TRUE);
    gtk_widget_add_css_class(lead, "help-lead");
    gtk_box_append(GTK_BOX(col), lead);

    for (int i = 0; i < v->n_sections; i++)
        gtk_box_append(GTK_BOX(col), help_section_widget(&v->sections[i]));

    gtk_widget_set_margin_top(col, 22);
    gtk_widget_set_margin_bottom(col, 32);
    gtk_widget_set_margin_start(col, 30);
    gtk_widget_set_margin_end(col, 30);

    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), col);
    gtk_widget_set_vexpand(scroll, TRUE);
    gtk_widget_set_hexpand(scroll, TRUE);
    return scroll;
}

/* The subject list. Built like a module submenu — same classes, same
   width, same heading — because it is the same navigation idea and
   should not read as a different kind of control. */
static GtkWidget *
help_build_submenu(GtkStack *stack)
{
    GtkWidget *list     = gtk_list_box_new();
    GtkWidget *col      = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *scrolled = gtk_scrolled_window_new();
    GtkWidget *hdr      = gtk_label_new("HELP");

    gtk_widget_add_css_class(list, "module-menu");
    gtk_widget_add_css_class(col, "module-menu");
    gtk_widget_add_css_class(col, "cat-system");
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(list), GTK_SELECTION_SINGLE);
    gtk_list_box_set_activate_on_single_click(GTK_LIST_BOX(list), TRUE);

    for (int i = 0; i < HELP_N_VIEWS; i++) {
        GtkWidget *row   = gtk_list_box_row_new();
        GtkWidget *box   = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
        GtkWidget *icon  = help_icon(HELP_VIEWS[i].icon);
        GtkWidget *label = gtk_label_new(HELP_VIEWS[i].name);

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
                     G_CALLBACK(help_view_row_activated), stack);

    if (HELP_N_VIEWS > 0)
        gtk_list_box_select_row(GTK_LIST_BOX(list),
            gtk_list_box_get_row_at_index(GTK_LIST_BOX(list), 0));

    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), list);
    gtk_widget_set_size_request(scrolled, 250, -1);
    gtk_widget_set_vexpand(scrolled, TRUE);

    gtk_widget_add_css_class(hdr, "menu-heading");
    gtk_label_set_xalign(GTK_LABEL(hdr), 0.0f);
    gtk_widget_set_margin_top(hdr, 12);
    gtk_widget_set_margin_bottom(hdr, 6);
    gtk_widget_set_margin_start(hdr, 16);
    gtk_box_append(GTK_BOX(col), hdr);
    gtk_box_append(GTK_BOX(col), scrolled);
    gtk_widget_set_vexpand(col, TRUE);
    return col;
}

/* The page. The header is built by hand rather than by the module page
   builder because Help has no module behind it: no id to look an icon or a
   name up from, no registry entry, no status pill and no output console.
   It borrows only the header's shape and classes. */
GtkWidget *
create_help_page(void)
{
    GtkWidget *outer  = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *header = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *hrow   = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *hicon  = help_icon("help-browser-symbolic");
    GtkWidget *htitle = gtk_label_new("Help");
    GtkWidget *hcat   = gtk_label_new("SYSTEM");
    GtkWidget *hdesc  = gtk_label_new(
        "How the toolkit is put together, one subject at a time.");
    GtkWidget *body   = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    GtkWidget *stack  = gtk_stack_new();

    gtk_widget_add_css_class(outer, "module-page");
    gtk_widget_set_vexpand(outer, TRUE);

    gtk_widget_add_css_class(header, "module-header-bar");
    gtk_widget_add_css_class(header, "cat-system");
    gtk_widget_add_css_class(hcat, "breadcrumb");
    gtk_widget_add_css_class(htitle, "module-header-title");
    gtk_widget_add_css_class(hcat, "module-header-category");
    gtk_widget_add_css_class(hdesc, "module-header-desc");

    gtk_image_set_pixel_size(GTK_IMAGE(hicon), 34);
    gtk_widget_set_hexpand(htitle, TRUE);
    gtk_label_set_xalign(GTK_LABEL(htitle), 0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(htitle), PANGO_ELLIPSIZE_END);
    gtk_label_set_xalign(GTK_LABEL(hdesc), 0.5f);
    gtk_label_set_justify(GTK_LABEL(hdesc), GTK_JUSTIFY_CENTER);
    gtk_label_set_wrap(GTK_LABEL(hdesc), TRUE);

    gtk_box_append(GTK_BOX(hrow), hicon);
    gtk_box_append(GTK_BOX(hrow), htitle);
    gtk_box_append(GTK_BOX(hrow), hcat);
    gtk_box_append(GTK_BOX(header), hrow);
    gtk_box_append(GTK_BOX(header), hdesc);

    gtk_stack_set_transition_type(GTK_STACK(stack),
                                  GTK_STACK_TRANSITION_TYPE_CROSSFADE);
    /* Not homogeneous, for the same reason a module page is not: a
       GtkStack otherwise takes its minimum height from its longest child,
       so the "Files & state" subject would set a floor under the whole
       page and push the shorter subjects off the bottom of the window. */
    gtk_stack_set_vhomogeneous(GTK_STACK(stack), FALSE);
    gtk_stack_set_hhomogeneous(GTK_STACK(stack), FALSE);

    for (int i = 0; i < HELP_N_VIEWS; i++)
        gtk_stack_add_named(GTK_STACK(stack),
                            help_body_view(&HELP_VIEWS[i]),
                            HELP_VIEWS[i].name);
    if (HELP_N_VIEWS > 0)
        gtk_stack_set_visible_child_name(GTK_STACK(stack),
                                         HELP_VIEWS[0].name);

    gtk_widget_add_css_class(body, "module-body");
    gtk_widget_set_vexpand(body, TRUE);
    gtk_widget_set_hexpand(body, TRUE);
    gtk_box_append(GTK_BOX(body), help_build_submenu(GTK_STACK(stack)));
    gtk_widget_set_hexpand(stack, TRUE);
    gtk_widget_set_vexpand(stack, TRUE);
    gtk_box_append(GTK_BOX(body), stack);

    gtk_box_append(GTK_BOX(outer), header);
    gtk_box_append(GTK_BOX(outer), body);
    return outer;
}
