# Part 1 — Orientation

Three chapters, because a reader who understands the shape of the toolkit can
read every later page without being told twice, and a reader who does not will
misread the interfaces as arbitrary. §1.1 says what the toolkit is. §1.2 states
the rules it holds itself to, which are the reason its interfaces look the way
they do. §1.3 describes the surfaces those rules are exposed through. §1.4 is
the vocabulary, and it is the chapter to return to.

## 1.1 What this toolkit is

IMSISting is a cellular research toolkit for the GSM, UMTS, LTE and 5G NR air
interfaces and the networks behind them. It is organised as **sixty-one
modules**, each of which is:

- one shell script under `modules/`, named by a two-digit number and a noun
  (`07_gsm_attack.sh`, `19_cipher_audit.sh`, `59_remote_node.sh`);
- one row in a catalogue that assigns it a **category**, a name and an icon;
- a set of **verbs** — one `--verb` per operation, 1,444 of them in total;
- a **store**: a directory under `loot/` that the module appends rows to;
- a **selftest**: `--selftest`, which runs assertions and prints `RESULT PASS`
  or `RESULT FAIL` and exits non-zero on the second.

The sixty-one modules fall into eleven categories, and the categories are how
the catalogue, the TUI menu and the GUI dashboard are all ordered:

| Category | Modules | What it is for |
|---|---|---|
| SYSTEM | 5 | Dependencies, the radio inventory, the field kit, the killchain, remote nodes |
| RECON | 3 | Cell survey, GSMTAP capture, tower mapping |
| RADIO | 14 | The air interfaces themselves, from GSM to NR, and the attacks that live on them |
| ACCESS | 7 | Getting onto a network: attach, slicing, femtocells, USSD, VoWiFi, RAN sharing |
| CORE NETWORK | 8 | EPC, 5G core, SS7, DNS, IMS, NAS, SBA, O-RAN |
| SIM / IDENTITY | 7 | The card and the identity: SUCI, OTA, AKA, eSIM, SIM swap, STK |
| TRACKING | 4 | Where a handset is: paging, timing advance, CSI fingerprinting, LPP |
| BASEBAND / DEVICE | 4 | Below the modem's API: fuzzing, exploits, injection, the baseband file system |
| ANALYSIS | 4 | Captures, ciphers, traffic, MAC and RLC |
| EXPLOIT KITS | 3 | Catalogues of published vulnerabilities for GSM/UMTS, LTE and NR |
| INTERCEPT / CARRIER | 2 | Lawful interception and the carrier API surface |

Three things about that split are worth stating plainly, because they are
choices and not accidents.

**The toolkit is not a chain.** No module calls another to complete an attack.
A module reads what it needs from `loot/` and from the air; a killchain module
exists to record the sequence a human performed, not to perform it. This is why
one module can be verified without the other sixty - and why a broken module
never silently invalidates a neighbouring verdict.

**The store is the interface between modules.** When an evil twin wants a
reconnaissance row to build a cell from, it reads the row out of
`loot/cell_recon/cells.tsv`. When a capture analysis wants to know which cipher
a network negotiated, it reads `loot/cipher_audit/sessions.tsv`. Nothing passes
through memory between modules, so every conclusion is reproducible from files
on disk, and a store you can read is a store you can audit.

**Nothing is a black box with a progress bar.** Every long operation either
declares what it is waiting for or hands off. A verb that cannot complete says
which binary, which transport or which capture it was missing, in a line that
begins `WHY`. That is the single most important property of the toolkit for a
researcher: the difference between "there is nothing here" and "I could not
look" is the difference between a finding and a guess, and the toolkit never
collapses the two. §1.2 turns that into rules.

## 1.2 The honesty rules

These eight rules are not aspiration. Each is enforced somewhere in the tree,
and each has a failure it prevents that has actually happened to somebody. A
reader who internalises them will find the interfaces predictable; a reader who
does not will read a grey chip as a bug report.

### Rule 1 — Unmeasured is not absent

A node that has never been probed reports `UNKNOWN`, not `ONLINE` and not
`OFFLINE`. A posture dimension nobody observed is grey (`UNOBSERVED`), never
green. A capture store with no rows is not an empty air interface.

The reason is asymmetric risk. Treating "I did not look" as "nothing there"
turns every failure of the tooling into a clean bill of health, and the operator
who most needs to know the difference is the one who has just lost a radio, a
capture interface or root.

*Where it lives:* node status words (§5.x), the target panel's posture chips
(§4.x), and every `--status-tsv` verb, which reports what was measured rather
than what is theoretically possible.

### Rule 2 — The exit code carries the verdict

Four codes, defined once and used everywhere:

| Code | Meaning | What the operator does next |
|---|---|---|
| `0` | Measured. The verb did what it says and the output is evidence. | Read the rows. |
| `1` | Could not. Something was expected to work and did not. | Read the `ERROR` line; the tool is usually right about what broke. |
| `2` | Refused. The request is invalid, unsafe, or outside what the tool will do. | Read the `WHY` line. |
| `3` | Handoff. The work moved somewhere the toolkit cannot follow: another machine, a missing toolkit, an empty remote store. | The output names where it went. |

A refusal (`2`) is a result, not a defect. When `57_evil_twin.sh` refuses to
radiate a twin that was prepared for contained mode, it is not failing — it is
preventing a loopback configuration from becoming a transmitter because a flag
was typed on the wrong command line.

### Rule 3 — Observed and advertised are different strengths of claim

A fact a capture proves is `observed`. A fact a configuration file asserts is
`advertised`. The evil twin's evidence store carries the distinction in a
column, because "the twin sent PLMN 001-01" and "a phone read PLMN 001-01" are
different sentences about the world, and a report that merges them is a report
that cannot be trusted.

The same distinction appears in `19_cipher_audit.sh`, where the cipher a
network *advertises* in system information is one store and the cipher a
session *negotiated* is another; the negotiated one wins, and the interface
names which store spoke.

### Rule 4 — Capabilities are measured, never typed

A node's class, roles and capabilities are produced by asking the machine
(`command -v`, a probe over the transport) and never by a field the operator
fills in. Where a value cannot be measured the field is empty and the interface
says so. `--presets` deliberately ships without a capabilities column: a preset
is a guess about a device class, and a guess must not be dressed as a
measurement.

*Where it lives:* `59_remote_node.sh` and the casebook's node table, the field
kit's RF pre-flight, and `01_radio.sh`, which reports the direction of a radio
from its driver rather than from the operator's optimism.

### Rule 5 — No invented call syntax

When a driver is not installed, the toolkit does not print a plausible command
line for it and hope. The transmit verbs of the air modules name the binary they
would have used and refuse. `01_radio.sh` produces a **handoff plan** — a file
recording the tool it would have run — instead of a capture file that does not
exist.

This is why several modules look less capable than they could: a printed
`hackrf_transfer` command that has never been executed is worth less than a
sentence saying the transmitter is absent, and considerably more dangerous,
because it can be copied into a report as though something had happened.

### Rule 6 — An unknown algorithm is never strong

The posture logic treats an unrecognised cipher as `WEAK` with the reason
"unknown strength", never as `HARDENED`. An integrity algorithm ending in `0`
(a null integrity algorithm) is `EXPOSED`, because that is the configuration
that lets forged NAS and SMS land. A GSM session reporting `n/a` for integrity
is `UNOBSERVED` — not null, not strong: the concept does not apply to that
generation, and the manual says so where a reader will meet it (§5.x).

### Rule 7 — A theme may not lie about a status colour

The GUI supports more than one palette. Every palette restates colours and
*leaves the status hues alone*: green stays ok, amber stays degraded, red stays
danger. A prettier red is still a red, and a theme that made a warning look
calm would be a theme that made the toolkit lie.

### Rule 8 — Absence of a verb is stated

Where a capability is missing on purpose, the interface says which clause is
missing rather than leaving a hole. `58_suci_catcher.sh` states that its
catcher needs a core with a subscriber database. `37_femtocell.sh` states which
piece of the small-cell stack is absent. The same rule governs this manual: a
reader who finds no section for a technique has found the toolkit's own verdict
on whether the technique is implemented.

## 1.3 The four surfaces

The same sixty-one modules are reachable through four surfaces. They are not
four implementations; they are four views over one command line, and the
command line is the truth.

**The module CLI** — `modules/NN_name.sh --verb`. Authoritative. Every verb,
every store and every exit code is defined here, and nothing about a module's
behaviour is decided anywhere else. If a GUI button and a module disagree, the
module is right and the button is a bug.

**The launcher** — `./imsisting.sh`. A menu over a table of
`CATEGORY|KEY|LABEL|MENU_FUNCTION|MODULE_ID` rows, useful for finding the
number of a module you have heard of but not memorised.

**The TUI** — `tools/imsisting_tui.py`, or `./imsisting.sh --tui`. A
full-screen terminal interface that reads the same table and the same module
index, offering categories, search, a module detail pane (description, needs,
verbs grouped by the same **views** the GUI uses) and one-click actions. Useful
over SSH, on a machine with no display, and while a capture is running in
another pane.

**The GUI** — `native/builddir/imsisting-gui`, built with meson and GTK 4. Ten
pages in a left drawer, a module catalogue on the dashboard, a per-module page
with the same views the TUI lists, and a header strip that reports the bench:
radio present, transmit capability, current frequency, cell count, GPS.

Two supporting agents belong with the surfaces rather than under a module,
because every surface may call them: `tools/node_agent.sh` (what runs on a
remote node) and `tools/ue_agent.sh` (what runs against a handset over adb).
Both are read-only by construction, and both refuse rather than guess when the
device they were pointed at answers with something unexpected.

## 1.4 The vocabulary

The toolkit uses a small number of words in a strict sense. This table is the
authoritative definition; later chapters assume it.

| Word | Definition |
|---|---|
| **module** | One of sixty-one shell scripts under `modules/`, identified by a two-digit number. |
| **verb** | One `--flag` operation of a module. Verbs return the exit codes of §1.2. |
| **store** | The directory under `loot/` a module writes. Usually one TSV with a fixed header. |
| **row** | One record in a store. A row is evidence; a deleted row is a lost finding. |
| **case** | A named collection under the casebook, into which stores can be exported as evidence. |
| **capture** | A pcap or a pcapng on disk. Modules that read captures never invent one. |
| **target** | The cell, network or device the operator has declared that the session is about. |
| **bench** | This machine and its radios, as reported by the header strip and `05_field_kit.sh`. |
| **node** | A machine registered in the fleet that a module can be pointed at instead of the local bench. |
| **transport** | How a node is reached: `local`, `ssh`, `adb`, `serial`, `qmi`, `mbim`, `diag`, `sms`. |
| **class** | What a node is, as measured: dongle, CPE, handset, single-board computer, core, relay. |
| **capability** | A measured ability of a node, e.g. `sdr-tx`, `gsmtap`, `pcsc`, `core`. |
| **role** | A suggested use for a node, derived from its capabilities: sensor, catcher, core, relay. |
| **stream** | A node's ongoing event feed, drained from a spool file with a byte cursor. |
| **run** | One bounded execution of a module, with a name, logs and evidence rows. |
| **evidence** | A stored fact with a source and a confidence: `observed` or `advertised`. |
| **chip** | A stated precondition on a card: needs a radio, needs a capture, transmits, reads. |
| **gate** | One of the `tools/check-*.sh` scripts that fails the tree when a claim stops being true. |
| **referee** | An independent oracle (tshark, pycrate, a published vector) used to check our own decoder. |
| **handoff** | Exit code 3. The work moved somewhere this toolkit cannot follow, and it says where. |
| **selftest** | A module's `--selftest`, which asserts its own behaviour and prints a count. |

Three words appear on every screen and must not be confused:

- **ready** — the operation can run with what is present.
- **degraded** — it can run, with a stated limitation.
- **handoff** — it cannot run here; the next step is elsewhere, and the message
  names it.

---

Part 1 has stated what the toolkit is, the rules it keeps, the surfaces that
express them and the words they use. Part 2 is practical: dependencies, radios,
and the first hour of work from an empty machine to a case that contains
evidence.
