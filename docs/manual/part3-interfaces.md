# Part 3 — Interfaces

Part 2 used the toolkit through its most honest surface: a shell prompt and one
module at a time. That surface is the one that always works, and it is the one
this part describes first and in the most detail — because the other two are
views over it, and a reader who knows the command line can always reconstruct
what a button did.

There are four things in this part. §3.1 is the module command line and the
launcher that indexes it. §3.2 is the terminal workspace. §3.3 is the window.
§3.4 is the gate suite, which is not an interface at all but is the reason the
other three can be trusted to say what they say.

A note on the relationship between them. The window does not contain a second
implementation of anything: every button is an argv array handed to the same
shell script you would have typed. When this part says "the GUI runs
`--turbo-decode`", it means the exact command in §3.1's sense, run as a child
process, with its stdout read back into a result pane. That is a deliberate
limit and it has a cost — the window cannot do anything the modules cannot do —
but it is what makes the whole thing auditable: any result you see on screen can
be reproduced in a terminal, and any result in a terminal can be pasted back.

## 3.1 The command line, and the launcher that indexes it

### One script, two lives

Every module is one file under `modules/`, and every one of them is written to
be both a program and a library:

```bash
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -o pipefail
    IMSISTING_CLI=1
    : "${TMP_DIR:=/tmp/imsisting}"
    : "${LOOT_DIR:=$IMSISTING_ROOT/loot}"
    ...
    declare -F banner >/dev/null 2>&1 || banner() { :; }
    declare -F info   >/dev/null 2>&1 || info()   { printf '[info] %s\n' "$*" >&2; }
    declare -F warn   >/dev/null 2>&1 || warn()   { printf '[warn] %s\n' "$*" >&2; }
    declare -F err    >/dev/null 2>&1 || err()    { printf '[err]  %s\n' "$*" >&2; }
    declare -F ok     >/dev/null 2>&1 || ok()     { printf '[ok]   %s\n' "$*" >&2; }
    gatk_cli_main "$@"
fi
```

That tail is why a gate can do this:

```bash
source modules/07_gsm_attack.sh
gatk_selftest          # no dispatch, no launcher, no window
```

and why the window can build a page out of a module without executing it. The
fallback `info`/`warn`/`err`/`ok` stubs matter more than they look: sourced, the
module has no launcher to define them, so each module defines a do-nothing
version and the launcher's version, when there is one, wins.

Every function a module defines is prefixed with its own tag — `gatk_` in
`07_gsm_attack`, `uair_` in `08_umts_air`, `et_` in `57_evil_twin`, `sc_` in
`58_suci_catcher`. The prefixes exist so that several modules can be loaded into
one shell without a collision, which is exactly what the codec gates do.

### The preamble

The first twenty-five lines of a module are the same in all sixty-one of them,
and each line is load-bearing.

*The root comes from the script's own path*, following symlinks:

```bash
if [[ -z "${IMSISTING_ROOT:-}" ]]; then
    _sl_src="${BASH_SOURCE[0]}"
    while [ -L "$_sl_src" ]; do ... done
    IMSISTING_ROOT="$(cd -P "$(dirname "$_sl_src")/.." && pwd)"
    export IMSISTING_ROOT
fi
```

A module launched standalone — from a `pkexec` prompt, from a desktop file, from
a cron job — has no launcher to tell it where the tree is, and its store must
still land inside that tree rather than in whatever directory happened to be
current.

*`HOME` is reset* when it does not match the tree's parent, because `pkexec`
runs with `HOME=/root` while writing to the invoking user's project. Anything
`$HOME`-relative would otherwise resolve into `/root` and the write would either
fail or succeed somewhere nobody looks.

*Five directories are named and created*:

| Variable | Default | What belongs in it |
|---|---|---|
| `IMSISTING_ROOT` | the checkout | the tree; every other path is derived from it |
| `TMP_DIR` | `/tmp/imsisting` | scratch: caches, logs of the window, intermediate files |
| `LOOT_DIR` | `$IMSISTING_ROOT/loot` | observations that are the *answer* — stores you keep |
| `CAPTURES_DIR` | `$IMSISTING_ROOT/captures` | raw captures, before anything decoded them |
| `LOGS_DIR` | `$IMSISTING_ROOT/logs` | what a long run writes while it runs |
| `STATE_DIR` | `$IMSISTING_ROOT/state` | what the next launch must remember |

The distinction between `loot/` and `captures/` is the one people get wrong
first: a capture is evidence of what crossed the air, a loot store is the
toolkit's reading of it. You may delete a loot store and rebuild it from the
capture; you cannot rebuild the capture. That is why `captures/` is the
directory to back up.

All five are environment variables first and defaults second, so a survey can be
relocated without touching the code:

```bash
LOOT_DIR=/mnt/field/loot CAPTURES_DIR=/mnt/field/captures \
    modules/02_cell_recon.sh --scan lte 20
```

### Verbs, and the usage block

Dispatch is one `case` on `"${1:-}"`, and the unknown-verb arm is the manual
for that module:

```bash
        *)
            cat >&2 <<EOF
GSM Catcher — IMSI catcher, A5/1 downgrade, TMSI de-anonymisation, Kc recovery

Usage: $0 COMMAND
  --status-tsv                 radio and plan state as TSV
  --plan <name>                write a handoff plan file and report the hardware
  ...
  --selftest                   verify sequence, classmark, messages and ciphers
  --menu                       interactive menu
EOF
            return 2 ;;
```

Two consequences follow. Asking a module for help is an error, so
`modules/07_gsm_attack.sh` with no arguments prints usage **to stderr** and exits
`2` — it is not a failure, it is a refusal to guess. And the usage block is the
only place a verb is described, which is what lets `tools/check-verbs.sh`
(§3.4) compare the set of documented verbs against the set of things the window
offers.

The usage text follows a shape across all sixty-one modules: a title line
naming the module and what it is for, `Usage:`, then groups separated by a blank
line and introduced by a short heading, because a flat list of ninety verbs
cannot be read. An argument in `<angle>` is required, one in `[brackets]` is
optional, and an `[a|b|c]` is a closed set with the default first.

### What a verb prints

Machine-readable output goes to **stdout**, as TSV, always with a header row:

```
ts	ts_epoch	run	step	channel	direction	protocol	message_type	message	source
```

That convention is not cosmetic. It is what lets `awk -F'\t' '$2 ~ /^GSM Um/'`
work, what lets the window fill a list without an API, what makes two runs
diffable, and what keeps a column from being renamed silently — because a
retired column name breaks a gate before it breaks a caller.

Human-facing lines go to **stderr**, and their first field is the kind:

| First field | Meaning | Exit code that usually follows |
|---|---|---|
| `ERROR` | the request cannot be honoured; the rest of the line says why | `2` |
| `WHY` | a capability is absent and here is the reason, with the alternative | `2` |
| `[info]` | progress on a run that is still going | carries on |
| `[warn]` | something was skipped or assumed | carries on |
| `[ok]` | the step the operator was waiting for finished | carries on |

The `WHY` line deserves its own sentence. When a module cannot do something —
no radio, no `tshark`, a driver that will not open — it does not print a generic
failure. It prints a `WHY` line naming the missing piece and the verb that would
work instead. A refusal you cannot act on is worse than no tool at all, and the
`WHY` line is the toolkit's answer to that.

Exit codes are the same three throughout, and §1.2 gave them in principle: `0`
measured and printed, `1` ran and the answer is negative or nothing was found,
`2` refused because the request or the bench cannot be honoured. A pipeline of
modules is therefore readable with `&&`:

```bash
modules/02_cell_recon.sh --scan lte 20 \
  && modules/04_tower_map.sh --survey lte 20
```

### The four flags to try first on any module

```bash
modules/26_ss7_map.sh                 # no verb: usage on stderr, exit 2
modules/26_ss7_map.sh --selftest      # prove this module's own arithmetic
modules/26_ss7_map.sh --status-tsv    # what it can see right now, as TSV
modules/26_ss7_map.sh --menu          # the same verbs as a numbered menu
```

`--selftest` is the one to reach for when a result looks wrong. It asserts the
module against published values — 357 rows in `07_gsm_attack`, a few dozen in
most others — and it runs without a radio, without a capture and without root.
If `--selftest` passes and your result still looks wrong, the module is doing
what it claims and the claim is what you disagree with, which is a different
conversation; if it fails, stop and read the failing row.

`--status-tsv` is the honest one. It reports what the module can see *now* — a
radio that answers, a tool that is present, a store with rows in it — and it
reports absence as absence rather than as zero. That distinction is why the
window's header strip can say `SDR none` instead of `SDR ready`.

### The launcher

`imsisting.sh` is an index, not an engine. Its job is to hold one table and to
turn a number into a function call:

```
CATEGORY|KEY|LABEL|MENU_FUNCTION|MODULE_ID
```

`KEY` is a sequential position — `01` through `61` — and the table's own header
comment says so, which is why the keys are unique and gapless. `MENU_FUNCTION`
names a shell function in the launcher; `MODULE_ID` names the script it ends up
running. Two rows may share a category and no two rows may share a key, because
`fn_for_key()` returns the first match and a duplicate key silently makes the
second row unreachable — a bug this tree has had once, and now has a gate
against (§3.4).

```bash
bash imsisting.sh --list            # every module, its key and its availability
bash imsisting.sh --index           # the module index as TSV
bash imsisting.sh --tui             # the terminal workspace, §3.2
bash imsisting.sh --gui             # the window, §3.3
bash imsisting.sh --version         # imsisting v1.0.86 — 61 modules, 2G/3G/4G/5G
bash imsisting.sh --help            # the above
```

The interactive browser needs root because the modules it launches may; the
read-only verbs do not. That asymmetry is deliberate: looking at a catalogue
should never require privilege, and transmitting always should.

### Declared settings

The launcher also owns the small set of settings that outlive a session:

```bash
bash imsisting.sh --settings list        # declared settings as TSV
bash imsisting.sh --settings set K V     # declare one
bash imsisting.sh --settings unset K     # back to the default
bash imsisting.sh --settings reset       # back to every default
```

A setting declared here is written to a file the modules read, and a module
reports the value it used, so "why did it use that path" has an answer. The
window's Settings page (§3.3) edits the same values; the two cannot drift apart
because there is only one store.

## 3.2 The terminal workspace

`tools/imsisting_tui.py` is a full-screen browser in Python's standard library
and nothing else. No `ncurses` bindings to install, no `pip`, no dependency that
can be missing on the box you are actually standing next to in a van.

```bash
./imsisting.sh --tui
python3 tools/imsisting_tui.py        # same program, no launcher
```

### What it knows, and where it learned it

The workspace does not carry its own catalogue. On start it reads:

- `IMSISTING_MODULE_TABLE` out of `imsisting.sh` — the categories, the keys and
  the labels, which is where the numbering on screen comes from;
- `module_index.tsv` — each module's verbs, whether it has a selftest, whether
  it has an info verb;
- the window's own source, for the **view names** each module's page is divided
  into, and which verbs live in which view.

That third source is what makes the terminal and the window agree about the
shape of a module. The alternative — a hand-kept list of views in the TUI — would
be a second catalogue, and second catalogues rot. Instead the views you see in
the terminal are the views the window draws, read from the same tables.

### Three panes

```
┌ IMSISTING ──────────┬──────────────────────────────────────────────┐
│ CATEGORIES          │ MODULES                                      │
│  SYSTEM        5    │ 01  Dependency Manager          9 verbs      │
│  RECON         3    │ 02  SDR / Radio Manager        11 verbs      │
│  RADIO        14    │ ...                                          │
│  ...                │                                              │
├─────────────────────┴──────────────────────────────────────────────┤
│ SEARCH  type to filter modules                                     │
│ ↑↓/jk modules   Tab category   Shift+Tab pages   / search          │
│ Enter open      ? help         q quit                              │
└────────────────────────────────────────────────────────────────────┘
```

The left column is the category list with counts, so you can see the shape of
the toolkit before choosing anything. The middle column is every module, keyed
by its menu number. Opening a module replaces the right-hand side with its
description, its **views** and the actions inside each view.

### Keys

| Context | Key | Effect |
|---|---|---|
| Dashboard | `↑` `↓` or `j` `k` | move through modules |
| Dashboard | `Tab` | cycle category filter |
| Dashboard | `Shift+Tab` | cycle the workspace pages |
| Dashboard | `/` | type into SEARCH |
| Dashboard | `Enter` | open the highlighted module |
| Dashboard | `?` or `h` | help |
| Dashboard | `q` | quit |
| Workspace | `↑` `↓` | move through actions |
| Workspace | `←` `→` or `[` `]` | previous / next module |
| Workspace | `Enter` | run the highlighted action |
| Workspace | `a` | give it arguments, then run |
| Workspace | `f` | filter the action list |
| Workspace | `s` | save the output pane to a file |
| Workspace | `c` | clear the output pane |
| Workspace | `Esc` | back to the dashboard |

Letters go to SEARCH on the dashboard, which surprises people once: `j` is a
navigation key only inside a module. Arrow keys are unambiguous in both places.

### Arguments are asked for, never guessed

A verb whose usage line reads `--since <epoch>` cannot be run by pressing
`Enter`. It opens a line where you type the argument, and the run does not start
until it is given. Nothing in the terminal workspace invents a value for an
argument: a run that would have to guess is a run that would produce a number
you cannot attribute later.

### Views the terminal cannot draw

Some views are drawn by the window and have no shell verb behind them at all —
the live catcher feeds (§3.3) are the clearest example: they are a widget
reading a store every two seconds, not a command. The workspace lists those as

```
Nodes                                  (in the GUI)
Stream                                 (in the GUI)
```

rather than omitting them. The view exists; the terminal says so and says where
it lives, instead of pretending the module has fewer views than it has.

### What it refuses

With no terminal attached — a cron job, a `docker run` without `-t`, an editor's
build hook — it prints why and exits non-zero rather than pretending to draw.
That refusal is asserted by `tools/check-tui.sh`, along with the key uniqueness
that the renumbering above depends on, a real pseudo-terminal render, and the
`--help` text.

## 3.3 The window

The GUI is GTK4 in C, built with meson, and it is optional in the same way the
terminal workspace is optional: nothing in it can do something the modules
cannot.

```bash
bash imsisting.sh --gui                 # or:
cd native && meson setup builddir && ninja -C builddir && ./builddir/imsisting-gui
```

Its own flags are few and mostly for scripted checks and screenshots:

```bash
native/builddir/imsisting-gui --module 07_gsm_attack   # open on a module
native/builddir/imsisting-gui --tab 2                  # open on notebook page 2
native/builddir/imsisting-gui --list-modules           # id, category, name as TSV
native/builddir/imsisting-gui --selftest               # every page's own arithmetic
native/builddir/imsisting-gui --version
```

### Boot, and what is inside the binary

The window carries its palette, its icons, its fonts and a coarse world map in
the binary as a GResource. It needs no network to draw itself, no icon theme to
be installed and no fonts to be present on the box; a machine with GTK and
nothing else still looks like the desk (§1.1).

Three stylesheets are loaded in a fixed order, each above the last:

1. `style.css` — the palette and the layout, the one the desk was drawn in;
2. `theme-<id>.css` — a second palette, if the Theme setting is not Night. It
   may restate **colours only**, never layout, which is why a theme cannot fall
   behind the layout it decorates;
3. `corners.css` — if the Corners setting is Square. Shape outranks palette, so
   this one loads above the theme.

The window has no console to print to, so it redirects its own standard error to
`tmp/gui.stderr`, tails that file, and turns anything that is not noise into an
event — which is how a GTK warning ends up in Notifications instead of vanishing.

What the window remembers between launches is a handful of rows in
`state/ui.tsv`: the catalogue's sort order, the density, the theme and the
corners. Deleting that file resets the window's appearance and nothing else.

### The header

Two strips. The upper one carries the title and version, the global search
field, and three buttons: **Target** (toggles the target panel), **Events** (with
a count) and the window controls. The lower one is the instrument strip:

```
SDR   TX   FREQ   CELLS   GPS                              polled just now
none  no   —      0       absent
```

Each chip is a reading, not a wish. `TX no` means no transmitter is usable —
which is the state most readers should be in most of the time (§2.2). `CELLS 0`
means the survey store is empty, not that there are no towers. The strip
refreshes on a timer and says when it last did, so "0" always has a timestamp
next to it.

### The drawer

The left edge holds a sliding drawer: the ten pages, then the module catalogue.
It slides **over** the page rather than pushing it aside. The Help page's own
words for this are the right ones — a drawer that took width would reflow every
card each time it opened, and navigation would be felt as a layout change.

The drawer's order and the notebook's internal order are not the same list, and
that matters when you are scripting screenshots or reading this manual against
the source:

| Notebook index | Drawer row | Question it answers |
|---|---|---|
| 0 | Dashboard | what can this toolkit do, and where do I start |
| 1 | Live Traffic | what are the sensors hearing right now |
| 2 | Casebook | what am I collecting, and for which case |
| 3 | Stats | how much have I actually collected |
| 4 | Notifications | what happened while I was not looking |
| 5 | Help | how does this window work |
| 6 | Settings | what does this toolkit do by default |
| 7 | Workflows | I have a question, not a module — where do I start |
| 8 | Map | where are these cells and observations |
| 9 | Fleet | what machines are these sensors on |

### Dashboard

The dashboard answers "what can this do" without a manual. It opens with four
**Start here** steps, in order: *Define the operation*, *Check the field kit*,
*Survey the cell layer*, *Watch traffic*. The order is the argument: set the
case before collecting, verify the bench before trusting it, look at the cell
layer before decoding it, and only then start watching. Under it sits the whole
catalogue — sixty-one cards grouped by the eleven categories, each with its icon,
its name and its one-line purpose, with search above and two controls beside it:
**Sort** (Workflow / Name / Category) and **Density** (Spacious / Compact).

Workflow order is not alphabetical and not by category. It is the order a
session actually moves in — dependency, radio, field kit, killchain, remote nodes
— which is why it is the default.

### Live Traffic

The page for as long as a survey is running. It filters packets by protocol,
follows a stream, pauses, resets, saves the buffer to a pcap, and shows a packet
inspector for the selected frame. Its own controls cover the things that decide
whether a long capture survives: an autosave interval, a rotation threshold, a
minimum signal level and a port. A packet below the minimum is not displayed;
that is a display filter, and the capture file still contains it.

### Casebook

Seven tabs, and the split is by object rather than by verb: **Overview**
(counters and the current case), **Evidence** (files with tags and a sensitivity
marker), **Captures** (indexed files), **Timeline** (events in order),
**Alerts** (raised by baselines and rules), **Nodes** (the sensor registry),
**Reports** (exported HTML, JSON, TSV). Each tab is a list over
`python3 tools/casebook.py` verbs, so anything you can do here you can do from a
shell — and the reverse, which is the point.

### Map

An equirectangular projection over a basemap compiled into the binary, with
layers read from `loot/map/layers/*.tsv`. Pan and zoom are checked by the
window's own selftest, because a direction bug is the one thing a screenshot
cannot show. Cells, observations and geo-tagged casebook entries are drawn on the
same plane so that "the tower we heard" and "the place we heard it from" can be
compared without exporting anything.

### Fleet

The registry of remote nodes: name, host, transport, class, role, capabilities,
status, detail and last-seen — read from the casebook's node store, under the same
columns as `tools/casebook.py nodes`. This is where a survey that spans more than
one box stops being a folder of TSVs and becomes a set of machines with roles
(§5.x).

### Stats

Counts, deliberately unglamorous: modules installed, loot files, captures, runs
recorded, **empty shelves** (categories with nothing collected), **never pressed**
(modules that have never been run on this box), a breakdown by module, and the
fleet. The last two counters are the useful ones. A toolkit is only as good as the
parts of it you have exercised, and "never pressed" is the honest measure of that.

### Notifications

The event log, one row per thing that happened, clearable. Both producers land
here: a module that exits non-zero, and the window itself — including the
"that theme is not in this build" toast described below.

### Help

Eleven subjects, in the window: Overview, Getting around, Modules, Running a
verb, Radio & transmit, Casebook & evidence, Files & state, Command line,
Hardware, Troubleshooting, Legal & ethics. It is a page rather than a dialog
because it is meant to be read with the window open beside it, and it is the same
doctrine as this manual compressed to a screenful per subject.

### Settings

Six views down the left: **Interface**, **Paths**, **Radio**, **Live traffic**,
**Notifications**, **Diagnostics**. Each row is one decision, its current value,
the built-in default and a note saying what the value means — the note is not
decoration, it is the only place the reason for a default is written down. Two of
them are appearance: Theme (Night / Ember) and Corners (Round / Square). Both are
persisted in `state/ui.tsv` and both are asserted by `--selftest`, because a
preference that offers a choice it cannot deliver is worse than no choice.

`Paths` shows each directory with the value in use, the source it came from (the
environment, the file, or the built-in default) and a `default` button. This is
the view to open first when a run wrote somewhere unexpected: it answers "where
did that go" before you go looking.

`Diagnostics` holds the things that are only interesting when something is wrong
— PIN state, crash reports, build facts, restart hints — and the log the window
writes about itself.

### Workflows

Twelve questions, each opened into the steps that answer it. The questions are
phrased the way an operator asks them, not the way a module is named: *See the
towers around me*, *Read my own SIM*, *Check whether my number is being ported*,
*Find out whether a band is being jammed*, *Test my operator's API*, *Capture and
read signalling*, *Watch for a fake tower*, *Read what a tower broadcasts*,
*Recover an identity*, *Audit a cipher*, *Build a fake cell in a lab*, *Run an
attack chain*. Every step runs a module that is already installed; a route adds no
capability, only an order and a worked example to type. Each route also states
what it needs (a radio, a capture, nothing at all) and what you will be holding
when it finishes.

### A module page

Open any card and the page is built the same way, which is what makes sixty-one
modules learnable once:

- a **view list** down the left, one row per view, in the order the module's
  author intended you to move through it — this is the same list the terminal
  workspace shows (§3.2);
- **cards** per view, each with a title in the imperative (*Read the store*,
  *Build the frame*, *Send it to a radio*) and a one-line explanation of what the
  button underneath will do;
- **verb rows**: a one-click button for a verb that needs no argument, a form
  with labelled fields for a verb that does, with an example already in the field
  so an empty form is never the first thing you see;
- **chips** stating what the verb needs: `NEEDS A RADIO`, `NEEDS A CAPTURE`,
  `TRANSMITS`, `NEEDS NO RADIO`, `READS`, `DOES READS`. A transmitting verb is
  marked as such with the same weight as a warning, because it is one;
- a **standard result card**: the argv that ran, the exit code, the output, and
  the store the run wrote to, if any.

The last of those is the most important. Every run in the window leaves behind
the exact command line, so the answer to "what did that button do" is never
"something in the GUI".

### The target panel

Toggled from the header, it floats on the right and holds the current target and
the case counters: the target set in the Casebook, its posture chips (what the
network is doing to this subscriber right now, read from the newest row of each
measurement), and the counts of evidence, captures, alerts and timeline entries
in the open case. Like the drawer, it floats rather than taking width.

The posture chips are the one place the window interprets anything: an algorithm
the toolkit cannot place never comes out strong, and the newest row wins. That
rule is asserted in `--selftest` as well.

### Themes and shape, and an honest failure

Two appearance settings, and one lesson behind each.

**Theme** (Night / Ember) works by loading a second sheet above the base one. The
Ember sheet is generated from the base sheet by `tools/gen-theme.py` — greys warm,
cool surfaces deepen toward black, the blue accent becomes an ember accent, and
green/red/amber keep their hue so a status colour still means what it means —
and it restates colours only. A theme therefore cannot fall behind the layout it
decorates. The one thing a generated palette cannot know is where the accent
should appear *on purpose*, so the generator appends a small hand-written tail for
the GTK widgets the base sheet never styled: entries, popovers, checkboxes,
switches, tooltips, scrollbars, selections.

**Corners** (Round / Square) loads a sheet whose whole content is a
border-radius reset, with an exception list for the two shapes that must stay
round — switches and radio knobs — because a square switch reads as a checkbox.

Both settings have the same failure mode and the window now refuses it. A
stylesheet that is not compiled into the binary draws nothing, silently, while
the control still says "Ember": GTK does not complain, so the user concludes the
theme is broken and the app concludes it worked. The window therefore looks the
sheet up first, and if it is missing it says

> The 'ember' theme is not in this build (/com/imsisting/native/theme-ember.css):
> the base palette is what is being drawn. Re-run tools/gen-icons-xml.sh and
> rebuild.

puts the same sentence in Notifications, reverts the setting, and only then
carries on. `--selftest` asserts the same fact twice — once per theme, once per
corner style — so a build that offers a choice it cannot deliver fails a gate
rather than wasting an afternoon.

## 3.4 The gate suite

Fifty-eight `tools/check-*.sh` scripts, sixty-one module selftests and one window
selftest. They are not tests of the toolkit's *results* in the wild — no gate can
tell you whether the tower you are looking at is the one you think — they are
tests of the claims that would otherwise be quietly false: that every verb is
reachable, that every decoder agrees with a referee, that the document you are
reading describes the thing that exists.

Four kinds, and they fail differently.

### Structural gates: does the interface still hold together

| Gate | What it asserts | The drift it prevents |
|---|---|---|
| `tools/check-paths.sh` | every path the tree assumes resolves: a directory a module writes into is created, a script a table names exists | a write into a directory nobody made, a card pointing at a deleted script |
| `tools/check-verbs.sh` | every documented verb sits in one of its submenu groups, or is a known modifier, or is exempt plumbing | a feature nobody can click |
| `tools/check-gui-text.sh` | no string literal beginning with `--` is handed to an API that renders text | a button labelled `--tr069-audit`, a verb moved onto the screen instead of a sentence |
| `tools/check-gui-pages.sh` | 22 checks that the spec-driven pages keep a card's answer inside the card — no near-black `OUTPUT` scroller bolted to the bottom, which made every module look like a terminal | the log well creeping back into a page |
| `tools/check-glossary.sh` | every key printed has a plain-words row; no row is dead; no label contains a verb token; every Workflows step names a verb its module documents | vocabulary invented at the call site, and a route pointing at nothing |
| `tools/check-theme.sh` | every theme sheet is named in the manifest, balanced, regenerable, and the manifest itself is current | the silent "Ember does nothing" bug |
| `tools/check-tui.sh` | the terminal workspace compiles, its keys are `01..N` in table order and unique, it refuses a non-TTY, and it renders in a real pseudo-terminal | duplicate menu keys, and a workspace that draws nothing |
| `tools/gen-module-index.sh --check` | `module_index.tsv` and `native/src/module_index.c` match the module table | an index that describes a previous version of the tree |
| `tools/gen-theme.py --check` | the Ember sheet is exactly what today's base sheet generates | a theme edited by hand and then left behind |

Two of these deserve their reason written down, because both are gates that exist
because of a bug rather than a plan.

`check-verbs.sh` insists that every non-modifier verb is placed in a submenu. Its
modifier list used to live inside the gate as one 237-name alternation; it is now
`tools/verb-modifiers.txt`, read by both the gate and the terminal workspace, so
the two cannot disagree about what counts as an action. The list is explicit
rather than a wildcard on purpose: a rule like "anything matching `--.*-.*` is a
modifier" would silently stop requiring a control for a real verb.

`check-tui.sh` asserts that the menu keys are `01..61` with no duplicates,
because the launcher's `fn_for_key()` returns the first match — a duplicate key
does not fail loudly, it makes a module unreachable.

### Codec oracle gates: does the decoder agree with somebody else

The largest group, and the reason to trust a decoded field. Each one feeds a
decoder in the tree and a referee outside it the same bytes, then compares.

The referees are named in each gate's header, and they are of four kinds:
`tshark` (a dissection of the same bytes), `pycrate` (an independent Python
implementation of the specification), published test vectors (3GPP's own, or the
values a specification prints), and a sibling module that implements the same
thing by a different route — which is the weakest of the four and is labelled as
such.

| Domain | Gates |
|---|---|
| GSM | `check-gsm-si` (tshark **and** pycrate, with five negative controls), `check-auth-oracle`, `check-keystream` |
| UMTS | `check-umts-rrc`, `check-umts-sib`, `check-umts-bch`, `check-umts-phy`, `check-umts-sccpch`, `check-umts-uplink`, `check-umts-catcher`, `check-umts-catcher-pcap` |
| LTE | `check-lte-sib-codec`, `check-lte-nb-codec`, `check-lte-phy-oracle`, `check-lte-rm-oracle`, `check-lte-corpus`, `check-lpp-codec` |
| 5G / NR | `check-nas-vectors`, `check-nas-identity`, `check-suci-catcher`, `check-nr-phy-oracle`, `check-ngap-codec`, `check-xnap-codec` |
| Core network | `check-gtp-codec`, `check-pfcp-codec`, `check-diameter-codec`, `check-sba-codec`, `check-sip-codec`, `check-vowifi-codec` |
| SS7 / RAN | `check-ss7-codec`, `check-ss7-map`, `check-sgsap`, `check-ranap-codec`, `check-rua-codec`, `check-x2ap-codec`, `check-supl`, `check-scp03t`, `check-li-ber` |
| SIM / device | `check-sim-codec`, `check-apdu-codec`, `check-stk-codec`, `check-ota-codec`, `check-ota-packet`, `check-ota-response`, `check-ussd-codec`, `check-smpp` |
| Physical layer | `check-phy-seqs`, `check-media-leg`, `check-calls` |
| Structure of the tree | `check-paths`, `check-verbs`, `check-gui-text`, `check-gui-pages`, `check-glossary`, `check-theme`, `check-tui` |
| Experiments | `check-evil-twin-lab`, `check-ransacked-corpus` |

A codec gate is only worth its runtime if it can fail. `check-gsm-si` carries five
**negative controls**: it copies the module, breaks its System Information
builders one at a time in five specific ways — drop the L2 pseudo-length, add a
LAPDm header to a BCCH block, put the LAI before the cell identity, put the cell
identity into SI4, count ARFCNs from the wrong end — and asserts that each broken
build produces the expected *change*. Without that, a gate that passes might be a
gate that compares two identical wrong things.

The SI framing fix in 1.0.78 is the worked example of the whole idea: the
toolkit's own builder and its own decoder disagreed about where the cell identity
goes, two independent referees sided with the decoder, and the gate that now
covers it was written in the same pass as the fix, with the disagreement as one
of its controls.

### Module selftests: does this module's own arithmetic hold

Every module has `--selftest`, and it is the same idea one level down: fixture
input, printed expectation, exit non-zero on a mismatch. They are what you run
after a merge, on a machine with no radio, in under a minute each:

```bash
for m in modules/*.sh; do bash "$m" --selftest >/dev/null || echo "FAIL $m"; done
```

`07_gsm_attack --selftest` is 357 assertion rows covering the catcher sequence, the
length indicators, the message types, the ciphers and the observation store.
`00_deps --selftest` injects a stub tool directory to prove that detection is by
*use* rather than by file. `58_suci_catcher --selftest` proves the record format
its live feed reads.

### The window's selftest, and the gates that are not shell

`imsisting-gui --selftest` runs without a display and checks what a screenshot
cannot: the map's pan arithmetic and its zoom floor, the fleet page's column
lookup, the posture chips' reading rules (an algorithm the toolkit cannot place
never comes out strong; the newest row wins), and that both appearance settings
are deliverable — which is the row that caught the unpackaged theme.

### Running them all

There is no single runner on purpose; each gate is a sentence you can read and a
decision you can make. The order that catches the most in the fewest minutes:

```bash
tools/check-paths.sh            # nothing points at nothing
tools/gen-module-index.sh --check
tools/check-verbs.sh            # slow: it reads every module
tools/check-gui-pages.sh
tools/check-gui-text.sh
tools/check-glossary.sh
tools/check-theme.sh
tools/check-tui.sh
native/builddir/imsisting-gui --selftest
```

then the codec group for whichever protocol you touched.

A gate's number is not the point and neither is a green board. The point is the
sentence each one asserts; when a gate fails, the useful move is to read its
header comment, which states what it holds and — just as honestly — what it
cannot see.

---

Part 3 has described the surfaces: the command line that is the truth, the
terminal that indexes it, the window that draws it, and the gates that keep the
drawing honest. Part 4 is the catalogue itself — the sixty-one modules, one page
each, in the order the drawer lists them — followed by this window's ten pages
described one at a time, so that "a page each" means the same thing for a module
as it does for the interface that shows it.
