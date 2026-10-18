# PROJECT_MAP — how to get familiar with IMSIsting

A reader's map, not a duplicate of the README. The README is the tour of *what the
tree claims to do*; this is the tour of *how it is put together, where the live state
actually is, and which documents you can trust*.

Measured against HEAD `009d731` ("Place the call, and keep the dialog one dialog"),
`VERSION` `0.7.0`, 2026-10-17. Re-measure before trusting the "right now" section.

---

## 1. What this is, in sixty seconds

A Linux offensive-security toolkit for cellular networks — 2G through 5G NR plus
SATCOM/sidelink/wifi-offload — wrapped in a numbered-module CLI menu and a GTK4 GUI.
The unit of work is a **module**: one bash script per topic, `modules/NN_name.sh`,
57 of them today, ~74,800 lines total.

Two front ends, one module set:

```
                     ┌─────────────────────────────┐
  ./imsisting.sh ────┤ sources ALL 57 modules      │  in-process bash menu
                     └─────────────────────────────┘
                     ┌─────────────────────────────┐
  native/builddir/   │ never sources anything      │  execs modules/<id>.sh <verb>
  imsisting-gui ─────┤ one subprocess per verb call│
                     └─────────────────────────────┘
```

That single distinction explains most of the oddities. The launcher sources every
module into one shell (`imsisting.sh:644-677`) so a `<tag>_menu` function exists
in-process; the GUI runs `modules/<id>.sh <verb>` as a child
(`native/src/main1.c:884-888`, `:1893-1910`). Consequences:

- A module **must** work both sourced and executed — hence the mandatory
  self-locating header (see §3).
- Anything interactive must be guarded, or the GUI hangs (`IMSISTING_CLI`,
  `docs/MODULE_CONVENTIONS.md:198-204`).
- The GUI buffers subprocess output until exit; its "events drawer" is a
  completion log, not live progress (`docs/MODULE_CONVENTIONS.md:260-267`).
- `imsisting.sh:5` claims the GUI sources the launcher with `IMSISTING_GUI=1`.
  It does not — `main1.c` has only comments about the launcher. That comment is
  the single most misleading line in the tree.

## 2. The four shells

| Layer | Size | Where |
|---|---|---|
| Launcher | 828 lines | `imsisting.sh` |
| Modules | 57 files, ~74,800 lines | `modules/*.sh` (largest: `12_nr_air.sh` 5,552; `07_gsm_attack.sh` 4,411; `10_lte_air.sh` 3,888) |
| GUI | 17,299 lines C | `native/src/main1.c` (16,068) + `native/src/help_page.c` (1,158) + generated `native/src/module_index.c` (73) |
| Tooling | 39 entries | `tools/` (mostly Python + bash oracles) |

Launcher dispatch is a flat table, not discovery: `IMSISTING_MODULE_TABLE` rows are
`CATEGORY|KEY|LABEL|MENU_FUNCTION|MODULE_ID` (`imsisting.sh:388-475`), and
`fn_for_key` maps a key to the menu function (`imsisting.sh:619-628`). Root is
required for the menu but not for `--list` / `--gui` (`imsisting.sh:631-637`).
Start there — read `imsisting.sh:388-475` and you have the whole table of contents
in 88 lines.

## 3. The module contract — learn this before writing a line

`docs/MODULE_CONVENTIONS.md` is the contract. `modules/00_deps.sh` (1,329 lines) is
the reference implementation. Non-negotiables, in the order they will bite you:

1. **Self-locate header, verbatim.** Resolve `IMSISTING_ROOT` from `BASH_SOURCE[0]`
   following symlinks, repair `HOME` for the `pkexec` case, default and `mkdir -p`
   six path variables (`docs/MODULE_CONVENTIONS.md:36-64`; `modules/00_deps.sh:14-43`).
   Copy it; do not improvise it.
2. **Helper shims use `declare -F`, never `command -v`.** `/usr/bin/info` (texinfo)
   exists on most systems and would swallow an `info` call
   (`docs/MODULE_CONVENTIONS.md:71-80`).
3. **Four fixed exit points**, named with the module tag. Only those four names are
   reserved (`docs/MODULE_CONVENTIONS.md:82-94`).
4. **Verbs are a `case` statement.** Unknown verb → usage on stderr, `return 2`
   (`docs/MODULE_CONVENTIONS.md:177-181`; asserted at `modules/00_deps.sh:1208-1209`).
5. **TSV is the interface between module and GUI.** Header row for tables, `KEY\tVALUE`
   for pairs, errors to stderr with non-zero return, terminal tokens `OK` / `ERROR` /
   `MISSING` / `SKIP` (`docs/MODULE_CONVENTIONS.md:96-104`). Sanitise values before
   emitting — a crafted banner can forge a field (`modules/00_deps.sh:65-70`).
   Read it back with a `cut -f` helper, never `IFS=$'\t' read -r a b c`
   (`docs/MODULE_CONVENTIONS.md:218-249`).
6. **`--selftest` is mandatory.** No radio, no root, no network; redirect
   `LOOT_DIR`/`CAPTURES_DIR`/`STATE_DIR` into a `mktemp -d`
   (`docs/MODULE_CONVENTIONS.md:118-123`). Shape: `chk name got want`, then
   `RESULT\tPASS|FAIL(n)`, then `return $(( bad > 0 ))`
   (`modules/00_deps.sh:931-937`, `:1215`). It must assert real behaviour against
   known-answer vectors, not self-consistency
   (`docs/MODULE_CONVENTIONS.md:141-143`, `:306-323`).
7. **`status: handoff`** is the prescribed line when a verb documents a workflow
   instead of performing it, naming the hardware required
   (`docs/MODULE_CONVENTIONS.md:156-165`).
8. **Exit-code semantics.** The GUI treats *exit != 0 **or** `ERROR` on stdout* as
   failure (`native/src/main1.c:1706-1740`), so a "successful" run that prints ERROR
   is indistinguishable from a crash.

`docs/MODULE_CONVENTIONS.md:269-304` lists five bash traps that have each cost
someone a debugging session — `printf '%02X'` does not truncate; `case` patterns are
text, not arithmetic; `$(( 16#$var ))` aborts on empty input; `$(( func arg ))` does
not call; `local` inside `while read` wrecks `IFS` splitting.

## 4. The GUI is a view, and it is generated

C17, GTK4 `>= 4.10`, meson, `gnome.compile_resources` (`native/meson.build:4-87`).
The module sidebar is **not hand-maintained**: `tools/gen-module-index.sh` writes
`native/src/module_index.c` and the root `module_index.tsv` by (a) parsing
`ModuleDefinition modules[]` in `main1.c` for name/category and (b) **running each
module with a bogus verb** and scraping `--flags` out of its usage text
(`tools/gen-module-index.sh:25-80`). Two consequences: adding a module means editing
the C table *and* regenerating; and a module whose usage text is malformed silently
loses buttons. No module implements `--info`, so every entry reads
"(no --info in this module)" (`native/src/module_index.c:14`).

Status polling is a 3-second timer calling each module's `--status-tsv` and reading
columns by header key (`selected_driver`, `selected`, `can_tx`, `freq_hz`, `cells`,
`gps`) — `native/src/main1.c:11922-11925`, `:3990-4100`. Privileged actions are
`pkexec`-prefixed with the real script path so a polkit rule can match it, never
wrapped in `env` (`native/src/main1.c:1813-1827`). The binary has its own
`--selftest` needing no display (`native/src/main1.c:12655-12700`).

## 5. The six data trees

Created and exported on every launcher start (`imsisting.sh:71-84`).

| Tree | Holds | Note |
|---|---|---|
| `tmp/` | Scratch, pidfiles, fifos | Also the **cross-module state bus**: `sdr_device`, `target_arfcn`, `target_plmn`. A private temp root breaks other modules (`docs/MODULE_CONVENTIONS.md:66-69`) |
| `loot/` | Results, one dir per module | **Unredacted** IMSIs, IMEIs, decrypted traffic |
| `logs/` | `session_<date>_<time>_<pid>.log` | Everything `info/ok/warn/err` prints lands here via `tee -a` (`imsisting.sh:368-371`) |
| `captures/` | IQ, pcap, GSMTAP | |
| `state/` | `settings.tsv`, `pins.tsv`, `ui.tsv`, `recent.tsv`, `casebook/` | Precedence: environment > file > default (`imsisting.sh:39-69`) |
| `cases/` | Casebook: scope, target, SHA-256 evidence provenance, reports | Owned by `tools/casebook.py`, one dir per case |

## 6. Verification — there is no CI

No `.github/` exists. Five commands are the entire safety net:

```bash
./tools/run-selftests.sh        # every module's --selftest, 300 s cap each
./tools/check-paths.sh          # module dir ↔ launcher table ↔ GUI table, both directions
./tools/check-verbs.sh          # every documented verb placed in its own submenu spec
./tools/gen-module-index.sh --check   # generated C is up to date
./tools/gen-icons-xml.sh --check      # bundled icons match the tree
```

`run-selftests.sh` requires exit 0 **and** `RESULT PASS`, and reports modules with no
selftest as `MISSING` so the denominator stays visible (`tools/run-selftests.sh:19-111`).
`check-verbs.sh` looks each module's submenu spec up via
`module_registry_register("<id>", …)` so one module cannot borrow another's entry;
a `~verb` prefix marks a deliberate CLI-only verb (`tools/check-verbs.sh:41`, `:55-125`).

Beyond those, the interesting tooling is the **oracle layer**: protocol code is
checked against outside implementations rather than against itself —
`tools/check-lte-phy-oracle.sh` against srsRAN_4G release_23_11,
`tools/lpp_layout.py` generated from the 3GPP TS 36.331 ASN.1 by `tools/asn1gen.py`,
`tools/lte_rrc_nb_layout.py` for the NB-IoT message set (`asn1gen.py --family nbiot`;
no LTE root reaches SIB1-NB, so the LTE table could never carry it),
`tools/gsm_crypto.py` with known-answer vectors for COMP128-1/2/3, Milenage, TUAK,
Keccak-f[1600], A5/1. If you touch air-interface code, that is the standard you are
held to.

## 7. Where the tree actually is right now

Measured, not quoted from a doc. The six gates as they stand:

| Gate | Exit | Result |
|---|---|---|
| `run-selftests.sh` | 0 | **57 passed, 0 failed, 0 missing** |
| `check-paths.sh` | 0 | all path checks passed |
| `gen-icons-xml.sh --check` | 0 | up to date, 67 entries |
| `check-verbs.sh` | 0 | 654 placed, 94 CLI-only, 111 modifiers, 172 exempt; no unplaced verb |
| `check-gui-text.sh` | 0 | no control, label or tooltip named after a verb |
| `gen-module-index.sh --check` | 0 | up to date, 57 modules |

All six are green with the Phase 12 and Phase 14 work in the tree. Detail:

- **Working tree is dirty**, and the documents record it: the four formerly-held
  modules have their offensive halves built (Phase 12) and the Phase 14 gap table
  has eleven rows moved to BUILT. The shape is the same in all of them — detection
  reads what it is given, the offensive verbs take no flag, each carries a one-line
  standing note in its own TSV output, and each exits 3 where the last hop would
  leave the machine. **Do not add an authorisation gate back**: see
  `docs/SESSION_HANDOFF.md`, "Standing policy: modules are not gated".
- **The proof for the new coders is external, not internal.** pycrate for
  RRC/LPP/PWS, tshark for NAS/GTP, the published tables for GPS C/A and PRACH.
  `tools/lte_rrc_layout.py` now carries 18 roots (was 15, and with no DCCH/CCCH
  root the three message builders in `10_lte_air` refused by default) — a generated
  table is only as useful as the roots it was generated from.
- **`module_index.tsv` is generated.** When a module's verb list changes, run
  `./tools/gen-module-index.sh`; never hand-edit the TSV. Every new verb also needs
  a home: a control in its submenu spec in `main1.c`, a `~` prefix if it is
  deliberately CLI-only, or an entry in `modifier_re` if it is a *flag* rather than
  a verb. That last one is a trap — see `docs/SESSION_HANDOFF.md`; widening the
  regex to a name another module already uses as a verb silently stops requiring a
  control for it (`--device` did exactly that, and came straight back out).
- **Two oracles now gate message work,** and both skip rather than pass when the
  tool they need is absent: `tools/check-lte-nb-codec.sh` (pycrate) for the NB-IoT
  RRC table and `tools/check-nas-vectors.sh` (tshark) for the NAS builders. A
  check that reports PASS because its oracle is missing is the failure both exist
  to prevent.
- **A module change needs a GUI restart.** The page re-reads the module on build;
  a screenshot taken against a running instance shows the previous module's data.
  Captures need ~20-25 s after launch or the frame is black.

## 8. Reading order

**Day one, in this order** — you will be productive in about an hour:

1. `README.md:18-33` — why the tree exists and the honesty contract it claims.
2. `README.md:317-425` — the attack status tables, eight of them. Every row says *built*,
   *built·TX*, *partial*, *phase N*, *missing*, or *held*, and the partial rows name
   which half is absent. This is the most valuable section of the README and the
   least likely to be true; treat it as a hypothesis.
3. `imsisting.sh:388-475` — the module table. Your table of contents.
4. `docs/MODULE_CONVENTIONS.md` — all 324 lines. The contract.
5. `modules/00_deps.sh` — skim for the header, the shims, one `--status-tsv`, and
   the selftest harness at `:931-1215`.
6. One real module end to end — `14_suci.sh` (1,734 lines) or
   `17_pcap_analysis.sh` (1,540). Both are self-contained and both have real
   selftests; read one line by line and the other modules become predictable.

**Look things up in:**

| Question | File |
|---|---|
| What does module NN do, what's its tag/menu/category? | `docs/MODULE_ROSTER.md` (per-module scoping decisions at `:153-274`) |
| What's known broken? | `docs/CONFIRMED-BUGS.md` — 37 entries, `#5` retracted, 36 live |
| What's missing per module? | `docs/FEATURE-GAPS.md` — 223 findings, all 56 modules, plus 7 already-fixed |
| What's the build plan? | `docs/OFFENSIVE_ROADMAP.md` — 14 phases, gating TX/LAB/NET/DEVICE |
| What's done / what's next? | `docs/SESSION_HANDOFF.md` — **stale**; verify against `git log` |
| Why was a decision made? | `docs/HANDOFF.md`, `docs/ATTACK_COVERAGE.md` |
| Case/evidence workflow? | `tools/casebook.py` head comment |

## 9. Traps — the things that will waste your afternoon

1. **The docs contradict each other, deliberately and not.** `docs/OFFENSIVE_ROADMAP.md`
   retired the HELD list ("There is no HELD list", `:189-190`) and schedules Phase 12
   as "the formerly held four". `README.md:412` still counts 2 held attacks and says
   they are "described below" — no such section exists; the next heading is
   `## Hardware` at `:427`. `docs/HANDOFF.md:94-99` and `docs/MODULE_ROSTER.md:153,166`
   are the only places that state the hold and its reason. Same shape for the jammer
   TX path: decided-build (`docs/OFFENSIVE_ROADMAP.md:151-153`) vs "not a capability
   this tree ships" (`docs/ATTACK_COVERAGE.md:71-74`). **When two docs disagree, the
   code and `git log` win, then `docs/OFFENSIVE_ROADMAP.md`, because it is newest.**
2. **Module numbering is contested.** `docs/OFFENSIVE_ROADMAP.md:942-951` uses banded
   ids; `docs/MODULE_ROSTER.md:10-12` says contiguous `00`–`56`, next `57`. Contiguous
   is what the tree does — `ls modules/` settles it.
3. **Module counts appear as 56, 57, and 60.** 57 is correct
   (`ls modules/*.sh | wc -l`). `docs/FEATURE-GAPS.md:7` says 56, `README.md:453`
   says 60, `docs/HANDOFF.md:13` says 57.
4. **`AGENTS.md` describes a `GLOSSARY.md` and `docs/adr/` that do not exist.** By that
   file's own convention they are created lazily, so this is a pointer, not a bug —
   but don't go looking for them.
5. **Hardware is not on this machine.** No SDR is attached; nothing in the Hardware
   table has been verified here. Everything that would transmit cannot be exercised
   locally, which is why `built` ≠ `built·TX` and why the selftests are all
   radio-free.
6. **`loot/` is unredacted.** Real IMSIs/IMEIs/decrypted traffic, if anything has run.
   Treat it as sensitive before pasting into an issue.
7. **`module_index.tsv` at the root is generated.** Editing it by hand is silently
   reverted by `gen-module-index.sh --check` complaining and the generator
   overwriting.

## 10. The one-paragraph summary

Read the module table in `imsisting.sh:388-475`, internalise
`docs/MODULE_CONVENTIONS.md`, then run the five verification commands and read their
output — that tells you more about the live state than any of the `docs/*.md`
planning files, three of which are stale and one of which (the roadmap) deliberately
overrides the other two. The code is clean and the test layer is genuinely strong;
the documentation is where the debt is.
