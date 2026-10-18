# Session handoff — IMSIsting

**Written:** 2026-10-16, at the point where the context was due to be cleared.
**Tree:** `/home/ysl/IMSIsting` · **HEAD:** `10a22c0` · **ahead of `origin/master` by 5**
**Sibling / design reference:** `/home/ysl/wifisting_beta` (read-only reference, never a runtime dependency)

Read this file first. It is the only thing that has to survive a context reset.

---

## 1. What this project is

A GTK4 cellular security toolkit for Linux, with a full CLI behind it. 57 standalone shell
modules in `modules/` covering 2G/GSM, 3G/UMTS, 4G/LTE and 5G/NR, plus passive analysis and
per-generation CVE kits. The GUI (`native/src/main1.c`, ~16,000 lines) is a **view over the
modules, not a container**: every action it can take is also a command you can run by hand.

The rule that decides most arguments: **the GUI may not claim more than the module did.** Every
module has a `--selftest`; hardware-gated verbs name the missing radio instead of returning an
empty result; a module that cannot do its job exits non-zero rather than reporting success.
`modules/05_field_kit.sh --guard-check` exists to prove it.

---

## 2. Build, run, verify — the exact commands

```bash
# build (meson/ninja; style.css is compiled into the binary as a gresource)
cd /home/ysl/IMSIsting && ninja -C native/builddir

# the gates — all four must be green before anything is called done
./native/builddir/imsisting-gui --selftest     # expect: RESULT PASS
tools/check-paths.sh                           # expect: all path checks passed
tools/check-verbs.sh                           # expect: 21 unplaced (the unchanged baseline)
tools/run-selftests.sh                         # expect: passed 57 failed 0 no selftest 0
```

### Seeing a page (the screenshot rig)

There is no window manager and no keyboard into the app under Xvfb; **clicks and scrolling work,
typing does not.** That is why the GUI takes a `--module` switch — use it instead of the search box.

```bash
# 1. a virtual display (recreate it if /tmp was cleaned or it died)
nohup Xvfb :99 -screen 0 1600x1000x24 >/tmp/xvfb.log 2>&1 &

# 2. the app, on a named module page. Other switches: --tab N (permanent page), --selftest,
#    --list-modules. Add --module <id> to land straight on a module page.
cd /home/ysl/IMSIsting
nohup dbus-run-session -- env DISPLAY=:99 GDK_BACKEND=x11 IMSISTING_NO_SPLASH=1 \
  ./native/builddir/imsisting-gui --module 21_lte_cve >/tmp/gui.log 2>&1 &
sleep 14          # it genuinely needs this long; earlier and the shot is black

# 3. screenshot, cropped to the 1180x760 bench
DISPLAY=:99 xwd -root -silent > /tmp/t.xwd
convert /tmp/t.xwd -crop 1180x760+0+0 +repage /tmp/shot.png

# 4. ALWAYS check for GTK complaints. Zero is the bar.
grep -c 'Gtk-CRITICAL\|Gtk-WARNING' /tmp/gui.log
```

**`/tmp/ui.py` is a driver** (`click`, `scroll`, `shot`, `focus`, `type_text`) using XTest via
ctypes. `/tmp` gets cleaned, so it may be gone — the version in this session is worth keeping
somewhere durable. Two things it encodes that cost time to learn:

* `focus()` is required: with no window manager nothing gives the app the keyboard.
* Every ctypes function needs explicit `argtypes`. Without them a 64-bit `KeySym` is passed as a
  32-bit C int and every keycode resolved is wrong.
* **Killing processes:** `pkill -f <pattern>` matches the shell running it and kills your own
  session. Use `pgrep -ax imsisting-gui` (exact name) and kill by PID.

**A UI change is not done until it has been seen.** Screenshot it, crop if needed, read it back.

---

## 3. Standing rules the user has set — these are not preferences

### The three that cost the most to learn (m13152, verbatim)

> * "the button in catalogue have results but where do you see these results ? it should be a place
>   somewhere in the same rectangle window and **never in the output windows** because these windows
>   are going to be removed from every modules they don't look good, **remember that**."
> * "never show the selftest button in the gui"
> * "there shouldn't be any **--verbs visible in the gui never**, remember that too."

### The output-card retirement (m09079, verbatim)

> "btw these output window are ugly so we gonna replace them module by module from now on."

`build_output_card()` (`main1.c:2603`) is **being retired**. When you touch a module page, replace
its raw output card; do not leave a page half-migrated. The CVE pages are done — the remaining
~54 module pages are not. The work is filed as **Phase 20 — the module pages** in
`docs/OFFENSIVE_ROADMAP.md`, with the measured surface, the per-page checklist and the order of
work. **Scope is the 48 spec-driven modules only** — the operator's instruction is to leave the
custom-built pages (`build != NULL`) alone for now, and `00_deps` is excluded by name.

### House style

`native/src/main1.c:1-23` is the architecture note. The conventions the user cares about:

* A module page is a **submenu on the left and a stack of views on the right**.
* `ModuleSubmenuEntry` (`main1.c:245-260`) — `{ name, icon, spec, build }`. `build` wins over
  `spec`; `spec` is `"verb[:Label][!]"` items separated by `|`, `#SECTION` names a card, `~` marks
  a verb whose value cannot be defaulted.
* `radio_view_shell(title, subtitle, &body)` is the shared chrome. `verb_card(heading, &body)` is
  the rectangle. `fkit_flow()`/`fkit_flow_add()` for rows of buttons, `fkit_note()` for prose.
* **The composer is the current standard for "run this."** `fkit_composer()` used to hardcode
  `--emit`; it is now a thin wrapper over `fkit_composer_verb(state, module_id, status, &entry,
  verb, label, placeholder, button_label)` (`main1.c:14286`). The Field Kit's call sites are
  unchanged. A preset **fills** the field and focuses it; it never fires it.
* Views are places: `place_push_view(state, owner, view)`.
* `native/resources/style.css` — use the `@define-color` tokens, never raw hex in a new rule
  unless the value is deliberately outside the set. **If a new rule names a font family, it may
  also need adding to the `window.fonts-system` override list** (the comment above it explains why).
* Extend the shared vocabulary; do not delete or restyle what is not yours.

---

## 4. What is done (the five unpushed commits)

| Commit | What |
|---|---|
| `80341ce` | **SIB4 and SIB5 codecs** in `tools/lte_asn1.py`, and both module decoders rewired to them. The old hand-rolled readers reported framing bits as cell fields. |
| `7c73c9d` | `docs/RANSACKED_CVE_REPORT.md` — a reading of the RANsacked LTE/5G core CVE corpus. |
| `687abec` | **CVE pages filed by class** rather than by verb: one Overview + one view per CVE class, one card per vector. |
| `6c80925` | **CVE results land in their own card.** No output card, no Selftest button, no verb in any label, no button named after one CVE. |
| `10a22c0` | **Target panel redesigned** into three framed zones, and un-occluded from module pages. |

### The two hard-won technical lessons from that work

1. **`GtkOverlay` paints children in the order they were added.** The sheet holding every page was
   added *after* the target column, so opening any page hid the panel. Fixed by adding the target
   column after the sheet (`main1.c:~11760`).
2. **A run reports when the run is finished, not when the process exits.** `g_subprocess_wait_check_async`
   can complete before the stdout/stderr pipe readers have drained, so a callback fired from
   `action_waited` sees only the first line or two. The verdict is recorded there and *reported*
   from `action_run_unref` — the last release, when the process is reaped AND both streams are at
   EOF. This was silently truncating the old output cards too.

### Standing policy: modules are not gated

The operator's rule, given after reviewing Phase 12: **do not build modules behind
an authorisation gate.** The four Phase 12 modules shipped with
`--i-have-a-lab-and-authorisation` and were ungated on that instruction. If you are
about to add a flag whose only job is to make the operator assert something,
don't — the toolkit is a tool, and a warning that costs a flag stops being read.

What replaces a gate, and what a reviewer should check instead:

1. **The artefact is real, the effect is absent.** Encoding, framing, parsing,
   request construction, command files: all done for real. Anything that would act
   on a live system — a socket, a reader, a portal, a phone line, a modulator —
   stops at the artefact and exits 3 with a named handoff.
2. **The note goes in the output, where it is read.** One TSV row (`note`,
   `STANDING_NOTE`) saying what the verb does not do. Not a stderr block: stderr
   is for diagnostics, and `--status-tsv` in particular must stay silent there
   because the GUI polls it.
3. **The retired flag is rejected, not swallowed.** Passing
   `--i-have-a-lab-and-authorisation` to an ungated module must be a usage error
   (rc 2). A silent no-op in a script is worse than the gate ever was.
4. **If a verb warns, warn where the reader is.** Two real defects came out of the
   gated cut and the lesson outlives it: `31_sim_defense` printed its 10-line
   disclaimer from `--status-tsv` (polled every few seconds — a warning nobody
   reads) and *not* on the refusal path (where the one operator who needed it was).

`33_jamming_detect` is the last module that still gates, from an explicit Phase 9
decision; it is a one-function removal if that is revisited.

### Two more, from the `45_iot` decode work### Two more, from the `45_iot` decode work

1. **A decode that slices hex is not a decoder, and its output is worse than an error.** The old
   `--decode-sib1` printed `hex[0:6]` as "MIB-NB", `hex[6:8]` as "SI Period × 1024" and
   `hex[12:18]` as "Cell ID", with exit 0. SIB1-NB is not a MIB-NB, has no TDD field, and its cell
   identity is **28 bits inside `cellAccessRelatedInfo-r13`**. Stable, plausible, invented, and
   indistinguishable from a real reading in the text. When a format has a published layout, either
   drive a real codec or refuse.
2. **pycrate's `to_aper()` is ALIGNED PER; unaligned is `to_uper()`.** TS 36.331 RRC is unaligned.
   Encoding a value with `to_aper` and decoding with the unaligned engine gives a plausible-looking
   mismatch that reads as a broken table. Cost a detour into suspecting the generator.

### The NB-IoT layout table (new, `45_iot`)

`tools/lte_rrc_nb_layout.py` is generated data — `tools/asn1gen.py --family nbiot`, 10 roots over
214 types, certified by `tools/lte-per-oracle/verify_per.py --table tools/lte_rrc_nb_layout.py`
(214/214 types, 2848 cases, 0 disagreements, 912-node structural audit). It is a separate table
because **no LTE root reaches `SystemInformationBlockType1_NB`** — the RRC closure never arrives at
the NB message set. Regeneration needs the oracle venv
(`/home/ysl/.lte-oracles/venv/bin/python`); running the codec needs neither pycrate nor anything
outside the standard library.

### A C bug worth remembering

```c
for (GtkWidget **w = (GtkWidget *[]){ a, b, c };
     w < (GtkWidget *[]){ a, b, c } + 3; w++)     /* WRONG */
```

Two compound literals are **two different arrays**, so the bound is garbage and the loop walks off
the end. Use a named local. This crashed the app twice in one session.

---

## 5. Open objectives, in priority order

1. **Phase 2 — finish it entirely, then report and display the to-do (m11700).**
   The roadmap's build order is `docs/OFFENSIVE_ROADMAP.md` §"Build order". Phase 2 is LTE:
   * `10_lte_air` — eNB run, RRC reconfiguration, SIB forging. **SIB1–SIB5 codecs are done**
     (`tools/lte_asn1.py`, with SIB4/SIB5 using reused `SIB4_Q_OFFSET_CELL` /
     `SIB4_PHYS_CELL_ID_RANGE` tables). Next is SIB6/7/8, then SIB9+.
   * `09_lte_attach` — forged attach.
   * `27_cellular_dns` — aLTEr on-path rewrite.
   The four-point bar every TX module is held to is at `docs/OFFENSIVE_ROADMAP.md:~658`:
   (1) spec-derived and asserted against a published vector or independent implementation, not its
   own output; (2) the transmit path written — waveform, timing, burst structure, SDR calls;
   (3) with no radio it fails honestly, non-zero, naming the missing device; (4)
   `05_field_kit --guard-check` classifies it honest.
2. **The output-card retirement across the remaining ~54 module pages** (m09079).
3. Offered but unanswered: writing the **RANsacked probe set** for the CVE kit (a handful of
   source-tree fingerprint probes, requirement `none`, which run today), and folding the
   recommendation into the roadmap as a Phase 7 note. The reasoning is in
   `docs/RANSACKED_CVE_REPORT.md` and the chat, not yet in the repo.

---

## 6. Where things live

| Thing | Path |
|---|---|
| GUI, all of it | `native/src/main1.c` (16,030 lines) |
| Stylesheet (gresource) | `native/resources/style.css` (2,896 lines) |
| Bundled icons | 57 `imsisting-<id>-symbolic` + `cheatsheets/`; resolved by `imsisting_icon_image()` (`main1.c:89`), which tries the compiled resource then the theme |
| Module registry | `module_registry_init()`, `main1.c:~15600`; module list table `modules[]`, generated index `module_index.c` |
| SIB / ASN.1 codecs | `tools/lte_asn1.py` — `encode_sib2/3/4/5`, `decode_sib2/3/4/5`, `SIBn_VECTORS`, `selftest()` |
| Casebook (targets, evidence, timeline) | `tools/casebook.py`; target fields at `:35` |
| Roadmap | `docs/OFFENSIVE_ROADMAP.md` |
| Module conventions | `docs/MODULE_CONVENTIONS.md` |
| The RANsacked reading | `docs/RANSACKED_CVE_REPORT.md` |

### Key anchors in `main1.c` (line numbers move; grep the symbol)

| Symbol | ~Line | What |
|---|---|---|
| `imsisting_action_run_full` | 1760 | the run: console buffer, `done` callback, `done_owner` kept alive |
| `action_run_unref` | 1650 | **where `done` is actually called** — last release |
| `group_verb_clicked` | 1930 | builds argv and the human label; honours a `label` data key |
| `fkit_composer_verb` | 14286 | the composer standard |
| `rtarget_panel_refresh` | 10623 | the whole target read-out, called from `status_poll` every 3s |
| `build_target_panel` | 10822 | the panel: zones, then the folded form |
| `rtarget_read_signal` | 10568 | sparkline data, from `loot/gsmtap/decoded.tsv` |
| `cve_build_overview` / `cve_build_class` | 15252 / 15203 | the CVE pages |
| `cve_result_strip` | 15048 | the in-card result panel (the output card's replacement) |
| `status_poll` | 4019 | the 3-second tick; drives the header strip, the case counters and the target panel |

### Data the target panel reads

* `tools/casebook.py --target-current-tsv` → `id selected rat plmn channel cell_id area pci band lat lon label first_seen last_seen`
* `loot/cell_recon/cells.tsv` → `rat gen arfcn freq_mhz plmn mcc mnc operator country cell_id tac_lac band rsrp_dbm cipher source ts`
* `loot/gsmtap/decoded.tsv` → `frame type channel arfcn uplink timeslot signal_dbm snr_db frame_number payload_len payload_hex ts_epoch ts_utc`
* `--status-tsv` → `active_case cases targets evidence alerts nodes`

---

## 7. Known state / rough edges

* **The target panel has almost nothing to show on this bench** and that is honest, not broken:
  the active case holds one target (`gsm`, PLMN blank, channel 51), `cells.tsv` is header-only (no
  survey has run), and the GTAP feed has one frame. The panel says `--` for each unknown rather
  than showing a zero.
* The `researched` CVE pages: `21_lte_cve` has **no** `--list-findings` verb, so its catalogue card
  shows two buttons, not three.
* `check-verbs` reports **21 unplaced verbs** — that is the baseline, not a regression. The one
  named in the output is `UNPLACED 55_nr_inject --rar-backoff-idx`.
* The GUI cannot be typed into under Xvfb; `--module` is the way in.

---

## 8. How to resume

1. `cd /home/ysl/IMSIsting && git log --oneline -6` — confirm HEAD is `10a22c0` or later.
2. `ninja -C native/builddir && ./native/builddir/imsisting-gui --selftest` — confirm the tree builds.
3. Re-read §3 above before touching any UI.
4. Pick up **Phase 2, item 1**: SIB6/SIB7/SIB8 codecs in `tools/lte_asn1.py`, following exactly the
   SIB4/SIB5 pattern (vectors captured from pycrate 0.8.1, asserted in `selftest()`), then rewire
   `lair_decode_sib6/7/8` in `modules/10_lte_air.sh` to them and drop
   `lair_note_private_layout` for those types.
5. The one thing worth re-deriving rather than trusting: **the extensibility rule.** pycrate reports
   `_ext = None` for a SEQUENCE with no extension marker, `_ext = []` for one that is extensible but
   declares no additions, and a non-empty list otherwise. An empty list is **not** None — such a
   SEQUENCE still emits its extension bit. A `len(_ext)` test puts the first field one bit early and
   everything after it out by that much. SIB4's `IntraFreqNeighCellInfo` is `[]`; SIB5's
   `InterFreqNeighCellInfo` is `None`. The two look alike and are not.
