# Part 4 — The catalogue

This is the reference half of the manual. Part 5 describes techniques — what a
family of attacks is for and how the pieces fit; this part describes **objects**:
the sixty-one modules, one page each, in the order the drawer lists them, then
the window's ten pages one at a time, then the target panel.

Read it two ways. As a catalogue, by looking up a module you have already met in
Part 5. Or as a tour, category by category, which is how it is arranged — because
the categories are not filing conveniences, they are the eleven answers to "what
kind of thing is this".

## 4.1 How this catalogue is built

Every module page here has the same five parts, in the same order, and the order
is the order you need them in:

1. **What it is for** — one paragraph, in terms of a session rather than a
   feature list.
2. **The commands** — four to eight lines you can paste, chosen to be a
   *session*, not an exhaustive list. The full list is one command away
   (`modules/NN_name.sh` with no arguments prints it) and printing all 1,400 here
   would make the manual unreadable without making it more complete.
3. **What it keeps** — the store, its path, and what a row in it means. A module
   with no store says so; "writes nothing" is a fact worth recording.
4. **When it refuses** — what has to be absent for the module to stop, and what
   it says when it does.
5. **What to read next** — the module it hands off to, or the technique page in
   Part 5 that puts it in context.

Two conventions run through all of it. A *store* means a file under `loot/` with
a header row, which is to say a thing you may query, diff, hand to somebody else
or delete and rebuild. And a *plan* means a file that describes what a module
would do — the hardware it would need, the steps in order — written before
anything transmits, so that the decision is reviewable by somebody who is not at
the keyboard.

## 4.2 SYSTEM — five modules about the box

These are the modules that answer questions about the machine rather than about
the network: what is installed, what is plugged in, whether the bench is honest,
and how to run everything else in a stated order. They are the category to read
first, and the category to re-read when a result looks wrong, because four times
in five the wrong result is a wrong bench.

### 4.2.1 `00_deps` — Dependency Manager

IMSISting is a shell toolkit over external programs, and this module is the
inventory of those programs. Its table is the single source of truth for "what
can this box do": each entry names a tool, how to probe it, and what its absence
means for the modules that need it.

What makes the inventory worth reading is that detection is by **use**, not by
presence. A `gnuradio` that cannot load the `gr-gsm` out-of-tree blocks, an
`srsRAN` with no application binary, a Python module that will not import — each
is reported `broken`, never `installed`. A file on the PATH proves only that a
file is on the PATH.

```bash
modules/00_deps.sh --preflight        # radio, capture paths and gates in one page
modules/00_deps.sh --status-tsv       # one row per registered tool
modules/00_deps.sh --missing-only     # only what is not usable
modules/00_deps.sh --check-versions   # present / absent / broken, with versions
modules/00_deps.sh --report           # write loot/deps/deps_report.tsv
modules/00_deps.sh --install-missing  # distro packages for what is missing
modules/00_deps.sh --install-pip      # the Python side
```

*What it keeps:* `loot/deps/deps_report.tsv`. Probe results are also memoised to
`tmp/deps_cache.<pid>/` — deliberately to files rather than shell variables,
because the callers read them through command substitution, which runs in a
subshell where an in-memory cache is discarded on exit. The cache key is derived
from `PATH` at call time, so a run that changes `PATH` re-probes instead of
returning a stale "missing".

*When it refuses:* never. This is the one module whose job is to report absence
rather than to refuse because of it — and it is what every other module's `WHY`
line is quoting.

*Read next:* §2.1, which walks the same module as a pre-flight; `01_radio` for the
half of the bench that `00_deps` cannot see.

### 4.2.2 `01_radio` — SDR / Radio Manager

The radio manager is an interface manager for software defined radios:
enumerate what is attached, ask each device what it can actually do, keep one
device selected, and arbitrate who is allowed to touch it.

It probes through each vendor's own tool rather than a generic USB scan, so what
comes back is capability, not a bus address: frequency range, sample rate, gain
range, and **direction**. A receive-only device — an RTL-SDR is the common case —
is flagged on every row and every row it produces, and a verb that would need to
transmit refuses by name instead of failing somewhere inside a vendor CLI with a
message about an argument.

```bash
modules/01_radio.sh --list-tsv                  # every attached SDR
modules/01_radio.sh --caps-tsv                  # what each one can do
modules/01_radio.sh --select 0                  # pick one; remembers the choice
modules/01_radio.sh --band-check 1842.5         # which band is this, can we reach it
modules/01_radio.sh --set-freq 935 --set-gain 32 --set-rate 2000000
modules/01_radio.sh --lock-claim survey 4711    # own the device for one operation
modules/01_radio.sh --lock-status-tsv           # who owns it, live or stale
modules/01_radio.sh --record 30                 # raw IQ into captures/
```

*What it keeps:* `loot/radio/`, the selection in `tmp/sdr_device`, and an
exclusive lock in `tmp/radio.lock`. The lock is the part worth understanding: two
modules recording from one radio produce two broken captures, so a module claims
the device before opening it, the claim is released only by the owner, and
`--lock-recover` removes a stale claim while still refusing to steal a live one.
A killed run leaves a stale claim rather than a silent second owner, which is the
failure you would rather have.

*When it refuses:* with no radio, `--record` and every transmit path stop and name
the missing device. `--plan` is the exception worth knowing: it prints the vendor
commands without running them, so the bench can be reviewed on a machine that has
no radio at all.

*Read next:* §2.2 on the radio, and §5.2 for what the receiver is for.

### 4.2.3 `05_field_kit` — Field Kit

Two jobs, both for the case where time is short and the radio may not be there at
all.

**Pre-flight.** `--capability` says what hardware is present and, more usefully,
what that means: not "hackrf found" but "transmit available on 2G and 4G, receive
only on 3G".

**Honesty verification.** `--guard-check` runs every radio-gated verb on the box
and asserts that each one fails *honestly* — non-zero exit, naming the missing
hardware, no success line, no fabricated row. This is the toolkit checking its own
doctrine rather than asking you to trust it, and its output is a store you can
keep as part of a bench record.

```bash
modules/05_field_kit.sh --capability
modules/05_field_kit.sh --guard-check          # writes loot/field_kit/guard-check.tsv
modules/05_field_kit.sh --scenarios            # what synthetic streams exist
modules/05_field_kit.sh --emit imsi-catcher 12 # deterministic GSMTAP, no radio
modules/05_field_kit.sh --emit gsm-attach 12 10 /tmp/attach.pcap
```

*What it keeps:* `loot/field_kit/guard-check.tsv`. `--emit` writes a pcap when
given a path and UDP datagrams when given a `host:port`; the stream is
deterministic, so the same scenario twice is the same bytes, which is what makes
it usable as a fixture in another module's selftest.

*When it refuses:* nothing to refuse — it is the module that verifies refusals.

*Read next:* §2.2. `--emit` is the best way to try a decoder with no hardware:
pipe it at `03_gsmtap` and read the result.

### 4.2.4 `25_killchain` — Killchain

A chain is a list of steps in a file. Each step names a module, a verb, that
verb's arguments, whether it needs hardware, and a sentence saying what the step
is for. The module runs the steps in order and records what happened to each one.

The point is not automation for its own sake. It is that a multi-step operation —
survey, select, decode, harvest — has an order that matters and a checkpoint that
matters more: a run that dies at step nine should resume at step nine, not at
step one, and the record of that run should say which step it died at.

```bash
modules/25_killchain.sh --list-chains          # every chain, steps, hardware count
modules/25_killchain.sh --show-chain recon     # resolve the steps, run nothing
modules/25_killchain.sh --run recon --dry-run  # print the resolved argv
modules/25_killchain.sh --run recon            # run it, write the report
modules/25_killchain.sh --pause                # cooperative: between steps
modules/25_killchain.sh --resume                # from the checkpoint
modules/25_killchain.sh --run-multi recon targets.tsv   # once per target
modules/25_killchain.sh --runs-tsv             # every recorded run, with outcome
```

A chain file is TSV and readable:

```
step	module	verb	args	hardware	description
1	02_cell_recon	--scan	lte	yes	survey the cell layer
2	03_gsmtap	--read	loot/gsmtap/live.pcap	no	decode what was captured
```

*What it keeps:* `loot/killchain/chains/` for the definitions,
`loot/killchain/runs/` for what happened, and `state/killchain/` for the
checkpoint a resume would use.

*When it refuses:* `--run` refuses a step that needs hardware when none is
present, and stops there unless `--keep-going` was given — in which case it
continues but the run's overall exit is still non-zero. A run that skipped
something is not a successful run.

*Read next:* §5.x for the chains as techniques, and `59_remote_node --dispatch`
for running one of these steps on another machine.

### 4.2.5 `59_remote_node` — Remote Nodes

The fleet. A "node" is another machine, a phone, a modem or a serial device that
can be told to run a module and report what it measured. This module is the front
door to the registry: it names the verbs, keeps the exit codes honest, and adds
the one summary a fleet needs — how far behind each node's spool you are.

The registry itself lives in `tools/casebook.py`, and the far side of a node is
`tools/node_agent.sh`. That split is deliberate: the verbs here are the same ones
the Casebook's Nodes tab calls, so a fleet you built in the window is a fleet you
can drive from a shell.

```bash
modules/59_remote_node.sh --caps                         # what THIS host could be
modules/59_remote_node.sh --presets                      # device classes
modules/59_remote_node.sh --add van-1 pi@10.0.0.5 --transport ssh --role survey
modules/59_remote_node.sh --probe van-1                  # ONLINE / OFFLINE / UNKNOWN
modules/59_remote_node.sh --list-tsv                     # class, caps, role, last seen
modules/59_remote_node.sh --stream van-1 --follow 5      # drain its spool, live
modules/59_remote_node.sh --dispatch van-1 02_cell_recon --scan lte
modules/59_remote_node.sh --collect van-1                # into the active case
modules/59_remote_node.sh --health                       # load, memory, disk, work
```

Transports are `ssh`, `local`, `adb`, `serial`, `qmi`, `mbim`, `diag` and `sms`.
A node's **roles** are inferred from what it actually reported in its probe;
`--set-roles` overrides that, and `--allow` limits which modules may be dispatched
to it, so a node cannot be talked into running something its owner did not
sanction.

*What it keeps:* the registry and the per-node spool cursors in the casebook's
node store; `--collect` copies the far side's state into the open case.

*When it refuses:* `UNKNOWN` is a distinct answer from `OFFLINE` and is never
rounded to either. `--probe` on a node whose transport is missing fails naming the
transport, and `--bulk-probe` continues past an unreachable node without
pretending it answered.

*Read next:* §4.13.5 for the Fleet page, and §5.x for a survey that spans more
than one box.

## 4.3 RECON — three modules about what is out there

Recon is the passive half of the toolkit. Nothing in this category transmits, and
that is why it is safe to start here: the first hour of any operation should cost
nothing but time, and everything learned in it makes the later steps cheaper.

### 4.3.1 `02_cell_recon` — Cell Recon

The reference module: survey GSM, UMTS, LTE or NR cells from a radio or from a
capture, and keep what you found. It is also the module this manual treats as the
worked example of the house contract — self-locating header, shared `tmp/`, TSV
output with untrusted text sanitised, hardware guards that name the missing radio,
and a `--selftest` that runs with no radio at all.

```bash
modules/02_cell_recon.sh --scan lte 20          # one survey pass, band 20
modules/02_cell_recon.sh --scan pcap capture.pcap
modules/02_cell_recon.sh --node van-1           # through a fleet node instead
modules/02_cell_recon.sh --list-tsv             # everything surveyed so far
modules/02_cell_recon.sh --arfcn lte 6300       # EARFCN to downlink MHz
modules/02_cell_recon.sh --plmn 262-01          # PLMN to operator and country
modules/02_cell_recon.sh --set-target lte 6300 262-01
modules/02_cell_recon.sh --export               # copy the survey into loot/
```

`--set-target` writes the *shared radio target* — the one row other modules read
when they need to know which cell the session is about. That is why it is a verb
here and not a setting: the target changes as you move, and it should change in
one place.

*What it keeps:* `loot/cell_recon/cells.tsv` for the current answer and one
`survey_<timestamp>.tsv` per pass, so a survey can be compared with the one before
it rather than overwriting it. ARFCN, PLMN and operator names are decoded from
tables in the module, which is what makes `--arfcn` and `--plmn` usable with no
radio at all.

*When it refuses:* `--scan` with no radio stops and names the device; `--scan
pcap` does not need one. `--node` refuses if the node is `UNKNOWN` rather than
`OFFLINE`, because those two mean different things (§4.2.5).

*Read next:* `04_tower_map` to put the cells on a plane, and §5.3 for a survey as
a technique.

### 4.3.2 `03_gsmtap` — GSMTAP Live Feed

GSMTAP is Osmocom's wrapper: a raw GSM, UMTS, LTE or NR message inside a UDP
packet on port 4729. Everything that can log a message — a base station, an SDR
stack, `05_field_kit --emit` — can log it in this shape, and this module is the
toolkit's ear for it.

The header codec here was verified against Wireshark's GSMTAP dissector rather
than recalled, which matters more than it sounds: two fields in this header are
easy to get backwards (the uplink flag shares a word with the ARFCN, and the
sub-type byte means different things per RAT), and both are asserted in
`--selftest` and in the gates.

```bash
modules/03_gsmtap.sh --listen 30                      # fill a pcap for 30 seconds
modules/03_gsmtap.sh --listen 60 --pipe | wireshark -k -i -
modules/03_gsmtap.sh --read capture.pcap              # decode into the store
modules/03_gsmtap.sh --decode-tsv                     # the store, as TSV
modules/03_gsmtap.sh --identities-tsv                 # identities seen in the clear
modules/03_gsmtap.sh --parse-header 02040d00...
modules/03_gsmtap.sh --build-header 2 1 0 0 0 0 1 0  # build one, as hex
```

The modifiers do the filtering that decides whether a long capture is useful:
`--port`, `--iface`, `--any-port`, `--since` / `--until`, `--arfcn`, `--channel`,
`--uplink`. `--forward host:port` relays every datagram live; `--watchlist FILE`
flags a TMSI, IMSI or IMEI you are looking for.

*What it keeps:* `loot/gsmtap/decoded.tsv`, one row per frame, with the timestamp,
the channel, the direction, the payload in hex and the decoded type where the
toolkit has a decoder for it.

*When it refuses:* `--listen` with no usable network binding says so rather than
capturing nothing quietly; `--read` on a file that is not a pcap names the file and
exits `2`.

*Read next:* `06_gsm_air`, `10_lte_air` and `17_pcap_analysis` consume what this
module stores; §5.3 is the technique.

### 4.3.3 `04_tower_map` — Tower Survey

The GPS-tagged survey: one point per cell, with the fix that was in effect when
the cell was seen, and three exporters. It is a separate module from
`02_cell_recon` on purpose — a survey without position is a list of cells, and a
survey with position is evidence of where they were.

```bash
modules/04_tower_map.sh --start-gpsd              # default /dev/ttyUSB0
modules/04_tower_map.sh --gps-quality-tsv         # fix now, or "no"
modules/04_tower_map.sh --survey lte 20           # one pass, one point per cell
modules/04_tower_map.sh --history                 # with a fix, without, distinct
modules/04_tower_map.sh --export-geojson
modules/04_tower_map.sh --export-kml              # points with a fix only
modules/04_tower_map.sh --export-csv
```

`--history` is the honesty check on the whole exercise: it reports how many points
were recorded with a fix, how many without, and how many distinct cells they
cover. A drive with 400 points and 12 with a fix is not a map, and the module says
so before you export one.

*What it keeps:* `loot/tower_map/points.tsv`, one row per observation with the
cell, the measurements and the position — or the absence of a position, recorded
as absence rather than as zero.

*When it refuses:* with no GPS fix it still surveys, and the points are stored
without one; the exporters exclude them from KML rather than inventing a place.

*Read next:* §4.13.4 for the Map page, which reads the layer files this module and
others write.

---

Part 4 continues with RADIO (§4.4), the fourteen modules that put the toolkit in
contact with the air, and then, category by category, the rest of the catalogue:
ACCESS, CORE NETWORK, SIM / IDENTITY, TRACKING, BASEBAND / DEVICE, ANALYSIS,
EXPLOIT KITS and INTERCEPT / CARRIER. The window's ten pages follow at §4.13 and
the target panel at §4.14.
