# Part 2 — Getting it running

Part 1 described the toolkit in the abstract. This part is concrete: what must
be installed, what the radios can and cannot do, and one worked session from an
empty machine to a case that contains evidence. §2.1 is the bench, §2.2 is the
radio, §2.3 is the first hour.

## 2.1 The bench: dependencies and pre-flight

IMSISting is a shell toolkit wrapped around external programs. It does not
vendor decoders, drivers or protocol stacks, and it does not pretend to work
without them: a module that needs `tshark` and cannot find it refuses, names
the binary, and exits `2`. That behaviour is only pleasant if you can see the
whole dependency picture before you are in the middle of a survey, which is what
the dependency module exists for.

### `00_deps` — Dependency Manager

```bash
modules/00_deps.sh --preflight        # radio, gates and capture state in one page
modules/00_deps.sh --status-tsv       # one row per registered tool, 6 TSV fields
modules/00_deps.sh --missing-only     # only what is not usable
modules/00_deps.sh --check-versions   # present / absent / broken, with versions
modules/00_deps.sh --report           # write loot/deps/deps_report.tsv
```

Start with `--preflight`. It answers three questions in one screen: is there a
radio, are the capture paths usable, and are the gates clean. The order matters
— a broken capture path makes every later result suspect, and it is cheaper to
find that now than after an hour of survey.

`--status-tsv` is the machine-readable form and the one to use in a script. Each
row describes one tool with six fields: the tool name, its class
(`sdr`, `decode`, `protocol`, `sim`, `net`, …), whether it is usable, the
package that provides it on Debian, the package that provides it on Arch, and a
note. "Usable" is not the same as "installed": a binary that exists but cannot
run is reported as broken, because a toolkit that counts a broken decoder as
present is a toolkit that reports empty results as findings.

`--install-missing` installs what is absent through the distribution's package
manager, and asks before it does. `--install-pip` covers the Python protocol
libraries that are not packaged. Neither is required to use the toolkit: most
modules degrade in a stated way rather than failing, and the ones that cannot
degrade refuse.

### `05_field_kit` — Field Kit

The field kit is the answer to a specific bad habit: claiming a capability
because a binary was on `$PATH`. It performs two things.

`--capability` reports what radio hardware is present and what that implies for
the work you might do next — receive only, transmit capable, full duplex, both
directions but one chain at a time. This is a stronger statement than
`01_radio --list-tsv`, which lists what answered a probe; the field kit maps the
answer onto consequences.

`--guard-check` is the honesty test the rest of the tree leans on. It runs every
radio-gated verb in the toolkit and verifies that each one *fails* correctly
when no radio is present: refusing with a named missing clause, or handing off,
never succeeding with empty output. If any gated verb returns `0` with no radio,
the field kit reports it as a defect. That is the mechanism which keeps
`loot/` honest when the hardware is unplugged, and it is why the modules can be
trusted in a lab.

`--emit` writes synthetic GSMTAP onto the loopback interface (or into a pcap)
from a set of built-in scenarios, and `--scenarios` lists them. This exists so
that the decoders, the stores and the interfaces can be exercised end to end on
a machine with no radio and no live network — and so that a reader of this
manual can reproduce every GSMTAP example in Part 5 without radiating anything.
The synthetic frames are labelled synthetic in the store's source column: a
scenario is evidence about the decoder, never about the air.

### `tools/fetch-reference-data.sh` — the public reference tables

A capture tells you what the air carried. It does not tell you who owns it. The
MCC/MNC register, the ITU's ISPC register and the IANA enterprise numbers are
what turn an identity into an operator, and they are public but not shipped:
they are hundreds of thousands of rows, they are revised, and a stale copy that
looks authoritative is worse than no copy at all.

```bash
tools/fetch-reference-data.sh                 # all three tables
tools/fetch-reference-data.sh --only ispc     # one
tools/fetch-reference-data.sh --check         # present / silent, no download
```

| Table | Source | Rows | Read by |
| ----- | ------ | ---- | ------- |
| `data/public/plmn.tsv` | the full public MCC/MNC register | ~2 500 | `02_cell_recon`, `04_tower_map`, `16_sim` |
| `data/public/ispc.tsv` | ITU Operational Bulletin, Q.708 annex | ~6 300 | `26_ss7_map --ispc` |
| `data/public/pen.tsv` | IANA enterprise numbers | ~67 000 | Diameter vendor ids |

Everything lands under `data/public/`, which is gitignored. Nothing is committed
and nothing is fetched at module run time: a module either finds a table or says
it did not.

The lookups report **three** states, and the difference is the point:

| State | Means | What a caller does |
| ----- | ----- | ------------------ |
| `ok` | the row was found | print the operator |
| `absent` | the table was read and holds no such row | that *is* the finding |
| `silent` | the table is not on this machine | report unobserved, never "absent" |

`silent` and `absent` are routinely confused and they never mean the same
thing. A PLMN that resolves to nothing in a downloaded register is an operator
missing from the public record; a PLMN that resolves to nothing because nobody
ran the fetch is a hole in the analyst's bench. Collapsing the second into the
first manufactures findings, which is the one failure this toolkit exists to
avoid.

### `data/opops/` — the operator's own tables

`data/opops/` is the private half: tables an operator supplies about its own
network. The toolkit ships the loader and the schema, never the contents —
which is also the reason it is useful, because the private numbers a core
network runs on are exactly the ones that must not be in a git repository.

| File | Header | Answers |
| ---- | ------ | ------- |
| `gt.tsv` | `gt_prefix, plmn, stp_type, note` | which PLMN and which STP a global-title prefix belongs to |
| `cellblock.tsv` | `plmn, range_lo, range_hi, kind, note` | whether a cell identity sits inside the block an operator was allocated |
| `iprange.tsv` | `plmn, cidr, role, note` | which core function owns an address |
| `smsc.tsv` | `plmn, smsc_gt, note` | the SMSC a home network routes short messages through |

Validation is an operator-internal binary: a subscriber who watches a spoofed
command from their handset will accept the command when the SMSC is approved,
and the SMSC identity is core-internal. These are not exported by any public
registry, published by any SIM vendor, or in any OEM code. A GT table is the
only thing that turns `op=470012000001` into a statement about the operator
whose HLR is being queried.

With `data/opops/` empty the toolkit is correct and shallow: it decodes, it
correlates, and it reports the store's contents as unobserved where an operator
table would have answered. That is the honest floor, not a bug.

Each table ships as a tracked `*.dist` template in the same directory. Copy the
one you need, drop the `.dist`, and replace the example rows:

```bash
cp data/opops/iprange.tsv.dist data/opops/iprange.tsv
tools/lib/refdata.sh            # source, not run: refdata_status_line
```

The templates carry the schema and one obvious example row each — never a real
operator's numbers, which is the whole reason the directory is private.

### Screening an interconnect peer

`iprange.tsv` is what turns a source address into a statement about a peer.
`11_lte_core` reads it for two questions that a border either answers or does
not, and answers both in the same three states the rest of the toolkit uses:

```bash
modules/11_lte_core.sh --gtp-screen-peer 198.51.100.5 32
modules/11_lte_core.sh --diameter-screen 16777251 316
```

The first asks two things in order. Is this address inside a prefix a
contracted peer was granted, and — the half a peer-level allow rule never
asks — may a peer originate this GTP-C message type at all. A message can come
from the right address and still be wrong: MBMS Session Start, or any
node-initiated procedure, is not something a roaming partner sends.

The second asks whether a Diameter (application, command) pair is one a roaming
peer may originate, or whether it belongs to an interface that only ever
traverses one operator's domain. S6a Update-Location arriving over an
interconnect is the identity-theft shape, not a protocol error, and it is named
as such.

Two things both verbs refuse to do. They do not resolve longest-prefix — the
first matching row wins, so put narrow prefixes above broad ones. And with no
`iprange.tsv` installed they answer `unknown`, not `deny`: a missing file must
never manufacture a blocked-peer finding.

## 2.2 The radio

### Inventory and selection

```bash
modules/01_radio.sh --list-tsv                 # every attached SDR, one row each
modules/01_radio.sh --select 0                 # by index, driver or serial
modules/01_radio.sh --select 'pluto:ip:192.168.2.1'
modules/01_radio.sh --caps-tsv                 # frequencies, rates, gains, direction
modules/01_radio.sh --band-check 942           # which band covers this frequency
```

Each roster row carries nine fields: driver, serial, frequency range, sample
rate range, gain range and direction. **Direction is derived from the driver,
not from the operator's optimism** — an RTL-SDR is `RX`, a HackRF is `RX/TX`, a
PlutoSDR is `RX/TX` on one chain each (a Pluto+ or a LibreSDR has two of each).
Modules that transmit ask `01_radio` whether the selected device can, and refuse
if it cannot; they never ask you.

Driver coverage: `hackrf`, `bladerf`, `limesdr`, `usrp`, `rtlsdr`, `pluto`,
`soapy`. The `pluto` driver exists as its own row rather than as a SoapySDR
vendor because an AD936x board has a control surface that matters: gain mode
must be set to manual before a hardware gain write is honoured, and a Pluto
announces itself over two transports (USB and Ethernet) that are distinct
devices with distinct URIs. `soapy` remains for everything else SoapySDR
supports, with the honest caveat recorded in Part 4: `SoapySDRUtil` enumerates
and configures but cannot write samples to a file, so a Soapy path that produces
a capture must go through gnuradio.

### Tuning, planning and recording

```bash
modules/01_radio.sh --set-freq 942 --set-rate 2000000 --set-gain 30
modules/01_radio.sh --plan hackrf          # the vendor commands that would run
modules/01_radio.sh --record 10            # ten seconds of raw IQ into captures/
```

`--plan` prints the exact vendor command line for the current selection. It is
the opposite of Rule 5 in §1.2: a plan is labelled a plan, it is written to a
`.plan.txt` file when the vendor tool is missing, and it is never presented as a
capture that happened.

`--record` writes raw IQ and reports the **sample format** it wrote, because the
consumer has to know: `cs8` for HackRF, `cu8` for RTL-SDR, `sc16` for bladeRF,
LimeSDR and USRP, `ci16` for a Pluto through libiio, `cf32` for a SoapySDR
flowgraph. A decoder that assumes the wrong format produces noise that looks
like a broken receiver.

### One radio, one owner

```bash
modules/01_radio.sh --lock-claim recon 12345
modules/01_radio.sh --lock-status-tsv
modules/01_radio.sh --lock-release recon
modules/01_radio.sh --lock-recover
```

A single SDR cannot be retuned by two modules at once, and the failure mode is
nasty: the second module silently retunes the first one's radio mid-capture and
the resulting store is a mixture of two experiments. The lock is a claim with an
owner and a pid. `--lock-recover` removes a claim whose owner is dead and
refuses one whose owner is alive — the trap most lock implementations fall into
is that they let a stale lock be stolen from a *running* process.

## 2.3 The first hour

This is one session, in order, from nothing to a case that contains evidence.
Every command below is real; substitute your own frequencies, PLMN and paths.
The example uses a GSM survey with a synthetic GSMTAP source, so it can be
followed on a machine with no radio at all.

### Step 1 — declare the case before touching a radio

```bash
python3 tools/casebook.py status
python3 tools/casebook.py case-create "site-a" "two macro cells, 900 and 1800" \
        "written authorisation, ticket 1234"
```

The case has a name, a **scope** and an **authorisation** note. The casebook asks
for the last two because a capture without a stated basis is a file that gets
deleted the first time somebody asks a lawyer about it, and because scope is what
tells a later reader which of your rows are inside the experiment.

### Step 2 — check the bench

```bash
modules/00_deps.sh --preflight
modules/05_field_kit.sh --capability
```

Nothing else happens until this is clean. If `--preflight` says the capture path
is unusable, fix it now; if `--capability` says receive only, plan a passive
session rather than discovering the limitation halfway through an attack.

### Step 3 — choose and check the radio

```bash
modules/01_radio.sh --list-tsv
modules/01_radio.sh --select 0
modules/01_radio.sh --caps-tsv
modules/01_radio.sh --band-check 942
```

`--band-check` answers whether the device you selected can actually reach the
frequency you intend to work on, including the antenna and amplifier question
that a bare frequency range hides.

### Step 4 — survey

```bash
modules/02_cell_recon.sh --scan gsm
modules/02_cell_recon.sh --list
```

The survey writes `loot/cell_recon/cells.tsv`:

```
rat  gen  arfcn  freq_mhz  plmn  mcc  mnc  operator  country
cell_id  tac_lac  band  rsrp_dbm  cipher  source  ts
```

Read the `source` column. A row that came out of a live scan and a row decoded
out of somebody else's capture are both useful and are not the same evidence.

### Step 5 — declare the target

```bash
modules/02_cell_recon.sh --set-target GSM 42 26201
python3 tools/casebook.py target-set GSM 26201 42 0A1B
```

Two commands, one meaning, two consumers. `02_cell_recon --set-target` writes the
shared radio target that modules read before they decode. The casebook's
`target-set` writes the target into the case, which is what the GUI's target
panel and the reports read. Keeping them in step is the operator's job, and the
GUI shows both so a mismatch is visible rather than silent.

### Step 6 — watch the air

```bash
modules/03_gsmtap.sh --listen 30
modules/03_gsmtap.sh --read captures/gsmtap-*.pcap
modules/03_gsmtap.sh --identities-tsv
```

`--listen` captures UDP 4729 into a pcap for the given number of seconds. Any
GSMTAP source can feed it: this toolkit's field kit, gr-gsm, srsRAN, Open5GS, a
node over the network. `--read` decodes a pcap into
`loot/gsmtap/decoded.tsv`, and `--identities-tsv` prints the identities that
crossed the air in the clear — which, on a 2G network with no cipher, is all of
them.

### Step 7 — read what you wrote, then close the loop

```bash
ls loot/cell_recon loot/gsmtap
python3 tools/casebook.py captures
python3 tools/casebook.py evidence-add loot/gsmtap/decoded.tsv 03_gsmtap observation
python3 tools/casebook.py report-html
```

`evidence-add` takes a file, a module tag, free tags and a sensitivity marker, so
the case records where the file came from and how it should be handled.
`report-html` renders the case — target, evidence, timeline, alerts — into one
document. At this point the first hour is over and you have: a scoped case, a
survey store, a decoded capture, an evidence index and a report, all of which
are files you can hand to somebody else.

---

Part 2 has covered the bench, the radio and a session end to end. Part 3
describes the interfaces those same commands are exposed through — the CLI in
more detail, then the TUI, then the GUI — and the gate suite that keeps the
whole structure from drifting.
