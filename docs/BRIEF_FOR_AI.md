# Brief for an AI contributing to IMSIsting

Read this before writing a single line. Everything here exists because ignoring it
shipped a real bug.

## What this project is

A cellular security research toolkit at `/home/ysl/IMSIsting`. A GTK4 GUI and a CLI
over **standalone bash modules**. The GUI is a view over the scripts; every action a
button takes is also a command you can run by hand.

Guiding principle: **most tools tell you they worked. This one is built to tell you
when they didn't.** A module that cannot do its job exits non-zero. Nothing reports
success while doing nothing.

Read these first, in order:
- `docs/MODULE_CONVENTIONS.md` — the contract. All 16 sections. This is a bug log, not style advice.
- `modules/02_cell_recon.sh` — the reference module. Copy its structure exactly.
- `modules/15_lte_core.sh` — the model for spec-sourced tables with exhaustive dispatch.
- `docs/ATTACK_COVERAGE.md` — which module owns which attack.

## The hard contract

Every module in `modules/NN_name.sh` must have:

**1. The self-locate header, verbatim from `02_cell_recon.sh`.** Resolves
`IMSISTING_ROOT` from its own path following symlinks, then repairs `HOME` (under
`pkexec`, `HOME=/root`, so `$HOME`-relative paths land wrong).

**2. Shared scratch at `$TMP_DIR` = `/tmp/imsisting`.** Cross-module state
(`sdr_device`, `target_arfcn`, `target_plmn`) lives there. A private temp root means
you cannot see what another module set.

**3. The `info` shim using `declare -F`, never `command -v`:**
```bash
declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
```
`/usr/bin/info` (texinfo) exists, so `command -v info` succeeds, the shim is never
defined, and every `info "msg"` execs texinfo treating the message as a filename.

**4. TSV output.** `KEY\tVALUE`. Errors to stderr. Non-zero on failure. **Never print
a success line when the operation failed** — a bare `return 1` with no message is
indistinguishable from a crash.

**5. Tag-prefixed functions** (`crec_*`, `gtap_*`) because the launcher sources every
module into one shell.

**6. Four fixed verbs:** `<tag>_cli_main`, `<tag>_cli_status_tsv`, `<tag>_selftest`,
`<tag>_menu`.

## The selftest is not optional and not decorative

Your module must ship `--selftest` that:
- exits **0**, and prints a final line `RESULT\tPASS`
- uses the `chk NAME GOT WANT` helper and counts failures
- runs with **no radio, no root, no network**
- redirects `LOOT_DIR`/`CAPTURES_DIR`/`STATE_DIR` into a `mktemp -d` scratch and traps EXIT to clean it
- never touches the real `loot/` tree

**A selftest that checks that directories exist is not a selftest.** That is the
failure mode this project has already been burned by. Ten modules were submitted
that pass `bash -n`, print "selftest passed", and assert **nothing** — they all fail
`tools/run-selftests.sh` because they never emit `RESULT\tPASS`. Do not repeat that.

### Assert against published values, not your own output

A selftest asserting what your code produces proves only that your code is
deterministic. Three real cases passed their own tests while being wrong:

- **A5/1** with wrong feedback taps. Caught only by the published Briceno/Goldberg/Wagner vector.
- **The NR-ARFCN raster** implemented as flat 5 kHz. The selftest passed because the one ARFCN asserted was a band edge, where the offset term is zero. Test a point *inside* a piecewise range, never only at a boundary.
- **The S6a command-code table**, shifted by one from 317. 270 assertions encoded the same wrong values. Caught against Wireshark's 3GPP Diameter dictionary.

**Where a published vector, spec table or independent implementation exists, assert
against it and cite the source in a comment.**

### Adjudicate disputed constants locally

`tshark` decodes most cellular protocols. Build a packet with `text2pcap` and read the
field name back. That technique settled the S6a table, the GTPv2 ULI IE number, and
the GSMTAP channel encoding. `/usr/share/wireshark/diameter/dictionary.xml` holds the
3GPP Diameter command and AVP tables.

### Test both directions

A detector that always fires is useless. Every classifier must assert it fires on the
positive case **and abstains on the negative**.

### An unknown value must never be classified as safe

Unknown algorithm → not "ok". Unknown SST → not eMBB. Unknown CSG mode → not "open".
Unknown TAR → unknown.

### Never assert that state exists

A selftest requiring a database, a capture or a previous run fails for every new user
while passing on the machine that wrote it. Build your own fixture, or report `SKIP`.

## The traps that produce confidently wrong output

These do not error. They return a plausible wrong answer, which is worse.

**Never parse TSV with `IFS=$'\t' read`.** Tab is whitespace to `read`, so a run of
tabs collapses and a row with an empty column shifts every later field. This shipped
twice; it made `23_cipher_audit` read a timestamp as the UE's capability and report a
downgrade on every session. Split with `cut -f`:
```bash
F=()
split_tsv() {
    F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do F+=("$(printf '%s' "$1" | cut -f"$i")"); done
}
```

**`printf '%02X'` does not truncate.** Above 255 it emits three hex digits and
corrupts whatever it is spliced into. Mask at the point of emission.

**`case` patterns are literal text.** `0x07)` never matches a decimal `7`.

**`$(( 16#$var ))` aborts the enclosing command substitution** on bad input, killing
the shell instead of returning an error.

**`$(( func arg ))` does not call the function.**

**`export A=x B="$A/y"` expands `$A` before assignment.**

**A heredoc replaces stdin.** `python3 - <<'EOF'` discards piped data. Stage it
through a file.

**A failed `mkdir` that returns 1 silently is a bug.** Say why.

## One attack, one owner

`docs/ATTACK_COVERAGE.md` assigns each attack to exactly one module. Two owners means
two implementations that disagree. If a capability belongs in an existing module, add
it there; do not create a second module for it.

## Do not duplicate what exists

44 modules are on disk. Before proposing a new one, grep for the capability. Check
`module_index.tsv` and the existing modules' verbs.

## Honesty about hardware

Nothing in this tree has been run against a real radio — there is no SDR on this
machine. Every over-the-air path is written and reviewed, **not verified**. Where a
vector needs hardware, write a `status: handoff` plan naming the exact device, and
say plainly in the output that nothing was sent. **"Written" and "works" are not the
same claim.**

## Legality

Some capabilities must not be built as operational tools regardless of intent:

- **Radio interference / jamming.** Transmitting to deny service is illegal in most jurisdictions, and it degrades emergency calls. Build detection and measurement instead — see `38_jamming_detect`.
- **Interception of communications you are not party to and not authorised for.**
- **Mass enumeration or attack against real subscribers.**
- **Fraud** — SIM swapping, premium-rate abuse, account takeover.

If a request lands in one of those, say so plainly, build the defensive or detection
half, and let the human decide. Do not quietly ship it; do not quietly refuse and
build nothing either.

## Before you say you are done

```bash
bash -n modules/NN_name.sh
modules/NN_name.sh --selftest          # exit 0 AND a RESULT<TAB>PASS line
./tools/gen-module-index.sh            # regenerate; --check fails if stale
./tools/check-paths.sh
./tools/check-verbs.sh
./tools/run-selftests.sh --all
```

Adding a module means four edits:
1. `modules/NN_name.sh`
2. a `modules[]` row in `native/src/main1.c`
3. a `module_registry_register()` call in the same file
4. a row in `IMSISTING_MODULE_TABLE` in `imsisting.sh`, with the module id as the **fifth** field

Do not hand-write `native/src/config.h` — meson generates it, and a copy in `src/`
shadows it and bakes the wrong root into the binary.

## Report format

For each file: the `bash -n` result, the `--selftest` result, the **assertion count**,
the exact commands you ran, what you fixed, and which external source each
known-answer test cites. If you changed an existing assertion, say which and why.
