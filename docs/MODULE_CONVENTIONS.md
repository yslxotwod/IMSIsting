# IMSIsting module conventions

Every file in `modules/` follows this contract. The GUI, the index generator
and the selftest runner all assume it. Divergence is a bug, not a style choice.

IMSIsting is a cellular security research toolkit covering 2G/GSM, 3G/UMTS,
4G/LTE and 5G/NR. The contract below is deliberately identical in shape to the
one the sibling `wifisting` tree uses, so a module author who knows one tree
can read the other without re-learning anything.

## 1. File naming

    modules/NN_name.sh

`NN` is two digits, `name` is lowercase with underscores. Ranges are grouped
by domain so the menu reads in order:

| Range | Domain |
|---|---|
| 00-09 | setup, radio interfaces, recon |
| 10-19 | per-generation air interface and core attacks |
| 20-29 | SIM/eSIM/OTA, analysis, scanners |
| 30+ | automation, killchain, reporting |

## 2. Header block (mandatory, verbatim shape)

Every module opens with the self-locate block. It resolves `IMSISTING_ROOT`
from the script's own path (following symlinks) so a module invoked directly
still writes into the project tree, then repairs `HOME` for the `pkexec` case.

```bash
#!/usr/bin/env bash
if [[ -z "${IMSISTING_ROOT:-}" ]]; then
    _sl_src="${BASH_SOURCE[0]}"
    while [ -L "$_sl_src" ]; do
        _sl_dir="$(cd -P "$(dirname "$_sl_src")" && pwd)"
        _sl_tgt="$(readlink "$_sl_src")"
        [[ "$_sl_tgt" != /* ]] && _sl_tgt="$_sl_dir/$_sl_tgt"
        _sl_src="$_sl_tgt"
    done
    IMSISTING_ROOT="$(cd -P "$(dirname "$_sl_src")/.." && pwd)"
    export IMSISTING_ROOT
    unset _sl_src _sl_dir _sl_tgt
fi
if [[ -n "${IMSISTING_ROOT:-}" ]]; then
    _real_home="$(dirname "$IMSISTING_ROOT")"
    if [[ -n "$_real_home" && -d "$_real_home" && "$HOME" != "$_real_home" ]]; then
        export HOME="$_real_home"
    fi
    unset _real_home
fi
: "${IMSISTING_HOME:=$IMSISTING_ROOT}"
: "${TMP_DIR:=/tmp/imsisting}"
: "${LOOT_DIR:=$IMSISTING_ROOT/loot}"
: "${CAPTURES_DIR:=$IMSISTING_ROOT/captures}"
: "${LOGS_DIR:=$IMSISTING_ROOT/logs}"
: "${STATE_DIR:=$IMSISTING_ROOT/state}"
mkdir -p "$TMP_DIR" "$LOOT_DIR" "$CAPTURES_DIR" "$LOGS_DIR" "$STATE_DIR" 2>/dev/null
```

`$TMP_DIR` is a **single shared** scratch root at `/tmp/imsisting`. Cross-module
state lives there (`sdr_device`, `target_arfcn`, `target_plmn`, ...). A module
that invents its own private temp root silently loses the ability to see what
another module set.

## 3. The `info` shim — use `declare -F`, never `command -v`

```bash
declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
```

This matters. `/usr/bin/info` (texinfo) exists on most systems, so
`command -v info` succeeds and the shim is never defined — every `info "msg"`
call then execs texinfo, which treats the message as a filename. Define all
four helpers the same way: `info`, `warn`, `err`, `ok`, plus `banner`.

## 4. Function naming

All functions in a module are prefixed with a short lowercase module tag to
avoid collisions when the launcher sources every module into one shell:

    02_cell_recon.sh  ->  crec_*        (banner, info, ... stay unprefixed)

The exit points are always named exactly:

    <tag>_cli_main        dispatch for standalone CLI
    <tag>_cli_status_tsv  machine-readable state
    <tag>_selftest        no-radio verification, exits 0 on pass
    <tag>_menu            interactive menu (the launcher calls this)

## 5. Output contract

- Machine-readable verbs emit **TSV**, one record per line. Key/value is
  `KEY\tVALUE`; tables carry a header row.
- Terminal status lines use `OK\t`, `ERROR\t`, `MISSING\t`, `SKIP\t`.
- Errors go to **stderr**; the function returns non-zero.
- **Never print a success line when the operation failed.** If the write
  failed with `Permission denied`, the module says so and returns non-zero.

## 6. Paths

| Purpose | Variable | Location |
|---|---|---|
| Scratch, pidfiles, fifos | `$TMP_DIR` | `/tmp/imsisting/` |
| Loot, keys, IMSIs, creds | `$LOOT_DIR` | `$IMSISTING_ROOT/loot/<module>/` |
| Captures (IQ, pcap, GSMTAP) | `$CAPTURES_DIR` | `$IMSISTING_ROOT/captures/` |
| Logs | `$LOGS_DIR` | `$IMSISTING_ROOT/logs/` |
| Persistent state (SQLite, JSON) | `$STATE_DIR` | `$IMSISTING_ROOT/state/` |

`mkdir -p` everything before writing to it. Loot paths are per-module so two
modules can never clobber each other's results file.

## 7. Self-test (mandatory)

Every module ships `--selftest`. It must run with **no radio, no root and no
network**, and it must not touch the real loot/capture tree: redirect
`LOOT_DIR`/`CAPTURES_DIR`/`STATE_DIR` into a `mktemp -d` under `$TMP_DIR`
first, and `export` the redirect so helper functions see it too.

The shape:

```bash
<tag>_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }
    # ... assertions ...
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}
```

Assert real behaviour: argument validation, parsing, byte-exact encode/decode
round-trips, TSV fields, and that a failure path returns non-zero. A selftest
that only prints PASS is worse than none — it hides regressions.

## 8. Long-running operations

`--start`/`--stop` pairs must actually reap children:

- Write the pid with **`${BASHPID:-$$}`**, not `$$` — under a subshell `$$` is
  the parent's pid and `--stop` signals the wrong process.
- Give each child its own pidfile so a fallback path can reap it if the trap
  never ran.
- Set the `trap` **after** the child pids are known.
- Make `--stop` idempotent: exiting 0 when nothing ran is correct.

## 9. Honesty about capability

If a verb documents a workflow instead of performing it, say so in its own
output and name it accordingly. A cellular toolkit has many vectors that need
hardware nobody has plugged in — an SDR, a USRP, a programmable SIM, a core
network testbed. Write the plan file, label it a plan, and have the verb print
`status: handoff` with the exact hardware needed. A button that looks like an
attack but produces a README is worse than no button. Where a vector *can* be
performed entirely in software — protocol encoding, pcap analysis, key
derivation, field parsing — perform it for real.

## 10. CLI dispatch

```bash
<tag>_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)  <tag>_cli_status_tsv ;;
        --selftest)    <tag>_selftest ;;
        --menu)        <tag>_menu ;;
        *) cat >&2 <<EOF
Usage: $0 --status-tsv
       $0 --selftest
EOF
           return 2 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -o pipefail
    IMSISTING_CLI=1
    : "${TMP_DIR:=/tmp/imsisting}"
    declare -F banner >/dev/null 2>&1 || banner() { :; }
    declare -F info   >/dev/null 2>&1 || info()   { printf '[info] %s\n' "$*" >&2; }
    declare -F warn   >/dev/null 2>&1 || warn()   { printf '[warn] %s\n' "$*" >&2; }
    declare -F err    >/dev/null 2>&1 || err()    { printf '[err]  %s\n' "$*" >&2; }
    declare -F ok     >/dev/null 2>&1 || ok()     { printf '[ok]   %s\n' "$*" >&2; }
    <tag>_cli_main "$@"
fi
```

Guard every `read -rp` with a CLI check, or the GUI hangs on a prompt:

```bash
if [[ -n "${IMSISTING_CLI:-}" ]]; then
    echo "[-] need a target; cannot prompt in CLI mode" >&2; return 1
fi
```

## 11. After adding a module

1. `bash -n modules/NN_name.sh` must pass.
2. `modules/NN_name.sh --selftest` must exit 0.
3. `modules/NN_name.sh --status-tsv` must emit parseable TSV.
4. Add the module to the `modules[]` table in `native/src/main1.c`. The
   generator reads the display name and category **from that table**, so this
   comes before step 5 or the index will show the raw id and `UNCATEGORISED`.
5. Regenerate the index: `tools/gen-module-index.sh`.
6. Add the module to `IMSISTING_MODULE_TABLE` in `imsisting.sh`.
7. `tools/check-paths.sh` and `tools/check-verbs.sh` must both pass.

## 12. Reading TSV back in — the empty-field trap

**Never read a TSV row with `IFS=$'\t' read -r a b c`.** Tab is whitespace to
`read`, so a run of tabs collapses and every field after an empty one shifts.
This is not theoretical: it silently mis-assigned every column in the tower
survey exporter, and it corrupts any row where a given protocol does not carry
a field (tshark `-T fields` emits empty fields for every layer a frame lacks;
gpsd omits `alt` and `speed` when there is no fix).

Split with `cut -f`, which preserves empty fields:

```bash
F=()
split_tsv() {
    F=()
    local i n
    n=$(printf '%s' "$1" | awk -F'\t' '{print NF}')
    for (( i = 1; i <= n; i++ )); do
        F+=("$(printf '%s' "$1" | cut -f"$i")")
    done
}

while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    split_tsv "$line"
    col_a="${F[0]:-}"; col_b="${F[1]:-}"; col_c="${F[2]:-}"
done < "$file"
```

The same trap applies when building a TSV: an empty field must still emit its
tab, or the consumer sees a short row. `printf 'a\t%s\tc\n' "$empty"` is
correct; a `printf` that omits the separator for empty values is not.

## 13. Do not assert state that may not exist

A selftest must pass on a machine that has never run the toolkit. Create your
own fixture inside the scratch dir, or report `SKIP`. Concretely: a selftest
that assumes no GPS receiver is attached will fail on a machine that has one,
and a selftest that assumes one is attached will fail everywhere else. Test the
*code path*, not the environment — feed the function a known input and assert
the known output.

## 14. Streams, not buffers

`g_subprocess_communicate_utf8_async` in the GUI buffers a module's entire
output and delivers it only when the process exits. That is fine for a
`--status-tsv` call that returns in milliseconds and wrong for a 30-second
survey, where the user sees nothing until it finishes. A live terminal needs
incremental reads from the subprocess pipe. Until the GUI does that, treat the
events drawer as a completion log, not a progress display.

## 15. Bash traps that produce confidently wrong output

These do not fail. They produce a plausible wrong answer, which in a security
tool is worse than a crash. Each was found by a selftest that asserted an
external value, not a self-consistent one.

**`printf '%02X'` does not truncate.** A value above 255 emits three hex digits
and silently corrupts whatever it is spliced into; `%04X` does the same above
65535. Mask at the point of emission, never at the call site:

```bash
<tag>_byte() { printf '%02X' "$(( ${1:-0} & 0xFF ))"; }
<tag>_word() { printf '%04X' "$(( ${1:-0} & 0xFFFF ))"; }
```

**`case` patterns are literal text, not arithmetic.** `case "$b" in 0x07)` never
matches a decimal `7`. Compare decimal, or normalise first.

**`$(( 16#$var ))` aborts the enclosing command substitution** on an empty or
invalid operand, killing the shell instead of returning an error. Validate the
string first:

```bash
[[ "$h" =~ ^[0-9A-Fa-f]{1,2}$ ]] || return 1
v=$(( 16#$h ))
```

**`$(( func arg ))` does not call the function.** That is a syntax error in the
best case and an arithmetic parse in the worst. Use `x=$(func arg)`.

**`local` inside a `while read` body**, combined with `IFS=tab`, wrecks field
splitting. Hoist declarations out of the loop.

**A high rank may mean a weaker cipher.** Rank order is a convention, not a
fact. Assert the ordering explicitly rather than trusting that "higher is
better" — an inverted comparison here reports a downgrade on every session.

## 16. Known-answer tests, not self-consistent ones

A selftest that asserts the value the code already produces only proves the
code is deterministic. It cannot catch a wrong constant. Three real cases from
this tree:

- A5/1 passed self-consistent tests with wrong feedback taps. It was caught
  only by asserting the published Briceno/Goldberg/Wagner vector.
- The NR-ARFCN raster passed because the single ARFCN asserted was a band edge,
  where the offset term is zero and a wrong raster still gives the right answer.
  Test a point *inside* each segment, never only at a boundary.
- The S6a command table passed 270 assertions that encoded the same wrong
  values the code carried. It was caught against Wireshark's 3GPP Diameter
  dictionary.

Where a published vector, spec table or independent implementation exists, the
selftest must assert against that and say in a comment where the value came
from. "It round-trips" is not a known-answer test.

