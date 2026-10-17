#!/usr/bin/env bash
#
# Cross-check modules/12_nr_air.sh's NR synchronisation sequences against
# TS 38.211 7.4.2, and against py3gpp as an independent implementation.
#
# This check is NOT part of tools/run-selftests.sh: it needs network access
# and a Python virtualenv, and it answers a different question from a
# selftest. Run it by hand when a generation stage changes.
#
# Why it exists: the sequences in modules/12_nr_air.sh were written from the
# specification, and the vectors the module asserts were computed from the
# same reading of it. A misread clause therefore produces a generator, a
# vector and a passing selftest that all encode the same mistake, and the
# selftest can never catch it. This check compares against two things that
# do not share our reading: the clause as written out again from scratch in
# tools/nr-phy-oracle/cmp_nr_sync.py, and py3gpp, a separate implementation.
#
# It already earned its keep. nair_sss_sequence() seeded x0 with the PSS
# initialisation, seeded x1 all-ones, and gave x1 x0's tap -- disagreeing
# with TS 38.211 7.4.2.3 on ALL 1008 cell identities while the module's own
# selftest passed. See the header of cmp_nr_sync.py for the clause.
#
# A second stage runs cmp_nr_mib.py, which answers a different question with
# the same shape of answer: nair_decode_mib() read every MIB field one bit
# early (the BCCH-BCH-MessageType CHOICE selector was omitted, and a padding
# bit invented at 23 to compensate) and reported both ENUMERATED fields
# inverted, so a normal srsRAN cell decoded as "barred". It is checked
# against the clause written out again in cmp_nr_mib.py and against a
# published decoding of a real srsRAN capture. That stage needs no py3gpp.
#
# == Stages ==
#
# The sync stage walks 1011 sequences inside modules/12_nr_air.sh and takes
# 40-60 s on an idle box, and considerably longer on a loaded one. With the
# MIB stage and both negative controls the whole file can exceed the 120 s
# cap this project puts on a check, so the stages are separately selectable
# and each one fits:
#
#   --stage=sync   sequences only          (the long one, 40-60 s)
#   --stage=mib    MIB offsets only        (a few seconds)
#   --stage=num    carrier numerology only (~40 s: 153 cells x 3 helpers,
#                                           each helper shelling out to awk)
#   --stage=bch    the BCH chain only      (~2 s: 6 cases x 24 fields, no
#                                           py3gpp and no network -- this
#                                           stage carries the reliability
#                                           sequence as data)
#   --stage=all    all four                (default)
#
# For a full verification inside the cap, run one stage per invocation:
#
#   timeout 120 ./tools/check-nr-phy-oracle.sh --stage=mib
#   timeout 120 ./tools/check-nr-phy-oracle.sh --stage=bch
#   timeout 120 ./tools/check-nr-phy-oracle.sh --stage=num
#   timeout 120 ./tools/check-nr-phy-oracle.sh --stage=sync
#
# Each stage runs its own negative control FIRST and refuses to report on the
# real module if the control does not pass. A check that has never been shown
# to fail is not evidence, and this oracle was written in response to a check
# that had passed a bug for the whole life of the file.
#
# What it covers: PSS and SSS sequence generation (TS 38.211 7.4.2.2 and
# 7.4.2.3) over all 3 PSS values and all 1008 cell identities; the MIB field
# offsets and enumerations of the BCCH-BCH-Message (TS 38.331 6.2.1 and
# 6.2.2); and the carrier numerology -- N_RB against TS 38.104 Tables
# 5.3.2-1 and 5.3.2-2, and N_FFT and the sample rate as the derivation
# TS 38.104 5.3 defines them.
#
# What it does NOT cover, stated rather than papered over: the PSS/SSS
# resource-element positions (TS 38.211 7.4.2.1 / 7.4.3), the PBCH payload
# beyond the MIB fields, the PBCH polar code, its scrambling and its DMRS,
# the SSB baseband generator and decoder (nair_write_bb_gen at
# modules/12_nr_air.sh:1063 and its decoder at :1455), PRACH, and every
# higher-layer stage in the module. Those still rest on the module's own
# selftest vectors, which is the exposure this file demonstrates is real.
#
# == Tolerance ==
#
# None. PSS and SSS chips are integers in {-1,+1} from mod-2 arithmetic,
# with no floating-point stage anywhere, so every comparison is exact.
# This is unlike the LTE oracle, where srsRAN's single-precision PSS forced
# a tolerance derived from its measured error rather than a guessed one.
#
# == Licensing ==
#
# py3gpp (https://github.com/catkira/py3gpp) is AGPL-3.0. Exactly as with
# srsRAN_4G in tools/check-lte-phy-oracle.sh, it is installed into a
# virtualenv OUTSIDE this repository, is never committed, and its source is
# never copied into this tree -- it is imported as a library and called as a
# black box. The comparator and the reference in it are ours, written from
# TS 38.211. Do not vendor py3gpp, and do not paste its source in here.
#
# Usage:  ./tools/check-nr-phy-oracle.sh [--stage=sync|mib|all] [workdir]
#
#   workdir   where the virtualenv lives (default
#             /tmp/imsisting-nr-phy-oracle). Pass a private directory to run
#             alongside somebody else.

set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGE="${NR_ORACLE_STAGE:-all}"

_args=()
for _a in "$@"; do
    case "$_a" in
        --stage=*)  STAGE="${_a#--stage=}" ;;
        --stage)    printf 'error: use --stage=<sync|mib|num|bch|all>\n' >&2; exit 2 ;;
        -h|--help)
            sed -n 's/^# \{0,1\}//p' "$0" | sed -n '/^Usage:/,/^$/p'
            exit 0 ;;
        *)          _args+=("$_a") ;;
    esac
done
set -- ${_args[@]+"${_args[@]}"}

case "$STAGE" in
    sync|mib|num|bch|all) ;;
    *) printf 'error: unknown stage "%s" (want sync, mib, num, bch or all)\n' "$STAGE" >&2; exit 2 ;;
esac

WORK="${1:-${TMPDIR:-/tmp}/imsisting-nr-phy-oracle}"
VENV="$WORK/venv"
CMP="$ROOT/tools/nr-phy-oracle/cmp_nr_sync.py"

printf '== NR PHY oracle (stage %s)\n' "$STAGE"
printf '   work dir: %s\n' "$WORK"
printf '   module  : %s\n' "$ROOT/modules/12_nr_air.sh"

if [[ ! -f "$CMP" ]]; then
    printf 'error: comparator missing: %s\n' "$CMP" >&2
    exit 2
fi
if [[ ! -f "$ROOT/modules/12_nr_air.sh" ]]; then
    printf 'error: module missing: %s\n' "$ROOT/modules/12_nr_air.sh" >&2
    exit 2
fi

rc=0

# The two pure-Python stages have the same shape: run the two-sided negative
# control first and refuse to report on the real module if it fails, because
# a comparator that has not been shown to fail cannot be shown to pass.
#
#   run_py_stage <label> <comparator> <negative-control>
run_py_stage() {
    local label="$1" cmp="$2" neg="$3" tag="$4" prc=0
    if [[ ! -f "$cmp" ]]; then
        printf '\n!! %s comparator missing; %s is unchecked\n' "$label" "$tag" >&2
        rc=2
        return
    fi
    printf '\n'
    if [[ -f "$neg" ]]; then
        python3 "$neg" || prc=$?
    else
        printf '!! %s negative control missing: %s\n' "$label" "$neg" >&2
        prc=2
    fi
    if [[ $prc -ne 0 ]]; then
        printf '\nerror: the %s negative control did not pass (exit %d).\n' "$label" "$prc" >&2
        printf 'The comparison below would prove nothing, so it is skipped.\n' >&2
        rc=$prc
        return
    fi
    printf '\n'
    python3 "$cmp" --module "$ROOT/modules/12_nr_air.sh" || prc=$?
    [[ $rc -eq 0 && $prc -ne 0 ]] && rc=$prc
}

# ════════════════════════════════════════════════════════════════════════
# stage: mib (no py3gpp needed, no network)
# ════════════════════════════════════════════════════════════════════════
if [[ "$STAGE" == all || "$STAGE" == mib ]]; then
    run_py_stage "MIB" \
        "$ROOT/tools/nr-phy-oracle/cmp_nr_mib.py" \
        "$ROOT/tools/nr-phy-oracle/negative-control-mib.py" \
        "the MIB field offsets"
fi

# ════════════════════════════════════════════════════════════════════════
# stage: bch (no py3gpp needed, no network)
#
# The BCH chain is the one part of the SSB a handset must read before it can
# camp: payload generation, CRC24C, the polar transform, rate matching and the
# two scramblers. The module asserts a pinned codeword for it, and a pinned
# constant computed from the same reading of the clause proves nothing about
# that reading -- which is how the module shipped a wrong CRC24C that its own
# selftest was happy with. This stage derives the codeword independently.
#
# This stage asks the module to regenerate its baseband generator, which the
# module writes to a fixed path under /tmp. Run this ONE AT A TIME in a given
# checkout; a second concurrent run can read, or be read by, the other's copy.
# ════════════════════════════════════════════════════════════════════════
if [[ "$STAGE" == all || "$STAGE" == bch ]]; then
    run_py_stage "BCH" \
        "$ROOT/tools/nr-phy-oracle/cmp_nr_bch.py" \
        "$ROOT/tools/nr-phy-oracle/negative-control-bch.py" \
        "the BCH chain"
fi

# ════════════════════════════════════════════════════════════════════════
# stage: num (no py3gpp needed, no network)
# ════════════════════════════════════════════════════════════════════════
if [[ "$STAGE" == all || "$STAGE" == num ]]; then
    run_py_stage "numerology" \
        "$ROOT/tools/nr-phy-oracle/cmp_nr_numerology.py" \
        "$ROOT/tools/nr-phy-oracle/negative-control-numerology.py" \
        "the carrier numerology"
fi

# ════════════════════════════════════════════════════════════════════════
# stage: sync (needs py3gpp; the long one)
# ════════════════════════════════════════════════════════════════════════
if [[ "$STAGE" == all || "$STAGE" == sync ]]; then
    mkdir -p "$WORK" || { printf 'error: cannot create %s\n' "$WORK" >&2; exit 2; }

    # Installed outside the repo on purpose: AGPL-3.0 code must not enter the
    # tree, and a venv under $WORK is disposable.
    if [[ ! -x "$VENV/bin/python" ]]; then
        printf '\n-- creating virtualenv at %s\n' "$VENV"
        if ! python3 -m venv "$VENV" >/dev/null 2>&1; then
            printf 'error: python3 -m venv failed; install python3-venv\n' >&2
            exit 2
        fi
    fi

    if ! "$VENV/bin/python" -c 'import py3gpp' >/dev/null 2>&1; then
        printf '\n-- installing py3gpp (AGPL-3.0) into %s\n' "$VENV"
        printf '   pip output suppressed unless it fails\n'
        if ! "$VENV/bin/pip" install --quiet --disable-pip-version-check py3gpp \
                >"$WORK/pip.log" 2>&1; then
            printf 'error: pip install py3gpp failed; tail of %s/pip.log:\n' "$WORK" >&2
            tail -15 "$WORK/pip.log" >&2
            printf '\n   Falling back to the spec-only check (no network?).\n'
        fi
    fi

    # Negative control before the real comparator, because a comparator that
    # cannot fail cannot pass either. It reintroduces the LTE SSS seeding bug
    # into a scratch copy and requires the comparator to reject it.
    NEG="$ROOT/tools/nr-phy-oracle/negative-control.sh"
    neg_rc=0
    if [[ -f "$NEG" ]]; then
        printf '\n'
        "$NEG" 30 || neg_rc=$?
    else
        printf '\n!! negative control missing: %s\n' "$NEG" >&2
        neg_rc=2
    fi
    if [[ $neg_rc -ne 0 ]]; then
        printf '\nerror: the negative control did not pass (exit %d).\n' "$neg_rc" >&2
        printf 'The comparator has not been shown to detect the bug it exists to\n' >&2
        printf 'catch, so its result on the real module would prove nothing.\n' >&2
        exit "$neg_rc"
    fi

    # $1 was the work directory and is already consumed; only pass through
    # what the caller supplied after it.
    printf '\n'
    extra=("${@:2}")
    if "$VENV/bin/python" -c 'import py3gpp, numpy' >/dev/null 2>&1; then
        "$VENV/bin/python" "$CMP" ${extra+"${extra[@]}"}
    else
        printf -- '-- py3gpp unavailable; running the spec check with the system python3\n'
        python3 "$CMP" --module "$ROOT/modules/12_nr_air.sh" ${extra+"${extra[@]}"}
    fi
    syncrec=$?
    [[ $rc -eq 0 && $syncrec -ne 0 ]] && rc=$syncrec
fi

if [[ "$STAGE" != all ]]; then
    printf '\n(stage %s only; the other stage did not run)\n' "$STAGE"
fi

printf '\nORACLE EXIT=%d\n' "$rc"
exit "$rc"
