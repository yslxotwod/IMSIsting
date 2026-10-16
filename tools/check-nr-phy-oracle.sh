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
# This script runs tools/nr-phy-oracle/negative-control.sh FIRST, and refuses
# to report on the real module if it does not pass. That control reintroduces
# exactly that seeding bug into a scratch copy and requires the comparator to
# reject it. A check that has never been shown to fail is not evidence, and
# this oracle was written in response to a check that had passed a bug for
# the whole life of the file.
#
# Runtime is about 95 seconds, dominated by 1011 bash function calls inside
# modules/12_nr_air.sh. Keep it inside a 120 s timeout.
#
# What it covers: PSS and SSS sequence generation (TS 38.211 7.4.2.2 and
# 7.4.2.3) over all 3 PSS values and all 1008 cell identities.
#
# What it does NOT cover, stated rather than papered over: the PSS/SSS
# resource-element positions (TS 38.211 7.4.2.1 / 7.4.3), the PBCH and its
# DMRS, PRACH, and every higher-layer stage in the module. Those still rest
# on the module's own selftest vectors, which is the exposure this file
# demonstrates is real.
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
# Usage:  ./tools/check-nr-phy-oracle.sh [workdir]
#
#   workdir   where the virtualenv lives (default
#             /tmp/imsisting-nr-phy-oracle). Pass a private directory to run
#             alongside somebody else.

set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${1:-${TMPDIR:-/tmp}/imsisting-nr-phy-oracle}"
VENV="$WORK/venv"
CMP="$ROOT/tools/nr-phy-oracle/cmp_nr_sync.py"

printf '== NR PHY oracle\n'
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

mkdir -p "$WORK" || { printf 'error: cannot create %s\n' "$WORK" >&2; exit 2; }

# ── set up the external reference implementation ────────────────────────
#
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

# ── negative control first ──────────────────────────────────────────────
#
# Run before the real comparator, because a comparator that cannot fail
# cannot pass either. It reintroduces the LTE SSS seeding bug into a scratch
# copy and requires the comparator to reject it. Cheap (30 cases), and it is
# the difference between "the oracle printed 0 mismatches" and "the oracle
# is able to print anything else".
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

# ── run the comparator ──────────────────────────────────────────────────
#
# $1 was the work directory and is already consumed; only pass through what
# the caller supplied after it (bash's ${@:2} is empty-safe here, but an
# explicit array keeps it obvious under `set -u`).
printf '\n'
extra=("${@:2}")
if "$VENV/bin/python" -c 'import py3gpp, numpy' >/dev/null 2>&1; then
    "$VENV/bin/python" "$CMP" ${extra+"${extra[@]}"}
else
    printf -- '-- py3gpp unavailable; running the spec check with the system python3\n'
    python3 "$CMP" --module "$ROOT/modules/12_nr_air.sh" ${extra+"${extra[@]}"}
fi
rc=$?

printf '\nORACLE EXIT=%d\n' "$rc"
exit "$rc"
