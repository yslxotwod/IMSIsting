#!/usr/bin/env bash
#
# Cross-check tools/lte_rrc.py's handover construction against pycrate, an
# independent ASN.1/PER implementation.
#
# This check is NOT part of tools/run-selftests.sh, because it needs a Python
# environment that has pycrate installed (and the tree's runtime is
# dependency-free). Run it by hand when the builder or the layout table changes.
#
# Why it exists: the engine under tools/lte_rrc.py already agrees with pycrate
# bit for bit on random values (tools/lte-per-oracle/verify_per.py). What that
# cannot show is whether the *builder's* field-level semantics are right -- that
# the target cell id an operator writes down ends up in the targetPhysCellId
# field and nowhere else. verify_rrc.py feeds one intended message to both
# encoders, has pycrate read our bits back, and compares the result against the
# operator's own words. Agreeing with a separate codebase on the same input is
# evidence; re-running this tree's encoder on its own output is not.
#
# What this does NOT cover, stated rather than papered over:
#   * any field tools/lte_rrc.py refuses -- the v890/v920 nonCriticalExtension
#     chain, every extension addition (r9 and later groups), the RLC UM bearers,
#     physicalConfigDedicated, drx-Config, phr-Config, and the
#     UTRA/GERAN/CDMA2000 measurement objects are never built, so they are never
#     compared;
#   * on-air behaviour: this compares two encoders, not a UE;
#   * pycrate's own correctness against TS 36.331. pycrate is the independent
#     implementation here; if it is wrong, both encoders are wrong together.
#
# Usage:  ./tools/lte-rrc-oracle/check-lte-rrc-oracle.sh
# Env:    LTE_ORACLE_PY  interpreter holding pycrate (default below)
# Exit:   0 every check agrees, 1 mismatch found, 2 could not set up the oracle.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ORACLE_PY="${LTE_ORACLE_PY:-/home/ysl/.lte-oracles/venv/bin/python}"

command -v python3 >/dev/null || { echo "python3 not found" >&2; exit 2; }

if [ ! -x "$ORACLE_PY" ]; then
    echo "no oracle interpreter at $ORACLE_PY" >&2
    echo "it is the only Python on this machine with pycrate installed;" >&2
    echo "set LTE_ORACLE_PY to point at one, or install pycrate there" >&2
    exit 2
fi

if ! "$ORACLE_PY" -c "import pycrate_asn1dir" >/dev/null 2>&1; then
    echo "$ORACLE_PY cannot import pycrate_asn1dir" >&2
    echo "without it there is no independent implementation to compare against" >&2
    exit 2
fi

echo "== builder selftest (stdlib only, pinned vectors from pycrate) =="
if ! python3 "$ROOT/tools/lte_rrc.py" selftest; then
    echo "the builder's own selftest failed; the oracle cannot mean anything" >&2
    exit 1
fi

echo
echo "== differential against pycrate =="
exec "$ORACLE_PY" "$ROOT/tools/lte-rrc-oracle/verify_rrc.py" "$@"
