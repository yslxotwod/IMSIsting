#!/usr/bin/env bash
# Deterministic offline contract checks for module 58's normalized event trace.
set -euo pipefail
ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MOD="$ROOT/modules/58_suci_catcher.sh"
D="$(mktemp -d)"
trap 'rm -rf "$D"' EXIT

fail() { printf 'FAIL	%s\n' "$1"; exit 1; }

cat > "$D/complete.tsv" <<'EOF'
uplink	rrc_setup_request
downlink	rrc_setup
uplink	rrc_setup_complete_registration_request
downlink	authentication_request
uplink	authentication_response
downlink	security_mode_command
uplink	security_mode_complete
downlink	registration_accept
EOF
out=$(bash "$MOD" --check-trace "$D/complete.tsv") || fail "complete trace rejected"
printf '%s\n' "$out" | grep -q $'^result\tcomplete$' || fail "complete result missing"
printf '%s\n' "$out" | grep -q $'^state\tregistered$' || fail "registered state missing"
printf '%s\n' "$out" | grep -q $'^identity_payload\tnot-in-trace$' || fail "payload handling declaration missing"
[[ "$(printf '%s\n' "$out" | grep -c $'^transition\t')" == 8 ]] || fail "wrong transition count"

cat > "$D/partial.tsv" <<'EOF'
uplink	rrc_setup_request
downlink	rrc_setup
EOF
out=$(bash "$MOD" --check-trace "$D/partial.tsv") || fail "valid partial trace rejected"
printf '%s\n' "$out" | grep -q $'^result\tpartial$' || fail "partial result missing"
printf '%s\n' "$out" | grep -q $'^expected_next\tuplink rrc_setup_complete_registration_request$' || fail "next event missing"

cat > "$D/invalid.tsv" <<'EOF'
uplink	rrc_setup_request
downlink	registration_accept
EOF
if bash "$MOD" --check-trace "$D/invalid.tsv" >"$D/out" 2>"$D/err"; then
    fail "out-of-order event accepted"
fi
grep -q 'expected downlink rrc_setup' "$D/err" || fail "wrong order diagnostic missing"

if bash "$MOD" --check-trace "$D/missing.tsv" >/dev/null 2>&1; then
    fail "missing trace accepted"
fi
: > "$D/empty.tsv"
if bash "$MOD" --check-trace "$D/empty.tsv" >/dev/null 2>&1; then
    fail "empty trace accepted"
fi
if bash "$MOD" --check-trace "$D/complete.tsv" unexpected-extra >/dev/null 2>&1; then
    fail "extra trace operand accepted"
fi
printf 'uplink\trrc_setup_request\tidentity=must-not-be-accepted\n' > "$D/extra-field.tsv"
if bash "$MOD" --check-trace "$D/extra-field.tsv" >/dev/null 2>&1; then
    fail "trace with identity field accepted"
fi
cat > "$D/too-long.tsv" <<'EOF'
uplink\trrc_setup_request
downlink\trrc_setup
uplink\trrc_setup_complete_registration_request
downlink\tauthentication_request
uplink\tauthentication_response
downlink\tsecurity_mode_command
uplink\tsecurity_mode_complete
downlink\tregistration_accept
uplink\trrc_setup_request
EOF
if bash "$MOD" --check-trace "$D/too-long.tsv" >/dev/null 2>&1; then
    fail "trace with extra transition accepted"
fi

# ── the classifier: scheme, curve, and the operator it refuses to invent ──
out=$(bash "$MOD" --classify 080100000021436587F9) || fail "null-scheme SUCI rejected"
printf '%s\n' "$out" | grep -q 'scheme=0 curve=none' || fail "null scheme not classified as scheme 0"
printf '%s\n' "$out" | grep -q 'msin=clear:123456789' || fail "null-scheme MSIN not reported"
printf '%s\n' "$out" | grep -q 'operator=not-in-suci' || fail "classifier named an operator from a SUCI"
out=$(bash "$MOD" --classify ZZ) || fail "malformed SUCI aborted the classifier"
printf '%s\n' "$out" | grep -q 'malformed' || fail "malformed SUCI not reported as malformed"

# ── the corpus: fixtures whose answer is known verify themselves ──
out=$(bash "$MOD" --corpus "$D/corpus") || fail "corpus did not verify"
printf '%s\n' "$out" | grep -q $'^result\tcorpus-verified$' || fail "corpus result missing"
[[ "$(printf '%s\n' "$out" | grep -c $'^fixture\t.*\tPASS$')" == 5 ]] || fail "wrong verified fixture count"

printf 'RESULT	PASS\n'
