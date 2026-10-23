#!/usr/bin/env bash
# HI1 BER checks: tools/li_hi1.py against pycrate (TS 33.108 Annex M).
#
# modules/42_li_probe.sh encodes the X1/HI1 provisioning and activation records
# with tools/li_hi1.py, a hand-written X.690 encoder with no third-party
# dependency. A hand-written encoder that only agrees with itself is the failure
# this tree keeps paying for, so this check is a second implementation: it
# compiles tools/asn/ts33108-hi1.asn with pycrate's ASN.1 compiler, builds the
# same values with pycrate's runtime, calls .to_ber(), and compares octet for
# octet. pycrate is an oracle here and nowhere else -- the module and
# tools/li_hi1.py run without it.
#
# A case that only one side knows about is a failure, not a skip: a table that
# drifted out of step would otherwise compare the cases that remain.
#
# Exit 0 all cases agree, 1 a disagreement, 2 the check could not run (no
# oracle interpreter). Absence of the oracle is never a pass.
set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ORACLE_PY="${LI_BER_ORACLE_PY:-/home/ysl/.lte-oracles/venv/bin/python}"
TOOL="$ROOT/tools/li_hi1.py"
ASN="$ROOT/tools/asn/ts33108-hi1.asn"

if [[ ! -x "$ORACLE_PY" ]]; then
    echo "SKIP	no oracle interpreter at $ORACLE_PY (set LI_BER_ORACLE_PY)" >&2
    exit 2
fi
if [[ ! -f "$TOOL" ]]; then
    echo "FAIL	$TOOL is missing" >&2
    exit 1
fi
if [[ ! -f "$ASN" ]]; then
    echo "FAIL	$ASN is missing; there is nothing to compile the encoder against" >&2
    exit 1
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/li-ber.XXXXXX")" || {
    echo "FAIL	mktemp failed" >&2
    exit 1
}
trap 'rm -rf "$WORK"' EXIT

echo "== HI1 BER (3GPP TS 33.108 Annex M, ThreeGPP-HI1NotificationOperations) =="
echo "== tools/li_hi1.py vs pycrate's .to_ber() =="

# Case tables. The name is the key both sides agree on; the arguments after the
# pipe are exactly what a caller would pass to tools/li_hi1.py.
ENCODE_CASES="liActivated-utc|--operation liActivated --liid LIID-0001 --utc 2026-01-01T00:00:00Z
liDeactivated-utc|--operation liDeactivated --liid LIID-0001 --utc 2026-01-01T00:00:00Z
liModified-utc|--operation liModified --liid LIID-0001 --utc 2026-01-01T00:00:00Z
localTime-summer|--operation liActivated --liid LIID-0001 --local-time 2026-01-01T00:00:00 --winter-summer summerTime
localTime-winter|--operation liDeactivated --liid LIID-0001 --local-time 2026-12-31T23:59:59 --winter-summer winterTime
localTime-notProvided|--operation liModified --liid LIID-0001 --local-time 2026-06-15T12:00:00 --winter-summer notProvided
netid-e164|--operation liActivated --liid LIID-0001 --utc 2026-01-01T00:00:00Z --operator-id OP01 --ne-id e164:1234
netid-dns|--operation liActivated --liid LIID-0001 --utc 2026-01-01T00:00:00Z --operator-id AB --ne-id dns:df2.example.invalid
target-imsi|--operation liActivated --liid LIID-0001 --utc 2026-01-01T00:00:00Z --target-type imsi
target-msisdn|--operation liActivated --liid LIID-0001 --utc 2026-01-01T00:00:00Z --target-type msisdn
commid|--operation liActivated --liid LIID-0001 --utc 2026-01-01T00:00:00Z --comm-id-num 12345678 --comm-operator-id OP01
commid-target|--operation liModified --liid LIID-0001 --epoch 1700000000 --comm-id-num 42 --comm-operator-id XY --target-type sip-uri
epoch|--operation liActivated --liid L --epoch 1700000000
liid-25|--operation liActivated --liid ABCDEFGHIJKLMNOPQRSTUVWXY --utc 2026-01-01T00:00:00Z
alarms|--operation alarms-indicator --alarm-info ALARM-1 --utc 2026-01-01T00:00:00Z
alarms-liid|--operation alarms-indicator --alarm-info ALARM-1 --utc 2026-01-01T00:00:00Z --liid LIID-0001 --operator-id OP01 --ne-id x25:12345"

# Values that must be refused. The referee is asked to build them too: for a
# SIZE violation pycrate's runtime rejects the value, which is the second
# opinion that the refusal is about the standard and not about this encoder.
REFUSAL_CASES="liid-empty|--operation liActivated --liid '' --utc 2026-01-01T00:00:00Z
liid-26|--operation liActivated --liid ABCDEFGHIJKLMNOPQRSTUVWXYZ --utc 2026-01-01T00:00:00Z
operator-6|--operation liActivated --liid L --utc 2026-01-01T00:00:00Z --operator-id ABCDEF
ne-e164-26|--operation liActivated --liid L --utc 2026-01-01T00:00:00Z --operator-id A --ne-id e164:ABCDEFGHIJKLMNOPQRSTUVWXYZ
alarm-26|--operation alarms-indicator --alarm-info ABCDEFGHIJKLMNOPQRSTUVWXYZ --utc 2026-01-01T00:00:00Z
utc-hour-25|--operation liActivated --liid L --utc 2026-01-01T25:00:00Z
utc-minute-60|--operation liActivated --liid L --utc 2026-01-01T00:60:00Z
utc-second-60|--operation liActivated --liid L --utc 2026-01-01T00:00:60Z
utc-month-13|--operation liActivated --liid L --utc 2026-13-01T00:00:00Z
utc-day-32|--operation liActivated --liid L --utc 2026-01-32T00:00:00Z
utc-feb-30|--operation liActivated --liid L --utc 2026-02-30T00:00:00Z
epoch-past-2049|--operation liActivated --liid L --epoch 4294967295"

# ── the referee ─────────────────────────────────────────────────────────
# pycrate's ASN.1 compiler produces objects that cannot encode; the generator
# writes the runtime module that can. Both steps run here, in the oracle venv
# only.
cat > "$WORK/referee.py" <<'PY'
import datetime
import importlib.util
import os
import sys

root, work = sys.argv[1], sys.argv[2]
asn = os.path.join(root, 'tools', 'asn', 'ts33108-hi1.asn')

from pycrate_asn1c import asnproc
from pycrate_asn1c.generator import PycrateGenerator

asnproc.compile_text(open(asn).read())
modname = 'ThreeGPP-HI1NotificationOperations'
if modname not in __import__('pycrate_asn1c.glob', fromlist=['GLOBAL']).GLOBAL.MOD:
    sys.stderr.write('ERROR\tthe ASN.1 module did not compile\n')
    sys.exit(1)
gen = os.path.join(work, 'gen_hi1.py')
PycrateGenerator(dest=gen)
spec = importlib.util.spec_from_file_location('gen_hi1', gen)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
from pycrate_asn1rt.glob import GLOBAL

MOD = GLOBAL.MOD[modname]

# A UTC time as the 7-tuple pycrate's UTCTime wants: YY, MM, DD, HH, MM, SS,
# zone. The None in the sixth slot of a GeneralizedTime value means "no
# fraction"; the None zone means "local time, no Z suffix".
def utc(y, mo, d, h, mi, s):
    return ('%02d' % (y % 100), '%02d' % mo, '%02d' % d,
            '%02d' % h, '%02d' % mi, '%02d' % s, 'Z')

def utc_epoch(n):
    t = datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=n)
    return utc(t.year, t.month, t.day, t.hour, t.minute, t.second)

def local(y, mo, d, h, mi, s, indication):
    return ('localTime', {
        'generalizedTime': ('%04d' % y, '%02d' % mo, '%02d' % d,
                            '%02d' % h, '%02d' % mi, '%02d' % s, None, None),
        'winterSummerIndication': indication})

def netid(op, form, value):
    return {'operator-Identifier': op,
            'network-Element-Identifier': (form, value)}

CASES = {
    'liActivated-utc': ('liActivated', {
        'lawfulInterceptionIdentifier': b'LIID-0001',
        'timeStamp': ('utcTime', utc(2026, 1, 1, 0, 0, 0))}),
    'liDeactivated-utc': ('liDeactivated', {
        'lawfulInterceptionIdentifier': b'LIID-0001',
        'timeStamp': ('utcTime', utc(2026, 1, 1, 0, 0, 0))}),
    'liModified-utc': ('liModified', {
        'lawfulInterceptionIdentifier': b'LIID-0001',
        'timeStamp': ('utcTime', utc(2026, 1, 1, 0, 0, 0))}),
    'localTime-summer': ('liActivated', {
        'lawfulInterceptionIdentifier': b'LIID-0001',
        'timeStamp': local(2026, 1, 1, 0, 0, 0, 'summerTime')}),
    'localTime-winter': ('liDeactivated', {
        'lawfulInterceptionIdentifier': b'LIID-0001',
        'timeStamp': local(2026, 12, 31, 23, 59, 59, 'winterTime')}),
    'localTime-notProvided': ('liModified', {
        'lawfulInterceptionIdentifier': b'LIID-0001',
        'timeStamp': local(2026, 6, 15, 12, 0, 0, 'notProvided')}),
    'netid-e164': ('liActivated', {
        'lawfulInterceptionIdentifier': b'LIID-0001',
        'timeStamp': ('utcTime', utc(2026, 1, 1, 0, 0, 0)),
        'network-Identifier': netid(b'OP01', 'e164-Format', b'1234')}),
    'netid-dns': ('liActivated', {
        'lawfulInterceptionIdentifier': b'LIID-0001',
        'timeStamp': ('utcTime', utc(2026, 1, 1, 0, 0, 0)),
        'network-Identifier': netid(b'AB', 'dNS-Format', b'df2.example.invalid')}),
    'target-imsi': ('liActivated', {
        'lawfulInterceptionIdentifier': b'LIID-0001',
        'timeStamp': ('utcTime', utc(2026, 1, 1, 0, 0, 0)),
        'target-Information': {'targetType': 'iMSI'}}),
    'target-msisdn': ('liActivated', {
        'lawfulInterceptionIdentifier': b'LIID-0001',
        'timeStamp': ('utcTime', utc(2026, 1, 1, 0, 0, 0)),
        'target-Information': {'targetType': 'mSISDN'}}),
    'commid': ('liActivated', {
        'lawfulInterceptionIdentifier': b'LIID-0001',
        'timeStamp': ('utcTime', utc(2026, 1, 1, 0, 0, 0)),
        'communicationIdentifier': {
            'communication-Identity-Number': b'12345678',
            'network-Identifier': {'operator-Identifier': b'OP01'}}}),
    'commid-target': ('liModified', {
        'lawfulInterceptionIdentifier': b'LIID-0001',
        'timeStamp': ('utcTime', utc_epoch(1700000000)),
        'communicationIdentifier': {
            'communication-Identity-Number': b'42',
            'network-Identifier': {'operator-Identifier': b'XY'}},
        'target-Information': {'targetType': 'sip-URI'}}),
    'epoch': ('liActivated', {
        'lawfulInterceptionIdentifier': b'L',
        'timeStamp': ('utcTime', utc_epoch(1700000000))}),
    'liid-25': ('liActivated', {
        'lawfulInterceptionIdentifier': b'ABCDEFGHIJKLMNOPQRSTUVWXY',
        'timeStamp': ('utcTime', utc(2026, 1, 1, 0, 0, 0))}),
    'alarms': ('alarms-indicator', {
        'timeStamp': ('utcTime', utc(2026, 1, 1, 0, 0, 0)),
        'alarm-information': b'ALARM-1'}),
    # What modules/42_li_probe.sh --provision-target and --activate must emit
    # for the conf this script writes at the end: the module maps WARRANT to the
    # LIID, TARGET_TYPE to target-Information.targetType, and LIPR_NOW to the
    # utcTime, so the module's own artefact is checked against these bytes.
    'module-provision': ('liActivated', {
        'lawfulInterceptionIdentifier': b'LIID-0001',
        'timeStamp': ('utcTime', utc(2026, 1, 1, 0, 0, 0)),
        'target-Information': {'targetType': 'iMSI'}}),
    'module-withdraw': ('liDeactivated', {
        'lawfulInterceptionIdentifier': b'LIID-0001',
        'timeStamp': ('utcTime', utc(2026, 1, 1, 0, 0, 0)),
        'target-Information': {'targetType': 'iMSI'}}),
    'alarms-liid': ('alarms-indicator', {
        'timeStamp': ('utcTime', utc(2026, 1, 1, 0, 0, 0)),
        'alarm-information': b'ALARM-1',
        'lawfulInterceptionIdentifier': b'LIID-0001',
        'network-Identifier': netid(b'OP01', 'x25-Format', b'12345')}),
}

# Values the standard forbids. pycrate's runtime enforces the SIZE constraints
# but not the clock fields, so a refusal is checked against the referee where the
# referee has an opinion and against the constraint text where it does not.
REFUSALS = {
    'liid-empty': ('liActivated', {
        'lawfulInterceptionIdentifier': b'',
        'timeStamp': ('utcTime', utc(2026, 1, 1, 0, 0, 0))}),
    'liid-26': ('liActivated', {
        'lawfulInterceptionIdentifier': b'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        'timeStamp': ('utcTime', utc(2026, 1, 1, 0, 0, 0))}),
    'operator-6': ('liActivated', {
        'lawfulInterceptionIdentifier': b'L',
        'timeStamp': ('utcTime', utc(2026, 1, 1, 0, 0, 0)),
        'network-Identifier': netid(b'ABCDEF', 'e164-Format', b'1')}),
    'ne-e164-26': ('liActivated', {
        'lawfulInterceptionIdentifier': b'L',
        'timeStamp': ('utcTime', utc(2026, 1, 1, 0, 0, 0)),
        'network-Identifier': netid(b'A', 'e164-Format',
                                    b'ABCDEFGHIJKLMNOPQRSTUVWXYZ')}),
    'alarm-26': ('alarms-indicator', {
        'timeStamp': ('utcTime', utc(2026, 1, 1, 0, 0, 0)),
        'alarm-information': b'ABCDEFGHIJKLMNOPQRSTUVWXYZ'}),
}

operation = MOD['ThreeGPP-HI1-Operation']

def encode(value):
    operation.set_val(value)
    return operation.to_ber().hex().upper()

for name, value in CASES.items():
    # The two module-* cases are not tables this script states: they are the
    # values modules/42_li_probe.sh builds from the conf it writes below, and
    # they are compared against the module rather than against the CLIs.
    kind = 'module' if name.startswith('module-') else 'encode'
    try:
        sys.stdout.write('%s\t%s\t%s\n' % (kind, name, encode(value)))
    except Exception as exc:
        sys.stdout.write('error\t%s\tpycrate refused a case that the table '
                         'says is encodable: %s: %s\n'
                         % (name, type(exc).__name__, exc))

for name, value in REFUSALS.items():
    try:
        got = encode(value)
        sys.stdout.write('encoded\t%s\t%s\n' % (name, got))
    except Exception as exc:
        sys.stdout.write('refused\t%s\t%s: %s\n'
                         % (name, type(exc).__name__, exc))
PY

if ! "$ORACLE_PY" "$WORK/referee.py" "$ROOT" "$WORK" > "$WORK/referee.tsv" 2> "$WORK/referee.err"; then
    echo "FAIL	the pycrate referee did not run:" >&2
    sed -n '1,20p' "$WORK/referee.err" >&2
    exit 1
fi
if [[ ! -s "$WORK/referee.tsv" ]]; then
    echo "FAIL	the pycrate referee printed nothing" >&2
    sed -n '1,20p' "$WORK/referee.err" >&2
    exit 1
fi

ref_value() {   # $1 kind, $2 name -> the referee's field 3
    awk -F'\t' -v k="$1" -v n="$2" '$1==k && $2==n {print $3; exit}' "$WORK/referee.tsv"
}
ref_seen() {    # $1 kind, $2 name -> "yes" when the referee has that row
    awk -F'\t' -v k="$1" -v n="$2" '$1==k && $2==n {print "yes"; exit}' "$WORK/referee.tsv"
}

nchk=0
bad=0
pass() { nchk=$(( nchk + 1 )); printf '%s\tPASS\t%s\n' "$1" "${2:-}"; }
fail() { nchk=$(( nchk + 1 )); bad=$(( bad + 1 )); printf '%s\tFAIL\t%s\n' "$1" "$2"; }

# ── encode cases: same value, same octets ───────────────────────────────
while IFS='|' read -r name args; do
    [[ -n "$name" ]] || continue
    if [[ "$(ref_seen encode "$name")" != "yes" ]]; then
        fail "encode-$name" "the referee has no such case (its tables and this one disagree)"
        continue
    fi
    want="$(ref_value encode "$name")"
    # shellcheck disable=SC2086
    got="$("$TOOL" --encode $args --hex 2> "$WORK/ours.err")"
    rc=$?
    if (( rc != 0 )); then
        fail "encode-$name" "tools/li_hi1.py exited $rc: $(sed -n '1,2p' "$WORK/ours.err" | tr '\n' ' ')"
    elif [[ "$got" != "$want" ]]; then
        fail "encode-$name" "ours=$got referee=$want"
    else
        pass "encode-$name"
    fi
done <<< "$ENCODE_CASES"

# ── refusal cases: this encoder refuses, and the standard agrees ────────
while IFS='|' read -r name args; do
    [[ -n "$name" ]] || continue
    # shellcheck disable=SC2086
    eval "set -- $args"
    got="$("$TOOL" --encode "$@" --hex 2> "$WORK/ours.err")"
    rc=$?
    kind="$(awk -F'\t' -v n="$name" '$2==n {print $1; exit}' "$WORK/referee.tsv")"
    if (( rc != 3 )); then
        fail "refuse-$name" "wanted exit 3 (refused), got $rc${got:+ and $got}"
        continue
    fi
    if ! grep -q '^ERROR	' "$WORK/ours.err"; then
        fail "refuse-$name" "refused without an ERROR line on stderr"
        continue
    fi
    case "$kind" in
        refused)
            pass "refuse-$name" "pycrate refuses the same value"
            ;;
        encoded|'')
            # The referee has no opinion (pycrate's UTCTime does not range-check
            # the clock), so the case stands on the constraint it names: the
            # refusal text has to say what is out of range.
            if grep -qiE 'outside|SIZE|cannot be written|not modelled|is required|no timestamp' \
                    "$WORK/ours.err"; then
                pass "refuse-$name" "pycrate has no opinion on this value; the refusal names its constraint"
            else
                fail "refuse-$name" "refused without naming the constraint: $(tr '\n' ' ' < "$WORK/ours.err")"
            fi
            ;;
        error)
            fail "refuse-$name" "$(ref_value error "$name")"
            ;;
        *)
            fail "refuse-$name" "unexpected referee row '$kind'"
            ;;
    esac
done <<< "$REFUSAL_CASES"

# ── the two tables have to be the same size ─────────────────────────────
refused_n="$(awk -F'\t' '$1=="refused"{c++} END{print c+0}' "$WORK/referee.tsv")"
edited_n=0
while IFS= read -r line; do
    [[ -n "$line" ]] && edited_n=$(( edited_n + 1 ))
done < <(awk -F'\t' '$1=="encode"{print $2}' "$WORK/referee.tsv")
ours_n=0
while IFS= read -r line; do
    [[ -n "$line" ]] && ours_n=$(( ours_n + 1 ))
done <<< "$ENCODE_CASES"
if (( ours_n != edited_n )); then
    fail "table-sizes" "this script states $ours_n encode case(s), the referee built $edited_n"
else
    pass "table-sizes"
fi
# The refusals must not all rest on this encoder's own judgement: pycrate has to
# reject the SIZE violations on its own, or the "refusal" is one implementation
# quarrelling with itself.
if (( refused_n >= 5 )); then
    pass "referee-refusals" "pycrate independently refuses $refused_n of these values"
else
    fail "referee-refusals" "pycrate refused only $refused_n value(s); the SIZE cases are not being checked against the standard"
fi

before="$bad"
# ── the module itself, not just the encoder ─────────────────────────────
# modules/42_li_probe.sh must emit exactly the referee's PDU for the same value:
# a correct encoder behind a wrong mapping is still a wrong artefact. The module
# exits 3 by design (it prints the artefact and hands delivery off), so the exit
# code is not the thing under test here.
cat > "$WORK/target.conf" <<'CONF'
TARGET_TYPE=imsi
TARGET=310150123456789
WARRANT=LIID-0001
SERVICES=iri,cc
DF2_DEST=10.0.0.2:9002
DF3_DEST=10.0.0.2:9003
CONF

module_pdu() {   # $1 verb, ... -> the artefact_hex the module prints
    local out
    out="$(LIPR_NOW=1767225600 bash "$ROOT/modules/42_li_probe.sh" "$@" "$WORK/target.conf" 2> "$WORK/module.err")"
    printf '%s\n' "$out" | awk -F'\t' '$1=="artefact_hex"{print $2; exit}'
}

for pair in "module-provision|--provision-target" "module-withdraw|--activate --action withdraw"; do
    name="${pair%%|*}"
    verb="${pair#*|}"
    want="$(ref_value module "$name")"
    # shellcheck disable=SC2086
    got="$(module_pdu $verb)"
    if [[ -z "$got" ]]; then
        fail "module-$name" "the module printed no artefact_hex: $(tr '\n' ' ' < "$WORK/module.err")"
    elif [[ "$got" != "$want" ]]; then
        fail "module-$name" "module=$got referee=$want"
    else
        pass "module-$name"
    fi
done

if (( bad == before && bad == 0 )); then
    echo
    echo "all HI1 BER checks agree with pycrate"
fi
printf 'ASSERTIONS\t%d\n' "$nchk"
printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
(( bad == 0 )) || exit 1
exit 0
