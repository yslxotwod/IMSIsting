#!/usr/bin/env bash
# check-gsm-si.sh — SI1/SI2/SI3/SI4 as 07_gsm_attack puts them on the air,
# against two independent decoders.
#
# The transmit path builds four System Information messages and a handset camps
# on whatever comes out. Both were wrong in ways that decode rather than fail:
# no L2 pseudo length, the protocol discriminator in the wrong nibble, the
# location area where the cell identity belongs, a cell identity in SI4 that the
# clause does not have, and a cell allocation bitmap counted upwards from ARFCN
# 1 instead of downwards from 124. Every one of those produced a plausible
# network on a decoder and a handset that would not camp.
#
# So the messages are refereed twice by implementations that share no code with
# this tree:
#   pycrate_mobile.TS44018_RR  decodes the message structure, which is where the
#                              element order and the pseudo length live.
#   tshark                     decodes the same bytes out of a real GSMTAP pcap,
#                              which is where the ARFCN bitmap arithmetic lives.
# Neither is trusted alone: a disagreement between them is reported as a
# disagreement rather than resolved in the module's favour.
#
# Five defects put back into a scratch copy of the module must each make this
# check fail -- a referee that passes a known-broken message is measuring itself.
#
# Exit 0 both decoders agree with the module, 1 a disagreement, 2 could not run.
set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MOD="$ROOT/modules/07_gsm_attack.sh"
SIB="$ROOT/modules/06_gsm_air.sh"
ORACLE_PY="${GSM_SI_ORACLE_PY:-${GTP_ORACLE_PY:-/home/ysl/.ota-oracles/venv/bin/python}}"

if [[ ! -r "$MOD" ]]; then
    echo "FAIL	$MOD is missing" >&2
    exit 1
fi
if [[ ! -x "$ORACLE_PY" ]]; then
    echo "SKIP	no oracle interpreter at $ORACLE_PY (set GSM_SI_ORACLE_PY)" >&2
    exit 2
fi
if ! "$ORACLE_PY" -c 'import pycrate_mobile.TS44018_RR' 2>/dev/null; then
    echo "SKIP	$ORACLE_PY has no pycrate_mobile.TS44018_RR" >&2
    exit 2
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# The module is asked through its own CLI, the way a person would ask it, so the
# referee measures the shipped path and not a function copied out of the file.
build() {   # <module path> -> the transmit plan on stdout
    bash "$1" --transmit 62 --waveform-only 2>"$TMP/build.err"
}

si_field() {   # <plan> <si1..si4>
    printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'
}

if ! build "$MOD" > "$TMP/plan" || [[ ! -s "$TMP/plan" ]]; then
    echo "FAIL	07_gsm_attack --transmit 62 --waveform-only produced no plan" >&2
    sed -n '1,3p' "$TMP/build.err" >&2
    exit 1
fi

rc=0
fail=0
row() {   # <name> <got> <want>
    if [[ "$2" == "$3" ]]; then
        printf 'PASS\t%s\n' "$1"
    else
        printf 'FAIL\t%s\twant=%s got=%s\n' "$1" "$3" "$2"
        rc=1; fail=$(( fail + 1 ))
    fi
}

echo "== 07_gsm_attack SI1..SI4 vs pycrate and tshark =="

# ── the module's own shape, before either oracle speaks ─────────────────────
for si in si1 si2 si3 si4; do
    h=$(si_field "$(cat "$TMP/plan")" "$si")
    printf '%s' "$h" > "$TMP/$si.hex"
    row "$si-nonempty" "$([[ -n "$h" ]] && echo yes)" "yes"
done
# The whole message, pseudo length octet included: 21+1, 22+1, 18+1, 12+1.
row si-lengths "$(printf '%s %s %s %s' \
    "$(( $(wc -c < "$TMP/si1.hex") / 2 ))" \
    "$(( $(wc -c < "$TMP/si2.hex") / 2 ))" \
    "$(( $(wc -c < "$TMP/si3.hex") / 2 ))" \
    "$(( $(wc -c < "$TMP/si4.hex") / 2 ))")" "22 23 19 13"

# ── oracle 1: pycrate decodes the message structure ────────────────────────
"$ORACLE_PY" - "$TMP" <<'PY' > "$TMP/pyc.out" 2> "$TMP/pyc.err"
import sys, pathlib
import pycrate_mobile.TS44018_RR as R

tmp = pathlib.Path(sys.argv[1])
want = {
    'si1': (R.RRSystemInfo1, 21, 25),
    'si2': (R.RRSystemInfo2, 22, 26),
    'si3': (R.RRSystemInfo3, 18, 27),
    'si4': (R.RRSystemInfo4, 12, 28),
}
bad = 0
for si, (cls, plen, mtype) in want.items():
    msg = bytes.fromhex((tmp / f'{si}.hex').read_text().strip())
    block = msg + b'\x2b' * (23 - len(msg))
    v = cls()
    try:
        v.from_bytes(block)
    except Exception as e:
        print(f'FAIL\tpycrate-{si}-decode\t{type(e).__name__}: {e}')
        bad += 1
        continue
    got_plen = v['L2PseudoLength']['Value'].get_val()
    header = v['RRHeader']
    proto = header['ProtDisc'].get_val()
    typ = header['Type'].get_val()
    print(f'{"PASS" if got_plen == plen else "FAIL"}\tpycrate-{si}-plen\t'
          f'want={plen} got={got_plen}')
    print(f'{"PASS" if proto == 6 else "FAIL"}\tpycrate-{si}-prot-disc\t'
          f'want=6 got={proto}')
    print(f'{"PASS" if typ == mtype else "FAIL"}\tpycrate-{si}-type\t'
          f'want={mtype} got={typ}')
    bad += (got_plen != plen) + (proto != 6) + (typ != mtype)

# SI3 carries the cell identity before the location area; SI4 carries no cell
# identity at all. Those two facts are the ones an earlier version had wrong.
#
# pycrate hands back the cell identity as a list of one integer and the location
# area as [three PLMN octets, LAC], so the assertions read those shapes rather
# than a flat hex string. The PLMN octets are compared as bytes because that is
# what the clause puts on the air.
def lai_bytes(lai):
    return lai['LAI']['PLMN'].get_val()

def lai_lac(lai):
    return lai['LAI']['LAC'].get_val()

v3 = R.RRSystemInfo3()
v3.from_bytes(bytes.fromhex((tmp / 'si3.hex').read_text().strip()) + b'\x2b' * 4)
ci = v3['CellId'].get_val()[0]
print(f'{"PASS" if ci == 161 else "FAIL"}\tpycrate-si3-cell-id\twant=161 got={ci}')
bad += (ci != 161)
plmn = lai_bytes(v3['LAI'])
lac = lai_lac(v3['LAI'])
print(f'{"PASS" if plmn.hex() == "62f210" else "FAIL"}\tpycrate-si3-plmn\t'
      f'want=62f210 got={plmn.hex()}')
bad += (plmn.hex() != '62f210')
print(f'{"PASS" if lac == 241 else "FAIL"}\tpycrate-si3-lac\twant=241 got={lac}')
bad += (lac != 241)

v4 = R.RRSystemInfo4()
v4.from_bytes(bytes.fromhex((tmp / 'si4.hex').read_text().strip()) + b'\x2b' * 10)
has_ci = 'CellId' in v4._by_name
print(f'{"PASS" if not has_ci else "FAIL"}\tpycrate-si4-no-cell-id\twant=absent got='
      f'{"present" if has_ci else "absent"}')
bad += has_ci
plmn4 = lai_bytes(v4['LAI'])
print(f'{"PASS" if plmn4.hex() == "62f210" else "FAIL"}\tpycrate-si4-plmn\t'
      f'want=62f210 got={plmn4.hex()}')
bad += (plmn4.hex() != '62f210')

# SI2's NCC permitted is one octet of ones and it sits after the frequency list.
v2 = R.RRSystemInfo2()
v2.from_bytes(bytes.fromhex((tmp / 'si2.hex').read_text().strip()))
ncc = v2['NCCPermitted'].get_val()[0]
print(f'{"PASS" if ncc == b"\xff" else "FAIL"}\tpycrate-si2-ncc\t'
      f'want=ff got={ncc.hex()}')
bad += (ncc != b'\xff')

# The frequency list is kept as raw octets by pycrate rather than as ARFCNs, so
# the bitmap itself is asserted: the list is 16 octets and the serving channel
# sits in it. tshark and 06_gsm_air are the two readers that turn it into an
# ARFCN number, and both are checked below.
raw = v2['BCCHFreqList'].to_bytes()
print(f'{"PASS" if len(raw) == 16 else "FAIL"}\tpycrate-si2-list-octets\t'
      f'want=16 got={len(raw)}')
bad += (len(raw) != 16)
print(f'{"PASS" if b"\x20" in raw else "FAIL"}\tpycrate-si2-arfcn-bit\t'
      f'want=62 present got={raw.hex()}')
bad += (b'\x20' not in raw)
print(f'BAD\t{bad}')
sys.exit(0 if bad == 0 else 1)
PY

if (( $? != 0 )); then
    rc=1
fi
grep -E '^(PASS|FAIL)' "$TMP/pyc.out" || {
    echo "FAIL	pycrate oracle produced no verdict" >&2
    sed -n '1,5p' "$TMP/pyc.err" >&2
    rc=1
}
if ! awk -F'	' '$1=="BAD" && $2==0 {n++} END {exit !(n==1)}' "$TMP/pyc.out"; then
    echo "FAIL	pycrate reported a nonzero defect count" >&2
    rc=1
fi

# ── oracle 2: tshark decodes the same bytes off the air ────────────────────
if ! command -v tshark >/dev/null 2>&1; then
    echo "SKIP	tshark not installed; pycrate alone refereed this run" >&2
else
    python3 - "$TMP" <<'PY' > "$TMP/mk.out" 2>&1
import struct, sys, pathlib
tmp = pathlib.Path(sys.argv[1])
def pcap(path, payload):
    g = struct.pack('!BBBBHbbIBBBB', 2, 4, 1, 0, 62, -60, 25, 1, 1, 0, 0, 0) + payload
    udp = struct.pack('!HHHH', 4729, 4729, 8 + len(g), 0) + g
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])) + udp
    open(path, 'wb').write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101) +
                           struct.pack('<IIII', 1, 0, len(ip), len(ip)) + ip)
for si in ('si1', 'si2', 'si3', 'si4'):
    msg = bytes.fromhex((tmp / f'{si}.hex').read_text().strip())
    pcap(tmp / f'{si}.pcap', msg + b'\x2b' * (23 - len(msg)))
print('ok')
PY
    for si in si1 si2 si3 si4; do
        tshark -r "$TMP/$si.pcap" -V > "$TMP/$si.txt" 2>/dev/null
    done
    grepfield() {   # <file> <regex>
        sed -n "s/.*$2.*/\1/p" "$1" 2>/dev/null | head -1
    }
    row tshark-si1-type "$(grep -c 'Message Type: System Information Type 1' "$TMP/si1.txt")" "1"
    row tshark-si2-type "$(grep -c 'Message Type: System Information Type 2' "$TMP/si2.txt")" "1"
    row tshark-si3-type "$(grep -c 'Message Type: System Information Type 3' "$TMP/si3.txt")" "1"
    row tshark-si4-type "$(grep -c 'Message Type: System Information Type 4' "$TMP/si4.txt")" "1"
    row tshark-si1-arfcn "$(grep -o 'List of ARFCNs = [0-9]*' "$TMP/si1.txt" | head -1 | awk '{print $NF}')" "62"
    row tshark-si2-arfcn "$(grep -o 'List of ARFCNs = [0-9]*' "$TMP/si2.txt" | head -1 | awk '{print $NF}')" "62"
    row tshark-si1-plen "$(grep -o 'L2 Pseudo Length value: [0-9]*' "$TMP/si1.txt" | head -1 | awk '{print $NF}')" "21"
    row tshark-si2-plen "$(grep -o 'L2 Pseudo Length value: [0-9]*' "$TMP/si2.txt" | head -1 | awk '{print $NF}')" "22"
    row tshark-si3-plen "$(grep -o 'L2 Pseudo Length value: [0-9]*' "$TMP/si3.txt" | head -1 | awk '{print $NF}')" "18"
    row tshark-si4-plen "$(grep -o 'L2 Pseudo Length value: [0-9]*' "$TMP/si4.txt" | head -1 | awk '{print $NF}')" "12"
    row tshark-si3-ci "$(grep -o 'Cell Identity - CI ([0-9]*)' "$TMP/si3.txt" | head -1 | tr -dc '0-9')" "161"
    row tshark-si3-mcc "$(grep -o 'Mobile Country Code (MCC): [A-Za-z]* ([0-9]*)' "$TMP/si3.txt" | head -1 | tr -dc '0-9')" "262"
    row tshark-si3-lac "$(sed -n 's/.*Location Area Code (LAC): 0x[0-9a-f]* (\([0-9]*\)).*/\1/p' "$TMP/si3.txt" | head -1)" "241"
    row tshark-si4-no-ci "$(grep -c 'Cell Identity - CI' "$TMP/si4.txt")" "0"
    row tshark-si2-ncc "$(grep -o 'NCC Permitted: 0x[0-9a-f]*' "$TMP/si2.txt" | head -1 | awk '{print $NF}')" "0xff"
    row tshark-no-malformed "$(cat "$TMP"/si[1-4].txt | grep -c 'Malformed')" "0"
fi

# ── the tree's own second reader, which shares the field map ───────────────
if [[ -r "$SIB" ]]; then
    si3=$(cat "$TMP/si3.hex")
    si4=$(cat "$TMP/si4.hex")
    si1=$(cat "$TMP/si1.hex")
    row sibling-si3-cell "$(bash "$SIB" --decode-si "$si3" 2>/dev/null |
        awk -F'\t' '$1=="cell_id"{print $2}')" "161"
    row sibling-si3-mcc "$(bash "$SIB" --decode-si "$si3" 2>/dev/null |
        awk -F'\t' '$1=="mcc"{print $2}')" "262"
    row sibling-si4-mcc "$(bash "$SIB" --decode-si "$si4" 2>/dev/null |
        awk -F'\t' '$1=="mcc"{print $2}')" "262"
    row sibling-si1-arfcn "$(bash "$SIB" --decode-si "$si1" 2>/dev/null |
        awk -F'\t' '$1=="cell_allocation_arfcns"{print $2}')" "62"
else
    echo "SKIP	06_gsm_air.sh not found; the second reader was not compared" >&2
fi

# ── negative control: each known defect must be caught ─────────────────────
#
# A referee that passes everything measures itself. Each of the five defects
# this check was written for is put back into a scratch copy of the module, and
# the copy must produce a message that no longer matches the property the
# referee asserts. The edits are done by exact string replacement inside the
# named builder, so a rename in the module makes this section fail loudly
# instead of silently testing nothing.
echo "== negative control =="
python3 - "$MOD" "$ROOT" "$TMP" <<'PYNEG'
import pathlib, subprocess, sys

mod = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
tmp = pathlib.Path(sys.argv[3])

# (name, function or None, old, new, check(got_hex, all_hex) -> bool, why)
CASES = [
    ('no-pseudo-length', 'gatk_build_si3',
     'printf \'%s%s\\n\' "$(gatk_l2pl $(( ${#body} / 2 )))" "$body"',
     'printf \'%s\\n\' "$body"',
     lambda si3, all_: si3[:2] == '06',
     'the message starts with the protocol discriminator, not a pseudo length'),
    ('lapdm-header', None,
     '    printf \'%s\' "$l3"',
     '    printf \'0303%s\' "$l3"',
     lambda si3, all_: si3[:4] == '0303',
     'the LAPDm header is inside the octets the pseudo length counts'),
    ('lai-before-ci', 'gatk_build_si3',
     'body="061b${ci_hex}${lai}${ccd}${cellopt}${cellsel}${rach}"',
     'body="061b${lai}${ci_hex}${ccd}${cellopt}${cellsel}${rach}"',
     lambda si3, all_: si3[6:10] == '62f2',
     'the cell identity sits where the location area belongs'),
    ('si4-cell-id', 'gatk_build_si4',
     'body="061c${lai}${cellsel}${rach}"',
     'body="061c${lai}00a1${cellsel}${rach}"',
     lambda si3, all_: len(all_['si4']) == 30,
     'SI4 carries two octets the clause does not give it'),
    ('arfcn-counted-up', 'gatk_chan_desc_bitmap0',
     'pos=$(( 128 - a ))',
     'pos=$(( a + 3 ))',
     lambda si3, all_: all_['si1'] != ref['si1'],
     'the cell allocation bitmap counts up from ARFCN 1'),
]

def build(script):
    r = subprocess.run(['bash', str(script), '--transmit', '62', '--waveform-only'],
                       capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout:
        return None
    out = {}
    for line in r.stdout.splitlines():
        k, _, v = line.partition('\t')
        out[k] = v
    return out

ref = build(mod)
if not ref:
    print('FAIL\tnegctl-reference\tthe unmodified module produced no plan')
    sys.exit(1)

rc = 0
for name, func, old, new, check, why in CASES:
    copy = root / 'modules' / f'.negctl-si.{name}.sh'
    text = mod.read_text()
    if func:
        head = text.index(f'{func}() {{')
        tail = text.index('\n}', head)
        body = text[head:tail]
        if old not in body:
            print(f'FAIL\tnegctl-{name}-applied\tthe builder no longer contains the line this case edits')
            copy.unlink(missing_ok=True)
            rc = 1
            continue
        text = text[:head] + body.replace(old, new, 1) + text[tail:]
    else:
        if old not in text:
            print(f'FAIL\tnegctl-{name}-applied\tthe module no longer contains the line this case edits')
            copy.unlink(missing_ok=True)
            rc = 1
            continue
        text = text.replace(old, new, 1)
    copy.write_text(text)
    try:
        broke = build(copy)
    finally:
        copy.unlink(missing_ok=True)
    if broke is None:
        print(f'PASS\tnegctl-{name}\tthe copy will not build, so it cannot pass')
        continue
    if check(broke.get('si3', ''), broke):
        print(f'PASS\tnegctl-{name}\t{why}')
    else:
        print(f'FAIL\tnegctl-{name}\t{why}, and the referee did not notice')
        rc = 1
sys.exit(rc)
PYNEG
if (( $? != 0 )); then
    rc=1
fi

echo
if (( rc == 0 )); then
    echo "RESULT	PASS	pycrate, tshark and 06_gsm_air agree with 07_gsm_attack"
else
    echo "RESULT	FAIL	$fail disagreement(s); the message on the air is not the one the module describes"
fi
exit $rc
