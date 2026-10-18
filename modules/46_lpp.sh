#!/usr/bin/env bash
# LPP Position Forgery — LTE Positioning Protocol (TS 37.355)
#
# LPP (LTE Positioning Protocol) is the positioning payload itself; it is not
# carried directly. Between the eNB and the E-SMLC it rides LPPa over S1AP
# (TS 36.455, TS 36.413), between the E-SMLC and the UE it rides NAS, and in
# 5G the same role is NRPPa (TS 38.455) over NGAP. This module builds and
# reads the LPP message, which is the part that carries the position.
#
# Attack owned: O14/P8 adjacency (location via signalling, positioning
# integrity). `--forge-position` builds a real LPP ProvideLocationInformation
# -- the message a target device sends the E-SMLC when it reports where it is
# -- with coordinates of the operator's choosing. `--parse-position` reads one
# back. Both go through the generated PER codec (tools/lte_asn1.py "lpp-*",
# table tools/lpp_layout.py from pycrate), so the bytes are the message, not an
# approximation of it; tools/lpp-oracle/check_lpp_position.py asserts that
# against pycrate bit for bit.
#
# What is NOT done here: delivery. To reach an E-SMLC the PDU has to be
# carried by a UE's NAS security context or by an eNB-side LPPa peer. Both are
# real projects (...11_lte_core.sh has S1AP), and neither is pretended below:
# --forge-position builds and stops, saying what it stopped short of
# (MODULE_CONVENTIONS §9).
#
# The positioning PROCEDURE half lives here too (Phase 14 row "OTDOA/UTDOA/PRS
# spoofing"). --otdoa-assist builds the OTDOA-ProvideAssistanceData an E-SMLC
# sends so a UE can measure PRS: reference cell and neighbours, each with
# prs-Bandwidth, prs-ConfigurationIndex, numDL-Frames and, on the reference
# cell, prs-MutingInfo. --otdoa-request builds what the UE sends back (its
# capabilities, or OTDOA-SignalMeasurementInformation with an RSTD and quality
# per neighbour), which is the shape a spoofed response has to look like.
# --prs-plan turns a PRS-ConfigurationIndex into the subframe occasions
# TS 36.211 6.10.4 gives it. The OTDOA messages go through the same generated
# PER table as the position report (tools/lpp_layout.py + tools/lte_per.py) and
# --oracle-check re-encodes the same values with pycrate and fails if a bit
# moved.
#
# Synopsis (the usage text above stays short on purpose: tools/check-verbs.sh
# harvests every --token from this module's usage output and reports the ones no
# menu reaches, so an option list there would look like ten commands):
#   --otdoa-assist  [--pci N] [--ecgi MCC:MNC:CI|none] [--earfcn N]
#                   [--prs-bw n6|n15|n25|n50|n75|n100] [--prs-index N]
#                   [--num-dl-frames sf-1|sf-2|sf-4|sf-6]
#                   [--muting po2|po4|po8|po16:BITS|none]
#                   [--nbr PCI:RSTD:UNC[:CP][:PRS-BW:PRS-IDX:numDL-FRAMES],...]
#                   [--initiator ...] [--transaction N]
#   --otdoa-request [--form measure|capabilities] [--sfn N] [--pci N]
#                   [--earfcn N] [--ref-res N] [--ref-val N] [--ref-samples N]
#                   [--nbr PCI:RSTD:RES:VAL[:SAMPLES],...] [--initiator ...]
#   --utdoa-config  [--pci N] [--ul-earfcn N] [--num-transmissions N]
#                   [--ul-bw n6|..|n100] [--srs-index N] [--srs-cs N]
#                   [--srs-antenna an1|an2|an4] [--cells N]
#   --prs-plan      [--pci N] [--prs-index N] [--num-dl-frames sf-N]
#                   [--prs-bw nNN] [--dl-bw nNN] [--occasions N] [--sfn-start N]
#   each of the first, second and fourth also takes --oracle-check.
#
# Each verb's plain encode needs only python3. --oracle-check needs the pycrate
# oracle (pycrate_asn1dir.LPP) in /home/ysl/.lte-oracles/venv, overridable with
# IMSI_LPP_ORACLE_PY; when it cannot be reached the verb refuses with rc 2 and a
# WHY instead of printing a PDU it could not compare. The encoding column always
# says which engine produced the octets.
#
# What is refused rather than invented:
#   - UTDOA octets. TS 37.355 has no uTDOA IE. Uplink UTDOA is LPPa (TS 36.455:
#     utdoaInformationRequest carrying RequestedSRSTransmissionCharacteristics
#     and SRSConfigurationForOneCell) plus RRC SRS config (TS 36.331 6.3.2), and
#     LPPa is a different protocol owned elsewhere. --utdoa-config prints those
#     fields, with the LPPa type names, and no octets.
#   - PRS samples. --prs-plan is a planner: it names the exact
#     tools/phy_seqs.py --seq prs command and does not run it.
#   - Hand-rolled PER. Nothing here assembles bits by hand; a PDU comes out of
#     the codec or nothing comes out.
#
# The S1AP elementary-procedure header helpers (--build-header, --decode-header,
# --list-pids) describe the header that sits INSIDE an S1AP PDU, in front of an
# LPPa payload: a real S1AP frame also carries an initiatingMessage /
# successfulOutcome / unsuccessfulOutcome tag and a PDU length before it.
#
# Resolve IMSISTING_ROOT from this script's own path.
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

MOD_TMP="$TMP_DIR/lpp"
LPP_DIR="$LOOT_DIR/lpp"
mkdir -p "$MOD_TMP" "$LPP_DIR" 2>/dev/null

# Palette
C_RED=$'\e[38;5;196m'; C_GRN=$'\e[38;5;46m';   C_YEL=$'\e[38;5;226m'
C_CYN=$'\e[38;5;51m';  C_MAG=$'\e[38;5;201m';  C_BLU=$'\e[38;5;39m'
C_ORG=$'\e[38;5;208m'; C_PUR=$'\e[38;5;135m';  C_DIM=$'\e[38;5;240m'
C_WHT=$'\e[38;5;255m'; C_BOLD=$'\e[1m';        C_RESET=$'\e[0m'
export C_RED C_GRN C_YEL C_CYN C_MAG C_BLU C_ORG C_PUR C_DIM C_WHT C_BOLD C_RESET

declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
declare -F ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
declare -F warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
declare -F err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }

# ── status ──────────────────────────────────────────────────────────────
lpp_status_tsv() {
    local tool_missing=()
    for t in python3; do
        command -v "$t" >/dev/null 2>&1 || tool_missing+=("$t")
    done
    local status=ok
    ((${#tool_missing[@]} > 0)) && status=missing
    printf 'STATUS\t%s\n' "$status"
    ((${#tool_missing[@]} > 0)) && printf 'MISSING\t%s\n' "$(IFS=,; echo "${tool_missing[*]}")"
}

# ── LPP protocol ID mapping (TS 36.413 §9.2) ───────────────────────────
declare -A LPP_PIDS=(
    [1]="locationInformation"
    [2]="positioningData"
    [3]="positioningInitialization"
    [4]="locationAlert"
    [5]="positioningUpdate"
    [6]="locationMeasurements"
)

get_lpp_pid_name() {
    local pid="$1"
    echo "${LPP_PIDS[$pid]:-unknown}"
}

# ── LPP message header decoding (TS 36.413 §9.3) ────────────────────────
lpp_decode_header() {
    local hex="$1"
    [[ -z "$hex" || ${#hex} -lt 8 ]] && { warn "LPP header too short"; return 1; }
    
    local procedure_code=$((16#${hex:0:2}))
    local criticality="${hex:2:2}"
    local length=$((16#${hex:4:4}))
    
    local proc_name=$(get_lpp_pid_name $procedure_code)
    
    cat << EOF
LPP Header
==========
Procedure Code: $procedure_code (0x$procedure_code) ($proc_name)
Criticality:    0x$criticality
Length:         $length bytes
EOF
}

lpp_build_header() {
    local procedure_code="${1:-1}"
    local criticality="${2:-reject}"
    local length="${3:-000c}"
    
    local crit_hex="00"
    case "$criticality" in
        reject) crit_hex="00" ;;
        ignore) crit_hex="01" ;;
        notify) crit_hex="02" ;;
    esac
    
    printf '%02x%s%s' "$procedure_code" "$crit_hex" "$length"
}

# ── the generated PER codec (tools/lte_asn1.py) ────────────────────────
# One implementation of TS 37.355 for the whole toolkit. The table is
# generated from pycrate and checked against it, so the module never
# hand-assembles a coordinate: the previous version of this file read latitude
# and longitude out of fixed byte offsets (hex:24:8 and hex:32:8) of an
# arbitrary buffer, which produced a position for any input at all and could
# never have matched a real message.
lpp_asn1() {
    python3 "$IMSISTING_ROOT/tools/lte_asn1.py" "$@"
}

# ── the positioning-procedure half (OTDOA / PRS / UTDOA) ───────────────
# OTDOA is one ASN.1 family and one codec, but tools/lte_asn1.py exposes only the
# position family (lpp-encode --lat/--lon) and cannot express a
# ProvideAssistanceData message: its --json path hands lists to a PER engine that
# needs CHOICE tuples. The procedure verbs therefore carry their own small driver
# over the SAME generated table (tools/lpp_layout.py + tools/lte_per.py), written
# out on demand so there is one copy in the tree and no second codec.
lpp_proc_py() {
    local py="$MOD_TMP/lpp_proc.py" tmp="$MOD_TMP/.lpp_proc.$$.py"
    mkdir -p "$MOD_TMP" 2>/dev/null
    cat > "$tmp" <<'LPP_PROC_PY'
#!/usr/bin/env python3
"""LPP positioning-procedure half for 46_lpp.sh: OTDOA / UTDOA / PRS.

OTDOA is encoded here for real, with the tree's generated PER codec
(tools/lte_per.py + tools/lpp_layout.py, whose table is pycrate's
LPP-PDU-Definitions). UTDOA is described, not encoded: LPP has no UTDOA types,
they live in LPPa (TS 36.455) -- see --utdoa-config.

Output is the module output contract, one TSV record per line.
"""
import os
import subprocess
import sys

ROOT = os.environ.get('IMSISTING_ROOT', '')
TOOLS = os.path.join(ROOT, 'tools')
if TOOLS not in sys.path:
    sys.path.insert(0, TOOLS)

HEADER = 'message\tfields\tbytes\thex\tbits_consumed\tencoding\tsent\tref\tlimit'

REF_ASSIST = ('TS 37.355 Annex A LPP-PDU-Definitions (OTDOA-ProvideAssistanceData, '
              'OTDOA-ReferenceCellInfo, OTDOA-NeighbourCellInfoList, PRS-Info); '
              'TS 37.355 6.5.1 OTDOA Positioning')
REF_MEAS = ('TS 37.355 Annex A LPP-PDU-Definitions (OTDOA-SignalMeasurementInformation, '
            'OTDOA-MeasQuality, NeighbourMeasurementElement); TS 37.355 6.5.1 OTDOA Positioning')
REF_CAPS = ('TS 37.355 Annex A LPP-PDU-Definitions (RequestCapabilities, '
            'OTDOA-RequestCapabilities); TS 37.355 6.5.1 OTDOA Positioning')
REF_SRS = ('TS 37.455 / TS 36.455 LPPa utdoaInformationRequest '
           '(RequestedSRSTransmissionCharacteristics, SRSConfigurationForOneCell); '
           'TS 36.331 6.3.2 SoundingRS-UL-ConfigDedicated')
REF_PRS = ('TS 36.211 6.10.4 (PRS periodicity/offset table); TS 37.355 Annex A PRS-Info '
           '(prs-Bandwidth, numDL-Frames); TS 37.355 prs-ConfigurationIndex')
ORACLE_PY_DEFAULT = '/home/ysl/.lte-oracles/venv/bin/python'

PRS_BW_RB = {'n6': 6, 'n15': 15, 'n25': 25, 'n50': 50, 'n75': 75, 'n100': 100}
NUM_DL_FRAMES = {'sf-1': 1, 'sf-2': 2, 'sf-4': 4, 'sf-6': 6}
MUTING_SIZES = {'po2': 2, 'po4': 4, 'po8': 8, 'po16': 16}


def bad(msg, why=None):
    sys.stderr.write('ERROR\t%s\n' % msg)
    if why:
        sys.stderr.write('WHY\t%s\n' % why)
    raise SystemExit(2)


def fail(msg, why=None, rc=3):
    sys.stderr.write('ERROR\t%s\n' % msg)
    if why:
        sys.stderr.write('WHY\t%s\n' % why)
    raise SystemExit(rc)


class Args:
    """--name value / --name=value / --flag. Unknown options are an error."""

    FLAGS = ('oracle-check', 'no-muting')

    def __init__(self, argv):
        self.d = {}
        self.pos = []
        i = 0
        while i < len(argv):
            a = argv[i]
            if a.startswith('--'):
                name = a[2:]
                if '=' in name:
                    name, val = name.split('=', 1)
                    self.d[name] = val
                    i += 1
                elif name in self.FLAGS:
                    self.d[name] = 'yes'
                    i += 1
                else:
                    if i + 1 >= len(argv):
                        bad('option --%s needs a value' % name)
                    self.d[name] = argv[i + 1]
                    i += 2
            else:
                self.pos.append(a)
                i += 1

    def check(self, allowed):
        unknown = set(self.d) - set(allowed) - set(self.FLAGS)
        if unknown:
            bad('unknown option(s): %s' % ' '.join('--' + u for u in sorted(unknown)))
        if self.pos:
            bad('unexpected argument(s): %s' % ' '.join(self.pos))

    def int(self, name, default, lo, hi):
        v = self.d.get(name)
        if v is None:
            return default
        try:
            n = int(v, 10)
        except ValueError:
            bad('--%s expects an integer, got %r' % (name, v))
        if not lo <= n <= hi:
            bad('--%s must be in %d..%d, got %d' % (name, lo, hi, n))
        return n

    def enum(self, name, default, choices):
        v = self.d.get(name, default)
        if v not in choices:
            bad('--%s must be one of %s, got %r' % (name, '|'.join(choices), v))
        return v

    def flag(self, name):
        return self.d.get(name) == 'yes'

    def text(self, name, default):
        return self.d.get(name, default)


# ── value builders (OTDOA) ───────────────────────────────────────────────
def parse_ecgi(spec):
    if spec in (None, '', 'none'):
        return None
    parts = spec.split(':')
    if len(parts) != 3:
        bad('--ecgi expects MCC:MNC:CELLIDENTITY, got %r' % spec)
    mcc, mnc, cell = parts
    if not (mcc.isdigit() and len(mcc) == 3):
        bad('--ecgi MCC must be three digits (37.355 carries one digit per field)')
    if not (mnc.isdigit() and len(mnc) in (2, 3)):
        bad('--ecgi MNC must be two or three digits')
    if not cell.isdigit():
        bad('--ecgi cellidentity must be decimal')
    ci = int(cell)
    if not 0 <= ci <= (1 << 28) - 1:
        bad('--ecgi cellidentity must be 0..268435455 (28 bits)')
    return {'mcc': [int(c) for c in mcc], 'mnc': [int(c) for c in mnc],
            'cellidentity': (ci, 28)}


def parse_muting(spec):
    if spec in (None, '', 'none'):
        return None
    if ':' not in spec:
        bad('--muting expects poN:BITS (e.g. po4:1010) or none')
    po, bits = spec.split(':', 1)
    if po not in MUTING_SIZES:
        bad('--muting po must be one of %s, got %r' % ('|'.join(MUTING_SIZES), po))
    n = MUTING_SIZES[po]
    if len(bits) != n or set(bits) - {'0', '1'}:
        bad('--muting %s needs exactly %d binary digits, got %r' % (po, n, bits))
    return po, (int(bits, 2), n)


def muting_desc(muting):
    if not muting:
        return 'absent'
    po, (val, n) = muting
    return '%s-r9=%s' % (po, format(val, '0%db' % n))


def prs_info(bw, idx, nf, muting):
    v = {'prs-Bandwidth': bw, 'prs-ConfigurationIndex': idx, 'numDL-Frames': nf}
    if muting:
        po, val = muting
        v['prs-MutingInfo-r9'] = (po + '-r9', val)
    return v


def parse_nbr_assist(spec):
    """PCI:RSTD:UNC[:CPLENGTH[:PRS-BW:PRS-INDEX:numDL-Frames]].

    The last three give that neighbour a PRS configuration of its own, which is
    what the IE is for: neighbouring cells do not have to share the reference
    cell's bandwidth, index or frame count.
    """
    parts = spec.split(':')
    if len(parts) not in (3, 4, 6, 7):
        bad('--nbr expects PCI:RSTD:UNC[:CPLENGTH][:PRS-BW:PRS-INDEX:numDL-FRAMES], '
            'got %r' % spec)
    try:
        pci, rstd, unc = (int(x) for x in parts[:3])
    except ValueError:
        bad('--nbr fields must be integers, got %r' % spec)
    cp = 'normal'
    if len(parts) in (4, 7):
        cp = parts[3]
        if cp not in ('normal', 'extended'):
            bad('--nbr cpLength must be normal|extended, got %r' % cp)
    n = {'physCellId': pci, 'cpLength': cp, 'expectedRSTD': rstd,
         'expectedRSTD-Uncertainty': unc}
    if len(parts) in (6, 7):
        nbw = parts[-3]
        if nbw not in PRS_BW_RB:
            bad('--nbr prs-Bandwidth must be one of %s, got %r'
                % ('|'.join(PRS_BW_RB), nbw))
        nnf = parts[-1]
        if nnf not in NUM_DL_FRAMES:
            bad('--nbr numDL-Frames must be one of %s, got %r'
                % ('|'.join(NUM_DL_FRAMES), nnf))
        try:
            nidx = int(parts[-2])
        except ValueError:
            bad('--nbr prs-ConfigurationIndex must be an integer, got %r' % parts[-2])
        if not 0 <= nidx <= 4095:
            bad('--nbr prs-ConfigurationIndex must be 0..4095, got %d' % nidx)
        n['prs'] = (nbw, nidx, nnf)
    if not 0 <= pci <= 503:
        bad('--nbr physCellId must be 0..503, got %d' % pci)
    if not 0 <= rstd <= 16383:
        bad('--nbr expectedRSTD must be 0..16383, got %d' % rstd)
    if not 0 <= unc <= 1023:
        bad('--nbr expectedRSTD-Uncertainty must be 0..1023, got %d' % unc)
    return n


def nbr_assist_value(n, bw, idx, nf):
    v = {'physCellId': n['physCellId'], 'cpLength': n['cpLength'],
         'expectedRSTD': n['expectedRSTD'],
         'expectedRSTD-Uncertainty': n['expectedRSTD-Uncertainty']}
    nbw, nidx, nnf = n['prs'] if 'prs' in n else (bw, idx, nf)
    # a neighbour carries its own PRS configuration; muting stays a property of
    # the reference cell in this message
    v['prsInfo'] = prs_info(nbw, nidx, nnf, None)
    return v


# ── LPP encode through the tree codec ───────────────────────────────────
def codec():
    try:
        import lpp_layout
        import lte_per
    except ImportError as exc:
        fail('cannot import the LPP layout/codec (%s)' % exc,
             'run from the repository root or set IMSISTING_ROOT; '
             'needs tools/lpp_layout.py and tools/lte_per.py')
    return lte_per.codec_from_module(lpp_layout)


def encode(c, msg):
    """Encode, verify the octets decode back, return (hex, bits)."""
    try:
        bits = c.encode_bitlen('LPP_Message', msg)
        h = c.encode_hex('LPP_Message', msg)
    except Exception as exc:
        fail('tree PER encoder rejected the value: %s' % exc,
             'a layout/value mismatch is a bug in this verb, not an input error')
    try:
        c.decode_hex('LPP_Message', h, exact=False)
    except Exception as exc:
        fail('tree PER decoder rejected the octets this verb just built: %s' % exc)
    return h, bits


# ── pycrate oracle ──────────────────────────────────────────────────────
def oracle_python():
    exe = os.environ.get('IMSI_LPP_ORACLE_PY') or ORACLE_PY_DEFAULT
    if not (os.path.isfile(exe) and os.access(exe, os.X_OK)):
        bad('LPP oracle unavailable: %s is not an executable interpreter' % exe,
            'the oracle check needs pycrate (pycrate_asn1dir.LPP); install it in '
            '/home/ysl/.lte-oracles/venv or point IMSI_LPP_ORACLE_PY at the venv python')
    return exe


ORACLE_ENCODE = r'''
import sys
from pycrate_asn1dir import LPP
D = LPP.LPP_PDU_Definitions
a = dict(x.split('=', 1) for x in sys.argv[1:])
def i(k): return int(a[k])
def ecgi():
    if a['ecgi'] == 'none': return None
    mcc, mnc, ci = a['ecgi'].split(':')
    return {'mcc': [int(c) for c in mcc], 'mnc': [int(c) for c in mnc],
            'cellidentity': (int(ci), 28)}
def muting():
    if a['muting'] == 'none': return None
    po, bits = a['muting'].split(':')
    return (po + '-r9', (int(bits, 2), len(bits)))
def prsinfo():
    v = {'prs-Bandwidth': a['bw'], 'prs-ConfigurationIndex': i('idx'),
         'numDL-Frames': a['nf']}
    m = muting()
    if m is not None:
        v['prs-MutingInfo-r9'] = m
    return v
tid = {'initiator': a['init'], 'transactionNumber': i('tn')}
if a['verb'] == 'otdoa-assist':
    ref = {'physCellId': i('pci'),
           'earfcnRef': i('earfcn'), 'cpLength': a['cp'], 'prsInfo': prsinfo()}
    if ecgi() is not None:
        ref['cellGlobalId'] = ecgi()
    nbrs = []
    for spec in a['nbrs'].split(','):
        if not spec: continue
        pci, rstd, unc, cp, bw, idx, nf = spec.split(':')
        # a neighbour carries its own PRS config but no muting in this message
        nbrs.append({'physCellId': int(pci), 'cpLength': cp,
                     'prsInfo': {'prs-Bandwidth': bw,
                                 'prs-ConfigurationIndex': int(idx),
                                 'numDL-Frames': nf},
                     'expectedRSTD': int(rstd),
                     'expectedRSTD-Uncertainty': int(unc)})
    otdoa = {'otdoa-ReferenceCellInfo': ref}
    if nbrs:
        otdoa['otdoa-NeighbourCellInfo'] = [nbrs]
    body = ('c1', ('provideAssistanceData', {'criticalExtensions':
            ('c1', ('provideAssistanceData-r9',
                    {'otdoa-ProvideAssistanceData': otdoa}))}))
elif a['verb'] == 'otdoa-request' and a['form'] == 'capabilities':
    body = ('c1', ('requestCapabilities', {'criticalExtensions':
            ('c1', ('requestCapabilities-r9', {'otdoa-RequestCapabilities': {}}))}))
elif a['verb'] == 'otdoa-request':
    nb = []
    for spec in a['nbrs'].split(','):
        if not spec: continue
        pci, rstd, res, val, sam = spec.split(':')
        q = {'error-Resolution': (int(res), 2), 'error-Value': (int(val), 5)}
        if sam != '-':
            q['error-NumSamples'] = (int(sam), 3)
        nb.append({'physCellIdNeighbour': int(pci), 'rstd': int(rstd),
                   'rstd-Quality': q})
    q = {'error-Resolution': (i('refres'), 2), 'error-Value': (i('refval'), 5)}
    if i('refsam') >= 0:
        q['error-NumSamples'] = (i('refsam'), 3)
    meas = {'systemFrameNumber': (i('sfn'), 10), 'physCellIdRef': i('pci'),
            'earfcnRef': i('earfcn'), 'referenceQuality': q,
            'neighbourMeasurementList': nb}
    body = ('c1', ('provideLocationInformation', {'criticalExtensions':
            ('c1', ('provideLocationInformation-r9',
                    {'otdoa-ProvideLocationInformation':
                     {'otdoaSignalMeasurementInformation': meas}}))}))
else:
    raise SystemExit('bad verb/form')
val = {'transactionID': tid, 'endTransaction': False, 'lpp-MessageBody': body}
D.LPP_Message.set_val(val)
bu = D.LPP_Message.to_uper()   # unaligned PER; LPP is not aligned (TS 37.355)
print('%d %s' % (len(bu) * 8, bu.hex().upper()))
'''


def oracle_check(c, msg, kv, want_hex, want_bits):
    exe = oracle_python()
    p = subprocess.run([exe, '-c', ORACLE_ENCODE] + ['%s=%s' % (k, v) for k, v in kv],
                       capture_output=True, text=True)
    if p.returncode != 0:
        bad('pycrate oracle failed (rc %d)' % p.returncode,
            (p.stderr.strip().splitlines() or ['no stderr'])[-1])
    lines = [ln for ln in p.stdout.strip().splitlines() if ln.strip()]
    if not lines:
        bad('the LPP oracle at %s printed nothing' % exe,
            'an interpreter that runs but emits no "<bits> <hex>" line never '
            'reached pycrate; point IMSI_LPP_ORACLE_PY at the oracle venv python '
            '(it imports pycrate_asn1dir.LPP)')
    try:
        obits, ohex = lines[-1].split()
        obits = int(obits)
    except ValueError:
        bad('pycrate oracle printed an unexpected line: %r' % lines[-1][:200])
    if ohex.upper() != want_hex.upper():
        fail('oracle mismatch: pycrate %s, tree %s (%d bits)'
             % (ohex, want_hex, want_bits),
             'the tree layout and pycrate disagree; do not trust either until '
             'tools/lpp-oracle/check_lpp_position.py says which is wrong')


# ── TSV helpers ─────────────────────────────────────────────────────────
def row(message, fields, ref, limit='-', bytes_='-', hex_='-', bits='-',
        encoding='-', sent=0):
    return '\t'.join(str(x) for x in (message, fields, bytes_, hex_, bits, encoding,
                                      sent, ref, limit))


def emit(rows):
    sys.stdout.write(HEADER + '\n')
    for r in rows:
        sys.stdout.write(r + '\n')
    sys.stdout.flush()


# ── verbs ───────────────────────────────────────────────────────────────
def otdoa_assist(argv):
    a = Args(argv)
    a.check(('pci', 'earfcn', 'ecgi', 'cp', 'prs-bw', 'prs-index', 'num-dl-frames',
             'muting', 'nbr', 'initiator', 'transaction'))
    pci = a.int('pci', 1, 0, 503)
    earfcn = a.int('earfcn', 6300, 0, 65535)
    ecgi_spec = a.text('ecgi', '001:01:1')
    ecgi = parse_ecgi(ecgi_spec)
    cp = a.enum('cp', 'normal', ('normal', 'extended'))
    bw = a.enum('prs-bw', 'n50', tuple(PRS_BW_RB))
    idx = a.int('prs-index', 0, 0, 4095)
    nf = a.enum('num-dl-frames', 'sf-1', tuple(NUM_DL_FRAMES))
    muting = parse_muting(a.text('muting', 'po4:1010'))
    if a.flag('no-muting'):
        muting = None
    nbr_specs = a.text('nbr', '2:0:5,3:3:5,4:8:10').split(',')
    nbrs = [nbr_assist_value(parse_nbr_assist(s), bw, idx, nf) for s in nbr_specs if s]
    if len(nbrs) > 24:
        bad('at most 24 neighbours per frequency layer (OTDOA-NeighbourCellInfoList)')
    pcis = [n['physCellId'] for n in nbrs]
    if pci in pcis:
        bad('neighbour PCI %d equals the reference PCI; expectedRSTD is measured '
            'against the reference cell' % pci)
    if len(set(pcis)) != len(pcis):
        bad('duplicate neighbour PCI in %r' % ','.join(nbr_specs))

    tid = {'initiator': a.enum('initiator', 'locationServer',
                              ('targetDevice', 'locationServer')),
           'transactionNumber': a.int('transaction', 1, 0, 255)}
    ref = {'physCellId': pci, 'earfcnRef': earfcn, 'cpLength': cp,
           'prsInfo': prs_info(bw, idx, nf, muting)}
    if ecgi is not None:
        ref['cellGlobalId'] = ecgi
    otdoa = {'otdoa-ReferenceCellInfo': ref}
    if nbrs:
        otdoa['otdoa-NeighbourCellInfo'] = [nbrs]
    msg = {'transactionID': tid, 'endTransaction': False,
           'lpp-MessageBody': ('c1', ('provideAssistanceData', {
               'criticalExtensions': ('c1', ('provideAssistanceData-r9',
                                            {'otdoa-ProvideAssistanceData': otdoa}))}))}
    c = codec()
    hexv, bits = encode(c, msg)

    if ecgi is None:
        ecgi_txt = 'cellGlobalId=absent'
    else:
        ecgi_txt = ('cellGlobalId{mcc=%s; mnc=%s; cellidentity=%d}'
                    % (ecgi_spec.split(':')[0], ecgi_spec.split(':')[1],
                       int(ecgi_spec.split(':')[2])))
    ref_fields = ('otdoa-ReferenceCellInfo{physCellId=%d; %s; earfcnRef=%d; cpLength=%s; '
                  'prsInfo{prs-Bandwidth=%s; prs-ConfigurationIndex=%d; numDL-Frames=%s; '
                  'prs-MutingInfo-r9=%s}}'
                  % (pci, ecgi_txt, earfcn, cp, bw, idx, nf, muting_desc(muting)))
    rows = [row('otdoa-assist', 'otdoa-ProvideAssistanceData carries: ' + ref_fields,
                REF_ASSIST, bytes_=(bits + 7) // 8, hex_=hexv, bits=bits,
                encoding='lpp_layout+lte_per (unaligned PER, LPP_Message)')]
    for n in nbrs:
        rows.append(row('otdoa-assist-nbr',
                        'otdoa-NeighbourCellInfo[]: physCellId=%d; cpLength=%s; '
                        'prsInfo{prs-Bandwidth=%s; prs-ConfigurationIndex=%d; '
                        'numDL-Frames=%s}; expectedRSTD=%d; expectedRSTD-Uncertainty=%d'
                        % (n['physCellId'], n['cpLength'],
                           n['prsInfo']['prs-Bandwidth'],
                           n['prsInfo']['prs-ConfigurationIndex'],
                           n['prsInfo']['numDL-Frames'],
                           n['expectedRSTD'], n['expectedRSTD-Uncertainty']),
                        REF_ASSIST,
                        limit='carried in freq layer earfcnRef=%d (no own earfcn; '
                              'per-layer EARFCN would need a second freq group)' % earfcn))
    rows.append(row('otdoa-assist-tx', 'transactionID{%s,%d}; endTransaction=false; '
                    'abort=false; criticalExtensions=c1'
                    % (tid['initiator'], tid['transactionNumber']), REF_ASSIST,
                    limit='assistance data is server-to-device; this verb builds it '
                          'and stops (no delivery, no gate)'))
    if idx >= 2400:
        rows.append(row('limit', 'prs-ConfigurationIndex=%d is in the 2400..4095 block '
                        'TS 36.211 6.10.4 leaves reserved (no PRS occasion)'
                        % idx, REF_PRS,
                        limit='encoded as given: ASN.1 allows 0..4095; the E-SMLC would '
                              'not schedule PRS with a reserved index'))
    if a.flag('oracle-check'):
        kv = [('verb', 'otdoa-assist'), ('pci', pci), ('earfcn', earfcn),
              ('ecgi', ecgi_spec), ('cp', cp), ('bw', bw), ('idx', idx), ('nf', nf),
              ('muting', 'none' if not muting else '%s:%s' % (
                  muting[0], format(muting[1][0], '0%db' % muting[1][1])),
           ), ('nbrs', ','.join('%d:%d:%d:%s:%s:%d:%s' % (
               n['physCellId'], n['expectedRSTD'], n['expectedRSTD-Uncertainty'],
               n['cpLength'], n['prsInfo']['prs-Bandwidth'],
               n['prsInfo']['prs-ConfigurationIndex'],
               n['prsInfo']['numDL-Frames']) for n in nbrs)),
              ('init', tid['initiator']), ('tn', tid['transactionNumber'])]
        oracle_check(c, msg, kv, hexv, bits)
        rows.append(row('oracle', 'pycrate LPP-PDU-Definitions encodes the same value '
                        'to the same octets', REF_ASSIST,
                        bytes_=(bits + 7) // 8, hex_=hexv, bits=bits,
                        encoding='pycrate_asn1dir.LPP (oracle)',
                        limit='needs %s; compare only, never used for the PDU'
                              % oracle_python()))
    emit(rows)
    return 0


def otdoa_request(argv):
    a = Args(argv)
    a.check(('form', 'sfn', 'pci', 'earfcn', 'ref-res', 'ref-val', 'ref-samples',
             'nbr', 'initiator', 'transaction'))
    form = a.enum('form', 'measure', ('measure', 'capabilities'))
    if form == 'capabilities':
        if set(a.d) & {'sfn', 'nbr', 'ref-res', 'ref-val', 'pci', 'earfcn'}:
            bad('--form capabilities takes no measurement options (it is an empty '
                'SEQUENCE); drop --sfn/--nbr/--ref-*')
        tid = {'initiator': a.enum('initiator', 'targetDevice',
                                  ('targetDevice', 'locationServer')),
               'transactionNumber': a.int('transaction', 1, 0, 255)}
        msg = {'transactionID': tid, 'endTransaction': False,
               'lpp-MessageBody': ('c1', ('requestCapabilities', {
                   'criticalExtensions': ('c1', ('requestCapabilities-r9', {
                       'otdoa-RequestCapabilities': {}}))}))}
        c = codec()
        hexv, bits = encode(c, msg)
        rows = [row('otdoa-request', 'OTDOA-RequestCapabilities{} -- an empty '
                    'extensible SEQUENCE: asking for OTDOA capabilities carries no '
                    'fields, only the LPP transaction',
                    REF_CAPS, bytes_=(bits + 7) // 8, hex_=hexv, bits=bits,
                    encoding='lpp_layout+lte_per (unaligned PER, LPP_Message)')]
        rows.append(row('otdoa-request-tx', 'transactionID{%s,%d}; '
                        'lpp-MessageBody.c1=requestCapabilities'
                        % (tid['initiator'], tid['transactionNumber']), REF_CAPS,
                        limit='the device asks; the E-SMLC answers with '
                              '--otdoa-assist-shaped data'))
        if a.flag('oracle-check'):
            kv = [('verb', 'otdoa-request'), ('form', 'capabilities'),
                  ('init', tid['initiator']), ('tn', tid['transactionNumber'])]
            oracle_check(c, msg, kv, hexv, bits)
            rows.append(row('oracle', 'pycrate agrees', REF_CAPS,
                            bytes_=(bits + 7) // 8, hex_=hexv, bits=bits,
                            encoding='pycrate_asn1dir.LPP (oracle)',
                            limit='needs %s' % oracle_python()))
        emit(rows)
        return 0

    sfn = a.int('sfn', 512, 0, 1023)
    pci = a.int('pci', 1, 0, 503)
    earfcn = a.int('earfcn', 6300, 0, 65535)
    refres = a.int('ref-res', 1, 0, 3)
    refval = a.int('ref-val', 5, 0, 31)
    refsam = None
    if 'ref-samples' in a.d:
        refsam = a.int('ref-samples', 3, 0, 7)
    nbr_specs = [s for s in a.text('nbr', '2:1234:1:9,3:2345:2:20:-').split(',') if s]
    nb = []
    seen = set()
    for spec in nbr_specs:
        parts = spec.split(':')
        if not 4 <= len(parts) <= 5:
            bad('--nbr expects PCI:RSTD:QUAL_RES:QUAL_VAL[:NUM_SAMPLES], got %r' % spec)
        try:
            npci, rstd, res, val = (int(x) for x in parts[:4])
        except ValueError:
            bad('--nbr fields must be integers, got %r' % spec)
        if not 0 <= npci <= 503:
            bad('--nbr PCI must be 0..503, got %d' % npci)
        if npci in seen:
            bad('duplicate neighbour PCI %d' % npci)
        seen.add(npci)
        if not 0 <= rstd <= 12711:
            bad('--nbr rstd must be 0..12711 (TS 37.355 RSTD range), got %d' % rstd)
        if not 0 <= res <= 3 or not 0 <= val <= 31:
            bad('--nbr quality needs RES 0..3 (2 bits) and VAL 0..31 (5 bits)')
        q = {'error-Resolution': (res, 2), 'error-Value': (val, 5)}
        if len(parts) == 5 and parts[4] != '-':
            sam = int(parts[4])
            if not 0 <= sam <= 7:
                bad('--nbr error-NumSamples is 3 bits (0..7)')
            q['error-NumSamples'] = (sam, 3)
        nb.append({'physCellIdNeighbour': npci, 'rstd': rstd, 'rstd-Quality': q})
    if len(nb) > 24:
        bad('at most 24 neighbour measurements (OTDOA-SignalMeasurementInformation)')
    if not nb:
        bad('at least one neighbour measurement is needed')

    tid = {'initiator': a.enum('initiator', 'targetDevice',
                              ('targetDevice', 'locationServer')),
           'transactionNumber': a.int('transaction', 1, 0, 255)}
    refq = {'error-Resolution': (refres, 2), 'error-Value': (refval, 5)}
    if refsam is not None:
        refq['error-NumSamples'] = (refsam, 3)
    meas = {'systemFrameNumber': (sfn, 10), 'physCellIdRef': pci,
            'earfcnRef': earfcn, 'referenceQuality': refq,
            'neighbourMeasurementList': nb}
    msg = {'transactionID': tid, 'endTransaction': False,
           'lpp-MessageBody': ('c1', ('provideLocationInformation', {
               'criticalExtensions': ('c1', ('provideLocationInformation-r9', {
                   'otdoa-ProvideLocationInformation': {
                       'otdoaSignalMeasurementInformation': meas}}))}))}
    c = codec()
    hexv, bits = encode(c, msg)
    rows = [row('otdoa-request', 'OTDOA-SignalMeasurementInformation{systemFrameNumber=%d; '
                'physCellIdRef=%d; earfcnRef=%d; referenceQuality{error-Resolution=%d; '
                'error-Value=%d%s}; neighbourMeasurementList=%d element(s)}'
                % (sfn, pci, earfcn, refres, refval,
                   '' if refsam is None else '; error-NumSamples=%d' % refsam, len(nb)),
                REF_MEAS, bytes_=(bits + 7) // 8, hex_=hexv, bits=bits,
                encoding='lpp_layout+lte_per (unaligned PER, LPP_Message)')]
    for n in nb:
        q = n['rstd-Quality']
        rows.append(row('otdoa-request-nbr',
                        'NeighbourMeasurementElement{physCellIdNeighbour=%d; rstd=%d; '
                        'rstd-Quality{error-Resolution=%d; error-Value=%d%s}}'
                        % (n['physCellIdNeighbour'], n['rstd'],
                           q['error-Resolution'][0], q['error-Value'][0],
                           '' if 'error-NumSamples' not in q
                           else '; error-NumSamples=%d' % q['error-NumSamples'][0]),
                        REF_MEAS))
    rows.append(row('otdoa-request-tx', 'transactionID{%s,%d}; endTransaction=false; '
                    'lpp-MessageBody.c1=provideLocationInformation'
                    % (tid['initiator'], tid['transactionNumber']), REF_MEAS,
                    limit='measurements only, no position estimate: '
                          '--forge-position is the estimate path; a spoofed response '
                          'must look like this (plausible RSTD, quality, SFN) or like '
                          'an OTDOA error (locationServerErrorCauses)'))
    if a.flag('oracle-check'):
        kv = [('verb', 'otdoa-request'), ('form', 'measure'), ('sfn', sfn),
              ('pci', pci), ('earfcn', earfcn), ('refres', refres),
              ('refval', refval), ('refsam', -1 if refsam is None else refsam),
              ('init', tid['initiator']),
              ('tn', tid['transactionNumber']),
              ('nbrs', ','.join('%d:%d:%d:%d:%s' % (
                  n['physCellIdNeighbour'], n['rstd'],
                  n['rstd-Quality']['error-Resolution'][0],
                  n['rstd-Quality']['error-Value'][0],
                  '-' if 'error-NumSamples' not in n['rstd-Quality']
                  else n['rstd-Quality']['error-NumSamples'][0]) for n in nb))]
        oracle_check(c, msg, kv, hexv, bits)
        rows.append(row('oracle', 'pycrate agrees', REF_MEAS,
                        bytes_=(bits + 7) // 8, hex_=hexv, bits=bits,
                        encoding='pycrate_asn1dir.LPP (oracle)',
                        limit='needs %s' % oracle_python()))
    emit(rows)
    return 0


def utdoa_config(argv):
    a = Args(argv)
    a.check(('pci', 'ul-earfcn', 'num-transmissions', 'ul-bw', 'srs-index',
             'srs-cs', 'srs-antenna', 'cells'))
    if a.flag('oracle-check'):
        bad('--utdoa-config has nothing to encode, so --oracle-check cannot check '
            'anything',
            'LPP has no UTDOA PDU and this verb does not build LPPa octets; the '
            'oracle would have no octets to compare')
    pci = a.int('pci', 1, 0, 503)
    earfcn = a.int('ul-earfcn', 18300, 0, 65535)
    ntx = a.int('num-transmissions', 500, 0, 500)
    ulbw = a.enum('ul-bw', 'n50', tuple(PRS_BW_RB))
    srsidx = a.int('srs-index', 7, 0, 1023)
    cs = a.int('srs-cs', 0, 0, 7)
    antenna = a.enum('srs-antenna', 'an1', ('an1', 'an2', 'an4'))
    cells = a.int('cells', 1, 1, 32)
    rows = []
    rows.append(row('utdoa-config', 'UTDOA-RequestLocationInformation is NOT an LPP '
                    'message: LPP (TS 37.355) has no UTDOA IEs at all; uplink UTDOA '
                    'runs over LPPa (TS 36.455) from eNB to E-SMLC',
                    REF_SRS,
                    limit='refused on purpose: no OTDOA-style encode exists for UTDOA '
                          'in LPP; see the utdoa-lppa rows for the real carrier'))
    rows.append(row('utdoa-lppa-request', 'utdoaInformationRequest carries '
                    'RequestedSRSTransmissionCharacteristics{numberOfTransmissions=%d; '
                    'bandwidth=%d (RB)}' % (ntx, PRS_BW_RB[ulbw]),
                    REF_SRS,
                    limit='field names and shapes transcribed from pycrate_asn1dir.LPPa '
                          '(LPPA-IEs); not emitted as octets here, because LPPa is a '
                          'different protocol and another module owns it'))
    for k in range(cells):
        rows.append(row('utdoa-lppa-srs', 'SRSConfigurationForOneCell{pci=%d; '
                        'ul-earfcn=%d; ul-bandwidth=%s; ul-cyclicPrefixLength=normal; '
                        'srs-BandwidthConfig=bw0; srs-Bandwidth=bw0; srs-AntennaPort=%s; '
                        'srs-HoppingBandwidth=hbw0; srs-cyclicShift=cs%d; '
                        'srs-ConfigIndex=%d; maxUpPts=true; transmissionComb=0; '
                        'freqDomainPosition=0; groupHoppingEnabled=false; deltaSS=0; '
                        'sfnInitialisationTime=0000000000}'
                        % (pci + k, earfcn, ulbw, antenna, cs, srsidx),
                        REF_SRS,
                        limit='one entry per cell the server wants SRS from; the UE '
                              'transmits SRS in those cells so several eNBs can time it'))
    rows.append(row('utdoa-timing', 'the E-SMLC derives the position from uplink '
                    'reception timing of those SRS; the fields above tell the UE '
                    'WHERE and WHEN to transmit', REF_SRS,
                    limit='what a forged uplink response would falsify is each cell\'s '
                          'SRS time-of-arrival; not modelled here'))
    rows.append(row('limit', 'no LPP ASN.1 types exist for OTDOA-adjacent UTDOA IEs '
                    'in this tree: `grep -c utdoa tools/lpp_layout.py` = 0, and '
                    'pycrate_asn1dir.LPP has none either; --oracle-check therefore '
                    'refuses here (rc 2): there are no octets to compare', REF_SRS,
                    limit='the UTDOA types are pycrate_asn1dir.LPPa '
                          '(LPPA-PDU-Contents: utdoaInformationRequest/-Response/'
                          '-Failure/-Update, LPPA-IEs: RequestedSRSTransmission'
                          'Characteristics, SRSConfigurationForOneCell), reachable via '
                          '/home/ysl/.lte-oracles/venv/bin/python'))
    emit(rows)
    return 0


def prs_plan(argv):
    a = Args(argv)
    a.check(('pci', 'prs-index', 'num-dl-frames', 'prs-bw', 'dl-bw', 'occasions',
             'sfn-start'))
    pci = a.int('pci', 1, 0, 503)
    idx = a.int('prs-index', 0, 0, 4095)
    nf = a.enum('num-dl-frames', 'sf-1', tuple(NUM_DL_FRAMES))
    bwn = a.enum('prs-bw', 'n50', tuple(PRS_BW_RB))
    dln = a.enum('dl-bw', 'n100', tuple(PRS_BW_RB))
    occ = a.int('occasions', 3, 1, 16)
    sfn0 = a.int('sfn-start', 0, 0, 1023)
    if idx >= 2400:
        bad('prs-ConfigurationIndex %d is reserved (TS 36.211 6.10.4 leaves '
            '2400..4095 without an occasion)' % idx,
            'the table cannot say when PRS would be transmitted for this index; '
            'pass 0..2399')
    if PRS_BW_RB[bwn] > PRS_BW_RB[dln]:
        bad('prs-Bandwidth %s is wider than the downlink bandwidth %s' % (bwn, dln),
            'PRS cannot occupy more resource blocks than the cell has')
    if idx <= 159:
        period, delta = 160, idx
    elif idx <= 479:
        period, delta = 320, idx - 160
    elif idx <= 1119:
        period, delta = 640, idx - 480
    else:
        period, delta = 1280, idx - 1120
    nprs = NUM_DL_FRAMES[nf]
    first = delta
    while first < sfn0 * 10:
        first += period
    rows = [row('prs-plan', 'prs-ConfigurationIndex=%d -> period=%d subframes '
                '(I_PRS=%d) and offset delta-PRS=%d; prs-Bandwidth=%s (%d RB); '
                'numDL-Frames=%s (N_PRS=%d consecutive subframes per occasion)'
                % (idx, period, period // 10, delta, bwn, PRS_BW_RB[bwn], nf, nprs),
                REF_PRS, encoding='table',
                limit='index implies period+offset only; numDL-Frames is the separate '
                      'LPP prsInfo IE (37.355), not encoded in prs-ConfigurationIndex')]
    for k in range(occ):
        s = first + k * period
        sfn = (s // 10) % 1024
        sf = s % 10
        subframes = ','.join('%d' % ((sf + j) % 10) for j in range(nprs))
        rows.append(row('prs-plan-occasion',
                        'occasion=%d; sfn=%d; subframe=%s; '
                        '(10*sfn+subframe-%d) mod %d == 0' % (k, sfn, subframes,
                                                               delta, period),
                        REF_PRS, encoding='table'))
    rows.append(row('prs-plan-nid',
                    'pci=%d; N_ID_PRS=%d; the PRS sequence is seeded from N_ID_PRS, '
                    'so the PCI fixes the samples as well as the cells'
                    % (pci, pci), REF_PRS, encoding='table',
                    limit='the c_init formula and the pseudo-random sequence live in '
                          'TS 36.211 6.10.4.1 and in tools/phy_seqs.py --seq prs; '
                          'this verb does not restate them'))
    out = os.path.join(os.environ.get('TMP_DIR', '/tmp/imsisting'), 'lpp',
                       'prs-pci%d-%s.cf32' % (pci, bwn))
    cmd = ('python3 tools/phy_seqs.py gen --seq prs --out %s --pci %d '
           '--n-rb-prs %d --n-rb-dl %d --format cf32'
           % (out, pci, PRS_BW_RB[bwn], PRS_BW_RB[dln]))
    rows.append(row('prs-plan-handoff',
                    'for samples run: ' + cmd, 'tools/phy_seqs.py --seq prs',
                    encoding='external-tool',
                    limit='not run by this verb: samples are phy_seqs.py\'s job '
                          '(planner only)'))
    emit(rows)
    return 0


VERBS = {
    'otdoa-assist': otdoa_assist,
    'otdoa-request': otdoa_request,
    'utdoa-config': utdoa_config,
    'prs-plan': prs_plan,
}


def main(argv):
    if not argv or argv[0] not in VERBS:
        bad('usage: lpp_proc.py <%s> [options]' % '|'.join(VERBS))
    try:
        return VERBS[argv[0]](argv[1:])
    except SystemExit:
        raise
    except BrokenPipeError:
        return 0
    except Exception as exc:  # never leak a traceback as "output"
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.stderr.write('ERROR\tinternal failure: %s\n' % exc)
        return 3


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

LPP_PROC_PY
    if [[ ! -s "$tmp" ]]; then
        rm -f "$tmp"
        return 1
    fi
    if cmp -s "$tmp" "$py" 2>/dev/null; then
        rm -f "$tmp"
    else
        mv -f "$tmp" "$py" || { rm -f "$tmp"; return 1; }
    fi
    printf '%s\n' "$py"
}

# Run one procedure verb. The driver speaks the module output contract itself
# (TSV header row, ERROR/WHY on stderr, rc 2 for bad input), so this wrapper
# only has to make sure it started.
lpp_proc_run() {
    local verb="$1"; shift
    command -v python3 >/dev/null 2>&1 || {
        err "python3 is required for $verb"
        return 2
    }
    local py
    py=$(lpp_proc_py) || {
        err "cannot write the procedure driver under $MOD_TMP"
        return 2
    }
    python3 "$py" "$verb" "$@"
}

lpp_otdoa_assist()  { lpp_proc_run otdoa-assist  "$@"; }
lpp_otdoa_request() { lpp_proc_run otdoa-request "$@"; }
lpp_utdoa_config()  { lpp_proc_run utdoa-config  "$@"; }
lpp_prs_plan()      { lpp_proc_run prs-plan      "$@"; }

# ── forge a position report ───────────────────────────────────────────
# <lat>,<lon> [radius-metres] -- builds a real LPP-Message carrying a
# ProvideLocationInformation. The radius selects TS 37.355's
# Ellipsoid-PointWithUncertaintyCircle (0..127 m); without it the report is a
# bare Ellipsoid-Point.
lpp_forge_position() {
    local spec="${1:-}"
    if [[ -z "$spec" ]]; then
        err "usage: --forge-position <lat>,<lon> [radius-metres]"
        err "  e.g. --forge-position 51.5007,-0.1246 30"
        return 2
    fi
    if [[ "$spec" != *,* ]]; then
        err "give the position as <lat>,<lon> (e.g. 51.5007,-0.1246)"
        return 2
    fi
    local lat="${spec%%,*}" lon="${spec#*,}" radius="${2:-}"
    local -a args=(lpp-encode --lat "$lat" --lon "$lon")
    [[ -n "$radius" ]] && args+=(--radius "$radius")

    local out rc=0
    out=$(lpp_asn1 "${args[@]}" 2>&1) || rc=$?
    if (( rc != 0 )); then
        printf '%s\n' "$out" >&2
        return "$rc"
    fi
    local f
    f() { printf '%s\n' "$out" | awk -F'\t' -v k="$1" '$1==k{print $2}'; }

    printf 'status\tbuilt\n'
    printf 'message\tprovideLocationInformation\n'
    printf 'pdu_bits\t%s\n' "$(f pdu_bits)"
    printf 'pdu_hex\t%s\n' "$(f pdu_hex)"
    printf 'latitude\t%s\n'   "$(f lat_deg)"
    printf 'longitude\t%s\n'  "$(f lon_deg)"
    printf 'latitude_sign\t%s\n' "$(f lat_sign)"
    printf 'grid_latitude\t%s\n'  "$(f deg_lat)"
    printf 'grid_longitude\t%s\n' "$(f deg_lon)"
    [[ -n "$radius" ]] && printf 'radius_m\t%s\n' "$radius"
    printf 'transport\t%s\n' "LPP over NAS (UE to E-SMLC) or LPPa over S1AP (eNB to E-SMLC, TS 36.455)"
    printf 'delivery\t%s\n' "not performed: this verb builds the message"
    printf 'requires\t%s\n' "a UE stack holding the target's NAS security context, or an eNB-side LPPa peer (11_lte_core.sh has S1AP); delivering an LPP message needs one of the two"
    printf 'note\t%s\n' "the E-SMLC records what the device reports; a device that reports a false position in a correctly encoded message is indistinguishable from an honest one at this layer"
    return 0
}

# ── read a position out of an LPP message ─────────────────────────────
# <hex|file> -- decodes the message and reports the estimate it carries. This
# is the read side of --forge-position and the check for a captured one.
lpp_parse_position() {
    local src="${1:-}"
    if [[ -z "$src" ]]; then
        err "usage: --parse-position <hex|file>"
        return 2
    fi
    local -a args
    if [[ -f "$src" ]]; then args=(--file "$src"); else args=(--hex "$src"); fi

    local out rc=0
    out=$(lpp_asn1 lpp-decode "${args[@]}" 2>&1) || rc=$?
    if (( rc != 0 )); then
        printf '%s\n' "$out" >&2
        return 1
    fi
    local f
    f() { printf '%s\n' "$out" | awk -F'\t' -v k="$1" '$1==k{print $2}'; }

    if [[ "$(f estimate)" == "none" ]]; then
        printf 'status\tno-position\n'
        printf 'body\t%s\n' "$(f body)"
        printf 'note\t%s\n' "$(f note)"
        return 0
    fi
    printf 'status\tdecoded\n'
    printf 'body\t%s\n' "$(f body)"
    printf 'shape\t%s\n' "$(f shape)"
    printf 'latitude\t%s\n' "$(f latitude)"
    printf 'longitude\t%s\n' "$(f longitude)"
    [[ -n "$(f radius_m)" ]] && printf 'radius_m\t%s\n' "$(f radius_m)"
    [[ -n "$(f transaction_number)" ]] && \
        printf 'transaction_number\t%s\n' "$(f transaction_number)"
    printf 'consistency\t%s\n' "compare against the serving cell: a forged fix that ignores timing advance and RSRP is inconsistent with both"
    return 0
}

# ── Position forgery detection ─────────────────────────────────────────
# Handoff, not a detection engine. LPP positioning payloads are ASN.1 PER
# (TS 37.355) carried inside LPPa/NRPPa; the latitude/longitude live in
# ProvideLocationInformation, which the TS 36.413 transport header above does
# not reach. Printing a verdict without decoding that layer would be a
# fabricated result, so this verb prints the plan and the exact tool needed
# instead (MODULE_CONVENTIONS §9).
lpp_detect_forgery() {
    local pcap="$1"
    [[ -z "$pcap" ]] && { warn "usage: --detect-forgery <pcap>"; return 1; }
    [[ -f "$pcap" ]] || { err "no such capture: $pcap"; return 1; }
    
    cat << EOF
Forged Position Detection: $pcap
================================
status: handoff

This module performs no detection on this capture. One layer is missing:

  Transport — LPP rides LPPa (S1AP, TS 36.413) or NRPPa (NGAP, TS 38.413), so
  the capture must first be dissected to the LPP PDU. The payload layer is not
  missing any more: once the PDU is out, --parse-position reads it.

  tshark (>= 3.x, LPP dissector) or Wireshark
      tshark -r $(printf '%q' "$pcap") -Y lpp -T fields -e lpp.pdu
  then feed each PDU to:  46_lpp.sh --parse-position <hex>

What to compare once decoded:
  - a reported accuracy better than the measured reference signal supports
  - a reported position inconsistent with the serving cell's timing advance
    and RSRP (a spoofed fix usually cannot stay consistent with both)
  - a report whose coordinates are inside the range but whose uncertainty is
    smaller than the cell geometry can support (--forge-position shows what a
    well-formed lie looks like; the range check alone will not catch it)

For a reference signal to compare against, run 02_cell_recon or 39_ta_geoloc
against the same serving cell.
EOF
}

# ── Selftest ───────────────────────────────────────────────────────────
lpp_selftest() {
    local bad=0 nchk=0
    chk() {
        nchk=$(( nchk + 1 ))
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$(( bad + 1 )); fi
    }

    # 1. Procedure code mapping
    chk pid-1-name "$(get_lpp_pid_name 1)" "locationInformation"
    chk pid-2-name "$(get_lpp_pid_name 2)" "positioningData"
    chk pid-99-unknown "$(get_lpp_pid_name 99)" "unknown"

    # 2. Header encoding
    local hdr=$(lpp_build_header 1 reject 000c)
    chk header-len "${#hdr}" "8"
    chk header-proc "$(printf '%02x' 1)" "01"

    # 3. Header decoding
    local dec=$(lpp_decode_header "0100000c")
    chk dec-proc "$(echo "$dec" | grep 'Procedure Code:' | awk '{print $3}')" "1"
    chk dec-len "$(echo "$dec" | grep 'Length:' | awk '{print $2}')" "12"

    # 4. A forged position report is a real LPP message. The bytes are pinned
    #    to what pycrate produces for the same value (tools/lpp-oracle/
    #    check_lpp_position.py asserts the whole family); pinning one here
    #    means a regenerated table that moves a bit is caught by the module's
    #    own selftest and not only by the oracle run.
    local out rc
    out=$(lpp_forge_position 51.5007,-0.1246 2>/dev/null); rc=$?
    chk forge-rc "$rc" "0"
    chk forge-status "$(echo "$out" | awk -F'\t' '$1=="status"{print $2}')" "built"
    chk forge-bits "$(echo "$out" | awk -F'\t' '$1=="pdu_bits"{print $2}')" "94"
    chk forge-hex "$(echo "$out" | awk -F'\t' '$1=="pdu_hex"{print $2}')" \
        "D2020028410124FB55FFA544"
    chk forge-message "$(echo "$out" | awk -F'\t' '$1=="message"{print $2}')" \
        "provideLocationInformation"
    chk forge-lat "$(echo "$out" | awk -F'\t' '$1=="latitude"{print $2}')" "51.5007000"
    chk forge-lon "$(echo "$out" | awk -F'\t' '$1=="longitude"{print $2}')" "-0.1246000"
    # The uncertainty variant is a different message, not a comment on this one.
    out=$(lpp_forge_position 51.5007,-0.1246 30 2>/dev/null)
    chk forge-radius-rc "$?" "0"
    chk forge-radius-hex "$(echo "$out" | awk -F'\t' '$1=="pdu_hex"{print $2}')" \
        "D2020028410524FB55FFA544F0"
    chk forge-radius-m "$(echo "$out" | awk -F'\t' '$1=="radius_m"{print $2}')" "30"
    # It must refuse rather than approximate what the protocol cannot carry.
    chk forge-lat-high "$(lpp_forge_position 91,0 >/dev/null 2>&1; echo $?)" "2"
    chk forge-lon-high "$(lpp_forge_position 0,181 >/dev/null 2>&1; echo $?)" "2"
    chk forge-radius-high "$(lpp_forge_position 51,-1 128 >/dev/null 2>&1; echo $?)" "2"
    chk forge-noarg "$(lpp_forge_position "" >/dev/null 2>&1; echo $?)" "2"
    chk forge-nocomma "$(lpp_forge_position 51.5 >/dev/null 2>&1; echo $?)" "2"

    # 5. Reading one back must return the position, not an offset.
    out=$(lpp_parse_position "D2020028410524FB55FFA544F0" 2>/dev/null); rc=$?
    chk parse-rc "$rc" "0"
    chk parse-status "$(echo "$out" | awk -F'\t' '$1=="status"{print $2}')" "decoded"
    chk parse-shape "$(echo "$out" | awk -F'\t' '$1=="shape"{print $2}')" \
        "ellipsoidPointWithUncertaintyCircle"
    chk parse-radius "$(echo "$out" | awk -F'\t' '$1=="radius_m"{print $2}')" "30"
    chk parse-lat "$(awk -F'\t' '$1=="latitude"{printf "%.4f", $2}' <<<"$out")" "51.5007"
    chk parse-lon "$(awk -F'\t' '$1=="longitude"{printf "%.4f", $2}' <<<"$out")" "-0.1246"
    # An arbitrary buffer used to produce a position here (it read bytes 24..32
    # as latitude and 32..40 as longitude and printed them as degrees). The
    # same buffer now decodes, correctly, as carrying no location estimate --
    # and the assertion that matters is that no coordinate comes out of it.
    out=$(lpp_parse_position "000000000000000000000000000000000000000000000000" 2>/dev/null)
    chk parse-junk-status "$(echo "$out" | awk -F'\t' '$1=="status"{print $2}')" "no-position"
    chk parse-junk-no-lat "$(echo "$out" | grep -c 'latitude')" "0"
    out=$(lpp_parse_position "$(lpp_build_header 1 reject 000c)" 2>/dev/null)
    chk parse-header-only "$(echo "$out" | awk -F'\t' '$1=="status"{print $2}')" "no-position"
    chk parse-header-only-no-lat "$(echo "$out" | grep -c 'latitude')" "0"

    # 6. Unknown values must fail
    chk header-short "$(lpp_decode_header "01" >/dev/null 2>&1; echo $?)" "1"
    chk parse-empty "$(lpp_parse_position "" >/dev/null 2>&1; echo $?)" "2"
    chk parse-missing "$(lpp_parse_position >/dev/null 2>&1; echo $?)" "2"

    # 7. --detect-forgery is a handoff: it must refuse rather than invent a
    #    verdict, and it must never claim an analysis it did not run.
    chk forgery-noargs "$(lpp_detect_forgery >/dev/null 2>&1; echo $?)" "1"
    chk forgery-nofile "$(lpp_detect_forgery /nonexistent-lpp.pcap >/dev/null 2>&1; echo $?)" "1"
    local forgery_out=$(lpp_detect_forgery "$BASH_SOURCE" 2>&1)
    chk forgery-says-handoff "$(echo "$forgery_out" | grep -c 'status: handoff')" "1"
    chk forgery-no-verdict "$(echo "$forgery_out" | grep -ciE 'anomalies detected|position outside valid bounds')" "0"

    # ── known answers: OTDOA / UTDOA / PRS procedure half ──────────────
    # Every hex literal below was produced by pycrate 0.8.1, not by this
    # tree: `pycrate_asn1dir.LPP` -> LPP_PDU_Definitions -> LPP_Message,
    # set_val(<the same value this verb builds>) then to_uper(), which is the
    # UNALIGNED PER encoder LPP uses. tools/lpp_layout.py + tools/lte_per.py
    # reproduce those octets bit for bit, and --oracle-check re-derives them
    # from pycrate at run time when the oracle venv is present. The claim here
    # is not "it round-trips": it is "an independent implementation agrees".
    local out rc sab
    lpp_field() { awk -F'\t' -v m="$2" -v c="$3" '$1==m{print $c}' <<< "$1"; }

    out=$(lpp_otdoa_assist 2>/dev/null); rc=$?
    chk assist-rc "$rc" 0
    chk assist-hex "$(lpp_field "$out" otdoa-assist 4)" \
        900218133402002010000001189C2600000C02680860040C0000000028C00C18000000C0518020300000040140
    chk assist-bits "$(lpp_field "$out" otdoa-assist 5)" 355
    chk assist-bytes "$(lpp_field "$out" otdoa-assist 3)" 45
    chk assist-nbr-count "$(grep -c '^otdoa-assist-nbr' <<< "$out")" 3
    chk assist-sent "$(awk -F'\t' 'NR > 1 && $7 != 0' <<< "$out" | wc -l)" 0
    case "$(lpp_field "$out" otdoa-assist 6)" in
        *lpp_layout+lte_per*) chk assist-encoding yes yes ;;
        *)                    chk assist-encoding no yes ;;
    esac

    # muting is an extension addition: dropping it must change the octets
    # (355 bits with po4 muting vs 330 without), so "carried" is testable.
    out=$(lpp_otdoa_assist --muting none 2>/dev/null)
    chk assist-nomute-hex "$(lpp_field "$out" otdoa-assist 4)" \
        900218133402002010000001189C06000010C00818000000005180183000000180A30040600000080280
    chk assist-nomute-bits "$(lpp_field "$out" otdoa-assist 5)" 330

    out=$(lpp_otdoa_assist --pci 5 --earfcn 100 --ecgi 001:01:7 --prs-bw n100 \
            --prs-index 160 --num-dl-frames sf-4 --muting none --nbr 10:100:20 2>/dev/null)
    chk assist-custom-hex "$(lpp_field "$out" otdoa-assist 4)" \
        90021813340A00201000000700640A140800C028285020190140
    chk assist-custom-bits "$(lpp_field "$out" otdoa-assist 5)" 204

    out=$(lpp_otdoa_assist --ecgi none --muting none --nbr '' 2>/dev/null)
    chk assist-bare-hex "$(lpp_field "$out" otdoa-assist 4)" 90021812140231380C0000
    chk assist-bare-bits "$(lpp_field "$out" otdoa-assist 5)" 85
    case "$(lpp_field "$out" otdoa-assist 2)" in
        *cellGlobalId=absent*) chk assist-bare-absent-ci yes yes ;;
        *)                     chk assist-bare-absent-ci no yes ;;
    esac

    # a neighbour may carry its own PRS configuration (own bandwidth, index and
    # frame count), not the reference cell's: that is the point of the IE.
    out=$(lpp_otdoa_assist --muting none --nbr 10:100:20:n100:1120:sf-2 2>/dev/null)
    chk assist-nbr-own-prs-hex "$(lpp_field "$out" otdoa-assist 4)" \
        900218133402002010000001189C06000000C0282A3010190140
    case "$(lpp_field "$out" otdoa-assist-nbr 2)" in
        *'prs-Bandwidth=n100'*) chk assist-nbr-own-prs yes yes ;;
        *)                      chk assist-nbr-own-prs no yes ;;
    esac

    out=$(lpp_otdoa_assist --pci 7 --prs-index 1120 --num-dl-frames sf-2 --nbr '' 2>/dev/null)
    chk assist-sf2-hex "$(lpp_field "$out" otdoa-assist 4)" \
        90021812340E002010000001189C268C040C0268
    chk assist-sf2-bits "$(lpp_field "$out" otdoa-assist 5)" 159

    lpp_otdoa_assist --pci 999 >/dev/null 2>&1; chk assist-pci-bad "$?" 2
    out=$(lpp_otdoa_assist --pci 999 2>/dev/null)
    chk assist-pci-bad-stdout "$(printf '%s' "$out" | wc -c)" 0
    lpp_otdoa_assist --nbr 2:99999:5 >/dev/null 2>&1; chk assist-rstd-bad "$?" 2
    lpp_otdoa_assist --nbr 1:0:5 >/dev/null 2>&1; chk assist-nbr-is-ref "$?" 2
    lpp_otdoa_assist --muting po3:1 >/dev/null 2>&1; chk assist-muting-bad "$?" 2

    out=$(lpp_otdoa_request 2>/dev/null); rc=$?
    chk request-rc "$rc" 0
    chk request-hex "$(lpp_field "$out" otdoa-request 4)" \
        920228111C0001189C12840084D2148019252540
    chk request-bits "$(lpp_field "$out" otdoa-request 5)" 156
    chk request-nbr-count "$(grep -c '^otdoa-request-nbr' <<< "$out")" 2
    case "$(lpp_field "$out" otdoa-request-tx 2)" in
        *targetDevice*) chk request-initiator yes yes ;;
        *)              chk request-initiator no yes ;;
    esac

    out=$(lpp_otdoa_request --form capabilities 2>/dev/null)
    chk request-caps-hex "$(lpp_field "$out" otdoa-request 4)" 92020010
    chk request-caps-bits "$(lpp_field "$out" otdoa-request 5)" 31
    lpp_otdoa_request --form capabilities --sfn 5 >/dev/null 2>&1
    chk request-caps-refuses-meas "$?" 2

    out=$(lpp_otdoa_request --sfn 100 --pci 7 --nbr 7:500:1:2:3 2>/dev/null)
    chk request-custom-hex "$(lpp_field "$out" otdoa-request 4)" \
        9202281118C807189C128001C1F45130
    chk request-custom-bits "$(lpp_field "$out" otdoa-request 5)" 124
    # error-NumSamples on the REFERENCE quality is the third component of
    # OTDOA-MeasQuality; this case pins it (a pycrate miss here once hid it).
    out=$(lpp_otdoa_request --sfn 810 --pci 237 --earfcn 52610 \
            --nbr 14:2476:3:9 --ref-samples 2 2>/dev/null)
    chk request-refsamples-hex "$(lpp_field "$out" otdoa-request 4)" \
        920228111E54EDCD8252A00071358690
    chk request-refsamples-bits "$(lpp_field "$out" otdoa-request 5)" 124
    lpp_otdoa_request --nbr 2:1234:1 >/dev/null 2>&1; chk request-nbr-bad "$?" 2

    # UTDOA: no LPP types exist, so the verb states fields and must emit no
    # octets at all -- a hex column here would be a fabricated LPPa PDU.
    out=$(lpp_utdoa_config 2>/dev/null); rc=$?
    chk utdoa-rc "$rc" 0
    chk utdoa-no-octets "$(awk -F'\t' 'NR > 1 && $4 != "-"' <<< "$out" | wc -l)" 0
    # two rows carry the name: where the fields came from, and the limit row
    # that names the oracle module for anyone who wants to encode LPPa
    chk utdoa-names-lppa "$(grep -c 'pycrate_asn1dir.LPPa' <<< "$out")" 2
    chk utdoa-says-zero-types "$(grep -c 'grep -c utdoa tools/lpp_layout.py' <<< "$out")" 1
    lpp_utdoa_config --oracle-check >/dev/null 2>&1; chk utdoa-refuses-oracle "$?" 2

    # PRS planner: period/offset from the 36.211 6.10.4 table, and a handoff
    # command that is named, not run.
    out=$(lpp_prs_plan --prs-index 159 --num-dl-frames sf-6 2>/dev/null); rc=$?
    chk prs-rc "$rc" 0
    case "$(lpp_field "$out" prs-plan 2)" in
        *period=160*)  chk prs-period-159 yes yes ;;
        *)             chk prs-period-159 no yes ;;
    esac
    case "$(lpp_field "$out" prs-plan 2)" in
        *delta-PRS=159*) chk prs-offset-159 yes yes ;;
        *)               chk prs-offset-159 no yes ;;
    esac
    case "$(lpp_field "$out" prs-plan 2)" in
        *N_PRS=6*) chk prs-numdl-frames yes yes ;;
        *)         chk prs-numdl-frames no yes ;;
    esac
    case "$(lpp_field "$out" prs-plan-occasion 2)" in
        *'mod 160 == 0'*) chk prs-occasion-formula yes yes ;;
        *)                chk prs-occasion-formula no yes ;;
    esac
    case "$(lpp_field "$out" prs-plan-handoff 2)" in
        *'tools/phy_seqs.py gen --seq prs'*) chk prs-handoff-cmd yes yes ;;
        *)                                   chk prs-handoff-cmd no yes ;;
    esac
    chk prs-handoff-not-run "$(lpp_field "$out" prs-plan-handoff 6)" external-tool
    case "$(lpp_field "$out" prs-plan-handoff 9)" in
        *'not run by this verb'*) chk prs-handoff-limit yes yes ;;
        *)                        chk prs-handoff-limit no yes ;;
    esac
    for pair in 160:320 480:640 1120:1280; do
        i=${pair%%:*}; want=${pair##*:}
        case "$(lpp_field "$(lpp_prs_plan --prs-index "$i" 2>/dev/null)" prs-plan 2)" in
            *"period=$want"*) chk "prs-period-$i" yes yes ;;
            *)                chk "prs-period-$i" no yes ;;
        esac
    done
    lpp_prs_plan --prs-index 2400 >/dev/null 2>&1; chk prs-reserved "$?" 2
    out=$(lpp_prs_plan --prs-index 2400 2>/dev/null)
    chk prs-reserved-stdout "$(printf '%s' "$out" | wc -c)" 0
    lpp_prs_plan --pci 999 >/dev/null 2>&1; chk prs-pci-bad "$?" 2

    # The oracle dependency must fail closed: rc 2, empty stdout, a WHY.
    sab=$(IMSI_LPP_ORACLE_PY=/nonexistent/python lpp_otdoa_assist --oracle-check 2>"$MOD_TMP/o.err")
    chk oracle-missing-rc "$?" 2
    chk oracle-missing-stdout "$(printf '%s' "$sab" | wc -c)" 0
    chk oracle-missing-why "$(grep -c '^WHY' "$MOD_TMP/o.err")" 1

    # an interpreter that runs but never reaches pycrate must also refuse, not
    # print a PDU: rc 2 with empty stdout, same rule as a missing venv.
    sab=$(IMSI_LPP_ORACLE_PY=/bin/true lpp_otdoa_assist --oracle-check 2>/dev/null)
    chk oracle-silent-rc "$?" 2
    chk oracle-silent-stdout "$(printf '%s' "$sab" | wc -c)" 0

    # With the oracle present, pycrate must reproduce the same octets.
    if [[ -x "${IMSI_LPP_ORACLE_PY:-/home/ysl/.lte-oracles/venv/bin/python}" ]]; then
        out=$("${IMSI_LPP_ORACLE_PY:-/home/ysl/.lte-oracles/venv/bin/python}" \
                -c 'import pycrate_asn1dir.LPP' 2>/dev/null && lpp_otdoa_assist --oracle-check 2>/dev/null)
        if [[ -n "$out" ]]; then
            chk oracle-present "$(grep -c '^oracle' <<< "$out")" 1
            chk oracle-present-hex "$(lpp_field "$out" oracle 4)" \
                900218133402002010000001189C2600000C02680860040C0000000028C00C18000000C0518020300000040140
        else
            printf '%s\tSKIP\n' oracle-present
        fi
    else
        printf '%s\tSKIP\n' oracle-present
    fi

    printf 'ASSERTIONS\t%d\n' "$nchk"
    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

# ── menu ───────────────────────────────────────────────────────────────
lpp_menu() {
    while true; do
        banner
        echo -e "  ${C_MAG}=== LPP Position Forgery ===${C_RESET}\n"
        cat << 'M'
  [1]  List LPP procedure codes
  [2]  Decode LPP header
  [3]  Build LPP header
  [4]  Forge a position report
  [5]  Parse a position report
  [6]  Detect forged positions
  [7]  Build OTDOA assistance data (reference cell + neighbours)
  [8]  Build a UE OTDOA response (measurements / capabilities)
  [9]  State the UTDOA uplink fields (LPPa)
  [10] Plan PRS occasions for a PRS-ConfigurationIndex
  [0]  back

M
        read -rp "  choice> " c || return 0
        case "$c" in
            1)
                for pid in "${!LPP_PIDS[@]}"; do
                    echo "$pid -> $(get_lpp_pid_name $pid)"
                done
                read -rp "  press enter " _ ;;
            2)
                read -rp "  hex> " h
                lpp_decode_header "$h"; read -rp "  press enter " _ ;;
            3)
                read -rp "  proc_code> " p
                read -rp "  crit> " c
                read -rp "  length> " l
                echo "$(lpp_build_header "$p" "$c" "$l")"
                read -rp "  press enter " _ ;;
            4)
                read -rp "  latitude,longitude> " u
                read -rp "  radius metres (blank for a bare point)> " m
                lpp_forge_position "$u" "$m"
                read -rp "  press enter " _ ;;
            5)
                read -rp "  hex or file> " h
                lpp_parse_position "$h"; read -rp "  press enter " _ ;;
            6)
                read -rp "  pcap path> " p
                lpp_detect_forgery "$p"; read -rp "  press enter " _ ;;
            7)
                read -rp "  reference PCI [1]> " p
                read -rp "  PRS configurationIndex [0]> " i
                read -rp "  neighbours PCI:RSTD:UNC,.. [2:0:5,3:3:5,4:8:10]> " n
                lpp_otdoa_assist --pci "${p:-1}" --prs-index "${i:-0}" \
                    --nbr "${n:-2:0:5,3:3:5,4:8:10}"
                read -rp "  press enter " _ ;;
            8)
                read -rp "  form (measure|capabilities) [measure]> " f
                lpp_otdoa_request --form "${f:-measure}"
                read -rp "  press enter " _ ;;
            9)
                lpp_utdoa_config; read -rp "  press enter " _ ;;
            10)
                read -rp "  PRS configurationIndex [0]> " i
                lpp_prs_plan --prs-index "${i:-0}"; read -rp "  press enter " _ ;;
            0) return ;;
            *) warn "invalid"; sleep 1 ;;
        esac
    done
}

# ── CLI dispatch ───────────────────────────────────────────────────────
lpp_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)   lpp_status_tsv ;;
        --list-pids)    for pid in "${!LPP_PIDS[@]}"; do echo "$pid -> $(get_lpp_pid_name $pid)"; done ;;
        --decode-header) lpp_decode_header "${1:-}" ;;
        --build-header)  lpp_build_header "${1:-1}" "${2:-reject}" "${3:-000c}" ;;
        --forge-position) lpp_forge_position "${1:-}" "${2:-}" ;;
        --parse-position) lpp_parse_position "${1:-}" ;;
        --detect-forgery) lpp_detect_forgery "${1:-}" ;;
        --otdoa-assist)  lpp_otdoa_assist "$@" ;;
        --otdoa-request) lpp_otdoa_request "$@" ;;
        --utdoa-config)  lpp_utdoa_config "$@" ;;
        --prs-plan)      lpp_prs_plan "$@" ;;
        --selftest)     lpp_selftest ;;
        --menu)         lpp_menu ;;
        *) cat >&2 <<EOF
LPP Position Forgery — LTE Positioning Protocol

Usage: $0 COMMAND
  --status-tsv         tool and store state as TSV
  --list-pids          list LPP procedure codes
  --decode-header <hex>
  --build-header [proc] [crit] [len]
  --forge-position <lat>,<lon> [radius-m]
                       build an LPP position report with these coordinates
  --parse-position <hex|file>
                       decode an LPP message and print the position in it
  --detect-forgery <pcap>
  --otdoa-assist       build the OTDOA-ProvideAssistanceData an E-SMLC sends:
                       reference cell, its PRS config, and up to 24 neighbours
                       (the header comment lists the options; --menu prompts)
  --otdoa-request      build what the UE sends back: OTDOA signal measurements
                       (RSTD per neighbour) or its capabilities
  --utdoa-config       state the UTDOA uplink fields (LPPa, TS 36.455) -- and
                       why they are not LPP messages
  --prs-plan           PRS occasions implied by a PRS-ConfigurationIndex, then
                       the samples handoff (a command named, not run)
  --selftest           verify tables and parsers
  --menu               interactive menu
EOF
            return 2 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -o pipefail
    IMSISTING_CLI=1
    : "${TMP_DIR:=/tmp/imsisting}"
    : "${LOOT_DIR:=$IMSISTING_ROOT/loot}"
    : "${CAPTURES_DIR:=$IMSISTING_ROOT/captures}"
    : "${LOGS_DIR:=$IMSISTING_ROOT/logs}"
    : "${STATE_DIR:=$IMSISTING_ROOT/state}"
    mkdir -p "$TMP_DIR" "$LOOT_DIR" "$CAPTURES_DIR" "$LOGS_DIR" "$STATE_DIR"
    declare -F banner >/dev/null 2>&1 || banner() { :; }
    declare -F info   >/dev/null 2>&1 || info()   { printf '[info] %s\n' "$*" >&2; }
    declare -F warn   >/dev/null 2>&1 || warn()   { printf '[warn] %s\n' "$*" >&2; }
    declare -F err    >/dev/null 2>&1 || err()    { printf '[err]  %s\n' "$*" >&2; }
    declare -F ok     >/dev/null 2>&1 || ok()     { printf '[ok]   %s\n' "$*" >&2; }
    lpp_cli_main "$@"
fi
