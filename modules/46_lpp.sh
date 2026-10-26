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
# The TRANSPORT around LPP lives here too: SUPL, OMA ULP 2.0 (TCP 7275). LPP
# says where the device is; SUPL is the envelope a network element actually
# opens a socket to send it in. --supl-build writes ULP-PDUs (SUPL INIT,
# SUPL START, SUPL POS, and Ver2-SUPLSETINIT, the only one carrying a target
# SET id), --supl-parse reads them back field by field, --supl-session writes
# the SET session id and SET id on their own, and --supl-pos puts an existing
# LPP-Message inside a SUPL POS so that --supl-parse hands those very bytes
# back to --parse-position. The ASN.1 is OMA-TS-ULP-V2_0_5-20191028-A, packed
# with UNALIGNED PER; the expected octets in the selftest are pycrate's, and
# tools/check-supl.sh re-checks them with tshark's ULP dissector.
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
#   --utdoa-build   [--pci N] [--ul-earfcn N] [--num-transmissions N]
#                   [--ul-bw n6|..|n100] [--srs-index N] [--srs-cs CS] [--srs-antenna an1|an2|an4]
#                   encodes the UTDOA IE contents as LPPa (TS 36.455) in APER
#                   and decodes them back; needs the pycrate oracle
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
        err "python3 is required for the SUPL verbs (--supl-build/--supl-parse/--supl-session/--supl-pos)"
        return 2
    }
    local py
    py=$(lpp_proc_py) || {
        err "cannot write the procedure driver under $MOD_TMP"
        return 2
    }
    python3 "$py" "$verb" "$@"
}

# ── R65: UTDOA octets, in the protocol that actually carries them ───────
# LPP (TS 37.355) has no UTDOA IEs. Uplink UTDOA is an LPPa procedure
# (TS 36.455): the E-SMLC sends utdoaInformationRequest, the eNB answers, and
# the contents are RequestedSRSTransmissionCharacteristics plus one
# SRSConfigurationForOneCell per cell that should listen. Naming those types was
# the earlier position; this verb encodes them. The octets come from pycrate
# (pycrate_asn1dir.LPPa) in APER, and every one is decoded back and compared, so
# the hex is a message that round-trips rather than a transcription.
#
# What is deliberately NOT emitted: the LPPa pdu layer itself. UTDOAInformation-
# Request in pycrate is a protocolIEs SEQUENCE OF with an OPEN_TYPE value field,
# and building that layer means choosing the id constant and criticality of a
# protocol this module does not own. The IE contents below are the part that
# carries the request, and the row says so rather than presenting a whole PDU.
lpp_utdoa_build() {
    local pci=1 earfcn=18300 ntx=500 bw=n50 idx=7 cs=cs0 ant=an1 maxupts=true
    while (($#)); do
        case "$1" in
            --pci)              pci="${2:-1}";      shift 2 ;;
            --ul-earfcn)        earfcn="${2:-18300}"; shift 2 ;;
            --num-transmissions) ntx="${2:-500}";   shift 2 ;;
            --ul-bw)            bw="${2:-n50}";     shift 2 ;;
            --srs-index)        idx="${2:-7}";      shift 2 ;;
            --srs-cs)           cs="${2:-cs0}";     shift 2 ;;
            --srs-antenna)      ant="${2:-an1}";    shift 2 ;;
            *) err "unknown option $1"; return 2 ;;
        esac
    done
    local py="${IMSI_LPP_ORACLE_PY:-/home/ysl/.lte-oracles/venv/bin/python}"
    if [[ ! -x "$py" ]]; then
        printf 'ERROR\tLPPa encoder unavailable: %s is not an executable interpreter\n' "$py" >&2
        printf 'WHY\tUTDOA contents are LPPa (TS 36.455) and the encoder is pycrate_asn1dir.LPPa; without it this verb has no octets to print\n' >&2
        printf 'FIX\tinstall pycrate in /home/ysl/.lte-oracles/venv or set IMSI_LPP_ORACLE_PY\n' >&2
        return 2
    fi
    local script="$MOD_TMP/lpp_utdoa_build.py"
    cat > "$script" <<'PYEOF'
import sys
try:
    from pycrate_asn1dir import LPPa
except ImportError as exc:
    sys.stderr.write('ERROR\tcannot import pycrate_asn1dir.LPPa: %s\n' % exc)
    raise SystemExit(2)
I = LPPa.LPPA_IEs
REF = ('TS 36.455 (LPPa) utdoaInformationRequest: RequestedSRSTransmissionCharacteristics, '
       'SRSConfigurationForOneCell; TS 36.331 6.3.2 SRS configuration')
REF_REQ = ('TS 36.455 UTDOAInformationRequest-IEs/RequestedSRSTransmissionCharacteristics '
           '(numberOfTransmissions, bandwidth)')
LIMIT = ('IE contents only: the LPPa pdu layer (protocolIEs with an OPEN_TYPE value) is a '
         'protocol this module does not own, so no S1AP-carried LPPa PDU is claimed here')
print('ie\ttype\toctets\thex\tdecoded_back\tref\tlimit')
a = dict(x.split('=', 1) for x in sys.argv[1:])
req = I.RequestedSRSTransmissionCharacteristics
req.set_val({'numberOfTransmissions': int(a['ntx']), 'bandwidth': int(a['bw_rb'])})
h = req.to_aper().hex()
back = I.RequestedSRSTransmissionCharacteristics
back.from_aper(bytes.fromhex(h))
ok = 'yes' if back.get_val() == req.get_val() else 'NO'
print('requested-srs\tRequestedSRSTransmissionCharacteristics\t%d\t%s\t%s\t%s\t%s'
      % (len(h) // 2, h, ok, REF_REQ, LIMIT))
cell = I.SRSConfigurationForOneCell
cell.set_val({'pci': int(a['pci']), 'ul-earfcn': int(a['earfcn']),
              'ul-bandwidth': a['bw'], 'ul-cyclicPrefixLength': 'normal',
              'srs-BandwidthConfig': 'bw0', 'srs-Bandwidth': 'bw0',
              'srs-AntennaPort': a['ant'], 'srs-HoppingBandwidth': 'hbw0',
              'srs-cyclicShift': a['cs'], 'srs-ConfigIndex': int(a['idx']),
              'maxUpPts': a['maxupts'], 'transmissionComb': 0,
              'freqDomainPosition': 0, 'groupHoppingEnabled': False,
              'deltaSS': 0, 'sfnInitialisationTime': (0, 64)})
h2 = cell.to_aper().hex()
back2 = I.SRSConfigurationForOneCell
back2.from_aper(bytes.fromhex(h2))
v2 = back2.get_val()
ok2 = 'yes' if v2['pci'] == int(a['pci']) and v2['srs-ConfigIndex'] == int(a['idx']) else 'NO'
print('srs-cell\tSRSConfigurationForOneCell\t%d\t%s\t%s\t%s\t%s'
      % (len(h2) // 2, h2, ok2, REF, LIMIT))
print('protocol\tLPPa (TS 36.455), not LPP (TS 37.355): LPP has no UTDOA IEs at all\t-\t-\t-\t%s\t%s'
      % (REF, LIMIT))
print('carrier\tLPPa over S1AP: DownlinkUEAssociatedLPPaTransport, then utdoaInformationResponse from the eNB\t-\t-\t-\t%s\t%s'
      % (REF, LIMIT))
print('encoding\tpycrate_asn1dir.LPPa, APER\t-\t-\t-\t%s\t%s' % (REF, LIMIT))
print('verdict\tutdoa_encoded_as_lppa')
PYEOF
    local bwrb
    case "$bw" in
        n6)   bwrb=6 ;;   n15)  bwrb=15 ;;  n25) bwrb=25 ;;
        n50)  bwrb=50 ;;  n75)  bwrb=75 ;;  n100) bwrb=100 ;;
        *) err "ul bandwidth is n6, n15, n25, n50, n75 or n100"; return 2 ;;
    esac
    "$py" "$script" "pci=$pci" "earfcn=$earfcn" "ntx=$ntx" "bw=$bw" \
        "bw_rb=$bwrb" "idx=$idx" "cs=$cs" "ant=$ant" "maxupts=$maxupts"
}


lpp_otdoa_assist()  { lpp_proc_run otdoa-assist  "$@"; }
lpp_otdoa_request() { lpp_proc_run otdoa-request "$@"; }
lpp_utdoa_config()  { lpp_proc_run utdoa-config  "$@"; }
lpp_prs_plan()      { lpp_proc_run prs-plan      "$@"; }

# ── SUPL / OMA ULP 2.0: the transport that carries LPP ──────────
# LPP is the payload; SUPL is how it moves. A real SLP reaches a handset by
# opening TCP 7275 and sending a ULP-PDU whose UlpMessage carries first the
# SUPL session handshake and then exactly the LPP-Message bytes that
# --forge-position builds. That envelope is ASN.1 (OMA-TS-ULP-V2_0_5-20191028-A)
# packed with UNALIGNED PER, and its extension additions are untagged open
# types (X.691 12.2), which is why the LPP payload sits behind a length
# determinant inside PosPayLoad instead of inline.
#
# Implemented, and nothing else invented:
#   ULP-PDU / Version / SessionID / SetSessionID / SETId / SlpSessionID /
#   SLPAddress / FQDN, SUPLINIT, SUPLSTART with SETCapabilities,
#   PosTechnology, PrefMethod, PosProtocol, LocationId, GsmCellInformation,
#   Status, SUPLPOS with PosPayLoad -> Ver2-PosPayLoad-extension ->
#   lPPPayload, and Ver2-SUPLSETINIT with targetSETID.
# Refused by name, with ERROR/WHY rather than a guess: SETId's ver2-imei,
# SUPLINIT's notification/qoP/mac/keyIdentity, SUPLSTART's qoP and
# nmr/ta/non-GSM cells, SUPLPOS's velocity and tia801Payload/rrcPayload/
# rrlpPayload alternatives, fragmented open types, and every UlpMessage
# alternative this file does not encode (msSUPLRESPONSE, msSUPLPOSINIT,
# msSUPLEND, msSUPLAUTHREQ, msSUPLAUTHRESP, the NOTIFY/TRIGGERED family).
# The envelope is still decoded and printed before the refusal, so a reader
# learns what the message is even when the body is out of scope.
lpp_supl_py() {
    local py="$MOD_TMP/lpp_supl.py" tmp="$MOD_TMP/.lpp_supl.$$.py"
    mkdir -p "$MOD_TMP" 2>/dev/null
    cat > "$tmp" <<'LPP_SUPL_PY'
"""SUPL / OMA ULP transport codec (uPER) - dev copy."""
import sys

POS_METHODS = ('agpsSETassisted','agpsSETbased','agpsSETassistedpref','agpsSETbasedpref',
               'autonomousGPS','aflt','ecid','eotd','otdoa','noPosition')
POS_METHODS_EXT = ('ver2-historicalDataRetrieval','ver2-agnssSETassisted','ver2-agnssSETbased',
                   'ver2-agnssSETassistedpref','ver2-agnssSETbasedpref','ver2-autonomousGNSS',
                   'ver2-sessioninfoquery','ver2-mbs')
SLP_MODES = ('proxy','nonProxy')
PREF_METHODS = ('agpsSETassistedPreferred','agpsSETBasedPreferred','noPreference')
STATUSES = ('stale','current','unknown')
POS_TECH = ('agpsSETassisted','agpsSETBased','autonomousGPS','aflt','ecid','eotd','otdoa')
POS_PROTOCOL = ('tia801','rrlp','rrc')
SET_ID = ('msisdn','mdn','min','imsi','nai','iPAddress')
SET_ID_EXT = ('ver2-imei',)
ULP_MSG = ('msSUPLINIT','msSUPLSTART','msSUPLRESPONSE','msSUPLPOSINIT','msSUPLPOS',
           'msSUPLEND','msSUPLAUTHREQ','msSUPLAUTHRESP')
ULP_MSG_EXT = ('msSUPLTRIGGEREDSTART','msSUPLTRIGGEREDRESPONSE','msSUPLTRIGGEREDSTOP',
               'msSUPLNOTIFY','msSUPLNOTIFYRESPONSE','msSUPLSETINIT','msSUPLREPORT')

def ceil_log2(n):
    b = 0
    while (1 << b) < n:
        b += 1
    return b

class BitW(object):
    def __init__(self):
        self.bits = []
    def u(self, n, v):
        assert 0 <= v < (1 << n), (n, v)
        for i in range(n - 1, -1, -1):
            self.bits.append((v >> i) & 1)
    def b(self, v):
        self.bits.append(1 if v else 0)
    def raw(self, data):
        for byte in data:
            self.u(8, byte)
    def pad(self):
        while len(self.bits) % 8:
            self.bits.append(0)
    def tobytes(self):
        self.pad()
        out = bytearray()
        for i in range(0, len(self.bits), 8):
            v = 0
            for bit in self.bits[i:i+8]:
                v = (v << 1) | bit
            out.append(v)
        return bytes(out)

class BitR(object):
    def __init__(self, data):
        self.bits = []
        for byte in data:
            for i in range(7, -1, -1):
                self.bits.append((byte >> i) & 1)
        self.pos = 0
    def left(self):
        return len(self.bits) - self.pos
    def u(self, n):
        if self.left() < n:
            raise ValueError('truncated: need %d bits, %d left' % (n, self.left()))
        v = 0
        for _ in range(n):
            v = (v << 1) | self.bits[self.pos]
            self.pos += 1
        return v
    def b(self):
        return self.u(1) == 1
    def raw(self, n):
        """read n bits and return them as octets (n must be a multiple of 8)"""
        if n % 8:
            return bytes(self.u(8) for _ in range(n // 8))
        return bytes(self.u(8) for _ in range(n // 8))

# ---- constrained helpers (unaligned PER) ----
def w_int(w, v, lo, hi):
    if hi > lo:
        w.u(ceil_log2(hi - lo + 1), v - lo)

def r_int(r, lo, hi):
    if hi == lo:
        return lo
    return lo + r.u(ceil_log2(hi - lo + 1))

def w_octstr(w, data, lo, hi):
    n = len(data)
    if not (lo <= n <= hi):
        raise ValueError('octet string of %d outside %d..%d' % (n, lo, hi))
    if hi > lo:
        w.u(ceil_log2(hi - lo + 1), n - lo)
    w.raw(data)

def r_octstr(r, lo, hi):
    n = r_int(r, lo, hi)
    return r.raw(n)

def w_visstr(w, s, lo, hi):
    data = s.encode('ascii')
    n = len(data)
    if not (lo <= n <= hi):
        raise ValueError('visible string of %d outside %d..%d' % (n, lo, hi))
    if hi > lo:
        w.u(ceil_log2(hi - lo + 1), n - lo)
    w.raw(data)

def r_visstr(r, lo, hi):
    n = r_int(r, lo, hi)
    return r.raw(n).decode('ascii')

def w_enum(w, names, value, ext=()):
    if value in ext:
        raise ValueError('extension enum value not supported here')
    w.b(0)
    w.u(ceil_log2(len(names)), names.index(value))

def r_enum_index(r, names, ext=()):
    """returns (name, is_extension, ext_index)"""
    isext = r.b()
    if isext:
        idx = r.u(ceil_log2(len(ext))) if len(ext) > 1 else (0 if ext else None)
        return None, True, idx
    return names[r.u(ceil_log2(len(names)))], False, None

def w_choice(w, names, value, ext=()):
    """value is (alt, payload); ext alternatives are index-only."""
    alt = value[0]
    if alt in names:
        w.b(0)
        w.u(ceil_log2(len(names)), names.index(alt))
    else:
        w.b(1)
        if len(ext) > 1:
            w.u(ceil_log2(len(ext)), ext.index(alt))
    return value[1]

def r_choice_head(r, names, ext=()):
    isext = r.b()
    if isext:
        idx = r.u(ceil_log2(len(ext))) if len(ext) > 1 else 0
        return ext[idx], True, True
    return names[r.u(ceil_log2(len(names)))], True, False

# ---- value tables / TBCD ----
def tbcd_octets(digits):
    d = [int(c) for c in digits]
    if len(d) > 16:
        raise ValueError('at most 16 digits')
    if len(d) % 2:
        d.append(0xF)
    out = bytearray()
    for i in range(0, len(d), 2):
        out.append((d[i+1] << 4) | d[i])
    if len(out) != 8:
        raise ValueError('SETId imsi/msisdn is 8 octets, got %d' % len(out))
    return bytes(out)

def tbcd_digits(data):
    out = []
    for byte in data:
        for nib in (byte & 0xF, byte >> 4):
            if nib == 0xF:
                return ''.join(out)
            if nib > 9:
                raise ValueError('bad BCD nibble %X' % nib)
            out.append(str(nib))
    return ''.join(out)

def hex2bytes(s, n=None):
    s = s.replace(' ', '')
    if len(s) % 2:
        raise ValueError('odd hex length %d' % len(s))
    data = bytes.fromhex(s)
    if n is not None and len(data) != n:
        raise ValueError('want %d octets, got %d' % (n, len(data)))
    return data

# ---- ULP-PDU assembly ----
def build_pdu(body):
    """body(BitW) encodes version, sessionID, message; prepends the 2-octet length."""
    w = BitW()
    body(w)
    bits = len(w.bits)
    total = 2 + (bits + 7) // 8
    out = bytearray([(total >> 8) & 0xFF, total & 0xFF])
    out += w.tobytes()
    return bytes(out)

def enc_version(w, maj=2, mn=0, servind=0):
    w.u(8, maj); w.u(8, mn); w.u(8, servind)

def enc_session(w, set_sid, slp_sid):
    w.b(set_sid is not None); w.b(slp_sid is not None)
    if set_sid is not None:
        enc_set_session(w, set_sid[0], set_sid[1], set_sid[2])
    if slp_sid is not None:
        enc_slp_session(w, slp_sid[0], slp_sid[1], slp_sid[2])



FQDN_ALPHABET = ('-', '.',) + tuple('0123456789') + tuple(chr(c) for c in range(ord('A'), ord('Z')+1)) + tuple(chr(c) for c in range(ord('a'), ord('z')+1))

def w_fqdn(w, s, lo=1, hi=255):
    """FQDN ::= VisibleString (FROM ("a".."z"|"A".."Z"|"0".."9"|".-")) (SIZE(1..255)).
    Restricted alphabet of 64 characters, sorted by ASCII, 6 bits per character."""
    bad = [c for c in s if c not in FQDN_ALPHABET]
    if bad:
        raise ValueError('character outside FQDN permitted alphabet: %r' % bad[0])
    n = len(s)
    if not (lo <= n <= hi):
        raise ValueError('fqdn of %d characters outside %d..%d' % (n, lo, hi))
    w.u(8, n - lo)
    for c in s:
        w.u(6, FQDN_ALPHABET.index(c))

def r_fqdn(r, lo=1, hi=255):
    n = lo + r.u(8)
    out = []
    for _ in range(n):
        i = r.u(6)
        out.append(FQDN_ALPHABET[i])
    return ''.join(out)

def enc_setid(w, kind, digits=None, ip=None):
    w.b(0)                       # CHOICE extension marker
    w.u(3, SET_ID.index(kind))
    if kind in ('msisdn', 'imsi', 'mdn'):
        w.raw(tbcd_octets(digits))
    elif kind == 'iPAddress':
        enc_ip(w, ip)
    else:
        raise ValueError('cannot encode SETId %s' % kind)

def enc_ip(w, dotted):
    parts = dotted.split('.')
    if len(parts) != 4:
        raise ValueError('ipv4 as a.b.c.d, got %r' % dotted)
    w.u(1, 0)                    # ipv4Address is choice alternative 0
    for p in parts:
        w.u(8, int(p))

def enc_set_session(w, sid, kind, digits):
    w.u(16, sid)
    enc_setid(w, kind, digits=digits)

def enc_slpaddr(w, kind, value):
    w.b(0)                       # CHOICE extension marker
    if kind == 'fqdn':
        w.u(1, 1)
        w_fqdn(w, value, 1, 255)
    elif kind == 'ipv4':
        w.u(1, 0)
        enc_ip(w, value)
    else:
        raise ValueError('cannot encode SLPAddress %s' % kind)

def enc_slp_session(w, sid, kind, value):
    w.raw(hex2bytes(sid, 4))
    enc_slpaddr(w, kind, value)

# SEQUENCE preamble rule (X.691 18.2/18.3, verified against pycrate bit lists):
# an extensible SEQUENCE emits the extension-presence bit FIRST, then one
# presence bit per OPTIONAL root component in component order, then the root
# component values in order.
def enc_suplinit(w, posmethod, slpmode, slpaddr=None):
    w.b(0)                       # extension additions absent
    w.b(0)                       # notification
    w.b(slpaddr is not None)     # sLPAddress
    w.b(0)                       # qoP
    w.b(0)                       # mac
    w.b(0)                       # keyIdentity
    w_enum(w, POS_METHODS, posmethod, POS_METHODS_EXT)
    if slpaddr is not None:
        enc_slpaddr(w, slpaddr[0], slpaddr[1])
    w.u(1, SLP_MODES.index(slpmode))

def enc_pos_tech(w, techs):
    w.b(0)                       # extension additions absent
    for name in POS_TECH:
        w.b(name in techs)

def enc_pos_protocol(w, protos):
    w.b(0)
    for name in POS_PROTOCOL:
        w.b(name in protos)

def enc_set_capabilities(w, techs, prefmethod, protos):
    w.b(0)                       # extension additions absent
    enc_pos_tech(w, techs)
    w.u(2, PREF_METHODS.index(prefmethod))
    enc_pos_protocol(w, protos)

def enc_gsm_cell(w, mcc, mnc, lac, ci):
    w.b(0)                       # extension additions absent
    w.b(0)                       # nmr
    w.b(0)                       # ta
    w.u(10, mcc); w.u(10, mnc); w.u(16, lac); w.u(16, ci)

def enc_location(w, mcc, mnc, lac, ci, status):
    w.b(0)                       # extension additions absent
    w.b(0); w.u(2, 0)            # cellInfo: gsmCell
    enc_gsm_cell(w, mcc, mnc, lac, ci)
    w_enum(w, STATUSES, status)

def enc_suplstart(w, techs, prefmethod, protos, mcc, mnc, lac, ci, status, qop=False):
    w.b(0)                       # extension additions absent
    w.b(qop)
    enc_set_capabilities(w, techs, prefmethod, protos)
    enc_location(w, mcc, mnc, lac, ci, status)

def enc_ver2_pospayload(w, lpps):
    w.b(0)                       # extension additions absent
    w.b(1)                       # lPPPayload present
    w.b(0)                       # tia801Payload absent
    w.u(2, len(lpps) - 1)        # SEQUENCE SIZE(1..3) OF
    for p in lpps:
        w_octstr(w, p, 1, 60000)

def w_open_type(w, encode_fn):
    """X.691 12.2 / 23.2: an extension addition value inside an extensible
    CHOICE is encoded as an untagged open type: the inner uPER encoding of
    the chosen alternative, padded to an octet boundary, prefixed by its
    length in octets (an unconstrained length determinant)."""
    inner = BitW()
    encode_fn(inner)
    inner.pad()
    data = inner.tobytes()
    n = len(data)
    if n < 128:
        w.b(0); w.u(7, n)
    elif n < 16384:
        w.b(1); w.b(0); w.u(14, n)
    else:
        raise ValueError('open type of %d octets needs fragmentation, refused' % n)
    w.raw(data)

def enc_suplpos(w, lpps):
    w.b(0)                       # extension additions absent
    w.b(0)                       # velocity absent
    w.b(1)                       # posPayLoad: extension addition chosen
    w.b(0)                       # index is normally small
    w.u(6, 0)                    # extension index 0 = ver2-PosPayLoad-extension
    w_open_type(w, lambda x: enc_ver2_pospayload(x, lpps))

def enc_ver2_suplsetinit(w, kind, digits):
    w.b(0)                       # extension additions absent
    w.b(0)                       # qoP absent
    w.b(0)                       # applicationID absent
    enc_setid(w, kind, digits)   # targetSETID SETId

def enc_msg_ext(w, ext_index, encode_fn):
    """An extentension alternative of UlpMessage is an untagged open type too."""
    w.b(1)                       # extension alternative chosen
    w.b(0)                       # index is normally small
    w.u(6, ext_index)
    w_open_type(w, encode_fn)

def hex_upper(data):
    return ''.join('%02X' % b for b in data)

# ---------------------------------------------------------------- decoding ---

def r_choice_root(r, names):
    """Read an extensible CHOICE head; returns (alt_name, index). Raises on
    extension alternatives, which this build does not decode."""
    ext = r.b()
    n = ceil_log2(len(names)) if len(names) > 1 else 0
    idx = r.u(n) if n else 0
    if ext:
        raise Refused('CHOICE extension alternative (index %d) is not decoded' % idx)
    if idx >= len(names):
        raise Refused('CHOICE index %d outside the %d root alternatives' % (idx, len(names)))
    return names[idx], idx

def r_choice_ext(r, root, extnames):
    if not r.b():
        n = ceil_log2(len(root)) if len(root) > 1 else 0
        idx = r.u(n) if n else 0
        if idx >= len(root):
            raise Refused('CHOICE index %d outside the %d root alternatives' % (idx, len(root)))
        return root[idx]
    if r.b():
        raise Refused('CHOICE extension index larger than 63 is not decoded')
    idx = r.u(6)
    if idx >= len(extnames):
        raise Refused('CHOICE extension index %d outside the %d known additions' % (idx, len(extnames)))
    return extnames[idx]

def r_open_type(r):
    """X.691 12.2: read an untagged open type and return its inner BitR."""
    if r.b():
        return None, None
    n = r.u(7)
    data = r.raw(n * 8)
    return data, BitR(data)

LAST_ROWS = []

class Refused(Exception):
    pass

def dec_version(r, rows):
    maj = r.u(8); mn = r.u(8); servind = r.u(8)
    rows.append(('version.maj', 'INTEGER', str(maj)))
    rows.append(('version.min', 'INTEGER', str(mn)))
    rows.append(('version.servind', 'INTEGER', str(servind)))
    return {'maj': maj, 'min': mn, 'servind': servind}

def dec_setid(r, rows, prefix='sessionID.setSessionID.setId'):
    ext = r.b()
    if ext:
        raise Refused('SETId extension alternative ver2-imei is not decoded')
    idx = r.u(3)
    if idx >= 6:
        raise Refused('SETId index %d outside the 6 root alternatives' % idx)
    kind = SET_ID[idx]
    rows.append((prefix, 'Choice', '%s (%d)' % (kind, idx)))
    if kind in ('msisdn', 'mdn', 'imsi'):
        raw = r.raw(64)
        digits = tbcd_digits(raw)
        rows.append((prefix + '.' + kind, 'OCTET STRING (8)', hex_upper(raw)))
        rows.append((prefix + '.' + kind + '.digits', 'TBCD digits', digits))
        return {'kind': kind, 'raw': hex_upper(raw), 'digits': digits}
    if kind == 'iPAddress':
        val = dec_ip_addr(r, rows, prefix)
        rows.append((prefix + '.iPAddress', 'Choice', 'iPAddress'))
        return {'kind': kind, 'raw': val, 'digits': val}
    if kind == 'nai':
        raw = r.raw((1 + r.u(10)) * 8)
        rows.append((prefix + '.nai', 'IA5String (1..1000)', raw.decode('ascii', 'replace')))
        return {'kind': kind, 'raw': hex_upper(raw), 'digits': raw.decode('ascii', 'replace')}
    raw = r.raw(34)
    rows.append((prefix + '.min', 'BIT STRING (34)', hex_upper(raw)))
    return {'kind': kind, 'raw': hex_upper(raw), 'digits': hex_upper(raw)}

def dec_set_session(r, rows):
    sid = r.u(16)
    rows.append(('sessionID.setSessionID.sessionId', 'INTEGER (0..65535)', str(sid)))
    st = dec_setid(r, rows)
    st['sessionId'] = sid
    return st

def dec_ip_addr(r, rows, prefix):
    # IPAddress ::= CHOICE { ipv4Address OCTET STRING(SIZE(4)),
    #                        ipv6Address OCTET STRING(SIZE(16)) } -- NOT extensible,
    # so there is one index bit and no extension marker (ULP-Components.asn:53).
    idx = r.u(1)
    if idx == 0:
        raw = r.raw(32)
        val = '.'.join(str(b) for b in raw)
        rows.append((prefix + '.iPAddress', 'Choice', 'ipv4Address (0)'))
        rows.append((prefix + '.iPAddress.ipv4Address', 'OCTET STRING (4)', val))
        return val
    raw = r.raw(128)
    rows.append((prefix + '.iPAddress', 'Choice', 'ipv6Address (1)'))
    rows.append((prefix + '.iPAddress.ipv6Address', 'OCTET STRING (16)', hex_upper(raw)))
    return hex_upper(raw)

def dec_slpid(r, rows):
    alt = r_choice_ext(r, ['iPAddress', 'fqdn'], [])
    if alt == 'iPAddress':
        return dec_ip_addr(r, rows, 'sessionID.slpSessionID.slpId')
    val = r_fqdn(r)
    rows.append(('sessionID.slpSessionID.slpId', 'Choice', 'fqdn (1)'))
    rows.append(('sessionID.slpSessionID.slpId.fqdn', 'VisibleString (1..255)', val))
    return val

def dec_slp_session(r, rows):
    raw = r.raw(32)
    rows.append(('sessionID.slpSessionID.sessionID', 'OCTET STRING (4)', hex_upper(raw)))
    val = dec_slpid(r, rows)
    return {'sid': hex_upper(raw), 'slpId': val}

def dec_pos_method(r, rows):
    name = r_choice_ext(r, POS_METHODS, POS_METHODS_EXT)
    rows.append(('msSUPLINIT.posMethod', 'Enumerated', name))
    return name

def dec_supl_init(r, rows):
    if r.b():
        raise Refused('SUPLINIT version 2 extension additions are not decoded')
    pres = [r.b() for _ in range(5)]
    rows.append(('msSUPLINIT', 'Sequence', 'posMethod, notification, sLPAddress, qoP, sLPMode, mac, keyIdentity'))
    rows.append(('msSUPLINIT.preamble', 'BIT STRING (5)', ''.join(str(int(b)) for b in pres)))
    names = ('notification', 'sLPAddress', 'qoP', 'mac', 'keyIdentity')
    for name, bit in zip(names, pres):
        if bit and name != 'sLPAddress':
            raise Refused('SUPLINIT optional component %s is present; its ASN.1 type is not modelled here' % name)
    posmethod = dec_pos_method(r, rows)
    slp = None
    if pres[1]:
        slp = dec_slpid(r, rows)
    slpmode = r.u(1)
    rows.append(('msSUPLINIT.sLPMode', 'Enumerated', SLP_MODES[slpmode]))
    return {'posMethod': posmethod, 'sLPAddress': slp, 'sLPMode': SLP_MODES[slpmode]}

def dec_supl_start(r, rows):
    if r.b():
        raise Refused('SUPLSTART version 2 extension additions are not decoded')
    qop = r.b()
    if qop:
        raise Refused('SUPLSTART.qoP is present; QoP is not modelled here')
    rows.append(('msSUPLSTART', 'Sequence', 'sETCapabilities, locationId'))
    if r.b():
        raise Refused('SETCapabilities version 2 extension additions are not decoded')
    rows.append(('msSUPLSTART.sETCapabilities', 'Sequence', 'posTechnology, prefMethod, posProtocol'))
    if r.b():
        raise Refused('PosTechnology version 2 extension additions are not decoded')
    tech = [r.b() for _ in POS_TECH]
    rows.append(('msSUPLSTART.sETCapabilities.posTechnology', 'Sequence', '7 BOOLEAN'))
    for name, bit in zip(POS_TECH, tech):
        rows.append(('msSUPLSTART.sETCapabilities.posTechnology.' + name, 'BOOLEAN', 'true' if bit else 'false'))
    pref = r.u(2)
    rows.append(('msSUPLSTART.sETCapabilities.prefMethod', 'Enumerated', PREF_METHODS[pref]))
    if r.b():
        raise Refused('PosProtocol version 2 extension additions are not decoded')
    prot = [r.b() for _ in POS_PROTOCOL]
    rows.append(('msSUPLSTART.sETCapabilities.posProtocol', 'Sequence', 'tia801, rrlp, rrc'))
    for name, bit in zip(POS_PROTOCOL, prot):
        rows.append(('msSUPLSTART.sETCapabilities.posProtocol.' + name, 'BOOLEAN', 'true' if bit else 'false'))
    if r.b():
        raise Refused('LocationId version 2 extension additions are not decoded')
    alt = r_choice_ext(r, ['gsmCell', 'wcdmaCell', 'cdmaCell'], ['ver2-CellInfo-extension'])
    if alt != 'gsmCell':
        raise Refused('CellInfo alternative %s is not modelled here' % alt)
    rows.append(('msSUPLSTART.locationId.cellInfo', 'Choice', 'gsmCell (0)'))
    if r.b():
        raise Refused('GsmCellInformation version 2 extension additions are not decoded')
    nmr = r.b(); ta = r.b()
    if nmr or ta:
        raise Refused('gsmCell.nmr or gsmCell.ta is present; those types are not modelled here')
    mcc = r.u(10); mnc = r.u(10); lac = r.u(16); ci = r.u(16)
    rows.append(('msSUPLSTART.locationId.cellInfo.gsmCell.refMCC', 'INTEGER (0..999)', str(mcc)))
    rows.append(('msSUPLSTART.locationId.cellInfo.gsmCell.refMNC', 'INTEGER (0..999)', str(mnc)))
    rows.append(('msSUPLSTART.locationId.cellInfo.gsmCell.refLAC', 'INTEGER (0..65535)', str(lac)))
    rows.append(('msSUPLSTART.locationId.cellInfo.gsmCell.refCI', 'INTEGER (0..65535)', str(ci)))
    name = r_choice_ext(r, STATUSES, [])
    rows.append(('msSUPLSTART.locationId.status', 'Enumerated', name))
    return {'prefMethod': PREF_METHODS[pref], 'mcc': mcc, 'mnc': mnc, 'lac': lac, 'ci': ci, 'status': name}

def dec_supl_pos(r, rows):
    if r.b():
        raise Refused('SUPLPOS version 2 extension additions are not decoded')
    if r.b():
        raise Refused('SUPLPOS.velocity is present; Velocity is not modelled here')
    alt = r_choice_ext(r, ['tia801payload', 'rrcPayload', 'rrlpPayload'],
                       ['ver2-PosPayLoad-extension'])
    if alt != 'ver2-PosPayLoad-extension':
        raise Refused('PosPayLoad alternative %s is not modelled here' % alt)
    rows.append(('msSUPLPOS.posPayLoad', 'Choice', 'ver2-PosPayLoad-extension (3, open type)'))
    data, inner = r_open_type(r)
    if data is None:
        raise Refused('fragmented open type is not decoded')
    rows.append(('msSUPLPOS.posPayLoad.ver2-PosPayLoad-extension', 'open type', '%d octets %s' % (len(data), hex_upper(data))))
    if inner.b():
        raise Refused('Ver2-PosPayLoad-extension is extensible; only the root part is decoded')
    lpp_present = inner.b(); tia_present = inner.b()
    if not lpp_present:
        raise Refused('Ver2-PosPayLoad-extension.lPPPayload is absent; nothing to carry')
    if tia_present:
        raise Refused('Ver2-PosPayLoad-extension.tia801Payload is present; only lPPPayload is modelled')
    n = 1 + inner.u(2)
    lpps = []
    for i in range(n):
        size = 1 + inner.u(ceil_log2(60000))
        raw = inner.raw(size * 8)
        lpps.append(raw)
        rows.append(('msSUPLPOS.lPPPayload[%d]' % i, 'OCTET STRING (1..60000)', hex_upper(raw)))
    left = inner.left()
    if left >= 8:
        raise Refused('%d trailing bits after lPPPayload in the open type' % left)
    if left and inner.u(left) != 0:
        raise Refused('non-zero padding bits after lPPPayload in the open type')
    rows.append(('msSUPLPOS.lPPPayload', 'SEQUENCE (SIZE(1..3)) OF OCTET STRING', '%d item(s) %s' % (len(lpps), ' '.join(hex_upper(x) for x in lpps))))
    return {'lPPPayload': [hex_upper(x) for x in lpps], 'lpp_payload_hex': hex_upper(lpps[0])}

def r_msg_choice(r, rows):
    if not r.b():
        idx = r.u(3)
        if idx >= len(ULP_MSG):
            raise Refused('UlpMessage index %d outside the 8 root alternatives' % idx)
        return ULP_MSG[idx], False
    if r.b():
        raise Refused('UlpMessage extension index larger than 63 is not decoded')
    idx = r.u(6)
    if idx >= len(ULP_MSG_EXT):
        raise Refused('UlpMessage extension index %d outside the %d known additions' % (idx, len(ULP_MSG_EXT)))
    return ULP_MSG_EXT[idx], True

def dec_msg_ext(r, msg, rows):
    data, inner = r_open_type(r)
    if data is None:
        raise Refused('fragmented open type is not decoded')
    rows.append(('message.' + msg, 'open type', '%d octets %s' % (len(data), hex_upper(data))))
    if msg != 'msSUPLSETINIT':
        raise Refused('message %s is an extension alternative whose ASN.1 this build does not encode' % msg)
    if inner.b():
        raise Refused('Ver2-SUPLSETINIT version 2 extension additions are not decoded')
    qop = inner.b(); appid = inner.b()
    if qop or appid:
        raise Refused('Ver2-SUPLSETINIT.qoP or .applicationID is present; those types are not modelled here')
    rows.append(('msSUPLSETINIT', 'Sequence', 'targetSETID, qoP OPTIONAL, applicationID OPTIONAL'))
    target = dec_setid(inner, rows, prefix='msSUPLSETINIT.targetSETID')
    left = inner.left()
    if left >= 8:
        raise Refused('%d trailing bits after targetSETID' % left)
    if left and inner.u(left) != 0:
        raise Refused('non-zero padding bits after targetSETID')
    return {'targetSETID': target}

def dec_ulp(hexstr):
    try:
        data = bytes.fromhex(hexstr.replace(' ', '').replace(':', ''))
    except ValueError:
        raise Refused('payload is not hexadecimal')
    if len(data) < 4:
        raise Refused('payload of %d octets is too short for a ULP-PDU' % len(data))
    declared = int.from_bytes(data[0:2], 'big')
    bodylen = (len(data) - 2) * 8
    if declared != len(data):
        raise Refused('ULP-PDU length field says %d octets but %d octets were given' % (declared, len(data)))
    r = BitR(data[2:])
    rows = []
    global LAST_ROWS
    LAST_ROWS = rows
    rows.append(('ULP-PDU', 'Sequence', 'length, version, sessionID, message'))
    rows.append(('ULP-PDU.length', 'INTEGER (0..65535)', str(declared)))
    dec_version(r, rows)
    spres = [r.b(), r.b()]
    rows.append(('sessionID', 'Sequence', 'setSessionID OPTIONAL, slpSessionID OPTIONAL'))
    rows.append(('sessionID.presence', 'BIT STRING (2)', ''.join(str(int(b)) for b in spres)))
    if not any(spres):
        raise Refused('sessionID has neither setSessionID nor slpSessionID')
    if spres[0]:
        dec_set_session(r, rows)
    if spres[1]:
        dec_slp_session(r, rows)
    msg, is_ext = r_msg_choice(r, rows)
    rows.append(('message', 'Choice', msg))
    extra = {}
    if is_ext:
        extra = dec_msg_ext(r, msg, rows)
    elif msg == 'msSUPLINIT':
        extra = dec_supl_init(r, rows)
    elif msg == 'msSUPLSTART':
        extra = dec_supl_start(r, rows)
    elif msg == 'msSUPLPOS':
        extra = dec_supl_pos(r, rows)
    else:
        raise Refused('message %s root part is not modelled here' % msg)
    left = r.left()
    if left >= 8:
        raise Refused('%d trailing bits after the message' % left)
    if left and r.u(left) != 0:
        raise Refused('non-zero padding bits after the message')
    return msg, rows, extra


# ------------------------------------------------------------------- CLI ----

DEFAULT_SESSION_ID = '001A'
DEFAULT_SET_DIGITS = '311040213456789'
DEFAULT_SLP_SID = '12345678'
DEFAULT_SLP_FQDN = 'slp.example.com'
DEFAULT_POS_METHOD = 'ecid'
DEFAULT_SLP_MODE = 'proxy'

SET_ID_ROOT = ('msisdn', 'mdn', 'min', 'imsi', 'nai', 'iPAddress')

def bad(msg, why=None):
    sys.stderr.write('ERROR\t%s\n' % msg)
    if why:
        sys.stderr.write('WHY\t%s\n' % why)
    sys.exit(2)

def fail(msg, why):
    sys.stderr.write('ERROR\t%s\n' % msg)
    sys.stderr.write('WHY\t%s\n' % why)
    sys.exit(1)

class Args(object):
    def __init__(self, argv):
        self.pos = []
        self.opts = {}
        self.flags = set()
        i = 0
        while i < len(argv):
            a = argv[i]
            if a.startswith('--'):
                if '=' in a:
                    k, v = a[2:].split('=', 1)
                    if not v:
                        bad('option %s needs a value' % a, 'spell it as %s=<value> or %s <value>' % (a, a))
                    self.opts[k] = v
                elif i + 1 < len(argv) and not argv[i + 1].startswith('--'):
                    self.opts[a[2:]] = argv[i + 1]
                    i += 1
                else:
                    self.flags.add(a[2:])
            else:
                self.pos.append(a)
            i += 1

def get_sid(a):
    raw = a.opts.get('session-id', DEFAULT_SESSION_ID)
    if len(raw) != 4 or any(c not in '0123456789abcdefABCDEF' for c in raw):
        bad('session id is %r, wanted 4 hex digits (2 octets)' % raw,
            'SetSessionID.sessionId is INTEGER (0..65535), so it is exactly 2 octets')
    return int(raw, 16)

def get_setid(a):
    kind = a.opts.get('set-id', 'imsi')
    if kind not in ('imsi', 'msisdn'):
        bad('set id kind is %r' % kind,
            'this build encodes the two SETId alternatives whose digits a network element can check: '
            'imsi (index 3) and msisdn (index 0); mdn/min/nai/iPAddress/ver2-imei are not built')
    digits = a.opts.get('set-digits', DEFAULT_SET_DIGITS)
    if not digits.isdigit():
        bad('set digits are %r, wanted decimal digits' % digits,
            'an imsi/msisdn SETId is 8 octets of TBCD, 15 significant digits padded with F')
    return kind, digits

def get_slp(a):
    sid = a.opts.get('slp-session-id', DEFAULT_SLP_SID)
    if len(sid) != 8 or any(c not in '0123456789abcdefABCDEF' for c in sid):
        bad('slp session id is %r, wanted 8 hex digits (4 octets)' % sid,
            'SlpSessionID.sessionID is OCTET STRING (SIZE(4))')
    if 'slp-ipv4' in a.opts:
        return sid, 'ipv4', a.opts['slp-ipv4']
    return sid, 'fqdn', a.opts.get('slp-fqdn', DEFAULT_SLP_FQDN)

def get_lpps(a):
    if 'lpp' not in a.opts:
        bad('a SUPL POS needs an LPP payload', 'pass it as: --lpp <lpp-hex> (the pdu_hex printed by --forge-position)')
    try:
        data = hex2bytes(a.opts['lpp'])
    except ValueError as e:
        bad('lpp payload is not hexadecimal: %s' % e, 'pass the LPP-Message bytes as hex, no 0x prefix')
    if not (1 <= len(data) <= 60000):
        bad('lpp payload is %d octets' % len(data),
            'PosPayLoad.lPPPayload is OCTET STRING (SIZE(1..60000)); a SUPL POS carries 1..3 of them')
    return [data]

def emit(header, rows):
    sys.stdout.write('\t'.join(header) + '\n')
    for r in rows:
        sys.stdout.write('\t'.join(str(x) for x in r) + '\n')

def cmd_build(msg, a):
    if msg not in ('init', 'start', 'pos', 'setinit'):
        bad('unknown SUPL message %r' % msg,
            'this build encodes SUPL INIT, SUPL START, SUPL POS and SUPL SETINIT; the other UlpMessage alternatives are refused by name')
    sid = get_sid(a)
    kind, digits = get_setid(a)
    try:
        tbcd = tbcd_octets(digits)
    except ValueError as e:
        bad('set digits %r cannot be TBCD encoded: %s' % (digits, e), 'give 15 decimal digits, or fewer with an F pad nibble')
    slp_sid, slp_kind, slp_val = get_slp(a)
    posmethod = a.opts.get('pos-method', DEFAULT_POS_METHOD)
    if posmethod not in POS_METHODS:
        bad('pos method %r is not a root PosMethod alternative' % posmethod,
            'root alternatives: %s; the version 2 additions need a different encoder' % ', '.join(POS_METHODS))
    slpmode = a.opts.get('slp-mode', DEFAULT_SLP_MODE)
    if slpmode not in SLP_MODES:
        bad('slp mode %r is not proxy or nonProxy' % slpmode, 'SLPMode ::= ENUMERATED { proxy, nonProxy }')
    lpps = get_lpps(a) if msg == 'pos' else None
    set_sid = None if msg in ('init', 'setinit') else (sid, kind, digits)
    slp_sid_t = None if msg == 'start' else (slp_sid, slp_kind, slp_val)

    def body(w):
        enc_version(w)
        enc_session(w, set_sid, slp_sid_t)
        if msg == 'init':
            w.b(0); w.u(3, 0)
            enc_suplinit(w, posmethod, slpmode)
        elif msg == 'start':
            w.b(0); w.u(3, 1)
            enc_suplstart(w, ('agpsSETBased', 'ecid', 'otdoa'), 'agpsSETBasedPreferred', ('rrc',),
                          310, 410, 0x1234, 0x5678, 'current')
        elif msg == 'setinit':
            # SUPLINIT carries no target SET id (it is not in its ASN.1);
            # Ver2-SUPLSETINIT is the trigger that does, and it is an
            # extension alternative, so it rides in an open type.
            enc_msg_ext(w, 5, lambda x: enc_ver2_suplsetinit(x, kind, digits))
        else:
            w.b(0); w.u(3, 4)
            enc_suplpos(w, lpps)

    data = build_pdu(body)
    bits = len(data) * 8
    lpp_hex = ' '.join(hex_upper(x) for x in lpps) if lpps else '-'
    name = {'init': 'SUPL INIT', 'start': 'SUPL START', 'pos': 'SUPL POS',
            'setinit': 'SUPL SETINIT'}[msg]
    emit(('message', 'bytes', 'bits', 'hex', 'encoding', 'lpp_payload'),
         ((name, len(data), bits, hex_upper(data), 'UALIGNED PER (X.691 UNALIGNED)', lpp_hex),))
    return 0

def cmd_parse(hexstr, a):
    try:
        msg, rows, extra = dec_ulp(hexstr)
    except Refused as e:
        if LAST_ROWS:
            emit(('field', 'type', 'value'), LAST_ROWS)
        fail('cannot decode this SUPL payload', str(e))
    except ValueError as e:
        fail('cannot decode this SUPL payload', str(e))
    rows = rows + [('lpp_payload', 'OCTET STRING', extra['lpp_payload_hex'])] if extra.get('lpp_payload_hex') else rows
    emit(('field', 'type', 'value'), rows)
    return 0

def cmd_session(a):
    if not a.pos:
        bad('--supl-session needs the SET session id', 'pass the SetSessionID.sessionId as 4 hex digits, e.g. 001a')
    raw = a.pos[0]
    if len(raw) != 4 or any(c not in '0123456789abcdefABCDEF' for c in raw):
        bad('session id is %r, wanted 4 hex digits (2 octets)' % raw,
            'SetSessionID.sessionId is INTEGER (0..65535), so it is exactly 2 octets')
    sid = int(raw, 16)
    kind, digits = get_setid(a)
    try:
        w = BitW(); enc_setid(w, kind, digits)
        setid_hex = hex_upper(w.tobytes())
        w = BitW(); enc_set_session(w, sid, kind, digits)
        sses_hex = hex_upper(w.tobytes())
    except ValueError as e:
        bad('cannot encode this SET id: %s' % e, 'an imsi/msisdn SETId is 8 octets of TBCD, 15 significant digits padded with F')
    idx = SET_ID_ROOT.index(kind)
    emit(('field', 'type', 'value'), (
        ('sessionId', 'INTEGER (0..65535)', str(sid)),
        ('setId', 'Choice', '%s (%d)' % (kind, idx)),
        ('setId.digits', 'TBCD digits', digits),
        ('setId.hex', 'SETId', setid_hex),
        ('setSessionID.hex', 'SetSessionID', sses_hex),
    ))
    return 0

def cmd_pos(a):
    if not a.pos and 'lpp' not in a.opts:
        bad('a SUPL POS needs an LPP payload',
            'pass it as --lpp <hex>; --supl-pos --lpp <hex> is the same build as --supl-build pos')
    if a.pos:
        a.opts.setdefault('lpp', a.pos[0])
    return cmd_build('pos', a)

def main(argv):
    if not argv:
        bad('no verb', 'build <init|start|pos>, parse <hex> or session <id-hex>')
    verb, rest = argv[0], argv[1:]
    if verb in ('-h', '--help', 'help'):
        bad('help was asked for', 'the bash side documents the verbs: --help lists --supl-build, --supl-parse, --supl-session and --supl-pos')
    a = Args(rest)
    if verb == 'build':
        if not a.pos:
            bad('build needs a message name', 'one of init, start, pos')
        return cmd_build(a.pos[0], a)
    if verb == 'parse':
        if not a.pos:
            bad('parse needs the payload hex', 'pass the ULP-PDU bytes as hex, no 0x prefix')
        return cmd_parse(a.pos[0], a)
    if verb == 'session':
        return cmd_session(a)
    if verb == 'pos':
        return cmd_pos(a)
    bad('unknown verb %r' % verb, 'build, parse, session and pos are the only verbs this driver knows')

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
LPP_SUPL_PY
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

# The driver speaks the module output contract itself (TSV header, ERROR/WHY
# on stderr, rc 2 for bad input, rc 1 for "I decoded the envelope but this
# part is out of scope"), so this wrapper only has to make sure it started.
lpp_supl_run() {
    local verb="$1"; shift
    command -v python3 >/dev/null 2>&1 || {
        err "python3 is required for the SUPL verbs (--supl-build/--supl-parse/--supl-session/--supl-pos)"
        return 2
    }
    local py
    py=$(lpp_supl_py) || {
        err "cannot write the SUPL codec under $MOD_TMP"
        return 2
    }
    python3 "$py" "$verb" "$@"
}

lpp_supl_build() {
    local msg="${1:-}"
    case "$msg" in
        '')
            err "usage: --supl-build <init|start|pos|setinit>"
            err "  init    SLP -> SET trigger. Its ASN.1 has NO target SET id."
            err "  start   SET -> SLP: SET capabilities and the cell it is in"
            err "  pos     the LPP carriage, needs the lpp option: --lpp <hex>"
            err "  setinit Ver2-SUPLSETINIT, the trigger that DOES carry a target SET id"
            return 2 ;;
    esac
    shift || true
    lpp_supl_run build "$msg" "$@"
}

lpp_supl_parse() {
    local hex="${1:-}"
    if [[ -z "$hex" ]]; then
        err "usage: --supl-parse <hex>"
        return 2
    fi
    lpp_supl_run parse "$hex"
}

lpp_supl_session() {
    if (($# == 0)); then
        err "usage: --supl-session <id-hex> [--set-id imsi|msisdn] [--set-digits <digits>]"
        err "  <id-hex> is SetSessionID.sessionId (4 hex digits): the part every message repeats"
        return 2
    fi
    lpp_supl_run session "$@"
}

# <hex> or --lpp <hex>: the same build, because the payload is the point.
lpp_supl_pos() {
    local hex=''
    local -a pass=()
    while (($#)); do
        case "$1" in
            --lpp)   hex="${2:-}"; shift 2 || shift ;;
            --lpp=*) hex="${1#--lpp=}"; shift ;;
            *)       pass+=("$1"); shift ;;
        esac
    done
    if [[ -z "$hex" ]]; then
        # --supl-pos <hex> is the same build as --supl-pos --lpp <hex>: the
        # first bare argument is the LPP payload, anything else is an option.
        local -a rest=()
        local a
        for a in ${pass[@]+"${pass[@]}"}; do
            if [[ -z "$hex" && "$a" != --* ]]; then
                hex="$a"
            else
                rest+=("$a")
            fi
        done
        pass=(${rest[@]+"${rest[@]}"})
    fi
    if [[ -z "$hex" ]]; then
        err "usage: --supl-pos <lpp-hex> (or --supl-pos --lpp <lpp-hex>)"
        err "  the LPP-Message bytes ride unchanged in PosPayLoad -> ver2-PosPayLoad-extension -> lPPPayload"
        return 2
    fi
    lpp_supl_run pos --lpp "$hex" "${pass[@]+"${pass[@]}"}"
}

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

# ── LCS — who may ask where a subscriber is ────────────────────────────
# The module owns the positioning protocols (LPP, LPPa, SUPL). This section
# owns the service around them: the request that starts a positioning session,
# what the answer is allowed to contain, and what a pile of answers adds up to.
# The Diameter carriage (SLh, SLg) belongs to the wire layer of 11_lte_core; this
# names the messages and refuses to print octets it cannot referee.

LPP_LCS_CLIENT_TYPES="emergency value-added lawful-intercept plmn-operator"

lpp_lcs_client_type_name() {
    case "${1,,}" in
        emergency)        echo "emergency" ;;
        value-added|value-added-services|vas) echo "value-added" ;;
        lawful-intercept|li) echo "lawful-intercept" ;;
        plmn-operator|operator) echo "plmn-operator" ;;
        *) return 1 ;;
    esac
}

lpp_lcs_location_type_name() {
    case "${1,,}" in
        ecgi|cell)      echo "ecgi" ;;
        tai|tracking-area) echo "tai" ;;
        geo|geographic) echo "geo" ;;
        velocity)       echo "velocity" ;;
        civic)          echo "civic" ;;
        *) return 1 ;;
    esac
}

lpp_lcs_ladder() {
    # location type, what the answer carries, the scale it resolves, and what
    # that scale actually means for whoever asked.
    cat <<'LADDER'
location_type	ecgi	the E-UTRAN cell global identity of the serving cell	cell	six octets of cell id; resolves to a cell, and a cell is 100 m to 2 km in practice
location_type	tai	the tracking area of the serving cell	area	the registration area the subscriber is registered in; km scale, and a rural TA can be tens of km
location_type	geo	latitude and longitude with an accuracy figure	metres	the answer the requester actually wanted; the accuracy field is the network choosing what to admit
location_type	velocity	speed and bearing for the moving subscriber	metres plus a direction	exists so that it can be sampled again: one velocity is a datapoint, two are a track
location_type	civic	a civic address	street	a postal address, which resolves to a building rather than a point
LADDER
}

lpp_cmd_lcs_ladder() {
    local rows n
    rows="$(lpp_lcs_ladder)"
    printf 'spec\tTS 29.172\tSLh and SLg, the Diameter carriage of LCS\n'
    printf 'spec\tTS 29.171\tLCS-AP, the same service over S1 between MME and E-SMLC\n'
    printf 'spec\tTS 23.271\tLCS stage 2: the request, the answer, the privacy check\n'
    printf 'wire\tDiameter\tnot encoded here: 11_lte_core owns the AVP layer (--diameter-peer)\n'
    printf 'wire\tLPP\tpositioning messages are this module (--otdoa-assist, --parse-position)\n'
    n="$(printf '%s\n' "$rows" | grep -c '^location_type')"
    printf 'location_types\t%s\n' "$n"
    printf '%s\n' "$rows"
    printf 'limit\tThe scale column is deployment-dependent: a cell id is not a distance, and an accuracy field is what the network chose to admit.\n'
    printf 'verdict\tlcs_granularity_stated\n'
}

lpp_lcs_entitlement() {
    cat <<'ENT'
client_type	emergency	may ask	yes	no consent, no subscription check, position goes to the PSAP	TS 23.271 9.1.1
client_type	value-added	may ask	yes	commercial service; the client type says commercial and the privacy check is the operator's	TS 23.271 9.1.2
client_type	lawful-intercept	may ask	yes	authorised intercept; the request carries the authorisation and the network does not verify it on the wire	TS 33.107
client_type	plmn-operator	may ask	yes	the operator locating its own subscriber, which is what every handover already does	TS 23.271 9.1
not_entitled	anyone else	may ask	no	there is no authentication of the client on the Diameter hop: a peer that can open a connection is a peer that can ask	TS 29.172 5
ENT
}

lpp_cmd_lcs_entitlement() {
    local rows
    rows="$(lpp_lcs_entitlement)"
    printf 'client_types\t4\n'
    printf '%s\n' "$rows"
    printf 'finding\tclient_type_is_a_declaration\tMEDIUM\tthe client type is a field in the request, not a credential: a peer that labels itself emergency is handled as an emergency\n'
    printf 'finding\tno_client_authentication_on_the_hop\tHIGH\tnothing in a Provide-Location-Request proves the identity of the GMLC that sent it, beyond being able to reach the MME\n'
    printf 'what_the_target_is_told\tnothing\tthe subscriber is not notified, and no message on the air says that a positioning session started\n'
    printf 'ref\tTS 29.172 6.1.3, TS 23.271 9, TS 33.107\n'
    printf 'limit\tEntitlement is a policy the operator configures; this table states the categories the specifications name, not the actual configuration of any operator.\n'
    printf 'verdict\tlcs_entitlement_stated\n'
}

lpp_cmd_lcs_ask() {
    local client="location-services" ctype="value-added" ltype="geo" target="" acc="50" rtime="10"
    while (($# > 0)); do
        case "$1" in
            --client)        client="${2:-}"; shift 2 ;;
            --client-type)   ctype="${2:-}"; shift 2 ;;
            --location-type) ltype="${2:-}"; shift 2 ;;
            --target)        target="${2:-}"; shift 2 ;;
            --accuracy)      acc="${2:-}"; shift 2 ;;
            --response-time) rtime="${2:-}"; shift 2 ;;
            *) warn "unknown option: $1"; return 2 ;;
        esac
    done
    local cn ln
    cn="$(lpp_lcs_client_type_name "$ctype")" || {
        err "unknown client type: $ctype"
        err "WHY	the specifications name four: $LPP_LCS_CLIENT_TYPES"
        return 2
    }
    ln="$(lpp_lcs_location_type_name "$ltype")" || {
        err "unknown location type: $ltype"
        err "WHY	the answer shapes are ecgi, tai, geo, velocity and civic"
        return 2
    }
    [[ "$acc" =~ ^[0-9]+$ ]] || { err "accuracy must be metres, as a number"; return 2; }
    [[ "$rtime" =~ ^[0-9]+$ ]] || { err "response time must be seconds, as a number"; return 2; }
    [[ -z "$target" ]] && target="(not stated)"

    printf 'request\tProvide-Location-Request\tSLg\tTS 29.172 7.3.1\n'
    printf 'client_name\t%s\n' "$client"
    printf 'client_type\t%s\n' "$cn"
    printf 'target_subscriber\t%s\n' "$target"
    printf 'location_type\t%s\n' "$ln"
    printf 'requested_accuracy_m\t%s\n' "$acc"
    printf 'response_time_s\t%s\n' "$rtime"
    lpp_lcs_ladder | awk -F'\t' -v want="$ln" '
        $1 == "location_type" && $2 == want {
            printf "answer_carries\t%s\n", $3
            printf "answer_scale\t%s\n", $4
            printf "answer_meaning\t%s\n", $5
        }'
    printf 'who_is_told\tnobody\n'
    printf 'what_proves_the_client\tnothing: the client name is a string the requester chose\n'
    case "$cn" in
        emergency)
            printf 'privacy_check\tbypassed by the client type\n'
            printf 'finding\temergency_label_skips_the_privacy_check\tHIGH\tthe same request with a different client type would be refused, so the label is the whole control\n' ;;
        value-added)
            printf 'privacy_check\tthe operator is expected to verify consent\n'
            printf 'finding\tcommercial_client_asks_for_geographic_precision\tMEDIUM\tan accuracy of %s m is finer than any service that needs a cell\n' "$acc" ;;
        lawful-intercept)
            printf 'privacy_check\treplaced by an authorisation field\n'
            printf 'finding\tauthorisation_is_an_unverified_field\tHIGH\tthe network checks that the field is present, not that the authorisation exists\n' ;;
        *)
            printf 'privacy_check\tthe operator locating its own subscriber\n' ;;
    esac
    if [[ "$ln" == "velocity" ]]; then
        printf 'finding\tvelocity_exists_to_be_sampled_again\tHIGH\tone velocity is a datapoint and two are a track, and each request looks like a single question\n'
    fi
    printf 'ref\tTS 29.172 6.1.3 and 7.3, TS 23.271 9\n'
    printf 'limit\tThis is what the request says. Whether any node checks it is a configuration question this module cannot observe.\n'
    printf 'verdict\tlcs_request_shaped\n'
}

lpp_cmd_lcs_audit() {
    local file="$1"
    [[ -z "$file" ]] && { warn "usage: --lcs-audit <answers.tsv>"; return 2; }
    [[ -f "$file" ]] || { err "no such file: $file"; return 1; }
    if ! awk -F'\t' 'NF >= 3 { found = 1 } END { exit found ? 0 : 1 }' "$file"; then
        err "no rows with at least three columns: expected client, client_type, location_type, subscriber, accuracy_m, t"
        return 1
    fi
    awk -F'\t' '
        NR == 1 && $1 !~ /^[A-Za-z_]+$/ { next }
        NR == 1 { next }
        NF < 3 { next }
        {
            client = $1; ctype = $2; ltype = $3; tgt = ($4 == "" ? "(unknown)" : $4)
            acc = $5 + 0
            requests++
            seen_client[client] = 1
            seen_sub[tgt] = 1
            per_sub[tgt]++
            if (ltype == "geo" || ltype == "civic") geo++
            if (ltype == "velocity") vel++
            if (ctype == "emergency") emerg++
            if (ctype == "value-added") vas++
            if (ctype == "lawful-intercept") li++
            if (acc > 0) { accsum += acc; accn++; if (accmin == 0 || acc < accmin) accmin = acc }
            pairs[client SUBSEP tgt] = 1
            byclient[client]++
            if (ltype == "geo" && ctype == "value-added") geoprecise[client]++
            if (ltype == "velocity") trackers[client]++
        }
        END {
            nc = 0; for (c in seen_client) nc++
            ns = 0; for (s in seen_sub) ns++
            np = 0; for (p in pairs) np++
            multi = 0
            for (s in per_sub) if (per_sub[s] > 1) { multi++; if (multisub == "") multisub = s }
            printf "answers\t%d\n", requests
            printf "clients\t%d\n", nc
            printf "subscribers\t%d\n", ns
            printf "client_subscriber_pairs\t%d\n", np
            printf "subscribers_located_more_than_once\t%d\n", multi
            if (multi > 0) printf "first_repeated_subscriber\t%s\n", multisub
            printf "geographic_answers\t%d\n", geo
            printf "velocity_answers\t%d\n", vel
            printf "emergency_answers\t%d\n", emerg
            printf "value_added_answers\t%d\n", vas
            printf "lawful_intercept_answers\t%d\n", li
            if (accn > 0) {
                printf "accuracy_m_min\t%d\n", accmin
                printf "accuracy_m_mean\t%.1f\n", accsum / accn
            }
            for (c in byclient) printf "client\t%s\t%d\n", c, byclient[c]
            for (c in geoprecise) {
                printf "finding\tcommercial_geographic_precision\tHIGH\tclient %s asked for a position, not a cell\n", c
            }
            for (c in trackers) {
                printf "finding\tvelocity_requests_are_a_track\tHIGH\tclient %s asked for velocity, which only pays off when repeated\n", c
            }
            if (multi > 0) {
                printf "finding\trepeated_requests_are_a_track\tHIGH\t%s was located %d times; every single answer looks like one question\n", multisub, per_sub[multisub]
            }
            printf "ref\tTS 29.172 7.3, TS 23.271 9\n"
            printf "limit\tThe file is what was logged. A missing privacy check cannot be seen from the answers, only inferred from who asked and what came back.\n"
            printf "verdict\t%s\n", (requests > 0 ? "location_answers_accounted" : "no_answers_in_this_file")
        }' "$file"
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

    # ── SUPL / OMA ULP 2.0: the transport around LPP ──────────────────
    # LPP is the payload; SUPL is the envelope that moves it over TCP 7275.
    # Every literal below is what pycrate produces for the same value (an
    # independent implementation of OMA TS ULP 2.0's ASN.1), and
    # tools/check-supl.sh replays these same octets through tshark 4.2.2's
    # ULP dissector on a real TCP flow. None of it is pinned to this file's
    # own encoder output.
    local s1 s2 s3 sr back reparsed
    s1=$(lpp_supl_build init 2>/dev/null); chk supl-init-rc "$?" 0
    chk supl-init-hex "$(lpp_field "$s1" "SUPL INIT" 4)" \
        0018020000448D159E10EE31D41ABD9B2D71A81A34C80030
    chk supl-init-bytes "$(lpp_field "$s1" "SUPL INIT" 2)" 24
    s2=$(lpp_supl_build start 2>/dev/null); chk supl-start-rc "$?" 0
    chk supl-start-hex "$(lpp_field "$s2" "SUPL START" 4)" \
        001B02000080068C4C0410490D961FE4412A2013666848D159E080
    s3=$(lpp_supl_build pos --lpp D2020028410124FB55FFA544 2>/dev/null); chk supl-pos-rc "$?" 0
    chk supl-pos-hex "$(lpp_field "$s3" "SUPL POS" 4)" \
        0032020000C0068C4C0410490D961FE448D159E10EE31D41ABD9B2D71A81A34C90800F40005E90100142080927DAAFFD2A20
    chk supl-pos-carries "$(lpp_field "$s3" "SUPL POS" 6)" D2020028410124FB55FFA544

    # The composition that is the point: the bytes --supl-parse hands back are
    # the ones --parse-position decodes unchanged. A single wrong bit in the
    # open type or in an lPPPayload length lands here, not in a comment.
    sr=$(lpp_supl_parse "$(lpp_field "$s3" "SUPL POS" 4)" 2>/dev/null); chk supl-parse-rc "$?" 0
    chk supl-parse-message "$(lpp_field "$sr" message 3)" msSUPLPOS
    back=$(lpp_field "$sr" lpp_payload 3)
    chk supl-roundtrip-lpp "$back" D2020028410124FB55FFA544
    reparsed=$(lpp_parse_position "$back" 2>/dev/null)
    chk supl-roundtrip-status "$(lpp_field "$reparsed" status 2)" decoded
    chk supl-roundtrip-shape "$(lpp_field "$reparsed" shape 2)" ellipsoidPoint
    chk supl-roundtrip-lat "$(lpp_field "$reparsed" latitude 2)" 51.5006983
    chk supl-roundtrip-lon "$(lpp_field "$reparsed" longitude 2)" -0.1246047

    # --supl-session prints the two pieces every message repeats, alone.
    sr=$(lpp_supl_session 001a 2>/dev/null); chk supl-session-rc "$?" 0
    chk supl-session-hex "$(lpp_field "$sr" setSessionID.hex 3)" 001A313010412436587F90
    chk supl-setid-hex "$(lpp_field "$sr" setId.hex 3)" 313010412436587F90
    chk supl-setid-digits "$(lpp_field "$sr" setId.digits 3)" 311040213456789
    sr=$(lpp_supl_session 001a --set-id msisdn --set-digits 001010000000001 2>/dev/null)
    chk supl-msisdn-choice "$(lpp_field "$sr" setId 3)" 'msisdn (0)'

    # SUPLINIT's ASN.1 has no target SET id (the message is posMethod,
    # notification/sLPAddress/qoP/mac/keyIdentity, sLPMode); SETINIT is the
    # trigger that does, so the target id is pinned there rather than invented.
    s3=$(lpp_supl_build setinit 2>/dev/null); chk supl-setinit-rc "$?" 0
    chk supl-setinit-hex "$(lpp_field "$s3" "SUPL SETINIT" 4)" \
        0021020000448D159E10EE31D41ABD9B2D71A81A34CA142418980820921B2C3FC8
    sr=$(lpp_supl_parse "$(lpp_field "$s3" "SUPL SETINIT" 4)" 2>/dev/null); chk supl-setinit-parse-rc "$?" 0
    chk supl-setinit-target "$(lpp_field "$sr" msSUPLSETINIT.targetSETID 3)" 'imsi (3)'

    # Refusals are refusals: no invented tags, no silent truncation, no
    # "closest match" for a message this file does not encode.
    chk supl-unknown-message "$(lpp_supl_build foo >/dev/null 2>&1; echo $?)" 2
    chk supl-pos-needs-lpp "$(lpp_supl_build pos >/dev/null 2>&1; echo $?)" 2
    chk supl-parse-short "$(lpp_supl_parse 0018 >/dev/null 2>&1; echo $?)" 1
    chk supl-parse-length-lie \
        "$(lpp_supl_parse 0026020000448D159E10EE31D41ABD9B2D71A81A34C80030 >/dev/null 2>&1; echo $?)" 1
    # A corrupted UlpMessage Choice: the root alternative is now msSUPLEND
    # (index 5), which this file does not encode. It must say so by name.
    chk supl-parse-other-message \
        "$(lpp_supl_parse 0018020000448D159E10EE31D41ABD9B2D71A81A34C94030 >/dev/null 2>&1; echo $?)" 1
    chk supl-parse-other-why \
        "$(lpp_supl_parse 0018020000448D159E10EE31D41ABD9B2D71A81A34C94030 2>&1 >/dev/null | grep -c '^WHY.*msSUPLEND')" 1

    # R65: UTDOA is LPPa, and the contents now encode as octets that round-trip.
    local ub
    ub=$(lpp_utdoa_build 2>/dev/null)
    chk utdoa-build-verdict "$(printf '%s\n' "$ub" | awk -F'\t' '$1=="verdict"{print $2}')" utdoa_encoded_as_lppa
    chk utdoa-build-protocol "$(printf '%s\n' "$ub" | awk -F'\t' '$1=="protocol"{print $2}' | grep -c 'TS 36.455')" 1
    chk utdoa-build-req-hex "$(printf '%s\n' "$ub" | awk -F'\t' '$1=="requested-srs"{print $4}')" 0001f431
    chk utdoa-build-req-octets "$(printf '%s\n' "$ub" | awk -F'\t' '$1=="requested-srs"{print $3}')" 4
    chk utdoa-build-srs-octets "$(printf '%s\n' "$ub" | awk -F'\t' '$1=="srs-cell"{print $3}')" 21
    chk utdoa-build-srs-roundtrip "$(printf '%s\n' "$ub" | awk -F'\t' '$1=="srs-cell"{print $5}')" yes
    chk utdoa-build-req-roundtrip "$(printf '%s\n' "$ub" | awk -F'\t' '$1=="requested-srs"{print $5}')" yes
    chk utdoa-build-bad-bw "$(lpp_utdoa_build --ul-bw n7 >/dev/null 2>&1; echo $?)" 2
    chk utdoa-build-not-lpp "$(printf '%s\n' "$ub" | awk -F'\t' '$1=="protocol" && $2 ~ /not LPP/{print "stated"}')" stated

    # The LCS service around the positioning protocols: the request, what an
    # answer resolves to, and what a log of answers adds up to.
    local lad lea lak laf
    lad=$(lpp_cmd_lcs_ladder 2>/dev/null)
    lea=$(lpp_cmd_lcs_entitlement 2>/dev/null)
    lak=$(lpp_cmd_lcs_ask --client-type emergency --location-type velocity 2>/dev/null)
    chk lcs-ladder-types "$(printf '%s\n' "$lad" | awk -F'\t' '$1=="location_types"{print $2}')" 5
    chk lcs-ladder-geo "$(printf '%s\n' "$lad" | awk -F'\t' '$1=="location_type" && $2=="geo"{print $3}' | grep -c 'latitude')" 1
    chk lcs-ladder-velocity "$(printf '%s\n' "$lad" | awk -F'\t' '$1=="location_type" && $2=="velocity"{print $5}' | grep -c 'sampled again')" 1
    chk lcs-ladder-verdict "$(printf '%s\n' "$lad" | awk -F'\t' '$1=="verdict"{print $2}')" lcs_granularity_stated
    chk lcs-ladder-nooctets "$(printf '%s\n' "$lad" | awk -F'\t' '$1=="wire" && $2=="Diameter"{print $3}' | grep -c 'not encoded here')" 1
    chk lcs-entitlement-rows "$(printf '%s\n' "$lea" | grep -c '^client_type	')" 4
    chk lcs-entitlement-noauth "$(printf '%s\n' "$lea" | awk -F'\t' '$1=="finding" && $2=="no_client_authentication_on_the_hop"{print $3}')" HIGH
    chk lcs-entitlement-told "$(printf '%s\n' "$lea" | awk -F'\t' '$1=="what_the_target_is_told"{print $2}')" nothing
    chk lcs-ask-client "$(printf '%s\n' "$lak" | awk -F'\t' '$1=="client_type"{print $2}')" emergency
    chk lcs-ask-carries "$(printf '%s\n' "$lak" | awk -F'\t' '$1=="answer_carries"{print $2}' | grep -c 'speed and bearing')" 1
    chk lcs-ask-emergency-finding "$(printf '%s\n' "$lak" | awk -F'\t' '$1=="finding" && $2=="emergency_label_skips_the_privacy_check"{print $3}')" HIGH
    chk lcs-ask-velocity-finding "$(printf '%s\n' "$lak" | awk -F'\t' '$1=="finding" && $2=="velocity_exists_to_be_sampled_again"{print $3}')" HIGH
    chk lcs-ask-verdict "$(printf '%s\n' "$lak" | awk -F'\t' '$1=="verdict"{print $2}')" lcs_request_shaped
    chk lcs-ask-bad-client "$(lpp_cmd_lcs_ask --client-type wizard >/dev/null 2>&1; echo $?)" 2
    chk lcs-ask-bad-type "$(lpp_cmd_lcs_ask --location-type streetview >/dev/null 2>&1; echo $?)" 2
    chk lcs-ask-bad-acc "$(lpp_cmd_lcs_ask --accuracy fine >/dev/null 2>&1; echo $?)" 2
    laf="$(mktemp)"
    printf 'client\tclient_type\tlocation_type\tsubscriber\taccuracy_m\tt\n' > "$laf"
    printf 'weather-app\tvalue-added\tgeo\t310150123456789\t25\t2026-02-01T10:00:00Z\n' >> "$laf"
    printf 'psap\temergency\tgeo\t310150123456789\t50\t2026-02-01T10:04:00Z\n' >> "$laf"
    printf 'fleet\tvalue-added\tvelocity\t310150123456789\t100\t2026-02-01T10:05:00Z\n' >> "$laf"
    printf 'mno\tplmn-operator\tecgi\t310150987654321\t0\t2026-02-01T10:06:00Z\n' >> "$laf"
    lak=$(lpp_cmd_lcs_audit "$laf" 2>/dev/null)
    chk lcs-audit-answers "$(printf '%s\n' "$lak" | awk -F'\t' '$1=="answers"{print $2}')" 4
    chk lcs-audit-clients "$(printf '%s\n' "$lak" | awk -F'\t' '$1=="clients"{print $2}')" 4
    chk lcs-audit-subs "$(printf '%s\n' "$lak" | awk -F'\t' '$1=="subscribers"{print $2}')" 2
    chk lcs-audit-repeat "$(printf '%s\n' "$lak" | awk -F'\t' '$1=="subscribers_located_more_than_once"{print $2}')" 1
    chk lcs-audit-repeat-id "$(printf '%s\n' "$lak" | awk -F'\t' '$1=="first_repeated_subscriber"{print $2}')" 310150123456789
    chk lcs-audit-min "$(printf '%s\n' "$lak" | awk -F'\t' '$1=="accuracy_m_min"{print $2}')" 25
    chk lcs-audit-geo "$(printf '%s\n' "$lak" | awk -F'\t' '$1=="geographic_answers"{print $2}')" 2
    chk lcs-audit-vas "$(printf '%s\n' "$lak" | awk -F'\t' '$1=="value_added_answers"{print $2}')" 2
    chk lcs-audit-track "$(printf '%s\n' "$lak" | awk -F'\t' '$1=="finding" && $2=="repeated_requests_are_a_track"{print $3}')" HIGH
    chk lcs-audit-precision "$(printf '%s\n' "$lak" | awk -F'\t' '$1=="finding" && $2=="commercial_geographic_precision"{print $3}')" HIGH
    chk lcs-audit-verdict "$(printf '%s\n' "$lak" | awk -F'\t' '$1=="verdict"{print $2}')" location_answers_accounted
    chk lcs-audit-noarg "$(lpp_cmd_lcs_audit >/dev/null 2>&1; echo $?)" 2
    chk lcs-audit-nofile "$(lpp_cmd_lcs_audit /tmp/definitely-not-here-lcs.tsv >/dev/null 2>&1; echo $?)" 1
    rm -f "$laf"
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
  [11] Build a SUPL INIT (the SLP -> SET trigger, ULP over TCP 7275)
  [12] Build a SUPL START (SET capabilities + the cell it is in)
  [13] Build a SUPL POS carrying an LPP payload
  [14] Parse a SUPL INIT / START / POS
  [15] Encode the SET session id / SET id on their own
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
            11)
                lpp_supl_build init; read -rp "  press enter " _ ;;
            12)
                lpp_supl_build start; read -rp "  press enter " _ ;;
            13)
                read -rp "  LPP-Message hex (the pdu_hex --forge-position prints)> " h
                read -rp "  SetSessionID.sessionId hex [001a]> " s
                lpp_supl_pos --lpp "${h:-D2020028410124FB55FFA544}" --session-id "${s:-001A}"
                read -rp "  press enter " _ ;;
            14)
                read -rp "  ULP-PDU hex> " h
                lpp_supl_parse "$h"; read -rp "  press enter " _ ;;
            15)
                read -rp "  SetSessionID.sessionId hex [001a]> " s
                read -rp "  set id kind imsi|msisdn [imsi]> " k
                lpp_supl_session "${s:-001A}" --set-id "${k:-imsi}"
                read -rp "  press enter " _ ;;
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
        --utdoa-build)   lpp_utdoa_build "$@" ;;
        --prs-plan)      lpp_prs_plan "$@" ;;
        --supl-build)    lpp_supl_build    "$@" ;;
        --supl-parse)    lpp_supl_parse    "$@" ;;
        --supl-session)  lpp_supl_session  "$@" ;;
        --supl-pos)      lpp_supl_pos      "$@" ;;
        --lcs-ladder)    lpp_cmd_lcs_ladder ;;
        --lcs-entitlement) lpp_cmd_lcs_entitlement ;;
        --lcs-ask)       lpp_cmd_lcs_ask "$@" ;;
        --lcs-audit)     lpp_cmd_lcs_audit "${1:-}" ;;
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
  --supl-build <init|start|pos|setinit>
                       build the OMA ULP envelope around LPP (TCP 7275):
                       init is the SLP->SET trigger, start the SET's
                       capabilities, pos the carriage that holds an LPP
                       payload, setinit the trigger with a target SET id
  --supl-parse <hex>   decode a SUPL message: one field per line, with
                       its ASN.1 type (Choice / Sequence / Enumerated)
  --supl-session <id-hex>
                       encode the SET session id and SET id on their own
  --supl-pos <lpp-hex> build the SUPL POS that carries this LPP payload
                       (the long form passes the payload as the lpp option)
  --lcs-ladder         what each location answer shape resolves to, cell,
                       tracking area, position, velocity, civic address
  --lcs-entitlement    who may ask for a position and what the target is told
  --lcs-ask            state one Provide-Location-Request: the client, its
                       declared type, the target and the accuracy asked for,
                       then what that answer would actually reveal
  --lcs-audit <tsv>    account for a log of location answers: who asked, for
                       whom, how precisely, and who has been located twice
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
