#!/usr/bin/env bash
# tools/check-supl.sh -- verify the SUPL / OMA ULP messages that
# modules/46_lpp.sh builds against an outside implementation: tshark 4.2.2's
# ULP dissector, on a real TCP flow to port 7275 (the IANA assignment for
# oma-ulp). This is the same shape as tools/check-nas-vectors.sh: the module's
# own CLI produces the bytes, a third party reads them, and only the third
# party's reading is under test.
#
# The claim under test is not "the module agrees with itself". It is that the
# ULP-PDU this tree writes is the PDU a third-party dissector reads back as
# msSUPLINIT / msSUPLSTART / msSUPLPOS / msSUPLSETINIT, with the session id,
# SET id, cell and position the module said it wrote -- and, for the
# composition that matters, that the LPP bytes --supl-parse hands back are the
# bytes tshark dissects as LPP inside that same SUPL POS. tshark prints the
# carried octets itself (`lPPPayload item: ...`), so the round trip is
# compared against tshark's reading, not against another copy of our encoder.
#
# Negation controls: a suite that only ever sees correct bytes cannot tell a
# decoder from a rubber stamp.
#   - a corrupted UlpMessage Choice tag must be reported as undecodable, not
#     as the message that was built;
#   - a ULP-PDU length field that lies must make tshark stop calling the bytes
#     ULP at all (`TCP segment data`, no ULP section), and 46_lpp.sh must
#     refuse it too.
#
# Exit codes: 0 every vector and control agrees, 1 a mismatch, 2 SKIP because
# python3 or tshark is absent. A skip is never reported as PASS: the summary
# line says SKIP and the exit code is 2. (Wireshark has had the ULP dissector
# for years; a missing tshark is a missing oracle, not a passing test.)
set -uo pipefail

ROOT=$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PY="${PYTHON:-python3}"

command -v "$PY" >/dev/null 2>&1 || {
    printf 'SKIP\tno %s on PATH, so the checker cannot build the vectors\n' "$PY"
    exit 2
}
command -v tshark >/dev/null 2>&1 || {
    printf 'SKIP\ttshark is not on PATH, so no outside implementation can read the built ULP-PDUs\n'
    exit 2
}

tmp=$(mktemp -d "${TMPDIR:-/tmp}/check-supl.XXXXXX") || {
    printf 'FAIL\tcould not make a temporary directory\n'
    exit 1
}
trap 'rm -rf "$tmp"' EXIT

cat > "$tmp/check_supl_built.py" <<'CHECK_SUPL_PY'
#!/usr/bin/env python3
"""Read the ULP-PDUs 46_lpp.sh builds with tshark's ULP dissector.

Every vector is produced by the module's own CLI, wrapped in a TCP segment to
port 7275 inside a synthetic Ethernet/IPv4 frame, and handed to
`tshark -r f.pcap -V`. What tshark decodes is compared with the message name
and values the module said it was building.
"""

import os
import re
import socket
import struct
import subprocess
import sys
import tempfile

ROOT = sys.argv[1]
MODULE = os.path.join(ROOT, 'modules', '46_lpp.sh')
TMPDIR = tempfile.mkdtemp(prefix='check-supl-')

LPP = 'D2020028410124FB55FFA544'

# id, module argv, message the module says it built, strings tshark must show
CASES = [
    ('supl-init', ['--supl-build', 'init'], 'SUPL INIT', [
        'OMA UserPlane Location Protocol',
        'length: 24',
        'message: msSUPLINIT (0)',
        'sessionID: 12345678',
        'slpId: fqdn (1)',
        'fqdn: slp.example.com',
        'posMethod: ecid (6)',
        'sLPMode: proxy (0)',
    ]),
    ('supl-start', ['--supl-build', 'start'], 'SUPL START', [
        'OMA UserPlane Location Protocol',
        'length: 27',
        'setId: imsi (3)',
        'imsi: 13010412436587f9',
        'IMSI: 311040213456789',
        'message: msSUPLSTART (1)',
        'prefMethod: agpsSETBasedPreferred (1)',
        'refMCC: 310',
        'refMNC: 410',
        'refLAC: 4660',
        'refCI: 22136',
        'status: current (1)',
    ]),
    ('supl-pos', ['--supl-build', 'pos', '--lpp', LPP], 'SUPL POS', [
        'OMA UserPlane Location Protocol',
        'length: 50',
        'sessionId: 26',
        'sessionID: 12345678',
        'message: msSUPLPOS (4)',
        'posPayLoad: ver2-PosPayLoad-extension (3)',
        'lPPPayload: 1 item',
        'LTE Positioning Protocol (LPP)',
        'degreesLatitude: 51.500704 degrees (4800213)',
        'degreesLongitude: -0.124605 degrees (-5807)',
    ]),
    ('supl-setinit', ['--supl-build', 'setinit'], 'SUPL SETINIT', [
        'OMA UserPlane Location Protocol',
        'length: 33',
        'message: msSUPLSETINIT (13)',
        'targetSETID: imsi (3)',
        'IMSI: 311040213456789',
    ]),
]

# A Choice tag corrupted to an extension alternative no dissector can name:
# tshark must say so instead of decoding the message that was built.
CORRUPT_CHOICE = '0018020000448D159E10EE31D41ABD9B2D71A81A34CAFC30'
# The same message with a ULP-PDU length field that lies (0x26 for 24 octets).
CORRUPT_LENGTH = '0026020000448D159E10EE31D41ABD9B2D71A81A34C80030'


def run_module(*args):
    r = subprocess.run(['bash', MODULE, *args], capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr


def field(out, name, col):
    """Value of `name` from a TSV output, header row or not.

    --supl-build and --supl-parse print a header row; --parse-position does
    not, so every line is considered and the header is simply never a match.
    """
    for line in out.splitlines():
        r = line.split('\t')
        if r and r[0] == name and len(r) > col:
            return r[col]
    return None


def pcap(payload, path):
    """One Ethernet/IPv4/TCP frame, destination port 7275, carrying the ULP-PDU."""
    eth = bytes.fromhex('00112233445566778899aabb') + b'\x08\x00'
    src = socket.inet_aton('10.0.0.1')
    dst = socket.inet_aton('10.0.0.2')
    tcp = struct.pack('!HHIIBBHHH', 50000, 7275, 1, 0, 5 << 4, 0x18, 8192, 0, 0)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload),
                     1, 0x4000, 64, 6, 0, src, dst)
    frame = eth + ip + tcp + payload
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        f.write(struct.pack('<IIII', 0, 0, len(frame), len(frame)))
        f.write(frame)
    return path


def dissect(hexstr, ident):
    path = pcap(bytes.fromhex(hexstr), os.path.join(TMPDIR, ident + '.pcap'))
    r = subprocess.run(['tshark', '-r', path, '-V'], capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr


def main():
    bad = 0
    ok_vectors = 0
    ok_controls = 0

    if not os.path.isfile(MODULE):
        print('FAIL\tmodule not found: %s' % MODULE)
        return 1

    for ident, argv, claim, needles in CASES:
        rc, out, err = run_module(*argv)
        if rc != 0:
            print('FAIL\t%s\tbuild rc=%d %s' % (ident, rc, err.strip()[:120]))
            bad += 1
            continue
        said = field(out, claim, 0)
        hexstr = field(out, claim, 3)
        if not hexstr or not re.fullmatch(r'[0-9A-Fa-f]+', hexstr):
            print('FAIL\t%s\tno hex column in: %s' % (ident, out.strip()[:120]))
            bad += 1
            continue
        trc, tout, terr = dissect(hexstr, ident)
        if trc != 0:
            print('FAIL\t%s\ttshark rc=%d %s' % (ident, trc, terr.strip()[:120]))
            bad += 1
            continue
        missing = [n for n in needles if n not in tout]
        malformed = 'Malformed Packet' in tout
        if missing or malformed:
            print('FAIL\t%s\tmodule said %s (%d bytes); tshark did not read it as that: '
                  'missing=%s malformed=%s'
                  % (ident, said, len(hexstr) // 2, missing, malformed))
            bad += 1
            continue
        print('ok\t%s\t%s\t%d bytes\t%s'
              % (ident, said, len(hexstr) // 2,
                 [n for n in needles if 'message:' in n][0].strip()))
        ok_vectors += 1

    # The composition that is the point: SUPL POS carries an LPP-Message, and
    # the bytes --supl-parse hands back must be the bytes tshark read as LPP.
    rc, out, err = run_module('--supl-pos', '--lpp', LPP)
    pos_hex = field(out, 'SUPL POS', 3) if rc == 0 else None
    if rc != 0 or not pos_hex:
        print('FAIL\tsupl-pos-composition\t--supl-pos --lpp rc=%d %s' % (rc, err.strip()[:120]))
        bad += 1
    else:
        trc, tout, terr = dissect(pos_hex, 'supl-pos-roundtrip')
        carried = re.search(r'lPPPayload item: ([0-9A-Fa-f]+)', tout)
        prc, pout, perr = run_module('--supl-parse', pos_hex)
        back = field(pout, 'lpp_payload', 2) if prc == 0 else None
        lrc, lout, lerr = run_module('--parse-position', back or '')
        redecoded = field(lout, 'status', 1) if lrc == 0 else None
        lat = field(lout, 'latitude', 1) if lrc == 0 else None
        problems = []
        if prc != 0:
            problems.append('--supl-parse rc=%d %s' % (prc, perr.strip()[:80]))
        if not back:
            problems.append('no lpp_payload column came back')
        elif back.upper() != LPP.upper():
            problems.append('handed back %s, not %s' % (back, LPP))
        if not carried:
            problems.append('tshark printed no lPPPayload item')
        elif back and carried.group(1).upper() != back.upper():
            problems.append('tshark read %s as the payload, module handed back %s'
                            % (carried.group(1), back))
        if redecoded != 'decoded':
            problems.append('--parse-position status=%s' % redecoded)
        if lat != '51.5006983':
            problems.append('--parse-position latitude=%s' % lat)
        if problems:
            print('FAIL\tsupl-pos-composition\t%s' % '; '.join(problems))
            bad += 1
        else:
            print('ok\tsupl-pos-composition\tLPP %s in, LPP %s out, tshark read %s, '
                  'degreesLatitude 4800213 -> %s'
                  % (LPP, back, carried.group(1), lat))
            ok_vectors += 1

    # Negation 1: the Choice tag is corrupted, so no dissector can name the
    # message. tshark must report it undecodable and must NOT call it the
    # message that was built; the module must refuse it with a WHY.
    trc, tout, terr = dissect(CORRUPT_CHOICE, 'corrupt-choice')
    mrc, mout, merr = run_module('--supl-parse', CORRUPT_CHOICE)
    problems = []
    if 'Undecoded' not in tout:
        problems.append('tshark did not flag the tag as Undecoded')
    if 'Choice no. 63' not in tout:
        problems.append('tshark did not name the bad choice index')
    if 'msSUPLINIT' in tout:
        problems.append('tshark still called the corrupted PDU msSUPLINIT')
    if mrc != 1:
        problems.append('module rc=%d, wanted 1' % mrc)
    if not re.search(r'^WHY\t', merr, re.M):
        problems.append('module printed no WHY')
    if problems:
        print('FAIL\tnegation-choice\t%s' % '; '.join(problems))
        bad += 1
    else:
        print('ok\tnegation-choice\tcorrupted Choice tag: tshark Undecoded '
              '("Choice no. 63 in extension"), not msSUPLINIT; 46_lpp.sh refused rc 1')
        ok_controls += 1

    # Negation 2: the ULP-PDU length field lies, so the octets are not a ULP
    # PDU at all -- tshark must fall back to "TCP segment data" with no ULP
    # section, and the module must refuse the length too.
    trc, tout, terr = dissect(CORRUPT_LENGTH, 'corrupt-length')
    mrc, mout, merr = run_module('--supl-parse', CORRUPT_LENGTH)
    problems = []
    if 'OMA UserPlane Location Protocol' in tout:
        problems.append('tshark still dissected it as ULP')
    if 'TCP segment data' not in tout:
        problems.append('tshark did not fall back to plain TCP data')
    if mrc != 1:
        problems.append('module rc=%d, wanted 1' % mrc)
    if problems:
        print('FAIL\tnegation-length\t%s' % '; '.join(problems))
        bad += 1
    else:
        print('ok\tnegation-length\tlength field lies: tshark reports TCP segment data, '
              'no ULP; 46_lpp.sh refused rc 1')
        ok_controls += 1

    print('checked\t%d of %d ULP vectors, %d of 2 negation controls'
          % (ok_vectors, len(CASES) + 1, ok_controls))
    print('RESULT\t%s' % ('PASS' if bad == 0 else 'FAIL(%d)' % bad))
    return 0 if bad == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
CHECK_SUPL_PY

"$PY" "$tmp/check_supl_built.py" "$ROOT"
rc=$?
case "$rc" in
    0|1|2) exit "$rc" ;;
    *) printf 'FAIL\tchecker exited %d\n' "$rc"; exit 1 ;;
esac
