#!/usr/bin/env bash
# tools/check-ss7-map.sh — grade the MAP answers this tree builds against
# outside implementations, instead of against our own decoder.
#
# Three lanes, each with its own oracle, each skipping rather than passing when
# its oracle is absent:
#
#   pycrate   the MAP ASN.1 from the 3GPP module, encoded and decoded by an
#             implementation that was generated from the standard. This is the
#             lane that can referee a *response* body.
#   tshark    the transport: MTP3 -> SCCP -> TCAP -> gsm_map over link type 141.
#             It names the transaction portion and the component, which is the
#             layer where a dialogue is really two messages or not.
#   osmo-stp  a real Signalling Transfer Point (Osmocom) that accepts an ASP over
#             M3UA/SCTP. It proves the association layer, not MAP: OsmoHLR speaks
#             GSUP, not MAP, so nothing in Osmocom answers an SRI.
#
# WHY tshark is not enough on its own, recorded here because it cost an hour:
# Wireshark's gsm_map table resolves opCode 22 to sendRoutingInfo in BOTH
# directions, so inside a returnResult it expects the request's msisdn and calls
# a correct SendRoutingInfoRes malformed. Probed with three shapes, all rejected
# the same way. pycrate agrees with TS 29.002 17.4.1 and with our octets.
#
# Exit: 0 pass, 1 fail, 2 skip (no oracle present at all). A skip is never a
# pass. TSV on stdout; SKIP lines on stderr.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODULE="$ROOT/modules/26_ss7_map.sh"
ORACLE_PY="${LTE_ORACLE_PY:-/home/ysl/.lte-oracles/venv/bin/python}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/ss7map.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

nchk=0; nfail=0; nskip=0
chk() { local n="$1" got="$2" want="$3"; nchk=$((nchk+1))
        if [[ "$got" == "$want" ]]; then printf 'ok\t%s\n' "$n"
        else printf 'FAIL\t%s\twant=%s\tgot=%s\n' "$n" "$want" "$got"; nfail=$((nfail+1)); fi; }
skip() { nskip=$((nskip+1)); printf 'SKIP\t%s\t%s\n' "$1" "$2" >&2; }

hex_of() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

# The answer under test: an SRI ack carrying one IMSI and one roaming number.
RESP="$("$MODULE" --build-response sri-ack --imsi 310150123456789 \
        --msc 310150987654321 --otid 00000001 2>/dev/null)"
PARAM="$(hex_of "$RESP" parameter)"
TCAP="$(hex_of "$RESP" hex)"
WANT_PARAM="A315890813100521436587F904099113100589674523F1"

chk param-built   "$PARAM" "$WANT_PARAM"
chk tcap-wrapped  "$(printf '%s' "$TCAP" | cut -c1-2)" "64"

# ── lane 1: pycrate, the only oracle that can judge a response body ──────
if [[ -x "$ORACLE_PY" ]]; then
    out=$("$ORACLE_PY" - "$PARAM" <<'PY'
import sys
from pycrate_asn1dir import TCAP_MAP as T
r = T.MAP_CH_DataTypes.SendRoutingInfoRes
given = bytes.fromhex(sys.argv[1])
val = {"imsi": bytes.fromhex("13100521436587F9"),
       "extendedRoutingInfo": ("routingInfo", ("roamingNumber", bytes.fromhex("9113100589674523F1")))}
r.set_val(val)
print("encode\t%s" % r.to_ber().hex().upper())
r2 = T.MAP_CH_DataTypes.SendRoutingInfoRes
r2.from_ber(given)
v = r2.get_val()
print("imsi\t%s" % v["imsi"].hex().upper())
print("roaming\t%s" % v["extendedRoutingInfo"][1][1].hex().upper())
PY
) || { printf 'FAIL\tpycrate-lane\tcould not run\n'; nfail=$((nfail+1)); }
    chk pycrate-encode   "$(grep -P '^encode\t' <<<"$out" | cut -f2)"   "$WANT_PARAM"
    chk pycrate-decode-imsi "$(grep -P '^imsi\t' <<<"$out" | cut -f2)"  "13100521436587F9"
    chk pycrate-decode-addr "$(grep -P '^roaming\t' <<<"$out" | cut -f2)" "9113100589674523F1"
else
    skip pycrate "$ORACLE_PY not present"
fi

# ── lane 2: tshark, the transport and the TCAP component ────────────────
if command -v tshark >/dev/null 2>&1; then
    MSU="$(hex_of "$("$MODULE" --build-response sri-ack --imsi 310150123456789 \
                     --msc 310150987654321 --otid 00000001 --wrap msu 2>/dev/null)" msu_hex)"
    python3 - "$MSU" "$WORK/frame.pcap" <<'PY'
import struct, sys
msu = bytes.fromhex(sys.argv[1])
with open(sys.argv[2], "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 141))
    f.write(struct.pack("<IIII", 1, 0, len(msu), len(msu)))
    f.write(msu)
PY
    dump=$(tshark -r "$WORK/frame.pcap" -V 2>/dev/null)
    chk tshark-stack     "$(grep -c 'mtp3:sccp:tcap:gsm_map' <<<"$dump")" "1"
    chk tshark-component "$(grep -c 'Component: returnResultLast' <<<"$dump")" "1"
    chk tshark-invoke    "$(grep -c 'invokeID: 1' <<<"$dump")" "1"
    chk tshark-opcode    "$(grep -c 'localValue: sendRoutingInfo (22)' <<<"$dump")" "1"
else
    skip tshark "tshark is not on PATH"
fi

# ── lane 3: osmo-stp, a real STP accepting an ASP over M3UA ──────────────
if command -v osmo-stp >/dev/null 2>&1; then
    cfg="$WORK/stp.cfg"
    {
        printf 'log stderr\n'
        printf 'logging level set-all error\n'
        printf 'line vty\n no login\n'
        printf 'cs7 instance 0\n'
        printf ' xua rkm routing-key-allocation dynamic-permitted\n'
        printf ' listen m3ua 2905\n'
        printf '  accept-asp-connections dynamic-permitted\n'
    } > "$cfg"
    osmo-stp -c "$cfg" >"$WORK/stp.log" 2>&1 &
    stp_pid=$!
    for _ in $(seq 1 40); do
        (exec 3<>/dev/tcp/127.0.0.1/2905) 2>/dev/null && { exec 3<&-; exec 3>&-; break; }
        sleep 0.1
    done
    if (exec 3<>/dev/tcp/127.0.0.1/2905) 2>/dev/null; then
        exec 3<&-; exec 3>&-
        chk osmo-stp-listening "yes" "yes"
        # Our side of the association: the module speaks M3UA over SCTP.
        sent=$(MAP_ARMED=1 timeout 20 "$MODULE" --m3ua-send 127.0.0.1 2905 2>&1 || true)
        chk osmo-asp-sent "$(grep -c '^status' <<<"$sent")" "1"
    else
        skip osmo-stp "the STP did not open 2905"
    fi
    kill "$stp_pid" 2>/dev/null; wait "$stp_pid" 2>/dev/null
else
    skip osmo-stp "osmo-stp is not on PATH (apt install osmo-stp)"
fi

# ── dialogue pairing ────────────────────────────────────────────────────
REQ="$(hex_of "$("$MODULE" --build-sri 310150123456789 2>/dev/null)" hex)"
d1=$("$MODULE" --dialogue "$REQ" "$TCAP" 2>/dev/null || true)
chk dialogue-complete "$(hex_of "$d1" verdict)" "complete"
BAD="$(printf '%s' "$TCAP" | sed 's/490400000001/490400000009/')"
d2=$("$MODULE" --dialogue "$REQ" "$BAD" 2>/dev/null || true)
chk dialogue-mismatch "$(hex_of "$d2" verdict)" "mismatched"

printf 'CHECKS\t%d\nFAILED\t%d\nSKIPPED\t%d\n' "$nchk" "$nfail" "$nskip"
if (( nfail > 0 )); then printf 'RESULT\tFAIL\n'; exit 1; fi
if (( nskip == 3 )); then printf 'RESULT\tSKIP\n'; exit 2; fi
printf 'RESULT\tPASS\n'
