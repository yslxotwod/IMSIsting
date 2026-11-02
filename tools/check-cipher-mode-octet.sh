#!/usr/bin/env bash
# Does the Cipher Mode Setting octet this tree builds mean what tshark says it
# means?
#
# `modules/07_gsm_attack.sh` builds the CIPHERING MODE COMMAND and maps each
# algorithm onto a wire value with gatk_alg_wire_code(). A mapping is exactly
# the kind of table that is right until someone "tidies" it, and the failure is
# silent: a command that switches on the wrong cipher looks like a command.
#
# So the octet is put in front of a dissector that does not share the table.
# GSMTAP over UDP 4729 is the carrier, because Wireshark decodes gsm_a only
# behind a GSMTAP header with a channel type; the frame is built byte for byte
# here rather than with text2pcap, which on this machine reads a plain hex file
# as zero packets.
#
# Exit: 0 agree, 1 disagree, 2 could not run.
set -u

TSHARK=${TSHARK:-/usr/bin/tshark}
if [[ ! -x "$TSHARK" ]]; then
    printf 'skip\tno tshark at %s\n' "$TSHARK"
    exit 2
fi

mod="$(cd -P "$(dirname "$0")/.." && pwd)/modules/07_gsm_attack.sh"
[[ -f "$mod" ]] || { printf 'skip\tno %s\n' "$mod"; exit 2; }

# gatk_alg_wire_code is a pure function with no dependencies, so it is lifted
# out of the module rather than the whole module being sourced (which would run
# its banner and set up directories).
wire_code_src=$(awk '/^gatk_alg_wire_code\(\) \{/,/^\}/' "$mod")
[[ -n "$wire_code_src" ]] || { printf 'skip\tcould not read gatk_alg_wire_code\n'; exit 2; }
eval "$wire_code_src"

tmp=$(mktemp -d) || exit 2
trap 'rm -rf "$tmp"' EXIT

bad=0
note=0

python3 - "$tmp" <<'PY'
import binascii
import os
import struct
import sys

out = sys.argv[1]


def csum(buf):
    s = 0
    for i in range(0, len(buf), 2):
        s += buf[i] << 8 | (buf[i + 1] if i + 1 < len(buf) else 0)
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def eth_ip_udp(payload):
    udp = struct.pack('>HHHH', 4729, 4729, 8 + len(payload), 0) + payload
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                      bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    ip = hdr[:10] + struct.pack('>H', csum(hdr)) + hdr[12:]
    eth = bytes([0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2, 0x08, 0x00])
    return eth + ip + udp


def gsmtap(payload):
    # version 2, header length 4 words, GSM Um, timeslot 0, ARFCN 1,
    # signal 0 dBm, snr 0 dB, frame number 0, channel type SDCCH, antenna 0,
    # sub-slot 0, reserved.
    return (bytes([0x02, 0x04, 0x01, 0x00]) + struct.pack('>H', 1) +
            bytes([0, 0]) + struct.pack('>I', 0) + bytes([0x06, 0, 0, 0]) +
            payload)


def pcap(path, payload):
    hdr = struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    rec = struct.pack('<IIII', 0, 0, len(payload), len(payload))
    open(path, 'wb').write(hdr + rec + payload)


def frame(l3):
    # LAPDm UI on SAPI 0: address 0x03, control 0x03, length octet = L3 length
    # shifted left by two (bits 7-2 are the length), then the L3 message and a
    # fill octet to keep the frame an even number of bytes.
    lapdm = bytes([0x03, 0x03, (len(l3) << 2) & 0xFF]) + l3
    if len(lapdm) % 2:
        lapdm += b'\x2b'
    return eth_ip_udp(gsmtap(lapdm))


# The four-octet form: protocol discriminator 06, message type 35, the cipher
# mode setting octet, then the cipher mode response octet.
for cms in range(0x00, 0x10):
    pcap(os.path.join(out, 'cm_%02x.pcap' % cms),
         frame(bytes([0x06, 0x35, cms, 0x04])))
# The three-octet form, which is the only way to say "no ciphering at all".
pcap(os.path.join(out, 'cm_sc0.pcap'), frame(bytes([0x06, 0x35, 0x00])))
raise SystemExit(0)
PY
[[ $? -eq 0 ]] || { printf 'skip\tcould not build the frames\n'; exit 2; }

# What tshark calls the algorithm for a given octet, as the integer it prints
# in parentheses; empty when the octet carries no algorithm at all.
alg_of() {
    local f="$1"
    "$TSHARK" -r "$f" -V 2>/dev/null \
        | awk '/Algorithm identifier:/{ if (match($0, /A5\/[0-7]/)) {
                   print substr($0, RSTART + 3, 1); exit } }'
}

index_of() {
    local f="$1"
    "$TSHARK" -r "$f" -V 2>/dev/null \
        | awk '/SC: /{ if (match($0, /SC: [^\n]*/)) { print } exit }'
}

# ── the mapping itself ──────────────────────────────────────────────────
for n in 1 2 3 4 5 6 7; do
    alg="A5/$n"
    code=$(gatk_alg_wire_code "$alg") || {
        printf 'FAIL\tno wire code for %s\n' "$alg"; bad=$((bad + 1)); continue; }
    cms=$(( (code << 1) | 1 ))
    hex=$(printf '%02x' "$cms")
    got=$(alg_of "$tmp/cm_$hex.pcap")
    if [[ -z "$got" ]]; then
        printf 'FAIL\ttshark read no algorithm from octet %s (tree says %s)\n' \
            "$hex" "$alg"
        bad=$((bad + 1))
    elif [[ "$got" == "$n" ]]; then
        printf 'ok\tct=0x%s\ttree %s\ttshark A5/%s\n' "$hex" "$alg" "$got"
    else
        printf 'FAIL\tct=0x%s\ttree %s\ttshark A5/%s\n' "$hex" "$alg" "$got"
        bad=$((bad + 1))
    fi
done

# ── and the octet that has no algorithm ─────────────────────────────────
# A5/0 shares an index with A5/1 in gatk_alg_wire_code, which is why the
# builder refuses it by name. This checks that the refusal is aimed at the
# right thing: 0x00 really is "no ciphering" to a dissector, and it really does
# arrive without a cipher mode response octet.
sc0=$(index_of "$tmp/cm_sc0.pcap")
if printf '%s' "$sc0" | grep -qi 'no ciphering'; then
    printf 'ok\tsc=0x00\ttshark: %s\n' "$(printf '%s' "$sc0" | sed 's/^ *//')"
else
    printf 'FAIL\tsc=0x00\ttshark did not read "no ciphering": %s\n' "${sc0:-<nothing>}"
    bad=$((bad + 1))
fi
coll=$(gatk_alg_wire_code A5/0)
if [[ "$coll" == "$(gatk_alg_wire_code A5/1)" ]]; then
    printf 'note\tA5/0 and A5/1 share wire code %s, so the builder must refuse A5/0\n' "$coll"
    note=$((note + 1))
else
    printf 'FAIL\tA5/0 no longer collides with A5/1 (%s vs %s) -- re-check the refusal\n' \
        "$coll" "$(gatk_alg_wire_code A5/1)"
    bad=$((bad + 1))
fi

if [[ $bad -eq 0 ]]; then
    printf 'RESULT\tPASS\t%d algorithm(s) agree, 1 note\n' 7
    exit 0
fi
printf 'RESULT\tFAIL\t%d disagreement(s)\n' "$bad"
exit 1
