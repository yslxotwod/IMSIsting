#!/usr/bin/env bash
# Check the SLg Provide-Location-Request this tree builds against a referee.
#
# The message is assembled from AVP codes typed out of TS 29.172, and a code
# typed one digit wrong produces a message that is still well-formed: the
# Diameter header parses, the length adds up, and the AVP walk lists the names
# the builder gave them. Every one of those checks compares the builder against
# itself. Wireshark's diameter dissector carries the same registry, so the only
# question it cannot answer by agreeing with us is whether the octets on the
# wire are the AVPs the standard defines.
#
# Exits 0 only when tshark decodes the built message as a PLR with the
# application id, command code and AVP set this tree claims.
#   0  tshark agrees
#   1  tshark disagrees (a mismatch is printed with both values)
#   2  the check could not run
set -u

cd "$(dirname "$0")/.." || exit 2

TSHARK=${TSHARK:-/usr/bin/tshark}
MODULE=modules/11_lte_core.sh

if [ ! -x "$TSHARK" ]; then
  echo "SKIP no tshark at $TSHARK"
  exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "SKIP no python3 to build the frame with"
  exit 0
fi
if [ ! -r "$MODULE" ]; then
  echo "FAIL no $MODULE"
  exit 2
fi

tmp=$(mktemp -d) || exit 2
trap 'rm -rf "$tmp"' EXIT

out=$(bash "$MODULE" --plr 310150123456789 2>/dev/null)
hex=$(printf '%s\n' "$out" | awk -F'\t' '$1=="hex"{print $2}')
claimed_app=$(printf '%s\n' "$out" | awk -F'\t' '$1=="application_id"{print $2}')
claimed_cmd=$(printf '%s\n' "$out" | awk -F'\t' '$1=="command_code"{print $2}')
claimed_avps=$(printf '%s\n' "$out" | awk -F'\t' '$1=="avp_names"{print $2}')

if [ -z "$hex" ]; then
  echo "FAIL the module built no message; --plr printed:"
  printf '%s\n' "$out" | sed 's/^/     /'
  exit 2
fi

# The frame is built here rather than with text2pcap: given a bare Diameter PDU
# and -T, text2pcap 4.2.2 reads the packet and writes none, which is a silent
# empty capture. One Ethernet/IPv4/TCP frame with real checksums is a dozen
# lines and gives the dissector exactly one thing to decode.
if ! python3 - "$hex" "$tmp/plr.pcap" <<'PYFRAME'
import binascii, struct, sys

hexs, outp = sys.argv[1], sys.argv[2]
payload = binascii.unhexlify(hexs)


def csum(b):
    if len(b) % 2:
        b += b"\0"
    total = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


eth = bytes.fromhex("001122334455") + bytes.fromhex("66778899aabb") + b"\x08\x00"
src, dst = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
tcp = struct.pack("!HHIIBBHHH", 40000, 3868, 1, 1, 5 << 4, 0x18, 8192, 0, 0) + payload
pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp))
tcp = tcp[:16] + struct.pack("!H", csum(pseudo + tcp)) + tcp[18:]
ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, src, dst)
ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
frame = eth + ip + tcp
with open(outp, "wb") as fh:
    fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    fh.write(struct.pack("<IIII", 0, 0, len(frame), len(frame)))
    fh.write(frame)
PYFRAME
then
  echo "FAIL could not build the capture from the module's hex"
  exit 2
fi

d=$(mktemp -d) || exit 2
"$TSHARK" -r "$tmp/plr.pcap" -d tcp.port==3868,diameter -V > "$tmp/dissect.txt" 2>/dev/null
if [ ! -s "$tmp/dissect.txt" ]; then
  echo "FAIL tshark produced no dissection"
  exit 2
fi

# tshark prints the numbers inside parentheses: "ApplicationId: 3GPP SLg
# (16777255)" and "Command Code: 3GPP-Provide-Location (8388620)". The number is
# what the standard pins down; the name is the dissector's own label.
got_app=$(sed -n 's/^ *ApplicationId:.*(\([0-9]*\)).*/\1/p' "$tmp/dissect.txt" | head -1)
got_cmd=$(sed -n 's/^ *Command Code:.*(\([0-9]*\)).*/\1/p' "$tmp/dissect.txt" | head -1)
got_name=$(sed -n 's/^ *Command Code: *//p' "$tmp/dissect.txt" | head -1 | sed 's/ *(.*//; s/ *$//')

rc=0
say() { echo "$1"; }

if [ -z "$got_app" ] || [ -z "$got_cmd" ]; then
  say "FAIL tshark did not decode the message as Diameter"
  say "     header lines it did print:"
  sed -n '1,12p' "$tmp/dissect.txt" | sed 's/^/     /'
  exit 1
fi

if [ "$got_app" != "$claimed_app" ]; then
  say "FAIL application id: the tree claims $claimed_app, tshark reads $got_app"
  rc=1
else
  say "ok   application id $got_app (the tree's claim)"
fi

if [ "$got_cmd" != "$claimed_cmd" ]; then
  say "FAIL command code: the tree claims $claimed_cmd, tshark reads $got_cmd"
  rc=1
elif [ -n "$got_name" ] && [ "$got_name" != "Provide-Location-Request" ] \
        && [ "$got_name" != "3GPP-Provide-Location" ]; then
  say "FAIL command $got_cmd is '$got_name' to tshark, not a Provide-Location request"
  rc=1
else
  say "ok   command code $got_cmd ${got_name:+($got_name)}"
fi

# The AVP names are the part a wrong code breaks silently: the builder names an
# AVP from its own table, so the only independent witness is the dissector.
# Compared case-insensitively, and deliberately so: TS 29.172 names the AVP
# "SLg-Location-Type" and the dissector prints "Slg-Location-Type". Capitalisation
# is not on the wire, so a case difference is reported as a note and never as a
# disagreement -- what matters is whether the octets resolve to that AVP at all.
sed -n 's/^ *AVP: \([^(]*\)(.*/\1/p' "$tmp/dissect.txt" \
  | sed 's/ *$//' | sort -u > "$tmp/tshark_exact.txt"
tr 'A-Z' 'a-z' < "$tmp/tshark_exact.txt" | sort -u > "$tmp/tshark_avps.txt"
printf '%s\n' "$claimed_avps" | tr ' ' '\n' | sed '/^$/d' | sort -u > "$tmp/claim_exact.txt"
tr 'A-Z' 'a-z' < "$tmp/claim_exact.txt" | sort -u > "$tmp/claim_avps.txt"

missing=$(comm -23 "$tmp/claim_avps.txt" "$tmp/tshark_avps.txt")
if [ -n "$missing" ]; then
  say "FAIL tshark does not see these AVPs the tree claims:"
  printf '%s\n' "$missing" | sed 's/^/     /'
  say "     tshark saw: $(tr '\n' ' ' < "$tmp/tshark_avps.txt")"
  rc=1
else
  say "ok   all $(wc -l < "$tmp/claim_avps.txt") claimed AVP name(s) decoded by tshark"
  # Where the spelling differs only in case, say so once: a reader comparing the
  # two lists by eye should not conclude the tree has a typo.
  caseonly=$(diff <(tr 'A-Z' 'a-z' < "$tmp/claim_exact.txt") "$tmp/claim_exact.txt" \
             | sed -n 's/^> //p' | tr '\n' ' ')
  for name in $caseonly; do
    low=$(printf '%s' "$name" | tr 'A-Z' 'a-z')
    other=$(grep -i -x -m1 "$low" "$tmp/tshark_exact.txt" 2>/dev/null || true)
    [ -n "$other" ] && [ "$other" != "$name" ] \
      && say "note the tree spells it $name; tshark spells it $other"
  done
fi

# The converse is reported, never asserted: the dissector names a few AVPs of
# its own (grouped framing, vendor) that the claim never made.
extra=$(comm -13 "$tmp/claim_avps.txt" "$tmp/tshark_avps.txt" | tr '\n' ' ')
[ -n "$extra" ] && say "note tshark also names: $extra"

if [ "$rc" -eq 0 ]; then
  say "RESULT PASS"
else
  say "RESULT FAIL"
fi
exit "$rc"
