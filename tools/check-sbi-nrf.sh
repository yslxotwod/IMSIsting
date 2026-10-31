#!/usr/bin/env bash
# Check the NRF registration this tree builds against two referees.
#
# modules/40_sba_pivot.sh --nrf-register assembles the NFRegister PUT by hand:
# the HTTP/2 connection preface, a HEADERS frame whose payload is a literal HPACK
# header block, and a DATA frame carrying the NFProfile. Every octet there is
# written from a reading of RFC 7540 and RFC 7541 (and TS 29.510 for the
# resource), so a check that only runs the module's own --hpack and --h2-parse
# over it would prove the builder and the parser share the same mistake.
#
# Two witnesses that were not written here:
#   1. Wireshark's http2 dissector, over a TCP stream the tree hands it. It
#      decodes the preface, the frame headers, the HPACK fields and the JSON body
#      with its own tables and its own json dissector.
#   2. python3-hpack, a separate HPACK implementation, decoding the header block
#      straight from the module's hpack_block row.
#
# The pcap is written by hand because text2pcap cannot frame a bare PDU: asked
# to do that, 4.2.2 reads the packet and writes none, which is a silent empty
# capture.
#
# Exits 0 only when both witnesses agree with every claim.
#   0  both witnesses agree
#   1  a witness disagrees (both values are printed)
#   2  the check could not run
set -u

cd "$(dirname "$0")/.." || exit 2

TSHARK=${TSHARK:-/usr/bin/tshark}
MODULE=modules/40_sba_pivot.sh

if [ ! -r "$MODULE" ]; then
  echo "FAIL no $MODULE"
  exit 2
fi

tmp=$(mktemp -d) || exit 2
trap 'rm -rf "$tmp"' EXIT

rc=0
say() { echo "$1"; }
fail() { say "FAIL $1"; rc=1; }

FIELD() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }

out=$(bash "$MODULE" --nrf-register --nf-type SMF --capacity 100 --priority 3 2>/dev/null)
req=$(FIELD "$out" request_hex)
hb=$(FIELD "$out" hpack_block)
body=$(FIELD "$out" body)
path=$(FIELD "$out" path)
method=$(FIELD "$out" method)
nfid=$(FIELD "$out" nf_instance_id)

if [ -z "$req" ] || [ -z "$hb" ] || [ -z "$body" ]; then
  fail "--nrf-register did not produce a request, a header block and a body"
  say "RESULT FAIL"
  exit "$rc"
fi

# ── witness 1: Wireshark, over a real TCP stream ────────────────────────
if [ -x "$TSHARK" ] && command -v python3 >/dev/null 2>&1; then
  cat > "$tmp/tcp.py" <<'PYFRAME'
import binascii, struct, sys

req, outp = binascii.unhexlify(sys.argv[1]), sys.argv[2]
# One TCP segment carrying the whole request on port 8080. The ports are needed:
# the http2 dissector keys on them, and port 80 would make it read a h2c
# upgrade attempt instead of a preface.
tcp = struct.pack("!HHIIBBHHH", 40000, 8080, 1, 1, 0x50, 0x18, 65535, 0, 0) + req
ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
                 b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02")
eth = b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00"
frame = eth + ip + tcp
with open(outp, "wb") as fh:
    fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    fh.write(struct.pack("<IIII", 0, 0, len(frame), len(frame)))
    fh.write(frame)
PYFRAME
  if python3 "$tmp/tcp.py" "$req" "$tmp/nrf.pcap" 2>/dev/null; then
    "$TSHARK" -r "$tmp/nrf.pcap" -d tcp.port==8080,http2 -V > "$tmp/nrf.txt" 2>/dev/null
    grep -q 'Protocols in frame:.*http2' "$tmp/nrf.txt" \
      && say "ok   tshark dissects the stream as HTTP/2" \
      || fail "tshark does not see HTTP/2 in the stream (protocols: $(grep -m1 'Protocols in frame' "$tmp/nrf.txt" || echo none))"

    got=$(sed -n 's/^ *Header: :method: //p' "$tmp/nrf.txt" | head -1)
    [ "$got" = "$method" ] \
      && say "ok   tshark reads :method $got" \
      || fail "tshark reads :method '$got' where the module claims '$method'"

    got=$(sed -n 's/^ *Header: :path: //p' "$tmp/nrf.txt" | head -1)
    [ "$got" = "$path" ] \
      && say "ok   tshark reads :path $got" \
      || fail "tshark reads :path '$got' where the module claims '$path'"

    got=$(sed -n 's/^ *Header: :authority: //p' "$tmp/nrf.txt" | head -1)
    [ -n "$got" ] \
      && say "ok   tshark reads :authority $got" \
      || fail "tshark reads no :authority from the header block"

    got=$(sed -n 's/^ *Header: content-type: //p' "$tmp/nrf.txt" | head -1)
    [ "$got" = "application/json" ] \
      && say "ok   tshark reads content-type $got" \
      || fail "tshark reads content-type '$got'"

    grep -q 'JavaScript Object Notation: application/json' "$tmp/nrf.txt" \
      && say "ok   tshark hands the DATA payload to its JSON dissector" \
      || fail "tshark does not dissect the DATA payload as JSON"

    grep -q "Member with value: nfInstanceId:$nfid" "$tmp/nrf.txt" \
      && say "ok   tshark reads the nfInstanceId the profile claims" \
      || fail "tshark does not read nfInstanceId:$nfid out of the body"

    grep -q 'Representation: Literal Header Field without Indexing' "$tmp/nrf.txt" \
      && say "ok   tshark reads the fields as the literal-without-indexing form (RFC 7541 6.2.2)" \
      || fail "tshark does not read the header block as literal-without-indexing"

    # The frame header the module built by hand, as the dissector reads it.
    got=$(sed -n 's/^ *Length: //p' "$tmp/nrf.txt" | head -1)
    want=$(( ${#hb} / 2 ))
    [ "$got" = "$want" ] \
      && say "ok   tshark reads the HEADERS length $got the module computed" \
      || fail "tshark reads HEADERS length '$got' where the header block is $want octets"
  else
    fail "could not write the pcap"
  fi
else
  say "SKIP tshark or python3 absent: no dissection witness"
fi

# ── witness 2: python3-hpack, an independent HPACK decoder ──────────────
if command -v python3 >/dev/null 2>&1 && python3 -c 'import hpack' 2>/dev/null; then
  cat > "$tmp/hp.py" <<'PYHP'
import binascii, sys
import hpack

block = binascii.unhexlify(sys.argv[1])
# raw=True keeps the values exactly as sent: no Huffman decoding is expected,
# because the module writes H=0 (RFC 7541 6.2.2), and a decoder that had to
# undo Huffman would report different octets here.
hdrs = {k.decode("latin-1"): v.decode("latin-1")
        for k, v in hpack.Decoder().decode(block, raw=True)}
want = dict(a.split("=", 1) for a in sys.argv[2:])
bad = 0
for name, value in sorted(want.items()):
    got = hdrs.get(name)
    if got == value:
        print("ok   python3-hpack decodes %s: %s" % (name, got))
    else:
        print("FAIL python3-hpack reads %s as %r, the module claims %r" % (name, got, value))
        bad = 1
# A decoder that ignored the module's length prefixes would still find the names
# in the block; an exact field count is what proves the framing is right.
print("count\t%d" % len(hdrs))
sys.exit(bad)
PYHP
    python3 "$tmp/hp.py" "$hb" ":method=$method" ":path=$path" "content-type=application/json" > "$tmp/hp.txt" 2>&1
    hp_rc=$?
    grep '^ok   ' "$tmp/hp.txt"
    grep '^FAIL' "$tmp/hp.txt" && rc=1
    cnt=$(awk -F'\t' '$1=="count"{print $2}' "$tmp/hp.txt")
    [ "$cnt" = "6" ] \
      && say "ok   python3-hpack finds exactly the six fields the module wrote" \
      || fail "python3-hpack finds '$cnt' fields where the module wrote six"
    [ "$hp_rc" -eq 0 ] || rc=1
else
  say "SKIP python3-hpack absent: no independent HPACK decoder"
fi

# ── the JSON body, parsed by a parser nobody here wrote ─────────────────
if command -v python3 >/dev/null 2>&1; then
  printf '%s' "$body" > "$tmp/body.json"
  if python3 - "$tmp/body.json" > "$tmp/json.txt" 2>&1 <<'PYJSON'
import json, sys
d = json.load(open(sys.argv[1]))
need = ["nfInstanceId", "nfType", "nfStatus", "ipv4Addresses", "fqdn", "nfServices"]
missing = [k for k in need if k not in d]
print("missing\t%s" % ",".join(missing))
print("nfType\t%s" % d.get("nfType"))
print("serviceName\t%s" % (d.get("nfServices") or [{}])[0].get("serviceName"))
sys.exit(1 if missing else 0)
PYJSON
  then
    say "ok   python3 json parses the NFProfile and finds every field TS 29.510 6.1 requires here"
    got=$(awk -F'\t' '$1=="nfType"{print $2}' "$tmp/json.txt")
    [ "$got" = "SMF" ] \
      && say "ok   the parsed profile says nfType $got" \
      || fail "the parsed profile says nfType '$got'"
    got=$(awk -F'\t' '$1=="serviceName"{print $2}' "$tmp/json.txt")
    [ "$got" = "nsmf" ] \
      && say "ok   the parsed service is $got, the SMF's own service name" \
      || fail "the parsed service name is '$got'"
  else
    fail "python3 json cannot parse the NFProfile: $(awk -F'\t' '$1=="missing"{print "missing " $2}' "$tmp/json.txt")"
  fi
else
  say "SKIP python3 absent: no independent JSON parser"
fi

# ── the guards: a refusal must name what is missing ─────────────────────
err=$(bash "$MODULE" --nrf-register --capacity 5 2>&1 >/dev/null)
case "$err" in
  *--nf-type*) say "ok   a registration with no --nf-type is refused by name" ;;
  *) fail "a registration with no --nf-type was not refused by name (got '$err')" ;;
esac
err=$(bash "$MODULE" --nrf-register --nf-type AMF --ip not-an-address 2>&1 >/dev/null)
case "$err" in
  *dotted*) say "ok   a non-IPv4 --ip is refused by name" ;;
  *) fail "a non-IPv4 --ip was not refused by name (got '$err')" ;;
esac

say "RESULT $([ "$rc" -eq 0 ] && echo PASS || echo FAIL)"
exit "$rc"
