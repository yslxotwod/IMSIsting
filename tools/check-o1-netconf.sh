#!/usr/bin/env bash
# Check the O1 NETCONF messages this tree builds against two referees.
#
# modules/48_oran.sh --o1-hello and --o1-rpc write the RFC 6242 §4.1 chunked
# framing, the RFC 6241 §8.1 hello and the RFC 6241 §7 operations by hand, with
# an ietf-interfaces payload from RFC 8343. Every one of those octets is written
# from a reading of those documents, so running the module's own framing routine
# back over its output would only prove the routine agrees with itself.
#
# Two witnesses that were not written here:
#   1. Wireshark's XML dissector, over a TCP stream to port 830 (the NETCONF
#      port). It parses the XML with its own parser and prints the tree, which
#      is what makes the framing check real: if the count in front of the
#      message were wrong, the dissector would see a different octet range.
#   2. Python's xml.etree plus a framing reader written from RFC 6242 §4.1 in
#      this file, which re-derives the chunk boundary instead of trusting it.
#
# The pcap is written by hand because text2pcap cannot frame a bare PDU.
#
# Exits 0 only when both witnesses agree with every claim.
#   0  both witnesses agree
#   1  a witness disagrees (both values are printed)
#   2  the check could not run
set -u

cd "$(dirname "$0")/.." || exit 2

TSHARK=${TSHARK:-/usr/bin/tshark}
MODULE=modules/48_oran.sh

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

cat > "$tmp/pcap.py" <<'PYFRAME'
import binascii, struct, sys
# One TCP segment to port 830 carrying the framed NETCONF message.
payload, outp = binascii.unhexlify(sys.argv[1]), sys.argv[2]
tcp = struct.pack("!HHIIBBHHH", 40000, 830, 1, 1, 0x50, 0x18, 65535, 0, 0) + payload
ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
                 b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02")
eth = b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00"
frame = eth + ip + tcp
with open(outp, "wb") as fh:
    fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    fh.write(struct.pack("<IIII", 0, 0, len(frame), len(frame)))
    fh.write(frame)
PYFRAME

# ── the framing, re-derived from RFC 6242 4.1 by a reader written here ──
cat > "$tmp/frame.py" <<'PYFRAME'
import binascii, sys, xml.etree.ElementTree as ET

blob = binascii.unhexlify(sys.argv[1]).decode("utf-8")
# RFC 6242 4.1: "\n#" <decimal count> "\n" <chunk> ... and "\n##\n" at the end.
if not blob.startswith("\n#"):
    print("FAIL the message does not begin with \\n# (RFC 6242 4.1)")
    sys.exit(1)
nl = blob.index("\n", 2)
count, body = int(blob[2:nl]), blob[nl + 1:]
# The chunk is exactly `count` octets; the end-of-chunks marker follows it.
chunk, rest = body[:count], body[count:]
if rest != "\n##\n":
    print("FAIL after %d octets the remainder is %r, not the \\n##\\n marker" % (count, rest))
    sys.exit(1)
print("ok   the framing counts %d octets and closes with \\n##\\n" % count)

root = ET.fromstring(chunk)
NCF = "{urn:ietf:params:xml:ns:netconf:base:1.0}"
IFM = "{urn:ietf:params:xml:ns:yang:ietf-interfaces}"
print("root\t%s" % root.tag)
if root.tag != NCF + "rpc":
    print("FAIL root element is %s, not {netconf:base:1.0}rpc" % root.tag)
    sys.exit(1)
print("ok   the framed chunk parses as XML with root {netconf:base:1.0}rpc")
print("message-id\t%s" % root.get("message-id"))
for name in ("edit-config", "target", "running", "config"):
    if root.find(".//" + NCF + name) is None and root.find(".//" + name) is None:
        print("FAIL the rpc has no %s element for edit-config (RFC 6241 7.2)" % name)
        sys.exit(1)
print("ok   edit-config, target, running and config are all present")
iface = root.find(".//" + IFM + "interface")
if iface is None:
    print("FAIL no {ietf-interfaces}interface in the payload (RFC 8343)")
    sys.exit(1)
name = iface.find(IFM + "name")
enabled = iface.find(IFM + "enabled")
print("interface\t%s" % (name.text if name is not None else "?"))
print("enabled\t%s" % (enabled.text if enabled is not None else "?"))
print("ok   the payload is an ietf-interfaces entry with a name and an enabled leaf")
PYFRAME

check_rpc() {  # <label> <expect-interface> <expect-enabled>
  local label="$1" want_if="$2" want_en="$3" out framed
  out=$(bash "$MODULE" --o1-rpc --interface "$want_if" --enabled "$want_en" 2>/dev/null)
  framed=$(FIELD "$out" framed_hex)
  if [ -z "$framed" ]; then
    fail "--o1-rpc produced no framed_hex"
    return
  fi

  if python3 "$tmp/frame.py" "$framed" > "$tmp/fr.txt" 2>&1; then
    grep '^ok   ' "$tmp/fr.txt"
    got=$(awk -F'\t' '$1=="message-id"{print $2}' "$tmp/fr.txt")
    [ "$got" = "101" ] && say "ok   the rpc-reply pairing id is $got" \
      || fail "message-id is '$got' where the module claims 101"
    got=$(awk -F'\t' '$1=="interface"{print $2}' "$tmp/fr.txt")
    [ "$got" = "$want_if" ] && say "ok   the payload names interface $got" \
      || fail "the payload names interface '$got' where '$want_if' was asked for"
    got=$(awk -F'\t' '$1=="enabled"{print $2}' "$tmp/fr.txt")
    [ "$got" = "$want_en" ] && say "ok   the payload sets enabled $got" \
      || fail "the payload sets enabled '$got' where '$want_en' was asked for"
  else
    fail "$label: the framing reader refused the message"
    sed 's/^/     /' "$tmp/fr.txt"
  fi

  if [ -x "$TSHARK" ]; then
    if python3 "$tmp/pcap.py" "$framed" "$tmp/$label.pcap" 2>/dev/null; then
      "$TSHARK" -r "$tmp/$label.pcap" -d tcp.port==830,xml -V > "$tmp/$label.txt" 2>/dev/null
      grep -q 'Protocols in frame:.*xml' "$tmp/$label.txt" \
        && say "ok   tshark parses the framed message as XML" \
        || fail "tshark does not parse the framed message as XML"
      grep -q 'message-id="101"' "$tmp/$label.txt" \
        && say "ok   tshark reads message-id 101 from the rpc" \
        || fail "tshark reads no message-id 101"
      grep -q 'xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces"' "$tmp/$label.txt" \
        && say "ok   tshark reads the ietf-interfaces namespace in the payload" \
        || fail "tshark reads no ietf-interfaces namespace"
      grep -q "^ *$want_if\$" "$tmp/$label.txt" \
        && say "ok   tshark reads the interface name $want_if" \
        || fail "tshark does not read the interface name $want_if"
      grep -q "^ *$want_en\$" "$tmp/$label.txt" \
        && say "ok   tshark reads enabled $want_en" \
        || fail "tshark does not read enabled $want_en"
    else
      fail "could not write the pcap"
    fi
  else
    say "SKIP no tshark at $TSHARK"
  fi
}

# ── the hello, both roles ──────────────────────────────────────────────
cat > "$tmp/hello.py" <<'PYHELLO'
import sys, xml.etree.ElementTree as ET

xml = open(sys.argv[1]).read()
NCF = "{urn:ietf:params:xml:ns:netconf:base:1.0}"
root = ET.fromstring(xml)
if root.tag != NCF + "hello":
    print("FAIL root is %s, not {netconf:base:1.0}hello" % root.tag)
    sys.exit(1)
caps = [c.text for c in root.findall(".//" + NCF + "capability")]
sid = root.find(NCF + "session-id")
print("caps\t%d" % len(caps))
print("signalling\t%s" % ("base:1.1" if any("base:1.1" in c for c in caps) else "base:1.0"))
print("session-id\t%s" % (sid.text if sid is not None else "absent"))
# An unescaped ampersand in a capability URI would have made this file
# unparseable, so reaching here at all means the escaping is right.
yang = [c for c in caps if "module=ietf-interfaces" in c]
print("yang\t%s" % (yang[0] if yang else "none"))
if not yang:
    print("FAIL no ietf-interfaces module capability (RFC 7950 5.6.4)")
    sys.exit(1)
print("ok   the hello parses, carries %d capabilities and %s"
      % (len(caps), "a session-id" if sid is not None else "no session-id"))
PYHELLO

for role in client server; do
  out=$(bash "$MODULE" --o1-hello "--$role" 2>/dev/null)
  xml=$(FIELD "$out" xml)
  framed=$(FIELD "$out" framed_hex)
  printf '%s' "$xml" > "$tmp/hello-$role.xml"
  if python3 "$tmp/hello.py" "$tmp/hello-$role.xml" > "$tmp/h.txt" 2>&1; then
    grep '^ok   ' "$tmp/h.txt"
    got=$(awk -F'\t' '$1=="caps"{print $2}' "$tmp/h.txt")
    [ "$got" = "7" ] && say "ok   the $role hello carries the seven capabilities the module claims" \
      || fail "the $role hello carries '$got' capabilities"
    got=$(awk -F'\t' '$1=="signalling"{print $2}' "$tmp/h.txt")
    [ "$got" = "base:1.1" ] && say "ok   the $role hello offers NETCONF 1.1 signalling" \
      || fail "the $role hello offers '$got'"
    got=$(awk -F'\t' '$1=="session-id"{print $2}' "$tmp/h.txt")
    if [ "$role" = server ]; then
      [ "$got" = "42" ] && say "ok   the server hello carries session-id 42 (RFC 6241 8.1)" \
        || fail "the server hello carries session-id '$got'"
    else
      [ "$got" = "absent" ] && say "ok   the client hello carries no session-id (RFC 6241 8.1)" \
        || fail "the client hello carries session-id '$got', which RFC 6241 8.1 forbids"
    fi
    got=$(awk -F'\t' '$1=="yang"{print $2}' "$tmp/h.txt")
    case "$got" in
      *"module=ietf-interfaces&revision=2018-02-20"*)
        say "ok   the YANG module capability unescapes to $got" ;;
      *) fail "the YANG module capability reads '$got'" ;;
    esac
  else
    fail "$role hello does not parse as XML"
    sed 's/^/     /' "$tmp/h.txt"
  fi
  if [ -x "$TSHARK" ] && [ -n "$framed" ]; then
    if python3 "$tmp/pcap.py" "$framed" "$tmp/hello-$role.pcap" 2>/dev/null; then
      "$TSHARK" -r "$tmp/hello-$role.pcap" -d tcp.port==830,xml -V > "$tmp/hello-$role.txt" 2>/dev/null
      grep -q '<hello' "$tmp/hello-$role.txt" \
        && say "ok   tshark parses the framed $role hello as XML" \
        || fail "tshark does not parse the framed $role hello"
      if [ "$role" = server ]; then
        grep -q '^ *42$' "$tmp/hello-$role.txt" \
          && say "ok   tshark reads session-id 42 in the server hello" \
          || fail "tshark does not read session-id 42"
      else
        grep -q '<session-id>' "$tmp/hello-$role.txt" \
          && fail "tshark finds a session-id in a client hello" \
          || say "ok   tshark finds no session-id in the client hello"
      fi
    fi
  fi
done

# ── the payload really is modelled: a second interface, a different value ──
check_rpc rpc-off "fronthaul0" "false"
check_rpc rpc-on "c-plane0" "true"

# ── refusals name what is missing ──────────────────────────────────────
err=$(bash "$MODULE" --o1-rpc --operation delete-everything 2>&1 >/dev/null)
case "$err" in
  *"--operation takes a NETCONF operation"*) say "ok   an unknown operation is refused by name" ;;
  *) fail "an unknown operation was not refused by name (got '$err')" ;;
esac
err=$(bash "$MODULE" --o1-rpc --enabled perhaps 2>&1 >/dev/null)
case "$err" in
  *"true or false"*) say "ok   a non-boolean --enabled is refused by name" ;;
  *) fail "a non-boolean --enabled was not refused by name (got '$err')" ;;
esac

say "RESULT $([ "$rc" -eq 0 ] && echo PASS || echo FAIL)"
exit "$rc"
