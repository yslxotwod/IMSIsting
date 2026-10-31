#!/usr/bin/env bash
# Check the SCCP messages this tree builds against a referee.
#
# modules/26_ss7_map.sh assembles SCCP unitdata by hand: the message type octet,
# the three pointers, the called and calling party addresses and the data
# parameter. Every one of those values is written from a reading of ITU-T Q.713
# (and the 3GPP TS 48.006 profile of it), so a check that compares the builder
# with the parser only proves the two share the same misunderstanding. The same
# is true of the TCAP decapsulation: --sccp-parse reports what it thinks it
# unwrapped.
#
# Wireshark's sccp and tcap dissectors carry the same field layout, so tshark is
# an independent witness. The frames are built here (Ethernet/IPv4/SCTP/M3UA)
# because text2pcap cannot frame a bare PDU: asked to do that, 4.2.2 reads the
# packet and writes none, which is a silent empty capture.
#
# Exits 0 only when tshark decodes every built message as the SCCP message the
# tree claims, with the point codes, SSNs, data length and TCAP tag the tree
# claims.
#   0  tshark agrees with every claim
#   1  tshark disagrees (both values are printed)
#   2  the check could not run
set -u

cd "$(dirname "$0")/.." || exit 2

TSHARK=${TSHARK:-/usr/bin/tshark}
MODULE=modules/26_ss7_map.sh

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

# m3ua_pcap <msu-hex> <out.pcap>: Ethernet / IPv4 / SCTP / M3UA DATA carrying the
# MTP3 message. M3UA DATA is class 1 (Transfer), type 1 (RFC 4666 3.3.1); its
# Protocol Data parameter (tag 0x0200) is where the MTP3 routing label lives, so
# the MSU the module built is passed through untouched.
cat > "$tmp/frame.py" <<'PYFRAME'
import binascii, struct, sys

# DLT_MTP3 (libpcap linktype 141). The whole frame is the MTP3 message the module
# built -- service information octet, routing label, SCCP -- which is exactly what
# --msu-dpc/--msu-opc put in front of the SCCP bytes. An Ethernet/SCTP/M3UA frame
# was tried first and dropped: Wireshark 4.2.2 decodes the M3UA DATA header but
# leaves the protocol data undissected without a routing-key preference, which
# would have made this referee skip the layer it is here to check. Linktype 141
# needs no preferences at all and puts MTP3, SCCP and TCAP in one chain.
msu, outp = binascii.unhexlify(sys.argv[1]), sys.argv[2]
with open(outp, "wb") as fh:
    fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 141))
    fh.write(struct.pack("<IIII", 0, 0, len(msu), len(msu)))
    fh.write(msu)
PYFRAME

rc=0
say() { echo "$1"; }
fail() { say "FAIL $1"; rc=1; }

# tshark 4.2.2 prints these SCCP fields as, for example:
#     Message Type: Unitdata (0x09)
#     Pointer to first Mandatory Variable parameter: 3
#     ..00 0000 0000 0001 = PC: 1
#     SubSystem Number: HLR (Home Location Register) (6)
#     Hop Counter: 0x07
#     Return Cause: Subsystem failure (0x03)
# so each extractor below copies the number and never the dissector's own label.
field_num() {  # <file> <sed-pattern> <1-based match>
  sed -n "$2" "$1" | sed -n "${3:-1}p"
}

check_one() {  # <label> [--sccp-build args...]
  local label="$1"; shift
  local out file
  file="$tmp/$label.pcap"
  out=$(bash "$MODULE" "$@" 2>/dev/null)
  local msu
  msu=$(printf '%s\n' "$out" | awk -F'\t' '$1=="msu_hex"{print $2}')
  if [ -z "$msu" ]; then
    say "FAIL $label: the module built no MSU; it printed:"
    printf '%s\n' "$out" | sed 's/^/     /'
    rc=1; return
  fi
  if ! python3 "$tmp/frame.py" "$msu" "$file" 2>/dev/null; then
    say "FAIL $label: could not build the capture"
    rc=1; return
  fi
  "$TSHARK" -r "$file" -V > "$tmp/$label.txt" 2>/dev/null
  if ! grep -q 'Signalling Connection Control Part' "$tmp/$label.txt"; then
    say "FAIL $label: tshark did not dissect the frame as SCCP; it printed:"
    sed -n '1,20p' "$tmp/$label.txt" | sed 's/^/     /'
    rc=1; return
  fi

  local claim_mt claim_cpc claim_cssn claim_opc claim_ossn
  claim_mt=$(printf '%s\n' "$out" | awk -F'\t' '$1=="sccp_message_type"{print $2}')
  claim_cpc=$(printf '%s\n' "$out" | awk -F'\t' '$1=="called_pc"{print $2}')
  claim_cssn=$(printf '%s\n' "$out" | awk -F'\t' '$1=="called_ssn"{print $2}')
  claim_opc=$(printf '%s\n' "$out" | awk -F'\t' '$1=="calling_pc"{print $2}')
  claim_ossn=$(printf '%s\n' "$out" | awk -F'\t' '$1=="calling_ssn"{print $2}')

  local got_mt got_cpc got_cssn got_opc got_ossn
  got_mt=$(field_num "$tmp/$label.txt" 's/^ *Message Type: *[^(]*(0x\([0-9a-fA-F]*\)).*/\1/p')
  got_cpc=$(field_num "$tmp/$label.txt" 's/.*= PC: *\([0-9]*\)$/\1/p' 1)
  got_opc=$(field_num "$tmp/$label.txt" 's/.*= PC: *\([0-9]*\)$/\1/p' 2)
  # The dissector prints the SSN with its name in front of it, so the leading
  # .* has to be greedy: "SubSystem Number: HLR (Home Location Register) (6)".
  got_cssn=$(field_num "$tmp/$label.txt" 's/^ *SubSystem Number: .*(\([0-9]*\))$/\1/p' 1)
  got_ossn=$(field_num "$tmp/$label.txt" 's/^ *SubSystem Number: .*(\([0-9]*\))$/\1/p' 2)

  if [ -z "$got_mt" ]; then
    fail "$label: tshark printed no SCCP message type; it printed:"
    sed -n '/Signalling Connection Control Part/,+10p' "$tmp/$label.txt" | sed 's/^/     /'
    return
  fi
  [ "${got_mt,,}" = "${claim_mt,,}" ] \
    && say "ok   $label message type 0x$got_mt" \
    || fail "$label message type: tree claims $claim_mt, tshark reads $got_mt"
  [ "${got_cpc:-none}" = "$claim_cpc" ] \
    && say "ok   $label called PC/SSN $got_cpc/$got_cssn" \
    || fail "$label called address: tree claims $claim_cpc/$claim_cssn, tshark reads ${got_cpc:-invisible}/${got_cssn:-invisible}"
  [ "${got_opc:-none}" = "$claim_opc" ] \
    && say "ok   $label calling PC/SSN $got_opc/$got_ossn" \
    || fail "$label calling address: tree claims $claim_opc/$claim_ossn, tshark reads ${got_opc:-invisible}/${got_ossn:-invisible}"

  # The three pointers are the part of Q.713 that a wrong offset breaks while
  # still parsing: the module computes them from where the parameter area
  # starts, and tshark reads them as the octets they are.
  local i key got_ptrs claim_ptrs=() parsed
  parsed=$(bash "$MODULE" --sccp-parse "$msu" --no-store 2>/dev/null)
  for i in 1 2 3; do
    case $i in
      1) key=pointer_called ;; 2) key=pointer_calling ;; 3) key=pointer_data ;;
    esac
    claim_ptrs+=("$(printf '%s\n' "$parsed" | awk -F'\t' -v k="$key" '$1==k{print $2}')")
  done
  i=0
  for pat in 'Pointer to first Mandatory Variable parameter' \
             'Pointer to second Mandatory Variable parameter' \
             'Pointer to third Mandatory Variable parameter'; do
    got_ptrs=$(field_num "$tmp/$label.txt" "s/^ *$pat: *\([0-9]*\)$/\1/p")
    [ "${got_ptrs:-none}" = "${claim_ptrs[$i]}" ] \
      && say "ok   $label $(printf '%s' "$pat" | tr 'A-Z' 'a-z') ${claim_ptrs[$i]}" \
      || fail "$label $pat: tree claims ${claim_ptrs[$i]}, tshark reads ${got_ptrs:-invisible}"
    i=$(( i + 1 ))
  done

  case "$label" in
    udts*)
      # A UDTS carries a return cause where the others carry class and handling;
      # tshark printing a cause is what proves the octet sits at offset 1.
      local claim_cause got_cause
      claim_cause=$(printf '%s\n' "$out" | awk -F'\t' '$1=="return_cause"{print $2}')
      got_cause=$(field_num "$tmp/$label.txt" 's/^ *Return Cause: *[^(]*(0x\([0-9a-fA-F]*\)).*/\1/p')
      [ "$(( 16#${got_cause:-0} ))" = "$claim_cause" ] \
        && say "ok   $label return cause $claim_cause" \
        || fail "$label return cause: tree claims $claim_cause, tshark reads ${got_cause:-invisible}"
      # And there is no class octet to read: a UDTS reassembled as a UDT would
      # have one.
      grep -q '= Class: ' "$tmp/$label.txt" \
        && fail "$label: tshark found a class octet in a UDTS" \
        || say "ok   $label carries no class octet" ;;
    xudt*)
      local claim_hop got_hop
      claim_hop=$(printf '%s\n' "$out" | awk -F'\t' '$1=="hop_counter"{print $2}')
      got_hop=$(field_num "$tmp/$label.txt" 's/^ *Hop Counter: *0x\([0-9a-fA-F]*\)$/\1/p')
      [ "$(( 16#${got_hop:-0} ))" = "$claim_hop" ] \
        && say "ok   $label hop counter $claim_hop" \
        || fail "$label hop counter: tree claims $claim_hop, tshark reads ${got_hop:-invisible}" ;;
  esac
}

# Each fixture uses the same address pair the module's own selftest uses, so a
# disagreement here points at the encoder rather than at the fixture.
check_one udt  --sccp-build udt  --called-pc 1 --called-ssn 6 --calling-pc 2 --calling-ssn 8 \
               --data 4142 --msu-dpc 1 --msu-opc 2 --no-store
check_one udts --sccp-build udts --called-pc 1 --called-ssn 6 --calling-pc 2 --calling-ssn 8 \
               --cause 3 --msu-dpc 1 --msu-opc 2 --no-store
check_one xudt --sccp-build xudt --called-pc 1 --called-ssn 6 --calling-pc 2 --calling-ssn 8 \
               --hop 7 --data 6200000500 --msu-dpc 1 --msu-opc 2 --no-store

# The TCAP decapsulation claim is checked separately: a UDT whose data parameter
# is a BEGIN built by the module's own MAP code. tshark reads the tag from the
# octet; --sccp-parse has to read the same dialog out of the same bytes.
out=$(bash "$MODULE" --sccp-build udt --called-pc 1 --called-ssn 6 --calling-pc 2 --calling-ssn 8 \
        --data 62104804000000016C08A10602010102012D --msu-dpc 1 --msu-opc 2 --no-store 2>/dev/null)
msu=$(printf '%s\n' "$out" | awk -F'\t' '$1=="msu_hex"{print $2}')
if [ -n "$msu" ] && python3 "$tmp/frame.py" "$msu" "$tmp/tcap.pcap" 2>/dev/null; then
  "$TSHARK" -r "$tmp/tcap.pcap" -V > "$tmp/tcap.txt" 2>/dev/null
  if grep -q 'Transaction Capabilities Application Part' "$tmp/tcap.txt"; then
    if grep -qiE '^ *begin *$' "$tmp/tcap.txt"; then
      say "ok   tshark reads a BEGIN inside the unitdata data parameter"
    else
      fail "tshark did not read the data parameter as a TCAP BEGIN"
      sed -n '/Transaction Capabilities/,+6p' "$tmp/tcap.txt" | sed 's/^/     /'
    fi
  else
    fail "tshark did not dissect the data parameter as TCAP"
  fi

  claim=$(bash "$MODULE" --sccp-parse "$msu" --no-store 2>/dev/null)
  claim_tag=$(printf '%s\n' "$claim" | awk -F'\t' '$1=="tcap_tag"{print $2}')
  claim_type=$(printf '%s\n' "$claim" | awk -F'\t' '$1=="tcap_message_type"{print $2}')
  claim_decap=$(printf '%s\n' "$claim" | awk -F'\t' '$1=="tcap_decapsulation"{print $2}')
  [ "$claim_decap" = "decapsulated" ] \
    && say "ok   --sccp-parse decapsulates the MSU tshark dissected" \
    || fail "--sccp-parse says '$claim_decap' about a frame tshark reads as TCAP"
  [ "$claim_tag" = "62" ] \
    && say "ok   --sccp-parse reads the BEGIN tag 62 tshark reads" \
    || fail "--sccp-parse reads tag '$claim_tag' where tshark reads 62"
  [ "$claim_type" = "begin" ] \
    && say "ok   --sccp-parse calls it a begin, as tshark does" \
    || fail "--sccp-parse calls tag 62 '$claim_type'"
else
  fail "could not build the TCAP-bearing unitdata"
fi

if [ "$rc" -eq 0 ]; then
  say "RESULT PASS"
else
  say "RESULT FAIL"
fi
exit "$rc"
