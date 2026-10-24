#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MOD="$ROOT/modules/57_evil_twin.sh"
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
export IMSISTING_ROOT="$ROOT" HOME="${HOME:-/tmp}"
fail() { printf 'FAIL\t%s\n' "$*" >&2; exit 1; }
pass() { printf 'PASS\t%s\n' "$*"; }
bash -n "$MOD" || fail syntax
bash -n "$ROOT/tools/check-evil-twin-lab.sh" || fail test-syntax
"$MOD" --selftest >"$tmp/selftest.out" || fail selftest
grep -qx $'selftest\tPASS' "$tmp/selftest.out" || fail selftest-output
pass selftest
printf 'rat\tgen\tarfcn\tfreq_mhz\tplmn\tmcc\tmnc\toperator\tcountry\tcell_id\ttac_lac\tband\trsrp_dbm\tcipher\tsource\tts\n' >"$tmp/cells.tsv"
printf 'LTE\t4G\t6300\t806.0\t208-01\t208\t01\tLab\tXX\t12345\t42\t20\t-75\t\tsrsran\t2026-01-01\n' >>"$tmp/cells.tsv"
printf 'LTE\t4G\t6300\t806.0\t208-01\t208\t01\t$(touch /tmp/evil-twin-test-injection)\tXX\t12345\t42\t20\t-75\t\tsrsran\t2026-01-01\n' >>"$tmp/cells.tsv"
"$MOD" --prepare-lte "$tmp/cells.tsv" 1 --out "$tmp/lte" >"$tmp/prepare-lte.out" || fail prepare-lte
[[ -s "$tmp/lte/enb.conf" && -s "$tmp/lte/rr.conf" ]] || fail lte-generated-files
grep -q 'dl_earfcn = 6300' "$tmp/lte/enb.conf" || fail lte-earfcn
grep -q 'cell_id = 12345;' "$tmp/lte/rr.conf" || fail lte-cell-id
pass lte-recon-to-config
"$MOD" --preflight-lte "$tmp/lte" >/dev/null 2>&1 && fail lte-expected-missing-config
"$MOD" --lte-test "$tmp/lte" 5 >/dev/null 2>&1 && fail lte-test-requires-local-configs
"$MOD" --prepare-lte "$tmp/cells.tsv" 1 --out / >/dev/null 2>&1 && fail lte-root-path
"$MOD" --prepare-lte "$tmp/cells.tsv" 1 --pci 504 --out "$tmp/bad-lte-pci" >/dev/null 2>&1 && fail lte-pci-range
"$MOD" --prepare-lte "$tmp/cells.tsv" 2 --out "$tmp/unsafe-lte-row" >/dev/null 2>&1 && fail lte-rejects-shell-substitution-row
[[ ! -e /tmp/evil-twin-test-injection ]] || fail lte-no-command-execution
printf 'rat\tgen\tarfcn\tfreq_mhz\tplmn\tmcc\tmnc\toperator\tcountry\tcell_id\ttac_lac\tband\trsrp_dbm\tcipher\tsource\tts\n' >"$tmp/nr.tsv"
printf 'NR\t5G\t640000\t3600.000\t208-01\t208\t01\tLab\tXX\t12345\t7\tn78\t-75\t\tsrsran\t2026-01-01\n' >>"$tmp/nr.tsv"
"$MOD" --prepare-nr "$tmp/nr.tsv" 1 --band n78 --out "$tmp/nr" --format open5gs >"$tmp/prepare-nr.out" || fail prepare-nr
[[ -s "$tmp/nr/gnb.conf" && -s "$tmp/nr/amf.yaml" ]] || fail nr-generated-files
grep -q 'dl_arfcn: 640000' "$tmp/nr/gnb.conf" || fail nr-arfcn
grep -q 'plmn: "20801"' "$tmp/nr/gnb.conf" || fail nr-plmn
grep -q 'tac: 7' "$tmp/nr/amf.yaml" || fail nr-tac
pass nr-recon-to-config
"$MOD" --prepare-nr "$tmp/cells.tsv" 1 --band n78 --out "$tmp/bad-nr" >/dev/null 2>&1 && fail nr-reject-lte-row
"$MOD" --prepare-nr "$tmp/nr.tsv" 1 --band n78 --pci 1008 --out "$tmp/bad-pci" >/dev/null 2>&1 && fail nr-pci-range
sed 's/3600.000/3600.001/' "$tmp/nr.tsv" >"$tmp/bad-frequency.tsv"
"$MOD" --prepare-nr "$tmp/bad-frequency.tsv" 1 --band n78 --out "$tmp/bad-frequency" >/dev/null 2>&1 && fail nr-frequency-mismatch
sed 's/n78/n48/' "$tmp/nr.tsv" >"$tmp/ambiguous-band.tsv"
"$MOD" --prepare-nr "$tmp/ambiguous-band.tsv" 1 --out "$tmp/ambiguous-band" >/dev/null 2>&1 && fail nr-requires-band-on-overlap
"$MOD" --prepare-nr "$tmp/nr.tsv" 1 --band n78 --out "$tmp/explicit-band" >/dev/null 2>&1 || fail nr-explicit-overlap-band
"$MOD" --preflight-nr "$tmp/nr" >/dev/null 2>&1 && fail nr-expected-missing-ue
"$MOD" --nr-test "$tmp/nr" 5 >/dev/null 2>&1 && fail nr-test-requires-local-configs
"$MOD" --prepare-nr "$tmp/nr.tsv" 1 --band n78 --out / >/dev/null 2>&1 && fail nr-root-path
mkdir -p "$tmp/loopback-lte" "$tmp/unsafe-lte"
for f in epc.conf enb.conf rr.conf srsue.conf; do : >"$tmp/loopback-lte/$f"; done
printf 'enb_addr = 127.0.0.1\n' >"$tmp/loopback-lte/rr.conf"
printf 'mme_addr = 127.0.0.5\n' >"$tmp/loopback-lte/epc.conf"
printf 'mme_addr = 127.0.0.5\ngtp_bind_addr = 127.0.0.1\ns1c_bind_addr = 127.0.0.1\n' >"$tmp/loopback-lte/enb.conf"
printf 'enb_addr = 127.0.0.1\n' >"$tmp/loopback-lte/srsue.conf"
printf 'enb_addr = 127.0.0.1\n' >"$tmp/loopback-lte/rr.conf"
"$MOD" --preflight-lte "$tmp/loopback-lte" >/dev/null 2>&1 && fail lte-preflight-requires-tools
"$MOD" --lte-test "$tmp/loopback-lte" 5 >/dev/null 2>&1 && fail lte-run-requires-explicit-ack
"$MOD" --lte-test "$tmp/loopback-lte" 5 --ack-isolated-lab >/dev/null 2>&1 && fail lte-run-requires-tools
cp "$tmp/loopback-lte/epc.conf" "$tmp/loopback-lte/enb.conf" "$tmp/loopback-lte/rr.conf" "$tmp/loopback-lte/srsue.conf" "$tmp/unsafe-lte/"
printf 'mme_addr = 192.0.2.10\n' >>"$tmp/unsafe-lte/enb.conf"
"$MOD" --lte-test "$tmp/unsafe-lte" 5 >/dev/null 2>&1 && fail lte-rejects-non-loopback-config
printf 'enb_addr = 192.0.2.20\n' >>"$tmp/unsafe-lte/srsue.conf"
"$MOD" --lte-test "$tmp/unsafe-lte" 5 >/dev/null 2>&1 && fail lte-rejects-non-loopback-peer
mkdir -p "$tmp/no-address" && : >"$tmp/no-address/empty.conf"
"$MOD" --lte-test "$tmp/no-address" 5 >/dev/null 2>&1 && fail lte-requires-loopback-address-fields
mkdir -p "$tmp/loopback-nr" "$tmp/unsafe-nr"
printf 'bind_addr: 127.0.0.5\n' >"$tmp/loopback-nr/amf.yaml"
printf 'amf: 127.0.0.5\n' >"$tmp/loopback-nr/gnb.conf"
printf 'amf_addr: 127.0.0.5\n' >"$tmp/loopback-nr/ue.yaml"
"$MOD" --preflight-nr "$tmp/loopback-nr" >/dev/null 2>&1 && fail nr-preflight-requires-tools
"$MOD" --nr-test "$tmp/loopback-nr" 5 >/dev/null 2>&1 && fail nr-run-requires-explicit-ack
"$MOD" --nr-test "$tmp/loopback-nr" 5 --ack-isolated-lab >/dev/null 2>&1 && fail nr-run-requires-loopback-address-fields
printf 'amf: 127.0.0.5\n' >>"$tmp/loopback-nr/amf.yaml"
printf 'ngap_addr: 127.0.0.1\n' >>"$tmp/loopback-nr/gnb.conf"
printf 'amf_addr: 127.0.0.5\n' >>"$tmp/loopback-nr/ue.yaml"
"$MOD" --nr-test "$tmp/loopback-nr" 5 --ack-isolated-lab >/dev/null 2>&1 && fail nr-run-requires-tools
cp "$tmp/loopback-nr/amf.yaml" "$tmp/loopback-nr/gnb.conf" "$tmp/loopback-nr/ue.yaml" "$tmp/unsafe-nr/"
printf 'bind_addr: 0.0.0.0\n' >>"$tmp/unsafe-nr/gnb.conf"
"$MOD" --nr-test "$tmp/unsafe-nr" 5 --ack-isolated-lab >/dev/null 2>&1 && fail nr-rejects-wildcard-bind
printf 'amf_addr: 198.51.100.2\n' >>"$tmp/unsafe-nr/ue.yaml"
"$MOD" --nr-test "$tmp/unsafe-nr" 5 --ack-isolated-lab >/dev/null 2>&1 && fail nr-rejects-routable-peer
pass config-and-path-guards
