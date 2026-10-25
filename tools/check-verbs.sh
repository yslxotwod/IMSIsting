#!/usr/bin/env bash
# check-verbs.sh — find verbs a module exposes that no GUI control can reach.
#
# A feature nobody can click is a feature nobody has. Every verb a module
# documents must either sit in one of its submenu groups (so it is clickable),
# or be a plumbing verb that belongs to the launcher and the test runner rather
# than to a person. A verb in neither category is a failure, and this check
# names it.
#
# Placement is read from the group specs in native/src/main1.c, where each
# module lists its submenus as "verb[!][@][:Label]" entries.
#
# Usage: tools/check-verbs.sh [--json] [--list]
#   --list  show every verb and where it is reached from
# Exit: 0 if every verb is placed or exempt, 1 otherwise.

set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MAIN="$ROOT/native/src/main1.c"
jsonout=0
listall=0
for a in "$@"; do
    case "$a" in
        --json) jsonout=1 ;;
        --list) listall=1 ;;
    esac
done

[[ -f "$MAIN" ]] || { echo "no $MAIN" >&2; exit 2; }

fail=0
n_placed=0
n_exempt=0
n_cli=0
declare -a unreachable=()
declare -a n_modifier=()

# Plumbing and modifier verbs. These are not user actions: the launcher, the
# test runner and the module internals call them. They are allowed to have no
# button.
#
# A modifier is a flag that changes what another verb is allowed to do rather
# than being a verb of its own -- --earfcn names a carrier for --tx-build, and
# --i-have-a-lab-and-authorisation is the gate a keyed transmit path consults.
# The gate is exempt and NOT placed on purpose: a GUI button that arms a
# transmitter is exactly the control this module refuses to provide, so the
# flag stays on the command line where the disclaimer has already been shown.
exempt_re='^(menu|selftest|status-tsv|info|__index_probe__|yes|quiet|help|version|prepare|preflight|ota-test|pci|out)$'

# A builder's named flags. These are arguments of --tx-build, not verbs: the
# listing below is deliberately explicit rather than a wildcard, so a new flag
# still has to be classified by a human who knows whether it is an argument or
# an action. 33_jamming_detect's constructor takes its twelve facts as flags
# because twelve positional arguments is an interface nobody can call safely.
# The list is explicit on purpose. A wildcard here would silently stop requiring
# a control for a verb, and widening it to a name another module already uses as a
# verb does exactly that: `device` was added for 35_baseband --device and had to
# come straight back out, because 52_stk --device is a verb with its own button.
modifier_re='^--(earfcn|clone-recon|i-have-a-lab-and-authorisation|mode|shape|format|rate|secs|centre|band|peak|on|off|seed|out|gen|key|dir|framing|freq|api|api-key|device-id|raw|serve|instrument|power|action|case|base|port|cause|identity|rand|autn|auts|algorithms|ksi|ksi-type|amf|area-ids|calls|critical-extensions-future|days|duration|dst|flow-id|i-ssb|inner-teid|iterations|klength|ki|algo|reveal|sn|sn-name|mcc|mcd-dist|mcd-src|meas-id|mib|mnc|mood|n-rb|n-rb-dl|n-rb-prs|ncs|neigh|top|v|warning-message|warning-type|non-critical-extension|op|opc|outer-seq|outer-teid|prio|prn|release-cause|reps|root|rsrp|rsrq|scs|seq|service-id|session-id|smds|sqn|src|t320|tid|segment-type|segment-number|srsran-version|ports|dummy|payload-text|segment|count|data-coding|late-non-critical|warning-area|payload|csri|vlr-name|mme-name|mmec|mmegi|lu-type|service-indicator|emm-mode|lai|tai|old-lai|plmn|nas|tmsi|dcs|dst-npi|dst-ton|interface-version|rd|service-type|src-npi|src-ton|system-type|psc|seconds|gain|freq|bch-hex|sibs|sib-sf|sib-code|sib-offset|mcc|mnc|no-key|bare|domain|txid|msc|otid|wrap|invoke|cssn|ossn|dpc|msisdn|imsi|k-enc|k-mac|host-challenge|card-challenge|dest-var|varid|barred|qrxlevmin|cellid|siw|valuetag|period|reselect|csg-indication|csg-identity|reslen|media|codec|play|rtp-port|record-wav|target|ud-hex|udhi|scts|vectors|code|wait)$'

# main1.c with every submenu table stripped out. A verb found in here is wired
# from C code -- a custom view building its own controls -- rather than named in
# a spec string. Keeping the two apart is what stops one module borrowing
# another's spec line.
codeonly=$(awk '/^static ModuleSubmenuEntry [a-z0-9_]+_entries\[\] = \{/ { f=1 }
                f && /^\};/ { f=0; next }
                !f' "$MAIN")

for f in "$ROOT"/modules/*.sh; do
    [[ -e "$f" ]] || continue
    mod=$(basename "$f" .sh)

    # Harvest the verbs from the module's own usage output.
    verbs=$(cd "$ROOT" && timeout 20 bash "$f" --__index_probe__ 2>&1 |
            grep -oE '\-\-[a-z][a-z0-9-]*' | sort -u)

    [[ -z "$verbs" ]] && continue

    # Scope every lookup to THIS module's own submenu table. Matching the bare
    # verb name anywhere in main1.c lets a verb borrow another module's entry:
    # 09_lte_attach's --identity-exposure was reported PLACED on the strength of
    # 06_gsm_air's spec, which hid that it had no working control at all.
    tab=$(grep -oE "module_registry_register\(\"$mod\", *[a-z0-9_]+_entries" "$MAIN" |
          head -1 | grep -oE '[a-z0-9_]+_entries')
    spec=""
    if [[ -n "$tab" ]]; then
        spec=$(awk "/static ModuleSubmenuEntry ${tab}\\[\\] = \\{/{f=1} f{print} f&&/^};/{exit}" "$MAIN")
    fi
    [[ -n "$spec" ]] || spec="$MAIN"

    while read -r v; do
        [[ -z "$v" ]] && continue

        if [[ "$v" =~ $exempt_re ]]; then
            n_exempt=$((n_exempt + 1))
            (( listall )) && printf 'EXEMPT   %-22s %s\n' "$mod" "$v"
            continue
        fi

        if [[ "$v" =~ $modifier_re ]]; then
            n_modifier+=("$mod $v")
            (( listall )) && printf 'MODIFIER %-22s %s\n' "$mod" "$v"
            continue
        fi

        # A '~' prefix in a group spec marks a verb that needs an argument only
        # the operator knows: it is deliberately kept on the command line.
        if grep -qE -- "~${v}([^a-z0-9-]|\$)" <<< "$spec"; then
            n_cli=$((n_cli + 1))
            (( listall )) && printf 'CLI-ONLY %-22s %s\n' "$mod" "$v"
            continue
        fi

        # Placed means the verb is named in this module's group spec in
        # main1.c. Match it as a whole token so --list does not satisfy
        # --list-tsv. A verb the module's own C code calls is reachable too --
        # custom views build their controls directly -- so fall back to the
        # code-only view of main1.c.
        if grep -qE -- "(^|[^a-z0-9-])${v}([^a-z0-9-]|\$)" <<< "$spec" ||
           grep -qE -- "(^|[^a-z0-9-])${v}([^a-z0-9-]|\$)" <<< "$codeonly"; then
            n_placed=$((n_placed + 1))
            (( listall )) && printf 'PLACED   %-22s %s\n' "$mod" "$v"
        else
            unreachable+=("$mod $v")
            fail=$((fail + 1))
            (( jsonout )) || printf 'UNPLACED  %-22s %s\n' "$mod" "$v"
        fi
    done <<< "$verbs"
done

if (( jsonout )); then
    printf '{"unplaced":%d,"verbs":[' "$fail"
    for i in "${!unreachable[@]}"; do
        (( i > 0 )) && printf ','
        printf '"%s"' "${unreachable[$i]}"
    done
    printf ']}\n'
else
    printf '\n'
    if (( fail == 0 )); then
        printf 'every documented verb is placed in a submenu or exempt\n'
        printf '  %d placed as one-click buttons, %d CLI-only (need an argument), %d modifiers, %d exempt plumbing verbs\n' \
            "$n_placed" "$n_cli" "${#n_modifier[@]}" "$n_exempt"
    else
        printf '%d verb(s) are neither placed in a submenu nor exempt\n' "$fail"
    fi
fi

(( fail == 0 )) || exit 1
exit 0
