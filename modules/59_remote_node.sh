#!/usr/bin/env bash
# Remote nodes: the fleet this toolkit drives from elsewhere, and what each one
# measured. The registry and the transports live in tools/casebook.py; the far
# side of a node is tools/node_agent.sh. This module is the front door: it names
# the verbs, keeps the exit codes honest and adds the one summary a fleet needs.
if [[ -z "${IMSISTING_ROOT:-}" ]]; then
    _rn_src="${BASH_SOURCE[0]}"
    while [ -L "$_rn_src" ]; do
        _rn_dir="$(cd -P "$(dirname "$_rn_src")" && pwd)"
        _rn_tgt="$(readlink "$_rn_src")"; [[ "$_rn_tgt" != /* ]] && _rn_tgt="$_rn_dir/$_rn_tgt"
        _rn_src="$_rn_tgt"
    done
    IMSISTING_ROOT="$(cd -P "$(dirname "$_rn_src")/.." && pwd)"
fi
export IMSISTING_ROOT
RN_TREE="$IMSISTING_ROOT"
rn_error() { printf 'ERROR\t%s\n' "$*" >&2; }
rn_why()   { printf 'WHY\t%s\n' "$*" >&2; }

# Everything a node answers with is a claim about a machine that is not this
# one. The tool is required rather than reimplemented: one writer for the node
# table, and the streams already keep their own cursor.
rn_tool() {
    local tool="$RN_TREE/tools/casebook.py"
    if [[ ! -r "$tool" ]]; then
        rn_error "no $tool"
        rn_why 'the node registry is the Casebook; a tree without it cannot hold a fleet either'
        return 1
    fi
    if ! command -v python3 >/dev/null 2>&1; then
        rn_error 'python3 is not on PATH'
        rn_why 'the Casebook is a python tool; without an interpreter the fleet cannot be read'
        return 1
    fi
    printf '%s\n' "$tool"
}

# The Casebook's own exit codes are the contract (0 done, 1 could not, 2
# refused, 3 handoff). They are passed through untouched: a caller that loses
# the difference between "the node is down" and "this transport does not exist"
# will go on to make the wrong decision about a whole fleet.
rn_run() {
    local tool rc
    tool=$(rn_tool) || return 1
    python3 "$tool" "$@"
    rc=$?
    return $rc
}

rn_cmd_add() {
    local name="${1:-}" host="${2:-}"
    shift 2 2>/dev/null || true
    if [[ -z "$name" || -z "$host" ]]; then
        rn_error 'usage: --add <name> <host> [--transport ssh|local|adb|serial|qmi|mbim|diag|sms] [--role ROLE] [--port N] [--class CLASS]'
        rn_why 'a node needs a name to call it and a host to reach it'
        return 2
    fi
    local transport=ssh role=sensor port="" klass=""
    while (($#)); do
        case "$1" in
            --transport) transport="${2:-}"; shift 2 || { rn_error '--transport needs a value'; return 2; } ;;
            --role)      role="${2:-}";      shift 2 || { rn_error '--role needs a value'; return 2; } ;;
            --port)      port="${2:-}";      shift 2 || { rn_error '--port needs a value'; return 2; } ;;
            --class)     klass="${2:-}";     shift 2 || { rn_error '--class needs a value'; return 2; } ;;
            *) rn_error "unknown option: $1"; return 2 ;;
        esac
    done
    local args=(--node-add "$name" "$host" "$transport" "$role")
    [[ -z "$port"  ]] || args+=(--port "$port")
    [[ -z "$klass" ]] || args+=(--class "$klass")
    rn_run "${args[@]}"
}

rn_cmd_remove() {
    [[ -n "${1:-}" ]] || { rn_error 'usage: --remove <name>'; return 2; }
    rn_run --node-remove "$1"
}

rn_cmd_list() { rn_run --node-list-tsv; }

rn_cmd_probe() {
    [[ -n "${1:-}" ]] || { rn_error 'usage: --probe <name>'; rn_why 'a probe asks one named node what it is'; return 2; }
    rn_run --node-probe "$1"
}

rn_cmd_stream() {
    local name="${1:-}"
    [[ -n "$name" ]] || { rn_error 'usage: --stream <name> [--follow SECONDS] [--interval S]'; return 2; }
    shift || true
    rn_run --node-stream "$name" "$@"
}

rn_cmd_stream_status() { rn_run --node-stream-status; }

rn_cmd_stream_stop() {
    [[ -n "${1:-}" ]] || { rn_error 'usage: --stream-stop <name>'; return 2; }
    rn_run --node-stream-stop "$1"
}

rn_cmd_collect() {
    [[ -n "${1:-}" ]] || { rn_error 'usage: --collect <name>'; return 2; }
    rn_run --node-collect "$1"
}

# Dispatch is the one verb that runs somebody else's code on somebody else's
# machine. The Casebook refuses the transports that cannot carry a shell and
# hands off (exit 3) when the toolkit is not there; both answers are kept.
rn_cmd_dispatch() {
    local name="${1:-}" module="${2:-}"
    shift 2 2>/dev/null || true
    [[ -n "$name" && -n "$module" ]] || {
        rn_error 'usage: --dispatch <name> <module> <verb> [args...]'
        rn_why 'the module has to be named: 06, 06_gsm_air or its display name'
        return 2
    }
    rn_run --node-dispatch "$name" "$module" "$@"
}

# A preset is a device class with the transport and role that class usually
# arrives with. It fills in no capability: the only capability worth having came
# from a probe of that machine.
rn_cmd_presets() { rn_run --node-presets; }

# What a node's measured capabilities are good for. Refused when nothing was
# measured, because a role nobody measured is a guess about a box you cannot see.
rn_cmd_roles() {
    [[ -n "${1:-}" ]] || { rn_error 'usage: --roles <name>'; return 2; }
    rn_run --node-suggest-roles "$1"
}

rn_cmd_set_roles() {
    [[ -n "${1:-}" && -n "${2:-}" ]] || { rn_error 'usage: --set-roles <name> sensor,capture'; return 2; }
    rn_run --node-set-roles "$1" "$2"
}

# Which modules may run on this node. An empty list means no restriction, and
# the verb says so instead of leaving it to be inferred.
rn_cmd_allow() {
    [[ -n "${1:-}" ]] || { rn_error 'usage: --allow <name> [module,...|-]'; return 2; }
    rn_run --node-allow "$@"
}

rn_cmd_bulk_probe() { rn_run --node-bulk-probe; }

rn_cmd_remove_offline() { rn_run --node-remove-offline "$@"; }

rn_cmd_health() { rn_run --node-health; }

# What THIS host could do if it were a node: the same capability probe the
# agent runs on the far side, so a comparison between two machines is a
# comparison between two runs of one script.
rn_cmd_caps() {
    local agent="$RN_TREE/tools/node_agent.sh"
    [[ -r "$agent" ]] || { rn_error "no $agent"; return 1; }
    sh "$agent" --probe --caps
}

# One row per number the fleet is judged by. A node nobody probed counts as
# unknown, never as healthy: the difference between "all reachable" and "nobody
# asked" is the whole reason this module exists.
rn_cmd_status() {
    local tool nodes streams
    tool=$(rn_tool) || return 1
    nodes=$(python3 "$tool" --node-list-tsv 2>/dev/null)
    [[ -n "$nodes" ]] || nodes=$(printf 'name\tstatus\n')
    streams=$(python3 "$tool" --node-stream-status 2>/dev/null)

    printf 'nodes\t%s\n'     "$(printf '%s\n' "$nodes" | awk 'NR>1 && NF' | wc -l | tr -d ' ')"
    printf 'online\t%s\n'    "$(printf '%s\n' "$nodes" | awk -F'\t' 'NR==1{for(i=1;i<=NF;i++) if($i=="status") c=i; next} c && $c=="ONLINE"' | wc -l | tr -d ' ')"
    printf 'offline\t%s\n'   "$(printf '%s\n' "$nodes" | awk -F'\t' 'NR==1{for(i=1;i<=NF;i++) if($i=="status") c=i; next} c && $c=="OFFLINE"' | wc -l | tr -d ' ')"
    printf 'unknown\t%s\n'   "$(printf '%s\n' "$nodes" | awk -F'\t' 'NR==1{for(i=1;i<=NF;i++) if($i=="status") c=i; next} c && ($c=="" || $c=="-" || $c=="UNKNOWN")' | wc -l | tr -d ' ')"
    printf 'streamed\t%s\n'  "$(printf '%s\n' "$streams" | awk 'NR>1 && NF' | wc -l | tr -d ' ')"
    printf 'stream_rows\t%s\n' "$(printf '%s\n' "$streams" | awk -F'\t' 'NR==1{for(i=1;i<=NF;i++) if($i=="rows") c=i; next} c && $c ~ /^[0-9]+$/ {s+=$c} END{print s+0}')"
    printf 'stale_streams\t%s\n' "$(printf '%s\n' "$streams" | awk -F'\t' 'NR==1{for(i=1;i<=NF;i++) if($i=="lag_s") c=i; next} c && $c ~ /^[0-9]+$/ && $c>300' | wc -l | tr -d ' ')"
    printf 'device_kinds\t%s\n' "$(printf '%s\n' "$nodes" | awk -F'\t' 'NR==1{for(i=1;i<=NF;i++) if($i=="class") c=i; next} c && $c!="" && $c!="-" {print $c}' | sort -u | paste -sd, -)"
}

rn_menu() {
    cat <<'EOF'
Remote Nodes — fleet registry, measured capabilities, captured events
  --add <name> <host> [--transport ssh|local|adb|serial|qmi|mbim|diag|sms]
                      [--role ROLE] [--port N] [--class CLASS]
  --remove <name>
  --list-tsv                    every node with class, caps, role and last seen
  --probe <name>                ask that node what it is; ONLINE/OFFLINE/UNKNOWN
  --caps                        what THIS host could do as a node
  --stream <name> [--follow S]  drain the node spool from this side's cursor
  --stream-status-tsv           rows, bytes, cursor and how far behind each node is
  --stream-stop <name>
  --dispatch <name> <module> <verb> [args...]
                                run a module on that node and keep its rows
  --collect <name>              copy node state into the active case
  --presets                     device classes and default transport per class
  --roles <name>                roles implied by measured capabilities
  --set-roles <name> r1,r2      set the roles by hand, against the probe
  --allow <name> [mods|-]       modules permitted to dispatch on that node
  --bulk-probe                  probe every node; unreachable nodes do not stop it
  --remove-offline [--dry-run]  prune nodes that answered OFFLINE
  --health                      load, memory, disk and running work per node
  --status-tsv                  fleet counts by status
  --selftest
EOF
}

# ── selftest ───────────────────────────────────────────────────────────────
# The point of these rows is that a fleet view must never round up. A node that
# nobody probed is UNKNOWN, a transport that does not exist is a refusal, and a
# missing toolkit on the far side is a handoff -- not an empty success.
rn_selftest() {
    local d rc=0 out
    d=$(mktemp -d) || return 1
    export CASEBOOK_DIR="$d/book" STATE_DIR="$d/state"
    rm -rf "$d/book" "$d/state"
    mkdir -p "$d/book" "$d/state"

    # every verb the menu advertises exists in the dispatcher
    local listed
    listed=$(rn_menu | sed -n 's/^  \(--[a-z-]*\).*/\1/p' | sort -u)
    for v in $listed; do
        [[ "$v" == --help || "$v" == --version ]] && continue
        grep -q -- "        $v" "$0" || grep -q -- "$v|" "$0" || { printf 'selftest\tmenu advertises %s but nothing runs it\n' "$v" >&2; rc=1; }
    done

    # add, then read it back with the columns move 1 introduced
    out=$(rn_cmd_add desk localhost --transport local --role sensor --class sdr 2>&1)
    printf '%s\n' "$out" | grep -q '^node[[:space:]]*desk' || { printf 'selftest\t--add did not register the node\n' >&2; rc=1; }
    out=$(rn_cmd_list 2>&1)
    printf '%s\n' "$out" | head -1 | grep -qw class || { printf 'selftest\t--list-tsv has no class column\n' >&2; rc=1; }
    printf '%s\n' "$out" | head -1 | grep -qw caps  || { printf 'selftest\t--list-tsv has no caps column\n' >&2; rc=1; }
    printf '%s\n' "$out" | awk -F'\t' '$1=="desk"' | grep -q . || { printf 'selftest\tthe node is missing from --list-tsv\n' >&2; rc=1; }

    # a probe of this host answers ONLINE and names a class
    out=$(rn_cmd_probe desk 2>&1)
    printf '%s\n' "$out" | grep -q '^status[[:space:]]*ONLINE' || { printf 'selftest\t--probe did not report ONLINE for a local node\n' >&2; rc=1; }
    printf '%s\n' "$out" | awk -F'\t' '$1=="class" && $2!=""' | grep -q . || { printf 'selftest\t--probe measured no class\n' >&2; rc=1; }

    # a transport this tree does not implement is refused, not guessed at
    rn_cmd_add modemhost 1.2.3.4 --transport sms >/dev/null 2>&1
    out=$(rn_cmd_probe modemhost 2>&1); local rc_sms=$?
    [[ "$rc_sms" == 2 ]] || { printf 'selftest\tsms transport exited %s, not 2\n' "$rc_sms" >&2; rc=1; }
    printf '%s\n' "$out" | grep -q 'no sms transport' || { printf 'selftest\tsms refusal did not name the missing transport\n' >&2; rc=1; }

    # an unknown transport never reaches the table
    rn_cmd_add weirdhost 1.2.3.4 --transport carrier-pigeon >/dev/null 2>&1
    [[ $? == 2 ]] || { printf 'selftest\tan unknown transport was accepted\n' >&2; rc=1; }

    # a stream of a local node writes a spool and a cursor
    NODE_SPOOL="$d/state/spool.tsv" NODE_STREAM_WINDOW=1 rn_cmd_stream desk >/dev/null 2>&1
    [[ $? == 0 ]] || { printf 'selftest\t--stream failed against a local node\n' >&2; rc=1; }
    out=$(rn_cmd_stream_status 2>&1)
    printf '%s\n' "$out" | head -1 | grep -qw lag_s || { printf 'selftest\t--stream-status-tsv has no lag column\n' >&2; rc=1; }

    # dispatch keeps the module's exit code and refuses what cannot carry a shell
    rn_cmd_add deadlink 1.2.3.4 --transport serial >/dev/null 2>&1
    rn_cmd_dispatch deadlink 26 --selftest >/dev/null 2>&1
    [[ $? == 2 ]] || { printf 'selftest\tdispatch over a modem link was not refused\n' >&2; rc=1; }
    rn_cmd_dispatch desk 99 --selftest >/dev/null 2>&1
    [[ $? == 2 ]] || { printf 'selftest\tdispatch of an unknown module was not refused\n' >&2; rc=1; }

    # the summary counts, and counts an unprobed node as unknown
    rn_cmd_add unprobed 1.2.3.4 --transport ssh >/dev/null 2>&1
    out=$(rn_cmd_status 2>&1)
    printf '%s\n' "$out" | grep -q '^nodes[[:space:]]*4$' || { printf 'selftest\t--status-tsv miscounted the fleet\n' >&2; rc=1; }
    printf '%s\n' "$out" | grep -q '^online[[:space:]]*1$' || { printf 'selftest\t--status-tsv miscounted ONLINE\n' >&2; rc=1; }
    printf '%s\n' "$out" | grep -q '^unknown[[:space:]]*3$' || { printf 'selftest\tan unprobed node is not counted as UNKNOWN\n' >&2; rc=1; }
    printf '%s\n' "$out" | grep -q '^streamed[[:space:]]*1$' || { printf 'selftest\t--status-tsv miscounted streams\n' >&2; rc=1; }

    # presets carry a transport and a role, never a capability
    out=$(rn_cmd_presets 2>&1)
    printf '%s\n' "$out" | head -1 | grep -qw transport || { printf 'selftest\t--presets has no transport column\n' >&2; rc=1; }
    printf '%s\n' "$out" | head -1 | grep -qw caps && { printf 'selftest\t--presets claims capabilities it never measured\n' >&2; rc=1; }
    printf '%s\n' "$out" | awk -F'\t' '$1=="dongle"' | grep -q . || { printf 'selftest\t--presets lost the dongle class\n' >&2; rc=1; }

    # roles are derived from a probe, and refused when nothing was measured
    rn_cmd_add bare 1.2.3.4 --transport ssh >/dev/null 2>&1
    rn_cmd_roles bare >/dev/null 2>&1
    [[ $? == 2 ]] || { printf 'selftest\t--roles invented roles for an unprobed node\n' >&2; rc=1; }
    rn_cmd_set_roles bare sensor,capture >/dev/null 2>&1
    rn_cmd_list 2>&1 | awk -F'\t' '$1=="bare"{print $6}' | grep -q 'sensor,capture' \
        || { printf 'selftest\t--set-roles did not store the roles\n' >&2; rc=1; }

    # the allow-list keeps a module off a node it was not admitted to
    rn_cmd_allow bare 06 >/dev/null 2>&1
    rn_cmd_dispatch bare 07 --selftest >/dev/null 2>&1
    [[ $? != 0 ]] || { printf 'selftest\t--dispatch ignored the allow-list\n' >&2; rc=1; }
    rn_cmd_allow bare - >/dev/null 2>&1 || { printf 'selftest\t--allow could not be cleared\n' >&2; rc=1; }

    # bulk probe and health keep the fleet readable when one node cannot answer.
    # The book is reset first so the rows under test cannot take a minute waiting
    # on an ssh node that does not exist: this row is about carrying on, not
    # about how long a timeout is.
    rm -f "$CASEBOOK_DIR/nodes.tsv"
    rn_cmd_add herenode localhost --transport local --role sensor >/dev/null 2>&1
    rn_cmd_add downnode 1.2.3.4 --transport sms --role relay >/dev/null 2>&1
    out=$(rn_cmd_bulk_probe 2>/dev/null); local bulk_rc=$?
    printf '%s\n' "$out" | head -1 | grep -qw status || { printf 'selftest\t--bulk-probe has no status column\n' >&2; rc=1; }
    printf '%s\n' "$out" | awk -F'\t' 'NR>1 && NF' | grep -q . || { printf 'selftest\t--bulk-probe reported no rows after a node it could not reach\n' >&2; rc=1; }
    printf '%s\n' "$out" | awk -F'\t' '$1=="herenode"' | grep -q ONLINE || { printf 'selftest\t--bulk-probe did not measure the node that answered\n' >&2; rc=1; }
    # A node on a transport nobody can ask is UNKNOWN and the run still succeeds:
    # "I could not ask" is not "the box is down", and only one of those is a
    # fleet failure.
    [[ "$bulk_rc" == 0 ]] || { printf 'selftest\ta bulk probe with an unaskable node exited %s, not 0\n' "$bulk_rc" >&2; rc=1; }
    printf '%s\n' "$out" | awk -F'\t' '$1=="downnode"{print $3}' | grep -q UNKNOWN \
        || { printf 'selftest\tan unaskable node was not reported UNKNOWN\n' >&2; rc=1; }
    out=$(rn_cmd_health 2>/dev/null)
    printf '%s\n' "$out" | head -1 | grep -qw disk_used_pct || { printf 'selftest\t--health has no disk column\n' >&2; rc=1; }
    printf '%s\n' "$out" | grep -q 'unmeasured' || { printf 'selftest\t--health claimed a number it never measured\n' >&2; rc=1; }

    # pruning is a dry run until it is asked to be real
    # A serial node pointed at a closed port answers, and the answer is OFFLINE:
    # a real box that did not pick up, which is the only thing pruning is for.
    rn_cmd_add deadbox 127.0.0.1 --transport serial --port 1 >/dev/null 2>&1
    rn_cmd_probe deadbox >/dev/null 2>&1
    out=$(rn_cmd_remove_offline --dry-run 2>&1)
    printf '%s\n' "$out" | grep -q 'would-remove' || { printf 'selftest\t--remove-offline --dry-run removed nothing and said nothing\n' >&2; rc=1; }
    rn_cmd_list 2>&1 | awk -F'\t' '$1=="deadbox"' | grep -q . || { printf 'selftest\t--dry-run pruned a node anyway\n' >&2; rc=1; }

    # this host as a node, through the same agent the far side runs
    out=$(rn_cmd_caps 2>&1)
    printf '%s\n' "$out" | grep -q '^class[[:space:]]' || { printf 'selftest\t--caps inferred no class\n' >&2; rc=1; }
    printf '%s\n' "$out" | grep -q '^cap[[:space:]]' || { printf 'selftest\t--caps listed no capabilities\n' >&2; rc=1; }

    # removal is real
    rn_cmd_remove unprobed >/dev/null 2>&1
    rn_cmd_list 2>&1 | awk -F'\t' '$1=="unprobed"' | grep -q . && { printf 'selftest\t--remove did not remove the node\n' >&2; rc=1; }

    # no interpreter is a named failure, not an empty fleet
    out=$(RN_TREE_SAVE="$RN_TREE" bash -c 'PATH=/nonexistent; . /dev/null; true' 2>/dev/null)
    local saved_path="$PATH"
    PATH=/nonexistent out=$(rn_cmd_list 2>&1); local rc_nopy=$?
    PATH="$saved_path"
    [[ "$rc_nopy" == 1 ]] || { printf 'selftest\tmissing python3 exited %s, not 1\n' "$rc_nopy" >&2; rc=1; }
    printf '%s\n' "$out" | grep -q 'python3 is not on PATH' || { printf 'selftest\tmissing python3 was not named\n' >&2; rc=1; }

    unset CASEBOOK_DIR STATE_DIR
    rm -rf -- "$d"
    if (( rc == 0 )); then builtin printf 'selftest\tPASS\nRESULT\tPASS\n'; else builtin printf 'selftest\tFAIL\nRESULT\tFAIL\n'; return 1; fi
}

rn_cli() {
    local cmd="${1:-}"; (($#)) && shift
    case "$cmd" in
        --add)                rn_cmd_add "$@" ;;
        --remove)             rn_cmd_remove "$@" ;;
        --list-tsv|--list|--nodes) rn_cmd_list "$@" ;;
        --probe)              rn_cmd_probe "$@" ;;
        --caps)               rn_cmd_caps "$@" ;;
        --stream)             rn_cmd_stream "$@" ;;
        --stream-status-tsv|--stream-status) rn_cmd_stream_status "$@" ;;
        --stream-stop)        rn_cmd_stream_stop "$@" ;;
        --collect)            rn_cmd_collect "$@" ;;
        --presets|--presets-tsv) rn_cmd_presets "$@" ;;
        --roles|--suggest-roles) rn_cmd_roles "$@" ;;
        --set-roles)          rn_cmd_set_roles "$@" ;;
        --allow|--allowed)    rn_cmd_allow "$@" ;;
        --bulk-probe)         rn_cmd_bulk_probe "$@" ;;
        --remove-offline)     rn_cmd_remove_offline "$@" ;;
        --health|--node-health-tsv) rn_cmd_health "$@" ;;
        --dispatch)           rn_cmd_dispatch "$@" ;;
        --status-tsv|--status) rn_cmd_status "$@" ;;
        --selftest)           rn_selftest ;;
        --help|-h|help|--menu|--__index_probe__|'') rn_menu ;;
        *) rn_error "unknown command: $cmd"; return 2 ;;
    esac
}
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then rn_cli "$@"; fi
