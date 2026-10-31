#!/usr/bin/env bash
# check-launchers.sh — verify that every launcher entry point resolves.
#
# The failure this catches: `bin/` wrappers are checked by check-paths.sh for
# existence and the executable bit, and for nothing else. A wrapper whose
# `exec` target was renamed, whose relative path was computed one level too
# low, or which forwards the wrong subcommand still passes that gate and then
# fails at runtime with a shell error the user reads as "the toolkit is
# broken". The wrappers are the first thing anyone types after cloning, so
# they get their own referee.
#
# What is proven, per entry point:
#
#   1. It exists, is executable, and is a regular file.
#   2. Its `exec` target exists and is executable (resolved statically, with no
#      code path that can see a stale file left by a previous run).
#   3. Running it under a stub PATH that records the exec produces the exact
#      launcher plus the exact arguments the wrapper is documented to forward.
#      A wrapper that silently drops `"$@"` fails here and nowhere else.
#   4. `imsisting.sh` in turn answers the subcommand the wrapper passes. A
#      wrapper that forwards `--gui` to a launcher that no longer has a
#      `--gui` arm is dead on arrival; this is checked against the launcher's
#      own dispatch rather than against this document.
#
# Nothing here starts a GUI, a TUI, a radio or a database. Every invocation is
# intercepted before the real launcher runs, so the gate is safe in a headless
# container and gives the same answer on a box with no GTK at all.
#
# Usage: tools/check-launchers.sh [--json] [--verbose]
# Exit: 0 if every wrapper resolves, 1 otherwise.

set -uo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
jsonout=0
verbose=0
for arg in "$@"; do
    case "$arg" in
        --json)     jsonout=1 ;;
        --verbose)  verbose=1 ;;
        -h|--help)  sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)          printf 'check-launchers: unknown flag %s\n' "$arg" >&2; exit 2 ;;
    esac
done

fail=0
declare -a problems=()
declare -a notes=()

problem() {
    problems+=("$1")
    fail=$((fail + 1))
    (( jsonout )) || printf 'FAIL  %s\n' "$1"
}

ok() {
    (( jsonout )) || printf 'OK    %s\n' "$1"
    (( verbose )) && notes+=("$1")
}

# ── the wrapper contract ────────────────────────────────────────────────────
#
# wrapper-path | launcher-script | forwarded-arguments (space separated)
#
# The forwarded arguments are what the wrapper must pass *in addition to*
# `"$@"`. An empty field means the wrapper is a plain passthrough.
#
# This table is the single source of the contract. README.md describes it in
# prose and neither is allowed to drift; both are checked here (the README
# claim is verified in section 5).
CONTRACT='
bin/imsisting|imsisting.sh|
bin/imsisting-gui|imsisting.sh|--gui
bin/imsisting-tui|imsisting.sh|--tui
bin/stinglab|stinglab.sh|
'

# ── 1 + 3: exercise each wrapper against a recording stub ───────────────────

# A stub that records the target it was asked to exec and the arguments it was
# handed, then exits 0 without running anything. It lives in a temp directory
# and is removed with it, so no stale copy can influence a later run.
STUBDIR="$(mktemp -d "${TMPDIR:-/tmp}/check-launchers.XXXXXX")"
cleanup() { rm -rf "$STUBDIR"; }
trap cleanup EXIT

RECORD="$STUBDIR/record"
: > "$RECORD"

# The wrapper resolves its target relative to its own realpath, so the stub
# must sit at the path the wrapper computes -- which is the real launcher. We
# therefore cannot stub by PATH alone; instead the recording happens by making
# the launcher itself note the call. That is achieved with a wrapper-specific
# environment variable the launcher is required to honour only for this gate:
# IMSISTING_LAUNCH_TRACE. The launcher does not read it; bash does not either.
#
# So the recording is done the portable way: run the wrapper with a BASH_ENV
# file that defines a function named `exec` shadowing the builtin for the
# duration of that shell. `exec` is a builtin, and a shell function takes
# precedence over a builtin of the same name, so the wrapper's `exec` call hits
# the function and never replaces the process.
cat > "$STUBDIR/bashenv" <<'STUB'
exec() {
    {
        printf 'TARGET\t%s\n' "${1:-}"
        shift || true
        printf 'ARG\t%s\n' "$@"
    } >> "$CHECK_LAUNCHERS_RECORD"
    exit 0
}
STUB

check_wrapper() {
    local wrapper="$1" launcher="$2" fwd="$3"
    local full="$ROOT/$wrapper"
    local name
    name="$(basename "$wrapper")"

    # 1. presence and executability
    if [[ ! -f "$full" ]]; then
        problem "$wrapper: missing"
        return
    fi
    if [[ -L "$full" ]]; then
        problem "$wrapper: symlink (the contract ships a real file)"
        return
    fi
    if [[ ! -x "$full" ]]; then
        problem "$wrapper: not executable (chmod +x)"
        return
    fi

    # 2. static exec target: the wrapper must name the launcher it forwards to.
    #    Resolved by reading the wrapper, not by assuming the table is right --
    #    a wrapper pointing somewhere else is exactly the drift this catches.
    if ! grep -qF "$launcher" "$full"; then
        problem "$wrapper: does not reference $launcher"
        return
    fi

    # 3. dynamic: run it with the recording shell, mark the arguments with a
    #    sentinel so the forwarded ones are distinguishable from "$@".
    : > "$RECORD"
    local sentinel_a="--selftest-sentinel"
    local sentinel_b="positional-two"
    CHECK_LAUNCHERS_RECORD="$RECORD" \
    BASH_ENV="$STUBDIR/bashenv" \
        bash "$full" "$sentinel_a" "$sentinel_b" >/dev/null 2>&1
    local rc=$?

    if (( rc != 0 )); then
        problem "$wrapper: exited $rc when traced"
        return
    fi

    local target
    target="$(awk -F'\t' '$1=="TARGET"{print $2; exit}' "$RECORD")"
    if [[ -z "$target" ]]; then
        problem "$wrapper: never called exec"
        return
    fi
    case "$target" in
        *"/$launcher") ;;
        *) problem "$wrapper: execs $target, expected .../$launcher"; return ;;
    esac

    local -a args=()
    while IFS=$'\t' read -r kind val; do
        [[ "$kind" == "ARG" ]] && args+=("$val")
    done < "$RECORD"

    # The forwarded arguments must come first, in order, then the sentinels.
    local idx=0 expect
    for expect in $fwd; do
        if [[ "${args[$idx]:-}" != "$expect" ]]; then
            problem "$wrapper: argument $idx is '${args[$idx]:-<none>}', expected '$expect'"
            return
        fi
        idx=$((idx + 1))
    done

    # "$@" must survive verbatim, sentinels and all.
    if [[ "${args[$idx]:-}" != "$sentinel_a" || "${args[$((idx + 1))]:-}" != "$sentinel_b" ]]; then
        problem "$wrapper: drops or mangles \"\$@\" (got '${args[*]:-<none>}')"
        return
    fi

    ok "$wrapper → $launcher${fwd:+ $fwd} + \"\$@\""
}

while IFS='|' read -r wrapper launcher fwd; do
    [[ -z "$wrapper" ]] && continue
    check_wrapper "$wrapper" "$launcher" "$fwd"
done <<< "$CONTRACT"

# ── 2b: the launchers the wrappers point at must themselves be executable ───

for launcher in imsisting.sh stinglab.sh; do
    if [[ ! -x "$ROOT/$launcher" ]]; then
        problem "$launcher: not executable"
    fi
done

# ── 4: every forwarded subcommand must exist in the launcher's dispatch ─────
#
# Read the dispatch case arms out of imsisting.sh rather than trusting a list.
# An arm is a line at statement position naming a long flag, as in:
#     --gui)
# The launcher accepts several spellings per arm; matching the first token of
# the arm is what a wrapper forwarding `--gui` will actually hit.

launcher_arms="$(
    awk '/^[[:space:]]*--[a-z0-9-]+\)/ { line=$0
          sub(/^[[:space:]]*/, "", line); sub(/\).*$/, "", line)
          n=split(line, parts, "|")
          for (i=1; i<=n; i++) { gsub(/[[:space:]]/, "", parts[i]); print parts[i] }
        }' "$ROOT/imsisting.sh" 2>/dev/null | sort -u
)"

if [[ -z "$launcher_arms" ]]; then
    problem "could not parse the flag dispatch out of imsisting.sh"
else
    while IFS='|' read -r wrapper launcher fwd; do
        [[ "$launcher" == "imsisting.sh" ]] || continue
        for flag in $fwd; do
            if ! grep -qxF -- "$flag" <<< "$launcher_arms"; then
                problem "$wrapper forwards $flag, which imsisting.sh does not dispatch"
            fi
        done
    done <<< "$CONTRACT"
fi

# ── 5: the README must not promise a wrapper the contract does not ship ─────
#
# README.md:74-85 names the shortcuts and tells the user to put bin/ on PATH.
# A README that advertises a wrapper the tree does not ship is the same class
# of lie as a dead table entry, so it is checked here rather than reviewed.

readme="$ROOT/README.md"
if [[ -r "$readme" ]]; then
    # Only the shortcut paragraph, so a wrapper named in some other context
    # does not count as a promise.
    #
    # The paragraph is read as ONE record, not as the lines under a heading.
    # The lead sentence is hard-wrapped across two lines, and the second line
    # starts at column zero -- so any line-oriented extraction sees the name
    # on the first line only when the wrap happens to fall somewhere else, and
    # a reflow of the README silently changes which wrappers it "promises".
    # awk's paragraph mode (RS="") hands back the whole block, wraps included,
    # and the extraction then searches the block as text rather than as lines.
    # The blank line that ends the paragraph is the only delimiter relied on;
    # the fence that follows it is not, because a paragraph mode record may
    # legitimately carry one.
    promised="$(awk 'BEGIN { RS = "" }
                     /^\*\*Shortcuts\.\*\*/ { print; exit }' "$readme" |
                grep -oE '`(imsisting|imsisting-gui|imsisting-tui|stinglab)( [^`]*)?`' |
                sed 's/`//g' | awk '{print $1}' | sort -u)"
    if [[ -z "$promised" ]]; then
        problem "README.md shortcut block names no wrapper (expected at least imsisting)"
    else
        while IFS= read -r name; do
            if ! grep -qE "^bin/${name}\|" <<< "$CONTRACT"; then
                problem "README.md promises '$name' but bin/$name is not in the contract"
            fi
        done <<< "$promised"
    fi
else
    problem "README.md: missing"
fi

# ── 6: the shim layer must not reach outside the tree ──────────────────────
#
# A wrapper that hard-codes an absolute install prefix works on one machine and
# fails on every other. The rule is the same as check-paths.sh section 1: paths
# are computed, never baked in.

while IFS='|' read -r wrapper _rest; do
    [[ -z "$wrapper" ]] && continue
    [[ -f "$ROOT/$wrapper" ]] || continue
    if grep -qE '(^|[[:space:]/])/(home|usr|opt|Users)/' "$ROOT/$wrapper"; then
        problem "$wrapper: contains an absolute install path"
    fi
done <<< "$CONTRACT"

# ── report ─────────────────────────────────────────────────────────────────

if (( jsonout )); then
    printf '{"fail":%d,"wrappers":%d,"problems":[' "$fail" "$(grep -cE '^bin/' <<< "$CONTRACT")"
    for i in "${!problems[@]}"; do
        (( i > 0 )) && printf ','
        printf '"%s"' "${problems[$i]//\"/\\\"}"
    done
    printf ']}\n'
else
    printf '\n'
    if (( fail == 0 )); then
        printf 'all launcher checks passed\n'
    else
        printf '%d problem(s)\n' "$fail"
    fi
fi

(( fail == 0 )) || exit 1
exit 0
