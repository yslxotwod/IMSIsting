#!/usr/bin/env bash
# =====================================================================
#  bump-version.sh — move VERSION forward, without tagging
#
#  `tools/release.sh` cuts a release: it refuses a dirty tree, commits,
#  tags and pushes. This is the other half — the number moves with the
#  work, so a push never carries a version that describes an older tree.
#
#  Usage:  tools/bump-version.sh patch        # 0.8.0 -> 0.8.1
#          tools/bump-version.sh minor        # 0.8.0 -> 0.9.0
#          tools/bump-version.sh major        # 0.8.0 -> 1.0.0
#          tools/bump-version.sh 1.2.3        # exactly that
#
#  It does not commit. The phase commit carries the number, which keeps
#  one commit per change rather than a bump commit that describes nothing.
#
#  VERSION is the only home of the number: imsisting.sh reads it at
#  startup and native/src/main1.c reads it at run time. The GUI header
#  takes it from native/builddir/config.h, which meson generates at
#  configure time — so after a bump, reconfigure or the header keeps
#  showing the old number. That is the one step this script prints and
#  does not perform, because a reconfigure needs to know where the build
#  directory is.
# =====================================================================
set -euo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

die() { printf 'bump-version: %s\n' "$*" >&2; exit 1; }

arg="${1:-}"
[[ -n "$arg" ]] || die "usage: tools/bump-version.sh patch|minor|major|X.Y.Z"

cur="$(cat VERSION 2>/dev/null || echo "")"
[[ "$cur" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "VERSION does not hold X.Y.Z, it holds: ${cur:-nothing}"

IFS=. read -r major minor patch <<< "$cur"

case "$arg" in
    patch)  next="$major.$minor.$((patch + 1))" ;;
    minor)  next="$major.$((minor + 1)).0" ;;
    major)  next="$((major + 1)).0.0" ;;
    *)
        [[ "$arg" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
            || die "version must be X.Y.Z or one of patch|minor|major, got: $arg"
        next="$arg"
        ;;
esac

# Forward only. A number that can go backwards is a number nothing can
# compare against, and "which build is this" stops having an answer.
newest=$(printf '%s\n%s\n' "$cur" "$next" | sort -V | tail -1)
[[ "$newest" == "$next" && "$next" != "$cur" ]] \
    || die "$next is not ahead of $cur"

printf '%s\n' "$next" > VERSION
printf 'bump-version: %s -> %s\n' "$cur" "$next"
printf 'bump-version: now reconfigure, or the GUI header keeps the old number:\n'
printf 'bump-version:   meson setup --reconfigure native/builddir && ninja -C native/builddir\n'
