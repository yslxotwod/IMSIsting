#!/usr/bin/env bash
# =====================================================================
#  make-tarball.sh — cut a source tarball from a tag
#
#  `git archive` is the right tool and it is not quite enough: the tree
#  expects five runtime directories that are deliberately never committed
#  (captures, logs, loot, state, tmp), so an archive straight from the tag
#  extracts to something that fails `tools/check-paths.sh` and cannot start.
#  This script archives the tag and adds those five empty directories, then
#  extracts the result somewhere else and proves it before reporting.
#
#  Usage:  tools/make-tarball.sh [X.Y.Z]
#
#  Without an argument the version in VERSION is used. The tag v<version>
#  must already exist: a tarball is a published artefact, so the thing it
#  was built from has to be in the repository first.
#
#  Exit: 0 built and verified, 1 could not build or the proof failed, 2 a
#  precondition is not met (dirty tree, missing tag, bad version).
# =====================================================================
set -euo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

die() { printf 'make-tarball: %s\n' "$*" >&2; exit 2; }

# The five directories the modules write into and git must not carry.
RUNTIME_DIRS=(captures logs loot state tmp)

ver="${1:-$(cat VERSION)}"
[[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "version must be X.Y.Z, got: $ver"

tag="v$ver"
git rev-parse -q --verify "refs/tags/$tag" >/dev/null \
    || die "no tag $tag — tag the commit before cutting a release tarball"

# An artefact built from uncommitted work is not the artefact the tag names.
git diff --quiet && git diff --cached --quiet \
    || die "working tree has uncommitted changes; the tarball would not be $tag"

commit="$(git rev-list -n1 "$tag")"
out="IMSIsting-$ver.tar.gz"
work="$(mktemp -d "${TMPDIR:-/tmp}/imsisting-tarball.XXXXXX")"
trap 'rm -rf "$work"' EXIT

# Archive the tag, not the working tree.
git archive --format=tar --prefix="IMSIsting-$ver/" "$tag" > "$work/src.tar" \
    || die "git archive failed for $tag"

# Add the empty runtime directories inside the archive's prefix.
mkdir -p "$work/add"
for d in "${RUNTIME_DIRS[@]}"; do
    mkdir -p "$work/add/IMSIsting-$ver/$d"
done

tar --append --file="$work/src.tar" -C "$work/add" "IMSIsting-$ver" \
    || die "could not append the runtime directories"

gzip -9 -n -c "$work/src.tar" > "$work/$out" || die "gzip failed"

# Prove it before publishing it: an archive nobody has extracted is a guess.
mkdir -p "$work/verify"
tar -xzf "$work/$out" -C "$work/verify" || die "the tarball does not extract"
vdir="$work/verify/IMSIsting-$ver"

[[ -x "$vdir/modules/01_radio.sh" ]] || { chmod +x "$vdir"/modules/*.sh "$vdir"/tools/*.sh 2>/dev/null || true; }

if ! ( cd "$vdir" && ./tools/check-paths.sh >/dev/null 2>&1 ); then
    printf 'make-tarball: check-paths failed inside the extracted tree\n' >&2
    ( cd "$vdir" && ./tools/check-paths.sh 2>&1 | tail -5 >&2 ) || true
    exit 1
fi

# A module has to run from the extracted tree with nothing else from here.
#
# The output is captured BEFORE it is searched. Piping the module straight into
# `grep -q` fails under `set -o pipefail` even when the module is healthy: grep
# exits at the first match, the module is still writing its later rows, takes
# SIGPIPE and reports 141, and the pipeline inherits it. That reads as "a
# module did not run" for a module that ran perfectly.
smoke=""
smoke=$( cd "$vdir" && bash modules/26_ss7_map.sh --sgsap-build \
          location-update-request --imsi 310150123456789 \
          --lai 310-150-4660 2>/dev/null ) || smoke=""
if ! printf '%s\n' "$smoke" | grep -q '^hex'; then
    printf 'make-tarball: a module did not run from the extracted tree\n' >&2
    exit 1
fi

mv "$work/$out" "$out"
bytes=$(stat -c %s "$out")
files=$(tar -tzf "$out" | grep -vc '/$' || true)
sha=$(sha256sum "$out" | cut -d' ' -f1)

printf 'file\t%s\n'    "$ROOT/$out"
printf 'version\t%s\n' "$ver"
printf 'tag\t%s\n'     "$tag"
printf 'commit\t%s\n'  "$(git rev-parse --short "$commit")"
printf 'bytes\t%s\n'   "$bytes"
printf 'files\t%s\n'   "$files"
printf 'sha256\t%s\n'  "$sha"
printf 'verified\tyes (extracted, check-paths passed, a module ran)\n'
