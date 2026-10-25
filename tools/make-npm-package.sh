#!/usr/bin/env bash
# tools/make-npm-package.sh — stamp the npm wrapper from a release tarball, then pack it.
#
#   tools/make-npm-package.sh                       # newest IMSIsting-*.tar.gz in the repo root
#   tools/make-npm-package.sh IMSIsting-1.0.0.tar.gz
#   tools/make-npm-package.sh --vendor …            # also copy the tarball into the package (43 MB)
#   tools/make-npm-package.sh --verify …            # install the packed .tgz into a temp prefix and run it
#
# What it does, in order:
#   1. derive the release version from the tarball's name (IMSIsting-<version>.tar.gz)
#   2. compute its sha256 and size, and write both into dist/npm/package.json under
#      imsisting.artifacts[<version>] — the wrapper refuses a tarball that disagrees
#   3. set dist/npm/package.json version + imsisting.release to match
#   4. npm pack into dist/, then print the artefact name, size and sha256
#
# The npm package never contains the toolkit: 43 MB of bash, python and GTK is a
# release artefact, not a node module. The wrapper fetches it once into a cache
# directory and verifies it there.

set -euo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG_DIR="$ROOT/dist/npm"
VENDOR=0
VERIFY=0
TARBALL=""

for arg in "$@"; do
    case "$arg" in
        --vendor) VENDOR=1 ;;
        --verify) VERIFY=1 ;;
        -h|--help)
            sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        -*)
            printf 'make-npm-package: unknown flag: %s\n' "$arg" >&2
            exit 2 ;;
        *) TARBALL="$arg" ;;
    esac
done

# npm wants a private cache and log directory; on a locked-down box ~/.npm may be
# read-only, and a packer that fails on EROFS is a packer nobody trusts.
NPM_CACHE="$(mktemp -d "${TMPDIR:-/tmp}/imsisting-npm.XXXXXX")"
trap 'rm -rf "$NPM_CACHE"' EXIT
export npm_config_cache="$NPM_CACHE"
export npm_config_logs_dir="$NPM_CACHE/_logs"

command -v node >/dev/null 2>&1 || { printf 'make-npm-package: node is required to stamp package.json\n' >&2; exit 1; }
command -v npm  >/dev/null 2>&1 || { printf 'make-npm-package: npm is required to pack\n' >&2; exit 1; }
[ -d "$PKG_DIR" ] || { printf 'make-npm-package: no dist/npm in %s\n' "$ROOT" >&2; exit 1; }

if [ -z "$TARBALL" ]; then
    TARBALL="$(ls -1 "$ROOT"/IMSIsting-*.tar.gz 2>/dev/null | sort -V | tail -1 || true)"
    [ -n "$TARBALL" ] || { printf 'make-npm-package: no IMSIsting-*.tar.gz in %s — run tools/make-tarball.sh first\n' "$ROOT" >&2; exit 1; }
fi
[ -f "$TARBALL" ] || { printf 'make-npm-package: no such tarball: %s\n' "$TARBALL" >&2; exit 1; }

base="$(basename "$TARBALL")"
case "$base" in
    IMSIsting-*.tar.gz) VERSION="${base#IMSIsting-}"; VERSION="${VERSION%.tar.gz}" ;;
    *) printf 'make-npm-package: %s is not named IMSIsting-<version>.tar.gz\n' "$base" >&2; exit 1 ;;
esac
case "$VERSION" in
    [0-9]*.[0-9]*) : ;;
    *) printf 'make-npm-package: release version "%s" is not x.y.z\n' "$VERSION" >&2; exit 1 ;;
esac

SHA="$(sha256sum "$TARBALL" | awk '{print $1}')"
BYTES="$(stat -c '%s' "$TARBALL")"

printf 'release  %s\n' "$VERSION"
printf 'tarball  %s\n' "$base"
printf 'sha256   %s\n' "$SHA"
printf 'bytes    %s\n' "$BYTES"

# Stamp package.json with node so JSON stays JSON (no sed surgery on a document
# a package manager will parse).
PKG_DIR="$PKG_DIR" TARBALL="$TARBALL" VERSION="$VERSION" SHA="$SHA" BYTES="$BYTES" VENDOR="$VENDOR" node -e '
const fs = require("fs");
const path = require("path");
const file = path.join(process.env.PKG_DIR, "package.json");
const pkg = JSON.parse(fs.readFileSync(file, "utf8"));
pkg.version = process.env.VERSION;
pkg.imsisting = pkg.imsisting || {};
pkg.imsisting.release = process.env.VERSION;
pkg.imsisting.artifacts = pkg.imsisting.artifacts || {};
pkg.imsisting.artifacts[process.env.VERSION] = {
    sha256: process.env.SHA,
    bytes: Number(process.env.BYTES),
};
fs.writeFileSync(file, JSON.stringify(pkg, null, 2) + "\n");
if (process.env.VENDOR === "1") {
    const dest = path.join(process.env.PKG_DIR, "IMSIsting-" + process.env.VERSION + ".tar.gz");
    fs.copyFileSync(process.env.TARBALL, dest);
    console.log("vendored " + path.basename(dest));
}
'

# The wrapper must at least parse and answer before it is packed.
node "$PKG_DIR/bin/imsisting.js" --npm-help >/dev/null || {
    printf 'make-npm-package: the wrapper does not run — refusing to pack\n' >&2
    exit 1
}

out="$(cd "$PKG_DIR" && npm pack --pack-destination "$ROOT/dist" 2>/dev/null | tail -1)"
tgz="$ROOT/dist/$(basename "$out")"
[ -f "$tgz" ] || { printf 'make-npm-package: npm pack produced nothing\n' >&2; exit 1; }

printf '\npackage  %s\n' "$(basename "$tgz")"
printf 'bytes    %s\n' "$(stat -c '%s' "$tgz")"
printf 'sha256   %s\n' "$(sha256sum "$tgz" | awk '{print $1}')"
printf 'install  npm install -g %s\n' "$(basename "$tgz")"

if [ "$VERIFY" = "1" ]; then
    prefix="$ROOT/tmp/npm-verify"
    cache="$ROOT/tmp/npm-verify-cache"
    rm -rf "$prefix" "$cache"
    mkdir -p "$prefix"
    npm install -g --prefix "$prefix" "$tgz" >/dev/null 2>&1 || {
        printf 'make-npm-package: the packed tarball does not install\n' >&2
        exit 1
    }
    bin="$prefix/bin/imsisting"
    [ -x "$bin" ] || { printf 'make-npm-package: no bin/imsisting after install\n' >&2; exit 1; }
    IMSISTING_CACHE="$cache" IMSISTING_TARBALL="$TARBALL" "$bin" --npm-install >/dev/null
    got="$(IMSISTING_CACHE="$cache" "$bin" --version)"
    case "$got" in
        *"v$VERSION"*) printf '\nverify   %s\n' "$got" ;;
        *) printf 'make-npm-package: installed wrapper printed "%s", expected v%s\n' "$got" "$VERSION" >&2; exit 1 ;;
    esac
    IMSISTING_CACHE="$cache" "$bin" --npm-module 06 --selftest >/dev/null 2>&1 && \
        printf 'verify   06_gsm_air --selftest PASS through the installed wrapper\n'
fi
