#!/usr/bin/env bash
# Build a self-contained .deb for VRA.
#
# Works anywhere dpkg-deb exists (Debian/Ubuntu, Termux, GitHub Actions).
# The package ships the pure-Python sources; the optional native accelerator
# is compiled at install time by postinst when a C compiler is available.
#
# Usage:  packaging/build_deb.sh  [output-dir]   (default: REPO_ROOT/dist)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

VERSION="$(cd "$REPO_ROOT" && grep -m1 '^version' pyproject.toml | sed -E 's/^version[[:space:]]*=[[:space:]]*["'\'' ][^0-9]*([0-9.]+).*/\1/')"
: "${VERSION:=0.1.0}"

PKG_NAME="vra_${VERSION}_all.deb"
OUT_DIR="${1:-$REPO_ROOT/dist}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

echo "==> Building $PKG_NAME (version $VERSION)"
echo "    repo:     $REPO_ROOT"
echo "    output:   $OUT_DIR"

STAGE_DEB="$STAGE/DEBIAN"
STAGE_BIN="$STAGE/usr/bin"
STAGE_LIB="$STAGE/usr/lib/vra"
STAGE_DOC="$STAGE/usr/share/doc/vra"

mkdir -p "$STAGE_DEB" "$STAGE_BIN" "$STAGE_LIB" "$STAGE_DOC"

# --- metadata -------------------------------------------------------------
cp "$SCRIPT_DIR/deb/control" "$STAGE_DEB/control"
cp "$SCRIPT_DIR/deb/postinst" "$STAGE_DEB/postinst"
chmod 755 "$STAGE_DEB/postinst"

# --- executable shim ------------------------------------------------------
cp "$SCRIPT_DIR/vra-bin" "$STAGE_BIN/vra"
chmod 755 "$STAGE_BIN/vra"

# --- python sources (no build caches / prebuilt extensions) ---------------
cp "$REPO_ROOT/pyproject.toml" "$STAGE_LIB/"
mkdir -p "$STAGE_LIB/vra"
# shellcheck disable=SC2164
( cd "$REPO_ROOT" && tar --exclude='__pycache__' --exclude='*.pyc' --exclude='*.so' \
    --exclude='*.egg-info' -cf - vra ) | ( cd "$STAGE_LIB" && tar -xf - )

# --- documentation ---------------------------------------------------------
cp "$REPO_ROOT/LICENSE" "$STAGE_DOC/copyright" 2>/dev/null || cp "$REPO_ROOT/LICENSE" "$STAGE_DOC/" 2>/dev/null || true
cp "$REPO_ROOT/README.md" "$STAGE_DOC/" 2>/dev/null || true
[ -d "$REPO_ROOT/docs" ] && cp -r "$REPO_ROOT/docs" "$STAGE_DOC/docs"
[ -d "$REPO_ROOT/examples" ] && cp -r "$REPO_ROOT/examples" "$STAGE_DOC/examples"
find "$STAGE" -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
find "$STAGE" -name '*.pyc' -delete 2>/dev/null || true

# --- build the archive ----------------------------------------------------
mkdir -p "$OUT_DIR"
dpkg-deb --build --root-owner-group "$STAGE" "$OUT_DIR/$PKG_NAME" >/dev/null

echo "==> OK: $OUT_DIR/$PKG_NAME"
echo "    installed size: $(du -sh "$STAGE" | cut -f1)"