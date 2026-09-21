#!/bin/sh
#
# Runtime check: run the real Bandizip.exe inside a wine prefix and let the
# built version.dll report what it patched.  Needs wine (64-bit) and xvfb-run.
#
#   make                       # builds dist/version.dll
#   tools/wine_test.sh /path/to/bandizip   # loads it into Bandizip.exe and prints the log
#
# Wine's own System32\version.dll is a builtin stub, so the override
# "version=n,b" is needed here to make wine pick the native DLL from the
# application directory.  Windows needs no override: version.dll is not a
# KnownDLL, so the application directory wins by the normal search order.
#
set -eu

APPDIR=$(cd "${1:-.}" && pwd)
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SANDBOX=$(mktemp -d)
PREFIX="${WINEPREFIX:-$HOME/.wine-bztest}"
LOGFILE="$SANDBOX/bzpatch.log"
LOGWIN="Z:$(printf '%s' "$LOGFILE" | tr / '\\')"

if [ ! -f "$ROOT/dist/version.dll" ]; then
    echo "dist/version.dll missing - run make first" >&2
    exit 1
fi

cp "$APPDIR/Bandizip.exe" "$SANDBOX/"
for extra in VersionNo.ini config.ini data langs; do
    [ -e "$APPDIR/$extra" ] && cp -r "$APPDIR/$extra" "$SANDBOX/"
done
cp "$ROOT/dist/version.dll" "$SANDBOX/version.dll"

[ -d "$PREFIX" ] || xvfb-run -a wineboot -i >/dev/null 2>&1

cd "$SANDBOX"
BZPATCH_LOG="$LOGWIN" WINEDLLOVERRIDES="version=n,b" \
    xvfb-run -a timeout 40 wine Bandizip.exe >/dev/null 2>&1 || true

echo "--- $LOGFILE ---"
if [ -s "$LOGFILE" ]; then
    cat "$LOGFILE"
else
    echo "(empty: version.dll did not run or did not log)"
fi
rm -rf "$SANDBOX"
