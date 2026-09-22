#!/usr/bin/env bash
# Render docs/social/shukra-social-card.html (1600x900) to a real PNG and write it to both places the repo uses:
# docs/shukra-social.png (README) and web/public/og.png (Open Graph and X card). The two stay byte-identical.
# Needs Google Chrome and macOS `sips` (both already on a Mac); nothing is installed.
#   ./docs/social/build-social-card.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
[[ -x "$CHROME" ]] || { echo "Google Chrome not found (set CHROME=...)" >&2; exit 1; }
RAW="$(mktemp "${TMPDIR:-/tmp}/shukra-card.XXXXXX.png")"
trap 'rm -f "$RAW"' EXIT
"$CHROME" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
  --window-size=1600,900 --screenshot="$RAW" "file://$HERE/shukra-social-card.html" >/dev/null 2>&1
sips -s format png "$RAW" --out "$ROOT/docs/shukra-social.png" >/dev/null
cp "$ROOT/docs/shukra-social.png" "$ROOT/web/public/og.png"
for f in "$ROOT/docs/shukra-social.png" "$ROOT/web/public/og.png"; do
  echo "wrote $f ($(sips -g pixelWidth -g pixelHeight "$f" | awk '/pixel/{printf "%s ", $2}')px, $(du -k "$f" | cut -f1) KB)"
done
