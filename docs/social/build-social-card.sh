#!/usr/bin/env bash
# Render the 1600x900 Shukra cards to real PNGs:
#   shukra-social-card.html       -> docs/shukra-social.png       (README, light)
#                                 -> web/public/og.png            (Open Graph and X card; byte-identical to the light PNG)
#   shukra-social-card-dark.html  -> docs/shukra-social-dark.png  (README <picture> for dark themes only; not copied to the site)
# Needs Google Chrome and macOS `sips` (both already on a Mac); nothing is installed.
#   ./docs/social/build-social-card.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
[[ -x "$CHROME" ]] || { echo "Google Chrome not found (set CHROME=...)" >&2; exit 1; }

shot() {
  local html="$1" out="$2" raw
  raw="$(mktemp "${TMPDIR:-/tmp}/shukra-card.XXXXXX.png")"
  "$CHROME" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
    --window-size=1600,900 --screenshot="$raw" "file://$html" >/dev/null 2>&1
  sips -s format png "$raw" --out "$out" >/dev/null
  rm -f "$raw"
}

shot "$HERE/shukra-social-card.html" "$ROOT/docs/shukra-social.png"
shot "$HERE/shukra-social-card-dark.html" "$ROOT/docs/shukra-social-dark.png"
cp "$ROOT/docs/shukra-social.png" "$ROOT/web/public/og.png"

for f in "$ROOT/docs/shukra-social.png" "$ROOT/docs/shukra-social-dark.png" "$ROOT/web/public/og.png"; do
  echo "wrote $f ($(sips -g pixelWidth -g pixelHeight "$f" | awk '/pixel/{printf "%s ", $2}')px, $(du -k "$f" | cut -f1) KB)"
done
