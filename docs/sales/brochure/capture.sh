#!/usr/bin/env bash
# Capture the console pages for the brochure from fixture mode (no daemon, no live data).
#   ./docs/sales/brochure/capture.sh [page ...]      # default: every page
#
# Needs node/npm (web/node_modules installed with `npm ci`), and Python 3 with Playwright and its Chromium
# (`pip install playwright && playwright install chromium`). Writes docs/sales/brochure/shots/<page>.png at 1440 px wide, as tall as the page needs (640 to 1900 px).
# The shots show fixture data (web/src/fixtures.ts). Caption them "illustrative", never as a live host.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WEB="$HERE/../../../web"
OUT="$HERE/shots"
PORT="${PORT:-5173}"
mkdir -p "$OUT"

cd "$WEB"
# Run the vite binary itself (not npx), so killing $SERVER really stops the dev server.
VITE_FIXTURE=1 node node_modules/vite/bin/vite.js --port "$PORT" --strictPort --host 127.0.0.1 >/dev/null 2>&1 &
SERVER=$!
trap 'kill "$SERVER" 2>/dev/null || true; wait "$SERVER" 2>/dev/null || true' EXIT
for _ in $(seq 1 60); do
  curl -sf "http://127.0.0.1:$PORT/" >/dev/null 2>&1 && break
  sleep 0.5
done
curl -sf "http://127.0.0.1:$PORT/" >/dev/null || { echo "dev server did not start on :$PORT" >&2; exit 1; }

PORT="$PORT" OUT="$OUT" python3 - "$@" <<'PY'
import os, sys
from playwright.sync_api import sync_playwright

port, out = os.environ["PORT"], os.environ["OUT"]
ALL = ["overview", "vms", "recorder", "explain", "kvm", "sched", "contention", "block",
       "programs", "connections", "drops", "detections", "isolate"]
pages = sys.argv[1:] or ALL

# Fixture mode signs in with the token "shukra"; the console keeps it in sessionStorage.
INIT = "sessionStorage.setItem('shukra-token', 'shukra');"
# The overview says "Fixture data..." in a warning. The brochure captions carry that statement instead.
HIDE = "document.querySelectorAll('p.warning').forEach(p => { if (p.textContent.startsWith('Fixture data')) p.remove(); });"

with sync_playwright() as p:
    b = p.chromium.launch(args=["--lang=en-US"])
    ctx = b.new_context(viewport={"width": 1440, "height": 900}, device_scale_factor=1, color_scheme="dark", locale="en-US")
    ctx.add_init_script(INIT)
    for name in pages:
        page = ctx.new_page()
        page.goto(f"http://127.0.0.1:{port}/#page={name}")
        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(600)
        page.evaluate(HIDE)
        if name == "isolate":
            page.get_by_role("button", name="Isolate…").click()
            page.wait_for_selector("[role=alertdialog]")
        # Fit the shot to the page: content bottom plus a margin, between 640 and 1900 px tall.
        bottom = page.evaluate("Math.ceil(document.querySelector('main').getBoundingClientRect().bottom + window.scrollY)")
        page.set_viewport_size({"width": 1440, "height": max(640, min(1900, bottom + 40))})
        page.wait_for_timeout(200)
        page.mouse.move(1430, 5)
        page.screenshot(path=os.path.join(out, f"{name}.png"))
        page.close()
        print("wrote", name)
    b.close()
PY

# Three same-size crops for the README's screenshot strip: (page, top offset in px). The offsets skip the page header.
# Needs Pillow; skipped where a shot was not taken.
OUT="$OUT" python3 - <<'PY'
import os
from PIL import Image
out = os.environ["OUT"]
for name, top in (("overview", 0), ("explain", 270), ("contention", 290)):
    src = os.path.join(out, name + ".png")
    if os.path.exists(src):
        im = Image.open(src)
        im.crop((0, top, im.width, min(im.height, top + 820))).save(os.path.join(out, "readme-" + name + ".png"), optimize=True)
        print("wrote readme-" + name)
PY
