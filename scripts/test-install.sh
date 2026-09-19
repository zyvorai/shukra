#!/usr/bin/env bash
# Tests deploy/install.sh by staging into a temporary root. It touches no service.
# Run from anywhere:  scripts/test-install.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "${T}"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok:   $*"; }

# A release-shaped tree. The binaries only need to answer -version.
TREE="${T}/tree"
mkdir -p "${TREE}/bin" "${TREE}/deploy" "${TREE}/configs" "${TREE}/web/dist"
printf '#!/bin/sh\necho "shukra v0.0.0-test"\n' > "${TREE}/bin/shukrad"
printf '#!/bin/sh\necho "shukractl v0.0.0-test"\n' > "${TREE}/bin/shukractl"
chmod +x "${TREE}/bin/"*
cp "${ROOT}/deploy/install.sh" "${ROOT}/deploy/shukra.service" "${TREE}/deploy/"
cp "${ROOT}/configs/detections.example.yaml" "${TREE}/configs/"
echo "<html>console</html>" > "${TREE}/web/dist/index.html"

S="${T}/root"
export SHUKRA_INSTALL_ROOT="${S}"
unset SHUKRA_API_KEY SHUKRA_WEB_DIR SHUKRA_NO_START || true
ETC="${S}/etc/shukra"

# 1. A first install with no key generates one, prints it once, and never uses the dev key.
out="$("${TREE}/deploy/install.sh" 2>&1)"
[[ -x "${S}/usr/local/bin/shukrad" && -x "${S}/usr/local/bin/shukractl" ]] || fail "binaries not installed"
[[ -f "${S}/usr/local/share/shukra/web/index.html" ]] || fail "console not installed"
key="$(sed -n 's/^SHUKRA_API_KEY=//p' "${ETC}/env")"
[[ ${#key} -ge 32 ]] || fail "generated key is too short: '${key}'"
[[ "${key}" != "shukra" ]] || fail "the dev key was installed"
grep -q "${key}" <<<"${out}" || fail "the generated key was not shown to the installer"
[[ "$(stat -f %Lp "${ETC}/env" 2>/dev/null || stat -c %a "${ETC}/env")" == "600" ]] || fail "env file is not 0600"
pass "first install generates a private random key and shows it once"

# 2. The unit is rendered: no placeholders left, the right paths, no key in it.
unit="${S}/etc/systemd/system/shukra.service"
! grep -q '@[A-Z_]*@' "${unit}" || fail "unresolved placeholder in the unit"
grep -q '^ExecStart=/usr/local/bin/shukrad ' "${unit}" || fail "wrong ExecStart"
grep -q -- '-web /usr/local/share/shukra/web' "${unit}" || fail "wrong web dir"
! grep -q "${key}" "${unit}" || fail "the key is in the unit file"
grep -q '^EnvironmentFile=-/etc/shukra/env' "${unit}" || fail "the unit does not read the env file"
pass "unit is rendered, and the key is not in it"

# 3. A second install keeps the operator's edits and the existing key, and prints no new key.
echo "# my rules" >> "${ETC}/detections.yaml"
echo "SHUKRA_EXTRA_ARGS=-tls-cert /x -tls-key /y" >> "${ETC}/env"
out="$("${TREE}/deploy/install.sh" 2>&1)"
grep -q "# my rules" "${ETC}/detections.yaml" || fail "an edited detections.yaml was overwritten"
grep -q "keeping existing" <<<"${out}" || fail "did not say it kept the rules"
[[ "$(sed -n 's/^SHUKRA_API_KEY=//p' "${ETC}/env")" == "${key}" ]] || fail "the existing key changed"
grep -q '^SHUKRA_EXTRA_ARGS=-tls-cert /x' "${ETC}/env" || fail "an operator's env line was dropped"
! grep -q "Generated an admin key" <<<"${out}" || fail "printed a key it did not generate"
diff -q "${ETC}/detections.example.yaml" "${ROOT}/configs/detections.example.yaml" >/dev/null || fail "the sample was not refreshed"
pass "re-install keeps edited rules, the key and operator env lines"

# 4. A supplied key replaces the old one, once, and other lines still survive.
SHUKRA_API_KEY="supplied-key-123" "${TREE}/deploy/install.sh" >/dev/null 2>&1
[[ "$(grep -c '^SHUKRA_API_KEY=' "${ETC}/env")" == "1" ]] || fail "duplicate key lines"
grep -q '^SHUKRA_API_KEY=supplied-key-123$' "${ETC}/env" || fail "the supplied key was not written"
grep -q '^SHUKRA_EXTRA_ARGS=' "${ETC}/env" || fail "an operator's env line was dropped on key change"
pass "a supplied key replaces the old one"

# 5. A tree missing a file is refused, not half installed.
rm "${TREE}/bin/shukractl"
if "${TREE}/deploy/install.sh" >/dev/null 2>&1; then fail "an incomplete tree was installed"; fi
pass "an incomplete tree is refused"

echo "all install checks passed"
