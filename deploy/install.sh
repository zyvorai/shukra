#!/usr/bin/env bash
# Install Shukra on THIS host from a release directory or a source tree.
#
# It expects, relative to the directory above this script:
#   bin/shukrad  bin/shukractl  deploy/shukra.service  configs/detections.example.yaml
#   and optionally web/dist
#
# deploy-remote.sh, the release tarball and the .deb all use this one routine, so
# they cannot drift apart.
#
# Environment:
#   SHUKRA_API_KEY        the admin key. If unset and none is installed yet, a
#                         random one is generated and printed once. The
#                         well-known dev key is never used here.
#   SHUKRA_WEB_DIR        where the console lives (default: the installed copy)
#   SHUKRA_INSTALL_ROOT   stage under this prefix instead of /, and touch no
#                         service. For packaging and tests.
#   SHUKRA_NO_START=1     install but do not enable or restart the service
set -euo pipefail

SRC="$(cd "$(dirname "$0")/.." && pwd)"
STAGE="${SHUKRA_INSTALL_ROOT:-}"
BIN_DIR="${SHUKRA_BIN_DIR:-/usr/local/bin}"
SHARE_DIR="${SHUKRA_SHARE_DIR:-/usr/local/share/shukra}"
WEB_DIR="${SHUKRA_WEB_DIR:-${SHARE_DIR}/web}"
ETC="${STAGE}/etc/shukra"
UNIT="${STAGE}/etc/systemd/system/shukra.service"

SUDO=""
if [[ -z "${STAGE}" && "$(id -u)" -ne 0 ]]; then SUDO="sudo"; fi
run() { ${SUDO} "$@"; }

for f in bin/shukrad bin/shukractl deploy/shukra.service configs/detections.example.yaml; do
  [[ -e "${SRC}/${f}" ]] || { echo "install: ${f} is missing from ${SRC}" >&2; exit 1; }
done

run install -d "${STAGE}${BIN_DIR}" "${ETC}"
run install -m 755 "${SRC}/bin/shukrad" "${STAGE}${BIN_DIR}/shukrad"
run install -m 755 "${SRC}/bin/shukractl" "${STAGE}${BIN_DIR}/shukractl"

# The console is optional, and installed only when it was built.
if [[ -z "${SHUKRA_WEB_DIR:-}" && -d "${SRC}/web/dist" ]]; then
  run install -d "${STAGE}${WEB_DIR}"
  run cp -R "${SRC}/web/dist/." "${STAGE}${WEB_DIR}/"
fi

# Detection rules are the operator's to edit: install the sample only when there
# is none, and keep the current sample beside it for comparison.
if [[ -e "${ETC}/detections.yaml" ]]; then
  echo "keeping existing ${ETC#"${STAGE}"}/detections.yaml"
else
  run install -m 644 "${SRC}/configs/detections.example.yaml" "${ETC}/detections.yaml"
fi
run install -m 644 "${SRC}/configs/detections.example.yaml" "${ETC}/detections.example.yaml"

# Keys live in a root-only file, not in the unit: systemctl show prints a unit's
# Environment= to every local user. Lines an operator added (TLS, sinks) are kept.
run touch "${ETC}/env"
run chmod 600 "${ETC}/env"
KEY="${SHUKRA_API_KEY:-}"
GENERATED=""
if [[ -z "${KEY}" ]] && ! run grep -q '^SHUKRA_API_KEY=' "${ETC}/env"; then
  # An older deploy kept the key in the unit itself. Carry it over rather than
  # generate a new one and lock the operator out.
  old="$(run sed -n 's/^Environment=SHUKRA_API_KEY=//p' "${UNIT}" 2>/dev/null | head -1 || true)"
  if [[ -n "${old}" ]]; then
    KEY="${old}"
    echo "migrated the API key from the old unit file into ${ETC#"${STAGE}"}/env" >&2
  else
    KEY="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    GENERATED=1
  fi
fi
if [[ -n "${KEY}" ]]; then
  run sed -i.bak '/^SHUKRA_API_KEY=/d' "${ETC}/env" && run rm -f "${ETC}/env.bak"
  printf 'SHUKRA_API_KEY=%s\n' "${KEY}" | run tee -a "${ETC}/env" >/dev/null
fi

# CAP_BPF and CAP_PERFMON exist from Linux 5.8. Before that the unit needs full
# root, so the two capability lines come out and the rest of the hardening stays.
unit="$(sed -e "s#@WEB_DIR@#${WEB_DIR}#" -e "s#@BIN_DIR@#${BIN_DIR}#" "${SRC}/deploy/shukra.service")"
kver="$(uname -r | cut -d. -f1-2)"
if [[ "$(printf '%s\n5.8\n' "${kver}" | sort -V | head -1)" != "5.8" ]]; then
  echo "kernel ${kver} is older than 5.8: running with full root capabilities, other hardening kept" >&2
  unit="$(printf '%s\n' "${unit}" | grep -vE '^(CapabilityBoundingSet|AmbientCapabilities)=')"
fi
run install -d "$(dirname "${UNIT}")"
printf '%s\n' "${unit}" | run tee "${UNIT}" >/dev/null

if [[ -n "${STAGE}" ]]; then
  echo "staged under ${STAGE}; no service touched"
else
  run systemctl daemon-reload
  if [[ "${SHUKRA_NO_START:-}" != "1" ]]; then
    run systemctl enable shukra >/dev/null 2>&1 || true
    run systemctl restart shukra
    sleep 1
    run systemctl is-active shukra
  fi
fi

if [[ -n "${GENERATED}" ]]; then
  echo "Generated an admin key. It is stored in ${ETC#"${STAGE}"}/env, and this is the only time it is shown:"
  echo "  SHUKRA_API_KEY=${KEY}"
fi
echo "installed shukra $("${STAGE}${BIN_DIR}/shukrad" -version 2>/dev/null | awk '{print $2}' || true)"
