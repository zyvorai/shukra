#!/usr/bin/env bash
# Shukra — remote deploy (SSH + rsync + host build)
#
# Shukra attaches eBPF on the hypervisor. It is not a cluster chart.
# This script follows Netra's deploy-remote entrypoint (HOST USER, rsync,
# remote build, operator CLI on PATH, env file, then a live check).
#
# Usage:
#   ./scripts/deploy-remote.sh user@10.0.1.5
#   ./scripts/deploy-remote.sh 80.79.5.173 sus
#   ./scripts/deploy-remote.sh 80.79.5.173 sus --verify-only
#
# SHUKRA_REMOTE_SUBDIR overrides the checkout under $HOME
# (default: .deployments/shukra).
# UI/API: :30970
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

DRY_RUN=false
VERIFY_ONLY=false
TARGET=""
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o ServerAliveInterval=30)
POSITIONAL=()

usage() {
  sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage ;;
    --dry-run) DRY_RUN=true; shift ;;
    --verify-only) VERIFY_ONLY=true; shift ;;
    -*)
      echo "unknown flag: $1" >&2
      exit 2
      ;;
    *)
      POSITIONAL+=("$1")
      shift
      ;;
  esac
done

if [[ ${#POSITIONAL[@]} -eq 1 ]]; then
  TARGET="${POSITIONAL[0]}"
elif [[ ${#POSITIONAL[@]} -eq 2 ]]; then
  if [[ "${POSITIONAL[0]}" == *@* ]]; then
    TARGET="${POSITIONAL[0]}"
  elif [[ "${POSITIONAL[1]}" == *@* ]]; then
    TARGET="${POSITIONAL[1]}"
  else
    TARGET="${POSITIONAL[1]}@${POSITIONAL[0]}"
  fi
elif [[ ${#POSITIONAL[@]} -gt 2 ]]; then
  echo "usage: $0 user@host   or   $0 HOST USER" >&2
  exit 2
fi

if [[ -z "${TARGET}" ]]; then
  echo "usage: $0 user@host   or   $0 HOST USER" >&2
  exit 2
fi

API_KEY_LOCAL="${SHUKRA_API_KEY:-shukra}"

ssh_host() { ssh "${SSH_OPTS[@]}" "$TARGET" "$@"; }
REMOTE_HOME="$(ssh_host 'printf %s "$HOME"')"
REMOTE_DIR="${REMOTE_HOME}/${SHUKRA_REMOTE_SUBDIR:-.deployments/shukra}"

log() { printf '[shukra-deploy] %s\n' "$*"; }

if $VERIFY_ONLY; then
  ssh_host "bash -s" <<EOF
set -euo pipefail
export SHUKRA_URL="http://127.0.0.1:30970"
export SHUKRA_API_KEY="${API_KEY_LOCAL}"
export SHUKRA_CLI_NO_BANNER=1
export SHUKRA_CLI_COLOR=false
export SHUKRA_SKIP_DOTENV=1
systemctl is-active shukra
shukractl status
shukractl programs
shukractl vms
shukractl trace list
curl -sf -H "Authorization: Bearer ${API_KEY_LOCAL}" "\$SHUKRA_URL/api/v1/status"
echo
EOF
  exit 0
fi

log "sync → ${TARGET}:${REMOTE_DIR}"
if ! $DRY_RUN; then
  ssh_host "mkdir -p ${REMOTE_DIR}"
  rsync -az --delete \
    --exclude '.git' --exclude 'bin' --exclude 'web/node_modules' --exclude 'web/dist' \
    --exclude 'bpf/*.o' --exclude 'bpf/vmlinux.h' --exclude '.DS_Store' --exclude '.cursor' \
    "${ROOT}/" "${TARGET}:${REMOTE_DIR}/"
fi

remote_script=$(cat <<EOF
set -euo pipefail
cd ${REMOTE_DIR}
export PATH="/usr/local/go/bin:/usr/local/bin:\$HOME/go/bin:/usr/bin:\$PATH"
export GOTOOLCHAIN=auto
API_KEY="${API_KEY_LOCAL}"

if ! command -v go >/dev/null 2>&1; then
  echo "go is not installed on the host" >&2
  exit 1
fi

echo "Building Shukra with \$(go version)"
if command -v npm >/dev/null 2>&1; then
  if [[ -f web/package-lock.json ]]; then
    npm --prefix web ci
  else
    npm --prefix web install
  fi
  npm --prefix web run build
else
  echo "npm not found; daemon will serve the API without the console bundle" >&2
fi

BPF_TAG=""
if command -v clang >/dev/null 2>&1 && [[ -r /sys/kernel/btf/vmlinux ]]; then
  if make generate && compgen -G "internal/bpfgen/*_bpfel.go" >/dev/null; then
    BPF_TAG="-tags shukrabpf"
  else
    echo "CO-RE objects were not generated; building without them" >&2
  fi
else
  echo "clang or BTF missing; programs will report detached" >&2
fi

mkdir -p bin
# shellcheck disable=SC2086
CGO_ENABLED=0 go build \${BPF_TAG} -o bin/shukrad ./cmd/shukrad
CGO_ENABLED=0 go build -o bin/shukractl ./cmd/shukractl

install_bin() {
  local src="\$1" dest="\$2"
  if install -m 755 "\$src" "\$dest" 2>/dev/null; then
    return 0
  fi
  sudo install -d /usr/local/bin
  sudo install -m 755 "\$src" "\$dest"
}
install_bin bin/shukrad /usr/local/bin/shukrad
install_bin bin/shukractl /usr/local/bin/shukractl

sudo mkdir -p /etc/shukra
sudo cp -f configs/detections.example.yaml /etc/shukra/detections.yaml

mkdir -p "\$HOME/.shukra"
printf '%s\n' "\$API_KEY" > "\$HOME/.shukra/api-key"
cat > "\$HOME/.shukra/env" <<ENVEOF
# Written by deploy-remote.sh — sourced automatically by shukractl.
SHUKRA_URL=http://127.0.0.1:30970
SHUKRA_API_KEY=\${API_KEY}
ENVEOF
chmod 600 "\$HOME/.shukra/"* || true

sudo tee /etc/systemd/system/shukra.service >/dev/null <<UNIT
[Unit]
Description=Shukra eBPF runtime intelligence for KVM
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${REMOTE_DIR}
Environment=SHUKRA_API_KEY=\${API_KEY}
ExecStart=/usr/local/bin/shukrad -listen 0.0.0.0:30970 -web ${REMOTE_DIR}/web/dist -watchlist /etc/shukra/detections.yaml
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT

retry() {
  local i
  for i in 1 2 3 4 5; do
    if "\$@"; then
      return 0
    fi
    echo "retry \$i: \$*" >&2
    sleep 2
  done
  return 1
}
retry sudo systemctl daemon-reload
retry sudo systemctl enable shukra
retry sudo systemctl restart shukra
sleep 1
sudo systemctl is-active shukra

export SHUKRA_URL="http://127.0.0.1:30970"
export SHUKRA_API_KEY="\$API_KEY"
export SHUKRA_CLI_NO_BANNER=1
export SHUKRA_CLI_COLOR=false
export SHUKRA_SKIP_DOTENV=1

echo "---- shukractl status ----"
shukractl status
echo "---- shukractl programs ----"
shukractl programs
echo "---- shukractl vms ----"
shukractl vms
echo "---- shukractl trace list ----"
shukractl trace list
curl -sf -H "Authorization: Bearer \$API_KEY" "\$SHUKRA_URL/api/v1/status"
echo
HOST_IP="\$(hostname -I | awk '{print \$1}')"
echo "API_KEY=\$API_KEY"
echo "SHUKRA_URL=http://\${HOST_IP}:30970"
echo "Shukra ready"
EOF
)

if $DRY_RUN; then
  log "dry-run remote script:"
  echo "$remote_script"
  exit 0
fi

ssh_host 'bash -s' <<<"$remote_script"
log "done — open http://<host>:30970  (token: ${API_KEY_LOCAL})"
