#!/usr/bin/env bash
# Shukra — remote deploy (SSH + rsync + host build, or a prebuilt release)
#
# Shukra attaches eBPF on the hypervisor. It is not a cluster chart.
#
# Usage:
#   ./scripts/deploy-remote.sh user@10.0.1.5
#   ./scripts/deploy-remote.sh 80.79.5.173 sus
#   ./scripts/deploy-remote.sh 80.79.5.173 sus --verify-only
#   ./scripts/deploy-remote.sh 80.79.5.173 sus --prebuilt dist/shukra-v1.2.3-linux-amd64.tar.gz
#
# Without --prebuilt the tree is rsynced to the host and built there (go, and
# clang plus kernel BTF for the BPF programs). With --prebuilt nothing is compiled
# on the host: the tarball from `make dist` carries the binaries, and the host
# needs only kernel BTF.
#
# SHUKRA_API_KEY        the admin key to install. Unset keeps the key already on
#                       the host, and a fresh host gets a random one.
# SHUKRA_REMOTE_SUBDIR  checkout under $HOME (default: .deployments/shukra)
# SHUKRA_SSH_OPTS       extra ssh/scp options, for example "-F ~/.lima/bpf/ssh.config"
# UI/API: :30970
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

DRY_RUN=false
VERIFY_ONLY=false
PREBUILT=""
TARGET=""
# shellcheck disable=SC2206
EXTRA_SSH=(${SHUKRA_SSH_OPTS:-})
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o ServerAliveInterval=30 ${EXTRA_SSH[@]+"${EXTRA_SSH[@]}"})
POSITIONAL=()

usage() {
  sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage ;;
    --dry-run) DRY_RUN=true; shift ;;
    --verify-only) VERIFY_ONLY=true; shift ;;
    --prebuilt)
      [[ $# -ge 2 ]] || { echo "--prebuilt needs a tarball" >&2; exit 2; }
      PREBUILT="$2"; shift 2 ;;
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
if [[ -n "${PREBUILT}" && ! -f "${PREBUILT}" ]]; then
  echo "prebuilt tarball not found: ${PREBUILT}" >&2
  exit 2
fi

ssh_host() { ssh "${SSH_OPTS[@]}" "$TARGET" "$@"; }
REMOTE_HOME="$(ssh_host 'printf %s "$HOME"')"
REMOTE_DIR="${REMOTE_HOME}/${SHUKRA_REMOTE_SUBDIR:-.deployments/shukra}"

log() { printf '[shukra-deploy] %s\n' "$*"; }

# The key the service actually uses is whatever is in /etc/shukra/env, so the
# checks read it from there instead of assuming the one on this command line.
read_key='API_KEY="$(sudo sed -n "s/^SHUKRA_API_KEY=//p" /etc/shukra/env | head -1)"'

if $VERIFY_ONLY; then
  ssh_host "bash -s" <<EOF
set -euo pipefail
${read_key}
export SHUKRA_URL="http://127.0.0.1:30970"
export SHUKRA_API_KEY="\$API_KEY"
export SHUKRA_CLI_NO_BANNER=1
export SHUKRA_CLI_COLOR=false
export SHUKRA_SKIP_DOTENV=1
systemctl is-active shukra
shukractl version
shukractl status
shukractl programs
shukractl vms
shukractl trace list
curl -sf -H "Authorization: Bearer \$API_KEY" "\$SHUKRA_URL/api/v1/status"
echo
EOF
  exit 0
fi

# Everything after the tree is on the host. The install itself is deploy/install.sh,
# the same routine the release tarball and the .deb use.
common_tail=$(cat <<EOF
${read_key}
mkdir -p "\$HOME/.shukra"
printf '%s\n' "\$API_KEY" > "\$HOME/.shukra/api-key"
cat > "\$HOME/.shukra/env" <<ENVEOF
# Written by deploy-remote.sh — sourced automatically by shukractl.
SHUKRA_URL=http://127.0.0.1:30970
SHUKRA_API_KEY=\${API_KEY}
ENVEOF
chmod 600 "\$HOME/.shukra/"* || true

export SHUKRA_URL="http://127.0.0.1:30970"
export SHUKRA_API_KEY="\$API_KEY"
export SHUKRA_CLI_NO_BANNER=1
export SHUKRA_CLI_COLOR=false
export SHUKRA_SKIP_DOTENV=1

echo "---- shukractl version ----"
shukractl version
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
echo "SHUKRA_URL=http://\${HOST_IP}:30970"
echo "Shukra ready"
EOF
)

key_env=""
if [[ -n "${SHUKRA_API_KEY:-}" ]]; then
  key_env="export SHUKRA_API_KEY='${SHUKRA_API_KEY}'"
fi

if [[ -n "${PREBUILT}" ]]; then
  remote_script=$(cat <<EOF
set -euo pipefail
cd ${REMOTE_DIR}/release
tar -xzf $(basename "${PREBUILT}") --strip-components=1
${key_env}
echo "Installing the prebuilt release (nothing is compiled on this host)"
./deploy/install.sh
${common_tail}
EOF
)
  log "prebuilt ${PREBUILT} → ${TARGET}:${REMOTE_DIR}/release"
  if ! $DRY_RUN; then
    ssh_host "rm -rf ${REMOTE_DIR}/release && mkdir -p ${REMOTE_DIR}/release"
    scp "${SSH_OPTS[@]}" "${PREBUILT}" "${TARGET}:${REMOTE_DIR}/release/"
  fi
else
  log "sync → ${TARGET}:${REMOTE_DIR}"
  if ! $DRY_RUN; then
    ssh_host "mkdir -p ${REMOTE_DIR}"
    rsync -az --delete -e "ssh ${SSH_OPTS[*]}" \
      --exclude '.git' --exclude 'bin' --exclude 'dist' --exclude 'web/node_modules' --exclude 'web/dist' \
      --exclude 'bpf/*.o' --exclude 'bpf/vmlinux.h' --exclude '.DS_Store' --exclude '.cursor' \
      "${ROOT}/" "${TARGET}:${REMOTE_DIR}/"
  fi
  remote_script=$(cat <<EOF
set -euo pipefail
cd ${REMOTE_DIR}
export PATH="/usr/local/go/bin:/usr/local/bin:\$HOME/go/bin:/usr/bin:\$PATH"
export GOTOOLCHAIN=auto

if ! command -v go >/dev/null 2>&1; then
  echo "go is not installed on the host" >&2
  exit 1
fi

VERSION="\$(git describe --tags --always --dirty 2>/dev/null || echo 0.1.0)"
LDFLAGS="-X github.com/zyvorai/shukra/internal/version.Version=\${VERSION}"
echo "Building Shukra \${VERSION} with \$(go version)"
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
CGO_ENABLED=0 go build \${BPF_TAG} -ldflags "\${LDFLAGS}" -o bin/shukrad ./cmd/shukrad
CGO_ENABLED=0 go build -ldflags "\${LDFLAGS}" -o bin/shukractl ./cmd/shukractl

${key_env}
./deploy/install.sh
${common_tail}
EOF
)
fi

if $DRY_RUN; then
  log "dry-run remote script:"
  echo "$remote_script"
  exit 0
fi

ssh_host 'bash -s' <<<"$remote_script"
log "done — open http://<host>:30970"
