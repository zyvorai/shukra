#!/usr/bin/env bash
# Build a release tarball and a .deb for THIS machine's architecture into dist/.
#
# Needs Linux with clang, llvm-strip, bpftool and kernel BTF (see `make generate`).
# The CO-RE objects are compiled into shukrad, so the result needs only kernel BTF
# to run: no compiler on the hypervisor. bpf/vmlinux.h is dumped from this
# machine's kernel, so build each architecture on that architecture.
#
#   VERSION=v1.2.3 scripts/package.sh
#   SHUKRA_SKIP_BUILD=1 scripts/package.sh     # reuse bin/ and web/dist as they are
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

[[ "$(uname -s)" == "Linux" ]] || { echo "package.sh must run on Linux: the BPF objects are built against this kernel's BTF" >&2; exit 1; }

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo 0.1.0)}"
case "$(uname -m)" in
  x86_64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac
NAME="shukra-${VERSION}-linux-${ARCH}"
DIST="${ROOT}/dist"
LDFLAGS="-X github.com/zyvorai/shukra/internal/version.Version=${VERSION}"

if [[ "${SHUKRA_SKIP_BUILD:-}" != "1" ]]; then
  make generate
  compgen -G "internal/bpfgen/*_bpfel.go" >/dev/null || { echo "no CO-RE objects were generated; refusing to package a daemon that cannot attach" >&2; exit 1; }
  if command -v npm >/dev/null 2>&1; then
    npm --prefix web ci
    npm --prefix web run build
  else
    echo "npm not found: the package will not include the console" >&2
  fi
  mkdir -p bin
  CGO_ENABLED=0 go build -tags shukrabpf -ldflags "${LDFLAGS}" -o bin/shukrad ./cmd/shukrad
  CGO_ENABLED=0 go build -ldflags "${LDFLAGS}" -o bin/shukractl ./cmd/shukractl
fi
[[ -x bin/shukrad && -x bin/shukractl ]] || { echo "bin/shukrad and bin/shukractl are needed" >&2; exit 1; }
# The daemon has to carry the BPF objects. A binary built without the tag would
# install fine and then report every program detached.
if ! go version -m bin/shukrad 2>/dev/null | grep -q 'shukrabpf'; then
  echo "bin/shukrad was not built with -tags shukrabpf; refusing to package it" >&2
  exit 1
fi

rm -rf "${DIST}"
TREE="${DIST}/${NAME}"
mkdir -p "${TREE}/bin" "${TREE}/deploy" "${TREE}/configs"
cp bin/shukrad bin/shukractl "${TREE}/bin/"
cp deploy/install.sh deploy/shukra.service "${TREE}/deploy/"
cp configs/detections.example.yaml "${TREE}/configs/"
cp LICENSE README.md "${TREE}/"
[[ -d web/dist ]] && { mkdir -p "${TREE}/web"; cp -R web/dist "${TREE}/web/dist"; }

tar -C "${DIST}" -czf "${DIST}/${NAME}.tar.gz" "${NAME}"
( cd "${DIST}" && sha256sum "${NAME}.tar.gz" > "${NAME}.tar.gz.sha256" )
echo "built ${DIST}/${NAME}.tar.gz"

# ---- .deb ----------------------------------------------------------------
if ! command -v dpkg-deb >/dev/null 2>&1; then
  echo "dpkg-deb not found: skipping the .deb"
  exit 0
fi
# A Debian version starts with a digit and may not contain a hyphen here.
DEBV="${VERSION#v}"
[[ "${DEBV}" =~ ^[0-9] ]] || DEBV="0~${DEBV}"
DEBV="${DEBV//-/+}"
P="${DIST}/deb"
rm -rf "${P}"
mkdir -p "${P}/DEBIAN" "${P}/usr/bin" "${P}/usr/lib/systemd/system" "${P}/usr/share/shukra" "${P}/usr/share/doc/shukra"
cp bin/shukrad bin/shukractl "${P}/usr/bin/"
sed -e 's#@WEB_DIR@#/usr/share/shukra/web#' -e 's#@BIN_DIR@#/usr/bin#' deploy/shukra.service > "${P}/usr/lib/systemd/system/shukra.service"
cp configs/detections.example.yaml "${P}/usr/share/shukra/"
[[ -d web/dist ]] && cp -R web/dist "${P}/usr/share/shukra/web"
cp LICENSE README.md "${P}/usr/share/doc/shukra/"

cat > "${P}/DEBIAN/control" <<CONTROL
Package: shukra
Version: ${DEBV}
Section: admin
Priority: optional
Architecture: ${ARCH}
Maintainer: Zyvor <noreply@zyvor.dev>
Homepage: https://github.com/zyvorai/shukra
Description: eBPF runtime intelligence and security for KVM
 Shukra watches QEMU/KVM guests from the hypervisor, with no agent in the VM.
 The eBPF programs are compiled in, so the host needs only kernel BTF
 (/sys/kernel/btf/vmlinux), not a compiler. The service runs with a small,
 documented set of capabilities and a read-only filesystem.
CONTROL

cat > "${P}/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e
mkdir -p /etc/shukra
[ -e /etc/shukra/detections.yaml ] || cp /usr/share/shukra/detections.example.yaml /etc/shukra/detections.yaml
cp -f /usr/share/shukra/detections.example.yaml /etc/shukra/detections.example.yaml
touch /etc/shukra/env
chmod 600 /etc/shukra/env
if ! grep -q '^SHUKRA_API_KEY=' /etc/shukra/env; then
  key="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  echo "SHUKRA_API_KEY=${key}" >> /etc/shukra/env
  echo "shukra: generated an admin key, stored in /etc/shukra/env (root only)"
fi
# CAP_BPF and CAP_PERFMON exist from Linux 5.8. On an older kernel, clear them.
kver="$(uname -r | cut -d. -f1-2)"
if [ "$(printf '%s\n5.8\n' "$kver" | sort -V | head -1)" != "5.8" ]; then
  mkdir -p /etc/systemd/system/shukra.service.d
  printf '[Service]\nCapabilityBoundingSet=\nAmbientCapabilities=\n' > /etc/systemd/system/shukra.service.d/legacy-caps.conf
fi
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload
  systemctl enable shukra >/dev/null 2>&1 || true
  systemctl restart shukra || true
fi
exit 0
POSTINST

cat > "${P}/DEBIAN/prerm" <<'PRERM'
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
  systemctl stop shukra 2>/dev/null || true
  case "$1" in remove|purge) systemctl disable shukra >/dev/null 2>&1 || true ;; esac
fi
# Isolation outlives the daemon on purpose. Removing the package removes the thing
# that could release it, so lift it here rather than leave a VM cut off for good.
case "$1" in remove|purge) /usr/bin/shukrad -detach-all -data-dir /var/lib/shukra >/dev/null 2>&1 || true ;; esac
exit 0
PRERM

cat > "${P}/DEBIAN/postrm" <<'POSTRM'
#!/bin/sh
set -e
if [ "$1" = "purge" ]; then
  rm -rf /etc/shukra /var/lib/shukra /etc/systemd/system/shukra.service.d
fi
if [ -d /run/systemd/system ]; then systemctl daemon-reload || true; fi
exit 0
POSTRM
chmod 755 "${P}/DEBIAN/postinst" "${P}/DEBIAN/prerm" "${P}/DEBIAN/postrm"

dpkg-deb --root-owner-group --build "${P}" "${DIST}/shukra_${DEBV}_${ARCH}.deb" >/dev/null
rm -rf "${P}"
( cd "${DIST}" && sha256sum "shukra_${DEBV}_${ARCH}.deb" > "shukra_${DEBV}_${ARCH}.deb.sha256" )
echo "built ${DIST}/shukra_${DEBV}_${ARCH}.deb"
