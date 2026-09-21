#!/usr/bin/env bash
# Check a downloaded Shukra release directory.
#
#   scripts/verify-release.sh artifacts
#   COSIGN_PUBLIC_KEY=cosign.pub scripts/verify-release.sh artifacts
#
# Every *.sha256 is checked with sha256sum. shukra.cdx.json, when present, must
# be a CycloneDX JSON document. Each *.sig is checked with cosign when a public
# key is set (COSIGN_PUBLIC_KEY or --key). Verification ignores the transparency
# log: the release workflow signs with a repository key, not a keyless identity.
#
# SHUKRA_REQUIRE_SBOM=1 fails when shukra.cdx.json is missing.
# SHUKRA_REQUIRE_SIGNATURES=1 fails when a payload has no .sig, cosign is
# missing, or no public key was given.
set -euo pipefail

dir=""
key="${COSIGN_PUBLIC_KEY:-}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --key)
      key="${2:-}"
      shift 2
      ;;
    -h|--help)
      sed -n '2,14p' "$0"
      exit 0
      ;;
    *)
      if [[ -n "$dir" ]]; then
        echo "one directory only" >&2
        exit 2
      fi
      dir="$1"
      shift
      ;;
  esac
done
dir="${dir:-artifacts}"
if [[ ! -d "$dir" ]]; then
  echo "not a directory: $dir" >&2
  exit 2
fi

fail=0
checked=0
shopt -s nullglob

for sum in "$dir"/*.sha256; do
  checked=$((checked + 1))
  name="$(basename "$sum")"
  payload="${name%.sha256}"
  got="$(sha256sum "$dir/$payload" 2>/dev/null | awk '{print $1}')"
  want="$(awk 'NF {print $1; exit}' "$sum")"
  if [[ -z "$got" || -z "$want" || "$got" != "$want" || ! -f "$dir/$payload" ]]; then
    echo "$payload: FAILED" >&2
    fail=1
  else
    echo "$payload: OK"
  fi
done
if [[ "$checked" -eq 0 ]]; then
  echo "no checksum files in $dir" >&2
  fail=1
fi

sbom="$dir/shukra.cdx.json"
if [[ -f "$sbom" ]]; then
  if ! python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d.get("bomFormat")=="CycloneDX" else 1)' "$sbom"; then
    echo "SBOM is not CycloneDX: $sbom" >&2
    fail=1
  else
    echo "SBOM is CycloneDX"
  fi
elif [[ "${SHUKRA_REQUIRE_SBOM:-}" == "1" ]]; then
  echo "SBOM is required and missing: $sbom" >&2
  fail=1
else
  echo "no SBOM (set SHUKRA_REQUIRE_SBOM=1 to require shukra.cdx.json)"
fi

payloads=()
for f in "$dir"/*; do
  [[ -f "$f" ]] || continue
  case "$f" in
    *.sig|*.att) continue ;;
  esac
  payloads+=("$f")
done

sigs=("$dir"/*.sig)
if [[ ${#sigs[@]} -eq 0 ]]; then
  if [[ "${SHUKRA_REQUIRE_SIGNATURES:-}" == "1" ]]; then
    echo "signatures are required and none were found" >&2
    fail=1
  else
    echo "no signatures (set SHUKRA_REQUIRE_SIGNATURES=1 to require them)"
  fi
else
  if [[ -z "$key" ]]; then
    echo "signatures are present; pass --key or COSIGN_PUBLIC_KEY to check them" >&2
    if [[ "${SHUKRA_REQUIRE_SIGNATURES:-}" == "1" ]]; then
      fail=1
    fi
  elif ! command -v cosign >/dev/null 2>&1; then
    echo "cosign is not installed" >&2
    fail=1
  else
    for sig in "${sigs[@]}"; do
      blob="${sig%.sig}"
      if [[ ! -f "$blob" ]]; then
        echo "signature has no payload: $sig" >&2
        fail=1
        continue
      fi
      if ! cosign verify-blob --insecure-ignore-tlog --key "$key" --signature "$sig" "$blob"; then
        fail=1
      fi
    done
  fi
  if [[ "${SHUKRA_REQUIRE_SIGNATURES:-}" == "1" ]]; then
    for blob in "${payloads[@]}"; do
      if [[ ! -f "$blob.sig" ]]; then
        echo "missing signature: $blob.sig" >&2
        fail=1
      fi
    done
  fi
fi

if [[ "$fail" -ne 0 ]]; then
  echo "release check failed" >&2
  exit 1
fi
echo "release check passed ($checked checksum files)"
