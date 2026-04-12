#!/bin/zsh
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  build-marker-package.sh --version <VERSION> [--run-root <DIR>]
EOF
}

RUN_ROOT="/tmp/dds-macos-e2e"
VERSION=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --run-root) RUN_ROOT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

[[ -n "${VERSION}" ]] || { echo "--version is required" >&2; exit 2; }
command -v pkgbuild >/dev/null || { echo "pkgbuild not found" >&2; exit 1; }

PKG_ID="com.dds.e2e.marker"
PKG_PATH="${RUN_ROOT}/packages/${PKG_ID}.pkg"
PAYLOAD_ROOT="${RUN_ROOT}/pkg-payload"
MARKER_PATH="${PAYLOAD_ROOT}/tmp/dds-macos-e2e/install-root/software-installed.txt"

rm -rf "${PAYLOAD_ROOT}"
mkdir -p "$(dirname "${MARKER_PATH}")" "${RUN_ROOT}/packages"
cat > "${MARKER_PATH}" <<EOF
dds macos e2e package
version=${VERSION}
generated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

pkgbuild \
  --identifier "${PKG_ID}" \
  --version "${VERSION}" \
  --root "${PAYLOAD_ROOT}" \
  --install-location / \
  "${PKG_PATH}" >/dev/null

shasum -a 256 "${PKG_PATH}" | awk '{ print $1 }' > "${RUN_ROOT}/packages/${PKG_ID}.sha256"
echo "${VERSION}" > "${RUN_ROOT}/packages/${PKG_ID}.version"

echo "pkg=${PKG_PATH}"
echo "sha256=$(cat "${RUN_ROOT}/packages/${PKG_ID}.sha256")"
