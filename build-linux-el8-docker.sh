#!/usr/bin/env bash
# Build del binario Linux dentro de Rocky Linux 8 (glibc ~2.28) vía Docker.
# Uso: ./build-linux-el8-docker.sh
# Salida: dist/robin-client-monitor.linux-el8-glibc28
#
# Requiere Docker. Apple Silicon amd64: DOCKER_DEFAULT_PLATFORM=linux/amd64
# ARM64 nativo: DOCKER_DEFAULT_PLATFORM=linux/arm64 TARGET_ARCH=aarch64 ./build-linux-el8-docker.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${ROOT}"

DOCKER="${DOCKER:-docker}"
IMAGE_TAG="${IMAGE_TAG:-robin-client-monitor:build-el8}"
PLATFORM="${DOCKER_DEFAULT_PLATFORM:-}"
TARGET_ARCH="${TARGET_ARCH:-}"
if [[ -z "${TARGET_ARCH}" ]]; then
  if [[ "${PLATFORM}" == *arm64* ]]; then
    TARGET_ARCH="aarch64"
  else
    TARGET_ARCH="$(uname -m)"
  fi
fi
case "${TARGET_ARCH}" in
  aarch64|arm64) ARCH_TAG="arm64" ;;
  *) ARCH_TAG="amd64" ;;
esac
OUT_NAME="${OUT_NAME:-robin-client-monitor.linux-el8-glibc28.${ARCH_TAG}}"

echo "[build-linux-el8-docker] Construyendo imagen ${IMAGE_TAG} (arch=${ARCH_TAG})…"
BUILD_ARGS=()
CREATE_ARGS=()
if [[ -n "${PLATFORM}" ]]; then
  BUILD_ARGS+=(--platform "${PLATFORM}")
  CREATE_ARGS+=(--platform "${PLATFORM}")
fi
"${DOCKER}" build "${BUILD_ARGS[@]}" -f Dockerfile.linux-el8 -t "${IMAGE_TAG}" "${ROOT}"

cid="$("${DOCKER}" create "${CREATE_ARGS[@]}" "${IMAGE_TAG}")"
cleanup() { "${DOCKER}" rm -f "${cid}" >/dev/null 2>&1 || true; }
trap cleanup EXIT

mkdir -p "${ROOT}/dist"
echo "[build-linux-el8-docker] Extrayendo binario a dist/${OUT_NAME}…"
"${DOCKER}" cp "${cid}:/build/dist/robin-client-monitor" "${ROOT}/dist/${OUT_NAME}"
chmod +x "${ROOT}/dist/${OUT_NAME}"

echo "[build-linux-el8-docker] OK: ${ROOT}/dist/${OUT_NAME}"
echo "[build-linux-el8-docker] Prueba en el servidor: ldd --version  (glibc del host debe ser >= 2.28 para este artefacto)."
