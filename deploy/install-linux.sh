#!/usr/bin/env bash
# ============================================================
#  Robin Client Monitor - Instalador (Linux / systemd) §16
#
#  Uso:
#    sudo ./deploy/install-linux.sh <binario> [config_client.json] [flags]
#
#  Flags / env (token de enrollment de un solo uso):
#    --enroll TOKEN          ROBIN_ENROLL_TOKEN
#    --enroll-server URL     ROBIN_ENROLL_SERVER
#    --enroll-tenant ID      ROBIN_ENROLL_TENANT
#    --enroll-name NAME      ROBIN_ENROLL_NAME
#    --enroll-insecure       ROBIN_ENROLL_INSECURE=1  (solo lab)
#    --skip-start            ROBIN_SKIP_START=1
# ============================================================
set -euo pipefail

APP_DIR="/opt/robin-client-monitor"
SERVICE="robin-client-monitor"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_SRC=""
CFG_SRC=""
ENROLL_TOKEN="${ROBIN_ENROLL_TOKEN:-}"
ENROLL_SERVER="${ROBIN_ENROLL_SERVER:-}"
ENROLL_TENANT="${ROBIN_ENROLL_TENANT:-}"
ENROLL_NAME="${ROBIN_ENROLL_NAME:-}"
ENROLL_INSECURE="${ROBIN_ENROLL_INSECURE:-}"
SKIP_START="${ROBIN_SKIP_START:-}"

usage() {
  echo "Uso: $0 <binario> [config_client.json] [--enroll TOKEN --enroll-server URL --enroll-tenant TENANT]" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --enroll) ENROLL_TOKEN="${2:-}"; shift 2 ;;
    --enroll-server) ENROLL_SERVER="${2:-}"; shift 2 ;;
    --enroll-tenant) ENROLL_TENANT="${2:-}"; shift 2 ;;
    --enroll-name) ENROLL_NAME="${2:-}"; shift 2 ;;
    --enroll-insecure) ENROLL_INSECURE=1; shift ;;
    --skip-start) SKIP_START=1; shift ;;
    -h|--help) usage ;;
    *)
      if [[ -z "${BIN_SRC}" ]]; then
        BIN_SRC="$1"
      elif [[ -z "${CFG_SRC}" ]]; then
        CFG_SRC="$1"
      else
        echo "ERROR: argumento extra: $1" >&2
        usage
      fi
      shift
      ;;
  esac
done

if [[ -z "${BIN_SRC}" ]]; then
  usage
fi
if [[ -z "${CFG_SRC}" ]]; then
  CFG_SRC="${ROOT}/config_client.packaged.json"
fi
if [[ ! -f "${BIN_SRC}" ]]; then
  echo "ERROR: no existe el binario ${BIN_SRC}" >&2
  exit 1
fi
if [[ ! -f "${CFG_SRC}" ]]; then
  echo "ERROR: no existe el config ${CFG_SRC}" >&2
  exit 1
fi

echo "[install] Instalando ${SERVICE} en ${APP_DIR}"
mkdir -p "${APP_DIR}"
install -m 0755 "${BIN_SRC}" "${APP_DIR}/robin-client-monitor"
install -m 0600 "${CFG_SRC}" "${APP_DIR}/config_client.json"
install -m 0644 "${ROOT}/robin-client-monitor.service" "/etc/systemd/system/${SERVICE}.service"

# shellcheck source=linux-icon.sh
source "${ROOT}/linux-icon.sh"
ICON_PNG=""
BIN_DIR="$(cd "$(dirname "${BIN_SRC}")" && pwd)"
for cand in \
  "${BIN_DIR}/robin-client-monitor.png" \
  "${ROOT}/../assets/ws-client-icon.png" \
  "${ROOT}/robin-client-monitor.png"; do
  if [[ -f "${cand}" ]]; then
    ICON_PNG="${cand}"
    break
  fi
done
if [[ -n "${ICON_PNG}" ]] && linux_icon_install "" "${ICON_PNG}" "${ROOT}/robin-client-monitor.desktop"; then
  linux_icon_refresh
  echo "[install] Icono instalado (${ICON_PNG})"
else
  echo "[install] AVISO: sin PNG; el binario no tendrá icono de escritorio (corre ./build.sh)" >&2
fi

if [[ -n "${ENROLL_TOKEN}" ]]; then
  echo "[install] Ejecutando enrollment (RF-CORE-01/02)…"
  ENROLL_ARGS=( --enroll "${ENROLL_TOKEN}" )
  [[ -n "${ENROLL_SERVER}" ]] && ENROLL_ARGS+=( --enroll-server "${ENROLL_SERVER}" )
  [[ -n "${ENROLL_TENANT}" ]] && ENROLL_ARGS+=( --enroll-tenant "${ENROLL_TENANT}" )
  [[ -n "${ENROLL_NAME}" ]] && ENROLL_ARGS+=( --enroll-name "${ENROLL_NAME}" )
  if [[ "${ENROLL_INSECURE}" == "1" ]]; then
    ENROLL_ARGS+=( --enroll-insecure )
  fi
  ( cd "${APP_DIR}" && ./robin-client-monitor "${ENROLL_ARGS[@]}" ) || \
    echo "[install] AVISO: enrollment falló; el agente usará config_client.json."
fi

echo "[install] Registrando servicio systemd…"
systemctl daemon-reload
systemctl enable "${SERVICE}"
if [[ "${SKIP_START}" != "1" ]]; then
  systemctl start "${SERVICE}"
fi

echo "[install] OK. Estado:"
systemctl --no-pager status "${SERVICE}" --lines=0 || true
echo "[install] Logs: journalctl -u ${SERVICE} -f"
