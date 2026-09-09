#!/usr/bin/env bash
set -euo pipefail

APP_NAME="robin-client-monitor"
ENTRYPOINT="ws_tools_client_embedded.py"
ICON_SVG="assets/ws-client-icon.svg"
ICON_PNG="assets/ws-client-icon.png"
ICON_ICO="assets/ws-client-icon.ico"
ICON_ICNS="assets/ws-client-icon.icns"

echo "[build] Iniciando build de ${APP_NAME} usando ${ENTRYPOINT}"

if [[ ! -f "${ENTRYPOINT}" ]]; then
  echo "[build] ERROR: no existe el archivo ${ENTRYPOINT}"
  exit 1
fi

# Genera .icns desde el SVG en macOS (qlmanage + sips + iconutil) si aún no existe.
ensure_macos_icns_from_svg() {
  local svg="$1"
  local icns="$2"
  [[ -f "${icns}" ]] && return 0
  [[ -f "${svg}" ]] || return 1
  local work png base
  work="$(mktemp -d)"
  base="$(basename "${svg}")"
  png="${work}/${base}.png"
  if ! qlmanage -t -s 1024 -o "${work}" "${svg}" >/dev/null 2>&1; then
    rm -rf "${work}"
    echo "[build] Aviso: qlmanage no pudo rasterizar ${svg}; compila sin .icns."
    return 1
  fi
  if [[ ! -f "${png}" ]]; then
    rm -rf "${work}"
    echo "[build] Aviso: no se encontró PNG generado (${png}); compila sin .icns."
    return 1
  fi
  mkdir -p "${work}/icon.iconset"
  sips -z 16 16     "${png}" --out "${work}/icon.iconset/icon_16x16.png"       >/dev/null 2>&1
  sips -z 32 32     "${png}" --out "${work}/icon.iconset/icon_16x16@2x.png"    >/dev/null 2>&1
  sips -z 32 32     "${png}" --out "${work}/icon.iconset/icon_32x32.png"       >/dev/null 2>&1
  sips -z 64 64     "${png}" --out "${work}/icon.iconset/icon_32x32@2x.png"    >/dev/null 2>&1
  sips -z 128 128   "${png}" --out "${work}/icon.iconset/icon_128x128.png"      >/dev/null 2>&1
  sips -z 256 256   "${png}" --out "${work}/icon.iconset/icon_128x128@2x.png"  >/dev/null 2>&1
  sips -z 256 256   "${png}" --out "${work}/icon.iconset/icon_256x256.png"     >/dev/null 2>&1
  sips -z 512 512   "${png}" --out "${work}/icon.iconset/icon_256x256@2x.png"  >/dev/null 2>&1
  sips -z 512 512   "${png}" --out "${work}/icon.iconset/icon_512x512.png"     >/dev/null 2>&1
  sips -z 1024 1024 "${png}" --out "${work}/icon.iconset/icon_512x512@2x.png"  >/dev/null 2>&1
  if ! iconutil -c icns "${work}/icon.iconset" -o "${icns}"; then
    rm -rf "${work}"
    echo "[build] Aviso: iconutil falló; compila sin .icns."
    return 1
  fi
  rm -rf "${work}"
  echo "[build] Generado ${icns} desde ${svg}"
}

# Crear/activar entorno virtual para la construcción.
# PyInstaller necesita la librería compartida de Python (libpython3.x.so/dll).
# Preferimos un python con lib compartida (p.ej. 3.14 en esta distro) o el
# Python "real" del PATH en Windows (evita el stub del Microsoft Store).
ARCH_SUFFIX=""
HOST_ARCH="$(uname -m 2>/dev/null || echo unknown)"
# TARGET_ARCH=aarch64|arm64|x86_64|amd64  (build nativo; PyInstaller no cruza bien)
TARGET_ARCH="${TARGET_ARCH:-${HOST_ARCH}}"
case "${TARGET_ARCH}" in
  aarch64|arm64) ARCH_SUFFIX="arm64" ;;
  x86_64|amd64) ARCH_SUFFIX="amd64" ;;
  *) ARCH_SUFFIX="${TARGET_ARCH}" ;;
esac
echo "[build] arch host=${HOST_ARCH} target=${TARGET_ARCH} (${ARCH_SUFFIX})"
OS="$(uname -s || true)"
PY_BIN="${PY_BUILD_PYTHON:-}"
if [[ -z "${PY_BIN}" ]]; then
  if [[ "${OS}" =~ MINGW|MSYS|CYGWIN|Windows_NT ]]; then
    # Windows: probar candidatos del PATH que respondan de verdad (py launcher,
    # python directo). Se verifica ejecutándolos, no solo por nombre.
    for cand in py python; do
      if command -v "${cand}" >/dev/null 2>&1 && \
         "${cand}" -c "import sys" >/dev/null 2>&1; then
        PY_BIN="${cand}"
        break
      fi
    done
  else
    for cand in /usr/bin/python3.14 /usr/bin/python3.12 /usr/bin/python3.11; do
      if [[ -x "${cand}" ]] && ldconfig -p 2>/dev/null | grep -q "libpython$(basename "${cand}" | sed 's/python//')\.so"; then
        PY_BIN="${cand}"
        break
      fi
    done
  fi
fi
if [[ -z "${PY_BIN}" ]]; then
  PY_BIN="python3"
fi
echo "[build] Python para build: ${PY_BIN}"
if [[ ! -d ".venv-build" ]]; then
  "${PY_BIN}" -m venv .venv-build
fi
# No usar `source activate` ni el CLI `pyinstaller`: en Git Bash el launcher
# (shebang `#!C:\...\python.exe`) sale 126. El python.exe del venv sí ejecuta.
if [[ -f ".venv-build/Scripts/python.exe" ]]; then
  VENV_PY=".venv-build/Scripts/python.exe"
elif [[ -x ".venv-build/bin/python" ]]; then
  VENV_PY=".venv-build/bin/python"
else
  echo "[build] ERROR: no hay python en .venv-build (Scripts/python.exe o bin/python)"
  exit 1
fi
echo "[build] Python del venv: ${VENV_PY}"

"${VENV_PY}" -m pip install --upgrade pip
# Dependencias necesarias para ejecutar ws_tools_client_embedded.py
"${VENV_PY}" -m pip install aiohttp requests cryptography pyinstaller psutil pillow

if [[ "${OS}" == "Darwin" ]]; then
  ensure_macos_icns_from_svg "${ICON_SVG}" "${ICON_ICNS}" || true
fi

# PyInstaller no acepta SVG. Rasteriza a png/ico (ImageMagick o Pillow).
# --icon solo aplica en Windows (.ico) y macOS (.icns); en Linux el ELF no
# lleva icono y PyInstaller ignora el flag (WARNING: Ignoring icon).
if [[ -f "${ICON_SVG}" ]]; then
  if "${VENV_PY}" scripts/rasterize_app_icon.py "${ICON_SVG}" "${ICON_PNG}" "${ICON_ICO}"; then
    echo "[build] Icono rasterizado desde ${ICON_SVG}"
  else
    echo "[build] Aviso: no se pudo rasterizar ${ICON_SVG}; Windows/macOS irán sin --icon."
  fi
fi

if [[ "${OS}" == "Linux" ]]; then
  echo "[build] Linux: el ELF no embebe --icon; se instala PNG + .desktop (y metadatos Nautilus)."
elif [[ "${OS}" == "Darwin" && ! -f "${ICON_ICNS}" ]]; then
  echo "[build] Aviso: no se usará --icon (falta ${ICON_ICNS})."
  echo "[build] En macOS se intenta crear ${ICON_ICNS} desde ${ICON_SVG} automáticamente."
elif [[ "${OS}" =~ MINGW|MSYS|CYGWIN|Windows_NT ]] && [[ ! -f "${ICON_ICO}" ]]; then
  echo "[build] Aviso: no se usará --icon (falta ${ICON_ICO})."
fi

# Módulos requeridos para que PyInstaller no omita librerías de observabilidad/red
HIDDEN=(
  --hidden-import colsoft_tools
  --hidden-import colsoft_tools.network_checks
  --hidden-import colsoft_tools.observability
  --hidden-import colsoft_tools.config_manager
  --hidden-import colsoft_tools.enrollment
  --hidden-import colsoft_tools.self_update
  --hidden-import colsoft_tools.scheduler
  --hidden-import colsoft_tools.tamper
  --hidden-import colsoft_tools.telemetry_buffer
  --hidden-import colsoft_tools.data_plane
  --hidden-import colsoft_tools.obs_monitors
  --hidden-import colsoft_tools.endpoint_security
  --hidden-import colsoft_tools.sec_monitors
  --hidden-import colsoft_tools.windows_collectors
  --hidden-import colsoft_tools.win_monitors
  --hidden-import colsoft_tools.linux_collectors
  --hidden-import colsoft_tools.linux_monitors
  --hidden-import colsoft_tools.tls_util
  --hidden-import colsoft_tools.cloud_metadata
  --hidden-import colsoft_tools.event_model
  --hidden-import colsoft_tools.agent_admin
  --hidden-import colsoft_tools.protocol
  --hidden-import colsoft_tools.security
  --hidden-import colsoft_tools.remediation
  --hidden-import colsoft_tools.tool_catalog
  --hidden-import certifi
  --hidden-import cryptography.hazmat.backends.openssl.backend
  --hidden-import psutil
  --hidden-import aiohttp
)

PYI_ARGS=(--clean --noconfirm --onefile --name "${APP_NAME}" "${HIDDEN[@]}" "${ENTRYPOINT}")
if [[ "${OS}" == "Darwin" && -f "${ICON_ICNS}" ]]; then
  PYI_ARGS+=(--icon "${ICON_ICNS}")
elif [[ "${OS}" =~ MINGW|MSYS|CYGWIN|Windows_NT ]] && [[ -f "${ICON_ICO}" ]]; then
  PYI_ARGS+=(--icon "${ICON_ICO}")
fi

echo "[build] Ejecutando: ${VENV_PY} -m PyInstaller ${PYI_ARGS[*]}"
"${VENV_PY}" -m PyInstaller "${PYI_ARGS[@]}"

# En Windows el binario lleva extensión .exe
if [[ "${OS}" =~ MINGW|MSYS|CYGWIN|Windows_NT ]]; then
  APP_NAME="${APP_NAME}.exe"
fi

if [[ ! -f "dist/${APP_NAME}" ]]; then
  echo "[build] ERROR: no se generó dist/${APP_NAME}"
  exit 1
fi
echo "[build] OK. Binario generado exitosamente en dist/${APP_NAME}"
if [[ "${APP_NAME}" == *.exe ]]; then
  ARCH_COPY="dist/robin-client-monitor.${ARCH_SUFFIX}.exe"
else
  ARCH_COPY="dist/robin-client-monitor.${ARCH_SUFFIX}"
fi
cp -f "dist/${APP_NAME}" "${ARCH_COPY}"
echo "[build] Copia por arch: ${ARCH_COPY}"

# Linux: ELF no lleva icono embebido. PNG + .desktop para el paquete; gio para
# que Nautilus muestre el icono en este host (metadatos locales, no viajan).
if [[ "${OS}" == "Linux" && -f "${ICON_PNG}" ]]; then
  cp -f "${ICON_PNG}" "dist/${APP_NAME}.png"
  PNG_ABS="$(readlink -f "dist/${APP_NAME}.png")"
  BIN_ABS="$(readlink -f "dist/${APP_NAME}")"
  cat > "dist/${APP_NAME}.desktop" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Robin Client Monitor
Comment=Agente de endpoint RobinLogs
Exec=${BIN_ABS}
Icon=${PNG_ABS}
Terminal=false
Categories=System;Monitor;
StartupNotify=false
EOF
  chmod +x "dist/${APP_NAME}.desktop" 2>/dev/null || true
  if command -v gio >/dev/null 2>&1; then
    for target in "${BIN_ABS}" "$(readlink -f "${ARCH_COPY}")"; do
      gio set "${target}" metadata::custom-icon "file://${PNG_ABS}" 2>/dev/null || true
    done
    echo "[build] Icono Linux: ${PNG_ABS} (Nautilus en este host + dist/${APP_NAME}.desktop)"
  else
    echo "[build] Icono Linux: ${PNG_ABS} y dist/${APP_NAME}.desktop"
  fi
fi

# --- Smoke test del binario (build+smoke) ---
# Valida que la identidad/config y los módulos del core común (RF-CORE-03/04/06/07)
# queden embebidos correctamente en el binario. El self-test lee
# config_client.json desde la carpeta del binario (modo frozen).
if [[ -f "config_client.json" ]]; then
  cp -f config_client.json "dist/config_client.json"
  echo "[build] config_client.json copiado a dist/ para el self-test."
fi
echo "[build] Ejecutando self-test del binario (smoke)…"
SMOKE_BIN="dist/${APP_NAME}"
chmod +x "${SMOKE_BIN}" 2>/dev/null || true
smoke_ok=0
if [[ "${OS}" =~ MINGW|MSYS|CYGWIN|Windows_NT ]]; then
  # Git Bash: ./foo.exe a veces sale 126 (sin +x o MSYS exec). cmd.exe sí corre el PE.
  if command -v cygpath >/dev/null 2>&1; then
    WIN_BIN="$(cygpath -w "${SMOKE_BIN}")"
    if cmd.exe //c "${WIN_BIN} --self-test"; then
      smoke_ok=1
    fi
  elif "${SMOKE_BIN}" --self-test; then
    smoke_ok=1
  fi
elif "${SMOKE_BIN}" --self-test; then
  smoke_ok=1
fi
if [[ "${smoke_ok}" -eq 1 ]]; then
  echo "[build] Smoke OK: binario con módulos del core común."
else
  echo "[build] ERROR: self-test falló; revisa hidden-imports o el config."
  exit 1
fi