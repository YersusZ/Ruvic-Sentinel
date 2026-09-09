#!/usr/bin/env bash
# Empaqueta el binario PyInstaller en .deb y/o .rpm (§16).
# Uso:
#   ./deploy/pack-linux.sh [ruta-al-binario]
# Env:
#   VERSION          default 0.9.0 (colsoft_tools.agent_admin.AGENT_VERSION)
#   ARCH             default: uname -m → amd64/arm64 (deb) y x86_64/aarch64 (rpm)
#   OUT_DIR          default dist/
#   SKIP_DEB / SKIP_RPM  1 para omitir
# Firma GPG (opcional, después): ./deploy/sign-linux.sh dist/*.deb dist/*.rpm
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${VERSION:-0.9.0}"
BIN_SRC="${1:-${ROOT}/dist/robin-client-monitor}"
OUT_DIR="${OUT_DIR:-${ROOT}/dist}"
UNIT="${ROOT}/deploy/robin-client-monitor.service"
CFG="${ROOT}/deploy/config_client.packaged.json"
DESKTOP="${ROOT}/deploy/robin-client-monitor.desktop"
POSTINST="${ROOT}/deploy/linux-pkg/postinst"
PRERM="${ROOT}/deploy/linux-pkg/prerm"
NAME="robin-client-monitor"
MAINTAINER="Ruvic Colsoft <ops@ruvic.xyz>"
# shellcheck source=linux-icon.sh
source "${ROOT}/deploy/linux-icon.sh"

ICON_PNG=""
for cand in \
  "${ROOT}/assets/ws-client-icon.png" \
  "${OUT_DIR}/robin-client-monitor.png" \
  "$(dirname "${BIN_SRC}")/robin-client-monitor.png"; do
  if [[ -f "${cand}" ]]; then
    ICON_PNG="${cand}"
    break
  fi
done

if [[ ! -f "${BIN_SRC}" ]]; then
  echo "ERROR: no existe el binario ${BIN_SRC} (corre ./build.sh primero)" >&2
  exit 1
fi
if [[ ! -f "${UNIT}" || ! -f "${CFG}" ]]; then
  echo "ERROR: faltan ${UNIT} o ${CFG}" >&2
  exit 1
fi

HOST_ARCH="$(uname -m)"
RAW_ARCH="${ARCH:-${HOST_ARCH}}"
case "${RAW_ARCH}" in
  x86_64|amd64) DEB_ARCH="amd64"; RPM_ARCH="x86_64" ;;
  aarch64|arm64) DEB_ARCH="arm64"; RPM_ARCH="aarch64" ;;
  *)
    echo "ERROR: ARCH no soportado: ${RAW_ARCH} (use amd64/x86_64 o arm64/aarch64)" >&2
    exit 1
    ;;
esac

mkdir -p "${OUT_DIR}"
STAGING="$(mktemp -d)"
cleanup() { rm -rf "${STAGING}"; }
trap cleanup EXIT

APP_DIR="${STAGING}/opt/${NAME}"
mkdir -p "${APP_DIR}" "${STAGING}/etc/systemd/system" "${STAGING}/usr/lib/${NAME}"
install -m 0755 "${BIN_SRC}" "${APP_DIR}/${NAME}"
install -m 0600 "${CFG}" "${APP_DIR}/config_client.json"
install -m 0644 "${UNIT}" "${STAGING}/etc/systemd/system/${NAME}.service"
install -m 0755 "${POSTINST}" "${STAGING}/usr/lib/${NAME}/postinst"
install -m 0755 "${PRERM}" "${STAGING}/usr/lib/${NAME}/prerm"
ICON_RPM_INSTALL=""
ICON_RPM_FILES=""
if [[ -n "${ICON_PNG}" ]] && linux_icon_install "${STAGING}" "${ICON_PNG}" "${DESKTOP}" "${NAME}"; then
  echo "[pack] icono ${ICON_PNG} + ${DESKTOP}"
  ICON_RPM_INSTALL="mkdir -p %{buildroot}/usr/share/icons/hicolor/512x512/apps
mkdir -p %{buildroot}/usr/share/pixmaps
mkdir -p %{buildroot}/usr/share/applications
install -m 0644 ${ICON_PNG} %{buildroot}/usr/share/icons/hicolor/512x512/apps/${NAME}.png
install -m 0644 ${ICON_PNG} %{buildroot}/usr/share/pixmaps/${NAME}.png
install -m 0644 ${DESKTOP} %{buildroot}/usr/share/applications/${NAME}.desktop"
  ICON_RPM_FILES="/usr/share/icons/hicolor/512x512/apps/${NAME}.png
/usr/share/pixmaps/${NAME}.png
/usr/share/applications/${NAME}.desktop"
else
  echo "[pack] AVISO: sin PNG/desktop; el paquete irá sin icono (corre ./build.sh)" >&2
fi

echo "[pack] staging ${STAGING} version=${VERSION} deb=${DEB_ARCH} rpm=${RPM_ARCH}"

# --- .deb ---
if [[ "${SKIP_DEB:-}" != "1" ]]; then
  if ! command -v dpkg-deb >/dev/null 2>&1; then
    echo "[pack] AVISO: dpkg-deb no está; omito .deb (apt install dpkg)" >&2
  else
    DEBIAN="${STAGING}/DEBIAN"
    mkdir -p "${DEBIAN}"
    cat > "${DEBIAN}/control" <<EOF
Package: ${NAME}
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: ${DEB_ARCH}
Maintainer: ${MAINTAINER}
Depends: systemd
Description: Robin Client Monitor (agente de endpoint)
 Agente WebSocket/OTLP con unidad systemd. Enrollment con token de un solo uso
 (RF-CORE-01/02) vía ROBIN_ENROLL_TOKEN en postinst o install-linux.sh.
EOF
    printf '%s\n' "/opt/${NAME}/config_client.json" > "${DEBIAN}/conffiles"
    install -m 0755 "${POSTINST}" "${DEBIAN}/postinst"
    install -m 0755 "${PRERM}" "${DEBIAN}/prerm"
    DEB_OUT="${OUT_DIR}/${NAME}_${VERSION}_${DEB_ARCH}.deb"
    DPKG_ARGS=(--build "${STAGING}" "${DEB_OUT}")
    if dpkg-deb --help 2>&1 | grep -q root-owner-group; then
      DPKG_ARGS=(--root-owner-group --build "${STAGING}" "${DEB_OUT}")
    fi
    dpkg-deb "${DPKG_ARGS[@]}"
    echo "[pack] OK ${DEB_OUT}"
  fi
fi

# --- .rpm ---
if [[ "${SKIP_RPM:-}" != "1" ]]; then
  if ! command -v rpmbuild >/dev/null 2>&1; then
    echo "[pack] AVISO: rpmbuild no está; omito .rpm (dnf install rpm-build)" >&2
  else
    RPM_ROOT="${STAGING}-rpm"
    mkdir -p "${RPM_ROOT}"/{BUILD,RPMS,SOURCES,SPECS,BUILDROOT}
    SPEC="${RPM_ROOT}/SPECS/${NAME}.spec"
    # rpmbuild no usa el staging Debian; re-instalamos en BUILDROOT vía spec.
    cat > "${SPEC}" <<EOF
Name: ${NAME}
Version: ${VERSION}
Release: 1%{?dist}
Summary: Robin Client Monitor (endpoint agent)
License: Proprietary
Group: Applications/System
URL: https://ruvic.xyz
BuildArch: ${RPM_ARCH}
Requires: systemd

%description
Agente WebSocket/OTLP con unidad systemd. Enrollment (RF-CORE-01/02) vía
ROBIN_ENROLL_TOKEN en %%post o deploy/install-linux.sh.

%install
mkdir -p %{buildroot}/opt/${NAME}
mkdir -p %{buildroot}/etc/systemd/system
mkdir -p %{buildroot}/usr/lib/${NAME}
install -m 0755 ${BIN_SRC} %{buildroot}/opt/${NAME}/${NAME}
install -m 0600 ${CFG} %{buildroot}/opt/${NAME}/config_client.json
install -m 0644 ${UNIT} %{buildroot}/etc/systemd/system/${NAME}.service
install -m 0755 ${POSTINST} %{buildroot}/usr/lib/${NAME}/postinst
install -m 0755 ${PRERM} %{buildroot}/usr/lib/${NAME}/prerm
${ICON_RPM_INSTALL}

%files
%attr(0755,root,root) /opt/${NAME}/${NAME}
%config(noreplace) %attr(0600,root,root) /opt/${NAME}/config_client.json
/etc/systemd/system/${NAME}.service
/usr/lib/${NAME}/postinst
/usr/lib/${NAME}/prerm
${ICON_RPM_FILES}

%post
/bin/sh /usr/lib/${NAME}/postinst

%preun
/bin/sh /usr/lib/${NAME}/prerm

%changelog
* $(date -u '+%a %b %d %Y') ${MAINTAINER} - ${VERSION}-1
- Paquete §16
EOF
    rpmbuild -bb \
      --define "_topdir ${RPM_ROOT}" \
      --define "_rpmdir ${OUT_DIR}" \
      --define "_build_name_fmt ${NAME}-${VERSION}-1.${RPM_ARCH}.rpm" \
      "${SPEC}"
    # rpmbuild may nest RPMS/<arch>/
    FOUND="$(find "${OUT_DIR}" "${RPM_ROOT}/RPMS" -name "${NAME}-${VERSION}*.rpm" 2>/dev/null | head -1 || true)"
    if [[ -n "${FOUND}" && "${FOUND}" != "${OUT_DIR}/${NAME}-${VERSION}-1.${RPM_ARCH}.rpm" ]]; then
      mv -f "${FOUND}" "${OUT_DIR}/${NAME}-${VERSION}-1.${RPM_ARCH}.rpm"
    fi
    echo "[pack] OK ${OUT_DIR}/${NAME}-${VERSION}-1.${RPM_ARCH}.rpm"
  fi
fi

echo "[pack] listo. Firma: ./deploy/sign-linux.sh ${OUT_DIR}/${NAME}_*.deb ${OUT_DIR}/${NAME}-*.rpm"
