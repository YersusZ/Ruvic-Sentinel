# shellcheck shell=bash
# Instala PNG + .desktop bajo un prefijo (staging o sistema vivo).
# Uso: linux_icon_install DEST_PREFIX PNG DESKTOP [name]

linux_icon_install() {
  local dest="${1:-}"
  local png="$2"
  local desktop="$3"
  local name="${4:-robin-client-monitor}"
  if [[ ! -f "${png}" || ! -f "${desktop}" ]]; then
    return 1
  fi
  mkdir -p "${dest}/usr/share/icons/hicolor/512x512/apps"
  mkdir -p "${dest}/usr/share/pixmaps"
  mkdir -p "${dest}/usr/share/applications"
  install -m 0644 "${png}" "${dest}/usr/share/icons/hicolor/512x512/apps/${name}.png"
  install -m 0644 "${png}" "${dest}/usr/share/pixmaps/${name}.png"
  install -m 0644 "${desktop}" "${dest}/usr/share/applications/${name}.desktop"
}

linux_icon_refresh() {
  gtk-update-icon-cache -f /usr/share/icons/hicolor >/dev/null 2>&1 || true
  update-desktop-database /usr/share/applications >/dev/null 2>&1 || true
}
