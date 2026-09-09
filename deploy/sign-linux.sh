#!/usr/bin/env bash
# Firma GPG de .deb / .rpm (§16).
# Env:
#   GPG_KEY_ID     id o email de la clave (obligatorio)
#   GPG_PASSPHRASE opcional (no interactivo)
# Uso: ./deploy/sign-linux.sh dist/robin-client-monitor_0.9.0_amd64.deb
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Uso: $0 <paquete.deb|paquete.rpm> [...]" >&2
  exit 1
fi
KEY="${GPG_KEY_ID:-}"
if [[ -z "${KEY}" ]]; then
  echo "ERROR: definí GPG_KEY_ID (fingerprint o email de la clave de firma)" >&2
  exit 1
fi

sign_deb() {
  local f="$1"
  if command -v dpkg-sig >/dev/null 2>&1; then
    dpkg-sig --sign builder -k "${KEY}" "${f}"
    return
  fi
  if command -v debsigs >/dev/null 2>&1; then
    debsigs --sign=origin -k "${KEY}" "${f}"
    return
  fi
  echo "ERROR: instalá dpkg-sig o debsigs para firmar ${f}" >&2
  return 1
}

sign_rpm() {
  local f="$1"
  if ! command -v rpmsign >/dev/null 2>&1 && ! command -v rpm >/dev/null 2>&1; then
    echo "ERROR: rpm/rpmsign no está en PATH" >&2
    return 1
  fi
  rpm --addsign --define "_gpg_name ${KEY}" "${f}"
}

for f in "$@"; do
  if [[ ! -f "${f}" ]]; then
    echo "ERROR: no existe ${f}" >&2
    exit 1
  fi
  case "${f}" in
    *.deb) sign_deb "${f}"; echo "[sign] OK ${f}" ;;
    *.rpm) sign_rpm "${f}"; echo "[sign] OK ${f}" ;;
    *) echo "ERROR: extensión no soportada: ${f}" >&2; exit 1 ;;
  esac
done
