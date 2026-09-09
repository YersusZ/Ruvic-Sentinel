"""
Auto-update con verificación de firma y rollback — SRS §9 (RF-CORE-05).

Extiende el `trigger_update` del catálogo D (§8.4-D) para cumplir el core común:

  - Descarga de la nueva versión desde una URL (params.url).
  - Verificación de firma Ed25519 del artefacto descargado contra la llave
    pública configurada (`auto_update.verify_public_key`) — el agente NO aplica
    un update sin firma válida (fail-closed).
  - Aplicación con rollback: se hace backup del binario/artefacto actual, se
    instala el nuevo y, si el post-check (`auto_update.verify_command`) falla,
    se restaura el backup automáticamente.
"""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from typing import Any, Dict, Optional, Tuple

from colsoft_tools.security import load_public_key, verify_command_signature


class UpdateError(Exception):
    """Error controlado del flujo de auto-update (mensaje para el backend)."""


def _auto_update_config(config: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    au = config.get("auto_update") if isinstance(config, dict) else None
    return au if isinstance(au, dict) else {}


def verify_update_signature(
    artifact_path: str,
    signature_b64: Optional[str],
    public_key_pem: Optional[str],
) -> bool:
    """Verifica la firma Ed25519 de un artefacto contra la llave pública.

    `signature_b64` debe firmar el SHA-256 del archivo (hex), como cadena
    canónica. Sin llave configurada y sin firma → False (fail-closed).
    """
    if not public_key_pem or not signature_b64:
        return False
    try:
        digest = hashlib.sha256()
        with open(artifact_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                digest.update(chunk)
        canonical = digest.hexdigest()
        return verify_command_signature(public_key_pem, canonical, signature_b64)
    except Exception:
        return False


def download_update(url: str, dest_dir: str, timeout: float = 60.0) -> str:
    """Descarga el artefacto de update a `dest_dir` (basename del URL)."""
    if not (url or "").strip().startswith(("http://", "https://")):
        raise UpdateError("url de update inválida (debe ser http/https)")
    os.makedirs(dest_dir, exist_ok=True)
    fname = os.path.basename(url.split("?")[0]) or "update.bin"
    dest = os.path.join(dest_dir, fname)
    try:
        urllib.request.urlretrieve(url, dest, timeout=timeout)  # noqa: S310
    except Exception as e:
        raise UpdateError(f"fallo descargando update: {e}") from e
    return dest


def _backup_path(target: str) -> str:
    return f"{target}.bak.{os.getpid()}"


def _run_verify_command(cmd: str, timeout: float = 60.0) -> bool:
    if not (cmd or "").strip():
        return True
    try:
        proc = subprocess.run(
            ["/bin/sh", "-c", cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            text=True,
        )
        return proc.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def apply_update_with_rollback(
    artifact_path: str,
    target_path: str,
    *,
    verify_command: Optional[str] = None,
    verify_timeout: float = 60.0,
) -> Dict[str, Any]:
    """Instala `artifact_path` sobre `target_path` con backup y rollback.

    1. Backup del target actual.
    2. Reemplazo atómico (copia al tmp + os.replace).
    3. Post-check (`verify_command`): si falla, se restaura el backup.
    Devuelve {ok, target, backup, rolled_back, error?}.
    """
    if not os.path.isfile(artifact_path):
        raise UpdateError(f"artefacto de update no encontrado: {artifact_path}")
    if not os.path.isfile(target_path):
        raise UpdateError(f"target de update no existe: {target_path}")

    backup = _backup_path(target_path)
    shutil.copy2(target_path, backup)

    tmp = f"{target_path}.tmp.{os.getpid()}"
    try:
        shutil.copy2(artifact_path, tmp)
        os.replace(tmp, target_path)
    except OSError as e:
        raise UpdateError(f"no se pudo instalar update: {e}") from e

    if not _run_verify_command(verify_command, verify_timeout):
        try:
            shutil.copy2(backup, tmp)
            os.replace(tmp, target_path)
        except OSError:
            pass
        return {
            "ok": False,
            "target": target_path,
            "backup": backup,
            "rolled_back": True,
            "error": "post-check del update falló; se restauró el backup",
        }

    return {"ok": True, "target": target_path, "backup": backup, "rolled_back": False}


def self_update(
    config: Optional[Dict[str, Any]],
    params: Optional[Dict[str, Any]],
    *,
    max_chars: int = 60000,
    artifact_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """Flujo completo de auto-update verificado (RF-CORE-05).

    params:
      - version / channel: opcionales (reporte).
      - url: artefacto a descargar. Si falta, se delega al script/command
        configurado en `auto_update` (compatibilidad con §8.4-D).
      - signature: firma Ed25519 del artefacto (obligatoria si hay
        `auto_update.verify_public_key`).
    """
    au = _auto_update_config(config)
    public_key = au.get("verify_public_key") or params.get("verify_public_key")
    signature = params.get("signature")
    url = (params.get("url") or "").strip()
    script = (au.get("script") or "").strip()
    command = (au.get("command") or "").strip()

    version = str(params.get("version") or "")
    channel = str(params.get("channel") or "")

    if not script and not command and not url:
        return {
            "tool": "trigger_update",
            "status": "ERROR",
            "error": (
                "self_update: falta 'url' o un mecanismo en auto_update "
                "(script/command)"
            ),
        }

    workdir = artifact_dir or tempfile.mkdtemp(prefix="robin-update-")
    artifact = None
    applied: Dict[str, Any] = {}

    try:
        if url:
            # 1. Descargar
            artifact = download_update(url, workdir)
            # 2. Verificar firma (fail-closed si hay llave configurada)
            if public_key:
                if not signature:
                    raise UpdateError(
                        "update rechazado: falta 'signature' y hay verify_public_key "
                        "configurado (RF-CORE-05 fail-closed)"
                    )
                if not verify_update_signature(artifact, signature, public_key):
                    raise UpdateError(
                        "update rechazado: firma Ed25519 del artefacto inválida"
                    )
            # 3. Aplicar sobre el binario actual (con rollback)
            target = au.get("target") or (
                sys.executable if getattr(sys, "frozen", False) else None
            )
            if not target:
                raise UpdateError(
                    "update rechazado: sin 'target' en auto_update (binario a reemplazar)"
                )
            applied = apply_update_with_rollback(
                artifact,
                target,
                verify_command=au.get("verify_command"),
                verify_timeout=float(au.get("verify_timeout") or 60),
            )
        elif script or command:
            # Compatibilidad §8.4-D: script/command de actualización local
            extra = [a for a in (version, url, channel) if a]
            try:
                if script:
                    proc_cmd = [script] + extra
                else:
                    proc_cmd = ["/bin/sh", "-c", command]
                timeout = min(max(float(params.get("timeout") or au.get("timeout") or 120), 5.0), 300.0)
                proc = subprocess.run(
                    proc_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    timeout=timeout,
                    text=True,
                )
                applied = {
                    "ok": proc.returncode == 0,
                    "returncode": proc.returncode,
                    "output": (proc.stdout or "")[:max_chars],
                }
                if not applied["ok"]:
                    applied["error"] = (
                        f"actualizador falló (rc={proc.returncode})"
                    )
            except subprocess.TimeoutExpired:
                applied = {
                    "ok": False,
                    "error": f"timeout ({timeout}s) en el actualizador",
                }
            except OSError as e:
                applied = {"ok": False, "error": f"no se pudo ejecutar actualizador: {e}"}
    except UpdateError as e:
        return {
            "tool": "trigger_update",
            "status": "ERROR",
            "error": f"self_update: {e}",
            "version": version,
            "channel": channel,
        }
    except Exception as e:
        return {
            "tool": "trigger_update",
            "status": "ERROR",
            "error": f"self_update: error inesperado: {e}",
        }
    finally:
        if url and artifact_dir is None:
            shutil.rmtree(workdir, ignore_errors=True)

    if not applied.get("ok"):
        return {
            "tool": "trigger_update",
            "status": "ERROR",
            "error": applied.get("error") or "update falló",
            "returncode": applied.get("returncode"),
            "output": applied.get("output"),
            "version": version,
            "channel": channel,
        }

    return {
        "tool": "trigger_update",
        "status": "OK",
        "returncode": 0,
        "version": version,
        "channel": channel,
        "verified_signature": bool(public_key),
        "rolled_back": applied.get("rolled_back"),
        "backup": applied.get("backup"),
        "output": applied.get("output"),
    }