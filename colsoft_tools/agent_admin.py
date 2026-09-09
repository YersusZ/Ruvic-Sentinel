"""
Administración del agente — SRS §8.4-D.

Implementa las acciones del catálogo D (admin del agente):
  - `update_config` : aplica un diff remoto sobre config_client.json con
    validación de esquema, backup atómico y claves de seguridad protegidas
    (no modificables en remoto — doble candado).
  - `trigger_update`: dispara el auto-update del agente vía un verificador /
    instalador local (`auto_update.script` o `auto_update.command`).
  - `restart_agent`  : reinicia el proceso del agente (re-exec con los mismos
    argumentos) DESPUÉS de que el cliente confirme la respuesta al backend.
  - `health_check`   : reporta el estado de salud del agente (uptime, versión,
    validez del config, etc.).

El control remoto de estas acciones pasa por el mismo plano de control: el
backend los emite como comandos con riesgo del catálogo (§8.4-D) y el agente
los ejecuta tras la verificación de firma y política local (§8.2/§8.5).
"""

import asyncio
import copy
import json
import os
import platform
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

from colsoft_tools.config_manager import (
    CONFIG_SCHEMA,  # noqa: F401  (re-export para compatibilidad)
    PROTECTED_CONFIG_KEYS,  # noqa: F401
    apply_config_diff,
    default_config_path,
    validate_config_diff,
)

# Versión del agente (build artefacto / release). Se reporta en health_check.
AGENT_VERSION = "0.9.0"

# Marca reservada que `restart_agent` inyecta en el resultado para que el
# cliente la detecte y programe el re-exec DESPUÉS de responder al backend.
RESTART_MARKER = "_agent_restart"

_PROCESS_START_TS = time.time()
_PROCESS_START_ISO = time.strftime(
    "%Y-%m-%dT%H:%M:%SZ", time.gmtime(_PROCESS_START_TS)
)

def _resource_snapshot() -> Dict[str, Any]:
    """RSS / CPU del proceso (NFR §15). Fail-open."""
    out: Dict[str, Any] = {}
    rss_bytes = None
    try:
        with open(f"/proc/{os.getpid()}/status", encoding="utf-8") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    rss_bytes = int(line.split()[1]) * 1024
                    break
    except (OSError, ValueError, IndexError):
        rss_bytes = None
    if rss_bytes is None:
        try:
            import resource as _res

            ru = _res.getrusage(_res.RUSAGE_SELF).ru_maxrss
            # Linux: kB; macOS: bytes.
            rss_bytes = int(ru) * 1024 if ru < 10_000_000 else int(ru)
        except Exception:
            rss_bytes = None
    if rss_bytes is not None:
        out["rss_bytes"] = rss_bytes
        out["rss_mb"] = round(rss_bytes / (1024 * 1024), 1)
    try:
        import psutil

        proc = psutil.Process(os.getpid())
        out["cpu_percent"] = proc.cpu_percent(interval=0.05)
        mem = proc.memory_info()
        out["rss_bytes"] = int(mem.rss)
        out["rss_mb"] = round(mem.rss / (1024 * 1024), 1)
    except Exception:
        pass
    return out


_default_config_path = default_config_path


def _load_disk_config(config_file: Optional[str]) -> Tuple[Dict[str, Any], str]:
    path = config_file or default_config_path()
    # Lectura RAW del disco (se conserva `_docs` y claves desconocidas al
    # reescribir); la validación de esquema corre por separado (RF-CORE-03).
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f), path
    except Exception:
        return {}, path


def update_config(
    config: Optional[Dict[str, Any]],
    config_file: Optional[str],
    params: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Aplica un diff remoto al config_client.json con validación de esquema.

    params:
      - config_diff | diff | config  (dict): claves a añadir/actualizar (top-level).
        `config_diff` es el nombre del SRS §8.4-D.
      - remove (list): claves a eliminar del config (opcional).

    Claves desconocidas/protegidas/tipo inválido → rechazo completo (nada se
    aplica). Se hace backup del archivo previo y escritura atómica.
    """
    params = params or {}
    diff = None
    for key in ("config_diff", "diff", "config"):
        if key in params and params[key] is not None:
            diff = params[key]
            break
    if diff is None:
        return {
            "tool": "update_config",
            "status": "ERROR",
            "error": "update_config: falta 'config_diff' (SRS) / 'diff' (objeto con claves a aplicar)",
        }

    normalized, errors = validate_config_diff(diff)
    if errors:
        return {
            "tool": "update_config",
            "status": "ERROR",
            "error": "update_config rechazado: " + "; ".join(errors[:8]),
            "errors": errors[:20],
        }

    remove = params.get("remove") or []
    if isinstance(remove, str):
        remove = [remove]
    remove_keys = [str(k) for k in (remove if isinstance(remove, list) else [])]
    bad_remove = [k for k in remove_keys if k in PROTECTED_CONFIG_KEYS]
    if bad_remove:
        return {
            "tool": "update_config",
            "status": "ERROR",
            "error": "update_config rechazado: no se pueden eliminar claves protegidas: "
            + ", ".join(bad_remove[:8]),
        }

    disk, path = _load_disk_config(config_file)
    base = disk or copy.deepcopy(config or {})

    base_final, backup = apply_config_diff(
        base,
        path,
        normalized,
        remove_keys,
    )

    return {
        "tool": "update_config",
        "status": "OK",
        "applied": sorted(normalized),
        "removed": sorted(k for k in remove_keys if k in disk or k in (config or {})),
        "backup": backup,
        "config_file": path,
        "note": "Los cambios aplican en el próximo reinicio del agente.",
    }


def trigger_update(
    config: Optional[Dict[str, Any]],
    params: Optional[Dict[str, Any]],
    *,
    max_chars: int = 60000,
) -> Dict[str, Any]:
    """Dispara el auto-update del agente (§8.4-D + RF-CORE-05).

    Con `auto_update.verify_public_key` y/o `params.url` delega en
    `colsoft_tools/self_update.py` (firma Ed25519 + rollback). Sin esos campos
    mantiene la compatibilidad con el mecanismo legacy (§8.4-D): ejecuta el
    script/command definido en `auto_update`.
    """
    params = params or {}
    au = config.get("auto_update") if isinstance(config, dict) else None
    if not isinstance(au, dict):
        return {
            "tool": "trigger_update",
            "status": "ERROR",
            "error": (
                "trigger_update: auto-update no configurado "
                "(clave 'auto_update' en config_client.json)"
            ),
        }

    # RF-CORE-05: flujo verificado (url + firma) cuando hay URL o llave pública
    if au.get("verify_public_key") or (params.get("url") or "").strip():
        from colsoft_tools.self_update import self_update

        return self_update(config, params, max_chars=max_chars)

    script = (au.get("script") or "").strip()
    command = (au.get("command") or "").strip()

    timeout = float(params.get("timeout") or au.get("timeout") or 120)
    timeout = min(max(timeout, 5.0), 300.0)

    extra = [
        a
        for a in (
            str(params.get("version") or ""),
            str(params.get("url") or ""),
            str(params.get("channel") or ""),
        )
        if a
    ]

    label = ""
    if script:
        label = f"{script} {' '.join(extra)}".strip()
        proc_cmd = [script] + extra
    elif command:
        label = command
        if platform.system() == "Windows":
            proc_cmd = [os.environ.get("COMSPEC") or "cmd.exe", "/c", command]
        else:
            sh = "/bin/sh" if os.path.isfile("/bin/sh") else "sh"
            proc_cmd = [sh, "-c", command]
    else:
        return {
            "tool": "trigger_update",
            "status": "ERROR",
            "error": (
                "trigger_update: 'auto_update' sin 'script' ni 'command' "
                "en config_client.json"
            ),
        }

    try:
        proc = subprocess.run(
            proc_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            text=True,
        )
    except subprocess.TimeoutExpired:
        return {
            "tool": "trigger_update",
            "status": "ERROR",
            "error": f"trigger_update: timeout ({timeout}s) en el actualizador",
        }
    except OSError as e:
        return {
            "tool": "trigger_update",
            "status": "ERROR",
            "error": f"trigger_update: no se pudo ejecutar actualizador: {e}",
        }

    output = (proc.stdout or "")[:max_chars]
    if proc.returncode != 0:
        return {
            "tool": "trigger_update",
            "status": "ERROR",
            "returncode": proc.returncode,
            "error": f"trigger_update: actualizador falló (rc={proc.returncode})",
            "output": output,
        }
    return {
        "tool": "trigger_update",
        "status": "OK",
        "returncode": 0,
        "command": label,
        "output": output,
    }


def restart_agent(params: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Solicita el reinicio del proceso del agente (§8.4-D).

    Devuelve un resultado con la marca reservada `_agent_restart` (delay en s).
    El cliente la detecta y, tras confirmar la respuesta al backend, re-ejecuta
    el proceso con los mismos argumentos (nunca se sale del proceso sin antes
    notificar).
    """
    params = params or {}
    delay = float(params.get("delay") or 2.0)
    delay = min(max(delay, 0.5), 30.0)
    return {
        "tool": "restart_agent",
        "status": "OK",
        RESTART_MARKER: delay,
        "delay": delay,
        "pid": os.getpid(),
        "message": f"Agente se reiniciará en {delay:g}s (misma config/argumentos)",
    }


async def schedule_agent_restart(delay: float = 2.0) -> None:
    """Tras `delay` s, re-ejecuta el agente con los mismos argumentos.

    Se programa DESPUÉS de enviar la respuesta del comando `restart_agent`,
    dando tiempo al backend para recibir el resultado antes del re-exec.
    """
    delay = min(max(float(delay or 0), 0.0), 60.0)
    await asyncio.sleep(delay)
    if getattr(sys, "frozen", False):
        args = [sys.executable] + list(sys.argv[1:])
    else:
        args = [sys.executable] + list(sys.argv)
    os.execv(sys.executable, args)


def health_check(
    config: Optional[Dict[str, Any]],
    *,
    config_file: Optional[str] = None,
) -> Dict[str, Any]:
    """Reporta el estado de salud del agente (§8.4-D)."""
    path = config_file or _default_config_path()
    config_valid = False
    config_mtime = None
    disk: Any = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            disk = json.load(f)
        config_valid = isinstance(disk, dict)
        config_mtime = os.path.getmtime(path)
    except OSError:
        pass
    except ValueError:
        pass

    # RF-CORE-06: tamper-resistance — estado del baseline de binario/config/cert
    tamper_status = None
    try:
        from colsoft_tools.tamper import TamperMonitor

        tamper_status = TamperMonitor(disk if isinstance(disk, dict) else {}).status()
    except Exception:
        tamper_status = {"tamper_protection": "unavailable"}

    cloud = {}
    try:
        from colsoft_tools.cloud_metadata import fetch_cloud_metadata

        cloud = fetch_cloud_metadata(disk if isinstance(disk, dict) else None)
    except Exception:
        cloud = {}

    return {
        "tool": "health_check",
        "status": "OK",
        "version": AGENT_VERSION,
        "pid": os.getpid(),
        "ppid": os.getppid(),
        "start_time": _PROCESS_START_ISO,
        "uptime_s": round(time.time() - _PROCESS_START_TS, 3),
        "python_version": sys.version.split()[0],
        "executable": sys.executable,
        "cwd": os.getcwd(),
        "argv": list(sys.argv),
        "config_file": path,
        "config_valid": config_valid,
        "config_mtime": config_mtime,
        "tamper": tamper_status,
        "control_channel": "connected",
        "resources": _resource_snapshot(),
        "cloud": cloud or None,
    }
