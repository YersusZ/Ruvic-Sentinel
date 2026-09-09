"""
Gestor de configuración del agente — SRS §9 (RF-CORE-03).

Valida el `config_client.json` contra un esquema ANTES de aplicar cualquier
cambio (carga inicial y diffs remotos de §8.4-D). Centraliza:

  - Esquema completo de tipos por clave (`CONFIG_SCHEMA`).
  - Claves protegidas (no modificables en remoto).
  - `validate_full_config`: valida un config completo (carga local).
  - `validate_config_diff`: valida un diff remoto (parcial, top-level).
  - `load_config`: lee + valida desde disco con fallos claros.
  - `apply_config_diff`: aplica un diff validado con backup y escritura atómica.

`colsoft_tools/agent_admin.py` (catálogo D) y los clientes reutilizan este
módulo para garantizar que ninguna configuración inválida entre en vigor.
"""

import copy
import json
import os
import shutil
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

# Default de auditoría local (§8.5). Vacío/ausente en config → este path
# (relativo al cwd / APP_DIR).
DEFAULT_AUDIT_LOG_PATH = os.path.join("results_logs", "agent_audit.jsonl")

# --- Esquema de configuración del agente (§9 RF-CORE-03) ---
# Tipos permitidos para cada clave de config_client.json. `_coerce` normaliza
# (bool a partir de "true"/"1", números a partir de strings, etc.).
CONFIG_SCHEMA: Dict[str, str] = {
    "client_name": "str",
    "identity_dir": "str",
    "agent_id": "str",
    "tenant_id": "str",
    "websocket_url": "str",
    "private_key": "str",
    "public_key": "str",
    "signing_public_key": "str",
    "require_command_signature": "bool",
    "allow_insecure_ws": "bool",
    "tls_ca_cert": "str",
    "tls_client_cert": "str",
    "tls_client_key": "str",
    "heartbeat_interval": "num",
    "max_chars": "num",
    # Alias deprecados de scheduler.interval_seconds / scheduler.tools.
    "minute_interval": "num",
    "tools_execution_interval": "list",
    "policy": "dict",
    "scripts_catalog": "dict",
    "audit_log_path": "str",
    "max_command_rate": "num",
    "auto_update": "dict",
    "telemetry_buffer": "dict",
    "tamper": "dict",
    "scheduler": "dict",
    "data_plane": "dict",
    "process_watch": "dict",
    "service_watch": "dict",
    "health_probes": "dict",
    "alerts": "dict",
    "security": "dict",
    "windows": "dict",
    "linux": "dict",
    "cloud": "dict",
}

# mTLS / firma / política / destino de canal: nadie con un solo canal remoto
# puede degradar el doble candado ni redirigir WS/OTLP.
PROTECTED_CONFIG_KEYS = {
    "private_key",
    "public_key",
    "signing_public_key",
    "require_command_signature",
    "allow_insecure_ws",
    "tls_ca_cert",
    "tls_client_cert",
    "tls_client_key",
    "policy",
    "scripts_catalog",
    "websocket_url",
    "data_plane",
}

_MAX_DIFF_KEYS = 100


def _coerce(value: Any, kind: str) -> Optional[Any]:
    """Coerciona `value` al tipo esperado por el esquema; None si es inválido."""
    if kind == "str":
        return value if isinstance(value, str) else None
    if kind == "bool":
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            low = value.strip().lower()
            if low in ("true", "1", "yes", "si", "on", "enabled"):
                return True
            if low in ("false", "0", "no", "off", "disabled"):
                return False
        if isinstance(value, (int, float)) and value in (0, 1):
            return bool(value)
        return None
    if kind == "num":
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            return value
        if isinstance(value, str):
            try:
                return float(value)
            except (TypeError, ValueError):
                return None
        return None
    if kind == "list":
        return value if isinstance(value, list) else None
    if kind == "dict":
        return value if isinstance(value, dict) else None
    return None


def validate_full_config(config: Any) -> Tuple[Dict[str, Any], List[str]]:
    """Valida un config completo contra el esquema.

    Devuelve (config_normalizado, errores). Las claves desconocidas o con tipo
    inválido se reportan; las válidas se conservan normalizadas. No se usan los
    valores inválidos (el config no debe entrar en vigor con datos corruptos).
    """
    errors: List[str] = []
    if not isinstance(config, dict):
        return {}, ["config debe ser un objeto JSON (dict)"]

    normalized: Dict[str, Any] = {}
    for key, value in config.items():
        key = str(key)
        if key in ("_docs", "_comment", "_version"):
            continue
        if key not in CONFIG_SCHEMA:
            errors.append(f"clave desconocida '{key}'")
            continue
        coerced = _coerce(value, CONFIG_SCHEMA[key])
        if coerced is None and not (
            isinstance(value, bool) and CONFIG_SCHEMA[key] == "bool"
        ):
            errors.append(
                f"tipo inválido para '{key}': esperaba {CONFIG_SCHEMA[key]}"
            )
            continue
        normalized[key] = coerced

    return normalized, errors


def validate_config_diff(diff: Any) -> Tuple[Dict[str, Any], List[str]]:
    """Valida un diff remoto contra el esquema (top-level, parcial).

    Devuelve (diff_normalizado, errores). Un diff se rechaza completo si tiene
    alguna clave desconocida, protegida o con tipo inválido (no se aplica nada).
    """
    errors: List[str] = []
    if not isinstance(diff, dict) or not diff:
        return {}, ["diff debe ser un objeto no vacío"]
    if len(diff) > _MAX_DIFF_KEYS:
        return {}, [f"diff con más de {_MAX_DIFF_KEYS} claves"]

    normalized: Dict[str, Any] = {}
    for key, value in diff.items():
        key = str(key)
        if key not in CONFIG_SCHEMA:
            errors.append(f"clave desconocida '{key}'")
            continue
        if key in PROTECTED_CONFIG_KEYS:
            errors.append(
                f"clave protegida '{key}' (requiere intervención local)"
            )
            continue
        coerced = _coerce(value, CONFIG_SCHEMA[key])
        if coerced is None and not (
            isinstance(value, bool) and CONFIG_SCHEMA[key] == "bool"
        ):
            errors.append(
                f"tipo inválido para '{key}': esperaba {CONFIG_SCHEMA[key]}"
            )
            continue
        normalized[key] = coerced

    return normalized, errors


def default_config_path() -> str:
    if getattr(sys, "frozen", False) and getattr(sys, "executable", None):
        return os.path.join(
            os.path.dirname(os.path.abspath(sys.executable)),
            "config_client.json",
        )
    return "config_client.json"


def load_config(config_file: Optional[str]) -> Tuple[Dict[str, Any], List[str], str]:
    """Lee y valida el config desde disco.

    Devuelve (config_normalizado, errores, path). Si el archivo no existe o no
    es JSON, devuelve ({}, [error], path) — el llamador decide si continuar
    con defaults seguros o abortar.
    """
    path = config_file or default_config_path()
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except OSError as e:
        return {}, [f"no se pudo leer {path}: {e}"], path
    except ValueError as e:
        return {}, [f"JSON inválido en {path}: {e}"], path

    normalized, errors = validate_full_config(raw)
    return normalized, errors, path


def atomic_write(path: str, data: Dict[str, Any]) -> None:
    d = os.path.dirname(os.path.abspath(path))
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def apply_config_diff(
    disk_config: Dict[str, Any],
    config_file: str,
    normalized_diff: Dict[str, Any],
    remove_keys: List[str] = None,
) -> Tuple[Dict[str, Any], Optional[str]]:
    """Aplica un diff ya validado sobre el config de disco.

    Devuelve (config_final, backup_path). Hace backup previo + escritura
    atómica. `remove_keys` elimina claves (no protegidas) del config final.
    """
    base = copy.deepcopy(disk_config) if disk_config else {}
    backup = f"{config_file}.bak.{int(time.time())}"
    try:
        shutil.copy2(config_file, backup)
    except OSError:
        backup = None

    for k in (remove_keys or []):
        base.pop(k, None)
    base.update(normalized_diff)

    atomic_write(config_file, base)
    return base, backup