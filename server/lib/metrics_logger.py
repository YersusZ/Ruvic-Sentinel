"""Robin Logger wrapper para el servidor de control (RobinLogs).

Taxonomía de ESTE agente (no tickets/SOC): docs/agent-telemetry.md.

Mejoras vs la versión 0.2.x:
  - JWT (robin-logger>=0.3.0): `ROBIN_LOGGER_JWT` / `ROBIN_LOGGER_JWT_TOKEN`;
    si hay JWT gana sobre API key (0.3.0).
  - Sanitiza `nan`/`inf` antes del JSON (no serializables).
  - Normaliza `warning` → `warn` (la API solo acepta debug|info|warn|error|fatal).
  - Timestamp `YYYY-MM-DD HH:MM:SS` UTC por evento (robin_logger.md).
  - Envío en thread daemon (no bloquea el event loop de uvicorn).
  - Stats de cache / retry / clear expuestos (`logger_status`, `retry_cached_logs`).
  - No-Op si faltan URL y credenciales (no falla el flujo de control).

Uso:
    from lib.metrics_logger import log_agent_event, log_tool_execution

    log_agent_event(agent_id, event_type="audit", category="system",
                    subcategory="agent_connected", level="info", data={...})

    # Ejecución de herramientas: categoriza por familia automáticamente
    # (network_check | observability | windows | linux | remediation | agent_admin | security).
    log_tool_execution(agent_id, "ping", message_id=..., command_status="success",
                       success=True, target="target=8.8.8.8 count=3",
                       result_summary="success=True", params={"host": "8.8.8.8"})
"""

import json
import math
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import requests
from dotenv import load_dotenv

try:
    from robin_logger import RobinLogger
except ImportError:  # pragma: no cover - entorno sin el paquete instalado
    RobinLogger = None  # type: ignore[assignment,misc]

# Singleton lazy + serialización del envío en segundo plano
_logger_instance: Optional[RobinLogger] = None
_logger_lock = threading.Lock()
_sender_pool = ThreadPoolExecutor(
    max_workers=4, thread_name_prefix="robin-logger"
)

# Levels aceptados por la API de RobinLogs
_VALID_LEVELS = ("debug", "info", "warn", "error", "fatal")

from colsoft_tools.data_plane import compact_logger_data
from colsoft_tools.protocol import resolve_command
from colsoft_tools.tool_catalog import (
    ADMIN_TOOLS,
    NETWORK_TOOLS,
    OBSERVABILITY_TOOLS,
    REMEDIATION_TOOLS,
    SECURITY_TOOLS,
    tool_category,
    tool_target_summary,
)

# Taxonomía: colsoft_tools/tool_catalog.py (docs/agent-telemetry.md).


def _load_env() -> None:
    BASE_DIR = Path(__file__).resolve().parent.parent  # server/
    load_dotenv(dotenv_path=BASE_DIR / ".env")


def _sanitize(value: Any) -> Any:
    """Reemplaza nan/inf (no serializables) por strings antes de enviar."""
    if isinstance(value, float):
        if math.isnan(value):
            return "NaN"
        if math.isinf(value):
            return "Infinity" if value > 0 else "-Infinity"
        return value
    if isinstance(value, dict):
        return {str(k): _sanitize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize(v) for v in value]
    return value


def _normalize_level(level: str) -> str:
    level = (level or "info").strip().lower()
    if level == "warning":
        return "warn"
    return level if level in _VALID_LEVELS else "info"


_VALID_COMMAND_STATUS = frozenset({"success", "error", "rejected", "expired"})


def _normalize_command_status(command_status: Optional[str], success: bool) -> str:
    """RDO: success|error|rejected|expired. `failed`/`UNKNOWN` no se emiten."""
    raw = (command_status or "").strip().lower()
    if raw == "failed":
        raw = "error"
    if raw in _VALID_COMMAND_STATUS:
        return raw
    return "success" if success else "error"


# SRS event.severity → level RobinLogs (debug|info|warn|error|fatal)
_SEVERITY_TO_LEVEL = {
    "debug": "debug",
    "info": "info",
    "low": "info",
    "medium": "warn",
    "warn": "warn",
    "warning": "warn",
    "high": "error",
    "error": "error",
    "critical": "fatal",
    "fatal": "fatal",
}

def _ingest_url(url: Optional[str]) -> Optional[str]:
    """Normaliza ROBIN_LOGGER_URL al endpoint de store, no al de consulta."""
    if not url:
        return url
    stripped = url.rstrip("/")
    if stripped.endswith("/api/logs"):
        fixed = stripped[: -len("/api/logs")] + "/api/robin-logger/store"
        print(
            "[LOGGER] ROBIN_LOGGER_URL apunta a GET /api/logs (consulta). "
            f"Usando ingesta {fixed}",
            flush=True,
        )
        return fixed
    return url


def query_url() -> Optional[str]:
    """URL de consulta GET /api/logs (no el endpoint de store)."""
    _load_env()
    explicit = (os.getenv("ROBIN_LOGGER_QUERY_URL") or "").strip().rstrip("/")
    if explicit:
        return explicit if explicit.endswith("/api/logs") else f"{explicit}/api/logs"

    raw = (os.getenv("ROBIN_LOGGER_URL") or "").strip().rstrip("/")
    if not raw:
        return None
    if raw.endswith("/api/logs"):
        return raw
    if raw.endswith("/api/robin-logger/store"):
        return raw[: -len("/api/robin-logger/store")] + "/api/logs"
    if raw.endswith("/api"):
        return f"{raw}/logs"
    return f"{raw}/api/logs"


def _query_headers() -> Dict[str, str]:
    _load_env()
    api_key = (os.getenv("ROBIN_LOGGER_API_KEY") or "").strip()
    jwt = (
        os.getenv("ROBIN_LOGGER_JWT") or os.getenv("ROBIN_LOGGER_JWT_TOKEN") or ""
    ).strip()
    headers: Dict[str, str] = {}
    if jwt:
        headers["Authorization"] = f"Bearer {jwt}"
    if api_key:
        headers["X-API-Key"] = api_key
        headers.setdefault("Authorization", f"Bearer {api_key}")
    return headers


# Query params que GET /api/logs de RobinLogs acepta (GET_LOGS.md).
LOGS_QUERY_PARAMS = (
    "date",
    "startDate",
    "endDate",
    "startHour",
    "endHour",
    "hour",
    "page",
    "limit",
    "per_page",
    "type",
    "category",
    "subcategory",
    "level",
    "agentId",
    "source",
    "tags",
    "search",
    "ip_dominio",
    "servicio_afectado",
    "userId",
    "user_id",
    "targetUserId",
)


class LogsQueryError(Exception):
    """Fallo al consultar RobinLogs (mapeable a HTTP en el REST)."""

    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _clean_logs_params(params: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Deja solo params documentados; resuelve alias SRS en subcategory."""
    out: Dict[str, Any] = {}
    for key, value in (params or {}).items():
        if key not in LOGS_QUERY_PARAMS or value is None or value == "":
            continue
        if key == "level" and str(value).strip().lower() == "warning":
            out[key] = "warn"
            continue
        if key == "subcategory" and isinstance(value, str):
            out[key] = resolve_command(value.strip()) or value
            continue
        out[key] = value
    if "per_page" in out and "limit" in out:
        out.pop("limit", None)
    from colsoft_tools.log_range import expand_query_window

    return expand_query_window(out)


def fetch_logs(
    params: Optional[Dict[str, Any]] = None,
    *,
    timeout: float = 30.0,
) -> Dict[str, Any]:
    """GET https://logs.robin-ai.xyz/api/logs (consulta; el SDK solo hace POST)."""
    url = query_url()
    headers = _query_headers()
    if not url or not headers:
        raise LogsQueryError(
            503,
            "RobinLogs no configurado: hacen falta ROBIN_LOGGER_URL "
            "y ROBIN_LOGGER_API_KEY o ROBIN_LOGGER_JWT",
        )
    q = _clean_logs_params(params)
    try:
        r = requests.get(url, headers=headers, params=q, timeout=timeout)
    except requests.RequestException as e:
        raise LogsQueryError(502, f"No se pudo contactar RobinLogs: {e}") from e
    if r.status_code == 401:
        raise LogsQueryError(
            502,
            "RobinLogs rechazó las credenciales (401). Revisa "
            "ROBIN_LOGGER_API_KEY / ROBIN_LOGGER_JWT.",
        )
    if r.status_code >= 400:
        raise LogsQueryError(
            502,
            f"RobinLogs HTTP {r.status_code}: {(r.text or '')[:400]}",
        )
    try:
        body = r.json()
    except ValueError as e:
        raise LogsQueryError(502, "RobinLogs no devolvió JSON") from e
    if not isinstance(body, dict):
        raise LogsQueryError(502, "RobinLogs devolvió un JSON inesperado")
    return body


def get_logger() -> Optional[RobinLogger]:
    """Singleton lazy. None (No-Op) si faltan URL y credenciales (URL + API key o JWT)."""
    global _logger_instance
    _load_env()

    url = _ingest_url(os.getenv("ROBIN_LOGGER_URL"))
    api_key = os.getenv("ROBIN_LOGGER_API_KEY")
    jwt = os.getenv("ROBIN_LOGGER_JWT") or os.getenv("ROBIN_LOGGER_JWT_TOKEN")
    if not url or (not api_key and not jwt):
        return None

    if _logger_instance is None:
        with _logger_lock:
            if _logger_instance is None:
                # async_mode=False: ya serializamos en `_sender_pool`. Si ambos
                # están activos, cada POST a RobinLogs abre más conexiones de las
                # que urllib3 reusa (pool=10) y aparece
                # "Connection pool is full, discarding connection".
                _logger_instance = RobinLogger(
                    base_url=url,
                    api_key=api_key,
                    jwt_token=jwt,
                    async_mode=False,
                )
    return _logger_instance


def log_agent_event(
    agent_id: str,
    event_type: str,      # 'audit', 'metrics', 'activity', ...
    category: str,        # 'system', 'network', 'observability', ...
    subcategory: str,     # 'agent_connected', 'tool_executed', ...
    level: str,           # 'debug' | 'info' | 'warn' | 'error' | 'fatal'
    data: Dict[str, Any],
    *,
    tenant_id: Optional[str] = None,
) -> None:
    """Envía un evento normalizado a RobinLogs (asíncrono, thread daemon).

    No-op si el logger no está configurado; nunca interrumpe el flujo.
    """
    logger = get_logger()
    if logger is None:
        return

    payload_data = {"agent_id": agent_id, **(_sanitize(data) if data else {})}
    if tenant_id:
        payload_data["tenant_id"] = tenant_id
    # robin_logger.md §3.1: `data.user_id` es el actor cuando existe.
    if payload_data.get("issued_by") and not payload_data.get("user_id"):
        payload_data["user_id"] = payload_data["issued_by"]
    payload_data = compact_logger_data(payload_data)

    ts = datetime.now(timezone.utc)
    # 0.3.0 normaliza a "YYYY-MM-DD HH:MM:SS" UTC; ISO-8601 también es válido.
    timestamp = ts.strftime("%Y-%m-%d %H:%M:%S")

    def _send() -> None:
        try:
            logger.send_log(
                type=event_type,
                category=category,
                subcategory=subcategory,
                level=_normalize_level(level),
                data=payload_data,
                timestamp=timestamp,
            )
        except Exception as e:  # noqa: BLE001 - no derribar el server
            print(f"[LOGGER ERROR] Fallo al enviar log: {e}", flush=True)

    _sender_pool.submit(_send)


def log_tool_execution(
    agent_id: str,
    tool: str,
    *,
    message_id: Optional[str] = None,
    command_status: Optional[str] = None,
    success: bool = True,
    target: Optional[str] = None,
    result_summary: Optional[str] = None,
    result: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None,
    params: Optional[Dict[str, Any]] = None,
    duration_ms: Optional[float] = None,
    tenant_id: Optional[str] = None,
    issued_by: Optional[str] = None,
) -> None:
    """Audita la ejecución de una herramienta con la taxonomía RobinLogs.

    type=audit, category=tool_category(tool) (network_check | observability |
    windows | linux | remediation | agent_admin | security), subcategory=nombre interno
    (alias SRS resuelto: `get_system_log` → `system_log`).
    """
    requested = (tool or "").strip() or "tool_executed"
    tool = resolve_command(requested)
    category = tool_category(tool)
    level = "error" if not success else "info"

    data: Dict[str, Any] = {
        "message_id": message_id,
        "tool": tool,
        "tool_family": category,
    }
    if requested != tool:
        data["command"] = requested
    if target is not None:
        data["target"] = target
    data["command_status"] = _normalize_command_status(command_status, success)
    data["success"] = bool(success)
    if result_summary is not None:
        data["result_summary"] = result_summary
    if result is not None:
        data["result"] = result
    if duration_ms is not None:
        data["duration_ms"] = duration_ms
    if error is not None:
        data["error"] = error
        level = "error"
    if params is not None:
        try:
            preview = json.dumps(
                _sanitize(params), ensure_ascii=False, default=str
            )
            data["params"] = (
                preview if len(preview) <= 600 else preview[:600] + "...[truncated]"
            )
        except Exception:
            data["params"] = str(params)[:600]
    if issued_by:
        data["issued_by"] = issued_by
        data["user_id"] = issued_by

    log_agent_event(
        agent_id=agent_id,
        event_type="audit",
        category=category,
        subcategory=tool,
        level=level,
        data=data,
        tenant_id=tenant_id,
    )


def log_event_push(
    agent_id: str,
    payload: Dict[str, Any],
    *,
    tenant_id: Optional[str] = None,
) -> None:
    """Audita un `event_push` del plano de control con taxonomía RobinLogs.

    El WS trae `event.event_type` (p.ej. `security.tamper_detected`) y
    `event.severity` (`critical`/`high`). Eso NO es `type`/`level` de RobinLogs
    (robin_logger.md §3.1: type=audit|metrics|activity, level=debug|info|warn|error|fatal).
    """
    event = payload.get("event") if isinstance(payload.get("event"), dict) else {}
    event_type = str(event.get("event_type") or "event_push")
    _, _, subtype = event_type.partition(".")

    if event_type.startswith("security."):
        log_type, category = "audit", event.get("category") or "security"
        subcategory = subtype or "detection"
    elif event_type.startswith("windows."):
        high = str(event.get("severity") or "").lower() in ("high", "critical", "error")
        if event_type in ("windows.sysmon", "windows.autorun_change") or high:
            log_type, category = "audit", event.get("category") or "security"
        else:
            log_type, category = "activity", event.get("category") or "windows"
        subcategory = subtype or "eventlog"
    elif event_type.startswith("linux."):
        high = str(event.get("severity") or "").lower() in ("high", "critical", "error")
        if event_type == "linux.unit_change" or high:
            log_type, category = "audit", event.get("category") or "security"
        else:
            log_type, category = "activity", event.get("category") or "linux"
        subcategory = subtype or "audit"
    elif event_type.startswith("alert.") or event_type == "health.probe":
        log_type, category = "activity", event.get("category") or "observability"
        subcategory = subtype or event_type
    elif event_type.startswith("telemetry."):
        log_type, category = "metrics", event.get("category") or "observability"
        tool = event.get("tool")
        if isinstance(tool, str) and tool.strip():
            subcategory = resolve_command(tool.strip()) or tool.strip()
        else:
            subcategory = subtype or "event_push"
    else:
        log_type = "activity"
        category = event.get("category") or "observability"
        subcategory = subtype or event_type or "event_push"

    severity = str(event.get("severity") or "info").strip().lower()
    level = _SEVERITY_TO_LEVEL.get(severity) or _normalize_level(severity)

    data: Dict[str, Any] = {
        "event_type": event_type,
        "tool": event.get("tool"),
        "request_id": event.get("request_id"),
        "scheduled": event.get("scheduled"),
        "tampered": event.get("tampered"),
    }
    for key in (
        "rule_id",
        "metric",
        "op",
        "value",
        "threshold",
        "check_id",
        "status",
        "changed",
        "pid",
        "name",
        "path",
        "sha256",
        "user",
        "username",
        "action",
        "change",
        "domain",
        "query",
        "mitre_technique",
        "technique",
        "summary",
        "score",
        "findings_count",
        "channel",
        "event_id",
        "provider",
        "computer",
        "record_id",
        "command",
        "event_data",
        "ts",
        "audit_type",
        "exe",
        "comm",
        "success",
        "unit",
        "active",
        "sub",
        "iface",
        "socket",
        "check_type",
    ):
        if event.get(key) is not None:
            data[key] = event.get(key)
    if event.get("error"):
        data["error"] = str(event.get("error"))[:400]
    if event.get("changes") is not None:
        data["changes"] = event.get("changes")
    if event.get("result") is not None:
        data["result"] = event.get("result")

    log_agent_event(
        agent_id=agent_id,
        event_type=log_type,
        category=str(category),
        subcategory=str(subcategory),
        level=level,
        data=data,
        tenant_id=tenant_id,
    )


def logger_status() -> Dict[str, Any]:
    """Estado del logger (credenciales presentes, tipo de auth, cache)."""
    _load_env()
    url = _ingest_url(os.getenv("ROBIN_LOGGER_URL")) or os.getenv("ROBIN_LOGGER_URL")
    api_key = os.getenv("ROBIN_LOGGER_API_KEY")
    jwt = os.getenv("ROBIN_LOGGER_JWT") or os.getenv("ROBIN_LOGGER_JWT_TOKEN")
    if not url or (not api_key and not jwt):
        return {
            "enabled": False,
            "reason": "faltan ROBIN_LOGGER_URL y credenciales (API key o JWT)",
        }
    logger = get_logger()
    cache = {}
    if logger is not None:
        try:
            cache = logger.get_cache_stats() or {}
        except Exception:
            cache = {}
    return {
        "enabled": True,
        "base_url": url,
        "query_url": query_url(),
        "auth": "jwt" if jwt else ("api_key" if api_key else "none"),
        "cache_stats": cache,
    }


def retry_cached_logs() -> Dict[str, Any]:
    """Fuerza el reenvío de logs cacheados (si el POST falló previamente)."""
    logger = get_logger()
    if logger is None:
        return {"attempted": False}
    try:
        return logger.retry_cached_logs() or {"attempted": True}
    except Exception as e:
        return {"attempted": False, "error": str(e)}


def clear_cache() -> Dict[str, Any]:
    """Limpia el cache local de logs pendientes."""
    logger = get_logger()
    if logger is None:
        return {"cleared": False}
    try:
        logger.clear_cache()
        return {"cleared": True}
    except Exception as e:
        return {"cleared": False, "error": str(e)}