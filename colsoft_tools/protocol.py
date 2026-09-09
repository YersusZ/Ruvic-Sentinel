"""
Protocolo de control WebSocket — SRS §8.3 (tipos de mensaje).

Tipos del plano de control:

| Tipo              | Dirección          | Propósito                                |
|-------------------|--------------------|------------------------------------------|
| command_request   | Backend → Agente   | Solicita ejecutar una acción             |
| command_ack       | Agente → Backend   | Acuse de recibo del comando (§8.6 `acked`)|
| command_response  | Agente → Backend   | Resultado de la acción (o status running)|
| event_push        | Agente → Backend   | Evento espontáneo de alta prioridad      |
| heartbeat         | Ambos              | Mantiene viva la conexión (liveness)     |
| auth_ack          | Backend → Agente   | Confirma sesión tras el handshake        |
| auth_challenge    | Backend → Agente   | Desafío RSA del handshake                |
| auth_response     | Agente → Backend   | Firma del desafío + public_key           |
| auth_error        | Backend → Agente   | Handshake rechazado                      |

La telemetría de volumen (métricas, resultados programados) NO viaja por este
canal: sale por OTLP/HTTP (`colsoft_tools/data_plane.py`, SRS §7.1 / RF-OBS-08).
`event_push` queda para detecciones de alta prioridad en el plano de control.

`command_ack` y el handshake RSA (`auth_challenge` / `auth_response` /
`auth_error`) son **contrato de este repo** (además de la tabla SRS §8.3).

Todos los mensajes llevan el campo "type". Los de comando llevan además
"message_id" (idempotencia / dedup, §8.6) y timestamps en ISO 8601 (UTC).

Seguridad del canal en `colsoft_tools/security.py` (§8.2/§8.5): firma Ed25519
por comando, política local, rate limiting, timeout y auditoría inmutable.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

# --- Tipos de mensaje (§8.3) ---
TYPE_COMMAND_REQUEST = "command_request"
TYPE_COMMAND_RESPONSE = "command_response"
TYPE_COMMAND_ACK = "command_ack"
TYPE_EVENT_PUSH = "event_push"
TYPE_HEARTBEAT = "heartbeat"
TYPE_AUTH_ACK = "auth_ack"
TYPE_AUTH_CHALLENGE = "auth_challenge"
TYPE_AUTH_RESPONSE = "auth_response"
TYPE_AUTH_ERROR = "auth_error"

# --- Estados de command_response (§8.6) ---
STATUS_RUNNING = "running"
STATUS_SUCCESS = "success"
STATUS_ERROR = "error"
# Alias de `error` si un cliente viejo manda `failed`. La cola lo mapea a CMD_FAILED.
STATUS_FAILED = "failed"
STATUS_EXPIRED = "expired"
STATUS_REJECTED = "rejected"

# --- Ciclo de vida del comando (§8.6) ---
CMD_PENDING = "pending"
CMD_SENT = "sent"
CMD_ACKED = "acked"
CMD_RUNNING = "running"
CMD_COMPLETED = "completed"
CMD_FAILED = "failed"
CMD_EXPIRED = "expired"
CMD_REJECTED = "rejected"

# §8.3: comandos largos emiten `status: running` y luego el resultado final.
LONG_RUNNING_COMMANDS = frozenset(
    {
        "run_script",
        "forensic_snapshot",
        "collect_forensic_snapshot",
        "collect_file",
        "traceroute",
        "windows_event_log",
        "windows_etw",
        "windows_autoruns",
        "windows_wmi",
        "windows_scheduled_tasks",
        "installed_software",
        "cve_inventory",
        "fim_scan",
        "linux_auditd",
        "linux_syslog",
        "linux_packages",
        "linux_systemd_units",
        "linux_ebpf",
        "linux_netlink",
        "windows_sysmon",
        "persistence_scan",
        "detection_scan",
    }
)

# Resultado de tool que el plano de control trata como comando fallido.
# El check corrió: UP/OK/DOWN/EMPTY y health_probes con down>0 son éxito
# (el hallazgo va en `result`). ERROR/UNSUPPORTED = no se pudo ejecutar.
_COMMAND_FAIL_STATUSES = frozenset(
    {"ERROR", "UNSUPPORTED", "error", "unsupported"}
)


def command_result_failed(result: Any) -> bool:
    """True si el payload de la tool debe mapear a command_response `error`."""
    if not isinstance(result, dict):
        return False
    status = str(result.get("status") or "").strip()
    return status in _COMMAND_FAIL_STATUSES

# --- Alias SRS (§8.4 canónico) → nombre interno actual ---
# Permite que el backend emita comandos con los nombres del catálogo del SRS
# mientras el agente sigue resolviendo a sus herramientas implementadas.
COMMAND_ALIASES = {
    "get_system_log": "system_log",
    "get_process_list": "process_list",
    "get_service_status": "service_status",
    "get_network_connections": "network_connections",
    "get_installed_software": "installed_software",
    "get_disk_usage": "disk_usage",
    "get_file_hash": "file_hash",
    "collect_forensic_snapshot": "forensic_snapshot",
    "get_system_metrics": "system_metrics",
    "get_hardware_inventory": "hardware_inventory",
    "run_health_probes": "health_probes",
    "get_health_probes": "health_probes",
    "tcp_check": "tcp_connect",
    "http_check": "http_get",
    "tls_check": "tls",
    "get_fim_scan": "fim_scan",
    "get_persistence_scan": "persistence_scan",
    "get_auth_audit": "auth_audit",
    "get_detection_scan": "detection_scan",
    "get_cis_score": "cis_score",
    "get_cve_inventory": "cve_inventory",
    "get_rootkit_check": "rootkit_check",
    "get_dns_monitor": "dns_monitor",
    "get_windows_event_log": "windows_event_log",
    "get_windows_etw": "windows_etw",
    "get_windows_autoruns": "windows_autoruns",
    "get_windows_wmi": "windows_wmi",
    "query_wmi": "windows_wmi",
    "get_windows_scheduled_tasks": "windows_scheduled_tasks",
    "get_scheduled_tasks": "windows_scheduled_tasks",
    "get_windows_sysmon": "windows_sysmon",
    "get_sysmon": "windows_sysmon",
    "get_windows_defender": "windows_defender",
    "get_defender_status": "windows_defender",
    "get_linux_ebpf": "linux_ebpf",
    "get_linux_auditd": "linux_auditd",
    "get_linux_syslog": "linux_syslog",
    "get_linux_proc_metrics": "linux_proc_metrics",
    "get_linux_netlink": "linux_netlink",
    "get_linux_systemd_units": "linux_systemd_units",
    "get_systemd_units": "linux_systemd_units",
    "get_linux_lsm": "linux_lsm",
    "get_selinux_status": "linux_lsm",
    "get_apparmor_status": "linux_lsm",
    "get_linux_packages": "linux_packages",
}


def resolve_command(command: str) -> str:
    """Resuelve un nombre de comando (SRS o legacy) al nombre interno del agente."""
    return COMMAND_ALIASES.get(command, command)


def now_iso() -> str:
    """Timestamp actual en ISO 8601 (UTC)."""
    return datetime.now(timezone.utc).isoformat()


def parse_iso(value: Optional[str]) -> Optional[datetime]:
    """Parsea ISO 8601 a datetime (acepta 'Z' como sufijo de UTC)."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


DEFAULT_COMMAND_TTL_SECONDS = 30.0


def default_expires_at(*, ttl_seconds: float = DEFAULT_COMMAND_TTL_SECONDS) -> str:
    """TTL de command_request (§8.3 / §8.6)."""
    from datetime import timedelta

    return (
        datetime.now(timezone.utc) + timedelta(seconds=max(float(ttl_seconds), 1.0))
    ).isoformat()


def is_expired(expires_at: Optional[str]) -> bool:
    """True si `expires_at` falta, es inválido o ya pasó (§8.6)."""
    exp = parse_iso(expires_at)
    if exp is None:
        return True
    return exp < datetime.now(timezone.utc)


def new_message_id() -> str:
    return str(uuid.uuid4())


def make_command_request(
    command: str,
    params: Optional[Dict[str, Any]] = None,
    *,
    message_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    issued_by: Optional[str] = None,
    issued_at: Optional[str] = None,
    expires_at: Optional[str] = None,
    signature: Optional[str] = None,
) -> Dict[str, Any]:
    """Backend → Agente: solicita ejecutar una acción (§8.3)."""
    msg: Dict[str, Any] = {
        "type": TYPE_COMMAND_REQUEST,
        "message_id": message_id or new_message_id(),
        "command": command,
        "params": params or {},
        "issued_at": issued_at or now_iso(),
        "expires_at": expires_at or default_expires_at(),
    }
    if agent_id:
        msg["agent_id"] = agent_id
    if tenant_id:
        msg["tenant_id"] = tenant_id
    if issued_by:
        msg["issued_by"] = issued_by
    if signature:
        msg["signature"] = signature
    return msg


def make_command_ack(
    message_id: str,
    *,
    agent_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Agente → Backend: acuse de recibo de un command_request (§8.6 `acked`).

    Se envía una vez el agente acepta el comando (firma/política OK) y antes de
    ejecutarlo; el backend transiciona `sent → acked`.
    """
    msg: Dict[str, Any] = {
        "type": TYPE_COMMAND_ACK,
        "message_id": message_id,
    }
    if agent_id:
        msg["agent_id"] = agent_id
    if tenant_id:
        msg["tenant_id"] = tenant_id
    return msg


def make_command_response(
    message_id: str,
    status: str,
    *,
    agent_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    result: Any = None,
    error: Optional[str] = None,
    started_at: Optional[str] = None,
    completed_at: Optional[str] = None,
    duration_ms: Optional[int] = None,
) -> Dict[str, Any]:
    """Agente → Backend: resultado de la acción (§8.3)."""
    msg: Dict[str, Any] = {
        "type": TYPE_COMMAND_RESPONSE,
        "message_id": message_id,
        "status": status,
    }
    if agent_id:
        msg["agent_id"] = agent_id
    if tenant_id:
        msg["tenant_id"] = tenant_id
    if result is not None:
        msg["result"] = result
    if error:
        msg["error"] = error
    if started_at:
        msg["started_at"] = started_at
    if completed_at:
        msg["completed_at"] = completed_at
    if duration_ms is not None:
        msg["duration_ms"] = int(duration_ms)
    return msg


def make_event_push(
    agent_id: Optional[str],
    event: Dict[str, Any],
    *,
    tenant_id: Optional[str] = None,
    ts: Optional[str] = None,
) -> Dict[str, Any]:
    """Agente → Backend: evento espontáneo de alta prioridad (§8.3 / §14)."""
    from colsoft_tools.event_model import normalize_event

    inner = normalize_event(
        event or {},
        agent_id=agent_id,
        tenant_id=tenant_id if tenant_id is not None else "",
        timestamp=ts,
    )
    msg: Dict[str, Any] = {
        "type": TYPE_EVENT_PUSH,
        "agent_id": agent_id,
        "event": inner,
        "ts": inner.get("timestamp") or ts or now_iso(),
        "tenant_id": inner.get("tenant_id") or "",
    }
    return msg


def make_heartbeat(
    agent_id: Optional[str] = None,
    *,
    tenant_id: Optional[str] = None,
    ts: Optional[str] = None,
) -> Dict[str, Any]:
    """Ambos sentidos: señal de liveness (§8.3)."""
    msg: Dict[str, Any] = {"type": TYPE_HEARTBEAT, "ts": ts or now_iso()}
    if agent_id:
        msg["agent_id"] = agent_id
    msg["tenant_id"] = tenant_id or ""
    return msg


def make_auth_ack(
    agent_id: str,
    *,
    tenant_id: Optional[str] = None,
    message: Optional[str] = None,
) -> Dict[str, Any]:
    """Backend → Agente: confirma la sesión tras el handshake (§8.3)."""
    msg: Dict[str, Any] = {"type": TYPE_AUTH_ACK, "agent_id": agent_id}
    if tenant_id:
        msg["tenant_id"] = tenant_id
    if message:
        msg["message"] = message
    return msg