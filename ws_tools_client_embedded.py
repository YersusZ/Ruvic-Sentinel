"""
WS Tools Executor Client (embedded URL/config).

Este cliente:
  - Se conecta a la `websocket_url` usando la firma RSA definida en tu `config_client.json`.
  - Ejecuta SOLO herramientas permitidas (lista blanca).
  - Permite la ejecución periódica programada de herramientas vía `scheduler`.
  - Si se desconecta, sigue intentando reconectar (con backoff).
"""

import argparse
import asyncio
import base64
import collections
import json
import os
import platform
import random
import signal
import socket
import sys
import tempfile
from contextlib import suppress
from typing import Any, Dict, Optional

import aiohttp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from colsoft_tools.agent_admin import (
    RESTART_MARKER,
    health_check,
    restart_agent,
    schedule_agent_restart,
    trigger_update,
    update_config,
)
from colsoft_tools.config_manager import default_config_path, load_config
from colsoft_tools.enrollment import (
    default_identity_location,
    identity_exists,
    load_identity,
    merge_runtime_config,
    resolve_identity_dir,
    resolve_pem_paths,
)
from colsoft_tools.network_checks import (
    check_http_service,
    check_tcp_port,
    check_tls_certificate,
    dns_lookup,
    ping_host,
    resolve_dns,
    traceroute,
)
from colsoft_tools.observability import (
    collect_file,
    collect_forensic_snapshot,
    get_disk_usage,
    get_file_hash,
    get_hardware_inventory,
    get_installed_software,
    get_network_connections,
    get_process_list,
    get_service_status,
    get_system_log,
    get_system_metrics,
    run_health_probes,
)
from colsoft_tools.endpoint_security import (
    auth_audit,
    cis_score,
    cve_inventory,
    detection_scan,
    dns_monitor,
    fim_scan,
    persistence_scan,
    rootkit_check,
)
from colsoft_tools.obs_monitors import is_control_plane_event, spawn_obs_tasks
from colsoft_tools.sec_monitors import spawn_sec_tasks
from colsoft_tools.win_monitors import spawn_win_tasks
from colsoft_tools.linux_monitors import spawn_linux_tasks
from colsoft_tools.log_range import time_kwargs
from colsoft_tools.windows_collectors import (
    EVENT_LOG_MAX_DEFAULT,
    windows_autoruns,
    windows_defender,
    windows_etw,
    windows_event_log,
    windows_event_log_bundle,
    windows_scheduled_tasks,
    windows_sysmon,
    windows_wmi,
)
from colsoft_tools.linux_collectors import (
    linux_auditd,
    linux_ebpf,
    linux_lsm,
    linux_netlink,
    linux_packages,
    linux_proc_metrics,
    linux_syslog,
    linux_syslog_bundle,
    linux_systemd_units,
)
from colsoft_tools.protocol import (
    LONG_RUNNING_COMMANDS,
    STATUS_ERROR,
    STATUS_EXPIRED,
    STATUS_REJECTED,
    STATUS_RUNNING,
    STATUS_SUCCESS,
    TYPE_AUTH_ACK,
    TYPE_AUTH_ERROR,
    TYPE_COMMAND_REQUEST,
    TYPE_HEARTBEAT,
    command_result_failed,
    is_expired,
    make_command_ack,
    make_command_response,
    make_event_push,
    make_heartbeat,
    now_iso,
    parse_iso,
    resolve_command,
)
from colsoft_tools.remediation import (
    block_ip,
    control_service,
    execute_script,
    isolate_host,
    kill_process,
    manager_host_from_config,
    resume_isolation_timer,
    restore_isolation,
    unblock_ip,
)
from colsoft_tools.scheduler import AgentScheduler
from colsoft_tools.security import (
    AuditLog,
    CommandPolicy,
    RateLimiter,
    _read_pem,
    command_canonical,
    command_timeout,
    resolve_script_from_catalog,
    verify_command_signature,
)
from colsoft_tools.tamper import TamperMonitor
from colsoft_tools.telemetry_buffer import TelemetryBuffer, buffer_from_config
from colsoft_tools.tls_util import make_client_ssl_context
from colsoft_tools.data_plane import DataPlaneExporter, compact_command_result, data_plane_enabled
from colsoft_tools.tool_catalog import (
    ADMIN_TOOLS,
    ALLOWED_TOOLS,
    NETWORK_TOOLS,
    OBSERVABILITY_TOOLS,
    REMEDIATION_TOOLS,
    SECURITY_TOOLS,
    WINDOWS_TOOLS,
    LINUX_TOOLS,
    tool_category as _tool_family_label,
    tool_target_summary as _tool_target_summary,
)

# Fallback WS_URL por si el config_client.json no lo tiene
WS_URL = "wss://localhost:8000/ws/colsoft-tools"

LOG_PREFIX = "[robin-client-monitor]"


def _log(msg: str, *, err: bool = False) -> None:
    line = f"{LOG_PREFIX} {msg}"
    if err:
        print(line, file=sys.stderr, flush=True)
    else:
        print(line, flush=True)


try:
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


class AgentInstanceLock:
    """Evita dos agentes con el mismo agent_id en paralelo (p. ej. nohup + terminal)."""

    def __init__(self, path: str) -> None:
        self.path = os.path.abspath(path)
        self._fp = None

    def acquire(self) -> None:
        if fcntl is None:
            return
        root = os.path.dirname(self.path) or "."
        os.makedirs(root, exist_ok=True)
        self._fp = open(self.path, "a+", encoding="utf-8")
        try:
            fcntl.flock(self._fp.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self._fp.seek(0)
            other = (self._fp.read() or "").strip()
            self._fp.close()
            self._fp = None
            if other.isdigit() and _pid_alive(int(other)):
                _log(
                    f"Ya hay un agente en ejecución (pid {other}). "
                    f"Deténlo con: kill {other}",
                    err=True,
                )
                raise SystemExit(1)
            raise SystemExit(
                "No se pudo tomar el lock del agente; "
                f"revisa {self.path} o elimínalo si el proceso ya no existe."
            )
        self._fp.seek(0)
        self._fp.truncate()
        self._fp.write(str(os.getpid()))
        self._fp.flush()

    def release(self) -> None:
        if self._fp is None:
            return
        try:
            if fcntl is not None:
                fcntl.flock(self._fp.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        with suppress(OSError):
            self._fp.close()
        self._fp = None
        with suppress(OSError):
            if os.path.isfile(self.path):
                os.remove(self.path)


class AgentShutdown:
    """Cooperativo: Ctrl+C / SIGTERM detiene WS, scheduler y reconexiones."""

    def __init__(self) -> None:
        self._event = asyncio.Event()
        self._signals = 0

    def request(self, signum: Optional[int] = None) -> None:
        self._signals += 1
        if self._signals >= 2:
            _log("Segunda señal de salida; terminando de inmediato.", err=True)
            os._exit(130)
        label = "Ctrl+C" if signum in (signal.SIGINT, None) else f"señal {signum}"
        _log(f"Apagado solicitado ({label}); cerrando sesión…")
        self._event.set()

    @property
    def requested(self) -> bool:
        return self._event.is_set()

    async def wait(self) -> None:
        await self._event.wait()

    async def wait_or_timeout(self, timeout: float) -> bool:
        """True si se pidió apagado antes de que expire ``timeout``."""
        if self.requested:
            return True
        try:
            await asyncio.wait_for(self._event.wait(), timeout=max(float(timeout), 0.0))
            return True
        except asyncio.TimeoutError:
            return False


def _install_shutdown_handlers(shutdown: AgentShutdown) -> None:
    loop = asyncio.get_running_loop()

    def _handler(signum: int) -> None:
        shutdown.request(signum)

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handler, sig)
        except (NotImplementedError, RuntimeError):
            signal.signal(sig, lambda s, _f: shutdown.request(s))


# Dedup de comandos por message_id (§8.6 — idempotencia ante reintentos del backend)
_CMD_DEDUP_MAX = 256
_cmd_dedup_ids = collections.deque(maxlen=_CMD_DEDUP_MAX)
_cmd_dedup_set: set = set()


def _is_duplicate_message(message_id: str) -> bool:
    if message_id in _cmd_dedup_set:
        return True
    if len(_cmd_dedup_set) >= _CMD_DEDUP_MAX:
        _cmd_dedup_set.discard(_cmd_dedup_ids.popleft())
    _cmd_dedup_ids.append(message_id)
    _cmd_dedup_set.add(message_id)
    return False


def _result_summary(tool: str, result: Any) -> str:
    if not isinstance(result, dict):
        return str(result)[:160]
    err = result.get("error")
    if err:
        return f"error={_truncate(str(err), 120)}"
    t = result.get("tool") or tool
    st = result.get("status")
    if t == "ping":
        return f"success={result.get('success')} status={st}"
    if t in ("http", "http_check", "http_get"):
        return f"http_status={result.get('status_code')} estado={st}"
    if t in ("tcp", "tcp_check", "tcp_connect"):
        return f"estado={st} tiempo={result.get('response_time')}"
    if t in ("dns", "dns_resolve"):
        ips = result.get("ips") or []
        return f"estado={st} ips={len(ips)}"
    if t == "dns_lookup":
        ans = result.get("answers") or []
        return f"estado={st} record_type={result.get('record_type')} respuestas={len(ans)}"
    if t == "traceroute":
        hops = result.get("hops") or []
        return f"estado={st} saltos={len(hops)} destino={result.get('target')}"
    if t == "collect_file":
        return f"estado={st} bytes={result.get('content_bytes')} truncado={result.get('truncated')} sha256={result.get('sha256')}"
    if t in ("tls", "tls_check"):
        return f"estado={st} handshake_s={result.get('handshake_time')}"
    if t == "system_metrics":
        cpu = (result.get("cpu") or {}).get("percent")
        mem = (result.get("memory") or {}).get("percent")
        return f"estado={st} cpu={cpu}% mem={mem}%"
    if t in ("process_list", "installed_software"):
        extra = f" hashed={result.get('hashed')}" if t == "installed_software" and result.get("hashed") is not None else ""
        return f"estado={st} count={result.get('count')}{extra}"
    if t == "hardware_inventory":
        cpu = result.get("cpu") or {}
        return f"estado={st} host={result.get('hostname')} cores={cpu.get('logical_cores')}"
    if t == "health_probes":
        return f"estado={st} checks={result.get('count')} down={result.get('down')}"
    if t == "service_status":
        name = result.get("service_name")
        if name:
            return (
                f"estado={st} service={name} "
                f"active={result.get('active_state')} sub={result.get('sub_state')}"
            )
        return f"estado={st} count={result.get('count')}"
    if t in ("start_service", "stop_service", "restart_service"):
        return (
            f"estado={st} action={result.get('action')} "
            f"service={result.get('service_name')} active={result.get('active_state')}"
        )
    if t in ("block_ip", "unblock_ip"):
        return (
            f"estado={st} action={result.get('action')} "
            f"ip={result.get('ip')} dir={result.get('direction')}"
        )
    if t == "network_connections":
        return f"estado={st} conexiones={result.get('count')}"
    if t == "disk_usage":
        return f"estado={st} discos={len(result.get('disks') or [])}"
    if t == "file_hash":
        return f"estado={st} hash={result.get('hash')}"
    if t == "system_log":
        return f"estado={st} lineas={result.get('count')}"
    if t == "forensic_snapshot":
        return f"estado={st} completado_en={result.get('completed_at')}"
    if t == "fim_scan":
        return f"estado={st} archivos={result.get('count')}"
    if t == "persistence_scan":
        return f"estado={st} items={result.get('count')}"
    if t == "auth_audit":
        return f"estado={st} eventos={result.get('count')}"
    if t == "detection_scan":
        return f"estado={st} detecciones={result.get('count')}"
    if t == "cis_score":
        return f"estado={st} score={result.get('score')} passed={result.get('passed')}/{result.get('total')}"
    if t == "cve_inventory":
        return f"estado={st} paquetes={result.get('count')}"
    if t == "rootkit_check":
        return f"estado={st} hallazgos={result.get('count')}"
    if t == "dns_monitor":
        return f"estado={st} consultas={result.get('count')}"
    if t in ("windows_event_log", "linux_auditd", "linux_syslog"):
        return f"estado={st} count={result.get('count')}"
    if t == "windows_etw":
        return f"estado={st} providers={result.get('count') or result.get('provider_count')}"
    if t == "windows_autoruns":
        return f"estado={st} count={result.get('count')}"
    if t == "windows_wmi":
        return f"estado={st} class={result.get('class_name') or result.get('class')} rows={result.get('count')}"
    if t == "windows_scheduled_tasks":
        return f"estado={st} tasks={result.get('count')}"
    if t == "windows_sysmon":
        return f"estado={st} count={result.get('count')}"
    if t == "windows_defender":
        return f"estado={st} enabled={result.get('antivirus_enabled')}"
    if t == "linux_proc_metrics":
        cpu = (result.get("cpu") or {}).get("percent")
        return f"estado={st} cpu={cpu}%"
    if t == "linux_packages":
        return f"estado={st} count={result.get('count')} hashed={result.get('hashed')}"
    if t == "linux_systemd_units":
        return f"estado={st} units={result.get('count')}"
    if t == "linux_lsm":
        return f"estado={st} active={result.get('active')}"
    if t == "linux_ebpf":
        return f"estado={st} programs={result.get('count') or result.get('program_count')}"
    if t == "linux_netlink":
        return f"estado={st} ifaces={result.get('count')}"
    if t == "health_check":
        return f"estado={st} v{result.get('version')} pid={result.get('pid')} uptime_s={result.get('uptime_s')}"
    if t == "update_config":
        return f"estado={st} aplicadas={result.get('applied')}"
    if t == "trigger_update":
        return f"estado={st} rc={result.get('returncode')}"
    if t == "restart_agent":
        return f"estado={st} reinicio_en={result.get('delay')}s"
    return f"estado={st}"


def _default_config_path() -> str:
    if getattr(sys, "frozen", False) and getattr(sys, "executable", None):
        return os.path.join(
            os.path.dirname(os.path.abspath(sys.executable)),
            "config_client.json",
        )
    return "config_client.json"


def load_runtime_config(
    config_file: str,
    *,
    identity_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """Carga la configuración del agente con validación previa (RF-CORE-03).

    Siempre lee `config_client.json` (scheduler, linux.*, alerts, data plane).
    Si hay identidad en ``enrollment/<equipo>/`` (o ``active.json``), sus campos
    pisan los del JSON. Devuelve siempre un dict (vacío si no hay nada).
    """
    cfg, errors, path = load_config(config_file)
    if errors:
        for e in errors:
            _log(f"Config inválido ({path}): {e}", err=True)

    config_dir = os.path.dirname(os.path.abspath(path))
    cfg = resolve_pem_paths(cfg, config_dir)

    ident_dir = resolve_identity_dir(cfg, explicit=identity_dir)
    if ident_dir and identity_exists(out_dir=ident_dir):
        try:
            bundle = load_identity(out_dir=ident_dir)
            if bundle:
                cfg = merge_runtime_config(cfg, bundle)
                _log(
                    f"Identidad de enrollment ({ident_dir!r}) + {path!r} "
                    f"(RF-CORE-01/02/03): agent_id={cfg.get('agent_id')!r}"
                )
                return _fallback_identity_key_files(cfg, config_dir, ident_dir)
        except Exception as e:
            _log(f"No se pudo cargar identidad de enrollment: {e}", err=True)

    if cfg.get("agent_id"):
        _log(f"Config cargada y validada desde {path!r} (RF-CORE-03)")
    cfg = _fallback_identity_key_files(cfg, config_dir, ident_dir)
    return cfg


def _fallback_identity_key_files(
    cfg: Dict[str, Any],
    config_dir: str,
    ident_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """Si el JSON perdió el PEM del desafío, usa enrollment/identity.key (§8.1)."""
    from colsoft_tools.enrollment import resolve_pem_paths

    if not isinstance(cfg, dict):
        return cfg
    roots = [os.path.join(config_dir, "enrollment")]
    if ident_dir:
        roots.append(ident_dir)
        roots.append(os.path.join(ident_dir, "certs"))
    for key, names in (
        ("private_key", ("identity.key", os.path.join("certs", "identity.key"))),
        ("public_key", ("identity.pub", os.path.join("certs", "identity.pub"))),
    ):
        val = cfg.get(key)
        if val and str(val).strip() and "-----BEGIN" in str(val):
            continue
        if val and os.path.isfile(str(val)):
            continue
        found = None
        for root in roots:
            for name in names:
                rel = os.path.join(root, name)
                if os.path.isfile(rel):
                    found = rel
                    break
            if found:
                break
        if found:
            cfg[key] = found
    return resolve_pem_paths(cfg, config_dir)


def _truncate(s: Optional[str], max_chars: int) -> str:
    if s is None:
        return ""
    s = str(s)
    if max_chars > 0 and len(s) > max_chars:
        return s[:max_chars] + f"\n...[truncated to {max_chars} chars]"
    return s


async def heartbeat_loop(
    ws: aiohttp.ClientWebSocketResponse,
    interval: float,
    agent_id_provider,
    *,
    tenant_id: Optional[str] = None,
    send_lock: Optional[asyncio.Lock] = None,
) -> None:
    """Envía heartbeats periódicos (§8.3 heartbeat / §8.1 liveness)."""
    while True:
        await asyncio.sleep(max(float(interval), 5.0))
        try:
            payload = json.dumps(
                make_heartbeat(agent_id_provider(), tenant_id=tenant_id),
                ensure_ascii=False,
                default=str,
            )
            if send_lock is None:
                await ws.send_str(payload)
            else:
                async with send_lock:
                    await ws.send_str(payload)
        except Exception as e:
            _log(f"Error enviando heartbeat: {e}", err=True)
            break


def _param_timeout_s(params: Dict[str, Any], default: int = 15) -> int:
    """SRS §8.4: `timeout_ms`; también se acepta `timeout` en segundos."""
    params = params or {}
    if params.get("timeout_ms") is not None:
        try:
            return max(1, int(round(float(params["timeout_ms"]) / 1000.0)))
        except (TypeError, ValueError):
            return default
    try:
        return int(params.get("timeout") or default)
    except (TypeError, ValueError):
        return default


async def execute_tool(
    tool: str,
    params: Dict[str, Any],
    *,
    max_chars: int,
    config: Optional[Dict[str, Any]] = None,
    config_file: Optional[str] = None,
) -> Dict[str, Any]:
    tool = resolve_command((tool or "").strip())
    params = params or {}

    if tool not in ALLOWED_TOOLS:
        return {
            "tool": tool,
            "status": "ERROR",
            "error": f"Tool no permitido: {tool}",
        }

    if tool == "ping":
        host = (params.get("host") or params.get("target") or "").strip()
        count = int(params.get("count") or 3)
        timeout = _param_timeout_s(params, default=15)
        if not host:
            return {"tool": tool, "status": "ERROR", "error": "Missing host"}
        res = ping_host(host, count=count, timeout=timeout)
        if isinstance(res, dict):
            res["output"] = _truncate(res.get("output"), max_chars)
            if res.get("error"):
                res["error"] = _truncate(res.get("error"), max_chars)
            if "status" not in res or not res["status"]:
                res["status"] = "UP" if res.get("success") is True else "DOWN"
            res["tool"] = tool
        return res

    if tool == "http_get":
        url = (params.get("url") or params.get("target") or "").strip()
        timeout = _param_timeout_s(params, default=10)
        if not url or not (
            url.startswith("http://") or url.startswith("https://")
        ):
            return {
                "tool": tool,
                "status": "ERROR",
                "error": "Invalid url (must start with http:// or https://)",
            }
        res = check_http_service(url, timeout=timeout)
        if isinstance(res, dict):
            res["tool"] = tool
        return res

    if tool == "tcp_connect":
        host = (params.get("host") or params.get("target") or "").strip()
        port = int(params.get("port") or 0)
        timeout = _param_timeout_s(params, default=3)
        if not host or port <= 0 or port > 65535:
            return {
                "tool": tool,
                "status": "ERROR",
                "error": "Invalid host/port",
            }
        res = check_tcp_port(host, port=port, timeout=timeout)
        if isinstance(res, dict):
            res["tool"] = tool
        return res

    if tool == "dns_resolve":
        host = (params.get("host") or params.get("target") or "").strip()
        if not host:
            return {"tool": tool, "status": "ERROR", "error": "Missing host"}
        res = resolve_dns(host)
        if isinstance(res, dict):
            res["tool"] = tool
        return res

    if tool == "dns_lookup":
        hostname = (params.get("hostname") or params.get("host") or "").strip()
        record_type = (params.get("record_type") or params.get("type") or "A").strip()
        if not hostname:
            return {"tool": tool, "status": "ERROR", "error": "Missing hostname"}
        res = dns_lookup(hostname, record_type=record_type)
        if isinstance(res, dict):
            res["tool"] = tool
        return res

    if tool == "traceroute":
        target = (params.get("target") or params.get("host") or "").strip()
        max_hops = int(params.get("max_hops") or 30)
        if params.get("timeout_ms") is not None or params.get("timeout"):
            timeout = float(_param_timeout_s(params, default=120))
        else:
            timeout = 0
        if not target:
            return {"tool": tool, "status": "ERROR", "error": "Missing target"}
        res = traceroute(target, max_hops=max_hops, timeout=timeout)
        if isinstance(res, dict):
            res["tool"] = tool
        return res

    if tool == "tls":
        target = (params.get("host") or params.get("target") or "").strip()
        timeout = _param_timeout_s(params, default=8)
        if not target:
            return {
                "tool": tool,
                "status": "ERROR",
                "error": "Missing host/target",
            }
        res = check_tls_certificate(target, timeout=timeout)
        if isinstance(res, dict):
            res["tool"] = tool
        return res

    # --- Observabilidad ---

    if tool == "system_metrics":
        cpu_interval = float(params.get("cpu_interval") or 0.5)
        return get_system_metrics(cpu_interval=cpu_interval)

    if tool == "process_list":
        name_filter = params.get("filter") or params.get("name")
        limit = int(params.get("limit") or 300)
        return get_process_list(name_filter=name_filter, limit=limit)

    if tool == "service_status":
        service_name = (
            params.get("service_name") or params.get("name") or ""
        ).strip() or None
        return get_service_status(service_name=service_name)

    if tool == "network_connections":
        kind = (params.get("kind") or "inet").strip()
        return get_network_connections(kind=kind)

    if tool == "installed_software":
        include_hash = bool(params.get("include_hash"))
        max_hash = int(params.get("max_hash") or 40)
        return get_installed_software(include_hash=include_hash, max_hash=max_hash)

    if tool == "hardware_inventory":
        return get_hardware_inventory()

    if tool == "health_probes":
        checks = params.get("checks")
        if not isinstance(checks, list):
            checks = ((config or {}).get("health_probes") or {}).get("checks") or []
        return run_health_probes(checks)

    if tool == "disk_usage":
        return get_disk_usage()

    if tool == "file_hash":
        path = (params.get("path") or "").strip()
        algo = (
            params.get("algo") or params.get("algorithm") or "sha256"
        ).strip()
        if not path:
            return {"tool": tool, "status": "ERROR", "error": "Missing path"}
        return get_file_hash(path, algo=algo)

    if tool == "system_log":
        source = params.get("source") or params.get("filter") or "system"
        level = params.get("level") or "warning"
        max_lines = int(params.get("max_lines") or 500)
        return get_system_log(
            source=source, level=level, max_lines=max_lines, **time_kwargs(params)
        )

    if tool == "forensic_snapshot":
        return collect_forensic_snapshot()

    if tool == "collect_file":
        path = (params.get("path") or "").strip()
        max_size_mb = params.get("max_size_mb") or 10.0
        if not path:
            return {"tool": tool, "status": "ERROR", "error": "Missing path"}
        return collect_file(path, max_size_mb=max_size_mb)

    # --- Seguridad base (§11) ---

    if tool == "fim_scan":
        paths = params.get("paths")
        if not isinstance(paths, list):
            sec = (config or {}).get("security") or {}
            fim_cfg = sec.get("fim") if isinstance(sec, dict) else {}
            paths = (fim_cfg or {}).get("paths") if isinstance(fim_cfg, dict) else None
        return fim_scan(paths)

    if tool == "persistence_scan":
        return persistence_scan()

    if tool == "auth_audit":
        max_entries = int(params.get("max_entries") or 80)
        return auth_audit(max_entries=max_entries)

    if tool == "detection_scan":
        return detection_scan()

    if tool == "cis_score":
        return cis_score()

    if tool == "cve_inventory":
        include_hash = bool(params.get("include_hash"))
        max_hash = int(params.get("max_hash") or 20)
        return cve_inventory(include_hash=include_hash, max_hash=max_hash)

    if tool == "rootkit_check":
        return rootkit_check()

    if tool == "dns_monitor":
        return dns_monitor()

    # --- Windows §12 (RF-WIN-01..07) ---

    if tool == "windows_event_log":
        range_kw = time_kwargs(params)
        if params.get("bundle"):
            max_per = int(params.get("max_events") or 20)
            return await asyncio.to_thread(
                windows_event_log_bundle, max_per, **range_kw
            )
        channel = (
            params.get("channel") or params.get("source") or "Security"
        )
        return await asyncio.to_thread(
            windows_event_log,
            str(channel),
            int(params.get("max_events") or EVENT_LOG_MAX_DEFAULT),
            **range_kw,
        )

    if tool == "windows_etw":
        return windows_etw(max_providers=int(params.get("max_providers") or 80))

    if tool == "windows_autoruns":
        return windows_autoruns()

    if tool == "windows_wmi":
        cls = params.get("class_name") or params.get("class") or "Win32_OperatingSystem"
        return windows_wmi(str(cls), max_rows=int(params.get("max_rows") or 40))

    if tool == "windows_scheduled_tasks":
        return windows_scheduled_tasks(max_tasks=int(params.get("max_tasks") or 120))

    if tool == "windows_sysmon":
        return windows_sysmon(max_events=int(params.get("max_events") or 30))

    if tool == "windows_defender":
        return windows_defender()

    # --- Linux §13 (RF-LIN-01..08) ---

    if tool == "linux_ebpf":
        return await asyncio.to_thread(
            linux_ebpf, int(params.get("max_programs") or 40)
        )

    if tool == "linux_auditd":
        return await asyncio.to_thread(
            linux_auditd, int(params.get("max_events") or 40), **time_kwargs(params)
        )

    if tool == "linux_syslog":
        range_kw = time_kwargs(params)
        if params.get("bundle"):
            max_per = int(params.get("max_lines") or params.get("max_events") or 20)
            return await asyncio.to_thread(linux_syslog_bundle, max_per, **range_kw)
        source = params.get("source") or params.get("filter") or "syslog"
        return await asyncio.to_thread(
            linux_syslog,
            str(source),
            int(params.get("max_lines") or 80),
            **range_kw,
        )

    if tool == "linux_proc_metrics":
        return await asyncio.to_thread(
            linux_proc_metrics, float(params.get("cpu_interval") or 0.15)
        )

    if tool == "linux_netlink":
        return await asyncio.to_thread(
            linux_netlink, int(params.get("max_ifaces") or 32)
        )

    if tool == "linux_systemd_units":
        return await asyncio.to_thread(
            linux_systemd_units,
            int(params.get("max_units") or 400),
            int(params.get("max_timers") or 200),
        )

    if tool == "linux_lsm":
        return await asyncio.to_thread(linux_lsm)

    if tool == "linux_packages":
        include_hash = bool(params.get("include_hash"))
        return await asyncio.to_thread(
            linux_packages,
            include_hash,
            int(params.get("max_hash") or 20),
            int(params.get("max_packages") or 400),
        )

    # --- Remediación (§8.4-C) ---

    if tool == "kill_process":
        kill_timeout = params.get("timeout")
        if kill_timeout is None and params.get("timeout_ms") is not None:
            kill_timeout = float(params["timeout_ms"]) / 1000.0
        return kill_process(
            pid=params.get("pid"),
            name=params.get("name"),
            force=bool(params.get("force")),
            timeout=float(kill_timeout if kill_timeout is not None else 5),
        )

    if tool in ("start_service", "stop_service", "restart_service"):
        service_name = (
            params.get("service_name") or params.get("name") or ""
        ).strip()
        if not service_name:
            return {
                "tool": tool,
                "status": "ERROR",
                "error": "Missing service_name",
            }
        action = {
            "start_service": "start",
            "stop_service": "stop",
            "restart_service": "restart",
        }[tool]
        return control_service(action, service_name)

    if tool in ("block_ip", "unblock_ip"):
        ip = (params.get("ip") or "").strip()
        direction = (params.get("direction") or "input").strip().lower()
        if not ip:
            return {"tool": tool, "status": "ERROR", "error": "Missing ip"}
        fn = block_ip if tool == "block_ip" else unblock_ip
        return fn(ip, direction=direction)

    if tool == "isolate_host":
        return isolate_host(
            reason=params.get("reason"),
            duration=params.get("duration") or params.get("duration_seconds"),
            manager_host=params.get("manager_host")
            or manager_host_from_config(config),
        )

    if tool == "restore_isolation":
        return restore_isolation()

    if tool == "run_script":
        script_id = (params.get("script_id") or "").strip()
        script_path = (
            resolve_script_from_catalog(config, script_id) if config else None
        )
        if not script_path:
            return {
                "tool": tool,
                "status": "ERROR",
                "error": (
                    "run_script rechazado: script_id no está en el catálogo firmado local"
                    if script_id
                    else "run_script rechazado: falta script_id (nunca se ejecuta código del payload)"
                ),
            }
        return execute_script(
            script_path,
            args=params.get("args"),
            timeout=float(params.get("timeout") or 120),
            max_chars=max_chars,
        )

    # --- Administración del agente (§8.4-D) ---

    if tool == "update_config":
        return update_config(config, config_file, params)

    if tool == "trigger_update":
        return trigger_update(config, params, max_chars=max_chars)

    if tool == "restart_agent":
        return restart_agent(params)

    if tool == "health_check":
        return health_check(config, config_file=config_file)

    return {"tool": tool, "status": "ERROR", "error": "Unhandled tool"}


async def client_session(
    ws_url: str,
    config_file: str,
    *,
    max_chars: int,
    concurrency: int,
    verbose: bool,
    telemetry_buffer: Optional[TelemetryBuffer] = None,
    identity_ref: Optional[Dict[str, Any]] = None,
    priority_queue: Optional[asyncio.Queue] = None,
) -> None:
    config = {}
    private_key_pem = None
    public_key_pem = None
    if config_file or resolve_identity_dir({}):
        try:
            config = load_runtime_config(config_file)
            private_key_pem = config.get("private_key")
            public_key_pem = config.get("public_key")
            if config.get("websocket_url"):
                ws_url = config.get("websocket_url")
            # §8.6: identidad estable del agente (cola entre reconexiones)
            from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

            _id_params = []
            _cname = (config.get("client_name") or "").strip()
            if _cname:
                _id_params.append(("client_name", _cname))
            _aid = (config.get("agent_id") or "").strip()
            if _aid:
                _id_params.append(("agent_id", _aid))
            _tid = (config.get("tenant_id") or "").strip()
            if _tid:
                _id_params.append(("tenant_id", _tid))
            if _id_params:
                _parts = urlsplit(ws_url)
                ws_url = urlunsplit(
                    (
                        _parts.scheme,
                        _parts.netloc,
                        _parts.path,
                        urlencode(parse_qsl(_parts.query) + _id_params),
                        _parts.fragment,
                    )
                )
            cname = (config.get("client_name") or "").strip()
            extra = f" cliente={cname!r}" if cname else ""
            _log(
                f"Config cargada desde {config_file!r}{extra} → WebSocket {ws_url}"
            )
        except Exception as e:
            _log(f"No se pudo leer config {config_file!r}: {e}", err=True)
    else:
        _log(f"Sin archivo de config; WebSocket {ws_url}")

    tenant_id = (config.get("tenant_id") or "").strip() or None
    state = {"agent_id": None}
    ident = identity_ref if isinstance(identity_ref, dict) else {}

    def _session_telemetry_sink(event):
        """Encola OTLP/event_push desde un comando on-demand (Win/Linux)."""
        if telemetry_buffer is None:
            return None
        msg = make_event_push(
            ident.get("agent_id") or state.get("agent_id"),
            event,
            tenant_id=ident.get("tenant_id") or tenant_id,
            ts=now_iso(),
        )
        telemetry_buffer.put(msg)
        if priority_queue is not None and is_control_plane_event(event or {}):
            try:
                priority_queue.put_nowait(msg)
            except asyncio.QueueFull:
                pass
        return None

    # TLS / mTLS (§8.2 / §15): wss:// con TLS 1.2+ y cert de cliente, o ws://
    # solo con allow_insecure_ws=true (lab). Nunca ssl=False de forma silenciosa.
    use_tls = ws_url.startswith("wss://")
    if use_tls:
        if not (config.get("tls_ca_cert") or "").strip():
            _log(
                "AVISO: wss:// sin tls_ca_cert (sin fijación de CA; se verifica "
                "contra tienda del sistema + certifi).",
                err=True,
            )
        ctx = make_client_ssl_context(config)
        connector = aiohttp.TCPConnector(ssl=ctx)
    else:
        if not bool(config.get("allow_insecure_ws", False)):
            raise RuntimeError(
                "URL ws:// insegura; configure 'allow_insecure_ws': true (solo lab) "
                "o use wss:// con certificados de enrollment."
            )
        connector = aiohttp.TCPConnector(ssl=False)

    policy = CommandPolicy(config)
    rate_limiter = RateLimiter(
        limit=int(config.get("max_command_rate") or 20), window=60.0
    )
    from colsoft_tools.config_manager import DEFAULT_AUDIT_LOG_PATH

    audit = AuditLog(config.get("audit_log_path") or DEFAULT_AUDIT_LOG_PATH)
    signing_public_key = config.get("signing_public_key")
    if config.get("require_command_signature") is False:
        _log(
            "require_command_signature=false ignorado: §8.2 exige firma Ed25519 "
            "en todo command_request.",
            err=True,
        )

    # RF-CORE-04: buffer de telemetría (memoria + disco) compartido con el
    # scheduler; se drena al reconectar. RF-CORE-06: tamper-resistance.
    if telemetry_buffer is None:
        telemetry_buffer = buffer_from_config(config)
    tamper = TamperMonitor(config, log=lambda *a, **k: _log(*a))
    _tamper_status = tamper.verify_and_rebaseline()
    if _tamper_status.get("tampered"):
        tamper_event = make_event_push(
            state.get("agent_id"),
            tamper.to_event(),
            tenant_id=tenant_id,
            ts=now_iso(),
        )
        telemetry_buffer.put(tamper_event)
        _log(
            f"[tamper] Modificación detectada: {_tamper_status.get('changes')}",
            err=True,
        )
    else:
        _log("Tamper-resistance: baseline verificado OK (RF-CORE-06).")

    async with aiohttp.ClientSession(connector=connector) as session:
        sem = asyncio.Semaphore(max(1, int(concurrency or 1)))
        heartbeat_interval = float(config.get("heartbeat_interval") or 30)

        _log(f"Conectando al servidor WebSocket → {ws_url}")
        async with session.ws_connect(ws_url, timeout=20) as ws:
            _log(f"Socket conectado (handshake OK) → {ws_url}")

            if private_key_pem and public_key_pem:
                from colsoft_tools.security import load_private_key

                private_key = load_private_key(private_key_pem)
            else:
                private_key = None

            # aiohttp no serializa writes concurrentes; heartbeat + Event Log
            # en el mismo socket cierra la sesión en Windows.
            ws_lock = asyncio.Lock()

            async def _send_json(obj: Any) -> None:
                payload = json.dumps(obj, ensure_ascii=False, default=str)
                async with ws_lock:
                    await ws.send_str(payload)

            # Tareas en segundo plano: heartbeat y event_push de prioridad
            # recién DESPUÉS de auth_ack. Si salen antes, el server consume
            # ese frame como "auth" y cierra (1008).
            authed = asyncio.Event()

            async def _heartbeat_after_auth() -> None:
                await authed.wait()
                await heartbeat_loop(
                    ws,
                    heartbeat_interval,
                    lambda: state.get("agent_id"),
                    tenant_id=tenant_id,
                    send_lock=ws_lock,
                )

            heartbeat_task = asyncio.create_task(_heartbeat_after_auth())

            async def _forward_priority_events() -> None:
                if priority_queue is None:
                    return
                await authed.wait()
                while True:
                    msg = await priority_queue.get()
                    if not isinstance(msg, dict):
                        continue
                    if state.get("agent_id") and not msg.get("agent_id"):
                        msg["agent_id"] = state["agent_id"]
                    try:
                        await _send_json(msg)
                    except Exception as e:
                        _log(f"Error enviando event_push de observabilidad: {e}", err=True)
                        break

            priority_task = asyncio.create_task(_forward_priority_events())

            try:
                async for msg in ws:
                    if msg.type == aiohttp.WSMsgType.ERROR:
                        _log(
                            f"WebSocket error de transporte: {ws.exception()}",
                            err=True,
                        )
                        break
                    if msg.type != aiohttp.WSMsgType.TEXT:
                        _log(
                            f"Mensaje ignorado (tipo={msg.type!r})", err=True
                        )
                        continue

                    try:
                        payload = json.loads(msg.data)
                    except Exception:
                        _log("Mensaje recibido no es JSON válido", err=True)
                        continue

                    ptype = payload.get("type")

                    if ptype == "auth_challenge":
                        if not private_key:
                            _log(
                                "auth_challenge recibido pero no hay llave privada en config; cerrando.",
                                err=True,
                            )
                            await ws.close()
                            return

                        _log(
                            "Autenticación: recibido auth_challenge; enviando auth_response (firma RSA)."
                        )
                        challenge = payload.get("challenge", "").encode(
                            "utf-8"
                        )
                        signature = private_key.sign(
                            challenge,
                            padding.PKCS1v15(),
                            hashes.SHA256(),
                        )

                        public_key_body = _read_pem(public_key_pem) or public_key_pem
                        auth_response = {
                            "type": "auth_response",
                            "public_key": public_key_body,
                            "signature": base64.b64encode(signature).decode(
                                "utf-8"
                            ),
                        }
                        await _send_json(auth_response)
                        _log("Autenticación: auth_response enviada.")
                        continue

                    if ptype == TYPE_AUTH_ERROR:
                        _log(
                            "Autenticación rechazada por el backend (auth_error): "
                            f"{payload.get('message') or 'sin detalle'}",
                            err=True,
                        )
                        await ws.close()
                        return

                    if ptype == TYPE_AUTH_ACK:
                        # §8.3: el backend confirma la sesión tras el handshake
                        state["agent_id"] = (
                            payload.get("agent_id") or state.get("agent_id")
                        )
                        if identity_ref is not None and state.get("agent_id"):
                            identity_ref["agent_id"] = state["agent_id"]
                        _log(
                            f"Autenticación confirmada por el backend (auth_ack): "
                            f"agent_id={state['agent_id']!r}"
                        )
                        authed.set()
                        # RF-OBS-08: si el plano de datos OTLP está activo, la
                        # telemetría NO viaja por el WS (canal separado).
                        if data_plane_enabled(config):
                            pending = telemetry_buffer.count()
                            if pending:
                                _log(
                                    f"Buffer de telemetría: {pending} evento(s) "
                                    "pendientes se exportan por OTLP (RF-OBS-08)."
                                )
                            continue
                        # RF-CORE-04: sesión establecida → drenar el buffer de
                        # telemetría acumulado (eventos programados/tamper).
                        try:
                            agent_id = state.get("agent_id")

                            async def _send_buffered(ev: Dict[str, Any]) -> None:
                                if tenant_id and not ev.get("tenant_id"):
                                    ev["tenant_id"] = tenant_id
                                if agent_id and not ev.get("agent_id"):
                                    ev["agent_id"] = agent_id
                                await _send_json(ev)

                            flushed = await telemetry_buffer.flush_to_ws(
                                _send_buffered
                            )
                            if flushed:
                                _log(
                                    f"Buffer de telemetría drenado: {flushed} evento(s) reenviados (RF-CORE-04)."
                                )
                        except Exception as e:
                            _log(
                                f"Error drenando buffer de telemetría: {e}",
                                err=True,
                            )
                        continue

                    if ptype == TYPE_HEARTBEAT:
                        # §8.3: heartbeat del backend (liveness). No se responde
                        # para evitar un loop de eco; el agente ya envía los suyos.
                        if verbose:
                            _log(
                                f"Heartbeat recibido del backend "
                                f"(agent_id={payload.get('agent_id')!r})."
                            )
                        continue

                    if ptype == TYPE_COMMAND_REQUEST:
                        message_id = str(payload.get("message_id") or "")
                        raw_command = (payload.get("command") or "").strip()
                        command = resolve_command(raw_command)
                        params = payload.get("params") or {}
                        started_at = now_iso()

                        if not message_id:
                            _log(
                                "command_request malformado (falta message_id); ignorando.",
                                err=True,
                            )
                            continue
                        if not raw_command:
                            _log(
                                "command_request malformado (falta command); rechazando.",
                                err=True,
                            )
                            await _send_json(
                                make_command_response(
                                    message_id,
                                    STATUS_REJECTED,
                                    agent_id=state.get("agent_id"),
                                    tenant_id=tenant_id,
                                    error="command_request sin command",
                                    started_at=started_at,
                                    completed_at=now_iso(),
                                )
                            )
                            continue

                        if _is_duplicate_message(message_id):
                            _log(
                                f"command_request duplicado message_id={message_id}; "
                                "ignorando (idempotencia §8.6)."
                            )
                            continue

                        # §8.2: verificar firma Ed25519 del backend antes de ejecutar
                        canonical = command_canonical(
                            message_id,
                            payload.get("agent_id"),
                            raw_command,
                            params,
                            payload.get("issued_by"),
                            payload.get("issued_at"),
                            payload.get("expires_at"),
                        )
                        sig_ok = verify_command_signature(
                            signing_public_key, canonical, payload.get("signature")
                        )
                        if not sig_ok:
                            reason = (
                                "Sin clave pública de firma configurada (enrollment §8.2)"
                                if not signing_public_key
                                else "Firma Ed25519 inválida"
                            )
                            _log(
                                f"Comando {raw_command!r} RECHAZADO message_id={message_id}: {reason}"
                            )
                            audit.append(
                                {
                                    "kind": "command_rejected",
                                    "message_id": message_id,
                                    "command": raw_command,
                                    "params": params,
                                    "issued_by": payload.get("issued_by"),
                                    "issued_at": payload.get("issued_at"),
                                    "reason": reason,
                                    "agent_id": state.get("agent_id"),
                                }
                            )
                            resp = make_command_response(
                                message_id,
                                STATUS_REJECTED,
                                agent_id=state.get("agent_id"),
                                tenant_id=tenant_id,
                                error=reason,
                                started_at=started_at,
                                completed_at=now_iso(),
                            )
                            await _send_json(resp)
                            continue

                        # §8.2/§8.5: política local (doble candado)
                        allowed, pol_reason = policy.check(command)
                        if not allowed:
                            _log(
                                f"Comando {raw_command!r} RECHAZADO por política message_id={message_id}: {pol_reason}"
                            )
                            audit.append(
                                {
                                    "kind": "command_rejected",
                                    "message_id": message_id,
                                    "command": raw_command,
                                    "params": params,
                                    "issued_by": payload.get("issued_by"),
                                    "issued_at": payload.get("issued_at"),
                                    "reason": pol_reason,
                                    "agent_id": state.get("agent_id"),
                                }
                            )
                            resp = make_command_response(
                                message_id,
                                STATUS_REJECTED,
                                agent_id=state.get("agent_id"),
                                tenant_id=tenant_id,
                                error=pol_reason,
                                started_at=started_at,
                                completed_at=now_iso(),
                            )
                            await _send_json(resp)
                            continue

                        # §8.5: rate limit local por comando
                        if not rate_limiter.allow_per_command(
                            str(state.get("agent_id") or "agent"), command
                        ):
                            reason = f"Rate limit local excedido para {command!r}"
                            _log(f"Comando {raw_command!r} RECHAZADO message_id={message_id}: {reason}")
                            resp = make_command_response(
                                message_id,
                                STATUS_REJECTED,
                                agent_id=state.get("agent_id"),
                                tenant_id=tenant_id,
                                error=reason,
                                started_at=started_at,
                                completed_at=now_iso(),
                            )
                            await _send_json(resp)
                            continue

                        # §8.5: run_script solo por script_id del catálogo, nunca payload
                        if command == "run_script":
                            script_id = (params.get("script_id") or "").strip()
                            script_path = resolve_script_from_catalog(config, script_id)
                            if not script_path:
                                reason = (
                                    "run_script rechazado: script_id no está en el catálogo firmado local"
                                    if script_id
                                    else "run_script rechazado: falta script_id (nunca se ejecuta código del payload)"
                                )
                                _log(f"{reason} (message_id={message_id})")
                                resp = make_command_response(
                                    message_id,
                                    STATUS_REJECTED,
                                    agent_id=state.get("agent_id"),
                                tenant_id=tenant_id,
                                    error=reason,
                                    started_at=started_at,
                                    completed_at=now_iso(),
                                )
                                await _send_json(resp)
                                continue

                        if is_expired(payload.get("expires_at")):
                            _log(
                                f"Comando {raw_command!r} expirado message_id={message_id} "
                                "(expires_at superado)."
                            )
                            resp = make_command_response(
                                message_id,
                                STATUS_EXPIRED,
                                agent_id=state.get("agent_id"),
                                tenant_id=tenant_id,
                                error="Comando expirado (expires_at)",
                                started_at=started_at,
                                completed_at=now_iso(),
                            )
                            await _send_json(resp)
                            continue

                        # §8.6: acuse de recibo (sent → acked en el backend)
                        await _send_json(
                            make_command_ack(
                                message_id,
                                agent_id=state.get("agent_id"),
                                tenant_id=tenant_id,
                            )
                        )

                        target = _tool_target_summary(command, params)
                        _log(
                            f"Comando remoto message_id={message_id} command={raw_command!r} "
                            f"[{_tool_family_label(command)}] {target}"
                        )

                        if command in LONG_RUNNING_COMMANDS:
                            await _send_json(
                                make_command_response(
                                    message_id,
                                    STATUS_RUNNING,
                                    agent_id=state.get("agent_id"),
                                    tenant_id=tenant_id,
                                    started_at=started_at,
                                )
                            )

                        timeout = command_timeout(command, params)
                        result = None
                        async with sem:
                            try:
                                result = await asyncio.wait_for(
                                    execute_tool(
                                        command,
                                        params,
                                        max_chars=max_chars,
                                        config=config,
                                        config_file=config_file,
                                    ),
                                    timeout=timeout,
                                )
                                if command_result_failed(result):
                                    status = STATUS_ERROR
                                    error = (
                                        (result.get("error") if isinstance(result, dict) else None)
                                        or (
                                            f"Resultado {result.get('status')}"
                                            if isinstance(result, dict) and result.get("status")
                                            else None
                                        )
                                        or "Ejecución falló en el agente"
                                    )
                                    result_body = result
                                else:
                                    status = STATUS_SUCCESS
                                    error = None
                                    result_body = result
                                _log(
                                    f"Resultado message_id={message_id} command={raw_command!r} "
                                    f"[{_tool_family_label(command)}] "
                                    f"→ {_result_summary(command, result)}"
                                )
                            except asyncio.TimeoutError:
                                status = STATUS_ERROR
                                error = f"Timeout ({timeout}s) excedido en el agente"
                                result_body = None
                                _log(
                                    f"Timeout message_id={message_id} command={raw_command!r} "
                                    f"tras {timeout}s",
                                    err=True,
                                )
                            except Exception as e:
                                status = STATUS_ERROR
                                error = str(e)
                                result_body = None
                                _log(
                                    f"Excepción message_id={message_id} command={raw_command!r}: {e}",
                                    err=True,
                                )

                            # §8.4-D: restart_agent → re-ejecutar tras responder al backend
                            _agent_restart = None
                            if isinstance(result, dict):
                                _agent_restart = result.pop(RESTART_MARKER, None)

                            completed_at = now_iso()
                            duration_ms = None
                            started_dt = parse_iso(started_at)
                            completed_dt = parse_iso(completed_at)
                            if started_dt and completed_dt:
                                duration_ms = int(
                                    (completed_dt - started_dt).total_seconds() * 1000
                                )

                            audit.append(
                                {
                                    "kind": "command_executed",
                                    "message_id": message_id,
                                    "command": raw_command,
                                    "params": params,
                                    "issued_by": payload.get("issued_by"),
                                    "issued_at": payload.get("issued_at"),
                                    "expires_at": payload.get("expires_at"),
                                    "status": status,
                                    "result_summary": _result_summary(command, result)
                                    if result is not None
                                    else None,
                                    "error": error,
                                    "started_at": started_at,
                                    "completed_at": completed_at,
                                    "agent_id": state.get("agent_id"),
                                }
                            )

                            if isinstance(result_body, dict):
                                result_body = compact_command_result(
                                    result_body, tool=command
                                )
                            resp = make_command_response(
                                message_id,
                                status,
                                agent_id=state.get("agent_id"),
                                tenant_id=tenant_id,
                                result=result_body,
                                error=error,
                                started_at=started_at,
                                completed_at=completed_at,
                                duration_ms=duration_ms,
                            )
                            await _send_json(resp)
                            _log(
                                f"Respuesta enviada message_id={message_id} status={status}"
                            )
                            if command in WINDOWS_TOOLS or command in LINUX_TOOLS or command in (
                                "windows_sysmon",
                                "windows_defender",
                                "linux_lsm",
                            ):
                                try:
                                    _session_telemetry_sink(
                                        {
                                            "event_type": "telemetry.tool_result",
                                            "category": _tool_family_label(command),
                                            "severity": (
                                                "error"
                                                if status != STATUS_SUCCESS
                                                else "info"
                                            ),
                                            "scheduled": False,
                                            "request_id": message_id,
                                            "tool": command,
                                            "result": result_body,
                                            "error": error,
                                        }
                                    )
                                except Exception as e:
                                    _log(
                                        f"Telemetría post-comando {command!r}: {e}",
                                        err=True,
                                    )
                            # §8.4-D: restart_agent → programar re-exec del proceso
                            if _agent_restart:
                                _log(
                                    f"restart_agent: reiniciando proceso en {float(_agent_restart):g}s"
                                )
                                asyncio.create_task(
                                    schedule_agent_restart(float(_agent_restart))
                                )
                        continue

                    # Mensajes no contemplados por §8.3 (por ahora)
                    if verbose:
                        try:
                            preview = _truncate(
                                json.dumps(payload, ensure_ascii=False),
                                500,
                            )
                        except Exception:
                            preview = str(payload)[:500]
                        _log(
                            f"Mensaje WS sin tipo manejado; tipo={ptype!r} vista_previa={preview}"
                        )
            finally:
                heartbeat_task.cancel()
                priority_task.cancel()
                _log(f"Sesión WebSocket finalizada (desconectado de {ws_url})")


async def run_forever(
    *,
    max_retries: int,
    retry_delay: int,
    max_chars: int,
    concurrency: int,
    config_file: str,
    verbose: bool,
    url: Optional[str] = None,
) -> None:
    attempt = 0
    delay = float(retry_delay)

    # RF-CORE-04: buffer de telemetría persistente (sobrevive reconexiones y
    # reinicios del proceso; los eventos pendientes se reenvían al reconectar).
    runtime_config = load_runtime_config(config_file)
    if runtime_config.get("max_chars") is not None:
        try:
            max_chars = int(runtime_config.get("max_chars"))
        except (TypeError, ValueError):
            pass
    from colsoft_tools.cloud_metadata import fetch_cloud_metadata

    fetch_cloud_metadata(runtime_config)
    telemetry_buffer = buffer_from_config(runtime_config)
    tenant_id = (runtime_config.get("tenant_id") or "").strip() or None
    iso_resume = resume_isolation_timer()
    if iso_resume:
        _log(f"Aislamiento al arrancar: {iso_resume}")
    identity_ref: Dict[str, Any] = {
        "agent_id": runtime_config.get("agent_id") or runtime_config.get("client_name"),
        "tenant_id": tenant_id,
    }
    priority_queue: asyncio.Queue = asyncio.Queue(maxsize=200)

    def _telemetry_sink(event):
        msg = make_event_push(
            identity_ref.get("agent_id"),
            event,
            tenant_id=identity_ref.get("tenant_id") or tenant_id,
            ts=now_iso(),
        )
        telemetry_buffer.put(msg)
        if is_control_plane_event(event or {}):
            try:
                priority_queue.put_nowait(msg)
            except asyncio.QueueFull:
                pass
        return None

    # RF-CORE-07: scheduler interno desacoplado del hilo WS. Corre en paralelo
    # al bucle de reconexión; sus resultados se encolan al buffer (RF-CORE-04).
    scheduler = AgentScheduler(
        runtime_config,
        execute=execute_tool,
        sink=_telemetry_sink,
        policy=CommandPolicy(runtime_config),
        config_file=config_file,
        log=lambda *a, **k: _log(*a),
    )
    scheduler_task = asyncio.create_task(scheduler.run_forever())

    # RF-OBS-08 / §7.1: plano de datos OTLP (HTTPS, batch + gzip), independiente del WS.
    data_plane = DataPlaneExporter(
        runtime_config,
        telemetry_buffer,
        log=lambda *a, **k: _log(a[0] if a else "", **k),
    )
    data_plane_task = asyncio.create_task(data_plane.run_forever())

    # RF-OBS-02/07/09: process watch, health probes, alertas locales.
    obs_tasks = spawn_obs_tasks(
        runtime_config,
        sink=_telemetry_sink,
        log=lambda *a, **k: _log(*a),
    )

    # RF-SEC-01..10: FIM, persistencia, auth, reglas, DNS, rootkit, CIS, CVE insumo.
    sec_tasks = spawn_sec_tasks(
        runtime_config,
        sink=_telemetry_sink,
        execute=execute_tool,
        policy=CommandPolicy(runtime_config),
        config_file=config_file,
        log=lambda *a, **k: _log(*a),
    )

    win_tasks = spawn_win_tasks(
        runtime_config,
        sink=_telemetry_sink,
        log=lambda *a, **k: _log(*a),
    )
    linux_tasks = spawn_linux_tasks(
        runtime_config,
        sink=_telemetry_sink,
        log=lambda *a, **k: _log(*a),
    )

    def _stop_background() -> None:
        scheduler_task.cancel()
        data_plane_task.cancel()
        for task in obs_tasks:
            task.cancel()
        for task in sec_tasks:
            task.cancel()
        for task in win_tasks:
            task.cancel()
        for task in linux_tasks:
            task.cancel()

    shutdown = AgentShutdown()
    _install_shutdown_handlers(shutdown)
    background_tasks = [
        scheduler_task,
        data_plane_task,
        *obs_tasks,
        *sec_tasks,
        *win_tasks,
        *linux_tasks,
    ]

    try:
        while not shutdown.requested:
            attempt += 1
            session_task = asyncio.create_task(
                client_session(
                    url or WS_URL,
                    config_file,
                    max_chars=max_chars,
                    concurrency=concurrency,
                    verbose=verbose,
                    telemetry_buffer=telemetry_buffer,
                    identity_ref=identity_ref,
                    priority_queue=priority_queue,
                )
            )
            shutdown_task = asyncio.create_task(shutdown.wait())
            done, pending = await asyncio.wait(
                {session_task, shutdown_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task

            if shutdown.requested:
                break

            if session_task in done and not session_task.cancelled():
                try:
                    session_task.result()
                except Exception as e:
                    retry_label = "∞" if max_retries < 0 else str(max_retries)
                    _log(
                        f"Desconectado o error: {e!r} | reintento #{attempt} (max_reintentos={retry_label})",
                        err=True,
                    )

            if max_retries >= 0 and attempt >= max_retries + 1:
                _log("max_retries alcanzado; saliendo.", err=True)
                break

            if shutdown.requested:
                break

            sleep_s = min(delay, 60.0)
            sleep_s *= random.uniform(0.8, 1.2)
            _log(f"Esperando {sleep_s:.1f}s antes de reconectar…")
            if await shutdown.wait_or_timeout(sleep_s):
                break
            delay = min(delay * 2, 60.0)
    finally:
        _stop_background()
        with suppress(asyncio.CancelledError):
            await asyncio.gather(*background_tasks, return_exceptions=True)


def _derive_enroll_server(ws_url: str) -> str:
    """Deriva la URL base del backend (http/https) desde la URL del WebSocket.

    `wss://host:8000/ws/colsoft-tools` → `https://host:8000`
    `ws://host:8000/ws/colsoft-tools`  → `http://host:8000`
    """
    try:
        from urllib.parse import urlsplit, urlunsplit

        parts = urlsplit(ws_url or "")
        scheme = "https" if parts.scheme == "wss" else "http"
        path = parts.path.rsplit("/ws/", 1)[0]
        return urlunsplit((scheme, parts.netloc, path, "", ""))
    except Exception:
        return ""


def _run_enrollment(args) -> int:
    """Provisiona la identidad persistente del agente (RF-CORE-01/02) vía CLI.

    Usa `--enroll <token>` + `--enroll-server <url>` (o deriva del WS URL) +
    `--enroll-tenant <tenant_id>`. Al terminar, `config_client.json`/identidad
    quedan en la carpeta del binario (modo frozen) o en `enrollment/`.
    """
    from colsoft_tools.enrollment import (
        allocate_identity_dir,
        enroll,
        identity_exists,
        load_identity,
        resolve_enroll_verify,
    )

    client_name = (args.enroll_name or "").strip() or (
        platform.node() or socket.gethostname() or "PC_Cliente"
    )
    tenant_id = (args.enroll_tenant or "").strip() or None
    out_dir = (
        (getattr(args, "enroll_dir", None) or "").strip()
        or allocate_identity_dir(client_name)
    )

    if identity_exists(out_dir=out_dir):
        bundle = load_identity(out_dir=out_dir)
        _log(
            f"Identidad ya provisionada en {out_dir!r}: "
            f"agent_id={bundle.get('agent_id')!r}"
        )
        return 0

    server = (args.enroll_server or "").strip() or _derive_enroll_server(WS_URL)
    if not server:
        _log(
            "enrollment: falta --enroll-server (o una URL WS válida para derivarla).",
            err=True,
        )
        return 1
    token = (args.enroll_token or "").strip()
    if not token:
        _log("enrollment: falta --enroll (token de un solo uso).", err=True)
        return 1

    _log(
        f"Enrollment (RF-CORE-01/02): server={server} client_name={client_name!r} "
        f"out_dir={out_dir!r} tenant_id={tenant_id!r}"
    )
    disk_cfg = None
    try:
        disk_cfg, _errs, _path = load_config(getattr(args, "config", None) or default_config_path())
    except Exception:
        disk_cfg = None
    ca = (getattr(args, "enroll_ca", None) or "").strip() or None
    verify = resolve_enroll_verify(
        server,
        ca,
        config=disk_cfg if isinstance(disk_cfg, dict) else None,
        identity_dir=out_dir,
    )
    cert_path = (getattr(args, "enroll_cert", None) or "").strip()
    key_path = (getattr(args, "enroll_key", None) or "").strip()
    client_cert = (cert_path, key_path) if cert_path and key_path else None
    if server.startswith("https://") and verify is True:
        _log(
            "enrollment HTTPS sin pin de CA: se usa la tienda del sistema. "
            "Pase --enroll-ca / ROBIN_ENROLL_CA o deje ca.crt en enrollment/."
        )
    try:
        bundle = enroll(
            server,
            token,
            client_name,
            out_dir=out_dir,
            tenant_id=tenant_id,
            timeout=30.0,
            verify=verify,
            client_cert=client_cert,
        )
    except Exception as e:
        _log(f"enrollment falló: {e}", err=True)
        return 1

    # Dev: el bundle del backend usa wss:// por defecto; con --enroll-insecure
    # se ajusta la identidad a ws:// + allow_insecure_ws (solo entornos dev).
    if getattr(args, "enroll_insecure", False):
        from colsoft_tools.enrollment import save_identity

        if bundle.get("websocket_url", "").startswith("wss://"):
            bundle["websocket_url"] = "ws://" + bundle["websocket_url"][6:]
        bundle["allow_insecure_ws"] = True
        save_identity(bundle, out_dir=out_dir)
        _log("Enrollment ajustado a modo inseguro (ws:// dev).")

    _log(
        f"Identidad provisionada OK: agent_id={bundle.get('agent_id')!r} "
        f"tenant_id={bundle.get('tenant_id')!r} → {out_dir!r}"
    )
    return 0


def _run_self_test(config_file: str) -> int:
    """Smoke test local (build/instalación): valida config, identidad y módulos.

    No conecta al backend; solo reporta el estado de los componentes del core
    común (RF-CORE-03/04/06/07 y RF-OBS-02/04/05/07/08/09). Sale 0 si todo está sano.
    """
    runtime = load_runtime_config(config_file)
    if not runtime:
        _log("self-test: sin config/identidad válida.", err=True)
        return 1

    checks = []
    # RF-CORE-03: validar el config de disco contra el esquema (sin errores)
    from colsoft_tools.config_manager import load_config

    _norm, _errs, _path = load_config(config_file)
    checks.append(("config (RF-CORE-03)", not _errs))
    try:
        from colsoft_tools.telemetry_buffer import TelemetryBuffer

        buf_dir = tempfile.mkdtemp(prefix="self-test-buf-")
        tb = TelemetryBuffer(
            buf_dir, max_events=5, max_age_days=1.0, max_file_bytes=65536
        )
        tb.put({"event_type": "self_test"})
        batch = tb.take(1)
        checks.append(
            (
                "buffer (RF-CORE-04)",
                len(batch) == 1 and tb.count() == 0,
            )
        )
    except Exception as e:
        checks.append((f"buffer (RF-CORE-04): {e}", False))
    try:
        from colsoft_tools.scheduler import AgentScheduler

        sched = AgentScheduler(
            runtime,
            execute=lambda *a, **k: {},
            sink=lambda *a, **k: None,
            policy=__import__("colsoft_tools.security", fromlist=["CommandPolicy"]).CommandPolicy(runtime),
        )
        checks.append(("scheduler (RF-CORE-07)", isinstance(sched.status(), dict)))
    except Exception as e:
        checks.append((f"scheduler (RF-CORE-07): {e}", False))
    try:
        from colsoft_tools.tamper import TamperMonitor

        tm = TamperMonitor(runtime, log=lambda *a, **k: None)
        checks.append(("tamper (RF-CORE-06)", isinstance(tm.status(), dict)))
    except Exception as e:
        checks.append((f"tamper (RF-CORE-06): {e}", False))
    try:
        from colsoft_tools.data_plane import DataPlaneExporter, events_to_otlp_logs
        from colsoft_tools.telemetry_buffer import TelemetryBuffer as _TB

        _tb = _TB(
            tempfile.mkdtemp(prefix="self-test-otlp-"),
            max_events=5,
            max_age_days=1.0,
            max_file_bytes=65536,
        )
        exporter = DataPlaneExporter(runtime, _tb, log=lambda *a, **k: None)
        sample = events_to_otlp_logs(
            [
                {
                    "type": "event_push",
                    "agent_id": runtime.get("agent_id") or "self-test",
                    "event": {"event_type": "telemetry.self_test", "tool": "health_check"},
                }
            ],
            runtime,
        )
        checks.append(
            (
                "data plane OTLP (RF-OBS-08)",
                isinstance(exporter.status(), dict) and bool(sample.get("resourceLogs")),
            )
        )
    except Exception as e:
        checks.append((f"data plane OTLP (RF-OBS-08): {e}", False))
    try:
        from colsoft_tools.observability import (
            get_hardware_inventory,
            get_system_log,
            run_health_probes,
        )

        hw = get_hardware_inventory()
        checks.append(("hardware inventory (RF-OBS-05)", hw.get("status") == "OK"))
        logs = get_system_log(max_lines=5, level="info")
        entries = logs.get("entries")
        log_ok = isinstance(logs, dict) and (
            entries is None
            or (
                isinstance(entries, list)
                and (not entries or isinstance(entries[0], dict))
            )
        )
        checks.append(("system_log normalized (RF-OBS-04)", log_ok))
        probes = run_health_probes(
            [{"id": "loopback", "type": "tcp", "host": "127.0.0.1", "port": 1, "timeout": 1}]
        )
        rec = (probes.get("checks") or [None])[0]
        # Puerto 1 suele estar cerrado: DOWN es un resultado válido del probe.
        # El smoke test cubre que el motor corre (RF-OBS-07), no que el puerto esté UP.
        checks.append(
            (
                "health_probes (RF-OBS-07)",
                probes.get("count") == 1
                and isinstance(rec, dict)
                and rec.get("status") in ("UP", "DOWN")
                and probes.get("status") in ("OK", "DOWN"),
            )
        )
    except Exception as e:
        checks.append((f"observability extras: {e}", False))
    try:
        from colsoft_tools.obs_monitors import AlertEngine, ProcessWatcher

        watcher = ProcessWatcher(interval_seconds=1, max_events_per_tick=40)
        baseline = watcher.tick()
        extra_key = (-1, 1.0)
        extra = {
            extra_key: {
                "pid": -1,
                "ppid": 0,
                "name": "self-test-proc",
                "username": "test",
                "create_time": 1.0,
                "cmdline": "self-test",
            }
        }
        created = watcher.tick({**(watcher._seen or {}), **extra})
        exited = watcher.tick(
            {k: v for k, v in (watcher._seen or {}).items() if k != extra_key}
        )
        process_ok = (
            baseline == []
            and any(e.get("event_type") == "process.created" for e in created)
            and any(e.get("event_type") == "process.exited" for e in exited)
        )
        checks.append(("process_watch (RF-OBS-02)", process_ok))
        engine = AlertEngine(
            [{"id": "cpu", "metric": "cpu.percent", "op": "gt", "threshold": 50}],
            cooldown_seconds=0,
        )
        alerts = engine.evaluate(
            {"cpu": {"percent": 90}, "memory": {"percent": 10}, "disks": []}
        )
        cleared = engine.evaluate(
            {"cpu": {"percent": 10}, "memory": {"percent": 10}, "disks": []}
        )
        alert_ok = any(
            e.get("event_type") == "alert.threshold" for e in alerts
        ) and any(e.get("event_type") == "alert.cleared" for e in cleared)
        checks.append(("alerts (RF-OBS-09)", alert_ok))
    except Exception as e:
        checks.append((f"obs_monitors: {e}", False))
    try:
        from colsoft_tools.endpoint_security import (
            cis_score,
            fim_diff,
            match_detection_rules,
            persistence_scan,
            rootkit_check,
        )
        from colsoft_tools.obs_monitors import is_control_plane_event as _cpe

        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.write(b"phase3-fim")
        tmp.close()
        from colsoft_tools.endpoint_security import fim_scan as _fim

        scan = _fim([tmp.name], include_process=False)
        files = {r["path"]: r for r in scan.get("files") or []}
        rec = files.get(tmp.name) or (scan.get("files") or [{}])[0]
        prev = {
            tmp.name: {
                "sha256": "0" * 64,
                "exists": True,
                "user": rec.get("user"),
                "uid": rec.get("uid"),
            }
        }
        curr = {
            tmp.name: {
                "sha256": rec.get("sha256"),
                "exists": True,
                "user": rec.get("user"),
                "uid": rec.get("uid"),
            }
        }
        diff = fim_diff(prev, curr)
        os.unlink(tmp.name)
        checks.append(
            (
                "fim (RF-SEC-01)",
                scan.get("status") == "OK" and any(d.get("change") == "modified" for d in diff),
            )
        )
        pers = persistence_scan()
        checks.append(("persistence (RF-SEC-02)", pers.get("status") == "OK"))
        hits = match_detection_rules(
            {"pid": 1, "name": "bash", "cmdline": "curl http://x | sh", "username": "root"}
        )
        checks.append(
            (
                "detection rules (RF-SEC-04)",
                any(h.get("rule_id") == "SEC-002" for h in hits),
            )
        )
        cis = cis_score()
        checks.append(
            ("cis_score (RF-SEC-06)", cis.get("status") == "OK" and "score" in cis)
        )
        rk = rootkit_check()
        checks.append(("rootkit (RF-SEC-08)", rk.get("status") == "OK"))
        checks.append(
            (
                "event_push security (RF-SEC-09)",
                _cpe({"event_type": "security.detection"}),
            )
        )
    except Exception as e:
        checks.append((f"endpoint_security: {e}", False))
    try:
        from colsoft_tools.obs_monitors import is_control_plane_event as _cpe_win
        from colsoft_tools.windows_collectors import (
            parse_evtx_xml,
            parse_logman_providers,
            windows_etw,
            windows_wmi,
        )

        sample = (
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            "<System><Provider Name='Microsoft-Windows-Security-Auditing'/>"
            "<EventID>4624</EventID><Level>0</Level>"
            "<TimeCreated SystemTime='2026-08-21T15:00:00.0000000Z'/>"
            "<Channel>Security</Channel><Computer>PC</Computer>"
            "<EventRecordID>9</EventRecordID></System></Event>"
        )
        parsed = parse_evtx_xml(sample)
        xml_ok = bool(parsed) and parsed[0].get("event_id") == "4624"
        checks.append(("windows evtx xml (RF-WIN-02)", xml_ok))
        providers = parse_logman_providers(
            "Provider                                 GUID\n"
            "Microsoft-Windows-Kernel-Process        {22FB2CD6-0000-0000-0000-000000000000}\n"
        )
        checks.append(("windows etw parse (RF-WIN-01)", len(providers) == 1))
        etw = windows_etw()
        wmi = windows_wmi("Win32_Evil")
        if platform.system() != "Windows":
            checks.append(("windows tools UNSUPPORTED off-Win", etw.get("status") == "UNSUPPORTED"))
            checks.append(("wmi allowlist even off-Win", wmi.get("status") == "UNSUPPORTED"))
        else:
            checks.append(("windows_etw callable", etw.get("status") in ("OK", "ERROR")))
            checks.append(("wmi allowlist reject", wmi.get("status") == "ERROR"))
        checks.append(
            (
                "event_push windows autorun (RF-WIN-03)",
                _cpe_win({"event_type": "windows.autorun_change"}),
            )
        )
    except Exception as e:
        checks.append((f"windows collectors: {e}", False))

    _log(
        f"self-test: agent_id={runtime.get('agent_id')!r} "
        f"tenant_id={runtime.get('tenant_id')!r} websocket_url={runtime.get('websocket_url')!r}"
    )
    ok = True
    for label, passed in checks:
        _log(f"  {'PASS' if passed else 'FAIL'} {label}")
        ok = ok and passed
    return 0 if ok else 1


def main() -> None:
    ap = argparse.ArgumentParser(
        description="WS Tools Executor Client (embedded)"
    )
    ap.add_argument(
        "--url",
        required=False,
        default=None,
        help="Override de websocket_url (si el config no trae una). "
        'Ej: "wss://host/ws/colsoft-tools"',
    )
    ap.add_argument(
        "--config",
        required=False,
        default=_default_config_path(),
        help="Ruta al config_client.json",
    )
    ap.add_argument("--max-chars", type=int, default=60000)
    ap.add_argument("--concurrency", type=int, default=10)
    ap.add_argument("--max-retries", type=int, default=-1, help="-1 = infinito")
    ap.add_argument("--retry-delay", type=int, default=2)
    ap.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Más trazas en consola",
    )
    ap.add_argument(
        "--enroll",
        dest="enroll_token",
        default=None,
        metavar="TOKEN",
        help="Token de un solo uso para provisionar la identidad persistente "
        "(RF-CORE-01/02). Requiere --enroll-server o una URL WS derivable.",
    )
    ap.add_argument(
        "--enroll-server",
        default=None,
        metavar="URL",
        help="URL base del backend (http/https). Si se omite, se deriva del WS URL.",
    )
    ap.add_argument(
        "--enroll-tenant",
        default=None,
        metavar="TENANT",
        help="tenant_id a registrar en la identidad (RF-CORE-08).",
    )
    ap.add_argument(
        "--enroll-name",
        default=None,
        metavar="NAME",
        help="client_name del agente (default: hostname). Carpeta: enrollment/<NAME>/.",
    )
    ap.add_argument(
        "--enroll-dir",
        default=os.environ.get("ROBIN_IDENTITY_DIR"),
        metavar="DIR",
        help="Carpeta destino del enrollment (default: enrollment/<NAME>/ única).",
    )
    ap.add_argument(
        "--identity-dir",
        default=os.environ.get("ROBIN_IDENTITY_DIR"),
        metavar="DIR",
        help="Identidad activa al arrancar (default: enrollment/active.json).",
    )
    ap.add_argument(
        "--enroll-insecure",
        action="store_true",
        help="Dev: ajusta la identidad provisionada a ws:// (allow_insecure_ws). "
        "Nunca usar en producción.",
    )
    ap.add_argument(
        "--enroll-ca",
        default=os.environ.get("ROBIN_ENROLL_CA"),
        metavar="PATH",
        help="PEM de la CA del servidor para pinnear POST /api/enroll (HTTPS).",
    )
    ap.add_argument(
        "--enroll-cert",
        default=os.environ.get("ROBIN_ENROLL_CERT"),
        metavar="PATH",
        help="Cert de cliente para re-enrolar contra un socket en mTLS.",
    )
    ap.add_argument(
        "--enroll-key",
        default=os.environ.get("ROBIN_ENROLL_KEY"),
        metavar="PATH",
        help="Llave del cert de --enroll-cert.",
    )
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="Smoke test local (config+identidad+módulos core) y salir.",
    )
    args = ap.parse_args()

    if args.enroll_token:
        rc = _run_enrollment(args)
        if rc != 0:
            raise SystemExit(rc)
        _log("Enrollment completado; arrancando agente…")

    if args.self_test:
        raise SystemExit(_run_self_test(args.config))

    runtime_config = load_runtime_config(
        args.config,
        identity_dir=(getattr(args, "identity_dir", None) or "").strip() or None,
    )
    agent_id = (
        (runtime_config.get("agent_id") or runtime_config.get("client_name") or "agent")
        .strip()
        .replace("/", "_")
    )
    ident_dir = resolve_identity_dir(
        runtime_config,
        explicit=(getattr(args, "identity_dir", None) or "").strip() or None,
    )
    lock_root = ident_dir or default_identity_location()
    lock_path = os.path.join(lock_root, f"{agent_id}.pid")
    instance_lock = AgentInstanceLock(lock_path)
    instance_lock.acquire()

    try:
        asyncio.run(
            run_forever(
                max_retries=int(args.max_retries),
                retry_delay=int(args.retry_delay),
                max_chars=int(args.max_chars),
                concurrency=int(args.concurrency),
                config_file=args.config,
                verbose=bool(args.verbose),
                url=args.url,
            )
        )
    except KeyboardInterrupt:
        _log("Salida por Ctrl+C")
        raise SystemExit(130)
    finally:
        instance_lock.release()


if __name__ == "__main__":
    main()