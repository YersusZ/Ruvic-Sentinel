"""Modelo unificado de eventos — SRS §14.

El backend no debe distinguir `WindowsEventX` / `SysmonEventY` / `LinuxAuditZ`.
Cada evento de telemetría se normaliza aquí antes de salir del agente
(`event_push` y buffer OTLP).
"""

from __future__ import annotations

import platform
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from colsoft_tools.cloud_metadata import fetch_cloud_metadata


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

SCHEMA_VERSION = "1.0"

_HOST_CACHE: Optional[Dict[str, Any]] = None


def reset_host_cache() -> None:
    """Solo tests."""
    global _HOST_CACHE
    _HOST_CACHE = None


def host_info() -> Dict[str, Any]:
    global _HOST_CACHE
    if _HOST_CACHE is None:
        info: Dict[str, Any] = {
            "hostname": platform.node() or "",
            "os": (platform.system() or "").lower(),
            "os_version": platform.platform(),
        }
        for key, value in fetch_cloud_metadata().items():
            if value:
                info[str(key)] = value
        _HOST_CACHE = info
    return dict(_HOST_CACHE)


def normalize_event(
    event: Dict[str, Any],
    *,
    agent_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> Dict[str, Any]:
    """Completa el envelope §14 sin borrar campos específicos de la fuente."""
    if not isinstance(event, dict):
        event = {"summary": str(event)}
    out = dict(event)
    out.setdefault("schema_version", SCHEMA_VERSION)
    ts = timestamp or out.get("timestamp") or out.get("ts") or _now_iso()
    out["timestamp"] = ts
    out.setdefault("ts", ts)
    if agent_id and not out.get("agent_id"):
        out["agent_id"] = agent_id
    # RF-CORE-08: el campo va siempre (string, posiblemente vacío).
    if tenant_id is not None:
        out["tenant_id"] = str(tenant_id)
    else:
        out.setdefault("tenant_id", "")
    if not isinstance(out.get("host"), dict):
        out["host"] = host_info()
    out.setdefault("event_type", "telemetry")
    out.setdefault("category", "observability")
    out.setdefault("severity", "info")
    if "user" not in out and out.get("username"):
        out["user"] = out.get("username")
    if "process" not in out and (
        out.get("pid") is not None
        or out.get("name")
        or out.get("comm")
        or out.get("cmdline")
        or out.get("exe")
    ):
        proc: Dict[str, Any] = {}
        if out.get("pid") is not None:
            proc["pid"] = out.get("pid")
        if out.get("ppid") is not None:
            proc["parent"] = out.get("ppid")
        name = out.get("name") or out.get("comm")
        if name:
            proc["name"] = name
        cmd = out.get("command_line") or out.get("cmdline") or out.get("exe")
        if cmd:
            proc["command_line"] = cmd
        if proc:
            out["process"] = proc
    if "detection" not in out and (out.get("rule_id") or out.get("technique")):
        det: Dict[str, Any] = {}
        if out.get("rule_id"):
            det["rule_id"] = out.get("rule_id")
        if out.get("technique"):
            det["mitre_technique"] = out.get("technique")
        if det:
            out["detection"] = det
    out.setdefault("network", out.get("network") or {})
    return out
