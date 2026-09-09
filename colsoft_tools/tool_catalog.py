"""Catálogo único de tools del agente (nombres internos) y taxonomía RobinLogs.

Fuente de verdad para allowlist, familia (`category`) y resumen de target.
Los alias SRS (§8.4) se resuelven con `protocol.resolve_command` antes de clasificar.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

from colsoft_tools.protocol import resolve_command

NETWORK_TOOLS = {
    "ping",
    "http_get",
    "tcp_connect",
    "dns_resolve",
    "tls",
    "traceroute",
    "dns_lookup",
}

OBSERVABILITY_TOOLS = {
    "system_metrics",
    "process_list",
    "service_status",
    "network_connections",
    "installed_software",
    "disk_usage",
    "file_hash",
    "system_log",
    "forensic_snapshot",
    "collect_file",
    "hardware_inventory",
    "health_probes",
}

WINDOWS_TOOLS = {
    "windows_event_log",
    "windows_etw",
    "windows_autoruns",
    "windows_wmi",
    "windows_scheduled_tasks",
}

LINUX_TOOLS = {
    "linux_ebpf",
    "linux_auditd",
    "linux_syslog",
    "linux_proc_metrics",
    "linux_netlink",
    "linux_systemd_units",
    "linux_packages",
}

REMEDIATION_TOOLS = {
    "kill_process",
    "start_service",
    "stop_service",
    "restart_service",
    "block_ip",
    "unblock_ip",
    "isolate_host",
    "restore_isolation",
    "run_script",
}

ADMIN_TOOLS = {
    "update_config",
    "trigger_update",
    "restart_agent",
    "health_check",
}

SECURITY_TOOLS = {
    "fim_scan",
    "persistence_scan",
    "auth_audit",
    "detection_scan",
    "cis_score",
    "cve_inventory",
    "rootkit_check",
    "dns_monitor",
    "windows_sysmon",
    "windows_defender",
    "linux_lsm",
}

ALLOWED_TOOLS = (
    NETWORK_TOOLS
    | OBSERVABILITY_TOOLS
    | WINDOWS_TOOLS
    | LINUX_TOOLS
    | REMEDIATION_TOOLS
    | ADMIN_TOOLS
    | SECURITY_TOOLS
)

# Identificadores de monitores (event_push / OTLP), no comandos WS.
TELEMETRY_TOOLS = {
    "process_watch",
    "alerts",
}

TOOL_CATEGORY_DEFAULT = "observability"


def tool_category(tool: str) -> str:
    """Familia → `category` RobinLogs: network_check | observability | windows | linux | remediation | agent_admin | security."""
    tool = resolve_command((tool or "").strip())
    if tool in NETWORK_TOOLS:
        return "network_check"
    if tool in REMEDIATION_TOOLS:
        return "remediation"
    if tool in ADMIN_TOOLS:
        return "agent_admin"
    if tool in SECURITY_TOOLS:
        return "security"
    if tool in WINDOWS_TOOLS:
        return "windows"
    if tool in LINUX_TOOLS:
        return "linux"
    if tool in TELEMETRY_TOOLS:
        return "observability"
    return TOOL_CATEGORY_DEFAULT


def _range_summary(p: Dict[str, Any]) -> str:
    bits = []
    if p.get("date"):
        bits.append(f"date={p.get('date')}")
    if p.get("startHour") or p.get("hour"):
        bits.append(f"startHour={p.get('startHour') or p.get('hour')}")
    if p.get("endHour") or p.get("hour"):
        bits.append(f"endHour={p.get('endHour') or p.get('hour')}")
    if p.get("startDate"):
        bits.append(f"startDate={p.get('startDate')}")
    if p.get("endDate"):
        bits.append(f"endDate={p.get('endDate')}")
    if p.get("since"):
        bits.append(f"since={p.get('since')}")
    if p.get("until"):
        bits.append(f"until={p.get('until')}")
    return (" " + " ".join(str(b) for b in bits)) if bits else ""


def tool_target_summary(tool: str, params: Optional[Dict[str, Any]] = None) -> str:
    """Resumen corto del objetivo (logs del agente y `data.target` en RobinLogs)."""
    tool = resolve_command((tool or "").strip())
    p = params or {}
    host = (p.get("host") or p.get("target") or "").strip()
    if tool == "http_get":
        return f"url={(p.get('url') or p.get('target') or '').strip() or '?'}"
    if tool in ("tcp_connect", "tcp_check"):
        return f"target={host or '?'} port={p.get('port', '?')}"
    if tool == "ping":
        if p.get("timeout_ms") is not None:
            t = f"timeout_ms={p.get('timeout_ms')!r}"
        else:
            t = f"timeout={p.get('timeout', 15)!r}"
        return f"target={host or '?'} count={p.get('count', 3)!r} {t}"
    if tool in ("dns_resolve", "tls"):
        return f"target={host or '?'}"
    if tool == "traceroute":
        return f"target={host or '?'} max_hops={p.get('max_hops', 30)!r}"
    if tool == "dns_lookup":
        p_host = (p.get("hostname") or p.get("host") or "").strip()
        return f"hostname={p_host or '?'} record_type={p.get('record_type') or p.get('type') or 'A'}"
    if tool == "collect_file":
        return f"path={p.get('path') or '?'} max_size_mb={p.get('max_size_mb', 10.0)!r}"
    if tool == "process_list":
        return f"filter={p.get('filter') or p.get('name') or '*'} limit={p.get('limit', 300)!r}"
    if tool == "system_log":
        return (
            f"source={p.get('source') or p.get('filter') or 'system'} "
            f"level={p.get('level', 'warning')} max_lines={p.get('max_lines', 500)!r}"
            f"{_range_summary(p)}"
        )
    if tool == "service_status":
        return f"service={p.get('service_name') or p.get('name') or '(todos)'}"
    if tool == "file_hash":
        return f"path={p.get('path') or '?'} algo={p.get('algo') or p.get('algorithm') or 'sha256'}"
    if tool == "installed_software":
        return f"include_hash={bool(p.get('include_hash'))} max_hash={p.get('max_hash', 40)!r}"
    if tool == "update_config":
        d = p.get("config_diff") or p.get("diff") or p.get("config") or {}
        if isinstance(d, dict):
            return f"diff={json.dumps(d, ensure_ascii=False)[:180]}"
        return "config_update"
    if tool == "restore_isolation":
        return "revert_firewall"
    if tool == "restart_agent":
        return f"delay={p.get('delay', 'default')}"
    if tool == "trigger_update":
        return f"version={p.get('version') or 'latest'}"
    if tool == "health_probes":
        checks = p.get("checks")
        n = len(checks) if isinstance(checks, list) else "config"
        return f"checks={n}"
    if tool == "fim_scan":
        paths = p.get("paths")
        n = len(paths) if isinstance(paths, list) else "default"
        return f"paths={n}"
    if tool == "auth_audit":
        return f"max_entries={p.get('max_entries', 80)!r}"
    if tool == "cve_inventory":
        return f"include_hash={bool(p.get('include_hash'))} max_hash={p.get('max_hash', 20)!r}"
    if tool == "windows_event_log":
        return (
            f"channel={p.get('channel') or p.get('source') or 'Security'} "
            f"max_events={p.get('max_events', 50)!r}{_range_summary(p)}"
        )
    if tool == "windows_etw":
        return f"max_providers={p.get('max_providers', 80)!r}"
    if tool == "windows_wmi":
        return f"class={p.get('class_name') or p.get('class') or 'Win32_OperatingSystem'}"
    if tool == "windows_scheduled_tasks":
        return f"max_tasks={p.get('max_tasks', 120)!r}"
    if tool == "windows_sysmon":
        return f"max_events={p.get('max_events', 30)!r}"
    if tool == "linux_ebpf":
        return f"max_programs={p.get('max_programs', 40)!r}"
    if tool == "linux_auditd":
        return f"max_events={p.get('max_events', 40)!r}{_range_summary(p)}"
    if tool == "linux_syslog":
        if p.get("bundle"):
            return (
                f"bundle max_lines={p.get('max_lines') or p.get('max_events') or 20!r}"
                f"{_range_summary(p)}"
            )
        return (
            f"source={p.get('source') or p.get('filter') or 'syslog'} "
            f"max_lines={p.get('max_lines', 80)!r}{_range_summary(p)}"
        )
    if tool == "linux_proc_metrics":
        return f"cpu_interval={p.get('cpu_interval', 0.15)!r}"
    if tool == "linux_netlink":
        return f"max_ifaces={p.get('max_ifaces', 32)!r}"
    if tool == "linux_systemd_units":
        return f"max_units={p.get('max_units', 400)!r}"
    if tool == "linux_packages":
        return f"include_hash={bool(p.get('include_hash'))} max_hash={p.get('max_hash', 20)!r}"
    if tool in (
        "health_check",
        "system_metrics",
        "network_connections",
        "disk_usage",
        "forensic_snapshot",
        "hardware_inventory",
        "persistence_scan",
        "detection_scan",
        "cis_score",
        "rootkit_check",
        "dns_monitor",
        "windows_autoruns",
        "windows_defender",
        "linux_lsm",
    ):
        return "(sin parámetros)"
    try:
        return json.dumps(p, ensure_ascii=False)[:180]
    except Exception:
        return str(p)[:180]
