"""
Plano de datos del agente — SRS §7.1 / RF-OBS-08.

El WebSocket es el plano de *control* (comandos, heartbeat, event_push de
alta prioridad). La telemetría de volumen (métricas, resultados programados,
logs) sale por un canal HTTP aparte: OTLP/HTTP JSON con batch y gzip.

Destino por defecto: el mismo host del backend (`/v1/logs` y `/v1/metrics`).
También acepta un collector OpenTelemetry (puerto 4318) si `endpoint` lo indica.

Config (`data_plane` en config_client.json):
  enabled                  bool   (default True si hay URL derivable)
  endpoint                 str    URL base o /v1/logs completo
  compression              str    "gzip" | "none"  (default gzip)
  batch_size               int    (default 32)
  batch_interval_seconds   num    (default 5)
  timeout_seconds          num    (default 15)
  insecure                 bool   permite http:// (lab); si no, se hereda
                                  de allow_insecure_ws
"""

from __future__ import annotations

import asyncio
import gzip
import json
import ssl
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

import aiohttp

from colsoft_tools.cloud_metadata import cloud_otlp_attributes, fetch_cloud_metadata
from colsoft_tools.protocol import parse_iso
from colsoft_tools.telemetry_buffer import TelemetryBuffer
from colsoft_tools.tls_util import make_client_ssl_context
from colsoft_tools.windows_collectors import flatten_wmi_row

from colsoft_tools.agent_admin import AGENT_VERSION

SERVICE_NAME = "robin-client-monitor"
SCOPE_NAME = "robin.agent"
SCOPE_VERSION = AGENT_VERSION

_SEVERITY = {
    "trace": (1, "TRACE"),
    "debug": (5, "DEBUG"),
    "info": (9, "INFO"),
    "warn": (13, "WARN"),
    "warning": (13, "WARN"),
    "error": (17, "ERROR"),
    "fatal": (21, "FATAL"),
    "critical": (21, "FATAL"),
    "high": (17, "ERROR"),
    "medium": (13, "WARN"),
    "low": (9, "INFO"),
}


def derive_otlp_base(ws_url: str) -> str:
    """wss://host:8000/ws/colsoft-tools → https://host:8000"""
    try:
        parts = urlsplit(ws_url or "")
        if not parts.scheme or not parts.netloc:
            return ""
        scheme = "https" if parts.scheme in ("wss", "https") else "http"
        path = parts.path.rsplit("/ws/", 1)[0] if "/ws/" in parts.path else ""
        if path in ("/",):
            path = ""
        return urlunsplit((scheme, parts.netloc, path.rstrip("/"), "", ""))
    except Exception:
        return ""


def data_plane_enabled(config: Dict[str, Any]) -> bool:
    cfg = config.get("data_plane") if isinstance(config.get("data_plane"), dict) else {}
    if "enabled" in cfg:
        return bool(cfg.get("enabled"))
    return bool(otlp_base_url(config))


def otlp_base_url(config: Dict[str, Any]) -> str:
    cfg = config.get("data_plane") if isinstance(config.get("data_plane"), dict) else {}
    endpoint = str(cfg.get("endpoint") or "").strip().rstrip("/")
    if endpoint:
        for suffix in ("/v1/logs", "/v1/metrics", "/v1/traces"):
            if endpoint.endswith(suffix):
                return endpoint[: -len(suffix)]
        return endpoint
    return derive_otlp_base(str(config.get("websocket_url") or ""))


def _nano(ts: Optional[str]) -> str:
    dt = parse_iso(ts) or datetime.now(timezone.utc)
    return str(int(dt.timestamp() * 1_000_000_000))


def _kv(key: str, value: Any) -> Optional[Dict[str, Any]]:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return {"key": key, "value": {"boolValue": value}}
    if isinstance(value, int) and not isinstance(value, bool):
        return {"key": key, "value": {"intValue": str(value)}}
    if isinstance(value, float):
        return {"key": key, "value": {"doubleValue": value}}
    return {"key": key, "value": {"stringValue": str(value)[:2048]}}


def _attrs(pairs: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for key, value in pairs.items():
        item = _kv(key, value)
        if item:
            out.append(item)
    return out


def _resource(config: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
    host = (
        config.get("client_name")
        or event.get("agent_id")
        or config.get("agent_id")
        or ""
    )
    attrs: Dict[str, Any] = {
        "service.name": SERVICE_NAME,
        "service.instance.id": event.get("agent_id") or config.get("agent_id"),
        "tenant.id": event.get("tenant_id") or config.get("tenant_id"),
        "host.name": host,
        "agent.id": event.get("agent_id") or config.get("agent_id"),
    }
    inner = event.get("event") if isinstance(event.get("event"), dict) else event
    host_meta = inner.get("host") if isinstance(inner.get("host"), dict) else {}
    attrs.update(cloud_otlp_attributes(host_meta or fetch_cloud_metadata(config)))
    return {"attributes": _attrs(attrs)}


def _severity(event: Dict[str, Any]) -> Tuple[int, str]:
    inner = event.get("event") if isinstance(event.get("event"), dict) else {}
    raw = str(inner.get("severity") or event.get("severity") or "info").strip().lower()
    return _SEVERITY.get(raw, (9, "INFO"))


def _event_body(event: Dict[str, Any]) -> str:
    inner = event.get("event") if isinstance(event.get("event"), dict) else event
    et = inner.get("event_type") or event.get("type") or "telemetry"
    tool = inner.get("tool") or ""
    return f"{et}" + (f" {tool}" if tool else "")


# Atributo OTLP string: si se corta a N chars el JSON queda inválido y el
# receptor lo guarda como payload.raw (p.ej. service_status con 200+ unidades).
_OTLP_PAYLOAD_MAX = 8000
_OTLP_LIST_SAMPLE = 12
_OTLP_PACKAGES_MAX = 200
_BULKY_LIST_KEYS = {
    "services",
    "processes",
    "connections",
    "entries",
    "items",
    "detections",
    "queries",
    "files",
    "findings",
    "hops",
    "checks",
    "disks",
    "providers",
    "of_interest",
    "tasks",
    "rows",
    "disk_io",
    "changes",
    "units",
    "timers",
    "programs",
    "denials",
    "interfaces",
    "sockets",
    "stats",
    "net",
    "rules",
    "profiles",
    "enabled",
    "events",
    "volumes",
    "answers",
    "applied",
}

_EVENT_ENTRY_KEYS = (
    "ts",
    "level",
    "provider",
    "event_id",
    "channel",
    "computer",
    "record_id",
    "source",
    "message",
    "pid",
    "host",
    # auditd / syslog Linux: slim_event_entry no debe dejar solo ts+pid
    "type",
    "uid",
    "exe",
    "comm",
    "syscall",
    "success",
    "msg",
)


def _dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


def _sample_list(items: List[Any], limit: int) -> Tuple[List[Any], int]:
    n = len(items)
    if n <= limit:
        return items, 0
    return items[:limit], n - limit


def _slim_package(pkg: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(pkg, dict):
        return None
    name = pkg.get("name") or pkg.get("product")
    if not name:
        return None
    rec: Dict[str, Any] = {"name": name, "version": pkg.get("version") or ""}
    if pkg.get("sha256"):
        rec["sha256"] = pkg.get("sha256")
    return rec


def _slim_event_data(data: Any, *, max_keys: int = 12, max_val: int = 180) -> Dict[str, str]:
    if not isinstance(data, dict):
        return {}
    slim: Dict[str, str] = {}
    for i, (key, value) in enumerate(data.items()):
        if i >= max_keys:
            break
        slim[str(key)] = str(value)[:max_val]
    return slim


def slim_event_entry(entry: Any) -> Optional[Dict[str, Any]]:
    """Event Log / Sysmon: metadatos + EventData recortado (cabe en RobinLogs)."""
    if not isinstance(entry, dict):
        return None
    rec = {k: entry.get(k) for k in _EVENT_ENTRY_KEYS if entry.get(k) is not None}
    if isinstance(rec.get("message"), str):
        rec["message"] = rec["message"][:180]
    data = _slim_event_data(entry.get("data"))
    if data:
        rec["data"] = data
    return rec


def _slim_record(item: Any) -> Any:
    """Misma receta que Event Log / paquetes: escalares + strings cortos."""
    if not isinstance(item, dict):
        return str(item)[:180]
    out: Dict[str, Any] = {}
    for i, (key, value) in enumerate(item.items()):
        if i >= 12:
            break
        name = str(key)
        if value is None or isinstance(value, (bool, int, float)):
            out[name] = value
        elif isinstance(value, str):
            out[name] = value[:180]
        elif isinstance(value, list):
            out[name] = f"[{len(value)}]"
        elif isinstance(value, dict):
            out[name] = _slim_event_data(value)
        else:
            out[name] = str(value)[:180]
    return out


def _compact_result(
    result: Dict[str, Any], *, list_limit: int = _OTLP_LIST_SAMPLE
) -> Dict[str, Any]:
    """Resume listados grandes; conserva count/status y una muestra."""
    out: Dict[str, Any] = {}
    truncated = bool(result.get("truncated"))
    for key, value in result.items():
        if key == "packages" and isinstance(value, list):
            slim = [p for p in (_slim_package(x) for x in value) if p]
            kept, omitted = _sample_list(slim, _OTLP_PACKAGES_MAX)
            out[key] = kept
            if omitted:
                truncated = True
                out["packages_omitted"] = omitted
            continue
        if key == "entries" and isinstance(value, list):
            slim = [e for e in (slim_event_entry(x) for x in value) if e]
            kept, omitted = _sample_list(slim or value, list_limit)
            out[key] = kept
            if omitted:
                truncated = True
                out["entries_omitted"] = omitted
            continue
        if key == "rows" and isinstance(value, list):
            slim = [
                r
                for r in (
                    flatten_wmi_row(x) or (x if isinstance(x, dict) else None)
                    for x in value
                )
                if r
            ]
            kept, omitted = _sample_list(slim, list_limit)
            out[key] = kept
            if omitted:
                truncated = True
                out["rows_omitted"] = omitted
            continue
        if key == "channels" and isinstance(value, dict):
            out[key] = {
                name: _compact_result(ch, list_limit=list_limit)
                if isinstance(ch, dict)
                else ch
                for name, ch in value.items()
            }
            if any(
                isinstance(ch, dict) and ch.get("truncated")
                for ch in out[key].values()
            ):
                truncated = True
            continue
        if key == "event_data" and isinstance(value, dict):
            out[key] = _slim_event_data(value)
            continue
        if key == "points" and isinstance(value, list):
            # Gauges OTLP (`otlp_metrics`): el widget filtra por name; no muestrear.
            slim_pts: List[Dict[str, Any]] = []
            for p in value:
                if not isinstance(p, dict) or p.get("name") is None:
                    continue
                rec: Dict[str, Any] = {"name": p.get("name"), "value": p.get("value")}
                if p.get("unit") is not None:
                    rec["unit"] = p.get("unit")
                if p.get("timeUnixNano") is not None:
                    rec["timeUnixNano"] = p.get("timeUnixNano")
                slim_pts.append(rec)
            if len(slim_pts) <= 200:
                out[key] = slim_pts
            else:
                kept, omitted = _sample_list(slim_pts, 200)
                out[key] = kept
                if omitted:
                    truncated = True
                    out["points_omitted"] = omitted
            continue
        if key in _BULKY_LIST_KEYS and isinstance(value, list):
            slim = [_slim_record(x) for x in value]
            kept, omitted = _sample_list(slim, list_limit)
            out[key] = kept
            if omitted:
                truncated = True
                out[f"{key}_omitted"] = omitted
            continue
        if isinstance(value, dict):
            nested = _compact_result(value, list_limit=list_limit)
            out[key] = nested
            if nested.get("truncated"):
                truncated = True
            continue
        out[key] = value
    if truncated:
        out["truncated"] = True
    return out


def _counts_only(result: Dict[str, Any]) -> Dict[str, Any]:
    """Último recurso: status/count por sección, sin listados."""
    out: Dict[str, Any] = {"truncated": True}
    for key in (
        "tool",
        "status",
        "count",
        "error",
        "score",
        "class_name",
        "namespace",
        "failed",
        "down",
        "response_time",
        "response_time_max",
        "uptime_seconds",
        "uptime_s",
        "filesystem_percent_max",
    ):
        if key in result:
            out[key] = result[key]
    for key, value in result.items():
        if isinstance(value, list):
            out[f"{key}_count"] = len(value)
        elif isinstance(value, dict):
            if value and all(not isinstance(v, (list, dict)) for v in value.values()):
                out[key] = dict(value)
                continue
            nested = _counts_only(value)
            nested.pop("truncated", None)
            if nested:
                out[key] = nested
    return out


def compact_event_for_otlp(inner: Dict[str, Any]) -> Dict[str, Any]:
    """Payload JSON siempre parseable y acotado para el atributo event.payload."""
    if not isinstance(inner, dict):
        return {"value": str(inner)[:500]}

    def _wrap(result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "schema_version": inner.get("schema_version") or "1.0",
            "event_type": inner.get("event_type"),
            "category": inner.get("category"),
            "severity": inner.get("severity"),
            "scheduled": inner.get("scheduled"),
            "request_id": inner.get("request_id"),
            "tool": inner.get("tool"),
            "tenant_id": inner.get("tenant_id") if inner.get("tenant_id") is not None else "",
        }
        if result is not None:
            payload["result"] = result
        if inner.get("error"):
            payload["error"] = str(inner.get("error"))[:400]
        return payload

    if "result" in inner and isinstance(inner.get("result"), dict):
        raw_result = inner["result"]
        for limit in (_OTLP_LIST_SAMPLE, 8, 4, 2):
            payload = _wrap(_compact_result(raw_result, list_limit=limit))
            if len(_dump(payload)) <= _OTLP_PAYLOAD_MAX:
                if limit < _OTLP_LIST_SAMPLE:
                    payload["result"]["truncated"] = True
                return payload
        payload = _wrap(_counts_only(raw_result))
        if len(_dump(payload)) <= _OTLP_PAYLOAD_MAX:
            return payload
    else:
        payload = dict(inner)
        if len(_dump(payload)) <= _OTLP_PAYLOAD_MAX:
            return payload

    return {
        "schema_version": inner.get("schema_version") or "1.0",
        "event_type": inner.get("event_type"),
        "tool": inner.get("tool"),
        "category": inner.get("category"),
        "scheduled": inner.get("scheduled"),
        "request_id": inner.get("request_id"),
        "tenant_id": inner.get("tenant_id") if inner.get("tenant_id") is not None else "",
        "truncated": True,
        "error": "payload_too_large",
    }


_WS_ENTRY_META = (
    "ts",
    "level",
    "provider",
    "event_id",
    "channel",
    "computer",
    "record_id",
    "source",
)
_WS_LIST_SAMPLE = 3


_WS_LINUX_ENTRY_META = (
    "type",
    "pid",
    "uid",
    "exe",
    "comm",
    "syscall",
    "success",
)


def _ws_slim_entry(entry: Any) -> Any:
    """Metadatos de Event Log sin EventData: el WS de control no aguanta blobs."""
    if not isinstance(entry, dict):
        return str(entry)[:80]
    rec = {k: entry.get(k) for k in _WS_ENTRY_META if entry.get(k) is not None}
    for key in _WS_LINUX_ENTRY_META:
        if entry.get(key) is not None and key not in rec:
            rec[key] = entry.get(key)
    # syslog/journal: el mensaje es el contenido; Event Log lo omite (blobs).
    if "event_id" not in rec and "provider" not in rec:
        msg = entry.get("message") or entry.get("msg")
        if isinstance(msg, str) and msg:
            rec["message"] = msg[:120]
    return rec


def _control_plane_result(
    result: Dict[str, Any], *, list_limit: int = _WS_LIST_SAMPLE
) -> Dict[str, Any]:
    """Versión mínima para command_response: counts + muestra sin `data`."""
    out: Dict[str, Any] = {}
    truncated = bool(result.get("truncated"))
    for key, value in result.items():
        if key in ("data", "event_data"):
            truncated = True
            continue
        if key == "channels" and isinstance(value, dict):
            out[key] = {
                name: _control_plane_result(ch, list_limit=list_limit)
                if isinstance(ch, dict)
                else ch
                for name, ch in value.items()
            }
            if any(
                isinstance(ch, dict) and ch.get("truncated")
                for ch in out[key].values()
            ):
                truncated = True
            continue
        if key in ("entries", "rows") and isinstance(value, list):
            slim = [_ws_slim_entry(x) for x in value]
            kept, omitted = _sample_list(slim, list_limit)
            orig = int(result.get("count") or 0) or (
                len(value) + int(result.get(f"{key}_omitted") or 0)
            )
            out[key] = kept
            extra = max(0, orig - len(kept))
            if extra:
                truncated = True
                out[f"{key}_omitted"] = extra
            continue
        if key in _BULKY_LIST_KEYS and isinstance(value, list):
            kept, omitted = _sample_list(value, list_limit)
            out[key] = [_slim_record(x) for x in kept]
            extra = omitted + int(result.get(f"{key}_omitted") or 0)
            if extra:
                truncated = True
                out[f"{key}_omitted"] = extra
            continue
        if isinstance(value, dict) and key not in (
            "cpu",
            "memory",
            "host",
            "identity",
        ):
            nested = _control_plane_result(value, list_limit=list_limit)
            out[key] = nested
            if nested.get("truncated"):
                truncated = True
            continue
        out[key] = value
    if truncated:
        out["truncated"] = True
    return out


def compact_command_result(
    result: Optional[Dict[str, Any]], *, tool: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """Acota el resultado de un comando para el WebSocket.

    Más agresivo que OTLP: Event Log / WMI sin EventData y muestra de 3.
    Un JSON de ~8–20 KB con PrivilegeList sigue tumbando aiohttp en Windows.
    """
    if not isinstance(result, dict):
        return result
    packed = compact_event_for_otlp(
        {
            "event_type": "telemetry.tool_result",
            "tool": tool or result.get("tool"),
            "result": result,
        }
    )
    inner = packed.get("result")
    if isinstance(inner, dict):
        inner = _control_plane_result(inner)
        if packed.get("truncated") or packed.get("error") == "payload_too_large":
            inner["truncated"] = True
        dumped = _dump(inner)
        if len(dumped) > _OTLP_PAYLOAD_MAX:
            inner = _counts_only(result)
            inner["tool"] = tool or result.get("tool")
            inner["truncated"] = True
        return inner
    return {
        "tool": tool or result.get("tool"),
        "status": result.get("status") or "ERROR",
        "truncated": True,
        "error": packed.get("error") or "payload_too_large",
    }


_LOGGER_KEEP = (
    "agent_id",
    "tenant_id",
    "user_id",
    "issued_by",
    "message_id",
    "tool",
    "tool_family",
    "success",
    "command_status",
    "status",
    "event_type",
    "error",
    "truncated",
    "target",
    "duration_ms",
    "result_summary",
    "command",
    "otlp",
    "points",
)


def compact_logger_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """Compacta cualquier `data` de send_log (tools, event_push, OTLP)."""
    if not isinstance(data, dict):
        return {"value": str(data)[:500]}
    out = dict(data)

    if isinstance(out.get("result"), dict):
        packed = compact_event_for_otlp(
            {
                "tool": out.get("tool"),
                "event_type": out.get("event_type") or "telemetry.tool_result",
                "category": out.get("tool_family") or out.get("category"),
                "result": out["result"],
            }
        )
        inner = packed.get("result")
        out["result"] = inner if isinstance(inner, dict) else packed
        if packed.get("truncated") or packed.get("error") == "payload_too_large":
            out["truncated"] = True

    if isinstance(out.get("payload"), dict):
        pl = out["payload"]
        if isinstance(pl.get("result"), dict):
            out["payload"] = compact_event_for_otlp(pl)
        else:
            packed = compact_event_for_otlp(
                {
                    "tool": out.get("tool") or pl.get("tool"),
                    "event_type": pl.get("event_type") or out.get("event_type"),
                    "result": pl,
                }
            )
            out["payload"] = packed.get("result") if isinstance(packed.get("result"), dict) else packed

    out = _compact_result(out)
    if len(_dump(out)) <= _OTLP_PAYLOAD_MAX:
        return out

    out["truncated"] = True
    for key in ("result", "payload"):
        blob = out.get(key)
        if isinstance(blob, dict) and len(_dump(blob)) > 4000:
            out[key] = _counts_only(blob)
    if len(_dump(out)) <= _OTLP_PAYLOAD_MAX:
        return out

    slim = {k: out[k] for k in _LOGGER_KEEP if k in out}
    slim["truncated"] = True
    return slim


def events_to_otlp_logs(
    events: List[Dict[str, Any]], config: Dict[str, Any]
) -> Dict[str, Any]:
    """Mapea event_push / dicts del buffer a OTLP JSON Logs."""
    by_resource: Dict[str, List[Dict[str, Any]]] = {}
    resources: Dict[str, Dict[str, Any]] = {}
    for ev in events:
        agent_id = str(ev.get("agent_id") or config.get("agent_id") or "")
        tenant_id = str(ev.get("tenant_id") or config.get("tenant_id") or "")
        key = f"{agent_id}|{tenant_id}"
        inner = ev.get("event") if isinstance(ev.get("event"), dict) else {}
        sev_n, sev_t = _severity(ev)
        compact = compact_event_for_otlp(inner or ev)
        record = {
            "timeUnixNano": _nano(ev.get("ts") or inner.get("timestamp")),
            "severityNumber": sev_n,
            "severityText": sev_t,
            "body": {"stringValue": _event_body(ev)},
            "attributes": _attrs(
                {
                    "event.type": inner.get("event_type") or ev.get("type"),
                    "tool": inner.get("tool"),
                    "category": inner.get("category") or compact.get("category"),
                    "request_id": inner.get("request_id"),
                    "scheduled": inner.get("scheduled"),
                    "tenant.id": tenant_id,
                    "agent.id": agent_id,
                }
            ),
        }
        try:
            dumped = _dump(compact)
            if len(dumped) > _OTLP_PAYLOAD_MAX:
                dumped = _dump(compact_event_for_otlp({"tool": inner.get("tool"), "truncated": True}))
            record["attributes"].append(
                {"key": "event.payload", "value": {"stringValue": dumped}}
            )
        except (TypeError, ValueError):
            pass
        by_resource.setdefault(key, []).append(record)
        resources.setdefault(key, _resource(config, ev))

    return {
        "resourceLogs": [
            {
                "resource": resources[key],
                "scopeLogs": [
                    {
                        "scope": {"name": SCOPE_NAME, "version": SCOPE_VERSION},
                        "logRecords": records,
                    }
                ],
            }
            for key, records in by_resource.items()
        ]
    }


def _gauge(name: str, value: Any, ts_nano: str, unit: str = "") -> Optional[Dict[str, Any]]:
    try:
        num = float(value)
    except (TypeError, ValueError):
        return None
    metric: Dict[str, Any] = {
        "name": name,
        "gauge": {"dataPoints": [{"asDouble": num, "timeUnixNano": ts_nano}]},
    }
    if unit:
        metric["unit"] = unit
    return metric


def _cpu_load_avg(cpu: Dict[str, Any], minutes: int) -> Optional[float]:
    """Load average 1/5/15 desde system_metrics (claves o lista load_avg_1_5_15)."""
    idx = {1: 0, 5: 1, 15: 2}.get(minutes)
    if idx is None:
        return None
    key = f"load_avg_{minutes}"
    raw = cpu.get(key)
    if isinstance(raw, (int, float)) and not isinstance(raw, bool):
        return float(raw)
    series = cpu.get("load_avg_1_5_15")
    if isinstance(series, (list, tuple)) and len(series) > idx:
        val = series[idx]
        if isinstance(val, (int, float)) and not isinstance(val, bool):
            return float(val)
    return None


def _network_byte_totals(result: Dict[str, Any]) -> Tuple[Optional[int], Optional[int]]:
    """bytes_sent / bytes_recv desde dict Windows, lista Linux, o `net` crudo."""
    net = result.get("network_io")
    if net is None:
        net = result.get("net")
    if isinstance(net, dict):
        sent, recv = net.get("bytes_sent"), net.get("bytes_recv")
        if sent is not None or recv is not None:
            try:
                return (
                    int(sent or 0) if sent is not None else 0,
                    int(recv or 0) if recv is not None else 0,
                )
            except (TypeError, ValueError):
                return sent, recv
        net = net.get("interfaces")
    if not isinstance(net, list):
        return None, None
    sent = recv = 0
    any_row = False
    for row in net:
        if not isinstance(row, dict):
            continue
        any_row = True
        sent += int(row.get("tx_bytes") or row.get("bytes_sent") or 0)
        recv += int(row.get("rx_bytes") or row.get("bytes_recv") or 0)
    return (sent, recv) if any_row else (None, None)


def _disk_io_totals(
    result: Dict[str, Any],
) -> Tuple[Optional[int], Optional[int], Optional[int], Optional[int]]:
    """Lecturas/escrituras acumuladas (ops y bytes) desde disk_io, disks o dict psutil.

    En Linux `system_metrics.disk_io` es un dict de totales (como Windows).
    `linux_proc_metrics` sigue trayendo `disks[]` de diskstats. El dashboard
    pinta IOPS con aggregate=rate sobre las ops.
    """
    rows: List[Any] = []
    for key in ("disk_io", "disks"):
        raw = result.get(key)
        if isinstance(raw, list):
            rows.extend(raw)
        elif isinstance(raw, dict) and (
            raw.get("read_count") is not None or raw.get("reads") is not None
        ):
            rows.append(raw)
    reads = writes = read_bytes = write_bytes = 0
    any_ops = any_bytes = False
    for row in rows:
        if not isinstance(row, dict):
            continue
        r = row.get("reads")
        if r is None:
            r = row.get("read_count")
        w = row.get("writes")
        if w is None:
            w = row.get("write_count")
        if r is None and w is None and row.get("percent") is not None:
            continue
        if isinstance(r, (int, float)) and not isinstance(r, bool):
            reads += int(r)
            any_ops = True
        if isinstance(w, (int, float)) and not isinstance(w, bool):
            writes += int(w)
            any_ops = True
        rb = row.get("read_bytes")
        wb = row.get("write_bytes")
        rs = row.get("read_sectors")
        ws = row.get("write_sectors")
        if isinstance(rb, (int, float)) and not isinstance(rb, bool):
            read_bytes += int(rb)
            any_bytes = True
        elif isinstance(rs, (int, float)) and not isinstance(rs, bool):
            read_bytes += int(rs) * 512
            any_bytes = True
        if isinstance(wb, (int, float)) and not isinstance(wb, bool):
            write_bytes += int(wb)
            any_bytes = True
        elif isinstance(ws, (int, float)) and not isinstance(ws, bool):
            write_bytes += int(ws) * 512
            any_bytes = True
    return (
        reads if any_ops else None,
        writes if any_ops else None,
        read_bytes if any_bytes else None,
        write_bytes if any_bytes else None,
    )


def _disk_queue_length(result: Dict[str, Any]) -> Optional[float]:
    dio = result.get("disk_io")
    if isinstance(dio, dict):
        raw = dio.get("queue_length")
        if isinstance(raw, (int, float)) and not isinstance(raw, bool):
            return float(raw)
    total = 0.0
    any_row = False
    for key in ("disk_io", "disks"):
        raw = result.get(key)
        if not isinstance(raw, list):
            continue
        for row in raw:
            if not isinstance(row, dict):
                continue
            ip = row.get("in_progress")
            if ip is None:
                ip = row.get("ios_in_progress")
            if isinstance(ip, (int, float)) and not isinstance(ip, bool):
                total += float(ip)
                any_row = True
    return total if any_row else None


def _fs_percent_max(result: Dict[str, Any]) -> Optional[float]:
    """Uso máximo de filesystem (volúmenes), no IOPS."""
    raw_max = result.get("filesystem_percent_max")
    if isinstance(raw_max, (int, float)) and not isinstance(raw_max, bool):
        return float(raw_max)
    best: Optional[float] = None
    for key in ("volumes", "disks"):
        raw = result.get(key)
        if not isinstance(raw, list):
            continue
        for row in raw:
            if not isinstance(row, dict):
                continue
            if row.get("reads") is not None and row.get("percent") is None:
                continue
            p = row.get("percent")
            if isinstance(p, (int, float)) and not isinstance(p, bool):
                best = float(p) if best is None else max(best, float(p))
    return best


def _network_packet_totals(
    result: Dict[str, Any],
) -> Tuple[Optional[int], Optional[int], Optional[int], Optional[int]]:
    """packets sent/recv, errores y drops desde dict Windows o lista Linux."""
    net = result.get("network_io")
    if net is None:
        net = result.get("net")
    sent = recv = errs = drops = 0
    any_row = False
    if isinstance(net, dict):
        ps, pr = net.get("packets_sent"), net.get("packets_recv")
        if ps is not None or pr is not None:
            try:
                sent = int(ps or 0)
                recv = int(pr or 0)
                errs = int(net.get("errin") or 0) + int(net.get("errout") or 0)
                drops = int(net.get("dropin") or 0) + int(net.get("dropout") or 0)
                return sent, recv, errs, drops
            except (TypeError, ValueError):
                pass
        net = net.get("interfaces")
    if not isinstance(net, list):
        return None, None, None, None
    for row in net:
        if not isinstance(row, dict):
            continue
        any_row = True
        sent += int(row.get("tx_packets") or row.get("packets_sent") or 0)
        recv += int(row.get("rx_packets") or row.get("packets_recv") or 0)
        errs += int(row.get("tx_errors") or 0) + int(row.get("rx_errors") or 0)
        errs += int(row.get("errin") or 0) + int(row.get("errout") or 0)
        drops += int(row.get("tx_dropped") or 0) + int(row.get("rx_dropped") or 0)
        drops += int(row.get("dropin") or 0) + int(row.get("dropout") or 0)
    return (sent, recv, errs, drops) if any_row else (None, None, None, None)


def _systemd_failed(result: Dict[str, Any]) -> Optional[int]:
    raw = result.get("failed")
    if isinstance(raw, (int, float)) and not isinstance(raw, bool):
        return int(raw)
    units = result.get("units")
    if not isinstance(units, list):
        return None
    return sum(
        1
        for u in units
        if isinstance(u, dict) and str(u.get("active") or "").lower() == "failed"
    )


_TCP_CONNECTION_GAUGES = (
    ("tcp", "system.network.connections", "{connections}"),
    ("listen", "system.network.connections.listen", "{connections}"),
    ("established", "system.network.connections.established", "{connections}"),
    ("time_wait", "system.network.connections.time_wait", "{connections}"),
    ("syn_recv", "system.network.connections.syn_recv", "{connections}"),
    ("syn_sent", "system.network.connections.syn_sent", "{connections}"),
    ("close_wait", "system.network.connections.close_wait", "{connections}"),
    ("udp", "system.network.connections.udp", "{connections}"),
)


def _tcp_connections_block(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    raw = result.get("tcp_connections")
    return raw if isinstance(raw, dict) else None


def _tcp_connection_gauges(
    result: Dict[str, Any], ts: str
) -> List[Optional[Dict[str, Any]]]:
    block = _tcp_connections_block(result)
    if not block:
        return []
    return [
        _gauge(name, block.get(key), ts, unit) for key, name, unit in _TCP_CONNECTION_GAUGES
    ]


def _probe_latency(result: Dict[str, Any]) -> Tuple[Optional[float], Optional[float]]:
    avg = result.get("response_time")
    mx = result.get("response_time_max")
    if isinstance(avg, (int, float)) and not isinstance(avg, bool):
        avg_f = float(avg)
    else:
        avg_f = None
    if isinstance(mx, (int, float)) and not isinstance(mx, bool):
        mx_f = float(mx)
    else:
        mx_f = None
    if avg_f is not None and mx_f is not None:
        return avg_f, mx_f
    times: List[float] = []
    for rec in result.get("checks") or []:
        if not isinstance(rec, dict) or rec.get("status") != "UP":
            continue
        raw = rec.get("response_time")
        if isinstance(raw, (int, float)) and not isinstance(raw, bool):
            times.append(float(raw))
    if not times:
        return avg_f, mx_f
    return (
        avg_f if avg_f is not None else sum(times) / len(times),
        mx_f if mx_f is not None else max(times),
    )


def events_to_otlp_metrics(
    events: List[Dict[str, Any]], config: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """Gauges OTLP desde system_metrics, health_probes, conexiones y systemd."""
    resource_metrics: List[Dict[str, Any]] = []
    for ev in events:
        inner = ev.get("event") if isinstance(ev.get("event"), dict) else {}
        result = inner.get("result") if isinstance(inner.get("result"), dict) else inner
        tool = inner.get("tool") or result.get("tool")
        ts = _nano(ev.get("ts") or result.get("timestamp") or result.get("ts"))
        candidates: List[Optional[Dict[str, Any]]] = []

        if tool == "health_probes" or result.get("tool") == "health_probes":
            if result.get("count") is None:
                continue
            avg_rt, max_rt = _probe_latency(result)
            candidates = [
                _gauge("health.probe.count", result.get("count"), ts, "{checks}"),
                _gauge("health.probe.down", result.get("down"), ts, "{checks}"),
                _gauge("health.probe.response_time", avg_rt, ts, "s"),
                _gauge("health.probe.response_time.max", max_rt, ts, "s"),
            ]
        elif tool == "linux_systemd_units" or result.get("tool") == "linux_systemd_units":
            candidates = [
                _gauge(
                    "system.systemd.units.failed",
                    _systemd_failed(result),
                    ts,
                    "{units}",
                ),
            ]
        elif (
            tool in ("system_metrics", "network_connections", "linux_proc_metrics")
            or "cpu" in result
            or _tcp_connections_block(result)
        ):
            if tool == "system_metrics" or "cpu" in result:
                cpu = result.get("cpu") if isinstance(result.get("cpu"), dict) else {}
                mem = result.get("memory") if isinstance(result.get("memory"), dict) else {}
                sent, recv = _network_byte_totals(result)
                disk_reads, disk_writes, disk_rbytes, disk_wbytes = _disk_io_totals(result)
                pkt_sent, pkt_recv, net_errs, net_drops = _network_packet_totals(result)
                fs_max = _fs_percent_max(result)
                used = mem.get("used")
                if used is None and mem.get("total") is not None and mem.get("available") is not None:
                    try:
                        used = int(mem["total"]) - int(mem["available"])
                    except (TypeError, ValueError):
                        used = None
                available = mem.get("available")
                available_mib = None
                if isinstance(available, (int, float)) and not isinstance(available, bool):
                    available_mib = float(available) / (1024.0 * 1024.0)
                uptime = result.get("uptime_seconds")
                if uptime is None:
                    uptime = result.get("uptime_s")
                swap_used = mem.get("swap_used")
                candidates.extend(
                    [
                        _gauge("system.cpu.utilization", cpu.get("percent"), ts, "%"),
                        _gauge(
                            "system.cpu.logical.count",
                            cpu.get("logical_cores"),
                            ts,
                            "{cpu}",
                        ),
                        _gauge("system.cpu.load_average.1m", _cpu_load_avg(cpu, 1), ts, "1"),
                        _gauge("system.cpu.load_average.5m", _cpu_load_avg(cpu, 5), ts, "1"),
                        _gauge("system.cpu.load_average.15m", _cpu_load_avg(cpu, 15), ts, "1"),
                        _gauge("system.memory.utilization", mem.get("percent"), ts, "%"),
                        _gauge("system.memory.usage", used, ts, "By"),
                        _gauge("system.memory.available", available, ts, "By"),
                        _gauge("system.memory.available.mbytes", available_mib, ts, "MiBy"),
                        _gauge(
                            "system.memory.swap.utilization",
                            mem.get("swap_percent"),
                            ts,
                            "%",
                        ),
                        _gauge("system.memory.swap.usage", swap_used, ts, "By"),
                        _gauge("system.filesystem.utilization", fs_max, ts, "%"),
                        _gauge("system.uptime", uptime, ts, "s"),
                        _gauge(
                            "system.processor.queue.length",
                            cpu.get("processor_queue_length"),
                            ts,
                            "{threads}",
                        ),
                        _gauge(
                            "system.processor.system_queue.length",
                            cpu.get("system_processor_queue_length")
                            or cpu.get("processor_queue_length"),
                            ts,
                            "{threads}",
                        ),
                        _gauge(
                            "system.disk.queue.length",
                            _disk_queue_length(result),
                            ts,
                            "{queue}",
                        ),
                        _gauge("system.network.io.bytes_sent", sent, ts, "By"),
                        _gauge("system.network.io.bytes_recv", recv, ts, "By"),
                        _gauge("system.network.packets.sent", pkt_sent, ts, "{packets}"),
                        _gauge("system.network.packets.recv", pkt_recv, ts, "{packets}"),
                        _gauge("system.network.errors", net_errs, ts, "{errors}"),
                        _gauge("system.network.dropped", net_drops, ts, "{packets}"),
                        _gauge("system.disk.operations.read", disk_reads, ts, "{ops}"),
                        _gauge("system.disk.operations.write", disk_writes, ts, "{ops}"),
                        _gauge("system.disk.io.read", disk_rbytes, ts, "By"),
                        _gauge("system.disk.io.write", disk_wbytes, ts, "By"),
                    ]
                )
            candidates.extend(_tcp_connection_gauges(result, ts))
        else:
            continue
        metrics = [m for m in candidates if m]
        if not metrics:
            continue
        resource_metrics.append(
            {
                "resource": _resource(config, ev),
                "scopeMetrics": [
                    {
                        "scope": {"name": SCOPE_NAME, "version": SCOPE_VERSION},
                        "metrics": metrics,
                    }
                ],
            }
        )
    if not resource_metrics:
        return None
    return {"resourceMetrics": resource_metrics}


def _ssl_context(config: Dict[str, Any], url: str) -> ssl.SSLContext:
    return make_client_ssl_context(config)


class DataPlaneExporter:
    """Drena el TelemetryBuffer por OTLP/HTTP (batch + gzip), independiente del WS."""

    def __init__(
        self,
        config: Dict[str, Any],
        buffer: TelemetryBuffer,
        *,
        log: Callable[..., None] = lambda *a, **k: None,
    ):
        self.config = config
        self.buffer = buffer
        self.log = log
        cfg = config.get("data_plane") if isinstance(config.get("data_plane"), dict) else {}
        self.batch_size = max(1, int(cfg.get("batch_size") or 32))
        self.interval = max(1.0, float(cfg.get("batch_interval_seconds") or 5))
        self.timeout = max(3.0, float(cfg.get("timeout_seconds") or 15))
        compression = str(cfg.get("compression") or "gzip").strip().lower()
        self.gzip = compression != "none"
        self.base = otlp_base_url(config)
        self.enabled = data_plane_enabled(config) and bool(self.base)
        insecure = cfg.get("insecure")
        if insecure is None:
            insecure = bool(config.get("allow_insecure_ws"))
        self.insecure = bool(insecure)

    def status(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "endpoint": f"{self.base}/v1/logs" if self.base else "",
            "compression": "gzip" if self.gzip else "none",
            "batch_size": self.batch_size,
            "batch_interval_seconds": self.interval,
            "pending": self.buffer.count(),
        }

    async def run_forever(self) -> None:
        if not self.enabled:
            self.log("Data plane OTLP desactivado (RF-OBS-08).")
            while True:
                await asyncio.sleep(3600)

        self.log(
            f"Data plane OTLP activo → {self.base}/v1/logs "
            f"(gzip={'on' if self.gzip else 'off'}, batch={self.batch_size}) (RF-OBS-08)."
        )
        try:
            connector = self._connector()
        except RuntimeError as e:
            self.log(f"Data plane OTLP no arranca: {e}", err=True)
            while True:
                await asyncio.sleep(3600)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            while True:
                try:
                    wait = 0.5 if self.buffer.count() >= self.batch_size else self.interval
                    await asyncio.sleep(wait)
                    batch = self.buffer.take(self.batch_size)
                    if not batch:
                        continue
                    try:
                        await self._export(session, batch)
                    except Exception as e:
                        self.buffer.restore(batch)
                        self.log(f"Data plane OTLP: reintento ({e})", err=True)
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    self.log(f"Data plane OTLP: error de bucle ({e})", err=True)
                    await asyncio.sleep(self.interval)

    def _connector(self) -> aiohttp.TCPConnector:
        url = f"{self.base}/v1/logs"
        if urlsplit(url).scheme == "http":
            if not self.insecure:
                raise RuntimeError(
                    "data plane http:// inseguro; use https:// o "
                    "data_plane.insecure / allow_insecure_ws (solo lab)."
                )
            return aiohttp.TCPConnector(ssl=False)
        ctx = _ssl_context(self.config, url)
        return aiohttp.TCPConnector(ssl=ctx)

    async def _export(
        self, session: aiohttp.ClientSession, batch: List[Dict[str, Any]]
    ) -> None:
        logs = events_to_otlp_logs(batch, self.config)
        await self._post(session, f"{self.base}/v1/logs", logs)
        metrics = events_to_otlp_metrics(batch, self.config)
        if metrics:
            try:
                await self._post(session, f"{self.base}/v1/metrics", metrics)
            except Exception as e:
                self.log(f"Data plane OTLP metrics: {e}", err=True)
        self.log(f"Data plane OTLP: exportados {len(batch)} evento(s).")

    async def _post(
        self, session: aiohttp.ClientSession, url: str, payload: Dict[str, Any]
    ) -> None:
        raw = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        body: Any = raw
        if self.gzip:
            body = gzip.compress(raw)
            headers["Content-Encoding"] = "gzip"
        async with session.post(url, data=body, headers=headers) as resp:
            if resp.status >= 300:
                text = await resp.text()
                raise RuntimeError(f"OTLP {resp.status} {url}: {text[:300]}")
