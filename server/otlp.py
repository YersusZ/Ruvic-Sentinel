"""Receptor OTLP/HTTP (JSON + gzip) — SRS §7.1 / RF-OBS-08.

Ingesta el plano de datos del agente (separado del WebSocket) y lo vuelca
a RobinLogs + results_logs, igual que un `event_push` de telemetría.

Rutas (OTLP HTTP):
  POST /v1/logs
  POST /v1/metrics
  POST /otlp/v1/logs
  POST /otlp/v1/metrics
"""

from __future__ import annotations

import gzip
import json
import logging
from typing import Any, Dict, List

from fastapi import APIRouter, Request, Response

from lib.metrics_logger import log_agent_event
from save_result import save_execution_result_to_json

logger = logging.getLogger("agent-server")

router = APIRouter(tags=["otlp"])

_LEVEL_FROM_SEV = {
    "TRACE": "debug",
    "DEBUG": "debug",
    "INFO": "info",
    "WARN": "warn",
    "WARNING": "warn",
    "ERROR": "error",
    "FATAL": "fatal",
    "CRITICAL": "fatal",
}


async def _read_otlp_json(request: Request) -> Dict[str, Any]:
    raw = await request.body()
    encoding = (request.headers.get("content-encoding") or "").lower()
    if encoding == "gzip" or (
        len(raw) >= 2 and raw[0] == 0x1F and raw[1] == 0x8B
    ):
        try:
            raw = gzip.decompress(raw)
        except OSError as e:
            logger.warning("OTLP gzip inválido: %s", e)
            return {}
    if not raw:
        return {}
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        logger.warning("OTLP JSON inválido: %s", e)
        return {}
    return data if isinstance(data, dict) else {}


def _any_value(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    if "stringValue" in value:
        return value.get("stringValue")
    if "intValue" in value:
        try:
            return int(value.get("intValue"))
        except (TypeError, ValueError):
            return value.get("intValue")
    if "doubleValue" in value:
        return value.get("doubleValue")
    if "boolValue" in value:
        return bool(value.get("boolValue"))
    return value


def _attrs(items: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if not isinstance(items, list):
        return out
    for item in items:
        if not isinstance(item, dict):
            continue
        key = str(item.get("key") or "")
        if not key:
            continue
        out[key] = _any_value(item.get("value"))
    return out


def _ingest_log_record(
    resource_attrs: Dict[str, Any],
    record: Dict[str, Any],
) -> None:
    rec_attrs = _attrs(record.get("attributes"))
    agent_id = str(
        rec_attrs.get("agent.id")
        or resource_attrs.get("agent.id")
        or resource_attrs.get("service.instance.id")
        or "unknown"
    )
    tenant_id = (
        rec_attrs.get("tenant.id")
        or resource_attrs.get("tenant.id")
        or None
    )
    event_type = str(rec_attrs.get("event.type") or "telemetry")
    tool = rec_attrs.get("tool")
    payload_raw = rec_attrs.get("event.payload")
    event_payload: Any = payload_raw
    if isinstance(payload_raw, str):
        try:
            event_payload = json.loads(payload_raw)
        except ValueError:
            # JSON cortado a N chars en el agente (antes del compact): no volcar
            # el fragmento crudo a RobinLogs.
            event_payload = {
                "truncated": True,
                "parse_error": True,
                "preview": payload_raw[:240],
            }

    sev = str(record.get("severityText") or "INFO").upper()
    level = _LEVEL_FROM_SEV.get(sev, "info")
    body = record.get("body") if isinstance(record.get("body"), dict) else {}
    body_text = body.get("stringValue") or event_type

    payload_sev = ""
    if isinstance(event_payload, dict):
        payload_sev = str(event_payload.get("severity") or "").lower()
    os_high = rec_attrs.get("category") == "security" or payload_sev in (
        "high",
        "critical",
        "error",
    )

    if event_type.startswith("security.") or event_type in (
        "windows.sysmon",
        "windows.autorun_change",
        "linux.unit_change",
    ) or (event_type.startswith(("linux.", "windows.")) and os_high):
        log_type, category = "audit", rec_attrs.get("category") or "security"
    elif event_type.startswith("windows."):
        log_type, category = "activity", rec_attrs.get("category") or "windows"
    elif event_type.startswith("linux."):
        log_type, category = "activity", rec_attrs.get("category") or "linux"
    elif event_type.startswith("alert.") or event_type in (
        "health.probe",
        "process.created",
        "process.exited",
    ):
        log_type, category = "activity", "observability"
    elif event_type.startswith("telemetry."):
        log_type, category = "metrics", rec_attrs.get("category") or (
            event_payload.get("category") if isinstance(event_payload, dict) else None
        ) or "observability"
    else:
        log_type, category = "activity", rec_attrs.get("category") or "observability"

    data: Dict[str, Any] = {
        "event_type": event_type,
        "tool": tool,
        "request_id": rec_attrs.get("request_id"),
        "scheduled": rec_attrs.get("scheduled"),
        "otlp": True,
        "body": body_text,
    }
    if isinstance(event_payload, dict):
        data["payload"] = event_payload

    if event_type.startswith("security.") or event_type.startswith("alert.") or event_type.startswith("windows.") or event_type.startswith("linux.") or event_type in (
        "health.probe",
        "process.created",
        "process.exited",
    ):
        brief = ""
        if isinstance(event_payload, dict):
            bits = []
            for key in (
                "rule_id",
                "metric",
                "op",
                "value",
                "threshold",
                "check_id",
                "status",
                "pid",
                "name",
                "path",
                "mitre_technique",
                "action",
                "domain",
                "summary",
                "channel",
                "event_id",
                "provider",
                "unit",
                "active",
                "sub",
                "iface",
                "audit_type",
                "exe",
                "comm",
                "change",
            ):
                if event_payload.get(key) is not None:
                    bits.append(f"{key}={event_payload.get(key)}")
            brief = " " + " ".join(bits) if bits else ""
        logger.info(
            "[OTLP] agent=%s %s tool=%s%s",
            agent_id,
            event_type,
            tool,
            brief,
        )

    if tool in ("cve_inventory", "installed_software", "linux_packages") and isinstance(event_payload, dict):
        from lib.cve_correlator import ingest_inventory, packages_from_result

        pkgs = packages_from_result(event_payload)
        if pkgs:
            ingest_inventory(
                str(agent_id),
                pkgs,
                tenant_id=str(tenant_id) if tenant_id else None,
            )

    if event_type.startswith(("linux.", "windows.", "security.", "alert.")):
        subcategory = event_type.split(".")[-1] or str(tool or "otlp")
    else:
        subcategory = str(tool or event_type.split(".")[-1] or "otlp")

    log_agent_event(
        agent_id=agent_id,
        event_type=log_type,
        category=category,
        subcategory=subcategory,
        level=level,
        data=data,
        tenant_id=str(tenant_id) if tenant_id else None,
    )
    save_execution_result_to_json(
        agent_id,
        {
            "type": "otlp_log",
            "event_type": event_type,
            "tool": tool or event_type.split(".")[-1] or "otlp",
            "tenant_id": tenant_id,
            "event": event_payload if isinstance(event_payload, dict) else record,
        },
    )


def _ingest_logs(payload: Dict[str, Any]) -> int:
    count = 0
    for rl in payload.get("resourceLogs") or []:
        if not isinstance(rl, dict):
            continue
        resource = rl.get("resource") if isinstance(rl.get("resource"), dict) else {}
        resource_attrs = _attrs(resource.get("attributes"))
        for sl in rl.get("scopeLogs") or []:
            if not isinstance(sl, dict):
                continue
            for record in sl.get("logRecords") or []:
                if isinstance(record, dict):
                    _ingest_log_record(resource_attrs, record)
                    count += 1
    return count


def _ingest_metrics(payload: Dict[str, Any]) -> int:
    count = 0
    for rm in payload.get("resourceMetrics") or []:
        if not isinstance(rm, dict):
            continue
        resource = rm.get("resource") if isinstance(rm.get("resource"), dict) else {}
        resource_attrs = _attrs(resource.get("attributes"))
        agent_id = str(
            resource_attrs.get("agent.id")
            or resource_attrs.get("service.instance.id")
            or "unknown"
        )
        tenant_id = resource_attrs.get("tenant.id")
        points: List[Dict[str, Any]] = []
        for sm in rm.get("scopeMetrics") or []:
            if not isinstance(sm, dict):
                continue
            for metric in sm.get("metrics") or []:
                if not isinstance(metric, dict):
                    continue
                name = metric.get("name")
                gauge = metric.get("gauge") if isinstance(metric.get("gauge"), dict) else {}
                for dp in gauge.get("dataPoints") or []:
                    if not isinstance(dp, dict):
                        continue
                    points.append(
                        {
                            "name": name,
                            "value": dp.get("asDouble", dp.get("asInt")),
                            "unit": metric.get("unit"),
                            "timeUnixNano": dp.get("timeUnixNano"),
                        }
                    )
                    count += 1
        if points:
            log_agent_event(
                agent_id=agent_id,
                event_type="metrics",
                category="observability",
                subcategory="otlp_metrics",
                level="info",
                data={"points": points, "otlp": True},
                tenant_id=str(tenant_id) if tenant_id else None,
            )
            save_execution_result_to_json(
                agent_id,
                {
                    "type": "otlp_metrics",
                    "tool": "otlp_metrics",
                    "tenant_id": tenant_id,
                    "points": points,
                },
            )
    return count


@router.post("/v1/logs")
@router.post("/otlp/v1/logs")
async def otlp_logs(request: Request) -> Response:
    payload = await _read_otlp_json(request)
    n = _ingest_logs(payload)
    logger.info("OTLP logs: %s record(s)", n)
    return Response(status_code=200)


@router.post("/v1/metrics")
@router.post("/otlp/v1/metrics")
async def otlp_metrics(request: Request) -> Response:
    payload = await _read_otlp_json(request)
    n = _ingest_metrics(payload)
    logger.info("OTLP metrics: %s data point(s)", n)
    return Response(status_code=200)
