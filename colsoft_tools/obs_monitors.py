"""
Monitores de observabilidad en segundo plano (RF-OBS-02 / 03 / 07 / 09).

Corren desacoplados del hilo WebSocket, igual que el scheduler (RF-CORE-07):
los eventos se encolan en el `TelemetryBuffer` vía `sink` y salen por OTLP.

  - ProcessWatcher: creación/salida de procesos (no solo snapshot).
  - ServiceWatcher: altas/bajas y cambio de estado de servicios (RF-OBS-03).
  - HealthProbeLoop: health checks tcp/http/process configurables.
  - AlertEngine: umbrales locales sobre system_metrics (edge).

RF-OBS-10 (contenedores/K8s) queda fuera: fase posterior.
"""

from __future__ import annotations

import asyncio
import inspect
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from colsoft_tools.observability import (
    get_system_metrics,
    metric_from_snapshot,
    run_health_probes,
    snapshot_processes,
    snapshot_services,
)

LogFn = Callable[..., None]
SinkFn = Callable[[Dict[str, Any]], Any]

_OPS = {
    "gt": lambda v, t: v > t,
    "gte": lambda v, t: v >= t,
    "lt": lambda v, t: v < t,
    "lte": lambda v, t: v <= t,
    "eq": lambda v, t: v == t,
}

# Detecciones de borde: van también por el WS (event_push), no solo OTLP.
# Volumen (process.created/exited, linux.netlink socket_added) queda en el
# batch OTLP: un fork-bomb o /proc/net/tcp no debe saturar el plano de control.
_CONTROL_PLANE_TYPES = {
    "health.probe",
    "windows.autorun_change",
    "windows.sysmon",
    "linux.unit_change",
}


def is_control_plane_event(event: Dict[str, Any]) -> bool:
    et = str((event or {}).get("event_type") or "")
    sev = str((event or {}).get("severity") or "").lower()
    # RF-SEC-09: detecciones de seguridad van por event_push, no esperan el batch.
    # RF-WIN: autoruns/sysmon y Event Log high/critical también.
    return (
        et.startswith("alert.")
        or et.startswith("security.")
        or et in _CONTROL_PLANE_TYPES
        or (
            et == "windows.eventlog"
            and sev in ("high", "critical", "error")
        )
        or (
            et == "linux.audit"
            and sev in ("high", "critical", "error")
        )
        or (
            et == "linux.netlink"
            and str((event or {}).get("change") or "").startswith("iface_")
        )
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _emit(sink: SinkFn, event: Dict[str, Any]) -> None:
    result = sink(event)
    if inspect.isawaitable(result):
        await result


def _interval(value: Any, default: float, minimum: float = 1.0) -> float:
    try:
        n = float(value)
    except (TypeError, ValueError):
        n = default
    return max(minimum, n)


class ProcessWatcher:
    """Compara snapshots sucesivos y emite process.created / process.exited."""

    def __init__(
        self,
        *,
        interval_seconds: float = 5.0,
        max_events_per_tick: int = 40,
        sink: Optional[SinkFn] = None,
        log: LogFn = lambda *a, **k: None,
    ):
        self.interval_seconds = _interval(interval_seconds, 5.0)
        self.max_events_per_tick = max(1, int(max_events_per_tick or 40))
        self.sink = sink
        self.log = log
        self._seen: Optional[Dict[tuple, Dict[str, Any]]] = None

    def tick(
        self, current: Optional[Dict[tuple, Dict[str, Any]]] = None
    ) -> List[Dict[str, Any]]:
        if current is None:
            current = snapshot_processes()
        if self._seen is None:
            self._seen = current
            return []

        events: List[Dict[str, Any]] = []
        created_keys = current.keys() - self._seen.keys()
        exited_keys = self._seen.keys() - current.keys()

        for key in created_keys:
            if len(events) >= self.max_events_per_tick:
                break
            proc = current.get(key) or {}
            events.append(self._event("process.created", proc))

        for key in exited_keys:
            if len(events) >= self.max_events_per_tick:
                break
            proc = self._seen.get(key) or {}
            events.append(self._event("process.exited", proc))

        self._seen = current
        return events

    def _event(self, event_type: str, proc: Dict[str, Any]) -> Dict[str, Any]:
        ct = proc.get("create_time")
        create_iso = None
        if isinstance(ct, (int, float)) and ct:
            try:
                create_iso = datetime.fromtimestamp(ct, tz=timezone.utc).isoformat()
            except (OSError, OverflowError, ValueError):
                create_iso = None
        return {
            "event_type": event_type,
            "category": "observability",
            "severity": "info",
            "tool": "process_watch",
            "pid": proc.get("pid"),
            "ppid": proc.get("ppid"),
            "name": proc.get("name"),
            "username": proc.get("username"),
            "cmdline": proc.get("cmdline"),
            "create_time": create_iso,
            "ts": _now_iso(),
        }

    async def run_forever(self) -> None:
        self.log(
            f"process_watch activo cada {self.interval_seconds:.0f}s "
            f"(máx. {self.max_events_per_tick} eventos/tick)"
        )
        while True:
            try:
                events = await asyncio.to_thread(self.tick)
                for event in events:
                    await _emit(self.sink or (lambda e: None), event)
                if events:
                    self.log(f"process_watch: {len(events)} evento(s)")
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.log(f"process_watch error: {e}")
            await asyncio.sleep(self.interval_seconds)


class ServiceWatcher:
    """RF-OBS-03: diff de servicios/daemons (sc / systemctl / launchctl).

    Primer tick = baseline. Linux con `linux.systemd.enabled` también emite
    `linux.unit_change` (todas las unidades, RF-LIN-06); este watcher es el
    equivalente cross-OS y solo mira servicios.
    """

    def __init__(
        self,
        *,
        interval_seconds: float = 30.0,
        max_events_per_tick: int = 40,
        sink: Optional[SinkFn] = None,
        log: LogFn = lambda *a, **k: None,
    ):
        self.interval_seconds = _interval(interval_seconds, 30.0, minimum=5.0)
        self.max_events_per_tick = max(1, int(max_events_per_tick or 40))
        self.sink = sink
        self.log = log
        self._seen: Optional[Dict[str, Dict[str, Any]]] = None

    def tick(
        self, current: Optional[Dict[str, Dict[str, Any]]] = None
    ) -> List[Dict[str, Any]]:
        if current is None:
            current = snapshot_services()
        if self._seen is None:
            self._seen = current
            return []
        events: List[Dict[str, Any]] = []
        added = set(current) - set(self._seen)
        removed = set(self._seen) - set(current)
        for key in sorted(added):
            if len(events) >= self.max_events_per_tick:
                break
            item = current.get(key) or {}
            events.append(self._event("added", item, key))
        for key in sorted(removed):
            if len(events) >= self.max_events_per_tick:
                break
            item = self._seen.get(key) or {}
            events.append(self._event("removed", item, key))
        for key in sorted(set(current) & set(self._seen)):
            if len(events) >= self.max_events_per_tick:
                break
            old = self._seen.get(key) or {}
            new = current.get(key) or {}
            if (old.get("active"), old.get("sub")) == (new.get("active"), new.get("sub")):
                continue
            events.append(self._event("state", new, key, old=old))
        self._seen = current
        return events

    def _event(
        self,
        change: str,
        item: Dict[str, Any],
        key: str,
        *,
        old: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        unit = item.get("unit") or key
        if change == "state" and old:
            summary = (
                f"state {unit} {old.get('active')}/{old.get('sub')} → "
                f"{item.get('active')}/{item.get('sub')}"
            )
        else:
            summary = f"{change} {unit}"
        return {
            "event_type": "service.changed",
            "category": "observability",
            "severity": "info",
            "tool": "service_watch",
            "summary": summary,
            "change": change,
            "unit": unit,
            "active": item.get("active"),
            "sub": item.get("sub"),
            "ts": _now_iso(),
        }

    async def run_forever(self) -> None:
        self.log(
            f"service_watch activo cada {self.interval_seconds:.0f}s "
            f"(RF-OBS-03, máx. {self.max_events_per_tick} eventos/tick)"
        )
        while True:
            try:
                events = await asyncio.to_thread(self.tick)
                for event in events:
                    await _emit(self.sink or (lambda e: None), event)
                if events:
                    self.log(f"service_watch: {len(events)} evento(s)")
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.log(f"service_watch error: {e}")
            await asyncio.sleep(self.interval_seconds)


class HealthProbeLoop:
    """Ejecuta health_probes en ciclo y emite health.probe al cambiar de estado."""

    def __init__(
        self,
        checks: List[Any],
        *,
        interval_seconds: float = 60.0,
        emit_always: bool = False,
        sink: Optional[SinkFn] = None,
        log: LogFn = lambda *a, **k: None,
    ):
        self.checks = list(checks or [])
        self.interval_seconds = _interval(interval_seconds, 60.0)
        self.emit_always = bool(emit_always)
        self.sink = sink
        self.log = log
        self._last: Dict[str, str] = {}

    def tick(self, snapshot: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        result = snapshot if snapshot is not None else run_health_probes(self.checks)
        events: List[Dict[str, Any]] = []
        for rec in result.get("checks") or []:
            check_id = str(rec.get("id") or "")
            status = str(rec.get("status") or "DOWN")
            prev = self._last.get(check_id)
            changed = prev != status
            self._last[check_id] = status
            if not changed and not self.emit_always:
                continue
            severity = "info" if status == "UP" else "warning"
            events.append(
                {
                    "event_type": "health.probe",
                    "category": "observability",
                    "severity": severity,
                    "tool": "health_probes",
                    "check_id": check_id,
                    "check_type": rec.get("type"),
                    "status": status,
                    "changed": changed,
                    "result": rec,
                    "ts": _now_iso(),
                }
            )
        return events

    async def run_forever(self) -> None:
        self.log(
            f"health_probes activo cada {self.interval_seconds:.0f}s "
            f"({len(self.checks)} check(s))"
        )
        while True:
            try:
                events = await asyncio.to_thread(self.tick)
                for event in events:
                    await _emit(self.sink or (lambda e: None), event)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.log(f"health_probes error: {e}")
            await asyncio.sleep(self.interval_seconds)


class AlertEngine:
    """Evalúa umbrales locales sobre un snapshot de system_metrics."""

    def __init__(
        self,
        rules: Optional[List[Any]] = None,
        *,
        interval_seconds: float = 30.0,
        cooldown_seconds: float = 300.0,
        sink: Optional[SinkFn] = None,
        log: LogFn = lambda *a, **k: None,
    ):
        self.rules = [r for r in (rules or []) if isinstance(r, dict)]
        self.interval_seconds = _interval(interval_seconds, 30.0)
        self.cooldown_seconds = max(0.0, float(cooldown_seconds or 0))
        self.sink = sink
        self.log = log
        self._last_fire: Dict[str, float] = {}
        self._firing: Dict[str, bool] = {}

    def evaluate(self, metrics: Dict[str, Any], *, now: Optional[float] = None) -> List[Dict[str, Any]]:
        now = time.monotonic() if now is None else now
        events: List[Dict[str, Any]] = []
        for i, rule in enumerate(self.rules):
            rule_id = str(rule.get("id") or f"rule-{i}")
            path = str(rule.get("metric") or "")
            op_name = str(rule.get("op") or "gt").lower()
            op = _OPS.get(op_name)
            try:
                threshold = float(rule.get("threshold"))
            except (TypeError, ValueError):
                continue
            if op is None or not path:
                continue
            value = metric_from_snapshot(metrics, path)
            if value is None:
                continue
            firing = bool(op(value, threshold))
            was = self._firing.get(rule_id, False)
            severity = str(rule.get("severity") or "warning")
            if firing:
                last = self._last_fire.get(rule_id, 0.0)
                if (now - last) < self.cooldown_seconds and was:
                    continue
                self._last_fire[rule_id] = now
                self._firing[rule_id] = True
                events.append(
                    {
                        "event_type": "alert.threshold",
                        "category": "observability",
                        "severity": severity,
                        "tool": "alerts",
                        "rule_id": rule_id,
                        "metric": path,
                        "op": op_name,
                        "threshold": threshold,
                        "value": value,
                        "ts": _now_iso(),
                    }
                )
            elif was:
                self._firing[rule_id] = False
                events.append(
                    {
                        "event_type": "alert.cleared",
                        "category": "observability",
                        "severity": "info",
                        "tool": "alerts",
                        "rule_id": rule_id,
                        "metric": path,
                        "op": op_name,
                        "threshold": threshold,
                        "value": value,
                        "ts": _now_iso(),
                    }
                )
        return events

    async def run_forever(self) -> None:
        self.log(
            f"alerts activo cada {self.interval_seconds:.0f}s "
            f"({len(self.rules)} regla(s), cooldown {self.cooldown_seconds:.0f}s)"
        )
        while True:
            try:
                metrics = await asyncio.to_thread(get_system_metrics, 0.1)
                events = self.evaluate(metrics)
                for event in events:
                    await _emit(self.sink or (lambda e: None), event)
                if events:
                    self.log(f"alerts: {len(events)} evento(s)")
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.log(f"alerts error: {e}")
            await asyncio.sleep(self.interval_seconds)


def spawn_obs_tasks(
    config: Dict[str, Any],
    sink: SinkFn,
    log: LogFn = lambda *a, **k: None,
) -> List[asyncio.Task]:
    """Arranca los monitores habilitados en `config`. Devuelve tasks cancelables."""
    tasks: List[asyncio.Task] = []

    pw_cfg = config.get("process_watch") or {}
    if isinstance(pw_cfg, dict) and pw_cfg.get("enabled"):
        watcher = ProcessWatcher(
            interval_seconds=pw_cfg.get("interval_seconds") or 5,
            max_events_per_tick=int(pw_cfg.get("max_events_per_tick") or 40),
            sink=sink,
            log=log,
        )
        tasks.append(asyncio.create_task(watcher.run_forever(), name="process_watch"))

    sw_cfg = config.get("service_watch") or {}
    if isinstance(sw_cfg, dict) and sw_cfg.get("enabled"):
        watcher = ServiceWatcher(
            interval_seconds=sw_cfg.get("interval_seconds") or 30,
            max_events_per_tick=int(sw_cfg.get("max_events_per_tick") or 40),
            sink=sink,
            log=log,
        )
        tasks.append(asyncio.create_task(watcher.run_forever(), name="service_watch"))

    hp_cfg = config.get("health_probes") or {}
    checks = hp_cfg.get("checks") if isinstance(hp_cfg, dict) else None
    hp_enabled = True if not isinstance(hp_cfg, dict) else hp_cfg.get("enabled")
    if hp_enabled is None:
        hp_enabled = bool(isinstance(checks, list) and checks)
    if hp_enabled and isinstance(checks, list) and checks:
        loop = HealthProbeLoop(
            checks,
            interval_seconds=hp_cfg.get("interval_seconds") or 60,
            emit_always=bool(hp_cfg.get("emit_always")),
            sink=sink,
            log=log,
        )
        tasks.append(asyncio.create_task(loop.run_forever(), name="health_probes"))

    al_cfg = config.get("alerts") or {}
    rules = al_cfg.get("rules") if isinstance(al_cfg, dict) else None
    al_enabled = True if not isinstance(al_cfg, dict) else al_cfg.get("enabled")
    if al_enabled is None:
        al_enabled = bool(isinstance(rules, list) and rules)
    if al_enabled and isinstance(rules, list) and rules:
        engine = AlertEngine(
            rules,
            interval_seconds=al_cfg.get("interval_seconds") or 30,
            cooldown_seconds=al_cfg.get("cooldown_seconds") or 300,
            sink=sink,
            log=log,
        )
        tasks.append(asyncio.create_task(engine.run_forever(), name="alerts"))

    if not tasks:
        log(
            "Monitores de observabilidad inactivos "
            "(process_watch / service_watch / health_probes.enabled+checks / alerts.enabled+rules)."
        )
    return tasks
