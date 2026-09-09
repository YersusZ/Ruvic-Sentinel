"""Monitores Windows en segundo plano (RF-WIN-01..03, 06).

Off por defecto. En Linux no arrancan.
Eventos:
  windows.eventlog       — canales Event Log (incl. ETW-backed)
  windows.autorun_change — diff de autoruns
  windows.sysmon         — eventos Sysmon si el servicio existe
"""

from __future__ import annotations

import asyncio
import inspect
import platform
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from colsoft_tools.windows_collectors import (
    EVENT_CHANNELS,
    autoruns_fingerprint,
    event_severity,
    windows_autoruns,
    windows_event_log,
    windows_sysmon,
)

LogFn = Callable[..., None]
SinkFn = Callable[[Dict[str, Any]], Any]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _emit(sink: Optional[SinkFn], event: Dict[str, Any]) -> None:
    if sink is None:
        return
    result = sink(event)
    if inspect.isawaitable(result):
        await result


def _interval(value: Any, default: float) -> float:
    try:
        n = float(value)
    except (TypeError, ValueError):
        n = default
    return max(5.0, n)


# Script-block logging (PowerShell/Operational). En un host con PS activo
# llena OTLP y RobinLogs; 4103 y el resto del canal sí se emiten.
_DEFAULT_IGNORE_EVENT_IDS = frozenset({4104})


def _event_id_set(value: Any, *, default: Optional[frozenset] = None) -> set:
    if value is None:
        return set(default or ())
    out: set = set()
    if not isinstance(value, (list, tuple, set, frozenset)):
        value = [value]
    for item in value:
        try:
            out.add(int(str(item).strip()))
        except (TypeError, ValueError):
            continue
    return out


def _as_event_id(value: Any) -> Optional[int]:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _slim_watch_data(data: Any, *, max_keys: int = 12, max_val: int = 180) -> Optional[Dict[str, str]]:
    if not isinstance(data, dict) or not data:
        return None
    slim: Dict[str, str] = {}
    for i, (key, value) in enumerate(data.items()):
        if i >= max_keys:
            break
        slim[str(key)] = str(value)[:max_val]
    return slim or None


def _win_event(
    event_type: str,
    *,
    severity: str,
    tool: str,
    summary: str,
    **extra: Any,
) -> Dict[str, Any]:
    category = extra.pop("category", None) or (
        "security"
        if event_type in ("windows.autorun_change", "windows.sysmon")
        or str(severity).lower() in ("high", "critical")
        else "windows"
    )
    event: Dict[str, Any] = {
        "event_type": event_type,
        "category": category,
        "severity": severity,
        "tool": tool,
        "summary": summary,
        "ts": _now_iso(),
    }
    event.update({k: v for k, v in extra.items() if v is not None})
    return event


class EventLogWatcher:
    """RF-WIN-01/02: poll wevtutil XML; primer tick = baseline."""

    def __init__(
        self,
        channels: Optional[List[str]] = None,
        *,
        interval_seconds: float = 30.0,
        max_events_per_tick: int = 40,
        ignore_event_ids: Any = None,
        sink: Optional[SinkFn] = None,
        log: LogFn = lambda *a, **k: None,
    ):
        self.channels = [c for c in (channels or EVENT_CHANNELS) if c]
        self.interval_seconds = _interval(interval_seconds, 30.0)
        self.max_events_per_tick = max(1, int(max_events_per_tick or 40))
        self.ignore_event_ids = _event_id_set(
            ignore_event_ids, default=_DEFAULT_IGNORE_EVENT_IDS
        )
        self.sink = sink
        self.log = log
        self._seen: set = set()
        self._primed = False

    def tick(self) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        for channel in self.channels:
            rec = windows_event_log(channel, max_events=self.max_events_per_tick)
            for entry in rec.get("entries") or []:
                key = (
                    channel,
                    str(entry.get("record_id") or ""),
                    str(entry.get("event_id") or ""),
                    str(entry.get("ts") or ""),
                )
                if not self._primed:
                    self._seen.add(key)
                    continue
                if key in self._seen:
                    continue
                self._seen.add(key)
                eid = _as_event_id(entry.get("event_id"))
                if eid is not None and eid in self.ignore_event_ids:
                    continue
                sev = event_severity(entry)
                events.append(
                    _win_event(
                        "windows.eventlog",
                        severity=sev,
                        tool="windows_event_log",
                        summary=f"{channel} id={entry.get('event_id')} {entry.get('provider')}",
                        channel=channel,
                        event_id=entry.get("event_id"),
                        provider=entry.get("provider"),
                        level=entry.get("level"),
                        record_id=entry.get("record_id"),
                        computer=entry.get("computer"),
                        ts=entry.get("ts"),
                        event_data=_slim_watch_data(entry.get("data")),
                    )
                )
                if len(events) >= self.max_events_per_tick:
                    self._primed = True
                    return events
        self._primed = True
        if len(self._seen) > 8000:
            self._seen = set(list(self._seen)[-4000:])
        return events

    async def run_forever(self) -> None:
        self.log(
            f"windows event_log activo cada {self.interval_seconds:.0f}s "
            f"({len(self.channels)} canal(es), RF-WIN-01/02)"
        )
        while True:
            try:
                events = await asyncio.to_thread(self.tick)
                for event in events:
                    await _emit(self.sink, event)
                if events:
                    self.log(f"windows event_log: {len(events)} evento(s)")
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.log(f"windows event_log error: {e}")
            await asyncio.sleep(self.interval_seconds)


class AutorunWatcher:
    """RF-WIN-03: diff de autoruns (primer tick = baseline)."""

    def __init__(
        self,
        *,
        interval_seconds: float = 300.0,
        sink: Optional[SinkFn] = None,
        log: LogFn = lambda *a, **k: None,
    ):
        self.interval_seconds = _interval(interval_seconds, 300.0)
        self.sink = sink
        self.log = log
        self._seen: Optional[Dict[str, Dict[str, Any]]] = None

    def tick(self) -> List[Dict[str, Any]]:
        scan = windows_autoruns()
        current = autoruns_fingerprint(scan)
        if self._seen is None:
            self._seen = current
            return []
        events: List[Dict[str, Any]] = []
        added = set(current) - set(self._seen)
        removed = set(self._seen) - set(current)
        for key in sorted(added):
            rec = current[key]
            events.append(
                _win_event(
                    "windows.autorun_change",
                    severity="high",
                    tool="windows_autoruns",
                    summary=f"Autorun nuevo {rec.get('kind')}: {rec.get('name') or rec.get('path')}",
                    change="created",
                    path=rec.get("path"),
                    name=rec.get("name"),
                    command=rec.get("command"),
                )
            )
        for key in sorted(removed):
            rec = self._seen[key]
            events.append(
                _win_event(
                    "windows.autorun_change",
                    severity="medium",
                    tool="windows_autoruns",
                    summary=f"Autorun eliminado {rec.get('kind')}: {rec.get('name') or rec.get('path')}",
                    change="deleted",
                    path=rec.get("path"),
                    name=rec.get("name"),
                )
            )
        self._seen = current
        return events

    async def run_forever(self) -> None:
        self.log(f"windows autoruns activo cada {self.interval_seconds:.0f}s (RF-WIN-03)")
        while True:
            try:
                events = await asyncio.to_thread(self.tick)
                for event in events:
                    await _emit(self.sink, event)
                if events:
                    self.log(f"windows autoruns: {len(events)} cambio(s)")
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.log(f"windows autoruns error: {e}")
            await asyncio.sleep(self.interval_seconds)


class SysmonWatcher:
    """RF-WIN-06: si Sysmon no está, el loop no emite (opcional)."""

    def __init__(
        self,
        *,
        interval_seconds: float = 30.0,
        max_events_per_tick: int = 20,
        sink: Optional[SinkFn] = None,
        log: LogFn = lambda *a, **k: None,
    ):
        self.interval_seconds = _interval(interval_seconds, 30.0)
        self.max_events_per_tick = max(1, int(max_events_per_tick or 20))
        self.sink = sink
        self.log = log
        self._seen: set = set()
        self._primed = False
        self._missing_logged = False

    def tick(self) -> List[Dict[str, Any]]:
        snap = windows_sysmon(max_events=self.max_events_per_tick)
        if not snap.get("installed"):
            return []
        events: List[Dict[str, Any]] = []
        for entry in snap.get("entries") or []:
            key = (
                str(entry.get("record_id") or ""),
                str(entry.get("event_id") or ""),
                str(entry.get("ts") or ""),
            )
            if not self._primed:
                self._seen.add(key)
                continue
            if key in self._seen:
                continue
            self._seen.add(key)
            events.append(
                _win_event(
                    "windows.sysmon",
                    severity=event_severity(entry),
                    tool="windows_sysmon",
                    summary=f"Sysmon id={entry.get('event_id')} {entry.get('provider')}",
                    channel=entry.get("channel"),
                    event_id=entry.get("event_id"),
                    provider=entry.get("provider"),
                    ts=entry.get("ts"),
                    event_data=_slim_watch_data(entry.get("data")),
                )
            )
            if len(events) >= self.max_events_per_tick:
                break
        self._primed = True
        return events

    async def run_forever(self) -> None:
        self.log(f"windows sysmon activo cada {self.interval_seconds:.0f}s (RF-WIN-06, opcional)")
        while True:
            try:
                events = await asyncio.to_thread(self.tick)
                if not events and not self._primed and not self._missing_logged:
                    snap = await asyncio.to_thread(windows_sysmon, 1)
                    if not snap.get("installed"):
                        self.log("Sysmon no instalado; el watcher sigue en idle.")
                        self._missing_logged = True
                for event in events:
                    await _emit(self.sink, event)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.log(f"windows sysmon error: {e}")
            await asyncio.sleep(self.interval_seconds)


def spawn_win_tasks(
    config: Dict[str, Any],
    sink: SinkFn,
    log: LogFn = lambda *a, **k: None,
) -> List[asyncio.Task]:
    """Arranca monitores `windows.*` si el SO es Windows y están enabled."""
    tasks: List[asyncio.Task] = []
    if platform.system() != "Windows":
        return tasks
    block = config.get("windows") if isinstance(config.get("windows"), dict) else {}
    if not block:
        log("Monitores Windows inactivos (windows: {} o ausente).")
        return tasks

    ev_cfg = block.get("event_log") if isinstance(block.get("event_log"), dict) else {}
    if ev_cfg.get("enabled"):
        watcher = EventLogWatcher(
            ev_cfg.get("channels") or list(EVENT_CHANNELS),
            interval_seconds=ev_cfg.get("interval_seconds") or 30,
            max_events_per_tick=int(ev_cfg.get("max_events_per_tick") or 40),
            ignore_event_ids=ev_cfg.get("ignore_event_ids"),
            sink=sink,
            log=log,
        )
        tasks.append(asyncio.create_task(watcher.run_forever(), name="win_event_log"))

    au_cfg = block.get("autoruns") if isinstance(block.get("autoruns"), dict) else {}
    if au_cfg.get("enabled"):
        watcher = AutorunWatcher(
            interval_seconds=au_cfg.get("interval_seconds") or 300,
            sink=sink,
            log=log,
        )
        tasks.append(asyncio.create_task(watcher.run_forever(), name="win_autoruns"))

    sm_cfg = block.get("sysmon") if isinstance(block.get("sysmon"), dict) else {}
    if sm_cfg.get("enabled"):
        watcher = SysmonWatcher(
            interval_seconds=sm_cfg.get("interval_seconds") or 30,
            max_events_per_tick=int(sm_cfg.get("max_events_per_tick") or 20),
            sink=sink,
            log=log,
        )
        tasks.append(asyncio.create_task(watcher.run_forever(), name="win_sysmon"))

    if not tasks:
        log("Monitores Windows inactivos (event_log/autoruns/sysmon.enabled).")
    return tasks
