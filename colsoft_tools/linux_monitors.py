"""Monitores Linux en segundo plano (RF-LIN-02, 05, 06).

Off por defecto. En Windows/macOS no arrancan.
Eventos:
  linux.audit          — auditd / audit.log
  linux.unit_change    — unidades/timers systemd: altas, bajas o cambio active/sub
  linux.netlink        — iface nueva o socket TCP nuevo
"""

from __future__ import annotations

import asyncio
import inspect
import platform
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from colsoft_tools.linux_collectors import (
    _net_sys_stats,
    _proc_tcp_sample,
    audit_severity,
    linux_auditd,
    linux_systemd_units,
    systemd_fingerprint,
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
    return max(1.0, n)


def _linux_event(
    event_type: str,
    *,
    severity: str,
    tool: str,
    summary: str,
    **extra: Any,
) -> Dict[str, Any]:
    category = extra.pop("category", None) or (
        # Persistencia (RF-LIN-06), igual que windows.autorun_change → security.
        # El comando on-demand linux_systemd_units sigue siendo familia `linux`.
        "security"
        if event_type == "linux.unit_change"
        or str(severity).lower() in ("high", "critical")
        else "linux"
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


class AuditdWatcher:
    """RF-LIN-02: poll audit.log / ausearch; primer tick = baseline."""

    def __init__(
        self,
        *,
        interval_seconds: float = 30.0,
        max_events_per_tick: int = 40,
        sink: Optional[SinkFn] = None,
        log: LogFn = lambda *a, **k: None,
    ):
        self.interval_seconds = _interval(interval_seconds, 30.0)
        self.max_events_per_tick = max(1, int(max_events_per_tick or 40))
        self.sink = sink
        self.log = log
        self._seen: set = set()
        self._primed = False

    def tick(self) -> List[Dict[str, Any]]:
        rec = linux_auditd(max_events=self.max_events_per_tick)
        events: List[Dict[str, Any]] = []
        for entry in rec.get("entries") or []:
            key = (
                str(entry.get("type") or ""),
                str(entry.get("pid") or ""),
                str(entry.get("ts") or ""),
                str(entry.get("msg") or "")[:80],
            )
            if not self._primed:
                self._seen.add(key)
                continue
            if key in self._seen:
                continue
            self._seen.add(key)
            sev = audit_severity(entry)
            events.append(
                _linux_event(
                    "linux.audit",
                    severity=sev,
                    tool="linux_auditd",
                    summary=f"{entry.get('type')} pid={entry.get('pid')} {entry.get('comm') or entry.get('exe')}",
                    audit_type=entry.get("type"),
                    pid=entry.get("pid"),
                    exe=entry.get("exe"),
                    comm=entry.get("comm"),
                    success=entry.get("success"),
                    ts=entry.get("ts"),
                )
            )
            if len(events) >= self.max_events_per_tick:
                break
        self._primed = True
        if len(self._seen) > 8000:
            self._seen = set(list(self._seen)[-4000:])
        return events

    async def run_forever(self) -> None:
        self.log(f"linux auditd activo cada {self.interval_seconds:.0f}s (RF-LIN-02)")
        while True:
            try:
                events = await asyncio.to_thread(self.tick)
                for event in events:
                    await _emit(self.sink, event)
                if events:
                    self.log(f"linux auditd: {len(events)} evento(s)")
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.log(f"linux auditd error: {e}")
            await asyncio.sleep(self.interval_seconds)


class SystemdUnitWatcher:
    """RF-LIN-06: diff de timers/unidades (primer tick = baseline)."""

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
        scan = linux_systemd_units()
        current = systemd_fingerprint(scan)
        if self._seen is None:
            self._seen = current
            self.log(
                f"linux systemd baseline: {len(current)} unidad(es)/timer(s); "
                "solo emite si aparece, desaparece o cambia active/sub"
            )
            return []
        events: List[Dict[str, Any]] = []
        added = current.keys() - self._seen.keys()
        removed = self._seen.keys() - current.keys()
        for key in list(added)[:40]:
            item = current.get(key) or {}
            events.append(
                _linux_event(
                    "linux.unit_change",
                    severity="medium",
                    tool="linux_systemd_units",
                    summary=f"added {key}",
                    change="added",
                    unit=item.get("unit") or key,
                    active=item.get("active"),
                    sub=item.get("sub"),
                )
            )
        for key in list(removed)[:40]:
            item = self._seen.get(key) or {}
            events.append(
                _linux_event(
                    "linux.unit_change",
                    severity="medium",
                    tool="linux_systemd_units",
                    summary=f"removed {key}",
                    change="removed",
                    unit=item.get("unit") or key,
                )
            )
        for key in current.keys() & self._seen.keys():
            old = self._seen.get(key) or {}
            new = current.get(key) or {}
            if (old.get("active"), old.get("sub")) == (new.get("active"), new.get("sub")):
                continue
            if "active" not in new and "sub" not in new:
                continue
            events.append(
                _linux_event(
                    "linux.unit_change",
                    severity="medium",
                    tool="linux_systemd_units",
                    summary=(
                        f"state {new.get('unit') or key} "
                        f"{old.get('active')}/{old.get('sub')} → "
                        f"{new.get('active')}/{new.get('sub')}"
                    ),
                    change="state",
                    unit=new.get("unit") or key,
                    active=new.get("active"),
                    sub=new.get("sub"),
                )
            )
            if len(events) >= 40:
                break
        self._seen = current
        return events

    async def run_forever(self) -> None:
        self.log(f"linux systemd activo cada {self.interval_seconds:.0f}s (RF-LIN-06)")
        while True:
            try:
                events = await asyncio.to_thread(self.tick)
                for event in events:
                    await _emit(self.sink, event)
                if events:
                    self.log(f"linux systemd: {len(events)} cambio(s)")
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.log(f"linux systemd error: {e}")
            await asyncio.sleep(self.interval_seconds)


class NetlinkWatcher:
    """RF-LIN-05: ifaces /sys y sockets /proc/net/tcp (poll)."""

    def __init__(
        self,
        *,
        interval_seconds: float = 15.0,
        max_events_per_tick: int = 40,
        sink: Optional[SinkFn] = None,
        log: LogFn = lambda *a, **k: None,
    ):
        self.interval_seconds = _interval(interval_seconds, 15.0)
        self.max_events_per_tick = max(1, int(max_events_per_tick or 40))
        self.sink = sink
        self.log = log
        self._ifaces: Optional[set] = None
        self._sockets: Optional[set] = None

    def tick(self) -> List[Dict[str, Any]]:
        try:
            ifaces = {row.get("iface") for row in _net_sys_stats(32) if row.get("iface")}
        except OSError:
            ifaces = set()
        try:
            socks = {
                f"{s.get('local')}-{s.get('remote')}-{s.get('inode')}"
                for s in _proc_tcp_sample(80)
            }
        except OSError:
            socks = set()
        events: List[Dict[str, Any]] = []
        if self._ifaces is None:
            self._ifaces = ifaces
            self._sockets = socks
            return []
        for name in ifaces - self._ifaces:
            events.append(
                _linux_event(
                    "linux.netlink",
                    severity="info",
                    tool="linux_netlink",
                    summary=f"iface up {name}",
                    change="iface_added",
                    iface=name,
                    category="linux",
                )
            )
        for name in self._ifaces - ifaces:
            events.append(
                _linux_event(
                    "linux.netlink",
                    severity="warning",
                    tool="linux_netlink",
                    summary=f"iface down {name}",
                    change="iface_removed",
                    iface=name,
                    category="linux",
                )
            )
        new_socks = socks - (self._sockets or set())
        for key in list(new_socks)[: self.max_events_per_tick]:
            events.append(
                _linux_event(
                    "linux.netlink",
                    severity="info",
                    tool="linux_netlink",
                    summary=f"tcp {key.split('-')[0]}",
                    change="socket_added",
                    socket=key[:120],
                    category="linux",
                )
            )
            if len(events) >= self.max_events_per_tick:
                break
        self._ifaces = ifaces
        self._sockets = socks
        return events

    async def run_forever(self) -> None:
        self.log(f"linux netlink activo cada {self.interval_seconds:.0f}s (RF-LIN-05)")
        while True:
            try:
                events = await asyncio.to_thread(self.tick)
                for event in events:
                    await _emit(self.sink, event)
                if events:
                    self.log(f"linux netlink: {len(events)} evento(s)")
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.log(f"linux netlink error: {e}")
            await asyncio.sleep(self.interval_seconds)


def spawn_linux_tasks(
    config: Dict[str, Any],
    sink: SinkFn,
    log: LogFn = lambda *a, **k: None,
) -> List[asyncio.Task]:
    """Arranca monitores `linux.*` si el SO es Linux y están enabled."""
    tasks: List[asyncio.Task] = []
    if platform.system() != "Linux":
        return tasks
    block = config.get("linux") if isinstance(config.get("linux"), dict) else {}
    if not block:
        log("Monitores Linux inactivos (linux: {} o ausente).")
        return tasks

    au_cfg = block.get("auditd") if isinstance(block.get("auditd"), dict) else {}
    if au_cfg.get("enabled"):
        watcher = AuditdWatcher(
            interval_seconds=au_cfg.get("interval_seconds") or 30,
            max_events_per_tick=int(au_cfg.get("max_events_per_tick") or 40),
            sink=sink,
            log=log,
        )
        tasks.append(asyncio.create_task(watcher.run_forever(), name="lin_auditd"))

    sd_cfg = block.get("systemd") if isinstance(block.get("systemd"), dict) else {}
    if sd_cfg.get("enabled"):
        watcher = SystemdUnitWatcher(
            interval_seconds=sd_cfg.get("interval_seconds") or 300,
            sink=sink,
            log=log,
        )
        tasks.append(asyncio.create_task(watcher.run_forever(), name="lin_systemd"))

    nl_cfg = block.get("netlink") if isinstance(block.get("netlink"), dict) else {}
    if nl_cfg.get("enabled"):
        watcher = NetlinkWatcher(
            interval_seconds=nl_cfg.get("interval_seconds") or 15,
            max_events_per_tick=int(nl_cfg.get("max_events_per_tick") or 40),
            sink=sink,
            log=log,
        )
        tasks.append(asyncio.create_task(watcher.run_forever(), name="lin_netlink"))

    if not tasks:
        log("Monitores Linux inactivos (auditd/systemd/netlink.enabled).")
    return tasks
