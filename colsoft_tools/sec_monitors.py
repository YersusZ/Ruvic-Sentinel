"""
Monitores de seguridad en segundo plano — SRS §11 (RF-SEC-01..10).

Corren desacoplados del hilo WebSocket (igual que `obs_monitors` / RF-CORE-07).
Las detecciones relevantes salen por `event_push` (RF-SEC-09) porque
`is_control_plane_event` trata `security.*` como plano de control.

RF-SEC-10: respuesta activa (`kill_process` / `block_ip` / `isolate_host`)
solo si `security.auto_response.enabled` y la política local §8.5 lo permite.
"""

from __future__ import annotations

import asyncio
import inspect
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from colsoft_tools.endpoint_security import (
    auth_audit,
    cis_score,
    cve_inventory,
    dns_monitor,
    fim_baseline_from_scan,
    fim_diff,
    fim_scan,
    match_detection_rules,
    persistence_fingerprint,
    persistence_scan,
    rootkit_check,
    _process_for_path,
)
from colsoft_tools.observability import snapshot_processes
from colsoft_tools.security import CommandPolicy

LogFn = Callable[..., None]
SinkFn = Callable[[Dict[str, Any]], Any]
ExecuteFn = Callable[..., Any]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _emit(sink: Optional[SinkFn], event: Dict[str, Any]) -> None:
    if sink is None:
        return
    result = sink(event)
    if inspect.isawaitable(result):
        await result


def _interval(value: Any, default: float, minimum: float = 1.0) -> float:
    try:
        n = float(value)
    except (TypeError, ValueError):
        n = default
    return max(minimum, n)


def _sec_block(config: Dict[str, Any]) -> Dict[str, Any]:
    raw = (config or {}).get("security")
    return raw if isinstance(raw, dict) else {}


def _sub(config: Dict[str, Any], key: str) -> Dict[str, Any]:
    raw = _sec_block(config).get(key)
    return raw if isinstance(raw, dict) else {}


def _sec_event(
    event_type: str,
    *,
    severity: str = "medium",
    tool: str,
    summary: str,
    **extra: Any,
) -> Dict[str, Any]:
    event: Dict[str, Any] = {
        "event_type": event_type,
        "category": "security",
        "severity": severity,
        "tool": tool,
        "summary": summary,
        "ts": _now_iso(),
    }
    event.update({k: v for k, v in extra.items() if v is not None})
    return event


class FimWatcher:
    """RF-SEC-01: compara hashes SHA-256 y atribuye usuario/proceso."""

    def __init__(
        self,
        paths: Optional[List[str]] = None,
        *,
        interval_seconds: float = 60.0,
        sink: Optional[SinkFn] = None,
        log: LogFn = lambda *a, **k: None,
    ):
        self.paths = list(paths or [])
        self.interval_seconds = _interval(interval_seconds, 60.0)
        self.sink = sink
        self.log = log
        self._baseline: Optional[Dict[str, Dict[str, Any]]] = None

    def tick(self, scan: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        scan = scan if scan is not None else fim_scan(
            self.paths or None, include_process=False
        )
        current = fim_baseline_from_scan(scan)
        if self._baseline is None:
            self._baseline = current
            return []
        diffs = fim_diff(self._baseline, current)
        self._baseline = current
        events: List[Dict[str, Any]] = []
        files_by_path = {
            rec.get("path"): rec for rec in (scan.get("files") or []) if rec.get("path")
        }
        for diff in diffs:
            rec = files_by_path.get(diff.get("path")) or {}
            process = rec.get("process") or _process_for_path(str(diff.get("path") or ""))
            events.append(
                _sec_event(
                    "security.fim_change",
                    severity="high",
                    tool="fim_scan",
                    summary=f"FIM {diff.get('change')}: {diff.get('path')}",
                    change=diff.get("change"),
                    path=diff.get("path"),
                    sha256=diff.get("sha256"),
                    prev_sha256=diff.get("prev_sha256"),
                    user=diff.get("user") or rec.get("user"),
                    uid=diff.get("uid") or rec.get("uid"),
                    process=process,
                    pid=(process or {}).get("pid") if isinstance(process, dict) else None,
                    name=(process or {}).get("name") if isinstance(process, dict) else None,
                )
            )
        return events

    async def run_forever(self) -> None:
        self.log(f"fim activo cada {self.interval_seconds:.0f}s (RF-SEC-01)")
        while True:
            try:
                events = await asyncio.to_thread(self.tick)
                for event in events:
                    await _emit(self.sink, event)
                if events:
                    self.log(f"fim: {len(events)} cambio(s)")
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.log(f"fim error: {e}")
            await asyncio.sleep(self.interval_seconds)


class PersistenceWatcher:
    """RF-SEC-02: nuevas/quitadas entradas de persistencia."""

    def __init__(
        self,
        *,
        interval_seconds: float = 120.0,
        sink: Optional[SinkFn] = None,
        log: LogFn = lambda *a, **k: None,
    ):
        self.interval_seconds = _interval(interval_seconds, 120.0)
        self.sink = sink
        self.log = log
        self._seen: Optional[Dict[str, Dict[str, Any]]] = None

    def tick(self, scan: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        scan = scan if scan is not None else persistence_scan()
        current = persistence_fingerprint(scan)
        if self._seen is None:
            self._seen = current
            return []
        events: List[Dict[str, Any]] = []
        added = set(current) - set(self._seen)
        removed = set(self._seen) - set(current)
        changed = [
            k
            for k in (set(current) & set(self._seen))
            if (current[k] or {}).get("sha256") != (self._seen[k] or {}).get("sha256")
        ]
        for key in sorted(added):
            rec = current[key]
            events.append(
                _sec_event(
                    "security.persistence_detected",
                    severity="high",
                    tool="persistence_scan",
                    summary=f"Nueva persistencia {rec.get('kind')}: {key}",
                    change="created",
                    kind=rec.get("kind"),
                    path=rec.get("path") or rec.get("name"),
                    sha256=rec.get("sha256"),
                    item=rec,
                )
            )
        for key in sorted(changed):
            rec = current[key]
            events.append(
                _sec_event(
                    "security.persistence_detected",
                    severity="high",
                    tool="persistence_scan",
                    summary=f"Persistencia modificada {rec.get('kind')}: {key}",
                    change="modified",
                    kind=rec.get("kind"),
                    path=rec.get("path") or rec.get("name"),
                    sha256=rec.get("sha256"),
                    item=rec,
                )
            )
        for key in sorted(removed):
            rec = self._seen[key]
            events.append(
                _sec_event(
                    "security.persistence_detected",
                    severity="medium",
                    tool="persistence_scan",
                    summary=f"Persistencia eliminada {rec.get('kind')}: {key}",
                    change="deleted",
                    kind=rec.get("kind"),
                    path=rec.get("path") or rec.get("name"),
                    item=rec,
                )
            )
        self._seen = current
        return events

    async def run_forever(self) -> None:
        self.log(
            f"persistence activo cada {self.interval_seconds:.0f}s (RF-SEC-02)"
        )
        while True:
            try:
                events = await asyncio.to_thread(self.tick)
                for event in events:
                    await _emit(self.sink, event)
                if events:
                    self.log(f"persistence: {len(events)} evento(s)")
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.log(f"persistence error: {e}")
            await asyncio.sleep(self.interval_seconds)


class AuthAuditLoop:
    """RF-SEC-03: emite logon/fallos/sudo nuevos (primer tick = baseline)."""

    def __init__(
        self,
        *,
        interval_seconds: float = 30.0,
        max_entries: int = 80,
        sink: Optional[SinkFn] = None,
        log: LogFn = lambda *a, **k: None,
    ):
        self.interval_seconds = _interval(interval_seconds, 30.0)
        self.max_entries = max(1, int(max_entries or 80))
        self.sink = sink
        self.log = log
        self._seen: set = set()
        self._primed = False

    def tick(self, snapshot: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        snap = snapshot if snapshot is not None else auth_audit(self.max_entries)
        events: List[Dict[str, Any]] = []
        current: set = set()
        for rec in snap.get("events") or []:
            key = (
                rec.get("action"),
                rec.get("user"),
                rec.get("message"),
            )
            current.add(key)
            if not self._primed:
                continue
            if key in self._seen:
                continue
            severity = str(rec.get("severity") or "medium")
            events.append(
                _sec_event(
                    "security.auth",
                    severity=severity,
                    tool="auth_audit",
                    summary=f"{rec.get('action')} user={rec.get('user')}",
                    action=rec.get("action"),
                    user=rec.get("user"),
                    mitre_technique=rec.get("mitre_technique"),
                    message=rec.get("message"),
                    source=rec.get("source"),
                )
            )
        self._seen = current
        self._primed = True
        return events

    async def run_forever(self) -> None:
        self.log(f"auth_audit activo cada {self.interval_seconds:.0f}s (RF-SEC-03)")
        while True:
            try:
                events = await asyncio.to_thread(self.tick)
                for event in events:
                    await _emit(self.sink, event)
                if events:
                    self.log(f"auth_audit: {len(events)} evento(s)")
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.log(f"auth_audit error: {e}")
            await asyncio.sleep(self.interval_seconds)


class DetectionEngine:
    """RF-SEC-04: reglas locales sobre procesos (PowerShell -enc, curl|sh, /tmp)."""

    def __init__(
        self,
        *,
        interval_seconds: float = 5.0,
        max_events_per_tick: int = 20,
        cooldown_seconds: float = 300.0,
        sink: Optional[SinkFn] = None,
        log: LogFn = lambda *a, **k: None,
        on_detection: Optional[Callable[[Dict[str, Any]], Any]] = None,
    ):
        self.interval_seconds = _interval(interval_seconds, 5.0)
        self.max_events_per_tick = max(1, int(max_events_per_tick or 20))
        self.cooldown_seconds = max(0.0, float(cooldown_seconds or 0))
        self.sink = sink
        self.log = log
        self.on_detection = on_detection
        self._last_fire: Dict[str, float] = {}

    def tick(
        self,
        processes: Optional[Dict[Any, Dict[str, Any]]] = None,
        *,
        now: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        now = time.monotonic() if now is None else now
        current = processes if processes is not None else snapshot_processes()
        events: List[Dict[str, Any]] = []
        for proc in (current or {}).values():
            if len(events) >= self.max_events_per_tick:
                break
            for hit in match_detection_rules(proc):
                key = f"{hit.get('rule_id')}:{hit.get('pid')}:{hit.get('cmdline')}"
                last = self._last_fire.get(key, 0.0)
                if (now - last) < self.cooldown_seconds:
                    continue
                self._last_fire[key] = now
                events.append(
                    _sec_event(
                        "security.detection",
                        severity=str(hit.get("severity") or "high"),
                        tool="detection_scan",
                        summary=str(hit.get("summary") or hit.get("name")),
                        rule_id=hit.get("rule_id"),
                        mitre_technique=hit.get("mitre_technique"),
                        technique=hit.get("mitre_technique"),
                        pid=hit.get("pid"),
                        ppid=hit.get("ppid"),
                        name=hit.get("process"),
                        process={
                            "pid": hit.get("pid"),
                            "name": hit.get("process"),
                            "command_line": hit.get("cmdline"),
                            "parent": hit.get("ppid"),
                        },
                        user=hit.get("user"),
                        cmdline=hit.get("cmdline"),
                        detection={
                            "rule_id": hit.get("rule_id"),
                            "mitre_technique": hit.get("mitre_technique"),
                        },
                    )
                )
                if len(events) >= self.max_events_per_tick:
                    break
        return events

    async def run_forever(self) -> None:
        self.log(
            f"detection activo cada {self.interval_seconds:.0f}s "
            f"(RF-SEC-04, máx. {self.max_events_per_tick}/tick)"
        )
        while True:
            try:
                events = await asyncio.to_thread(self.tick)
                for event in events:
                    await _emit(self.sink, event)
                    if self.on_detection:
                        result = self.on_detection(event)
                        if inspect.isawaitable(result):
                            await result
                if events:
                    self.log(f"detection: {len(events)} hallazgo(s)")
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.log(f"detection error: {e}")
            await asyncio.sleep(self.interval_seconds)


class DnsWatcher:
    """RF-SEC-07: nuevas consultas DNS (dominio y/o resolver) + proceso."""

    def __init__(
        self,
        *,
        interval_seconds: float = 15.0,
        sink: Optional[SinkFn] = None,
        log: LogFn = lambda *a, **k: None,
    ):
        self.interval_seconds = _interval(interval_seconds, 15.0)
        self.sink = sink
        self.log = log
        self._seen: Optional[set] = None

    def tick(self, snapshot: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        snap = snapshot if snapshot is not None else dns_monitor()
        current: set = set()
        events: List[Dict[str, Any]] = []
        for rec in snap.get("queries") or []:
            key = (
                rec.get("domain") or rec.get("resolver"),
                rec.get("pid"),
                rec.get("process"),
            )
            current.add(key)
            if self._seen is None or key in self._seen:
                continue
            domain = rec.get("domain") or rec.get("resolver")
            events.append(
                _sec_event(
                    "security.dns_query",
                    severity="low",
                    tool="dns_monitor",
                    summary=f"DNS {domain} pid={rec.get('pid')}",
                    domain=domain,
                    query=rec.get("domain"),
                    resolver=rec.get("resolver"),
                    pid=rec.get("pid"),
                    name=rec.get("process"),
                    user=rec.get("user"),
                    cmdline=rec.get("cmdline"),
                    process={
                        "pid": rec.get("pid"),
                        "name": rec.get("process"),
                        "command_line": rec.get("cmdline"),
                    },
                    network={"domain": rec.get("domain"), "dst": rec.get("resolver")},
                )
            )
        if self._seen is None:
            self._seen = current
            return []
        self._seen = current
        return events

    async def run_forever(self) -> None:
        self.log(f"dns_monitor activo cada {self.interval_seconds:.0f}s (RF-SEC-07)")
        while True:
            try:
                events = await asyncio.to_thread(self.tick)
                for event in events:
                    await _emit(self.sink, event)
                if events:
                    self.log(f"dns_monitor: {len(events)} consulta(s) nueva(s)")
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.log(f"dns_monitor error: {e}")
            await asyncio.sleep(self.interval_seconds)


class RootkitLoop:
    """RF-SEC-08: emite solo si hay hallazgos (no cada tick)."""

    def __init__(
        self,
        *,
        interval_seconds: float = 300.0,
        cooldown_seconds: float = 1800.0,
        sink: Optional[SinkFn] = None,
        log: LogFn = lambda *a, **k: None,
    ):
        self.interval_seconds = _interval(interval_seconds, 300.0, minimum=30.0)
        self.cooldown_seconds = max(0.0, float(cooldown_seconds or 0))
        self.sink = sink
        self.log = log
        self._last_fire: Dict[str, float] = {}

    def tick(
        self,
        snapshot: Optional[Dict[str, Any]] = None,
        *,
        now: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        now = time.monotonic() if now is None else now
        snap = snapshot if snapshot is not None else rootkit_check()
        events: List[Dict[str, Any]] = []
        for rec in snap.get("findings") or []:
            fid = str(rec.get("id") or rec.get("summary"))
            last = self._last_fire.get(fid, 0.0)
            if (now - last) < self.cooldown_seconds:
                continue
            self._last_fire[fid] = now
            events.append(
                _sec_event(
                    "security.rootkit_heuristic",
                    severity=str(rec.get("severity") or "high"),
                    tool="rootkit_check",
                    summary=str(rec.get("summary") or fid),
                    rule_id=fid,
                    finding=rec,
                    pids=rec.get("pids"),
                    path=(rec.get("paths") or [None])[0],
                )
            )
        return events

    async def run_forever(self) -> None:
        self.log(
            f"rootkit activo cada {self.interval_seconds:.0f}s (RF-SEC-08)"
        )
        while True:
            try:
                events = await asyncio.to_thread(self.tick)
                for event in events:
                    await _emit(self.sink, event)
                if events:
                    self.log(f"rootkit: {len(events)} hallazgo(s)")
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.log(f"rootkit error: {e}")
            await asyncio.sleep(self.interval_seconds)


class CisLoop:
    """RF-SEC-06: score periódico; event_push si el score cae bajo el umbral."""

    def __init__(
        self,
        *,
        interval_seconds: float = 3600.0,
        min_score: float = 70.0,
        sink: Optional[SinkFn] = None,
        log: LogFn = lambda *a, **k: None,
    ):
        self.interval_seconds = _interval(interval_seconds, 3600.0, minimum=60.0)
        self.min_score = float(min_score)
        self.sink = sink
        self.log = log
        self._last_score: Optional[float] = None

    def tick(self, snapshot: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        snap = snapshot if snapshot is not None else cis_score()
        score = snap.get("score")
        events: List[Dict[str, Any]] = []
        try:
            score_n = float(score)
        except (TypeError, ValueError):
            return events
        failed = [
            c for c in (snap.get("checks") or []) if isinstance(c, dict) and not c.get("passed")
        ]
        dropped = self._last_score is not None and score_n < self._last_score
        below = score_n < self.min_score
        if below or dropped:
            events.append(
                _sec_event(
                    "security.cis_finding",
                    severity="medium" if below else "low",
                    tool="cis_score",
                    summary=f"CIS score {score_n} (mín. {self.min_score})",
                    score=score_n,
                    findings_count=len(failed),
                    checks=failed[:20],
                )
            )
        self._last_score = score_n
        return events

    async def run_forever(self) -> None:
        self.log(f"cis_score activo cada {self.interval_seconds:.0f}s (RF-SEC-06)")
        while True:
            try:
                events = await asyncio.to_thread(self.tick)
                for event in events:
                    await _emit(self.sink, event)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.log(f"cis_score error: {e}")
            await asyncio.sleep(self.interval_seconds)


class CveInventoryLoop:
    """RF-SEC-05: emite el insumo de inventario para el motor CVE del backend."""

    def __init__(
        self,
        *,
        interval_seconds: float = 86400.0,
        sink: Optional[SinkFn] = None,
        log: LogFn = lambda *a, **k: None,
    ):
        self.interval_seconds = _interval(interval_seconds, 86400.0, minimum=300.0)
        self.sink = sink
        self.log = log

    def tick(self) -> Dict[str, Any]:
        inv = cve_inventory()
        return {
            "event_type": "telemetry.tool_result",
            "category": "security",
            "severity": "info",
            "scheduled": True,
            "tool": "cve_inventory",
            "result": inv,
            "ts": _now_iso(),
        }

    async def run_forever(self) -> None:
        self.log(
            f"cve_inventory activo cada {self.interval_seconds:.0f}s (RF-SEC-05 insumo)"
        )
        while True:
            try:
                event = await asyncio.to_thread(self.tick)
                await _emit(self.sink, event)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.log(f"cve_inventory error: {e}")
            await asyncio.sleep(self.interval_seconds)


class ActiveResponse:
    """RF-SEC-10: dispara remediación sujeta a CommandPolicy §8.5."""

    def __init__(
        self,
        config: Dict[str, Any],
        *,
        policy: CommandPolicy,
        execute: Optional[ExecuteFn] = None,
        sink: Optional[SinkFn] = None,
        log: LogFn = lambda *a, **k: None,
        config_file: Optional[str] = None,
    ):
        block = _sub(config, "auto_response")
        self.enabled = bool(block.get("enabled"))
        self.actions = [
            a for a in (block.get("actions") or []) if isinstance(a, dict)
        ]
        self.policy = policy
        self.execute = execute
        self.sink = sink
        self.log = log
        self.config = config
        self.config_file = config_file

    def action_for(self, rule_id: Optional[str]) -> Optional[Dict[str, Any]]:
        if not rule_id:
            return None
        for rec in self.actions:
            if str(rec.get("rule_id") or "") == str(rule_id):
                return rec
        return None

    def params_for(self, action: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
        params = dict(action.get("params") or {})
        cmd = str(action.get("command") or "")
        if cmd == "kill_process":
            params.setdefault("pid", event.get("pid"))
            params.setdefault("name", event.get("name"))
        if cmd == "block_ip":
            net = event.get("network") or {}
            params.setdefault("ip", params.get("ip") or net.get("dst") or event.get("resolver"))
            params.setdefault("direction", "output")
        if cmd == "isolate_host":
            params.setdefault("reason", event.get("summary") or event.get("rule_id"))
            if not params.get("manager_host"):
                from colsoft_tools.remediation import manager_host_from_config

                host = manager_host_from_config(self.config)
                if host:
                    params["manager_host"] = host
        return params

    async def maybe_respond(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self.enabled or not self.execute:
            return None
        action = self.action_for(event.get("rule_id"))
        if not action:
            return None
        cmd = str(action.get("command") or "").strip()
        if cmd not in ("kill_process", "block_ip", "isolate_host"):
            return None
        allowed, reason = self.policy.check(cmd)
        if not allowed:
            blocked = _sec_event(
                "security.response_blocked",
                severity="medium",
                tool=cmd,
                summary=f"Respuesta activa bloqueada por política: {cmd}",
                rule_id=event.get("rule_id"),
                action=cmd,
                error=reason,
            )
            await _emit(self.sink, blocked)
            self.log(f"auto_response RECHAZADA {cmd}: {reason}")
            return blocked
        params = self.params_for(action, event)
        try:
            result = self.execute(
                cmd,
                params,
                max_chars=int(self.config.get("max_chars") or 60000),
                config=self.config,
                config_file=self.config_file,
            )
            if inspect.isawaitable(result):
                result = await result
        except Exception as e:
            result = {"status": "ERROR", "error": str(e)}
        executed = _sec_event(
            "security.response_executed",
            severity="high",
            tool=cmd,
            summary=f"Respuesta activa {cmd} por {event.get('rule_id')}",
            rule_id=event.get("rule_id"),
            action=cmd,
            pid=event.get("pid"),
            name=event.get("name"),
            result=result,
        )
        await _emit(self.sink, executed)
        self.log(f"auto_response {cmd} rule={event.get('rule_id')} status={result.get('status')}")
        return executed


def spawn_sec_tasks(
    config: Dict[str, Any],
    sink: SinkFn,
    *,
    execute: Optional[ExecuteFn] = None,
    policy: Optional[CommandPolicy] = None,
    config_file: Optional[str] = None,
    log: LogFn = lambda *a, **k: None,
) -> List[asyncio.Task]:
    """Arranca los monitores `security.*` habilitados. Devuelve tasks cancelables."""
    tasks: List[asyncio.Task] = []
    sec = _sec_block(config)
    if not sec:
        log("Monitores de seguridad inactivos (security: {} o ausente).")
        return tasks

    responder = ActiveResponse(
        config,
        policy=policy or CommandPolicy(config),
        execute=execute,
        sink=sink,
        log=log,
        config_file=config_file,
    )

    fim_cfg = _sub(config, "fim")
    if fim_cfg.get("enabled"):
        watcher = FimWatcher(
            fim_cfg.get("paths") or [],
            interval_seconds=fim_cfg.get("interval_seconds") or 60,
            sink=sink,
            log=log,
        )
        tasks.append(asyncio.create_task(watcher.run_forever(), name="fim"))

    pers_cfg = _sub(config, "persistence")
    if pers_cfg.get("enabled"):
        watcher = PersistenceWatcher(
            interval_seconds=pers_cfg.get("interval_seconds") or 120,
            sink=sink,
            log=log,
        )
        tasks.append(
            asyncio.create_task(watcher.run_forever(), name="persistence")
        )

    auth_cfg = _sub(config, "auth_audit")
    if auth_cfg.get("enabled"):
        loop = AuthAuditLoop(
            interval_seconds=auth_cfg.get("interval_seconds") or 30,
            max_entries=int(auth_cfg.get("max_entries") or 80),
            sink=sink,
            log=log,
        )
        tasks.append(asyncio.create_task(loop.run_forever(), name="auth_audit"))

    det_cfg = _sub(config, "detection")
    if det_cfg.get("enabled"):
        engine = DetectionEngine(
            interval_seconds=det_cfg.get("interval_seconds") or 5,
            max_events_per_tick=int(det_cfg.get("max_events_per_tick") or 20),
            cooldown_seconds=det_cfg.get("cooldown_seconds") or 300,
            sink=sink,
            log=log,
            on_detection=responder.maybe_respond if responder.enabled else None,
        )
        tasks.append(
            asyncio.create_task(engine.run_forever(), name="detection")
        )

    dns_cfg = _sub(config, "dns")
    if dns_cfg.get("enabled"):
        watcher = DnsWatcher(
            interval_seconds=dns_cfg.get("interval_seconds") or 15,
            sink=sink,
            log=log,
        )
        tasks.append(asyncio.create_task(watcher.run_forever(), name="dns"))

    rk_cfg = _sub(config, "rootkit")
    if rk_cfg.get("enabled"):
        loop = RootkitLoop(
            interval_seconds=rk_cfg.get("interval_seconds") or 300,
            cooldown_seconds=rk_cfg.get("cooldown_seconds") or 1800,
            sink=sink,
            log=log,
        )
        tasks.append(asyncio.create_task(loop.run_forever(), name="rootkit"))

    cis_cfg = _sub(config, "cis")
    if cis_cfg.get("enabled"):
        loop = CisLoop(
            interval_seconds=cis_cfg.get("interval_seconds") or 3600,
            min_score=float(cis_cfg.get("min_score") or 70),
            sink=sink,
            log=log,
        )
        tasks.append(asyncio.create_task(loop.run_forever(), name="cis"))

    cve_cfg = _sub(config, "cve_inventory")
    if cve_cfg.get("enabled"):
        loop = CveInventoryLoop(
            interval_seconds=cve_cfg.get("interval_seconds") or 86400,
            sink=sink,
            log=log,
        )
        tasks.append(
            asyncio.create_task(loop.run_forever(), name="cve_inventory")
        )

    if not tasks:
        log(
            "Monitores de seguridad inactivos "
            "(security.fim/persistence/auth_audit/detection/dns/rootkit/cis)."
        )
    elif responder.enabled:
        log(
            f"auto_response activo ({len(responder.actions)} acción(es), RF-SEC-10)"
        )
    return tasks
