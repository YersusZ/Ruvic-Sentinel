"""
Scheduler interno del agente — SRS §9 (RF-CORE-07).

Una sola clave de config: `scheduler` (`interval_seconds`, `tools`, `run_once`).
Alias deprecados: `scheduler.interval_minutes`, top-level `minute_interval` y
`tools_execution_interval`.

Corre en un bucle DESACOPLADO de la sesión WebSocket. Antes, `periodic_tools_loop`
vivía dentro de `client_session` y se cancelaba al desconectar; con este
scheduler las tareas siguen corriendo entre reconexiones y los resultados se
encolan en el `TelemetryBuffer` (RF-CORE-04) cuando no hay conexión.

El scheduler recibe un `sink` (función asíncrona que acepta el evento a
emitir). El cliente conecta el sink al buffer/WS según el estado de la sesión,
manteniendo el scheduler agnóstico del canal de transporte.
"""

import asyncio
import inspect
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

from colsoft_tools.data_plane import compact_event_for_otlp
from colsoft_tools.protocol import resolve_command
from colsoft_tools.security import CommandPolicy, command_timeout
from colsoft_tools.tool_catalog import tool_category


def _scheduler_block(config: Dict[str, Any]) -> Dict[str, Any]:
    raw = config.get("scheduler")
    return raw if isinstance(raw, dict) else {}


def items_from_config(config: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
    """Normaliza `scheduler.tools` (o el alias `tools_execution_interval`).

    Formatos aceptados:
      - lista de objetos {"tool", "params", "timeout"}
      - lista de strings (nombres de tool, sin params)
      - dict {tool: params} (backward compat)
    """
    sched = _scheduler_block(config)
    tools_config = sched["tools"] if "tools" in sched else config.get(
        "tools_execution_interval"
    )
    items: List[Tuple[str, Dict[str, Any]]] = []
    if isinstance(tools_config, list):
        for item in tools_config:
            if isinstance(item, dict):
                t_name = (item.get("tool") or "").strip()
                t_params = dict(item.get("params") or {})
                if item.get("timeout") is not None:
                    t_params["timeout"] = float(item["timeout"])
                if t_name:
                    items.append((t_name, t_params))
            elif isinstance(item, str):
                items.append((item.strip(), {}))
    elif isinstance(tools_config, dict):
        for t_name, t_params in tools_config.items():
            items.append(
                (t_name, t_params if isinstance(t_params, dict) else {})
            )
    return items


def interval_seconds(config: Dict[str, Any]) -> float:
    """Cadencia del scheduler (segundos). 0 = desactivado.

    Preferencia: `scheduler.interval_seconds`, luego `scheduler.interval_minutes`
    (×60, deprecado) y el alias top-level `minute_interval` (×60).
    """
    sched = _scheduler_block(config)
    raw = sched.get("interval_seconds")
    if raw is not None:
        try:
            return max(float(raw or 0), 0.0)
        except (TypeError, ValueError):
            return 0.0
    minutes = sched.get("interval_minutes")
    if minutes is None:
        minutes = config.get("minute_interval")
    try:
        return max(float(minutes or 0), 0.0) * 60.0
    except (TypeError, ValueError):
        return 0.0


class AgentScheduler:
    """Bucle periódico independiente del hilo WS.

    `execute` es una corrutina `(tool, params) -> dict` que ejecuta la tool.
    `sink` es una corrutina `(event: dict) -> None` que encola/emite el
    resultado (el cliente la conecta al TelemetryBuffer o al WS).
    """

    def __init__(
        self,
        config: Dict[str, Any],
        *,
        execute: Callable[[str, Dict[str, Any]], Any],
        sink: Callable[[Dict[str, Any]], Any],
        policy: CommandPolicy,
        config_file: Optional[str] = None,
        log: Callable[..., None] = lambda *a, **k: None,
    ):
        self.config = config
        self.execute = execute
        self.sink = sink
        self.policy = policy
        self.config_file = config_file
        self.log = log
        self._interval = interval_seconds(config)
        self._items = items_from_config(config)
        sched = _scheduler_block(config)
        self._run_once = bool(sched.get("run_once") or sched.get("once"))

    def enabled(self) -> bool:
        if not self._items:
            return False
        if self._run_once:
            return True
        return self._interval > 0

    def status(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled(),
            "interval_s": self._interval,
            "tools": len(self._items),
            "run_once": self._run_once,
        }

    async def run(self) -> None:
        """Ejecuta una pasada de las herramientas programadas (sin espera inicial)."""
        if not self.enabled():
            self.log("Ejecución periódica no configurada o desactivada.")
            return

        for raw_name, params in self._items:
            tool_name = resolve_command(raw_name)
            req_id = f"auto-{uuid.uuid4().hex[:10]}"
            allowed, pol_reason = self.policy.check(tool_name)
            if not allowed:
                self.log(
                    f"Ejecución programada RECHAZADA id={req_id} "
                    f"tool={raw_name!r}: {pol_reason}"
                )
                continue
            family = tool_category(tool_name)
            try:
                timeout = command_timeout(tool_name, params)
                result = await asyncio.wait_for(
                    self.execute(
                        tool_name,
                        params,
                        max_chars=int(self.config.get("max_chars") or 60000),
                        config=self.config,
                        config_file=self.config_file,
                    ),
                    timeout=timeout,
                )
                if isinstance(result, dict):
                    # Compacta para el buffer OTLP (muestra ~12), no el recorte
                    # agresivo del WS (~3): IOPS/FS se calculan después y
                    # necesitan totales, no las primeras 3 filas.
                    packed = compact_event_for_otlp(
                        {
                            "event_type": "telemetry.tool_result",
                            "category": family,
                            "severity": "info",
                            "scheduled": True,
                            "request_id": req_id,
                            "tool": tool_name,
                            "result": result,
                        }
                    )
                    inner = packed.get("result")
                    if isinstance(inner, dict):
                        result = inner
                    elif packed.get("error") == "payload_too_large":
                        result = {
                            "tool": tool_name,
                            "status": result.get("status") or "ERROR",
                            "truncated": True,
                            "error": "payload_too_large",
                        }
                event = {
                    "event_type": "telemetry.tool_result",
                    "category": family,
                    "severity": "info",
                    "scheduled": True,
                    "request_id": req_id,
                    "tool": tool_name,
                    "result": result,
                }
            except asyncio.TimeoutError:
                event = {
                    "event_type": "telemetry.tool_result",
                    "category": family,
                    "severity": "error",
                    "scheduled": True,
                    "request_id": req_id,
                    "tool": tool_name,
                    "error": f"Timeout ({timeout}s) excedido en el agente",
                }
            except Exception as e:
                event = {
                    "event_type": "telemetry.tool_result",
                    "category": family,
                    "severity": "error",
                    "scheduled": True,
                    "request_id": req_id,
                    "tool": tool_name,
                    "error": str(e),
                }
            try:
                await self._emit(event)
            except Exception:
                pass

    async def _emit(self, event: Dict[str, Any]) -> None:
        """Acepta sink sync o async (el cliente suele pasar TelemetryBuffer.put)."""
        result = self.sink(event)
        if inspect.isawaitable(result):
            await result

    async def run_forever(self) -> None:
        """Bucle infinito: espera `interval` y ejecuta una pasada."""
        if not self.enabled():
            self.log("Ejecución periódica no configurada o desactivada.")
            return
        if self._run_once:
            self.log(
                f"Scheduler run_once: {len(self._items)} herramienta(s), "
                "una pasada al arrancar."
            )
            await self.run()
            return
        self.log(
            f"Scheduler activo: {len(self._items)} herramienta(s) cada "
            f"{self._interval:.0f}s (desacoplado del WS, RF-CORE-07)."
        )
        while True:
            await asyncio.sleep(self._interval)
            await self.run()