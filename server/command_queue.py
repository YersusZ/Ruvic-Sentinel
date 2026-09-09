"""Cola de comandos pendientes del backend — SRS §8.6.

Implementa el ciclo de vida de los comandos (`pending → sent → acked → running
→ completed | failed | expired | rejected`) y una cola persistente con TTL
(`expires_at`): si el agente reconecta después del TTL, el comando se descarta
y se reporta `expired` en vez de ejecutarse fuera de contexto.

La cola es idempotente: reintentar con el mismo `message_id` devuelve el mismo
registro (dedup del lado servidor, §8.6).
"""

import datetime
import json
import logging
import os
import uuid
from typing import Any, Dict, List, Optional, Set

from colsoft_tools.protocol import (
    CMD_ACKED,
    CMD_COMPLETED,
    CMD_EXPIRED,
    CMD_FAILED,
    CMD_PENDING,
    CMD_REJECTED,
    CMD_RUNNING,
    CMD_SENT,
    is_expired,
    now_iso,
)

logger = logging.getLogger("agent-server")

# Estados terminales (§8.6): ya no se reenvían ni reintentan.
TERMINAL_STATES: Set[str] = {
    CMD_COMPLETED,
    CMD_FAILED,
    CMD_EXPIRED,
    CMD_REJECTED,
}

# TTL mínimo por defecto si no se especifica timeout (segundos).
DEFAULT_TTL_SECONDS = float(os.getenv("COMMAND_TTL_SECONDS", "30"))


class CommandQueue:
    """Registra y persiste el ciclo de vida de los comandos del plano de control.

    Cada comando se guarda en `results_logs/queue/<message_id>.json` para
    sobrevivir a reinicios del backend (los pendientes se re-despachan cuando el
    agente reconecta).
    """

    def __init__(self, persist_dir: Optional[str] = None):
        self._records: Dict[str, Dict[str, Any]] = {}
        self._by_agent: Dict[str, Set[str]] = {}
        self._persist_dir = persist_dir or os.path.join(
            "results_logs", "queue"
        )
        os.makedirs(self._persist_dir, exist_ok=True)
        self._load()

    # --- persistencia ---

    def _record_path(self, message_id: str) -> str:
        return os.path.join(self._persist_dir, f"{message_id}.json")

    def _load(self) -> None:
        for fname in os.listdir(self._persist_dir):
            if not fname.endswith(".json"):
                continue
            try:
                with open(
                    os.path.join(self._persist_dir, fname), "r", encoding="utf-8"
                ) as f:
                    record = json.load(f)
                self._records[record["message_id"]] = record
                self._by_agent.setdefault(record["agent_id"], set()).add(
                    record["message_id"]
                )
            except Exception as e:
                logger.error(f"No se pudo cargar registro de cola {fname}: {e}")

    def _persist(self, record: Dict[str, Any]) -> None:
        path = self._record_path(record["message_id"])
        tmp = f"{path}.tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(record, f, indent=2, ensure_ascii=False)
            os.replace(tmp, path)
        except OSError as e:
            logger.error(
                f"No se pudo persistir registro {record['message_id']}: {e}"
            )

    # --- API ---

    def enqueue(
        self,
        agent_id: str,
        tool: str,
        params: Dict[str, Any],
        *,
        issued_by: str,
        timeout: Optional[float] = None,
        message_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Crea (o devuelve) un registro de comando con estado `pending`.

        Idempotente por `message_id`: si el registro ya existe se devuelve tal
        cual (dedup de reintentos del backend, §8.6).
        """
        mid = message_id or str(uuid.uuid4())
        existing = self._records.get(mid)
        if existing is not None:
            return existing

        try:
            ttl = max(float(timeout), DEFAULT_TTL_SECONDS)
        except (TypeError, ValueError):
            ttl = DEFAULT_TTL_SECONDS
        expires_at = (
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(seconds=ttl)
        ).isoformat()

        record: Dict[str, Any] = {
            "message_id": mid,
            "agent_id": agent_id,
            "tool": tool,
            "params": params,
            "issued_by": issued_by,
            "issued_at": now_iso(),
            "expires_at": expires_at,
            "state": CMD_PENDING,
            "attempts": 0,
            "status": None,
            "result": None,
            "error": None,
            "started_at": None,
            "completed_at": None,
            "duration_ms": None,
            "sent_at": None,
        }
        self._records[mid] = record
        self._by_agent.setdefault(agent_id, set()).add(mid)
        self._persist(record)
        logger.info(
            f"[QUEUE] comandos encolado message_id={mid} agent={agent_id} "
            f"tool={tool} expires_at={expires_at}"
        )
        return record

    def get(self, message_id: str) -> Optional[Dict[str, Any]]:
        return self._records.get(message_id)

    def list_for_agent(self, agent_id: str) -> List[Dict[str, Any]]:
        mids = sorted(
            self._by_agent.get(agent_id, set()),
            key=lambda m: self._records[m]["issued_at"],
        )
        return [self._records[m] for m in mids if m in self._records]

    def list_all(self) -> List[Dict[str, Any]]:
        return list(self._records.values())

    def mark(
        self,
        message_id: str,
        state: str,
        **updates: Any,
    ) -> Optional[Dict[str, Any]]:
        """Transiciona el estado del registro y lo persiste (§8.6)."""
        record = self._records.get(message_id)
        if record is None:
            return None
        record["state"] = state
        record.update(updates)
        self._persist(record)
        logger.info(
            f"[QUEUE] estado message_id={message_id} → {state}"
            + (f" (agent={record['agent_id']})" if record.get("agent_id") else "")
        )
        return record

    def non_terminal_for(self, agent_id: str) -> List[Dict[str, Any]]:
        """Registros no terminales del agente (pending/sent/acked/running)."""
        return [
            rec
            for rec in self.list_for_agent(agent_id)
            if rec["state"] not in TERMINAL_STATES
        ]

    def is_record_expired(self, record: Dict[str, Any]) -> bool:
        return is_expired(record.get("expires_at"))

    def expire(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Marca `expired` (TTL superado) y reporta en vez de ejecutar (§8.6)."""
        return self.mark(
            record["message_id"],
            CMD_EXPIRED,
            status=CMD_EXPIRED,
            error="Comando expirado (expires_at superado)",
            completed_at=now_iso(),
        )
