import asyncio
import datetime
import json
import logging
import os
from typing import Any, Dict, List, Optional

from fastapi import HTTPException, WebSocket

from command_queue import CommandQueue, TERMINAL_STATES
from colsoft_tools.protocol import (
    CMD_ACKED,
    CMD_COMPLETED,
    CMD_EXPIRED,
    CMD_FAILED,
    CMD_PENDING,
    CMD_REJECTED,
    CMD_RUNNING,
    CMD_SENT,
    STATUS_ERROR,
    STATUS_EXPIRED,
    STATUS_FAILED,
    STATUS_REJECTED,
    STATUS_RUNNING,
    STATUS_SUCCESS,
    TYPE_COMMAND_ACK,
    TYPE_COMMAND_RESPONSE,
    TYPE_HEARTBEAT,
    make_command_request,
    now_iso,
    resolve_command,
)
from colsoft_tools.security import (
    DEFAULT_DISABLED,
    RateLimiter,
    command_canonical,
    command_timeout,
    sign_command_ed25519,
)

# §8.6: traducción del `status` de command_response al estado del comando
RESP_TO_STATE = {
    STATUS_RUNNING: CMD_RUNNING,
    STATUS_SUCCESS: CMD_COMPLETED,
    STATUS_ERROR: CMD_FAILED,
    STATUS_FAILED: CMD_FAILED,
    STATUS_REJECTED: CMD_REJECTED,
    STATUS_EXPIRED: CMD_EXPIRED,
}

# Configuración de Logging
logging.basicConfig(
    level=logging.INFO,
    format="[server] %(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("agent-server")

# Llave de firma Ed25519 del backend (§8.2). El agente la conoce por el enrollment.
_signing_key_pem: Optional[str] = None


def _signing_key_path() -> Optional[str]:
    """Ruta actual de SERVER_SIGNING_KEY (se relee del entorno; no congelar al import)."""
    raw = (os.getenv("SERVER_SIGNING_KEY") or "").strip()
    return raw or None


def signing_key_status() -> Dict[str, Any]:
    """Diagnóstico para /health (sin exponer el PEM)."""
    path = _signing_key_path()
    if not path:
        return {
            "configured": False,
            "path": None,
            "readable": False,
            "loaded": False,
        }
    readable = os.path.isfile(path) and os.access(path, os.R_OK)
    return {
        "configured": True,
        "path": path,
        "readable": readable,
        "loaded": _signing_key_pem is not None,
    }


def _load_signing_key() -> Optional[str]:
    """Carga la llave privada de firma desde SERVER_SIGNING_KEY.

    Sin archivo persistente no se firma nada (fail-closed, §8.2). No se genera
    una llave efímera: los agentes enrollados rechazarían esos comandos.
    """
    global _signing_key_pem
    if _signing_key_pem is not None:
        return _signing_key_pem
    path = _signing_key_path()
    if path:
        try:
            with open(path, "r", encoding="utf-8") as f:
                pem = f.read()
            if not pem.strip():
                logger.error("SERVER_SIGNING_KEY apunta a un archivo vacío: %s", path)
                return None
            _signing_key_pem = pem
            logger.info("SERVER_SIGNING_KEY cargada desde %s", path)
            return _signing_key_pem
        except OSError as e:
            logger.error(
                "No se pudo leer SERVER_SIGNING_KEY (%s): %s", path, e
            )
            return None
    logger.error(
        "SERVER_SIGNING_KEY no configurado: no se despachan command_request "
        "(docs/produccion.md)."
    )
    return None


# Comandos Alto/Crítico habilitados explícitamente por política (§8.4/§8.5)
ALLOWED_HIGH_RISK: set = {
    c.strip()
    for c in os.getenv("ALLOW_HIGH_RISK_COMMANDS", "").split(",")
    if c.strip()
}


def backend_command_forbidden(resolved: str) -> bool:
    """True si el backend debe 403.

    Solo Alto/Crítico (`DEFAULT_DISABLED`) usan `ALLOW_HIGH_RISK_COMMANDS`.
    El control de servicios (`REQUIRES_ALLOWLIST`) lo aplica el agente con
    `policy.allowed_commands`, igual que §8.4-C — el manager no los bloquea
    con el mismo env var.
    """
    return resolved in DEFAULT_DISABLED and resolved not in ALLOWED_HIGH_RISK

# Rate limiting por agente y por tipo de comando (§8.5)
_rl_command = RateLimiter(
    limit=int(os.getenv("RATE_LIMIT_COMMAND_PER_MIN", "10")), window=60.0
)
_rl_agent = RateLimiter(
    limit=int(os.getenv("RATE_LIMIT_AGENT_PER_MIN", "30")), window=60.0
)

# Máximo silencio del agente (sin heartbeat) antes de marcar offline (~3× intervalo WS).
AGENT_LIVENESS_SECONDS = float(os.getenv("AGENT_LIVENESS_SECONDS", "90"))


def _parse_iso_timestamp(raw: str) -> Optional[datetime.datetime]:
    text = (raw or "").strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt
    except ValueError:
        return None


class ConnectionManager:

    def __init__(self):
        # Mapeo: agent_id -> WebSocket
        self.active_connections: Dict[str, WebSocket] = {}
        # Mapeo: agent_id -> Metadata del Agente
        self.agent_metadata: Dict[str, Dict[str, Any]] = {}
        # Mapeo: request_id -> Future
        self.pending_requests: Dict[str, asyncio.Future] = {}
        # §8.6: cola de comandos con estados y TTL (persistente)
        self.command_queue = CommandQueue()

    def register_connection(
        self,
        websocket: WebSocket,
        agent_id: str,
        *,
        client_name: str = "",
        public_key: Optional[str] = None,
        tenant_id: Optional[str] = None,
        remote_ip: Optional[str] = None,
    ) -> str:
        """Registra el socket con `agent_id` estable (§8.6). No genera un ID de sesión.

        Sin `agent_id` en el query el handshake de `controllers` asigna un fallback
        `{client_name}-{suffix}` antes de llamar aquí.
        """
        agent_id = (agent_id or "").strip()
        if not agent_id:
            raise ValueError("agent_id requerido (identidad estable §8.6)")
        ip = remote_ip or (
            websocket.client.host if websocket.client else "IP Desconocida"
        )
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.active_connections[agent_id] = websocket
        self.agent_metadata[agent_id] = {
            "client_name": client_name or "Desconocido",
            "remote_ip": ip,
            "connected_at": now_iso,
            "last_seen": now_iso,
            "public_key": public_key,
            "tenant_id": tenant_id or os.getenv("DEFAULT_TENANT_ID", ""),
        }
        logger.info("Agente registrado agent_id=%r (IP: %s)", agent_id, ip)
        return agent_id

    def disconnect(self, agent_id: str):
        """Limpia los diccionarios al desconectarse el agente."""
        if agent_id in self.active_connections:
            del self.active_connections[agent_id]
        if agent_id in self.agent_metadata:
            del self.agent_metadata[agent_id]
        logger.info(f"Agente eliminado de conexiones activas: {agent_id}")

    def _last_activity(self, agent_id: str) -> Optional[datetime.datetime]:
        meta = self.agent_metadata.get(agent_id) or {}
        for key in ("last_seen", "connected_at"):
            ts = _parse_iso_timestamp(str(meta.get(key) or ""))
            if ts is not None:
                return ts
        return None

    def is_agent_online(
        self,
        agent_id: str,
        *,
        now: Optional[datetime.datetime] = None,
    ) -> bool:
        """True si hay socket activo y heartbeat reciente (liveness §8.3)."""
        ws = self.active_connections.get(agent_id)
        if ws is None:
            return False
        try:
            from starlette.websockets import WebSocketState

            if ws.client_state != WebSocketState.CONNECTED:
                return False
        except Exception:
            pass
        last = self._last_activity(agent_id)
        if last is None:
            return True
        now = now or datetime.datetime.now(datetime.timezone.utc)
        age = (now - last.astimezone(datetime.timezone.utc)).total_seconds()
        return age <= AGENT_LIVENESS_SECONDS

    def prune_stale_connections(self) -> List[str]:
        """Elimina sesiones WS sin liveness reciente (TCP zombie / agente caído)."""
        removed: List[str] = []
        for agent_id in list(self.active_connections.keys()):
            if self.is_agent_online(agent_id):
                continue
            removed.append(agent_id)
            self.disconnect(agent_id)
        return removed

    def get_connected_agents(self) -> List[Dict[str, Any]]:
        agents = []
        for agent_id, meta in self.agent_metadata.items():
            if not self.is_agent_online(agent_id):
                continue
            pub_key = meta.get("public_key")
            agents.append(
                {
                    "agent_id": agent_id,
                    "client_name": meta.get("client_name", "Desconocido"),
                    "remote_ip": meta.get("remote_ip", "0.0.0.0"),
                    "connected_at": meta.get("connected_at", ""),
                    "last_seen": meta.get("last_seen") or meta.get("connected_at", ""),
                    "public_key_preview": (
                        pub_key[:30] + "..." if pub_key else None
                    ),
                    "tenant_id": meta.get("tenant_id", ""),
                }
            )
        return agents

    async def send_command_to_agent(
        self,
        agent_id: str,
        tool: str,
        params: Dict[str, Any],
        timeout: Optional[float] = None,
        issued_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        resolved = resolve_command(tool)

        # §8.5: Alto/Crítico (DEFAULT_DISABLED) exigen ALLOW_HIGH_RISK_COMMANDS.
        if backend_command_forbidden(resolved):
            raise HTTPException(
                status_code=403,
                detail=(
                    f"Comando '{tool}' deshabilitado por defecto en el backend. "
                    "Requiere política explícita (ALLOW_HIGH_RISK_COMMANDS)."
                ),
            )

        if not _load_signing_key():
            raise HTTPException(
                status_code=503,
                detail="SERVER_SIGNING_KEY no configurado; no se firman comandos (§8.2).",
            )

        # §8.5: rate limiting por agente y por tipo de comando
        if not _rl_agent.allow(f"agent:{agent_id}"):
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit excedido para el agente '{agent_id}'.",
            )
        if not _rl_command.allow(f"agent:{agent_id}:cmd:{resolved}"):
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit excedido para {resolved} en agente '{agent_id}'.",
            )

        # §8.5: timeout obligatorio. REST `timeout` es la espera HTTP;
        # si no viene, se usa el mismo cálculo que el agente (`params` incluidos).
        effective_timeout = (
            float(timeout)
            if timeout
            else command_timeout(resolved, params)
        )
        effective_timeout = min(
            max(effective_timeout, 5.0), 300.0
        )

        # §8.6: encolar el comando (idempotente por message_id, con TTL expires_at)
        record = self.command_queue.enqueue(
            agent_id,
            resolved,
            params,
            issued_by=issued_by or "api:user",
            timeout=effective_timeout,
        )
        message_id = record["message_id"]

        websocket = self.active_connections.get(agent_id)
        if websocket is None:
            # §8.6: agente offline → el comando queda en la cola (pending) y se
            # despacha cuando reconecte (si no expiró antes).
            logger.info(
                f"Agente {agent_id} offline: comando {tool} encolado "
                f"message_id={message_id} (se despachará al reconectar)"
            )
            return {
                "id": message_id,
                "ok": True,
                "queued": True,
                "tool": resolved,
                "state": CMD_PENDING,
                "result": None,
            }

        if not await self._dispatch_record(
            agent_id, record, register_future=True
        ):
            # El agente se desconectó entre el check y el send → vuelve a la cola
            return {
                "id": message_id,
                "ok": True,
                "queued": True,
                "tool": resolved,
                "state": CMD_PENDING,
                "result": None,
            }

        try:
            entry = self.pending_requests[message_id]
            response_data = await asyncio.wait_for(
                entry["future"], timeout=effective_timeout
            )
            return self._normalize_response(message_id, resolved, response_data)
        except asyncio.TimeoutError:
            # El comando sigue su ciclo en la cola (sent/acked/running); el
            # backend reporta el resultado cuando el agente responda.
            state = (
                self.command_queue.get(message_id) or {}
            ).get("state", CMD_SENT)
            logger.error(
                f"Timeout esperando respuesta de agent_id={agent_id} "
                f"message_id={message_id} (estado {state})"
            )
            raise HTTPException(
                status_code=504,
                detail=(
                    f"Timeout ({effective_timeout}s) esperando respuesta del agente "
                    f"'{agent_id}'; el comando sigue {state} en la cola "
                    f"(message_id={message_id})."
                ),
            )
        finally:
            self.pending_requests.pop(message_id, None)

    async def _dispatch_record(
        self,
        agent_id: str,
        record: Dict[str, Any],
        *,
        register_future: bool,
    ) -> bool:
        """Firma y envía un command_request desde un registro de la cola (§8.6).

        Con `register_future=True` (camino síncrono REST) registra un future para
        esperar la respuesta; en el re-despacho por reconexión no se registra
        (fire-and-forget: el estado lo actualiza el handler de respuestas).
        """
        websocket = self.active_connections.get(agent_id)
        if websocket is None:
            return False

        tool = record["tool"]
        params = record["params"]
        message_id = record["message_id"]
        issued_by = record.get("issued_by") or "api:user"
        issued_at = record["issued_at"]
        expires_at = record["expires_at"]

        # §8.2: firma Ed25519 del command_request
        signing_key = _load_signing_key()
        if not signing_key:
            logger.error(
                f"No se despacha message_id={message_id}: SERVER_SIGNING_KEY ausente"
            )
            return False
        canonical = command_canonical(
            message_id,
            agent_id,
            tool,
            params,
            issued_by,
            issued_at,
            expires_at,
        )
        signature = sign_command_ed25519(signing_key, canonical)

        # §8.3 command_request: Backend → Agente
        tenant_id = (self.agent_metadata.get(agent_id) or {}).get(
            "tenant_id"
        ) or os.getenv("DEFAULT_TENANT_ID", "")
        message = make_command_request(
            tool,
            params,
            agent_id=agent_id,
            tenant_id=tenant_id or None,
            message_id=message_id,
            issued_by=issued_by,
            issued_at=issued_at,
            expires_at=expires_at,
            signature=signature,
        )

        if register_future:
            loop = asyncio.get_running_loop()
            future = loop.create_future()
            self.pending_requests[message_id] = {
                "future": future,
                "tool": tool,
                "params": params,
            }

        try:
            await websocket.send_text(json.dumps(message))
        except Exception as e:
            logger.error(
                f"No se pudo enviar command_request message_id={message_id}: {e}"
            )
            if register_future:
                self.pending_requests.pop(message_id, None)
            return False

        attempts = int(record.get("attempts", 0)) + 1
        self.command_queue.mark(
            message_id, CMD_SENT, attempts=attempts, sent_at=now_iso()
        )
        logger.info(
            f"Comando firmado enviado a agent_id={agent_id} message_id={message_id} "
            f"command={tool} expires_at={expires_at}"
        )
        return True

    async def dispatch_pending(self, agent_id: str) -> None:
        """§8.6: al reconectar, despacha la cola pendiente del agente.

        Los comandos cuyo TTL (`expires_at`) ya pasó se descartan y reportan
        `expired` en vez de ejecutarse fuera de contexto. Los que ya estaban en
        `sent`/`acked`/`running` de una sesión previa no se reenvían (evita doble
        ejecución); se resuelven cuando el agente responda.
        """
        websocket = self.active_connections.get(agent_id)
        if websocket is None:
            return

        for record in self.command_queue.non_terminal_for(agent_id):
            if self.command_queue.is_record_expired(record):
                expired = self.command_queue.expire(record)
                logger.warning(
                    f"Comando {record['message_id']} de {agent_id} EXPIRADO en "
                    "cola (TTL superado); no se ejecutará fuera de contexto."
                )
                continue
            if record["state"] != CMD_PENDING:
                continue
            await self._dispatch_record(
                agent_id, record, register_future=False
            )

    def _normalize_response(
        self, message_id: str, tool: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Traduce un command_response (§8.3) al formato esperado por la REST API."""
        status = data.get("status")
        return {
            "id": message_id,
            "ok": status == STATUS_SUCCESS,
            "tool": tool,
            "result": data.get("result"),
            "error": data.get("error"),
            "status": status,
        }

    def handle_agent_message(self, agent_id: str, message_str: str):
        try:
            data = json.loads(message_str)
        except Exception as e:
            logger.error(f"Mensaje no JSON de {agent_id}: {e}")
            return None

        ptype = data.get("type")

        if ptype == TYPE_COMMAND_RESPONSE:
            # §8.3/§8.6 command_response: actualizar estado en la cola y resolver
            # el future pendiente (solo en estados terminales).
            req_id = str(data.get("message_id") or "")
            status = data.get("status")
            new_state = RESP_TO_STATE.get(status)

            if new_state:
                updates: Dict[str, Any] = {
                    "status": status,
                    "result": data.get("result"),
                    "error": data.get("error"),
                }
                if new_state in TERMINAL_STATES:
                    updates["completed_at"] = now_iso()
                self.command_queue.mark(req_id, new_state, **updates)

            entry = self.pending_requests.get(req_id)
            if (
                entry
                and not entry["future"].done()
                and new_state in TERMINAL_STATES
            ):
                entry["future"].set_result(data)
                self.pending_requests.pop(req_id, None)
        elif ptype == TYPE_COMMAND_ACK:
            # §8.6: sent → acked (el agente aceptó el comando, aún no termina)
            req_id = str(data.get("message_id") or "")
            self.command_queue.mark(req_id, CMD_ACKED)
        elif ptype == TYPE_HEARTBEAT:
            # §8.3 heartbeat: señal de liveness del agente
            meta = self.agent_metadata.get(agent_id)
            if meta:
                meta["last_seen"] = datetime.datetime.now(
                    datetime.timezone.utc
                ).isoformat()

        return data


manager = ConnectionManager()
