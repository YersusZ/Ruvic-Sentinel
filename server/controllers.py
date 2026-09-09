import asyncio
import datetime
import json
import logging
import os
import uuid
from typing import Any, Dict, List, Optional

from fastapi import (
    APIRouter,
    Body,
    Depends,
    HTTPException,
    Query,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import JSONResponse

from colsoft_tools.data_plane import compact_event_for_otlp
from colsoft_tools.protocol import (
    CMD_PENDING,
    STATUS_RUNNING,
    STATUS_SUCCESS,
    TYPE_AUTH_ERROR,
    TYPE_COMMAND_ACK,
    TYPE_COMMAND_RESPONSE,
    TYPE_EVENT_PUSH,
    TYPE_HEARTBEAT,
    make_auth_ack,
    make_heartbeat,
    resolve_command,
)
from connection_manager import manager, signing_key_status
from command_queue import TERMINAL_STATES
from lib.jwt_auth import (
    issued_by_from_jwt,
    jwt_can_issue_command,
    jwt_required_enabled,
    require_robin_jwt,
)
from lib.agent_store import (
    apply_tool_snapshot,
    count_stored_agents,
    get_agent,
    list_agents as list_stored_agents,
    mysql_configured,
    needs_static_inventory,
    upsert_agent,
    upsert_user,
)
from lib.ruvic_user import (
    clear_owner_logs_cache,
    owner_ids_from_jwt,
    owner_ids_from_user,
    user_id_candidates_for_jwt,
)
from lib.metrics_logger import (
    LogsQueryError,
    fetch_logs,
    log_agent_event,
    log_event_push,
    log_tool_execution,
    logger_status,
    tool_target_summary,
)
from lib.cve_correlator import (
    correlate_packages,
    get_agent_findings,
    ingest_inventory,
    load_catalog,
    packages_from_result,
)
from models import AgentInfo, ToolExecutionRequest, ToolExecutionResponse
from save_result import save_execution_result_to_json
from colsoft_tools.security import verify_rsa_challenge

logger = logging.getLogger("agent-router")
router = APIRouter()


def _event_push_brief(event: Dict[str, Any]) -> str:
    """Resumen corto para el log del server (alertas / probes)."""
    parts = []
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
        "score",
        "channel",
        "event_id",
        "unit",
        "iface",
        "audit_type",
        "exe",
        "comm",
        "change",
    ):
        val = event.get(key)
        if val is not None:
            parts.append(f"{key}={val}")
    return " ".join(parts)


def _agents_list_unscoped() -> bool:
    return (os.getenv("AGENTS_LIST_UNSCOPED") or "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def _enforce_query_user_id(query_user_id: Optional[str], user: Any) -> None:
    q = (query_user_id or "").strip()
    if not q:
        return
    if not isinstance(user, dict):
        raise HTTPException(
            status_code=401,
            detail="user_id query requires authentication",
        )
    sub = str(user.get("sub") or "").strip()
    if not sub or q != sub:
        raise HTTPException(
            status_code=403,
            detail="user_id query must match JWT sub",
        )


def _list_has_owner_scope(ids: Dict[str, str], user: Any) -> bool:
    candidates = user_id_candidates_for_jwt(
        user if isinstance(user, dict) else None,
        ids,
    )
    client = (ids.get("client_id") or "").strip()
    return bool(candidates or client)


def _resolve_ws_agent_id(param_agent_id: str, client_name: str) -> str:
    """Usa el ``agent_id`` del enroll si el WS trae un id legacy/desactualizado."""
    param = (param_agent_id or "").strip()
    cname = (client_name or "").strip()
    if not param or get_agent(param) or not cname or not mysql_configured():
        return param
    matches = [
        row
        for row in list_stored_agents()
        if (row.get("client_name") or "").strip() == cname
        and str(row.get("agent_id") or "").startswith("agt_")
        and str(row.get("user_id") or "").strip()
    ]
    if len(matches) != 1:
        return param
    enrolled = str(matches[0].get("agent_id") or "").strip()
    if not enrolled or enrolled == param:
        return param
    logger.warning(
        "agent_id WS %r no está en inventario; usando enrollado %r "
        "(client_name=%r). Actualice enrollment/identity.json.",
        param,
        enrolled,
        cname,
    )
    return enrolled


def _bind_ruvic_owner(agent_id: str, user: Any, **fields: Any) -> None:
    """Persiste users + agents. user_id/client_id salen del GET a Ruvic."""
    try:
        ids = owner_ids_from_user(
            user if isinstance(user, dict) else None,
            agent_id=agent_id,
        )
        uid = (ids.get("user_id") or "").strip()
        if uid:
            upsert_user(
                uid,
                client_id=ids.get("client_id") or None,
            )
        upsert_agent(
            agent_id,
            user_id=uid or None,
            client_id=ids.get("client_id") or None,
            **fields,
        )
    except Exception as e:
        logger.warning("inventario de agente no se pudo guardar: %s", e)


async def _deferred_bind_ruvic_owner(
    agent_id: str,
    *,
    delays: tuple[float, ...] = (2.0, 5.0),
    **fields: Any,
) -> None:
    """Reintenta dueño tras indexar ``agent_connected`` en Robin Logs."""
    bind_fields = dict(fields)
    for delay in delays:
        await asyncio.sleep(delay)
        if not manager.is_agent_online(agent_id):
            return
        row = get_agent(agent_id) or {}
        if str(row.get("user_id") or "").strip():
            return
        clear_owner_logs_cache(agent_id)
        _bind_ruvic_owner(agent_id, None, **bind_fields)
        row = get_agent(agent_id) or {}
        if str(row.get("user_id") or "").strip() or str(
            row.get("client_id") or ""
        ).strip():
            return


def _agent_payload(
    stored: Dict[str, Any],
    *,
    live: Optional[Dict[str, Any]] = None,
    online: bool = False,
) -> Dict[str, Any]:
    live = live or {}
    uid = stored.get("user_id") or ""
    user = None
    if uid:
        user = {
            "user_id": uid,
            "client_id": stored.get("client_id") or "",
        }
    return {
        "agent_id": stored.get("agent_id") or live.get("agent_id"),
        "client_name": stored.get("client_name") or live.get("client_name") or "",
        "remote_ip": stored.get("remote_ip") or live.get("remote_ip") or "",
        "connected_at": live.get("connected_at") or stored.get("last_seen") or "",
        "public_key_preview": live.get("public_key_preview"),
        "tenant_id": stored.get("tenant_id") or live.get("tenant_id") or "",
        "user_id": uid,
        "client_id": stored.get("client_id") or "",
        "hostname": stored.get("hostname") or "",
        "os_name": stored.get("os_name") or "",
        "os_version": stored.get("os_version") or "",
        "arch": stored.get("arch") or "",
        "cpu_model": stored.get("cpu_model") or "",
        "cpu_logical_cores": stored.get("cpu_logical_cores"),
        "cpu_physical_cores": stored.get("cpu_physical_cores"),
        "cpu_freq_mhz": stored.get("cpu_freq_mhz"),
        "ram_total_gb": stored.get("ram_total_gb"),
        "disk_total_gb": stored.get("disk_total_gb"),
        "firmware_vendor": stored.get("firmware_vendor") or "",
        "firmware_product": stored.get("firmware_product") or "",
        "firmware_serial": stored.get("firmware_serial") or "",
        "firmware_uuid": stored.get("firmware_uuid") or "",
        "agent_version": stored.get("agent_version") or "",
        "inventory_captured_at": stored.get("inventory_captured_at") or "",
        "online": online,
        "first_seen": stored.get("first_seen"),
        "last_seen": live.get("last_seen") or stored.get("last_seen"),
        "user": user,
    }


async def _capture_static_inventory(agent_id: str) -> None:
    """Pide hardware_inventory + health_check al conectar (UPDATE del mismo agent_id)."""
    if not needs_static_inventory(agent_id):
        return
    try:
        await manager.send_command_to_agent(
            agent_id,
            "hardware_inventory",
            {},
            timeout=45.0,
            issued_by="api:inventory",
        )
    except Exception as e:
        logger.warning("inventario hardware %s: %s", agent_id, e)
    try:
        await manager.send_command_to_agent(
            agent_id,
            "health_check",
            {},
            timeout=20.0,
            issued_by="api:inventory",
        )
    except Exception as e:
        logger.warning("inventario health_check %s: %s", agent_id, e)

# Intervalo de heartbeat que envía el servidor (segundos). Ajustable por env.
SERVER_HEARTBEAT_INTERVAL = float(os.getenv("SERVER_HEARTBEAT_INTERVAL", "30"))


async def _server_heartbeat_loop(
    websocket: WebSocket, agent_id: str, interval: float
) -> None:
    """Envía heartbeats periódicos del servidor (§8.3: heartbeat en ambos sentidos).

    No se responde a los heartbeats del agente (evita loop de eco); cada lado
    envía los suyos de forma independiente.
    """
    while True:
        await asyncio.sleep(max(float(interval), 5.0))
        try:
            await websocket.send_text(json.dumps(make_heartbeat(agent_id)))
        except Exception:
            break


@router.get("/", include_in_schema=False)
@router.get("/health", summary="Healthcheck para orquestación (sin auth)")
async def health() -> Dict[str, Any]:
    pending = [
        r
        for r in manager.command_queue.list_all()
        if r.get("state") not in TERMINAL_STATES
    ]
    manager.prune_stale_connections()
    mysql_ready = False
    stored_agents = 0
    if mysql_configured():
        try:
            stored_agents = count_stored_agents()
            mysql_ready = True
        except Exception as e:
            logger.warning("health: inventario MySQL no accesible: %s", e)
    return {
        "status": "ok",
        "agents": len(manager.get_connected_agents()),
        "pending_commands": len(pending),
        "mysql_inventory": {
            "configured": mysql_configured(),
            "ready": mysql_ready,
            "stored_agents": stored_agents if mysql_ready else None,
        },
        "signing_key": signing_key_status(),
    }


async def wait_for_auth_response(
    websocket: WebSocket, timeout: float = 5.0
) -> Optional[Dict[str, Any]]:
    """Lee el socket hasta `auth_response`, ignorando heartbeat/event_push.

    El agente puede tener health_probes/alerts encolados y enviarlos en cuanto
    abre el WS; el primer frame no tiene por qué ser la firma del desafío.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + max(float(timeout), 0.1)
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise asyncio.TimeoutError()
        raw = await asyncio.wait_for(websocket.receive_text(), timeout=remaining)
        try:
            data = json.loads(raw)
        except ValueError:
            continue
        if isinstance(data, dict) and data.get("type") == "auth_response":
            return data


@router.websocket("/ws/colsoft-tools")
async def websocket_endpoint(websocket: WebSocket):
    client_ip = websocket.client.host if websocket.client else "127.0.0.1"

    # 1. Obtener parámetros iniciales
    param_agent_id = websocket.query_params.get("agent_id")
    client_name = (
        websocket.query_params.get("client_name") or f"Client_{client_ip}"
    )
    tenant_id = websocket.query_params.get("tenant_id")

    await websocket.accept()

    # 2. Desafío de autenticación
    challenge_str = uuid.uuid4().hex
    await websocket.send_text(
        json.dumps({"type": "auth_challenge", "challenge": challenge_str})
    )

    public_key_pem = None
    authenticated = False
    try:
        auth_data = await wait_for_auth_response(websocket, timeout=5.0)
        if auth_data:
            public_key_pem = auth_data.get("public_key")
            sig_b64 = auth_data.get("signature")
            # §8.2: el agente debe probar que posee la llave privada firmando el
            # desafío con RSA (PKCS1v15+SHA256) — verificación real en el backend.
            if public_key_pem and sig_b64:
                authenticated = verify_rsa_challenge(
                    public_key_pem, challenge_str.encode("utf-8"), sig_b64
                )
    except (asyncio.TimeoutError, Exception):
        authenticated = False

    if not authenticated:
        logger.warning(
            f"Autenticación FALLIDA (firma RSA del desafío inválida o ausente) "
            f"desde {client_ip} client_name={client_name!r}"
        )
        try:
            await websocket.send_text(
                json.dumps(
                    {
                        "type": TYPE_AUTH_ERROR,
                        "message": "Firma RSA del desafío inválida (autenticación rechazada).",
                    }
                )
            )
        except Exception:
            pass
        try:
            await websocket.close(code=1008)
        except Exception:
            pass
        return

    session_suffix = uuid.uuid4().hex[:6]
    clean_name = (client_name or "agente").strip().replace(" ", "-")

    if param_agent_id:
        # §8.6: identidad estable del agente (la que usa la cola de comandos).
        # Sin sufijo de sesión: persiste entre reconexiones.
        agent_id = _resolve_ws_agent_id(param_agent_id.strip(), client_name)
    else:
        # Backward compat: ID de sesión único por conexión
        agent_id = f"{clean_name}-{session_suffix}"

    # 4. Registrar con agent_id estable (§8.6). Sin query param: fallback de sesión.
    manager.register_connection(
        websocket,
        agent_id,
        client_name=client_name,
        public_key=public_key_pem,
        tenant_id=tenant_id or os.getenv("DEFAULT_TENANT_ID", ""),
        remote_ip=client_ip,
    )

    log_agent_event(
        agent_id=agent_id,
        event_type="activity",
        category="system",
        subcategory="agent_connected",
        level="info",
        data={"status": "online"},
        tenant_id=tenant_id,
    )

    logger.info(
        f"Agente registrado agent_id={agent_id} ({client_name} - IP: {client_ip})"
    )
    bind_fields = {
        "client_name": client_name,
        "tenant_id": tenant_id or os.getenv("DEFAULT_TENANT_ID", ""),
        "remote_ip": client_ip,
        "hostname": client_name,
    }
    _bind_ruvic_owner(agent_id, None, **bind_fields)
    asyncio.create_task(_deferred_bind_ruvic_owner(agent_id, **bind_fields))

    # 5. Confirmar sesión al agente (§8.3 auth_ack: Backend → Agente)
    await websocket.send_text(
        json.dumps(make_auth_ack(agent_id, tenant_id=tenant_id))
    )
    logger.info(f"auth_ack enviado a agent_id={agent_id}")

    # §8.6: despachar la cola pendiente del agente (comandos no expirados).
    # Los que superaron el TTL se reportan `expired` en vez de ejecutarse.
    await manager.dispatch_pending(agent_id)
    asyncio.create_task(_capture_static_inventory(agent_id))

    # Heartbeat periódico del servidor (§8.3 heartbeat, sin eco)
    heartbeat_task = asyncio.create_task(
        _server_heartbeat_loop(websocket, agent_id, SERVER_HEARTBEAT_INTERVAL)
    )

    try:
        while True:
            data_str = await websocket.receive_text()
            try:
                payload = json.loads(data_str)
            except json.JSONDecodeError:
                logger.error(
                    f"[SERVER ERROR] Mensaje no es JSON válido: {data_str[:100]}"
                )
                continue

            ptype = payload.get("type")

            if ptype == TYPE_COMMAND_RESPONSE:
                # §8.3 command_response: resolver el REST pendiente + auditar
                manager.handle_agent_message(agent_id, data_str)
                message_id = payload.get("message_id")
                status = payload.get("status", "unknown")
                # El tool se lee de la cola (§8.6), no de pending_requests (que
                # ya se eliminó al resolver el future) → evita guardar "unknown".
                queue_rec = manager.command_queue.get(str(message_id or ""))
                tool_name = (
                    queue_rec.get("tool") if queue_rec else None
                ) or "unknown"
                if status == STATUS_RUNNING:
                    continue
                ok = status in (STATUS_SUCCESS,)
                result = payload.get("result") or {}
                if ok and isinstance(result, dict) and resolve_command(tool_name) in (
                    "hardware_inventory",
                    "health_check",
                    "system_metrics",
                ):
                    try:
                        apply_tool_snapshot(agent_id, resolve_command(tool_name), result)
                        if resolve_command(tool_name) in (
                            "hardware_inventory",
                            "health_check",
                        ):
                            clear_owner_logs_cache(agent_id)
                            _bind_ruvic_owner(agent_id, None)
                    except Exception as e:
                        logger.warning(
                            "inventario estático %s tool=%s: %s",
                            agent_id,
                            tool_name,
                            e,
                        )
                result_summary = (
                    result.get("status", "COMPLETED")
                    if isinstance(result, dict)
                    else "COMPLETED"
                )
                compacted_result = None
                if isinstance(result, dict) and result:
                    compacted_result = compact_event_for_otlp(
                        {
                            "event_type": "telemetry.tool_result",
                            "tool": tool_name,
                            "result": result,
                        }
                    ).get("result")
                started = payload.get("started_at")
                completed = payload.get("completed_at")
                duration_ms = None
                if started and completed:
                    try:
                        duration_ms = round(
                            (
                                datetime.datetime.fromisoformat(completed)
                                - datetime.datetime.fromisoformat(started)
                            ).total_seconds()
                            * 1000
                        )
                    except (ValueError, TypeError):
                        duration_ms = None

                if ok and resolve_command(tool_name) in (
                    "cve_inventory",
                    "installed_software",
                    "linux_packages",
                ):
                    pkgs = packages_from_result(result)
                    if pkgs:
                        cve_rec = await asyncio.to_thread(
                            ingest_inventory,
                            agent_id,
                            pkgs,
                            tenant_id=payload.get("tenant_id") or tenant_id,
                        )
                        if cve_rec.get("count"):
                            log_agent_event(
                                agent_id=agent_id,
                                event_type="audit",
                                category="security",
                                subcategory="cve_match",
                                level="error" if cve_rec.get("score", 0) >= 50 else "warn",
                                data={
                                    "count": cve_rec.get("count"),
                                    "score": cve_rec.get("score"),
                                    "matches": (cve_rec.get("matches") or [])[:20],
                                },
                                tenant_id=payload.get("tenant_id") or tenant_id,
                            )

                log_tool_execution(
                    agent_id=agent_id,
                    tool=tool_name,
                    message_id=message_id,
                    command_status=status,
                    success=ok,
                    target=tool_target_summary(
                        tool_name, (queue_rec or {}).get("params") or {}
                    ),
                    result_summary=result_summary,
                    result=compacted_result,
                    error=payload.get("error"),
                    params=(queue_rec or {}).get("params") or {},
                    duration_ms=duration_ms,
                    tenant_id=tenant_id,
                    issued_by=(queue_rec or {}).get("issued_by"),
                )

                save_execution_result_to_json(
                    agent_id,
                    {
                        "type": TYPE_COMMAND_RESPONSE,
                        "message_id": message_id,
                        "tool": tool_name,
                        "ok": ok,
                        "status": status,
                        "result": result,
                        "error": payload.get("error"),
                        "payload": payload,
                    },
                )
                continue

            if ptype == TYPE_EVENT_PUSH:
                # §8.3 event_push: evento espontáneo del agente (detección/telemetría)
                event = payload.get("event") or {}
                et = event.get("event_type") or "event_push"
                logger.info(
                    "event_push agent=%s %s tool=%s %s",
                    agent_id,
                    et,
                    event.get("tool"),
                    _event_push_brief(event),
                )
                log_event_push(
                    agent_id=agent_id,
                    payload=payload,
                    tenant_id=payload.get("tenant_id") or tenant_id,
                )
                save_execution_result_to_json(
                    agent_id,
                    {
                        "type": TYPE_EVENT_PUSH,
                        "message_id": payload.get("message_id"),
                        "request_id": event.get("request_id"),
                        "tool": event.get("tool"),
                        "event_type": event.get("event_type"),
                        "event": event,
                    },
                )
                continue

            if ptype == TYPE_COMMAND_ACK:
                # §8.6 command_ack: sent → acked (el agente aceptó el comando)
                manager.handle_agent_message(agent_id, data_str)
                continue

            if ptype == TYPE_HEARTBEAT:
                # §8.3 heartbeat del agente (liveness): solo actualizar last_seen,
                # sin eco. El servidor envía sus propios heartbeats periódicos.
                manager.handle_agent_message(agent_id, data_str)
                continue

            if ptype in (None, "auth_response"):
                # Handshake / legacy: sin acción adicional
                continue

            logger.info(f"Mensaje tipo desconocido {ptype!r} de {agent_id}")

    except WebSocketDisconnect:
        heartbeat_task.cancel()
        log_agent_event(
            agent_id=agent_id,
            event_type="activity",
            category="system",
            subcategory="agent_disconnected",
            level="warn",
            data={"status": "offline"},
            tenant_id=tenant_id,
        )
        manager.disconnect(agent_id)
    except Exception as e:
        heartbeat_task.cancel()
        logger.error(f"Error en WebSocket {agent_id}: {e}")
        manager.disconnect(agent_id)


def _stored_agents_for_owner(
    ids: Dict[str, str],
    user: Any = None,
) -> List[Dict[str, Any]]:
    """Inventario MySQL visible para el JWT.

    Busca por ``sub``, id de /auth/me (si difiere) y ``client_id`` del token.
    """
    filter_client = (ids.get("client_id") or "").strip() or None
    candidates = user_id_candidates_for_jwt(
        user if isinstance(user, dict) else None,
        ids,
    )
    seen: set[str] = set()
    out: List[Dict[str, Any]] = []

    def _add(rows: List[Dict[str, Any]]) -> None:
        for row in rows:
            aid = row.get("agent_id") or ""
            if aid and aid not in seen:
                seen.add(aid)
                out.append(row)

    if candidates:
        for uid in candidates:
            _add(list_stored_agents(user_id=uid))
    if filter_client:
        _add(list_stored_agents(client_id=filter_client))
    if not candidates and not filter_client and _agents_list_unscoped():
        _add(list_stored_agents())
    return out


def _agent_owned_by(
    row: Dict[str, Any],
    ids: Dict[str, str],
    user: Any = None,
) -> bool:
    """True si la fila pertenece al dueño del JWT (user_id o client_id)."""
    if not row:
        return False
    filter_client = (ids.get("client_id") or "").strip()
    candidates = user_id_candidates_for_jwt(
        user if isinstance(user, dict) else None,
        ids,
    )
    row_user = str(row.get("user_id") or "").strip()
    row_client = str(row.get("client_id") or "").strip()
    if not candidates and not filter_client:
        return _agents_list_unscoped()
    if row_user and candidates and row_user in candidates:
        return True
    if filter_client and row_client == filter_client:
        return True
    return False


# --- Endpoints REST API ---


@router.get(
    "/api/agents",
    response_model=List[AgentInfo],
    summary="Listar agentes (inventario MySQL + sesión WS)",
)
async def list_agents(
    user_id: Optional[str] = Query(
        None,
        description="Debe coincidir con el sub del JWT autenticado",
    ),
    user: Any = Depends(require_robin_jwt),
):
    _enforce_query_user_id(user_id, user)
    ids = owner_ids_from_jwt(user if isinstance(user, dict) else None)
    scoped = _list_has_owner_scope(ids, user)
    unscoped = _agents_list_unscoped()
    manager.prune_stale_connections()
    stored = _stored_agents_for_owner(ids, user)
    live_by_id = {
        item["agent_id"]: item for item in manager.get_connected_agents()
    }
    seen = set()
    out: List[Dict[str, Any]] = []
    for row in stored:
        aid = row.get("agent_id") or ""
        seen.add(aid)
        out.append(
            _agent_payload(
                row,
                live=live_by_id.get(aid),
                online=manager.is_agent_online(aid),
            )
        )
    if unscoped and not scoped:
        for aid, live in live_by_id.items():
            if aid in seen:
                continue
            out.append(_agent_payload({}, live=live, online=True))
    elif scoped:
        for aid, live in live_by_id.items():
            if aid in seen:
                continue
            if not manager.is_agent_online(aid):
                continue
            row = get_agent(aid) or {}
            if not _agent_owned_by(row, ids, user):
                continue
            out.append(_agent_payload(row, live=live, online=True))
    elif not jwt_required_enabled() and user is None:
        for aid, live in live_by_id.items():
            if aid in seen:
                continue
            if not manager.is_agent_online(aid):
                continue
            row = get_agent(aid) or {}
            if str(row.get("user_id") or "").strip() or str(
                row.get("client_id") or ""
            ).strip():
                continue
            out.append(_agent_payload(row, live=live, online=True))
    return out


@router.get(
    "/api/agents/{agent_id}",
    response_model=AgentInfo,
    summary="Ficha estática de un agente",
)
async def get_agent_record(agent_id: str, user: Any = Depends(require_robin_jwt)):
    manager.prune_stale_connections()
    row = get_agent(agent_id)
    live_by_id = {
        item["agent_id"]: item for item in manager.get_connected_agents()
    }
    live = live_by_id.get(agent_id)
    if not row and not live:
        raise HTTPException(status_code=404, detail="Agente no encontrado")
    ids = owner_ids_from_jwt(user if isinstance(user, dict) else None)
    if _list_has_owner_scope(ids, user):
        if not _agent_owned_by(row or {}, ids, user):
            raise HTTPException(status_code=404, detail="Agente no encontrado")
    return _agent_payload(
        row or {},
        live=live,
        online=manager.is_agent_online(agent_id),
    )


_SO_LOG_TOOLS = frozenset(
    {
        "windows_event_log",
        "linux_syslog",
        "linux_auditd",
        "system_log",
    }
)


@router.post(
    "/api/agents/{agent_id}/execute",
    response_model=ToolExecutionResponse,
    summary="Ejecutar herramienta en un agente específico",
)
async def execute_agent_tool(
    agent_id: str,
    payload: ToolExecutionRequest = Body(...),
    user: Any = Depends(require_robin_jwt),
):
    if not jwt_can_issue_command(user, payload.tool):
        raise HTTPException(
            status_code=403,
            detail=(
                f"Rol JWT insuficiente para ejecutar {payload.tool!r} "
                "(ROBIN_JWT_EXECUTE_ROLES / ROBIN_JWT_HIGH_RISK_ROLES)."
            ),
        )
    resolved_tool = resolve_command(payload.tool)
    if resolved_tool in _SO_LOG_TOOLS:
        manager.prune_stale_connections()
        if not manager.is_agent_online(agent_id):
            raise HTTPException(
                status_code=409,
                detail=(
                    "Agente offline. Conecte el agente antes de pedir logs "
                    "del sistema operativo a demanda."
                ),
            )
    _bind_ruvic_owner(agent_id, user)
    response_data = await manager.send_command_to_agent(
        agent_id=agent_id,
        tool=payload.tool,
        params=payload.params,
        timeout=payload.timeout,
        issued_by=issued_by_from_jwt(user),
    )

    # §8.6: agente offline → el comando quedó en la cola (202, se despachará al
    # reconectar). El estado se consulta vía GET /api/commands/{message_id}.
    if response_data.get("queued"):
        return JSONResponse(
            status_code=202,
            content={
                "id": response_data.get("id"),
                "agent_id": agent_id,
                "ok": True,
                "queued": True,
                "tool": response_data.get("tool"),
                "state": response_data.get("state", CMD_PENDING),
                "message": (
                    "Agente offline: comando encolado; se despachará al reconectar "
                    "(si no expira antes)."
                ),
            },
        )

    return ToolExecutionResponse(
        id=response_data.get("id", "req-unknown"),
        agent_id=agent_id,
        ok=response_data.get("ok", False),
        tool=response_data.get("tool", payload.tool),
        result=response_data.get("result"),
        error=response_data.get("error"),
    )


@router.get(
    "/api/agents/{agent_id}/commands",
    response_model=List[dict],
    summary="Listar comandos del agente con su estado (§8.6)",
    dependencies=[Depends(require_robin_jwt)],
)
async def list_agent_commands(agent_id: str):
    return manager.command_queue.list_for_agent(agent_id)


@router.get(
    "/api/agents/{agent_id}/commands/{message_id}",
    response_model=dict,
    summary="Consultar estado de un comando específico (§8.6)",
    dependencies=[Depends(require_robin_jwt)],
)
async def get_command_status(agent_id: str, message_id: str):
    record = manager.command_queue.get(message_id)
    if record is None or record.get("agent_id") != agent_id:
        raise HTTPException(
            status_code=404,
            detail=f"No existe el comando '{message_id}' para el agente '{agent_id}'.",
        )
    return record


@router.get(
    "/api/commands",
    response_model=List[dict],
    summary="Listar todos los comandos de la cola (§8.6)",
    dependencies=[Depends(require_robin_jwt)],
)
async def list_all_commands():
    return manager.command_queue.list_all()


@router.get(
    "/api/commands/{message_id}",
    response_model=dict,
    summary="Consultar estado de un comando por message_id (§8.6)",
    dependencies=[Depends(require_robin_jwt)],
)
async def get_command_by_id(message_id: str):
    record = manager.command_queue.get(message_id)
    if record is None:
        raise HTTPException(
            status_code=404,
            detail=f"No existe el comando '{message_id}'.",
        )
    return record


@router.get(
    "/api/logs",
    summary="Consultar logs en RobinLogs (proxy de GET /api/logs)",
    dependencies=[Depends(require_robin_jwt)],
)
async def get_robin_logs(
    date: Optional[str] = Query(
        None,
        description="Un día UTC (YYYY-MM-DD). Sin horas: día entero. Con startHour/endHour/hour: se traduce a startDate/endDate.",
    ),
    startDate: Optional[str] = Query(
        None, description="Inicio de rango ISO 8601 (inclusive). Default: hace 30 días."
    ),
    endDate: Optional[str] = Query(
        None, description="Fin de rango ISO 8601 (inclusive). Default: ahora."
    ),
    startHour: Optional[str] = Query(
        None,
        description="Hora de inicio (HH o HH:MM, UTC) sobre date o startDate.",
    ),
    endHour: Optional[str] = Query(
        None,
        description="Hora de fin (HH o HH:MM, UTC). Con HH entero incluye esa hora.",
    ),
    hour: Optional[str] = Query(
        None, description="Una hora UTC (0-23 o HH:MM). Equivale a startHour=endHour."
    ),
    page: int = Query(1, ge=1, description="Página 1-based"),
    limit: int = Query(50, ge=1, le=100000, description="Tamaño de página (máx. 100000)"),
    per_page: Optional[int] = Query(
        None, ge=1, le=100000, description="Alias de limit; si ambos vienen, gana per_page"
    ),
    type: Optional[str] = Query(
        None, description="Filtro metadata.type (audit, activity, metrics, …)"
    ),
    category: Optional[str] = Query(
        None,
        description="Filtro metadata.category (network_check, observability, …)",
    ),
    subcategory: Optional[str] = Query(
        None,
        description="Filtro metadata.subcategory (nombre interno: system_log, ping, …)",
    ),
    level: Optional[str] = Query(
        None, description="debug|info|warn|error|fatal (warning se normaliza a warn)"
    ),
    agentId: Optional[str] = Query(
        None,
        description="Filtro por agentId de store (no data.agent_id de este agente)",
    ),
    source: Optional[str] = Query(None),
    tags: Optional[List[str]] = Query(None, description="Repetible; $in en tags"),
    search: Optional[str] = Query(None, description="Regex case-insensitive sobre message"),
    ip_dominio: Optional[str] = Query(None, description="metadata.data.ip_dominio"),
    servicio_afectado: Optional[str] = Query(
        None, description="metadata.data.servicio_afectado"
    ),
    userId: Optional[str] = Query(None, description="Admin only; alias user_id/targetUserId"),
    user_id: Optional[str] = Query(None, include_in_schema=False),
    targetUserId: Optional[str] = Query(None, include_in_schema=False),
):
    """Proxy autenticado a RobinLogs GET /api/logs.

    Auth hacia RobinLogs: ROBIN_LOGGER_API_KEY / ROBIN_LOGGER_JWT del server.
    Auth de esta API: JWT Robin si ROBIN_JWT_REQUIRED=1.
    """
    params: Dict[str, Any] = {
        "date": date,
        "startDate": startDate,
        "endDate": endDate,
        "startHour": startHour,
        "endHour": endHour,
        "hour": hour,
        "page": page,
        "limit": limit,
        "per_page": per_page,
        "type": type,
        "category": category,
        "subcategory": subcategory,
        "level": level,
        "agentId": agentId,
        "source": source,
        "tags": tags,
        "search": search,
        "ip_dominio": ip_dominio,
        "servicio_afectado": servicio_afectado,
        "userId": userId,
        "user_id": user_id,
        "targetUserId": targetUserId,
    }
    try:
        return await asyncio.to_thread(fetch_logs, params)
    except LogsQueryError as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail) from e


@router.get(
    "/api/execution-logs",
    response_model=List[dict],
    summary="Logs locales de ejecución de herramientas (results_logs/)",
    dependencies=[Depends(require_robin_jwt)],
)
async def get_all_execution_logs():
    logs = []
    for root, dirs, files in os.walk("results_logs"):
        for file in files:
            if file.endswith(".json"):
                log_path = os.path.join(root, file)
                with open(log_path, "r", encoding="utf-8") as f:
                    try:
                        log_data = json.load(f)
                        logs.append(log_data)
                    except json.JSONDecodeError:
                        logger.error(
                            f"[SERVER ERROR] No se pudo decodificar el archivo JSON: {log_path}"
                        )

    return logs


@router.get(
    "/api/cve/catalog",
    summary="Catálogo CVE local del motor de correlación (RF-SEC-05)",
    dependencies=[Depends(require_robin_jwt)],
)
async def cve_catalog():
    catalog = load_catalog()
    return {
        "count": len(catalog),
        "engine": "local-catalog",
        "cves": [
            {
                "cve": e.get("cve"),
                "product": e.get("product"),
                "severity": e.get("severity"),
                "cvss": e.get("cvss"),
                "summary": e.get("summary"),
            }
            for e in catalog
        ],
    }


@router.post(
    "/api/cve/correlate",
    summary="Cruzar inventario name+version contra el catálogo CVE (RF-SEC-05)",
    dependencies=[Depends(require_robin_jwt)],
)
async def cve_correlate(payload: Dict[str, Any] = Body(...)):
    packages = payload.get("packages") or []
    if not isinstance(packages, list):
        raise HTTPException(status_code=400, detail="packages debe ser una lista")
    agent_id = str(payload.get("agent_id") or "").strip()
    if agent_id:
        return await asyncio.to_thread(
            ingest_inventory,
            agent_id,
            packages,
            tenant_id=payload.get("tenant_id"),
        )
    return correlate_packages(packages)


@router.get(
    "/api/agents/{agent_id}/vulnerabilities",
    summary="Última correlación CVE del agente (RF-SEC-05)",
    dependencies=[Depends(require_robin_jwt)],
)
async def agent_vulnerabilities(agent_id: str):
    rec = get_agent_findings(agent_id)
    if rec is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Sin inventario CVE para '{agent_id}'. "
                "Ejecute cve_inventory o installed_software en el agente."
            ),
        )
    return rec


@router.get(
    "/api/system/logger-status",
    summary="Estado del logger RobinLogs y de la validación JWT",
    dependencies=[Depends(require_robin_jwt)],
)
async def system_logger_status():
    return {
        "logger": logger_status(),
        "jwt_required": jwt_required_enabled(),
        "robin_api_url": (
            os.getenv("ROBIN_API_URL") or "https://back.ruvic.xyz/api"
        ),
    }