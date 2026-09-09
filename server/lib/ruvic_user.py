"""Identidad Ruvic para el inventario: `user_id` / `client_id` salen del GET de logs.

Fuente: `GET https://logs.robin-ai.xyz/api/logs` (GET_LOGS.md). Cada documento
trae `userId` (dueño de la API key) y `agentId` (bot). El GET no incluye
email ni nombre.
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple

import requests

from lib.jwt_auth import _robin_api_url

logger = logging.getLogger("agent-server")

_CACHE: Dict[str, Tuple[float, Dict[str, str]]] = {}
_CACHE_TTL = 300.0

_EMPTY = {
    "user_id": "",
    "client_id": "",
}


def _user_url() -> str:
    explicit = (os.getenv("ROBIN_USER_URL") or "").strip()
    if explicit:
        return explicit.rstrip("/")
    path = (os.getenv("ROBIN_USER_PATH") or "/auth/me").strip() or "/auth/me"
    if not path.startswith("/"):
        path = "/" + path
    return f"{_robin_api_url()}{path}"


def _unwrap(payload: Any) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    for key in ("data", "user", "result"):
        inner = payload.get(key)
        if isinstance(inner, dict) and (
            inner.get("id")
            or inner.get("userId")
            or inner.get("clientId")
        ):
            return inner
    return payload


def _pick(data: Dict[str, Any], *keys: str) -> str:
    for key in keys:
        if "." in key:
            cur: Any = data
            ok = True
            for part in key.split("."):
                if not isinstance(cur, dict) or part not in cur:
                    ok = False
                    break
                cur = cur[part]
            if ok and cur is not None and str(cur).strip():
                return str(cur).strip()
            continue
        val = data.get(key)
        if val is not None and str(val).strip():
            return str(val).strip()
    return ""


def ids_from_payload(
    payload: Optional[Dict[str, Any]] = None,
    jwt_claims: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    """Normaliza user_id / client_id desde JSON de Ruvic o el JWT."""
    body = _unwrap(payload or {})
    claims = {
        k: v
        for k, v in (jwt_claims or {}).items()
        if k != "_access_token"
    }
    user_id = _pick(
        body,
        "userId",
        "user_id",
        "idUsuario",
        "id_usuario",
        "uid",
        "_id",
        "id",
        "sub",
    ) or _pick(claims, "sub", "userId", "user_id", "id")
    client_id = _pick(
        body,
        "clientId",
        "client_id",
        "idCliente",
        "id_cliente",
        "cliente.id",
        "client.id",
        "accountId",
        "account_id",
        "modelBotId",
        "model_bot_id",
    ) or _pick(claims, "modelBotId", "clientId", "client_id", "accountId")
    return {"user_id": user_id, "client_id": client_id}


def profile_from_payload(
    payload: Optional[Dict[str, Any]] = None,
    jwt_claims: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    """user_id y client_id (JWT /auth/me)."""
    ids = ids_from_payload(payload, jwt_claims)
    return {"user_id": ids["user_id"], "client_id": ids["client_id"]}


def profile_from_log(log: Optional[Dict[str, Any]]) -> Dict[str, str]:
    """Campos de un documento GET /api/logs (GET_LOGS.md)."""
    if not isinstance(log, dict):
        return dict(_EMPTY)
    meta = log.get("metadata") if isinstance(log.get("metadata"), dict) else {}
    data = meta.get("data") if isinstance(meta.get("data"), dict) else {}
    user_id = (
        _pick(log, "userId", "user_id")
        or _pick(data, "userId", "user_id")
    )
    client_id = (
        _pick(log, "clientId", "client_id")
        or _pick(data, "clientId", "client_id")
        or _pick(log, "agentId")
    )
    issued = str(data.get("issued_by") or "").strip()
    if not user_id and issued.startswith("user:"):
        user_id = issued.split(":", 1)[-1].strip()
    return {
        "user_id": user_id,
        "client_id": client_id,
    }


def _log_agent_id(log: Dict[str, Any]) -> str:
    meta = log.get("metadata") if isinstance(log.get("metadata"), dict) else {}
    data = meta.get("data") if isinstance(meta.get("data"), dict) else {}
    return str(data.get("agent_id") or "").strip()


def fetch_owner_from_logs(agent_id: Optional[str] = None) -> Dict[str, str]:
    """GET /api/logs → userId del dueño de la API key (y del agente si hay match)."""
    agent_id = (agent_id or "").strip()
    cache_key = f"logs:{agent_id or '_'}"
    now = time.time()
    hit = _CACHE.get(cache_key)
    if hit and (now - hit[0]) < _CACHE_TTL:
        return dict(hit[1])

    try:
        from lib.metrics_logger import LogsQueryError, fetch_logs
    except Exception as e:
        logger.warning("GET logs Ruvic no importable (%s)", e)
        return dict(_EMPTY)

    rows: list = []
    try:
        queries = []
        if agent_id:
            queries.append(
                {
                    "type": "activity",
                    "category": "system",
                    "subcategory": "agent_connected",
                    "page": 1,
                    "limit": 50,
                }
            )
        queries.append({"page": 1, "limit": 50})
        seen = False
        for params in queries:
            body = fetch_logs(params)
            chunk = body.get("data") if isinstance(body, dict) else None
            if isinstance(chunk, list):
                rows.extend(chunk)
                seen = True
            if rows:
                break
        if not seen:
            return dict(_EMPTY)
    except LogsQueryError as e:
        logger.warning("GET /api/logs Ruvic falló HTTP %s: %s", e.status_code, e.detail)
        return dict(_EMPTY)
    except Exception as e:
        logger.warning("GET /api/logs Ruvic no disponible (%s)", e)
        return dict(_EMPTY)

    chosen = None
    if agent_id:
        for log in rows:
            if isinstance(log, dict) and _log_agent_id(log) == agent_id:
                chosen = log
                break
    elif not agent_id:
        for log in rows:
            if isinstance(log, dict) and (
                log.get("userId") or log.get("user_id") or log.get("_id")
            ):
                chosen = log
                break
    profile = profile_from_log(chosen)
    if profile.get("user_id") or profile.get("client_id"):
        _CACHE[cache_key] = (now, profile)
    return dict(profile)


def fetch_ruvic_user(
    access_token: Optional[str],
    *,
    jwt_claims: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    """GET /auth/me (opcional). Cache 5 min por token. Nunca loguea el Bearer."""
    fallback = profile_from_payload(None, jwt_claims)
    token = (access_token or "").strip()
    if not token:
        return fallback

    cache_key = hashlib.sha256(token.encode("utf-8")).hexdigest()
    now = time.time()
    hit = _CACHE.get(cache_key)
    if hit and (now - hit[0]) < _CACHE_TTL:
        return dict(hit[1])

    url = _user_url()
    try:
        resp = requests.get(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            },
            timeout=10,
        )
        if resp.status_code >= 400:
            logger.warning(
                "GET usuario Ruvic falló HTTP %s en %s; se usan claims JWT.",
                resp.status_code,
                url,
            )
            _CACHE[cache_key] = (now, fallback)
            return fallback
        ids = profile_from_payload(resp.json(), jwt_claims)
        if not ids["user_id"] and not ids["client_id"]:
            ids = fallback
        _CACHE[cache_key] = (now, ids)
        return ids
    except Exception as e:
        logger.warning("GET usuario Ruvic no disponible (%s); se usan claims JWT.", e)
        return fallback


def _merge_profile(*parts: Dict[str, str]) -> Dict[str, str]:
    out = dict(_EMPTY)
    for part in parts:
        for key in _EMPTY:
            val = str((part or {}).get(key) or "").strip()
            if val and not out[key]:
                out[key] = val
    return out


def owner_ids_from_jwt(user: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """Dueño para GET /api/agents: claims del Bearer + /auth/me. No usa GET /api/logs.

    El listado de la plataforma debe filtrar por quien inició sesión, no por el
    userId de la API key del logger.

    ``user_id`` siempre toma ``sub`` del JWT cuando está presente: el inventario
    MySQL y OpenHands usan ese UUID; ``/auth/me`` puede devolver un ``id`` interno
    distinto.
    """
    if not isinstance(user, dict) or not user:
        return dict(_EMPTY)
    raw = user.get("_access_token")
    token = raw if isinstance(raw, str) else None
    ids = fetch_ruvic_user(token, jwt_claims=user)
    sub = str(user.get("sub") or "").strip()
    if sub:
        ids["user_id"] = sub
    return ids


def owner_ids_from_user(
    user: Optional[Dict[str, Any]] = None,
    *,
    agent_id: Optional[str] = None,
) -> Dict[str, str]:
    """Dueño para persistir: JWT > fila MySQL > GET /api/logs (solo si falta owner)."""
    if isinstance(user, dict) and str(user.get("sub") or "").strip():
        return owner_ids_from_jwt(user)
    aid = (agent_id or "").strip()
    if aid:
        try:
            from lib.agent_store import get_agent

            row = get_agent(aid) or {}
        except Exception:
            row = {}
        uid = str(row.get("user_id") or "").strip()
        if uid:
            return {
                "user_id": uid,
                "client_id": str(row.get("client_id") or "").strip(),
            }
        return fetch_owner_from_logs(aid)
    return dict(_EMPTY)


def user_id_candidates_for_jwt(
    user: Optional[Dict[str, Any]] = None,
    ids: Optional[Dict[str, str]] = None,
) -> List[str]:
    """IDs Robin en MySQL para filtrar listados: ``sub`` del JWT e ``id`` de /auth/me."""
    out: List[str] = []
    ids = ids or {}
    sub = str(ids.get("user_id") or "").strip()
    if isinstance(user, dict):
        sub = str(user.get("sub") or "").strip() or sub
    if sub and sub not in out:
        out.append(sub)
    if isinstance(user, dict):
        token = user.get("_access_token")
        if isinstance(token, str) and token.strip():
            profile = fetch_ruvic_user(token.strip(), jwt_claims=user)
            alt = (profile.get("user_id") or "").strip()
            if alt and alt not in out:
                out.append(alt)
    return out


def clear_owner_logs_cache(agent_id: Optional[str] = None) -> None:
    """Limpia cache de ``fetch_owner_from_logs`` (reintentos tras conectar agente)."""
    if agent_id:
        key = f"logs:{(agent_id or '').strip() or '_'}"
        _CACHE.pop(key, None)
        return
    for key in list(_CACHE.keys()):
        if key.startswith("logs:"):
            _CACHE.pop(key, None)


def reset_ruvic_user_cache() -> None:
    _CACHE.clear()
