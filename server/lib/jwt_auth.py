"""Validación de JWT de Robin (RS256) — integración externa.

Documentación: docs/produccion.md.

  - GET {ROBIN_API_URL}/auth/public-key  → llave pública PEM (cacheada 1h).
  - `Authorization: Bearer <jwt>` verificado con PyJWT (`algorithms=['RS256']`).
  - Claims exigidos: `exp`, `sub`, `modelBotId`, `roles`.
  - `alg` debe ser RS256 (rechaza `none` / HMAC). `type` debe ser `access`
    si está presente. `iss` solo si se define `ROBIN_JWT_ISSUER`.
  - `jti` se acepta si viene; no se exige ni se consulta la blacklist de
    logout de Robin (guía JWT §6: un validador externo no ve esa lista).
  - `roles` se exige como claim y **autoriza** `POST .../execute`:
    `ROBIN_JWT_EXECUTE_ROLES` (cualquier comando) y
    `ROBIN_JWT_HIGH_RISK_ROLES` (Alto/Crítico). `*` = cualquier rol.
    Sin esos roles → 403.
  - Nunca se usa la llave privada ni HS256/secreto compartido.

Activación por env: `ROBIN_JWT_REQUIRED=1` (default 0 → dev/E2E sin token).
Producción: `=1` + `ROBIN_JWT_ISSUER`.
"""

import os
import time
from typing import Any, Dict, Optional

import jwt
import requests
from fastapi import Header, HTTPException

_ROBIN_PEM: Optional[str] = None
_ROBIN_KID: Optional[str] = None
_ROBIN_FETCHED_AT: float = 0.0

# Cache de la llave pública (minutos/horas); solo se re-descarga si cambia el
# `kid` o falla la verificación (doc §1).
_PUBKEY_TTL_SECONDS = 3600


def _robin_api_url() -> str:
    return (os.getenv("ROBIN_API_URL") or "https://back.ruvic.xyz/api").rstrip("/")


def jwt_required_enabled() -> bool:
    """True si la API REST exige un JWT de Robin válido."""
    return os.getenv("ROBIN_JWT_REQUIRED", "0") == "1"


def get_public_key(*, force: bool = False) -> Optional[str]:
    """Descarga y cachea la llave pública RS256 de Robin (doc §1).

    Devuelve el PEM cacheado si la re-descarga falla (fail-open de disponibilidad;
    la verificación de firma sigue siendo estricta).
    """
    global _ROBIN_PEM, _ROBIN_KID, _ROBIN_FETCHED_AT

    if (
        _ROBIN_PEM
        and not force
        and (time.time() - _ROBIN_FETCHED_AT) < _PUBKEY_TTL_SECONDS
    ):
        return _ROBIN_PEM

    try:
        r = requests.get(f"{_robin_api_url()}/auth/public-key", timeout=10)
        r.raise_for_status()
        data = r.json()
        pem = data.get("public_key")
        if not pem:
            return _ROBIN_PEM
        _ROBIN_PEM = pem
        _ROBIN_KID = data.get("kid") or _ROBIN_KID
        _ROBIN_FETCHED_AT = time.time()
        return _ROBIN_PEM
    except Exception:
        return _ROBIN_PEM


def decode_robin_jwt(token: str) -> Dict[str, Any]:
    """Decodifica y valida un JWT de Robin. Lanza jwt.PyJWTError si es inválido.

    Firma: RS256 contra la llave pública de Robin (nunca HS256/secreto).
    """
    token = (token or "").strip()
    if not token:
        raise jwt.InvalidTokenError("token vacío")

    # Rechazar `alg: none` / HMAC explícitamente antes de verificar.
    try:
        headers = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError as e:
        raise jwt.InvalidTokenError(f"header inválido: {e}") from e

    alg = headers.get("alg")
    if alg != "RS256":
        raise jwt.InvalidTokenError(f"alg debe ser RS256, recibido {alg!r}")

    kid = headers.get("kid")
    pem = get_public_key()
    if pem is None:
        raise jwt.InvalidKeyError("no se pudo obtener la llave pública de Robin")

    # Kid cambió → la llave se rotó: re-descargar una vez y reintentar.
    if kid and _ROBIN_KID and kid != _ROBIN_KID:
        pem = get_public_key(force=True)
        if not pem:
            raise jwt.InvalidKeyError(
                f"kid={kid!r} no coincide y no se pudo refrescar la llave"
            )

    issuer = (os.getenv("ROBIN_JWT_ISSUER") or "").strip() or None

    def _verify(key: str) -> Dict[str, Any]:
        data = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            issuer=issuer,
            options={"require": ["exp", "sub", "modelBotId", "roles"]},
        )
        # doc §3: `type` debe ser 'access' cuando está presente.
        if data.get("type") and data.get("type") != "access":
            raise jwt.InvalidTokenError("claim 'type' != 'access'")
        return data

    try:
        return _verify(pem)
    except jwt.InvalidSignatureError:
        # doc §1: re-pedir la llave si falla la verificación (rotación sin kid).
        pem = get_public_key(force=True)
        if not pem:
            raise
        return _verify(pem)


def require_robin_jwt(
    authorization: Optional[str] = Header(default=None),
) -> Optional[Dict[str, Any]]:
    """FastAPI dependency: exige `Authorization: Bearer <JWT Robin>`.

    Con `ROBIN_JWT_REQUIRED=0` (default) no valida nada → dev/E2E sin token.
    Si igual llega un Bearer válido, se decodifica (GET usuario Ruvic / inventario).
    Con `=1`, devuelve 401 si falta el header o el token es inválido.
    `POST /execute` además exige roles (`jwt_can_issue_command`).
    """
    token = ""
    if authorization and authorization.startswith("Bearer "):
        token = authorization[len("Bearer "):].strip()

    if not jwt_required_enabled():
        if not token:
            return None
        try:
            claims = decode_robin_jwt(token)
            claims["_access_token"] = token
            return claims
        except Exception:
            return None

    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Missing token (header 'Authorization: Bearer <jwt>')",
        )
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401, detail="Authorization debe ser 'Bearer <jwt>'"
        )
    try:
        claims = decode_robin_jwt(token)
        claims["_access_token"] = token
        return claims
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")


def jwt_roles(user: Optional[Dict[str, Any]]) -> set:
    """Normaliza `roles` del JWT a un set lowercase."""
    if not user:
        return set()
    raw = user.get("roles")
    if isinstance(raw, str):
        items = [raw]
    elif isinstance(raw, (list, tuple, set)):
        items = list(raw)
    else:
        items = []
    return {str(r).strip().lower() for r in items if str(r).strip()}


def _roles_from_env(name: str, default: str) -> set:
    return {
        p.strip().lower()
        for p in (os.getenv(name) or default).split(",")
        if p.strip()
    }


def jwt_can_issue_command(
    user: Optional[Dict[str, Any]], tool: str
) -> bool:
    """RBAC mínimo §8.2: execute vs Alto/Crítico.

    Sin JWT (dev, ROBIN_JWT_REQUIRED=0) no se aplica. Roles por env:
    ROBIN_JWT_EXECUTE_ROLES (default admin,operator,analyst,soc,gestor)
    ROBIN_JWT_HIGH_RISK_ROLES (default admin,soc,operator)
    `*` en cualquiera = cualquier claim `roles` (lab).
    """
    if user is None:
        return True
    from colsoft_tools.protocol import resolve_command
    from colsoft_tools.security import DEFAULT_DISABLED

    roles = jwt_roles(user)
    execute_roles = _roles_from_env(
        "ROBIN_JWT_EXECUTE_ROLES", "admin,operator,analyst,soc,gestor"
    )
    if "*" not in execute_roles and not roles & execute_roles:
        return False
    resolved = resolve_command((tool or "").strip())
    if resolved in DEFAULT_DISABLED:
        high = _roles_from_env(
            "ROBIN_JWT_HIGH_RISK_ROLES", "admin,soc,operator"
        )
        if "*" in high:
            return True
        return bool(roles & high)
    return True


def issued_by_from_jwt(user: Optional[Dict[str, Any]]) -> str:
    """Valor `issued_by` del command_request (§8.3 / JWT_EXTERNAL_INTEGRATION §3).

    El claim `sub` es el user id de Robin. Sin JWT (dev) se usa `api:user`.
    """
    if not user:
        return "api:user"
    sub = user.get("sub")
    if sub:
        return f"user:{sub}"
    return "api:user"