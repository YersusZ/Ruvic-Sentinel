"""
Enrollment server-side — SRS §9 (RF-CORE-01/02).

Endpoints:

  - ``POST /api/enrollment-tokens`` — JWT Robin → token de un solo uso ligado
    al ``sub`` del usuario; se anexa a ``ENROLLMENT_TOKENS_FILE`` (JSONL).
  - ``POST /enroll`` y ``POST /api/enroll`` — token + ``client_name`` → bundle
    de identidad persistente. Tokens emitidos por JWT atan ``user_id`` sin Bearer
    en el CLI del agente; líneas planas en el archivo = tokens legacy manuales.

Tokens de un solo uso; consumidos en ``enrollment_consumed.json``. Emitidos en
``enrollment_issued.json`` y, si ``ENROLLMENT_TOKENS_FILE`` está definido, en
JSONL (append automático al mint/consumo; se recargan al reiniciar el pod).
"""

import datetime
import json
import logging
import os
import secrets
import uuid
from typing import Any, Dict, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Request
from pydantic import BaseModel

logger = logging.getLogger("agent-server")

router = APIRouter()

# --- Configuración (env) ---
_ENROLL_DIR = os.getenv("ENROLL_DIR", "results_logs")
_CONSUMED_FILE = os.path.join(_ENROLL_DIR, "enrollment_consumed.json")
_ISSUED_FILE = os.path.join(_ENROLL_DIR, "enrollment_issued.json")
_ISSUED_TOKEN_PREFIX = "enr_"
_TOKEN_TTL_SECONDS = int(os.getenv("ENROLLMENT_TOKEN_TTL_SECONDS", "86400"))

CA_KEY_PATH = os.getenv(
    "ENROLLMENT_CA_KEY", os.path.join("certs", "server", "ca.key")
)
CA_CERT_PATH = os.getenv(
    "ENROLLMENT_CA_CERT", os.path.join("certs", "server", "ca.crt")
)
VALIDITY_DAYS = int(os.getenv("ENROLLMENT_VALIDITY_DAYS", "3650"))


class EnrollRequest(BaseModel):
    token: str
    client_name: str
    tenant_id: Optional[str] = None


class MintEnrollmentTokenResponse(BaseModel):
    token: str
    expires_at: str
    user_id: str
    client_id: str = ""


def _now_utc() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _iso(dt: datetime.datetime) -> str:
    return dt.astimezone(datetime.timezone.utc).isoformat()


def _atomic_write_json(path: str, payload: Any) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _load_issued_raw() -> Dict[str, Any]:
    try:
        with open(_ISSUED_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _purge_expired_issued(issued: Dict[str, Any]) -> Dict[str, Any]:
    now = _now_utc()
    kept: Dict[str, Any] = {}
    for token, meta in issued.items():
        if not isinstance(meta, dict):
            continue
        expires_raw = (meta.get("expires_at") or "").strip()
        if not expires_raw:
            kept[token] = meta
            continue
        try:
            expires_at = datetime.datetime.fromisoformat(
                expires_raw.replace("Z", "+00:00")
            )
        except ValueError:
            kept[token] = meta
            continue
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
        if expires_at >= now:
            kept[token] = meta
    return kept


def _load_issued() -> Dict[str, Any]:
    from_file = _load_issued_from_tokens_file()
    from_disk = _purge_expired_issued(_load_issued_raw())
    merged = {**from_file, **from_disk}
    return _purge_expired_issued(merged)


def _save_issued(issued: Dict[str, Any]) -> None:
    _atomic_write_json(_ISSUED_FILE, _purge_expired_issued(issued))


def _tokens_file_path() -> Optional[str]:
    """Ruta del archivo persistente (JSONL + líneas planas legacy)."""
    explicit = (os.getenv("ENROLLMENT_TOKENS_FILE") or "").strip()
    if explicit:
        return explicit
    persist = (os.getenv("ENROLLMENT_TOKENS_PERSIST") or "").strip().lower()
    if persist in ("1", "true", "yes", "on"):
        return os.path.join(_ENROLL_DIR, "enrollment_tokens.jsonl")
    return None


def _tokens_file_auto_append() -> bool:
    if not _tokens_file_path():
        return False
    raw = (os.getenv("ENROLLMENT_TOKENS_AUTO_APPEND") or "1").strip().lower()
    return raw not in ("0", "false", "no", "off")


def _append_tokens_file(record: Dict[str, Any]) -> None:
    path = _tokens_file_path()
    if not path or not _tokens_file_auto_append():
        return
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    line = json.dumps(record, ensure_ascii=False)
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")
        f.flush()
        os.fsync(f.fileno())


def _load_issued_from_tokens_file() -> Dict[str, Any]:
    path = _tokens_file_path()
    if not path or not os.path.isfile(path):
        return {}
    consumed = _load_consumed()
    issued: Dict[str, Any] = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#") or not line.startswith("{"):
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(rec, dict):
                    continue
                if rec.get("event") == "consumed":
                    continue
                tok = (rec.get("token") or "").strip()
                if not tok or tok in consumed:
                    continue
                issued[tok] = {
                    "user_id": str(rec.get("user_id") or "").strip(),
                    "client_id": str(rec.get("client_id") or "").strip(),
                    "created_at": str(rec.get("created_at") or "").strip(),
                    "expires_at": str(rec.get("expires_at") or "").strip(),
                }
    except OSError as e:
        logger.warning("no se pudo leer ENROLLMENT_TOKENS_FILE %s: %s", path, e)
        return {}
    return _purge_expired_issued(issued)


def init_enrollment_store() -> None:
    """Crea ENROLL_DIR y el archivo de tokens si está configurado."""
    os.makedirs(_ENROLL_DIR, exist_ok=True)
    path = _tokens_file_path()
    if not path:
        return
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    if not os.path.isfile(path):
        with open(path, "a", encoding="utf-8"):
            pass
        logger.info("Archivo de tokens de enrollment creado: %s", path)


def _issued_owner(token: str) -> Optional[Dict[str, str]]:
    meta = _load_issued().get(token)
    if not isinstance(meta, dict):
        return None
    return {
        "user_id": str(meta.get("user_id") or "").strip(),
        "client_id": str(meta.get("client_id") or "").strip(),
    }


def _load_static_tokens() -> set:
    raw = os.getenv("ENROLLMENT_TOKENS", "")
    tokens = {t.strip() for t in raw.split(",") if t.strip()}
    tokens_file = _tokens_file_path()
    if tokens_file and os.path.isfile(tokens_file):
        try:
            with open(tokens_file, "r", encoding="utf-8") as f:
                for raw_line in f:
                    line = raw_line.strip()
                    if not line or line.startswith("#") or line.startswith("{"):
                        continue
                    tokens.add(line)
        except OSError as e:
            logger.warning(
                "no se pudo leer tokens planos de %s: %s", tokens_file, e
            )
    return tokens


def _load_tokens() -> set:
    """Tokens válidos: estáticos (env/archivo) + emitidos por JWT (no expirados)."""
    tokens = set(_load_static_tokens())
    tokens.update(_load_issued().keys())
    return tokens


def _load_consumed() -> set:
    try:
        with open(_CONSUMED_FILE, "r", encoding="utf-8") as f:
            return set(json.load(f))
    except (OSError, ValueError):
        return set()


def _save_consumed(consumed: set) -> None:
    _atomic_write_json(_CONSUMED_FILE, sorted(consumed))


def _consume_token(token: str) -> Tuple[bool, Optional[Dict[str, str]]]:
    """Consume token de un solo uso.

    Devuelve (True, owner) si es válido. owner=None para tokens estáticos legacy;
    owner={user_id, client_id} para tokens emitidos vía JWT.
    """
    token = (token or "").strip()
    if not token:
        return False, None

    consumed = _load_consumed()
    if token in consumed:
        return False, None

    issued = _load_issued()
    if token in issued:
        owner = _issued_owner(token)
        if not owner or not owner.get("user_id"):
            return False, None
        issued.pop(token, None)
        _save_issued(issued)
        consumed.add(token)
        _save_consumed(consumed)
        _append_tokens_file(
            {
                "event": "consumed",
                "token": token,
                "consumed_at": _iso(_now_utc()),
            }
        )
        return True, owner

    if token not in _load_static_tokens():
        return False, None

    consumed.add(token)
    _save_consumed(consumed)
    return True, None


def mint_enrollment_token(
    user_id: str,
    *,
    client_id: str = "",
    ttl_seconds: Optional[int] = None,
) -> Dict[str, str]:
    """Emite un token de enrollment ligado al dueño (un solo uso)."""
    uid = (user_id or "").strip()
    if not uid:
        raise ValueError("user_id requerido para emitir token de enrollment")
    ttl = ttl_seconds if ttl_seconds is not None else _TOKEN_TTL_SECONDS
    ttl = max(60, int(ttl))
    created = _now_utc()
    expires = created + datetime.timedelta(seconds=ttl)
    token = _ISSUED_TOKEN_PREFIX + secrets.token_urlsafe(24)
    issued = _load_issued()
    issued[token] = {
        "user_id": uid,
        "client_id": (client_id or "").strip(),
        "created_at": _iso(created),
        "expires_at": _iso(expires),
    }
    _save_issued(issued)
    _append_tokens_file(
        {
            "event": "mint",
            "token": token,
            "user_id": uid,
            "client_id": (client_id or "").strip(),
            "created_at": _iso(created),
            "expires_at": _iso(expires),
            "source": "jwt",
        }
    )
    return {
        "token": token,
        "expires_at": _iso(expires),
        "user_id": uid,
        "client_id": (client_id or "").strip(),
    }


def require_jwt_to_mint_enrollment_token(
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    """Exige JWT Robin válido para emitir tokens (prod y lab)."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Missing token (header 'Authorization: Bearer <jwt>')",
        )
    bearer = authorization.split(" ", 1)[1].strip()
    try:
        from lib.jwt_auth import decode_robin_jwt

        claims = decode_robin_jwt(bearer)
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}") from e
    claims["_access_token"] = bearer
    return claims


def _owner_ids_for_enroll(
    request: Request,
    *,
    agent_id: str,
    token_owner: Optional[Dict[str, str]],
) -> Dict[str, str]:
    from lib.ruvic_user import owner_ids_from_user

    claims: Dict[str, Any] = {}
    auth = request.headers.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        bearer = auth.split(" ", 1)[1].strip()
        try:
            from lib.jwt_auth import decode_robin_jwt

            claims = decode_robin_jwt(bearer)
        except Exception:
            claims = {}
        claims["_access_token"] = bearer

    if token_owner and token_owner.get("user_id"):
        bound_uid = token_owner["user_id"]
        bound_cid = token_owner.get("client_id") or ""
        if claims:
            jwt_ids = owner_ids_from_user(claims, agent_id=agent_id)
            jwt_uid = (jwt_ids.get("user_id") or "").strip()
            if jwt_uid and jwt_uid != bound_uid:
                raise HTTPException(
                    status_code=403,
                    detail="El JWT no coincide con el dueño del token de enrollment.",
                )
            if bound_cid and jwt_ids.get("client_id"):
                jwt_cid = (jwt_ids.get("client_id") or "").strip()
                if jwt_cid and jwt_cid != bound_cid:
                    raise HTTPException(
                        status_code=403,
                        detail="El JWT no coincide con el client_id del token de enrollment.",
                    )
        return {"user_id": bound_uid, "client_id": bound_cid}

    return owner_ids_from_user(claims or None, agent_id=agent_id)


def _load_ca():
    """Carga la CA de enrollment (key + cert) para firmar certificados de cliente."""
    if not os.path.isfile(CA_KEY_PATH) or not os.path.isfile(CA_CERT_PATH):
        raise HTTPException(
            status_code=500,
            detail=(
                "Enrollment no configurado: faltan ENROLLMENT_CA_KEY/"
                "ENROLLMENT_CA_CERT (ejecuta scripts/enroll.py o configura rutas)."
            ),
        )
    try:
        with open(CA_KEY_PATH, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(CA_CERT_PATH, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"CA de enrollment inválida: {e}"
        ) from e
    return ca_key, ca_cert


def _load_signing_public_key_pem() -> Optional[str]:
    """Llave pública Ed25519 del backend (del SERVER_SIGNING_KEY)."""
    path = (os.getenv("SERVER_SIGNING_KEY") or "").strip()
    if not path or not os.path.isfile(path):
        return None
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519

        with open(path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        if isinstance(key, ed25519.Ed25519PrivateKey):
            return key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode()
    except Exception:
        pass
    return None


def _issue_client_cert(ca_key, ca_cert, client_name: str):
    """Par RSA + cert de cliente (CN=client_name). Sin SAN extra.

    El SAN del *servidor* (IP/DNS del gateway) se pone en `server.crt` con
    `scripts/enroll.py --san`, no en este endpoint.
    """
    agent_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, client_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Colsoft Agent"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(agent_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=VALIDITY_DAYS)
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=True,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(agent_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    key_pem = agent_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return key_pem, cert_pem


def _trust_forwarded_headers() -> bool:
    raw = (os.getenv("ENROLLMENT_TRUST_FORWARDED") or "").strip().lower()
    return raw in ("1", "true", "yes", "on")


def _public_host(request: Request) -> str:
    """Host público para el websocket_url del bundle (no hardcodear localhost)."""
    env_host = (os.getenv("ENROLLMENT_PUBLIC_HOST") or "").strip()
    if env_host:
        return env_host
    if _trust_forwarded_headers():
        forwarded = (request.headers.get("x-forwarded-host") or "").split(",")[0].strip()
        if forwarded:
            return forwarded
    return (request.headers.get("host") or "").strip() or "localhost:8000"


def _ws_url_for_request(request: Request) -> str:
    """URL WebSocket que el agente debe usar tras el enrollment."""
    return ws_url_for_enrollment(
        host=_public_host(request),
        url_scheme=request.url.scheme,
        forwarded_proto=request.headers.get("x-forwarded-proto") or "",
        trust_forwarded=_trust_forwarded_headers(),
    )


def ws_url_for_enrollment(
    *,
    host: str,
    url_scheme: str = "https",
    forwarded_proto: str = "",
    trust_forwarded: bool = False,
) -> str:
    """Arma websocket_url. Cabeceras X-Forwarded-* solo si trust_forwarded."""
    template = os.getenv("ENROLLMENT_WS_URL", "wss://{host}/ws/colsoft-tools")
    if "{host}" not in template:
        return template
    if trust_forwarded and (forwarded_proto or "").strip():
        proto = forwarded_proto.strip().lower()
    else:
        proto = (url_scheme or "https").lower()
    if proto in ("http", "ws"):
        template = template.replace("wss://", "ws://", 1)
    return template.format(host=host)


def _build_bundle(
    client_name: str, tenant_id: Optional[str], ws_url: str
) -> Dict[str, Any]:
    """Compone el bundle de identidad persistente del agente (RF-CORE-02)."""
    ca_key, ca_cert = _load_ca()

    # Identidad persistente (no generada por sesión)
    agent_id = (
        "agt_"
        + client_name.lower().strip().replace(" ", "-")
        + "_"
        + uuid.uuid4().hex[:6]
    )

    # Par RSA para el desafío de autenticación (§8.1)
    ident_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ident_pub_pem = ident_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    ident_priv_pem = ident_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()

    # Certificado de cliente mTLS firmado por la CA
    agent_key_pem, agent_cert_pem = _issue_client_cert(ca_key, ca_cert, client_name)

    return {
        "agent_id": agent_id,
        "client_name": client_name,
        "tenant_id": tenant_id or os.getenv("DEFAULT_TENANT_ID", ""),
        "websocket_url": ws_url,
        "private_key": ident_priv_pem,
        "public_key": ident_pub_pem,
        "signing_public_key": _load_signing_public_key_pem() or "",
        "tls_ca_cert": open(CA_CERT_PATH, "r", encoding="utf-8").read(),
        "tls_client_cert": agent_cert_pem,
        "tls_client_key": agent_key_pem,
    }


@router.post(
    "/api/enrollment-tokens",
    response_model=MintEnrollmentTokenResponse,
    summary="Emitir token de enrollment ligado al JWT (un agente, un uso)",
)
async def create_enrollment_token(
    user: Dict[str, Any] = Depends(require_jwt_to_mint_enrollment_token),
):
    """OpenHands / Ruvic: el usuario autenticado obtiene un token para un agente nuevo.

    El token queda pre-asociado a ``sub`` del JWT. El host puede enrollar solo
    con ese token (sin pegar el JWT en el CLI); si envía Bearer, debe coincidir.
    """
    from lib.ruvic_user import owner_ids_from_user

    ids = owner_ids_from_user(user)
    uid = (ids.get("user_id") or "").strip()
    if not uid:
        raise HTTPException(
            status_code=400,
            detail="JWT sin user_id identificable (claim sub).",
        )
    try:
        minted = mint_enrollment_token(
            uid,
            client_id=ids.get("client_id") or "",
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    logger.info(
        "Token de enrollment emitido user_id=%r client_id=%r expires_at=%s",
        minted["user_id"],
        minted.get("client_id") or "",
        minted["expires_at"],
    )
    return MintEnrollmentTokenResponse(**minted)


@router.post("/enroll", summary="Enrollment con token de un solo uso (RF-CORE-01/02)")
@router.post("/api/enroll", summary="Alias REST de POST /enroll")
async def enroll(request: Request, payload: EnrollRequest = Body(...)):
    token = (payload.token or "").strip()
    client_name = (payload.client_name or "").strip()
    if not token or not client_name:
        raise HTTPException(
            status_code=400, detail="token y client_name son obligatorios"
        )

    # Fallar antes de consumir el token si la CA no está configurada.
    _load_ca()

    ok, token_owner = _consume_token(token)
    if not ok:
        raise HTTPException(
            status_code=403,
            detail="Token de enrollment inválido o ya utilizado (de un solo uso).",
        )

    bundle = _build_bundle(
        client_name, payload.tenant_id, _ws_url_for_request(request)
    )

    try:
        from lib.agent_store import upsert_agent, upsert_user

        ids = _owner_ids_for_enroll(
            request,
            agent_id=bundle["agent_id"],
            token_owner=token_owner,
        )
        uid = (ids.get("user_id") or "").strip()
        if uid:
            upsert_user(
                uid,
                client_id=ids.get("client_id") or None,
            )
        upsert_agent(
            bundle["agent_id"],
            client_name=client_name,
            tenant_id=bundle.get("tenant_id") or "",
            hostname=client_name,
            user_id=uid or None,
            client_id=ids.get("client_id") or None,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.warning("inventario enroll no se pudo guardar: %s", e)

    logger.info(
        f"Enrollment completado: agent_id={bundle['agent_id']} "
        f"client_name={client_name!r} tenant_id={bundle['tenant_id']!r}"
    )
    return bundle