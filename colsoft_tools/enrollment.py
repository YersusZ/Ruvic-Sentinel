"""
Enrollment del agente — SRS §9 (RF-CORE-01/02).

El agente obtiene su identidad PERSISTENTE (agent_id + certificado de cliente +
llaves) mediante un token de un solo uso contra el backend (`POST /enroll`).

  - RF-CORE-01: token de un solo uso (el backend lo consume tras el primer uso;
    reintentar con el mismo token devuelve error).
  - RF-CORE-02: certificado de cliente + identidad persistente — se guarda en
    `enrollment/<nombre-equipo>/identity.json` (y PEMs en esa carpeta) y se
    reutiliza en arranques posteriores (NO se regenera por sesión).

El flujo:
  1. `enroll(server_url, token, client_name, out_dir)` → POST /enroll.
  2. El backend devuelve el bundle de identidad (agent_id, llaves RSA/Ed25519,
     certs mTLS, CA, tenant_id, policy por defecto).
  3. Se persiste el bundle como JSON + PEM; el agente lo carga en el arranque.

Reintentar un enrollment ya completado devuelve la identidad local (idempotente
si ya existe), evitando regenerar certificados.
"""

import json
import os
import re
import secrets
import sys
from typing import Any, Dict, Optional, Tuple, Union

import requests

DEFAULT_OUT_DIR = os.path.join("enrollment")
IDENTITY_FILE = "identity.json"
ACTIVE_POINTER_FILE = "active.json"


def enrollment_root(base: Optional[str] = None) -> str:
    """Raíz `enrollment/` junto al binario (frozen) o en el CWD."""
    if base:
        return os.path.abspath(base)
    return os.path.abspath(default_identity_location())


def sanitize_enrollment_dirname(client_name: str) -> str:
    raw = (client_name or "").strip() or "host"
    safe = re.sub(r"[^\w.\-]+", "-", raw, flags=re.UNICODE)
    safe = safe.strip(".-_") or "host"
    return safe[:96]


def allocate_identity_dir(
    client_name: str,
    *,
    base_root: Optional[str] = None,
) -> str:
    """Carpeta única bajo enrollment/ con el nombre del equipo (sin sobrescribir)."""
    root = enrollment_root(base_root)
    base = sanitize_enrollment_dirname(client_name)
    candidate = os.path.join(root, base)
    if not identity_exists(candidate):
        return candidate
    for _ in range(128):
        suffix = secrets.token_hex(3)
        candidate = os.path.join(root, f"{base}_{suffix}")
        if not identity_exists(candidate):
            return candidate
    raise RuntimeError(
        f"no se pudo asignar carpeta de enrollment única para {client_name!r}"
    )


def write_active_identity_pointer(
    identity_dir: str,
    *,
    base_root: Optional[str] = None,
    client_name: Optional[str] = None,
    agent_id: Optional[str] = None,
) -> str:
    """Marca la identidad activa del host (la usa el agente al arrancar)."""
    root = enrollment_root(base_root)
    os.makedirs(root, exist_ok=True)
    rel = os.path.relpath(os.path.abspath(identity_dir), root)
    payload: Dict[str, str] = {"identity_dir": rel}
    if client_name:
        payload["client_name"] = str(client_name)
    if agent_id:
        payload["agent_id"] = str(agent_id)
    path = os.path.join(root, ACTIVE_POINTER_FILE)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def read_active_identity_pointer(base_root: Optional[str] = None) -> Optional[str]:
    root = enrollment_root(base_root)
    path = os.path.join(root, ACTIVE_POINTER_FILE)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    rel = (data.get("identity_dir") or "").strip()
    if not rel:
        return None
    candidate = os.path.normpath(os.path.join(root, rel))
    if not candidate.startswith(os.path.abspath(root) + os.sep):
        return None
    return candidate if identity_exists(candidate) else None


def resolve_identity_dir(
    config: Optional[Dict[str, Any]] = None,
    *,
    explicit: Optional[str] = None,
    base_root: Optional[str] = None,
) -> Optional[str]:
    """Resuelve la carpeta de identidad a cargar al arrancar el agente."""
    for raw in (
        explicit,
        (os.getenv("ROBIN_IDENTITY_DIR") or "").strip() or None,
        str((config or {}).get("identity_dir") or "").strip() or None,
    ):
        if raw:
            path = raw if os.path.isabs(raw) else os.path.normpath(
                os.path.join(enrollment_root(base_root), raw)
            )
            if identity_exists(path):
                return os.path.abspath(path)

    active = read_active_identity_pointer(base_root)
    if active:
        return active

    client_name = str((config or {}).get("client_name") or "").strip()
    if client_name:
        by_name = os.path.join(
            enrollment_root(base_root),
            sanitize_enrollment_dirname(client_name),
        )
        if identity_exists(by_name):
            return os.path.abspath(by_name)

    legacy = os.path.join(enrollment_root(base_root), IDENTITY_FILE)
    if os.path.isfile(legacy):
        return os.path.abspath(enrollment_root(base_root))

    return None


def identity_path(out_dir: Optional[str] = None) -> str:
    out = out_dir or DEFAULT_OUT_DIR
    return os.path.join(out, IDENTITY_FILE)


def identity_exists(out_dir: Optional[str] = None) -> bool:
    return os.path.isfile(identity_path(out_dir))


def resolve_pem_paths(bundle: Dict[str, Any], base_dir: str) -> Dict[str, Any]:
    """Resuelve tls_* / signing_public_key relativos a `base_dir`.

    No toca PEMs embebidos. Rutas del paquete `client/` (ca.crt junto al JSON).
    """
    if not isinstance(bundle, dict):
        return bundle
    root = os.path.abspath(base_dir or ".")
    for key in (
        "tls_ca_cert",
        "tls_client_cert",
        "tls_client_key",
        "signing_public_key",
        "private_key",
        "public_key",
    ):
        val = bundle.get(key)
        if not val or not isinstance(val, str):
            continue
        if "-----BEGIN" in val:
            continue
        if os.path.isabs(val) and os.path.isfile(val):
            bundle[key] = val
            continue
        if os.path.isfile(val):
            bundle[key] = os.path.abspath(val)
            continue
        rel = os.path.normpath(os.path.join(root, val))
        if os.path.isfile(rel):
            bundle[key] = rel
    return bundle


def _resolve_identity_paths(bundle: Dict[str, Any], identity_dir: str) -> Dict[str, Any]:
    """Resuelve rutas de certs relativas a `enrollment/` (portable Linux/Windows)."""
    return resolve_pem_paths(bundle, identity_dir)


def load_identity(out_dir: Optional[str] = None) -> Optional[Dict[str, Any]]:
    path = identity_path(out_dir)
    try:
        with open(path, "r", encoding="utf-8") as f:
            bundle = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(bundle, dict):
        return None
    return _resolve_identity_paths(bundle, os.path.dirname(os.path.abspath(path)))


def save_identity(bundle: Dict[str, Any], out_dir: Optional[str] = None) -> str:
    """Persiste el bundle de identidad (JSON + PEM) y devuelve su path."""
    out = os.path.abspath(out_dir or DEFAULT_OUT_DIR)
    os.makedirs(out, exist_ok=True)

    certs_dir = os.path.join(out, "certs")
    os.makedirs(certs_dir, exist_ok=True)

    # Guardar PEMs por separado (paths en el bundle apuntan a estos archivos)
    pem_files = {
        "tls_ca_cert": os.path.join(certs_dir, "ca.crt"),
        "tls_client_cert": os.path.join(certs_dir, "agent.crt"),
        "tls_client_key": os.path.join(certs_dir, "agent.key"),
        "signing_public_key": os.path.join(certs_dir, "signing.pub"),
        "private_key": os.path.join(certs_dir, "identity.key"),
        "public_key": os.path.join(certs_dir, "identity.pub"),
    }
    for key, path in pem_files.items():
        value = bundle.get(key)
        if value:
            with open(path, "w", encoding="utf-8") as f:
                f.write(value)
            try:
                os.chmod(path, 0o600 if key.endswith("key") else 0o644)
            except OSError:
                pass
            bundle[key] = path

    # Guardar llaves RSA del desafío embebidas (igual que config_client.json)
    path = identity_path(out)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, ensure_ascii=False, indent=2)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def enroll(
    server_url: str,
    token: str,
    client_name: str,
    *,
    out_dir: Optional[str] = None,
    timeout: float = 30.0,
    tenant_id: Optional[str] = None,
    verify: Union[bool, str] = True,
    client_cert: Optional[Tuple[str, str]] = None,
) -> Dict[str, Any]:
    """Realiza el enrollment con token de un solo uso (RF-CORE-01/02).

    Devuelve el bundle de identidad persistido. Si la identidad ya existe en
    ``out_dir``, la devuelve (idempotente) sin volver a consumir el token.

    ``verify``: True (tienda del sistema), False (solo lab) o ruta a CA PEM.
    ``out_dir``: carpeta destino; si se omite, usa ``enrollment/<client_name>/``
    (sufijo único si ya existe).
    """
    if out_dir is None:
        out_dir = allocate_identity_dir(client_name)
    else:
        out_dir = os.path.abspath(out_dir)

    existing = load_identity(out_dir)
    if existing:
        return existing

    base = (server_url or "").rstrip("/")
    if not base.startswith(("http://", "https://")):
        raise ValueError("server_url debe ser http/https (ej: https://host:8000)")
    if not (token or "").strip():
        raise ValueError("token de enrollment requerido (de un solo uso)")
    if isinstance(verify, str) and verify.strip():
        if not os.path.isfile(verify):
            raise ValueError(f"CA de enrollment no encontrada: {verify}")
        verify = verify.strip()

    payload: Dict[str, Any] = {
        "token": str(token).strip(),
        "client_name": client_name,
    }
    if tenant_id:
        payload["tenant_id"] = tenant_id

    post_kw: Dict[str, Any] = {"json": payload, "timeout": timeout, "verify": verify}
    if client_cert:
        post_kw["cert"] = client_cert

    last_error: Optional[Exception] = None
    resp = None
    for path in ("/api/enroll", "/enroll"):
        try:
            resp = requests.post(f"{base}{path}", **post_kw)
        except requests.RequestException as e:
            last_error = e
            continue
        if resp.status_code != 404:
            break
    if resp is None:
        raise RuntimeError(
            f"enrollment: no se pudo contactar {base}/api/enroll: {last_error}"
        ) from last_error

    if resp.status_code != 200:
        detail = ""
        try:
            detail = resp.json().get("detail") or resp.text
        except ValueError:
            detail = resp.text
        raise RuntimeError(
            f"enrollment rechazado (HTTP {resp.status_code}): {detail}"
        )

    bundle = resp.json()
    if not bundle.get("agent_id"):
        raise RuntimeError("enrollment: el backend no devolvió agent_id")

    save_identity(bundle, out_dir)
    target = os.path.abspath(out_dir or DEFAULT_OUT_DIR)
    write_active_identity_pointer(
        target,
        client_name=str(bundle.get("client_name") or client_name),
        agent_id=str(bundle.get("agent_id") or ""),
    )
    return bundle


DEFAULT_MAX_COMMAND_RATE = 20

# Solo estos campos del bundle pisan el JSON local. scheduler / linux / alerts
# / data_plane viven en config_client.json aunque identity.json tenga extras.
_IDENTITY_OVERLAY_KEYS = frozenset(
    {
        "agent_id",
        "client_name",
        "tenant_id",
        "websocket_url",
        "private_key",
        "public_key",
        "signing_public_key",
        "tls_ca_cert",
        "tls_client_cert",
        "tls_client_key",
        "allow_insecure_ws",
    }
)

_IDENTITY_DEFAULTS = {
    "require_command_signature": True,
    "allow_insecure_ws": False,
    "heartbeat_interval": 30,
    "scheduler": {},
    "policy": {
        "allowed_commands": [],
        "allow_high_risk": False,
    },
    "scripts_catalog": {},
    "audit_log_path": os.path.join("results_logs", "agent_audit.jsonl"),
    "max_command_rate": DEFAULT_MAX_COMMAND_RATE,
}


def identity_to_config(bundle: Dict[str, Any]) -> Dict[str, Any]:
    """Convierte el bundle de enrollment en un config_client.json utilizable."""
    cfg = dict(bundle or {})
    for key, value in _IDENTITY_DEFAULTS.items():
        cfg.setdefault(key, value)
    return cfg


def merge_runtime_config(
    disk_cfg: Optional[Dict[str, Any]], bundle: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    """JSON local + identidad: el bundle pisa certs/id; el JSON cubre el resto.

    El server solo devuelve identidad. scheduler, linux.*, alerts y data_plane
    viven en `config_client.json` (README_CONFIG).
    """
    merged = dict(disk_cfg or {})
    for key, value in (bundle or {}).items():
        if key not in _IDENTITY_OVERLAY_KEYS:
            continue
        if value is None or value == "":
            continue
        merged[key] = value
    if bundle:
        if "allow_insecure_ws" in bundle and bundle["allow_insecure_ws"] is not None:
            merged["allow_insecure_ws"] = bool(bundle["allow_insecure_ws"])
        else:
            ws = str(merged.get("websocket_url") or "")
            has_mtls = bool(
                str(merged.get("tls_client_cert") or "").strip()
                and str(merged.get("tls_client_key") or "").strip()
            )
            if has_mtls and ws.startswith("wss://"):
                merged["allow_insecure_ws"] = False
    if merged.get("allow_insecure_ws"):
        # Ingress Robin: no usar PEMs de enrollment para TLS del host público.
        merged["tls_ca_cert"] = ""
        merged["tls_client_cert"] = ""
        merged["tls_client_key"] = ""
    for key, value in _IDENTITY_DEFAULTS.items():
        merged.setdefault(key, value)
    return merged


def default_identity_location() -> str:
    if getattr(sys, "frozen", False) and getattr(sys, "executable", None):
        return os.path.join(
            os.path.dirname(os.path.abspath(sys.executable)),
            "enrollment",
        )
    return DEFAULT_OUT_DIR


def resolve_enroll_verify(
    server_url: str,
    ca_path: Optional[str] = None,
    *,
    config: Optional[Dict[str, Any]] = None,
    identity_dir: Optional[str] = None,
) -> Union[bool, str]:
    """CA para POST /api/enroll (pin, no tienda del sistema a ciegas si hay PEM)."""
    if ca_path and str(ca_path).strip():
        return str(ca_path).strip()
    base = (server_url or "").strip().lower()
    if not base.startswith("https://"):
        return True
    candidates = []
    cfg = config if isinstance(config, dict) else {}
    pinned = str(cfg.get("tls_ca_cert") or "").strip()
    if pinned:
        candidates.append(pinned)
    root = os.path.abspath(identity_dir or default_identity_location())
    candidates.extend(
        (
            os.path.join(root, "certs", "ca.crt"),
            os.path.join(root, "ca.crt"),
        )
    )
    for path in candidates:
        if path and os.path.isfile(path):
            return path
    return True