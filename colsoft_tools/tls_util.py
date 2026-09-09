"""TLS 1.2+ y mTLS para el agente — SRS §8.2 / §15.

`ssl.create_default_context()` ya niega TLS 1.0/1.1 en Python 3.10+, pero el
NFR pide el piso explícito. mTLS es obligatorio salvo `allow_insecure_ws`
(lab): sin `tls_client_cert`/`tls_client_key` el canal no arranca.

Servidor: `parse_ssl_cert_reqs` es el contrato del repo (no el de uvicorn CLI).
`1` y `required` son CERT_REQUIRED. Sin CA no se degrada a CERT_NONE.
"""

from __future__ import annotations

import os
import ssl
from typing import Any, Dict, Optional, Union


def _cafile(config: Dict[str, Any]) -> Optional[str]:
    ca = str(config.get("tls_ca_cert") or "").strip()
    return ca or None


def _client_pair(config: Dict[str, Any]) -> tuple[str, str]:
    cert = str(config.get("tls_client_cert") or "").strip()
    key = str(config.get("tls_client_key") or "").strip()
    return cert, key


def parse_ssl_cert_reqs(
    value: Union[str, int, None] = None,
    *,
    default: int = ssl.CERT_REQUIRED,
) -> int:
    """Mapea SSL_CERT_REQS al enum de `ssl`.

    Contrato del repo (docs/produccion.md), distinto de uvicorn CLI:

    - ``required`` / ``2`` / ``1`` / ``true`` → ``CERT_REQUIRED``
    - ``optional`` / ``bootstrap`` → ``CERT_OPTIONAL``
    - ``none`` / ``0`` / ``false`` → ``CERT_NONE``

    ``1`` es REQUIRED aquí (histórico). ``uvicorn --ssl-cert-reqs 1`` es
    OPTIONAL en stdlib; no arrancar el server con el CLI de uvicorn.
    """
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return ssl.CERT_REQUIRED if value else ssl.CERT_NONE
    if isinstance(value, int):
        # Enum de stdlib (OPTIONAL=1, REQUIRED=2). El "1" de las env es string.
        if value in (ssl.CERT_NONE, ssl.CERT_OPTIONAL, ssl.CERT_REQUIRED):
            return int(value)
        raise ValueError(f"SSL_CERT_REQS numérico inválido: {value!r}")
    text = str(value).strip().lower()
    if text in ("required", "require", "2", "true", "on", "yes"):
        return ssl.CERT_REQUIRED
    if text in ("1",):
        return ssl.CERT_REQUIRED
    if text in ("optional", "bootstrap"):
        return ssl.CERT_OPTIONAL
    if text in ("none", "0", "false", "off", "no"):
        return ssl.CERT_NONE
    raise ValueError(f"SSL_CERT_REQS inválido: {value!r}")


def make_client_ssl_context(
    config: Dict[str, Any],
    *,
    require_client_cert: Optional[bool] = None,
) -> ssl.SSLContext:
    """Contexto TLS 1.2+ para WSS / OTLP HTTPS.

    Si `require_client_cert` es None, se deriva de `allow_insecure_ws`:
    lab (`true`) puede ir sin cert de cliente; producción exige mTLS.

    Robin ingress (`allow_insecure_ws: true` + `wss://`): el TLS del servidor
    lo termina el ingress (Let's Encrypt). ``tls_ca_cert`` del enrollment es
    la CA que firma certs de *agente*, no la del ingress — no usarla para
    verificar el host público.
    """
    insecure = bool(config.get("allow_insecure_ws"))
    if require_client_cert is None:
        require_client_cert = not insecure

    cafile = None if insecure else _cafile(config)
    ctx = ssl.create_default_context(cafile=cafile)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if cafile is None:
        try:
            import certifi

            ctx.load_verify_locations(certifi.where())
        except Exception:
            pass

    cert, key = _client_pair(config) if not insecure else ("", "")
    if require_client_cert:
        if not cert or not key:
            raise RuntimeError(
                "mTLS obligatorio (SRS §15): configure tls_client_cert y "
                "tls_client_key (enrollment) o allow_insecure_ws solo en lab."
            )
        if not os.path.isfile(cert) or not os.path.isfile(key):
            raise RuntimeError(
                "mTLS obligatorio (SRS §15): no se encuentran "
                f"tls_client_cert={cert!r} o tls_client_key={key!r}."
            )
        ctx.load_cert_chain(cert, key)
    elif cert and key and os.path.isfile(cert) and os.path.isfile(key):
        ctx.load_cert_chain(cert, key)
    return ctx


def make_server_ssl_context(
    *,
    certfile: str,
    keyfile: str,
    password: Optional[str] = None,
    ca_certs: Optional[str] = None,
    cert_reqs: Union[int, str, None] = ssl.CERT_REQUIRED,
) -> ssl.SSLContext:
    """Contexto TLS 1.2+ del backend. Sin CA no hay mTLS silencioso."""
    reqs = parse_ssl_cert_reqs(cert_reqs)
    ca = (ca_certs or "").strip() or None
    if reqs != ssl.CERT_NONE and not ca:
        raise RuntimeError(
            "mTLS: SSL_CA_CERTS es obligatorio cuando SSL_CERT_REQS es "
            "required/optional; no se degrada a CERT_NONE."
        )
    if not certfile or not keyfile:
        raise RuntimeError("SSL_CERTFILE y SSL_KEYFILE son obligatorios para TLS.")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile, keyfile, password=password or None)
    if ca:
        if not os.path.isfile(ca):
            raise RuntimeError(f"SSL_CA_CERTS no existe: {ca}")
        ctx.load_verify_locations(ca)
        ctx.verify_mode = reqs
    else:
        ctx.verify_mode = ssl.CERT_NONE
    return ctx
