"""Arranque TLS/mTLS del servidor de control (SRS §8.2 / §15).

Docker y `python main.py` comparten este módulo: las env `SSL_*` no dependen
del CLI de uvicorn (`uvicorn main:app` no pineaba el contexto).

Enrollment online contra un socket ya en CERT_REQUIRED no puede presentar
cert de cliente (aún no existe). Por eso, si hay TLS, se abre un **bootstrap**
en loopback (default 8001): `/health`, `/enroll`, `/api/enroll` sin mTLS.
El puerto 8000 sigue en CERT_REQUIRED. PKI offline: `scripts/enroll.py`.
"""

from __future__ import annotations

import logging
import os
import ssl
import threading
from dataclasses import dataclass
from typing import Any, Optional

from fastapi import FastAPI

from colsoft_tools.tls_util import make_server_ssl_context, parse_ssl_cert_reqs

logger = logging.getLogger("agent-server")

CONTROL_HOST = os.getenv("HOST", "0.0.0.0")
CONTROL_PORT = int(os.getenv("PORT", "8000"))


@dataclass(frozen=True)
class SslSettings:
    certfile: Optional[str]
    keyfile: Optional[str]
    password: Optional[str]
    ca_certs: Optional[str]
    cert_reqs: int
    bootstrap_host: str
    bootstrap_port: Optional[int]
    bootstrap_tls: bool

    @property
    def tls_enabled(self) -> bool:
        return bool(self.certfile and self.keyfile)


def _env_path(name: str) -> Optional[str]:
    raw = (os.getenv(name) or "").strip()
    return raw or None


def _truthy(raw: Optional[str], *, default: bool) -> bool:
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def load_ssl_settings(*, strict: bool = True) -> SslSettings:
    certfile = _env_path("SSL_CERTFILE")
    keyfile = _env_path("SSL_KEYFILE")
    ca = _env_path("SSL_CA_CERTS")
    password = os.getenv("SSL_KEYFILE_PASSWORD") or None
    reqs_raw = os.getenv("SSL_CERT_REQS")
    cert_reqs = parse_ssl_cert_reqs(reqs_raw)

    tls = bool(certfile and keyfile)
    if bool(certfile) != bool(keyfile):
        raise RuntimeError("SSL_CERTFILE y SSL_KEYFILE deben definirse juntos.")
    if tls and cert_reqs != ssl.CERT_NONE and not ca and strict:
        raise RuntimeError(
            "SSL_CERTFILE está definido y SSL_CERT_REQS exige mTLS, pero "
            "falta SSL_CA_CERTS. No se arranca en claro ni con CERT_NONE."
        )

    bootstrap_host = (os.getenv("ENROLLMENT_BOOTSTRAP_HOST") or "127.0.0.1").strip()
    port_raw = os.getenv("ENROLLMENT_BOOTSTRAP_PORT")
    if port_raw is None:
        bootstrap_port = 8001 if tls else None
    elif port_raw.strip().lower() in ("", "0", "off", "false", "no"):
        bootstrap_port = None
    else:
        bootstrap_port = int(port_raw)

    bootstrap_tls = _truthy(
        os.getenv("ENROLLMENT_BOOTSTRAP_TLS"),
        default=tls,
    )
    return SslSettings(
        certfile=certfile,
        keyfile=keyfile,
        password=password,
        ca_certs=ca,
        cert_reqs=cert_reqs,
        bootstrap_host=bootstrap_host,
        bootstrap_port=bootstrap_port,
        bootstrap_tls=bootstrap_tls,
    )


def make_bootstrap_app() -> FastAPI:
    """App mínima: health + enrollment. Sin WS, OTLP ni execute."""
    from enrollment import router as enrollment_router

    app = FastAPI(title="WS Tools enrollment bootstrap", docs_url=None, redoc_url=None)
    app.include_router(enrollment_router)

    @app.get("/health", include_in_schema=False)
    def bootstrap_health() -> dict[str, str]:
        return {"status": "ok", "role": "bootstrap"}

    return app


def _pinned_server(app: Any, *, host: str, port: int, ssl_context: Optional[ssl.SSLContext], ssl_kw: dict) -> Any:
    import uvicorn

    class _PinnedConfig(uvicorn.Config):
        def load(self) -> None:
            super().load()
            if ssl_context is not None:
                self.ssl = ssl_context
            elif self.ssl is not None:
                self.ssl.minimum_version = ssl.TLSVersion.TLSv1_2

    return uvicorn.Server(_PinnedConfig(app, host=host, port=port, **ssl_kw))


def control_ssl_context(settings: SslSettings) -> ssl.SSLContext:
    return make_server_ssl_context(
        certfile=settings.certfile or "",
        keyfile=settings.keyfile or "",
        password=settings.password,
        ca_certs=settings.ca_certs,
        cert_reqs=settings.cert_reqs,
    )


def bootstrap_ssl_context(settings: SslSettings) -> Optional[ssl.SSLContext]:
    if not settings.bootstrap_tls or not settings.tls_enabled:
        return None
    return make_server_ssl_context(
        certfile=settings.certfile or "",
        keyfile=settings.keyfile or "",
        password=settings.password,
        ca_certs=None,
        cert_reqs=ssl.CERT_NONE,
    )


def start_bootstrap(settings: SslSettings) -> Optional[threading.Thread]:
    if not settings.bootstrap_port:
        return None
    app = make_bootstrap_app()
    ctx = bootstrap_ssl_context(settings)
    ssl_kw: dict = {}
    if ctx is not None:
        ssl_kw = {
            "ssl_certfile": settings.certfile,
            "ssl_keyfile": settings.keyfile,
            "ssl_keyfile_password": settings.password,
        }
    scheme = "https" if ctx is not None else "http"
    logger.info(
        "Enrollment bootstrap en %s://%s:%s (/health, /api/enroll) sin mTLS. "
        "El plano de control sigue en el puerto %s con SSL_CERT_REQS=%s.",
        scheme,
        settings.bootstrap_host,
        settings.bootstrap_port,
        CONTROL_PORT,
        settings.cert_reqs,
    )

    def _run() -> None:
        _pinned_server(
            app,
            host=settings.bootstrap_host,
            port=settings.bootstrap_port,
            ssl_context=ctx,
            ssl_kw=ssl_kw,
        ).run()

    thread = threading.Thread(target=_run, name="enroll-bootstrap", daemon=True)
    thread.start()
    return thread


def run_control_server(app: Any, settings: SslSettings) -> None:
    ssl_kw: dict = {}
    ctx = None
    if settings.tls_enabled:
        ctx = control_ssl_context(settings)
        ssl_kw = {
            "ssl_certfile": settings.certfile,
            "ssl_keyfile": settings.keyfile,
            "ssl_keyfile_password": settings.password,
        }
        if settings.ca_certs:
            ssl_kw["ssl_ca_certs"] = settings.ca_certs
            ssl_kw["ssl_cert_reqs"] = int(settings.cert_reqs)
        logger.info(
            "Control plane TLS en %s:%s (verify_mode=%s)",
            CONTROL_HOST,
            CONTROL_PORT,
            ctx.verify_mode,
        )
    else:
        logger.warning(
            "Control plane HTTP en %s:%s (sin SSL_CERTFILE; solo lab).",
            CONTROL_HOST,
            CONTROL_PORT,
        )
    _pinned_server(
        app,
        host=CONTROL_HOST,
        port=CONTROL_PORT,
        ssl_context=ctx,
        ssl_kw=ssl_kw,
    ).run()
