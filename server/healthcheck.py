"""Liveness de Docker: no usa el CLI de uvicorn ni asume HTTP en 8000.

Con TLS, el /health del puerto de control exige cert de cliente. Se consulta
el bootstrap de enrollment (loopback) o, si está desactivado, TCP en 8000.
"""

from __future__ import annotations

import socket
import ssl
import sys
import urllib.error
import urllib.request

from tls_runtime import CONTROL_PORT, load_ssl_settings


def _open(url: str, *, tls: bool) -> None:
    ctx = None
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    urllib.request.urlopen(url, timeout=3, context=ctx)


def main() -> int:
    try:
        settings = load_ssl_settings(strict=False)
    except Exception:
        return 1

    if settings.bootstrap_port:
        tls = bool(settings.bootstrap_tls and settings.tls_enabled)
        scheme = "https" if tls else "http"
        url = f"{scheme}://127.0.0.1:{settings.bootstrap_port}/health"
        try:
            _open(url, tls=tls)
            return 0
        except (urllib.error.URLError, OSError, TimeoutError):
            return 1

    if not settings.tls_enabled:
        try:
            _open(f"http://127.0.0.1:{CONTROL_PORT}/health", tls=False)
            return 0
        except (urllib.error.URLError, OSError, TimeoutError):
            return 1

    try:
        socket.create_connection(("127.0.0.1", CONTROL_PORT), 3).close()
        return 0
    except OSError:
        return 1


if __name__ == "__main__":
    sys.exit(main())
