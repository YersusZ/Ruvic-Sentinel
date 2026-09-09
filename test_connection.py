"""Prueba de conexión estándar del conector ruvic_sentinel.

Firma: def test_connection() -> tuple[bool, str]
Lee exclusivamente RUVIC_SENTINEL_*. Nunca lanza excepciones.

    python test_connection.py
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
_LIB = _ROOT / "lib"
if _LIB.is_dir() and str(_LIB) not in sys.path:
    sys.path.insert(0, str(_LIB))


def test_connection() -> tuple[bool, str]:
    """GET /api/agents con RUVIC_SENTINEL_*. /health es opcional (mTLS)."""
    try:
        from ruvic_sentinel_connector import (
            SentinelAuthError,
            SentinelClient,
            SentinelDataError,
            SentinelNetworkError,
        )
    except ImportError:
        return (
            False,
            "La librería ruvic-sentinel-connector no está instalada. "
            "Instala con: pip install git+https://github.com/YersusZ/"
            "Ruvic-Sentinel.git#subdirectory=lib",
        )

    client = None
    try:
        client = SentinelClient()
        health_note = "health=omitido"
        try:
            health = client.health()
            status = health.get("status") if isinstance(health, dict) else None
            health_note = f"health={status!r}"
        except (SentinelNetworkError, SentinelAuthError, SentinelDataError):
            # Con mTLS el /health del puerto de control puede exigir cert de
            # cliente; el JWT se valida en GET /api/agents.
            health_note = "health no disponible (mTLS u orquestación)"

        agents = client.list_agents()
        base_url = client.config.base_url
        count = len(agents) if isinstance(agents, list) else 0
        return True, (
            f"Conexión exitosa a {base_url} ({health_note}, agentes={count})."
        )
    except ValueError as exc:
        return False, str(exc)
    except SentinelAuthError as exc:
        return False, f"Autenticación fallida: {exc}"
    except SentinelNetworkError as exc:
        return False, f"Error de red: {exc}"
    except SentinelDataError as exc:
        return False, f"Error de datos: {exc}"
    except Exception as exc:  # noqa: BLE001 — firma estándar: nunca propagar
        return False, f"Error inesperado: {exc}"
    finally:
        if client is not None:
            client.close()


if __name__ == "__main__":
    ok, message = test_connection()
    print(f"{'OK' if ok else 'FALLO'}: {message}")
    raise SystemExit(0 if ok else 1)
