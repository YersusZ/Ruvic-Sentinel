"""Configuración del conector leída desde variables de entorno.

Prefijo de plataforma: RUVIC_SENTINEL_
"""

from __future__ import annotations

import os
from dataclasses import dataclass

ENV_PREFIX = "RUVIC_SENTINEL_"


def _as_bool(raw: str, default: bool = True) -> bool:
    text = (raw or "").strip().lower()
    if not text:
        return default
    return text in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class SentinelConfig:
    """Parámetros del plano de control REST."""

    base_url: str
    token: str
    timeout: float = 30.0
    verify_tls: bool = True

    @classmethod
    def from_env(cls) -> "SentinelConfig":
        """Construye la configuración desde RUVIC_SENTINEL_*.

        Raises:
            ValueError: si falta BASE_URL o TOKEN.
        """
        missing = [
            f"{ENV_PREFIX}{name}"
            for name in ("BASE_URL", "TOKEN")
            if not (os.environ.get(f"{ENV_PREFIX}{name}") or "").strip()
        ]
        if missing:
            raise ValueError(
                "Faltan variables de entorno del conector ruvic_sentinel: "
                + ", ".join(missing)
                + ". Configura el conector en Settings → Conectores."
            )
        timeout_raw = os.environ.get(f"{ENV_PREFIX}TIMEOUT", "30").strip() or "30"
        try:
            timeout = float(timeout_raw)
        except ValueError as exc:
            raise ValueError(
                f"{ENV_PREFIX}TIMEOUT debe ser un número (segundos), "
                f"recibido {timeout_raw!r}."
            ) from exc
        return cls(
            base_url=os.environ[f"{ENV_PREFIX}BASE_URL"].strip().rstrip("/"),
            token=os.environ[f"{ENV_PREFIX}TOKEN"].strip(),
            timeout=max(1.0, timeout),
            verify_tls=_as_bool(
                os.environ.get(f"{ENV_PREFIX}VERIFY_TLS", "true"),
                default=True,
            ),
        )
