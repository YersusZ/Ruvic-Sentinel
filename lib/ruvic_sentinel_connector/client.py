"""Cliente HTTP del plano de control Ruvic Sentinel.

Capacidades:
- health():                 GET /health (sin JWT).
- list_agents():            GET /api/agents
- get_agent(agent_id):      GET /api/agents/{id}
- execute(...):             POST /api/agents/{id}/execute
- list_commands(agent_id):  GET /api/agents/{id}/commands
- get_command(...):         GET /api/agents/{id}/commands/{message_id}
- create_enrollment_token(): POST /api/enrollment-tokens

Las credenciales salen de RUVIC_SENTINEL_* (ver config.SentinelConfig.from_env).
"""

from __future__ import annotations

from typing import Any

import httpx

from .config import SentinelConfig
from .exceptions import (
    SentinelAuthError,
    SentinelDataError,
    SentinelNetworkError,
)
from .logging_utils import get_logger


class SentinelClient:
    """Cliente REST del plano de control.

    Args:
        config: si se omite, se lee de RUVIC_SENTINEL_*.

    Ejemplo:
        >>> client = SentinelClient()
        >>> client.list_agents()
        [{'agent_id': 'agt_…', 'online': True, ...}]
    """

    def __init__(self, config: SentinelConfig | None = None) -> None:
        self.config = config or SentinelConfig.from_env()
        self._logger = get_logger()
        self._client = httpx.Client(
            base_url=self.config.base_url,
            timeout=self.config.timeout,
            verify=self.config.verify_tls,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self.config.token}",
            },
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "SentinelClient":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        auth: bool = True,
    ) -> Any:
        # auth=False quita el Bearer (GET /health). httpx fusiona headers;
        # Authorization: None elimina el default del Client.
        headers: dict[str, str | None] | None = None
        if not auth:
            headers = {"Accept": "application/json", "Authorization": None}
        try:
            response = self._client.request(
                method,
                path,
                json=json,
                params=params,
                headers=headers,
            )
        except httpx.TimeoutException as exc:
            raise SentinelNetworkError(
                f"Timeout ({self.config.timeout}s) al llamar {method} {path} "
                f"en {self.config.base_url}."
            ) from exc
        except httpx.RequestError as exc:
            raise SentinelNetworkError(
                f"No se pudo alcanzar {self.config.base_url}{path}: {exc}"
            ) from exc

        if response.status_code in (401, 403):
            detail = _response_detail(response)
            raise SentinelAuthError(
                f"Autenticación rechazada (HTTP {response.status_code}) "
                f"en {path}. Revisa RUVIC_SENTINEL_TOKEN. {detail}"
            )
        if response.status_code == 404:
            raise SentinelDataError(
                f"Recurso no encontrado (HTTP 404) en {path}. "
                f"{_response_detail(response)}"
            )
        if response.status_code >= 400:
            raise SentinelDataError(
                f"El plano de control respondió HTTP {response.status_code} "
                f"en {path}. {_response_detail(response)}"
            )
        if not response.content:
            return None
        try:
            return response.json()
        except ValueError as exc:
            raise SentinelDataError(
                f"Respuesta no JSON en {path}: {response.text[:200]}"
            ) from exc

    def health(self) -> dict[str, Any]:
        """Healthcheck del control plane (no exige JWT)."""
        payload = self._request("GET", "/health", auth=False)
        if not isinstance(payload, dict):
            raise SentinelDataError("GET /health no devolvió un objeto JSON.")
        self._logger.info(
            "Health ok en %s (agents=%s)",
            self.config.base_url,
            payload.get("agents"),
        )
        return payload

    def list_agents(self) -> list[dict[str, Any]]:
        """Inventario de agentes del JWT autenticado."""
        payload = self._request("GET", "/api/agents")
        if not isinstance(payload, list):
            raise SentinelDataError("GET /api/agents no devolvió una lista.")
        self._logger.info("Listados %d agentes", len(payload))
        return payload

    def get_agent(self, agent_id: str) -> dict[str, Any]:
        """Ficha de un agente (inventario + sesión WS)."""
        aid = (agent_id or "").strip()
        if not aid:
            raise SentinelDataError("agent_id es obligatorio.")
        payload = self._request("GET", f"/api/agents/{aid}")
        if not isinstance(payload, dict):
            raise SentinelDataError("GET /api/agents/{id} no devolvió un objeto.")
        return payload

    def execute(
        self,
        agent_id: str,
        tool: str,
        params: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """Ejecuta una tool en el agente (puede devolver queued=true si está offline)."""
        aid = (agent_id or "").strip()
        name = (tool or "").strip()
        if not aid:
            raise SentinelDataError("agent_id es obligatorio.")
        if not name:
            raise SentinelDataError("tool es obligatorio.")
        body: dict[str, Any] = {"tool": name, "params": params or {}}
        if timeout is not None:
            body["timeout"] = float(timeout)
        payload = self._request("POST", f"/api/agents/{aid}/execute", json=body)
        if not isinstance(payload, dict):
            raise SentinelDataError("POST execute no devolvió un objeto.")
        self._logger.info(
            "execute agent=%s tool=%s ok=%s queued=%s",
            aid,
            name,
            payload.get("ok"),
            payload.get("queued"),
        )
        return payload

    def list_commands(self, agent_id: str) -> list[dict[str, Any]]:
        """Cola de comandos de un agente."""
        aid = (agent_id or "").strip()
        if not aid:
            raise SentinelDataError("agent_id es obligatorio.")
        payload = self._request("GET", f"/api/agents/{aid}/commands")
        if not isinstance(payload, list):
            raise SentinelDataError("GET commands no devolvió una lista.")
        return payload

    def get_command(self, agent_id: str, message_id: str) -> dict[str, Any]:
        """Estado de un comando concreto."""
        aid = (agent_id or "").strip()
        mid = (message_id or "").strip()
        if not aid or not mid:
            raise SentinelDataError("agent_id y message_id son obligatorios.")
        payload = self._request("GET", f"/api/agents/{aid}/commands/{mid}")
        if not isinstance(payload, dict):
            raise SentinelDataError("GET command no devolvió un objeto.")
        return payload

    def create_enrollment_token(self) -> dict[str, Any]:
        """Emite un token enr_… de un solo uso ligado al JWT."""
        payload = self._request("POST", "/api/enrollment-tokens")
        if not isinstance(payload, dict):
            raise SentinelDataError(
                "POST /api/enrollment-tokens no devolvió un objeto."
            )
        self._logger.info("Token de enrollment emitido")
        return payload


def _response_detail(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        text = (response.text or "").strip()
        return text[:300] if text else ""
    if isinstance(body, dict):
        for key in ("detail", "message", "error"):
            value = body.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return str(body)[:300]
    return str(body)[:300]
