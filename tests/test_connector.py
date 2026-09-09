"""Pruebas unitarias de la librería del conector (sin red)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / "lib"
sys.path.insert(0, str(LIB))

from ruvic_sentinel_connector import (  # noqa: E402
    SentinelAuthError,
    SentinelClient,
    SentinelConfig,
    SentinelNetworkError,
)
from ruvic_sentinel_connector.config import ENV_PREFIX  # noqa: E402


class TestSentinelConfig(unittest.TestCase):
    def test_from_env_requires_base_url_and_token(self) -> None:
        env = {f"{ENV_PREFIX}BASE_URL": "", f"{ENV_PREFIX}TOKEN": ""}
        with patch.dict("os.environ", env, clear=True):
            with self.assertRaises(ValueError) as ctx:
                SentinelConfig.from_env()
        self.assertIn("Settings → Conectores", str(ctx.exception))

    def test_from_env_reads_prefix(self) -> None:
        env = {
            f"{ENV_PREFIX}BASE_URL": "https://sentinel.example/",
            f"{ENV_PREFIX}TOKEN": "jwt-token",
            f"{ENV_PREFIX}TIMEOUT": "12",
            f"{ENV_PREFIX}VERIFY_TLS": "false",
        }
        with patch.dict("os.environ", env, clear=False):
            cfg = SentinelConfig.from_env()
        self.assertEqual(cfg.base_url, "https://sentinel.example")
        self.assertEqual(cfg.token, "jwt-token")
        self.assertEqual(cfg.timeout, 12.0)
        self.assertFalse(cfg.verify_tls)


class TestSentinelClient(unittest.TestCase):
    def _client(self) -> SentinelClient:
        cfg = SentinelConfig(
            base_url="https://sentinel.example",
            token="jwt-token",
            timeout=5.0,
        )
        return SentinelClient(config=cfg)

    def test_list_agents_ok(self) -> None:
        client = self._client()
        response = MagicMock()
        response.status_code = 200
        response.content = b"[{}]"
        response.json.return_value = [{"agent_id": "agt_1", "online": True}]
        with patch.object(client._client, "request", return_value=response):
            rows = client.list_agents()
        self.assertEqual(rows[0]["agent_id"], "agt_1")
        client.close()

    def test_execute_maps_401(self) -> None:
        client = self._client()
        response = MagicMock()
        response.status_code = 401
        response.content = b"{}"
        response.json.return_value = {"detail": "Unauthorized"}
        response.text = "Unauthorized"
        with patch.object(client._client, "request", return_value=response):
            with self.assertRaises(SentinelAuthError):
                client.execute("agt_1", "health_check")
        client.close()

    def test_execute_queued_202(self) -> None:
        client = self._client()
        response = MagicMock()
        response.status_code = 202
        response.content = b'{"queued":true}'
        response.json.return_value = {
            "id": "cmd_1",
            "ok": True,
            "queued": True,
            "tool": "health_check",
        }
        with patch.object(client._client, "request", return_value=response):
            payload = client.execute("agt_1", "health_check")
        self.assertTrue(payload["queued"])
        self.assertEqual(payload["id"], "cmd_1")
        client.close()

    def test_health_omits_authorization(self) -> None:
        client = self._client()
        response = MagicMock()
        response.status_code = 200
        response.content = b'{"status":"ok"}'
        response.json.return_value = {"status": "ok", "agents": 0}
        with patch.object(client._client, "request", return_value=response) as req:
            client.health()
        kwargs = req.call_args.kwargs
        self.assertEqual(kwargs["headers"]["Authorization"], None)
        client.close()

    def test_network_error(self) -> None:
        import httpx

        client = self._client()
        with patch.object(
            client._client,
            "request",
            side_effect=httpx.ConnectError("boom"),
        ):
            with self.assertRaises(SentinelNetworkError):
                client.health()
        client.close()


if __name__ == "__main__":
    unittest.main()
