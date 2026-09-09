"""
Tamper-resistance del agente — SRS §9 (RF-CORE-06).

Detecta modificación no autorizada de los componentes del agente:

  - Binario del agente (sys.executable / script).
  - Config (`config_client.json`).
  - Certificados de identidad (tls_ca_cert / tls_client_cert / tls_client_key).

Mecanismo:
  - En el primer arranque se calcula un baseline de hashes (SHA-256) y se
    persiste en `results_logs/tamper_baseline.json` (con la huella del propio
    baseline para detectar su manipulación).
  - En cada arranque (y bajo demanda) se recalculan los hashes y se comparan;
    cualquier diferencia se reporta como evento de seguridad (`event_push`
    severity=critical) y se refleja en `health_check` / `status`.

El baseline se regenera únicamente si el config lo autoriza
(`tamper.allow_rebaseline: true`); por defecto una diferencia se considera
tamper y NUNCA se auto-rebasa.
"""

import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_BASELINE_FILE = os.path.join("results_logs", "tamper_baseline.json")


def _sha256_file(path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _sha256_bytes(data: Optional[str]) -> Optional[str]:
    if data is None:
        return None
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _monitored_paths(config: Dict[str, Any]) -> Dict[str, str]:
    """Mapea {label: path_or_value} de los componentes a vigilar."""
    paths: Dict[str, str] = {}

    if getattr(sys, "frozen", False):
        paths["binary"] = sys.executable
    else:
        try:
            paths["binary"] = os.path.abspath(sys.argv[0])
        except Exception:
            pass

    cfg_path = config.get("_config_path") or "config_client.json"
    if os.path.isfile(cfg_path):
        paths["config"] = cfg_path

    for label, key in (
        ("tls_ca_cert", "tls_ca_cert"),
        ("tls_client_cert", "tls_client_cert"),
        ("tls_client_key", "tls_client_key"),
    ):
        p = config.get(key)
        if p and os.path.isfile(str(p)):
            paths[label] = str(p)

    return paths


def compute_snapshot(config: Dict[str, Any]) -> Dict[str, Any]:
    """Snapshot de hashes actual de los componentes (RF-CORE-06)."""
    snapshot: Dict[str, Any] = {}
    for label, path in _monitored_paths(config).items():
        snapshot[label] = {
            "path": path,
            "sha256": _sha256_file(path),
            "size_bytes": os.path.getsize(path) if os.path.isfile(path) else None,
            "mtime": (
                datetime.fromtimestamp(
                    os.path.getmtime(path), tz=timezone.utc
                ).isoformat()
                if os.path.isfile(path)
                else None
            ),
        }
    for label, key in (("signing_public_key", "signing_public_key"),):
        snapshot[label] = {
            "value_sha256": _sha256_bytes(config.get(key)),
        }
    return snapshot


def _fingerprint(snapshot: Dict[str, Any]) -> str:
    canonical = json.dumps(
        snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class TamperMonitor:
    """Detecta modificación de binario/config/cert y lo reporta."""

    def __init__(
        self,
        config: Dict[str, Any],
        *,
        baseline_file: Optional[str] = None,
        allow_rebaseline: Optional[bool] = None,
        log: Any = print,
    ):
        self.config = config
        tamper_cfg = config.get("tamper") or {}
        self.baseline_file = os.path.abspath(
            baseline_file
            or tamper_cfg.get("baseline_file")
            or DEFAULT_BASELINE_FILE
        )
        self.allow_rebaseline = (
            bool(tamper_cfg.get("allow_rebaseline"))
            if allow_rebaseline is None
            else bool(allow_rebaseline)
        )
        self.log = log
        self._last_check: Optional[Dict[str, Any]] = None

    def baseline_exists(self) -> bool:
        return os.path.isfile(self.baseline_file)

    def load_baseline(self) -> Optional[Dict[str, Any]]:
        try:
            with open(self.baseline_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return None

    def save_baseline(self) -> Dict[str, Any]:
        """Genera y persiste el baseline (primer arranque / rebaseline)."""
        snapshot = compute_snapshot(self.config)
        baseline = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "snapshot": snapshot,
            "fingerprint": _fingerprint(snapshot),
        }
        d = os.path.dirname(self.baseline_file)
        if d:
            os.makedirs(d, exist_ok=True)
        tmp = f"{self.baseline_file}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(baseline, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.baseline_file)
        try:
            os.chmod(self.baseline_file, 0o600)
        except OSError:
            pass
        return baseline

    def check(self) -> Dict[str, Any]:
        """Compara el snapshot actual contra el baseline (RF-CORE-06).

        Devuelve {ok, tampered, changes, baseline_fingerprint_ok}. Si no existe
        baseline, lo crea (primer arranque) y reporta ok.
        """
        baseline = self.load_baseline()
        if baseline is None:
            baseline = self.save_baseline()
            result = {
                "ok": True,
                "tampered": False,
                "baseline_created": True,
                "changes": [],
                "baseline_fingerprint_ok": True,
            }
            self._last_check = result
            return result

        stored_fp = baseline.get("fingerprint")
        baseline_fp_ok = stored_fp == _fingerprint(baseline.get("snapshot") or {})

        snapshot = compute_snapshot(self.config)
        changes: List[Dict[str, Any]] = []
        for label, current in (snapshot or {}).items():
            expected = (baseline.get("snapshot") or {}).get(label)
            if expected is None:
                changes.append(
                    {"component": label, "reason": "componente nuevo (sin baseline)"}
                )
                continue
            if current.get("sha256") != expected.get("sha256") or current.get(
                "value_sha256"
            ) != expected.get("value_sha256"):
                changes.append(
                    {
                        "component": label,
                        "path": current.get("path"),
                        "expected_sha256": expected.get("sha256")
                        or expected.get("value_sha256"),
                        "actual_sha256": current.get("sha256")
                        or current.get("value_sha256"),
                        "reason": "hash modificado",
                    }
                )

        if not changes and baseline_fp_ok:
            result = {"ok": True, "tampered": False, "changes": []}
        else:
            result = {
                "ok": False,
                "tampered": True,
                "changes": changes,
                "baseline_fingerprint_ok": baseline_fp_ok,
                "baseline_file": self.baseline_file,
            }
        self._last_check = result
        return result

    def verify_and_rebaseline(self) -> Dict[str, Any]:
        """`check()`; si hay cambios y `allow_rebaseline`, regenera el baseline.

        Solo se rebasa si fue autorizado explícitamente; en caso contrario el
        tamper queda reportado y pendiente de resolución local.
        """
        result = self.check()
        if result.get("tampered") and self.allow_rebaseline:
            new_baseline = self.save_baseline()
            result["rebaselined"] = True
            result["new_fingerprint"] = new_baseline.get("fingerprint")
            self.log(
                "[tamper] Cambios detectados y baseline regenerado "
                "(allow_rebaseline=true)."
            )
        return result

    def to_event(self) -> Dict[str, Any]:
        """Evento de seguridad listo para `event_push` (severity=critical)."""
        result = self._last_check or self.check()
        return {
            "event_type": "security.tamper_detected",
            "category": "security",
            "severity": "critical" if result.get("tampered") else "info",
            "tampered": result.get("tampered", False),
            "changes": result.get("changes", []),
            "baseline_file": self.baseline_file,
            "baseline_fingerprint_ok": result.get("baseline_fingerprint_ok", True),
        }

    def status(self) -> Dict[str, Any]:
        result = self._last_check or self.check()
        return {
            "tamper_protection": "active",
            "baseline_file": self.baseline_file,
            "baseline_exists": self.baseline_exists(),
            "allow_rebaseline": self.allow_rebaseline,
            **result,
        }