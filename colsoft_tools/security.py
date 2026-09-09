"""
Seguridad del canal de control — SRS §8.2 y §8.5.

Cubre:
  - Firma por comando (Ed25519): el backend firma cada `command_request` y el
    agente la verifica contra la llave pública fijada en el enrollment (§8.2).
  - Verificación de la firma RSA del desafío de autenticación en el backend.
  - Catálogo de riesgo por comando y política local por defecto
    (Alto/Crítico deshabilitados, §8.4/§8.5).
  - Allowlist local de comandos (doble candado, §8.2).
  - Rate limiting por agente y por tipo de comando (§8.5).
  - Timeout obligatorio por comando (§8.5).
  - Auditoría local inmutable (cadena de hashes) (§8.5).
  - `run_script` por catálogo (`script_id`), nunca código en el payload (§8.5).
"""

import base64
import hashlib
import json
import os
import time
from collections import deque
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding

from colsoft_tools.protocol import resolve_command
from colsoft_tools.tool_catalog import ALLOWED_TOOLS

# --- Catálogo de riesgo por comando (§8.4) ---
# Claves aceptadas: alias SRS (§8.4) y nombre interno del agente.
COMMAND_RISK: Dict[str, str] = {
    # A. Diagnóstico de red — Bajo
    "ping": "bajo",
    "traceroute": "bajo",
    "dns_lookup": "bajo",
    "dns_resolve": "bajo",
    "tcp_check": "bajo",
    "tcp_connect": "bajo",
    "http_check": "bajo",
    "http_get": "bajo",
    "tls_check": "bajo",
    "tls": "bajo",
    # B. Recolección de información
    "get_system_log": "medio",
    "system_log": "medio",
    "get_process_list": "bajo",
    "process_list": "bajo",
    "get_service_status": "bajo",
    "service_status": "bajo",
    "get_network_connections": "bajo",
    "network_connections": "bajo",
    "get_installed_software": "bajo",
    "installed_software": "bajo",
    "get_disk_usage": "bajo",
    "disk_usage": "bajo",
    "get_file_hash": "medio",
    "file_hash": "medio",
    "collect_forensic_snapshot": "medio",
    "forensic_snapshot": "medio",
    "collect_file": "alto",
    "get_system_metrics": "bajo",
    "system_metrics": "bajo",
    "get_hardware_inventory": "bajo",
    "hardware_inventory": "bajo",
    "run_health_probes": "bajo",
    "get_health_probes": "bajo",
    "health_probes": "bajo",
    # Seguridad base §11 (lectura; no remedia)
    "fim_scan": "medio",
    "get_fim_scan": "medio",
    "persistence_scan": "bajo",
    "get_persistence_scan": "bajo",
    "auth_audit": "medio",
    "get_auth_audit": "medio",
    "detection_scan": "bajo",
    "get_detection_scan": "bajo",
    "cis_score": "bajo",
    "get_cis_score": "bajo",
    "cve_inventory": "bajo",
    "get_cve_inventory": "bajo",
    "rootkit_check": "bajo",
    "get_rootkit_check": "bajo",
    "dns_monitor": "bajo",
    "get_dns_monitor": "bajo",
    "windows_event_log": "medio",
    "get_windows_event_log": "medio",
    "windows_etw": "bajo",
    "get_windows_etw": "bajo",
    "windows_autoruns": "bajo",
    "get_windows_autoruns": "bajo",
    "windows_wmi": "medio",
    "get_windows_wmi": "medio",
    "query_wmi": "medio",
    "windows_scheduled_tasks": "bajo",
    "get_windows_scheduled_tasks": "bajo",
    "get_scheduled_tasks": "bajo",
    "windows_sysmon": "bajo",
    "get_windows_sysmon": "bajo",
    "get_sysmon": "bajo",
    "windows_defender": "bajo",
    "get_windows_defender": "bajo",
    "get_defender_status": "bajo",
    "linux_ebpf": "bajo",
    "get_linux_ebpf": "bajo",
    "linux_auditd": "medio",
    "get_linux_auditd": "medio",
    "linux_syslog": "medio",
    "get_linux_syslog": "medio",
    "linux_proc_metrics": "bajo",
    "get_linux_proc_metrics": "bajo",
    "linux_netlink": "bajo",
    "get_linux_netlink": "bajo",
    "linux_systemd_units": "bajo",
    "get_linux_systemd_units": "bajo",
    "get_systemd_units": "bajo",
    "linux_lsm": "bajo",
    "get_linux_lsm": "bajo",
    "get_selinux_status": "bajo",
    "get_apparmor_status": "bajo",
    "linux_packages": "bajo",
    "get_linux_packages": "bajo",
    # C. Acciones de remediación
    "kill_process": "alto",
    "start_service": "medio-alto",
    "stop_service": "medio-alto",
    "restart_service": "medio-alto",
    "block_ip": "alto",
    "unblock_ip": "alto",
    "isolate_host": "critico",
    "restore_isolation": "critico",
    "run_script": "critico",
    # D. Administración del agente
    "update_config": "medio",
    "trigger_update": "bajo",
    "restart_agent": "medio",
    "health_check": "bajo",
}

# Comandos Alto/Crítico deshabilitados por defecto (§8.4/§8.5).
DEFAULT_DISABLED = {
    "collect_file",
    "kill_process",
    "block_ip",
    "unblock_ip",
    "isolate_host",
    "restore_isolation",
    "run_script",
}

# Comandos que requieren allowlist explícita por host/grupo (§8.4-C).
REQUIRES_ALLOWLIST = {
    "start_service",
    "stop_service",
    "restart_service",
}

# Catálogo SRS "Habilitado" cuando `allowed_commands` está vacío.
# Alto/Crítico y control de servicios no entran: hay que listarlos.
DEFAULT_ENABLED_COMMANDS = frozenset(
    c
    for c in ALLOWED_TOOLS
    if c not in DEFAULT_DISABLED and c not in REQUIRES_ALLOWLIST
)

# Timeout por defecto según riesgo (§8.5: timeout obligatorio).
DEFAULT_TIMEOUT_BY_RISK = {
    "bajo": 30.0,
    "medio": 60.0,
    "medio-alto": 60.0,
    "alto": 90.0,
    "critico": 120.0,
}
# Overrides por comando: herramientas con runtime natural mayor que el default
# de su riesgo (p.ej. traceroute recorre saltos y supera los 30s de 'bajo').
COMMAND_DEFAULT_TIMEOUT = {
    "traceroute": 120.0,
    "installed_software": 90.0,
    "linux_packages": 90.0,
    "cve_inventory": 90.0,
    "forensic_snapshot": 90.0,
    "collect_forensic_snapshot": 90.0,
    "fim_scan": 90.0,
    "windows_event_log": 90.0,
    "windows_etw": 60.0,
    "windows_autoruns": 60.0,
    "windows_scheduled_tasks": 60.0,
    "windows_sysmon": 60.0,
    "linux_ebpf": 60.0,
    "linux_netlink": 60.0,
    "linux_systemd_units": 60.0,
    "linux_auditd": 60.0,
    "linux_syslog": 60.0,
    "persistence_scan": 60.0,
    "detection_scan": 60.0,
    "windows_wmi": 60.0,
    "collect_file": 90.0,
    "run_script": 120.0,
}
MIN_TIMEOUT = 5.0
MAX_TIMEOUT = 300.0


def _read_pem(value: Optional[str]) -> Optional[str]:
    """Acepta PEM inline o ruta a un archivo .pem/.crt/.key/.pub."""
    if not value:
        return None
    text = str(value).strip()
    if "-----BEGIN" in text:
        return text
    if os.path.isfile(text):
        try:
            with open(text, "r", encoding="utf-8") as f:
                return f.read()
        except OSError:
            return None
    return text


def load_public_key(pem: Optional[str]):
    data = _read_pem(pem)
    if not data:
        return None
    try:
        return serialization.load_pem_public_key(data.encode("utf-8"))
    except Exception:
        return None


def load_private_key(pem: Optional[str]):
    data = _read_pem(pem)
    if not data:
        return None
    try:
        return serialization.load_pem_private_key(data.encode("utf-8"), password=None)
    except Exception:
        return None


# --- Firma por comando (Ed25519) ---

def command_canonical(
    message_id: str,
    agent_id: Optional[str],
    command: str,
    params: Dict[str, Any],
    issued_by: Optional[str],
    issued_at: Optional[str],
    expires_at: Optional[str],
) -> str:
    """Serialización canónica del command_request para firmar/verificar.

    Params se serializa de forma determinista (claves ordenadas, sin espacios)
    para que backend y agente produzcan siempre la misma cadena.
    """
    try:
        params_json = json.dumps(
            params or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
    except (TypeError, ValueError):
        params_json = "{}"
    return "\n".join(
        [
            str(message_id),
            str(agent_id or ""),
            str(command),
            str(issued_by or ""),
            str(issued_at or ""),
            str(expires_at or ""),
            params_json,
        ]
    )


def sign_command_ed25519(
    private_key_pem: str, canonical: str
) -> str:
    """Firma la cadena canónica y devuelve base64(ed25519_sig)."""
    key = load_private_key(private_key_pem)
    if key is None:
        raise ValueError("Llave de firma Ed25519 inválida o no configurada")
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError("La llave de firma no es Ed25519")
    sig = key.sign(canonical.encode("utf-8"))
    return base64.b64encode(sig).decode("utf-8")


def verify_command_signature(
    public_key_pem: Optional[str], canonical: str, signature_b64: Optional[str]
) -> bool:
    """Verifica la firma Ed25519 del comando contra la llave pública del enrollment."""
    if not public_key_pem or not signature_b64:
        return False
    key = load_public_key(public_key_pem)
    if key is None or not isinstance(key, ed25519.Ed25519PublicKey):
        return False
    try:
        key.verify(base64.b64decode(signature_b64), canonical.encode("utf-8"))
        return True
    except Exception:
        return False


# --- Verificación de la firma RSA del desafío (handshake) ---

def verify_rsa_challenge(
    public_key_pem: str, challenge: bytes, signature_b64: str
) -> bool:
    """Verifica que `signature_b64` es PKCS1v15+SHA256 de `challenge` con la llave RSA."""
    key = load_public_key(public_key_pem)
    if key is None:
        return False
    try:
        key.verify(
            base64.b64decode(signature_b64),
            challenge,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


# --- Política local (doble candado, §8.2/§8.5) ---

class CommandPolicy:
    """Allowlist local por host/grupo. Alto/Crítico deshabilitados por defecto."""

    def __init__(self, config: Dict[str, Any]):
        pol = config.get("policy") or {}
        self.allowed: set = {
            str(c) for c in (pol.get("allowed_commands") or []) if c
        }
        self.allow_high_risk: bool = bool(pol.get("allow_high_risk"))

    def check(self, command: str) -> Tuple[bool, str]:
        """Devuelve (permitido, razón_de_rechazo). `command` debe estar resuelto."""
        cmd = resolve_command((command or "").strip())
        if not cmd:
            return False, "Comando vacío"
        if cmd not in COMMAND_RISK and cmd not in ALLOWED_TOOLS:
            return False, f"Comando {cmd!r} desconocido (no está en el catálogo)"
        risk = COMMAND_RISK.get(cmd, COMMAND_RISK.get(command or "", "bajo"))

        # §8.4/§8.5: Alto/Crítico deshabilitados por defecto.
        # Hace falta allow_high_risk Y estar en allowed_commands (no basta el flag).
        if risk in ("alto", "critico"):
            if not self.allow_high_risk:
                return (
                    False,
                    f"Comando {cmd!r} (riesgo {risk}) deshabilitado por política local",
                )
            if cmd not in self.allowed:
                return (
                    False,
                    f"Comando {cmd!r} (riesgo {risk}) requiere allowed_commands explícito",
                )

        # §8.4-C: control de servicios requiere allowlist explícita (host/grupo),
        # incluso con allow_high_risk — lista blanca nominal de servicios.
        if cmd in REQUIRES_ALLOWLIST and cmd not in self.allowed:
            return (
                False,
                f"Comando {cmd!r} requiere allowlist explícita (§8.4-C)",
            )

        if self.allowed:
            if cmd not in self.allowed:
                return False, f"Comando {cmd!r} no está en la allowlist local"
        elif cmd not in DEFAULT_ENABLED_COMMANDS:
            return (
                False,
                f"Comando {cmd!r} no está habilitado por defecto (lista vacía = catálogo SRS bajo/medio)",
            )

        return True, ""


# --- Rate limiting (§8.5) ---

class RateLimiter:
    """Ventana deslizante por clave (agente, agente:comando, ...)."""

    def __init__(self, limit: int = 10, window: float = 60.0):
        self.limit = int(limit)
        self.window = float(window)
        self._events: Dict[str, deque] = {}

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        q = self._events.setdefault(key, deque())
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        return True

    def allow_per_command(self, agent_id: str, command: str) -> bool:
        if not self.allow(f"agent:{agent_id}"):
            return False
        return self.allow(f"agent:{agent_id}:cmd:{command}")


# --- Timeout obligatorio (§8.5) ---

def command_timeout(command: str, params: Optional[Dict[str, Any]] = None) -> float:
    """Timeout efectivo para un comando: riesgo por defecto, params/timeout como tope.

    Un override por comando (`COMMAND_DEFAULT_TIMEOUT`) gana sobre el default
    del riesgo para tools con runtime natural mayor (p.ej. traceroute).
    """
    cmd = resolve_command((command or "").strip())
    risk = COMMAND_RISK.get(cmd, COMMAND_RISK.get((command or "").strip(), "bajo"))
    default = COMMAND_DEFAULT_TIMEOUT.get(
        cmd, DEFAULT_TIMEOUT_BY_RISK.get(risk, 30.0)
    )
    t = default
    if params:
        try:
            if params.get("timeout_ms") is not None:
                t = float(params.get("timeout_ms")) / 1000.0
            elif params.get("timeout") is not None:
                t = float(params.get("timeout"))
            else:
                t = default
        except (TypeError, ValueError):
            t = default
    return min(max(t, MIN_TIMEOUT), MAX_TIMEOUT)


# --- Auditoría local inmutable (§8.5) ---

class AuditLog:
    """Log append-only con cadena de hashes (trazabilidad no repudiable).

    Cada registro enlaza el hash del anterior: alterar cualquier entrada
    invalida todos los hashes posteriores.
    """

    GENESIS = "genesis-0000-0000000000000000000000000000000000000000"

    def __init__(self, path: str):
        self.path = path
        if self.path:
            d = os.path.dirname(os.path.abspath(self.path))
            os.makedirs(d, exist_ok=True)
        self._prev_hash = self._load_tail_hash()

    def _load_tail_hash(self) -> str:
        if not self.path or not os.path.exists(self.path):
            return self.GENESIS
        last = None
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    last = line
        if last is None:
            return self.GENESIS
        try:
            return str(json.loads(last).get("hash") or self.GENESIS)
        except Exception:
            return self.GENESIS

    def append(self, record: Dict[str, Any]) -> Dict[str, Any]:
        from colsoft_tools.config_manager import DEFAULT_AUDIT_LOG_PATH

        if not self.path:
            self.path = DEFAULT_AUDIT_LOG_PATH
            d = os.path.dirname(os.path.abspath(self.path))
            os.makedirs(d, exist_ok=True)
            self._prev_hash = self._load_tail_hash()
        rec = dict(record or {})
        rec["ts"] = rec.get("ts") or time.time()
        canonical = json.dumps(
            rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
        )
        digest = hashlib.sha256(
            f"{self._prev_hash}|{canonical}".encode("utf-8")
        ).hexdigest()
        rec["prev_hash"] = self._prev_hash
        rec["hash"] = digest
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
            f.flush()
            os.fsync(f.fileno())
        self._prev_hash = digest
        return rec


# --- run_script por catálogo (§8.5) ---

def _file_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def script_catalog_canonical(script_id: str, path: str, sha256_hex: str) -> str:
    """Cadena firmada del catálogo: id + basename + hash (no el path absoluto)."""
    return "\n".join(
        [
            str(script_id or "").strip(),
            os.path.basename(str(path or "")),
            str(sha256_hex or "").strip().lower(),
        ]
    )


def resolve_script_from_catalog(
    config: Dict[str, Any], script_id: str
) -> Optional[str]:
    """Resuelve `script_id` a un script local con hash y firma Ed25519.

    Nunca se ejecuta código del payload. La entrada debe ser
    `{path, sha256, signature}` verificada contra `signing_public_key`.
    Un path suelto (string) se rechaza.
    """
    script_id = (script_id or "").strip()
    if not script_id:
        return None
    catalog = config.get("scripts_catalog")
    if not isinstance(catalog, dict):
        return None
    entry = catalog.get(script_id)
    if isinstance(entry, str):
        return None
    if not isinstance(entry, dict):
        return None
    path = str(entry.get("path") or "").strip()
    expected = str(entry.get("sha256") or "").strip().lower()
    signature = entry.get("signature")
    if not path or not os.path.isfile(path):
        return None
    try:
        digest = _file_sha256(path)
    except OSError:
        return None
    if not expected or digest != expected:
        return None
    pub = config.get("signing_public_key")
    canonical = script_catalog_canonical(script_id, path, digest)
    if not verify_command_signature(pub, canonical, signature if isinstance(signature, str) else None):
        return None
    return path
