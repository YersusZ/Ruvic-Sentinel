"""
Acciones de remediación para el agente de endpoint — SRS §8.4-C.

Cubren la categoría "C. Acciones de remediación" del catálogo de comandos
del SRS: kill_process, start_service/stop_service/restart_service,
block_ip/unblock_ip, isolate_host, restore_isolation y run_script por catálogo.

Todas las funciones devuelven dicts serializables a JSON y nunca lanzan
excepciones hacia afuera: cualquier error queda en el campo "error" del
resultado (mismo patrón que colsoft_tools.observability).

El habilitado/denegado por riesgo y allowlist se resuelve en
`colsoft_tools/security.CommandPolicy` (Alto/Crítico deshabilitados por
defecto, §8.4/§8.5); estas funciones SOLO ejecutan la acción ya autorizada.

Linux: iptables. Windows: netsh advfirewall. macOS: servicios via launchctl.
`kill_process` usa psutil en ambos SO (en Windows también coincide `name.exe`).
"""

import ipaddress
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def _iso_from_unix(ts: Optional[float]) -> Optional[str]:
    if ts is None:
        return None
    from datetime import datetime, timezone

    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OSError):
        return None


def _require_psutil():
    try:
        import psutil  # type: ignore
        return psutil
    except ImportError as e:
        raise RuntimeError(
            "psutil no está instalado. Agrega 'psutil' a requirements.txt "
            "e inclúyelo como hidden-import en el build de PyInstaller."
        ) from e


def _run(cmd: List[str], timeout: int = 20) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
    except FileNotFoundError:
        return subprocess.CompletedProcess(
            cmd, -1, "", f"comando no encontrado: {cmd[0]}"
        )


# ---------------------------------------------------------------------------
# kill_process — termina un proceso por PID o nombre
# ---------------------------------------------------------------------------

def kill_process(
    pid: Any = None,
    name: Optional[str] = None,
    force: bool = False,
    timeout: float = 5.0,
) -> Dict[str, Any]:
    """Termina un proceso por `pid` o por `name` (todos los que coincidan).

    `force=True` envía SIGKILL si no termina tras `timeout` (SIGTERM primero).
    Nunca se termina a sí mismo (evita matar al agente).
    """
    psutil = _require_psutil()
    try:
        my_pid = os.getpid()
        killed: List[int] = []
        errors: List[str] = []

        def _terminate(proc, label: str):
            try:
                if proc.pid == my_pid:
                    errors.append(f"rechazado: no se termina al propio agente (pid={my_pid})")
                    return
                proc.terminate()
                # Espera activa: un proceso huérfano/zombie se considera
                # terminado aunque su padre no lo haya recogido aún (psutil
                # wait() puede colgarse en ese caso).
                deadline = time.monotonic() + float(timeout)
                while time.monotonic() < deadline:
                    try:
                        if proc.status() in (
                            psutil.STATUS_ZOMBIE,
                            psutil.STATUS_DEAD,
                        ):
                            break
                    except psutil.NoSuchProcess:
                        break
                    time.sleep(0.1)
                else:
                    if force:
                        proc.kill()
                        proc.wait(timeout=float(timeout))
                    else:
                        errors.append(f"pid {proc.pid} no terminó (use force=true)")
                        return
                killed.append(proc.pid)
            except psutil.NoSuchProcess:
                errors.append(f"{label}: proceso inexistente")
            except psutil.AccessDenied:
                errors.append(f"{label}: permisos insuficientes")

        if pid is not None:
            try:
                proc = psutil.Process(int(pid))
                _terminate(proc, f"pid {pid}")
            except (ValueError, TypeError):
                return {
                    "tool": "kill_process", "status": "ERROR",
                    "error": f"pid inválido: {pid!r}",
                }
            except psutil.NoSuchProcess:
                return {
                    "tool": "kill_process", "status": "ERROR",
                    "error": f"proceso con pid={pid} no existe",
                }
        elif name:
            target = str(name).strip()
            if not target:
                return {"tool": "kill_process", "status": "ERROR", "error": "name vacío"}
            found = False
            for proc in psutil.process_iter(["pid", "name", "cmdline"]):
                pname = proc.info.get("name") or ""
                cl = " ".join(proc.info.get("cmdline") or [])
                if _process_name_matches(target, pname, cl):
                    found = True
                    _terminate(proc, f"name={target!r} pid={proc.pid}")
            if not found:
                return {
                    "tool": "kill_process", "status": "ERROR",
                    "error": f"no se encontró ningún proceso con name={target!r}",
                }
        else:
            return {
                "tool": "kill_process", "status": "ERROR",
                "error": "se requiere 'pid' o 'name'",
            }

        status = "OK" if killed else "ERROR"
        return {
            "tool": "kill_process",
            "status": status,
            "os": platform.system(),
            "killed": killed,
            "errors": errors,
            "error": "; ".join(errors) if errors else None,
        }
    except Exception as e:
        return {"tool": "kill_process", "status": "ERROR", "error": str(e)}


# ---------------------------------------------------------------------------
# start_service / stop_service / restart_service
# ---------------------------------------------------------------------------

def _service_linux(action: str, service_name: str) -> Dict[str, Any]:
    cmd = ["systemctl", action, service_name]
    res = _run(cmd, timeout=60)
    if res.returncode != 0:
        return {
            "tool": f"{action}_service",
            "status": "ERROR",
            "action": action,
            "service_name": service_name,
            "returncode": res.returncode,
            "error": res.stderr.strip() or res.stdout.strip() or "systemctl falló",
        }
    show = _run(["systemctl", "show", service_name, "--no-page",
                 "--property=ActiveState,SubState"])
    props = dict(
        line.split("=", 1) for line in show.stdout.strip().splitlines() if "=" in line
    )
    return {
        "tool": f"{action}_service",
        "status": "OK",
        "os": "Linux",
        "backend": "systemctl",
        "action": action,
        "service_name": service_name,
        "returncode": 0,
        "active_state": props.get("ActiveState"),
        "sub_state": props.get("SubState"),
        "error": None,
    }


def _service_windows(action: str, service_name: str) -> Dict[str, Any]:
    if action == "restart":
        res1 = _run(["sc", "stop", service_name], timeout=60)
        res2 = _run(["sc", "start", service_name], timeout=60)
        res = res2 if res2.returncode == 0 else res1
    else:
        res = _run(["sc", action, service_name], timeout=60)
    if res.returncode != 0:
        return {
            "tool": f"{action}_service",
            "status": "ERROR",
            "action": action,
            "service_name": service_name,
            "returncode": res.returncode,
            "error": res.stderr.strip() or res.stdout.strip() or "sc falló",
        }
    from colsoft_tools.observability import _windows_scm_state

    query = _run(["sc", "query", service_name], timeout=20)
    state = None
    for line in (query.stdout or "").splitlines():
        if "STATE" in line:
            state = line.strip()
            break
    parsed = _windows_scm_state(state)
    return {
        "tool": f"{action}_service",
        "status": "OK",
        "os": "Windows",
        "backend": "sc",
        "action": action,
        "service_name": service_name,
        "returncode": 0,
        "raw": res.stdout.strip(),
        "raw_state": state,
        "active_state": parsed.get("active_state"),
        "sub_state": parsed.get("sub_state"),
        "error": None,
    }


def control_service(action: str, service_name: str) -> Dict[str, Any]:
    """start | stop | restart de un servicio/daemon (SRS §8.4-C)."""
    action = (action or "").strip().lower()
    service_name = (service_name or "").strip()
    if action not in ("start", "stop", "restart"):
        return {
            "tool": "start_service", "status": "ERROR",
            "error": f"acción inválida: {action!r}",
        }
    if not service_name:
        return {
            "tool": f"{action}_service", "status": "ERROR",
            "error": "se requiere 'service_name'",
        }
    system = platform.system()
    try:
        if system == "Linux":
            return _service_linux(action, service_name)
        if system == "Windows":
            return _service_windows(action, service_name)
        if system == "Darwin":
            cmd = {
                "start": ["launchctl", "load", service_name],
                "stop": ["launchctl", "unload", service_name],
                "restart": ["launchctl", "kickstart", f"-k system/{service_name}"],
            }.get(action)
            res = _run(cmd or [], timeout=60)
            from colsoft_tools.observability import _service_status_macos

            listed = _service_status_macos(service_name)
            row = (listed.get("services") or [None])[0] if isinstance(listed, dict) else None
            row = row if isinstance(row, dict) else {}
            return {
                "tool": f"{action}_service",
                "status": "OK" if res.returncode == 0 else "ERROR",
                "os": "Darwin",
                "backend": "launchctl",
                "action": action,
                "service_name": service_name,
                "returncode": res.returncode,
                "active_state": row.get("active_state"),
                "sub_state": row.get("sub_state"),
                "error": None if res.returncode == 0 else (res.stderr.strip() or "launchctl falló"),
            }
        return {
            "tool": f"{action}_service", "status": "ERROR",
            "error": f"SO no soportado: {system}",
        }
    except Exception as e:
        return {"tool": f"{action}_service", "status": "ERROR", "error": str(e)}


# ---------------------------------------------------------------------------
# block_ip / unblock_ip — regla de firewall puntual (iptables en Linux)
# ---------------------------------------------------------------------------

_CHAIN_BY_DIRECTION = {
    "input": "INPUT",
    "output": "OUTPUT",
    "forward": "FORWARD",
}


def _is_root() -> bool:
    try:
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except AttributeError:
        return False


def _is_windows() -> bool:
    return platform.system() == "Windows"


def _is_privileged() -> bool:
    if _is_windows():
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False
    return _is_root()


def _normalize_direction(direction: Optional[str]) -> Optional[str]:
    raw = (direction or "input").strip().lower()
    aliases = {
        "in": "input",
        "inbound": "input",
        "out": "output",
        "outbound": "output",
        "fwd": "forward",
    }
    mapped = aliases.get(raw, raw)
    if mapped in _CHAIN_BY_DIRECTION:
        return mapped
    return None


def _process_name_matches(target: str, proc_name: str, cmdline: str) -> bool:
    t = (target or "").strip().lower()
    if not t:
        return False
    pname = (proc_name or "").lower()
    cl = (cmdline or "").lower()
    t_exe = t if t.endswith(".exe") else f"{t}.exe"
    p_stem = pname[:-4] if pname.endswith(".exe") else pname
    return (
        t in pname
        or t_exe == pname
        or t == p_stem
        or t in cl
        or t_exe in cl
    )


def _firewall_rule(
    action: str, ip: str, direction: str = "input"
) -> Dict[str, Any]:
    action = (action or "").strip()
    mapped = _normalize_direction(direction)
    if not mapped:
        return {
            "tool": f"{action}_ip", "status": "ERROR",
            "error": f"direction inválido: {direction!r} (input|output|forward)",
        }
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {
            "tool": f"{action}_ip", "status": "ERROR",
            "error": f"ip inválida: {ip!r}",
        }
    system = platform.system()
    if system == "Windows":
        return _firewall_windows(action, ip, mapped)
    if system != "Linux":
        return {
            "tool": f"{action}_ip", "status": "UNSUPPORTED",
            "os": system,
            "error": f"firewall no implementado en {system} (Linux iptables / Windows netsh)",
        }
    chain = _CHAIN_BY_DIRECTION[mapped]
    if not _is_privileged():
        return {
            "tool": f"{action}_ip", "status": "ERROR",
            "os": "Linux",
            "error": "se requiere root para modificar iptables",
        }
    if shutil.which("iptables") is None:
        return {
            "tool": f"{action}_ip", "status": "ERROR",
            "error": "iptables no está instalado",
        }

    flag = "-A" if action == "block" else "-D"
    if mapped in ("input", "forward"):
        rule = [flag, chain, "-s", ip, "-j", "DROP"]
    else:
        rule = [flag, chain, "-d", ip, "-j", "DROP"]
    res = _run(["iptables", *rule], timeout=20)
    if res.returncode != 0:
        return {
            "tool": f"{action}_ip", "status": "ERROR",
            "os": "Linux",
            "direction": mapped,
            "ip": ip,
            "returncode": res.returncode,
            "error": res.stderr.strip() or "iptables falló",
        }
    return {
        "tool": f"{action}_ip",
        "status": "OK",
        "os": "Linux",
        "backend": "iptables",
        "action": action,
        "direction": mapped,
        "ip": ip,
        "rule": "iptables " + " ".join(rule),
        "rules": ["iptables " + " ".join(rule)],
        "error": None,
    }


def _windows_block_rule_name(direction: str, ip: str) -> str:
    """Nombre estable: block y unblock deben referir la misma regla netsh."""
    return f"robin-block-{direction}-{ip}".replace(":", "-")


def _firewall_windows(action: str, ip: str, direction: str) -> Dict[str, Any]:
    if not shutil.which("netsh"):
        return {
            "tool": f"{action}_ip", "status": "ERROR",
            "os": "Windows",
            "error": "netsh no está en PATH",
        }
    if not _is_privileged():
        return {
            "tool": f"{action}_ip", "status": "ERROR",
            "os": "Windows",
            "error": "se requiere Administrador para netsh advfirewall",
        }
    dirs = ("in", "out") if direction == "forward" else (
        ("in",) if direction == "input" else ("out",)
    )
    errors: List[str] = []
    applied: List[str] = []
    for d in dirs:
        name = _windows_block_rule_name(d, ip)
        if action == "block":
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={name}", f"dir={d}", "action=block", f"remoteip={ip}",
            ]
        else:
            cmd = [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={name}",
            ]
        res = _run(cmd, timeout=20)
        if res.returncode != 0:
            errors.append((res.stderr or res.stdout or "netsh falló").strip()[:300])
        else:
            applied.append(" ".join(cmd))
    if errors and not applied:
        return {
            "tool": f"{action}_ip",
            "status": "ERROR",
            "os": "Windows",
            "backend": "netsh",
            "direction": direction,
            "ip": ip,
            "error": "; ".join(errors),
        }
    return {
        "tool": f"{action}_ip",
        "status": "OK",
        "os": "Windows",
        "backend": "netsh",
        "action": action,
        "direction": direction,
        "ip": ip,
        "rule": applied[0] if len(applied) == 1 else "; ".join(applied),
        "rules": applied,
        "error": "; ".join(errors) if errors else None,
    }


def block_ip(ip: str, direction: str = "input") -> Dict[str, Any]:
    """Aplica una regla DROP puntual para `ip` (SRS §8.4-C, Alto)."""
    return _firewall_rule("block", ip, direction)


def unblock_ip(ip: str, direction: str = "input") -> Dict[str, Any]:
    """Elimina la regla DROP puntual para `ip` (SRS §8.4-C, Alto)."""
    return _firewall_rule("unblock", ip, direction)


# ---------------------------------------------------------------------------
# isolate_host — aísla la red del host excepto hacia el manager
# ---------------------------------------------------------------------------

_STATE_FILE = "remediation_state.json"


def _state_path() -> str:
    return os.environ.get(
        "REMEDIATION_STATE_FILE"
    ) or os.path.join(os.getcwd(), _STATE_FILE)


def _load_state() -> Dict[str, Any]:
    try:
        with open(_state_path(), "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_state(state: Dict[str, Any]) -> bool:
    try:
        path = _state_path()
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)
        return True
    except OSError:
        return False


def _iptables_safe(args: List[str]) -> str:
    try:
        res = subprocess.run(
            ["iptables", *args], capture_output=True, text=True, timeout=20
        )
        return res.stderr.strip() or ""
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return str(e)


def _apply_rules(rules: List[List[str]]) -> List[str]:
    errors = []
    for rule in rules:
        err = _iptables_safe(rule)
        if err:
            errors.append(f"{' '.join(rule)}: {err}")
    return errors


def _remove_rules(rules: List[List[str]]) -> List[str]:
    errors = []
    for rule in reversed(rules):
        if not rule:
            continue
        delete = list(rule)
        # -I → -D para revertir la misma regla
        if delete[0] == "-I":
            delete[0] = "-D"
        err = _iptables_safe(delete)
        if err:
            errors.append(f"{' '.join(delete)}: {err}")
    return errors


def _restore_isolate(rules: List[List[str]]) -> None:
    _remove_rules(rules)
    state = _load_state()
    state.pop("isolate_rules", None)
    state.pop("isolate_until", None)
    _save_state(state)


def _schedule_restore(rules: List[List[str]], duration: float) -> None:
    def _restore() -> None:
        time.sleep(max(float(duration), 1.0))
        _restore_isolate(rules)

    threading.Thread(target=_restore, daemon=True).start()


def manager_host_from_config(config: Optional[Dict[str, Any]]) -> Optional[str]:
    """IP del servidor de control a partir de `websocket_url` (no  usa 127.0.0.1 a ciegas)."""
    if not isinstance(config, dict):
        return None
    raw = str(config.get("websocket_url") or "").strip()
    if not raw:
        return None
    host = (urlsplit(raw).hostname or "").strip()
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
        if infos:
            return str(infos[0][4][0])
    except OSError:
        return None
    return None


def resume_isolation_timer() -> Optional[str]:
    """Al arrancar el agente: revertir aislamiento expirado o reprogramar el hilo."""
    state = _load_state()
    linux_rules = state.get("isolate_rules") or []
    win_rules = state.get("isolate_windows_rules") or []
    if not linux_rules and not win_rules:
        return None
    until = state.get("isolate_until")
    if until is None:
        return "isolated_until_restore"
    try:
        remaining = float(until) - time.time()
    except (TypeError, ValueError):
        remaining = -1.0
    if remaining <= 0:
        restore_isolation()
        return "expired_restored"
    if win_rules:
        names = list(win_rules)

        def _restore() -> None:
            time.sleep(max(remaining, 1.0))
            _restore_isolate_windows(names)

        threading.Thread(target=_restore, daemon=True).start()
    elif linux_rules:
        _schedule_restore(list(linux_rules), remaining)
    return f"timer_resumed_{int(remaining)}s"


def isolate_host(
    reason: Optional[str] = None,
    duration: Optional[float] = None,
    manager_host: Optional[str] = None,
    duration_seconds: Optional[float] = None,
) -> Dict[str, Any]:
    """Aísla la red del host excepto hacia `manager_host` y loopback (§8.4-C, Crítico).

    Linux: iptables DROP en INPUT/OUTPUT/FORWARD con excepciones.
    Windows: netsh advfirewall (bloquear perfiles + allow al manager).
    Si `duration`/`duration_seconds` es positivo, se revierte después.
    """
    system = platform.system()
    manager = (manager_host or "").strip() or "127.0.0.1"
    try:
        ipaddress.ip_address(manager)
    except ValueError:
        return {
            "tool": "isolate_host", "status": "ERROR",
            "error": f"manager_host inválido: {manager!r}",
        }
    try:
        raw_dur = duration if duration is not None else duration_seconds
        dur = float(raw_dur or 0)
    except (TypeError, ValueError):
        dur = 0.0

    if system == "Windows":
        return _isolate_windows(reason, dur, manager)
    if system != "Linux":
        return {
            "tool": "isolate_host", "status": "UNSUPPORTED",
            "os": system,
            "error": f"aislamiento no implementado en {system} (Linux iptables / Windows netsh)",
        }
    if not _is_privileged():
        return {
            "tool": "isolate_host", "status": "ERROR",
            "os": "Linux",
            "error": "se requiere root para aislar la red (iptables)",
        }
    if shutil.which("iptables") is None:
        return {
            "tool": "isolate_host", "status": "ERROR",
            "error": "iptables no está instalado",
        }

    state = _load_state()
    prev_rules = state.get("isolate_rules") or []
    if prev_rules:
        _remove_rules(prev_rules)
    if state.get("isolate_windows_rules"):
        _remove_windows_isolate(state.get("isolate_windows_rules") or [])

    rules: List[List[str]] = []
    for chain in ("INPUT", "OUTPUT"):
        rules.append(["-I", chain, "1", "-j", "DROP"])
        rules.append(["-I", chain, "1", "-m", "conntrack",
                      "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
        rules.append(["-I", chain, "1", "-i" if chain == "INPUT" else "-o",
                      "lo", "-j", "ACCEPT"])
        if chain == "INPUT":
            rules.append(["-I", chain, "1", "-s", manager, "-j", "ACCEPT"])
        else:
            rules.append(["-I", chain, "1", "-d", manager, "-j", "ACCEPT"])
    rules.append(["-I", "FORWARD", "1", "-j", "DROP"])

    errors = _apply_rules(rules)
    if errors:
        _remove_rules(rules)
        return {
            "tool": "isolate_host", "status": "ERROR",
            "os": "Linux",
            "error": "no se pudo aplicar el aislamiento: " + "; ".join(errors),
        }

    until = None
    if dur > 0:
        until = time.time() + dur
        _schedule_restore(rules, dur)

    state["isolate_backend"] = "iptables"
    state["isolate_rules"] = rules
    state["isolate_windows_rules"] = []
    state["isolate_until"] = until
    state["isolate_reason"] = reason
    state["isolate_ts"] = time.time()
    if not _save_state(state):
        _remove_rules(rules)
        return {
            "tool": "isolate_host",
            "status": "ERROR",
            "os": "Linux",
            "error": "aislamiento aplicado pero no se pudo persistir el estado; se revirtió",
        }

    return {
        "tool": "isolate_host",
        "status": "OK",
        "os": "Linux",
        "backend": "iptables",
        "reason": reason,
        "manager_host": manager,
        "rules": [f"iptables {' '.join(r)}" for r in rules],
        "expires_at": _iso_from_unix(until),
        "restore_after_s": dur if dur > 0 else None,
        "error": None,
    }


_WIN_ISOLATE_POLICY = "blockinbound,blockoutbound"
_WIN_ISOLATE_RULES = (
    "robin-isolate-mgr-in",
    "robin-isolate-mgr-out",
    "robin-isolate-lo-in",
    "robin-isolate-lo-out",
)


def _netsh_ok(args: List[str]) -> str:
    res = _run(["netsh", *args], timeout=20)
    if res.returncode != 0:
        return (res.stderr or res.stdout or "netsh falló").strip()[:400]
    return ""


def _remove_windows_isolate(rule_names: List[str]) -> List[str]:
    errors: List[str] = []
    for name in rule_names:
        err = _netsh_ok(["advfirewall", "firewall", "delete", "rule", f"name={name}"])
        if err and "No rules match" not in err and "ninguna" not in err.lower():
            errors.append(f"{name}: {err}")
    err = _netsh_ok(
        ["advfirewall", "set", "allprofiles", "firewallpolicy", "notconfigured"]
    )
    if err:
        errors.append(f"policy: {err}")
    return errors


def _isolate_windows(
    reason: Optional[str], duration: float, manager: str
) -> Dict[str, Any]:
    if not shutil.which("netsh"):
        return {
            "tool": "isolate_host", "status": "ERROR",
            "os": "Windows",
            "error": "netsh no está en PATH",
        }
    if not _is_privileged():
        return {
            "tool": "isolate_host", "status": "ERROR",
            "os": "Windows",
            "error": "se requiere Administrador para aislar con Windows Firewall",
        }

    state = _load_state()
    prev_win = state.get("isolate_windows_rules") or []
    if prev_win:
        _remove_windows_isolate(prev_win)
    if state.get("isolate_rules"):
        _remove_rules(state.get("isolate_rules") or [])

    cmds = [
        ["advfirewall", "set", "allprofiles", "firewallpolicy", _WIN_ISOLATE_POLICY],
        [
            "advfirewall", "firewall", "add", "rule",
            f"name={_WIN_ISOLATE_RULES[0]}", "dir=in", "action=allow",
            f"remoteip={manager}",
        ],
        [
            "advfirewall", "firewall", "add", "rule",
            f"name={_WIN_ISOLATE_RULES[1]}", "dir=out", "action=allow",
            f"remoteip={manager}",
        ],
        [
            "advfirewall", "firewall", "add", "rule",
            f"name={_WIN_ISOLATE_RULES[2]}", "dir=in", "action=allow",
            "remoteip=127.0.0.1",
        ],
        [
            "advfirewall", "firewall", "add", "rule",
            f"name={_WIN_ISOLATE_RULES[3]}", "dir=out", "action=allow",
            "remoteip=127.0.0.1",
        ],
    ]
    errors = []
    applied = []
    for args in cmds:
        err = _netsh_ok(args)
        if err:
            errors.append(err)
        else:
            applied.append("netsh " + " ".join(args))
    if errors:
        _remove_windows_isolate(list(_WIN_ISOLATE_RULES))
        return {
            "tool": "isolate_host", "status": "ERROR",
            "os": "Windows",
            "backend": "netsh",
            "error": "no se pudo aplicar el aislamiento: " + "; ".join(errors),
        }

    until = None
    if duration > 0:
        until = time.time() + duration
        names = list(_WIN_ISOLATE_RULES)

        def _restore() -> None:
            time.sleep(max(float(duration), 1.0))
            _restore_isolate_windows(names)

        threading.Thread(target=_restore, daemon=True).start()

    state["isolate_backend"] = "netsh"
    state["isolate_rules"] = []
    state["isolate_windows_rules"] = list(_WIN_ISOLATE_RULES)
    state["isolate_until"] = until
    state["isolate_reason"] = reason
    state["isolate_ts"] = time.time()
    if not _save_state(state):
        _remove_windows_isolate(list(_WIN_ISOLATE_RULES))
        return {
            "tool": "isolate_host",
            "status": "ERROR",
            "os": "Windows",
            "error": "aislamiento aplicado pero no se pudo persistir el estado; se revirtió",
        }

    return {
        "tool": "isolate_host",
        "status": "OK",
        "os": "Windows",
        "backend": "netsh",
        "reason": reason,
        "manager_host": manager,
        "rules": applied,
        "expires_at": _iso_from_unix(until),
        "restore_after_s": duration if duration > 0 else None,
        "error": None,
    }


def _restore_isolate_windows(rule_names: List[str]) -> None:
    _remove_windows_isolate(rule_names)
    state = _load_state()
    state.pop("isolate_windows_rules", None)
    state.pop("isolate_until", None)
    state.pop("isolate_backend", None)
    _save_state(state)


def restore_isolation() -> Dict[str, Any]:
    """Revierte un aislamiento previo (reglas guardadas en el estado)."""
    state = _load_state()
    linux_rules = state.get("isolate_rules") or []
    win_rules = state.get("isolate_windows_rules") or []
    if not linux_rules and not win_rules:
        return {
            "tool": "restore_isolation", "status": "OK",
            "error": None, "restored": False,
        }
    errors: List[str] = []
    if linux_rules:
        errors.extend(_remove_rules(linux_rules))
    if win_rules:
        errors.extend(_remove_windows_isolate(win_rules))
    state.pop("isolate_rules", None)
    state.pop("isolate_windows_rules", None)
    state.pop("isolate_until", None)
    state.pop("isolate_backend", None)
    _save_state(state)
    return {
        "tool": "restore_isolation", "status": "OK" if not errors else "ERROR",
        "restored": True,
        "error": "; ".join(errors) if errors else None,
    }


# ---------------------------------------------------------------------------
# run_script — ejecuta un script del catálogo firmado (nunca código del payload)
# ---------------------------------------------------------------------------

def _script_argv(script_path: str, arg_list: List[str]) -> List[str]:
    """Intérprete según SO y extensión. En Windows no asume bash."""
    ext = os.path.splitext(script_path)[1].lower()
    args = list(arg_list)
    if platform.system() == "Windows":
        if ext == ".ps1":
            return [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                script_path,
                *args,
            ]
        if ext in (".bat", ".cmd"):
            comspec = os.environ.get("COMSPEC") or "cmd.exe"
            return [comspec, "/c", script_path, *args]
        if ext == ".py":
            return [sys.executable or "python", script_path, *args]
        return [script_path, *args]
    if os.access(script_path, os.X_OK):
        return [script_path, *args]
    if ext == ".py":
        return [sys.executable or "python3", script_path, *args]
    return ["bash", script_path, *args]


def execute_script(
    script_path: str,
    args: Any = None,
    timeout: float = 120.0,
    max_chars: int = 0,
) -> Dict[str, Any]:
    """Ejecuta un script aprobado (`script_path` del catálogo) con `args`.

    Nunca recibe código del payload: solo la ruta resuelta por `script_id`
    desde el catálogo local firmado (§8.5).
    """
    if not script_path or not os.path.isfile(script_path):
        return {
            "tool": "run_script", "status": "ERROR",
            "error": f"script no encontrado en el catálogo: {script_path!r}",
        }

    arg_list: List[str] = []
    if isinstance(args, list):
        arg_list = [str(a) for a in args]
    elif isinstance(args, str) and args.strip():
        arg_list = args.split()

    try:
        t = float(timeout or 120)
        t = min(max(t, 1.0), 300.0)
    except (TypeError, ValueError):
        t = 120.0

    started = time.time()
    cmd = _script_argv(script_path, arg_list)
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=t)
    except FileNotFoundError:
        return {
            "tool": "run_script", "status": "ERROR",
            "error": f"intérprete/script no disponible para {script_path!r}",
        }
    except subprocess.TimeoutExpired:
        return {
            "tool": "run_script", "status": "ERROR",
            "error": f"timeout ({t}s) excedido ejecutando {script_path!r}",
        }
    except Exception as e:
        return {"tool": "run_script", "status": "ERROR", "error": str(e)}

    duration_ms = int((time.time() - started) * 1000)
    ok = res.returncode == 0
    out = res.stdout or ""
    if max_chars and max_chars > 0 and len(out) > max_chars:
        out = out[:max_chars] + f"\n...[truncated to {max_chars} chars]"
    return {
        "tool": "run_script",
        "status": "OK" if ok else "ERROR",
        "script_path": script_path,
        "args": arg_list,
        "returncode": res.returncode,
        "stdout": out,
        "stderr": (res.stderr or "")[:2000] if not ok else None,
        "duration_ms": duration_ms,
        "error": None if ok else (res.stderr.strip() or f"returncode={res.returncode}"),
    }