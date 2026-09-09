"""
Collectors de seguridad de endpoint — SRS §11 (RF-SEC-01..08).

Tools on-demand (mismo patrón que `observability.py`): nunca lanzan hacia
afuera; el error va en el dict. Los loops periódicos viven en
`colsoft_tools/sec_monitors.py`.

  RF-SEC-01  FIM (SHA-256 + usuario + proceso)
  RF-SEC-02  Persistencia (Win: Run/services/tasks; Linux: cron/timers/keys)
  RF-SEC-03  Auditoría de autenticación (logon/logoff, fallos, sudo/su)
  RF-SEC-04  Motor de reglas locales + MITRE ATT&CK
  RF-SEC-05  Inventario canónico para correlación CVE (el motor es backend)
  RF-SEC-06  Score de hardening CIS (subset Level 1)
  RF-SEC-07  DNS (dominio + proceso origen, best-effort)
  RF-SEC-08  Heurísticas de rootkit
"""

from __future__ import annotations

import hashlib
import os
import platform
import re
import shutil
import stat
import subprocess

try:
    import pwd
except ImportError:  # Windows
    pwd = None  # type: ignore[assignment]
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_windows() -> bool:
    return platform.system() == "Windows"


def _is_linux() -> bool:
    return platform.system() == "Linux"


def _unsupported(tool: str) -> Dict[str, Any]:
    return {
        "tool": tool,
        "status": "UNSUPPORTED",
        "os": platform.system(),
        "error": f"{tool} no está implementado en {platform.system()}",
    }


def _run(cmd: List[str], timeout: int = 15) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
    except FileNotFoundError:
        return subprocess.CompletedProcess(
            cmd, -1, "", f"comando no encontrado: {cmd[0]}"
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, -1, "", "timeout")


def _read_text(path: str, max_bytes: int = 256 * 1024) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(max_bytes)
    except OSError:
        return None


def _sha256_file(path: str, max_bytes: int = 64 * 1024 * 1024) -> Optional[str]:
    try:
        if not path or not os.path.isfile(path):
            return None
        if os.path.getsize(path) > max_bytes:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _username_for_uid(uid: int) -> Optional[str]:
    if pwd is None:
        return None
    try:
        return pwd.getpwuid(uid).pw_name
    except (KeyError, TypeError, OverflowError, AttributeError):
        return None


def _file_meta(path: str) -> Dict[str, Any]:
    """SHA-256 + dueño + mtime. Usuario vía st_uid (Linux) o owner (Win)."""
    info: Dict[str, Any] = {"path": path, "exists": os.path.lexists(path)}
    try:
        st = os.lstat(path)
    except OSError as e:
        info["error"] = str(e)
        return info
    info.update(
        {
            "size": st.st_size,
            "mtime": datetime.fromtimestamp(
                st.st_mtime, tz=timezone.utc
            ).isoformat(),
            "mode": oct(st.st_mode & 0o777),
            "uid": getattr(st, "st_uid", None),
            "gid": getattr(st, "st_gid", None),
            "is_file": stat.S_ISREG(st.st_mode),
            "is_dir": stat.S_ISDIR(st.st_mode),
            "is_link": stat.S_ISLNK(st.st_mode),
        }
    )
    uid = info.get("uid")
    if isinstance(uid, int) and not _is_windows():
        info["user"] = _username_for_uid(uid)
    if info.get("is_file") and not info.get("is_link"):
        info["sha256"] = _sha256_file(path)
    return info


def _process_for_path(path: str) -> Optional[Dict[str, Any]]:
    """Proceso que tiene el archivo abierto (lsof/fuser). Best-effort."""
    if shutil.which("lsof"):
        res = _run(["lsof", "-nP", "-F", "pcn", "--", path], timeout=8)
        pid = name = cmd = None
        for line in (res.stdout or "").splitlines():
            if not line:
                continue
            tag, val = line[0], line[1:]
            if tag == "p":
                if pid is not None:
                    break
                try:
                    pid = int(val)
                except ValueError:
                    pid = None
            elif tag == "c":
                name = val
            elif tag == "n" and cmd is None:
                cmd = val
        if pid:
            return {"pid": pid, "name": name, "path": cmd or path}
    if shutil.which("fuser"):
        res = _run(["fuser", "-v", path], timeout=8)
        text = (res.stderr or "") + "\n" + (res.stdout or "")
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[1].isdigit():
                try:
                    return {
                        "pid": int(parts[1]),
                        "name": parts[0],
                        "user": parts[0] if not parts[0].isdigit() else None,
                    }
                except ValueError:
                    continue
    return None


def _expand_paths(paths: Iterable[str], *, max_files: int = 400) -> List[str]:
    """Archivos regulares a vigilar. Un directorio aporta sus hijos (1 nivel)."""
    out: List[str] = []
    seen = set()
    for raw in paths or []:
        path = os.path.expanduser(os.path.expandvars(str(raw).strip()))
        if not path or path in seen:
            continue
        if os.path.isdir(path) and not os.path.islink(path):
            try:
                names = sorted(os.listdir(path))
            except OSError:
                continue
            for name in names:
                if len(out) >= max_files:
                    return out
                child = os.path.join(path, name)
                if child in seen:
                    continue
                if os.path.isfile(child) and not os.path.islink(child):
                    seen.add(child)
                    out.append(child)
            continue
        seen.add(path)
        out.append(path)
        if len(out) >= max_files:
            break
    return out


def default_fim_paths() -> List[str]:
    if _is_windows():
        windir = os.environ.get("WINDIR", r"C:\Windows")
        return [
            os.path.join(windir, r"System32\drivers\etc\hosts"),
            os.path.join(windir, r"System32\drivers\etc\lmhosts"),
        ]
    paths = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/sudoers",
        "/etc/hosts",
        "/etc/hostname",
        "/etc/crontab",
        "/etc/ssh/sshd_config",
        "/etc/login.defs",
    ]
    return [p for p in paths if os.path.exists(p)] + [
        p for p in ("/etc/sudoers.d", "/etc/cron.d", "/etc/ssh/sshd_config.d")
        if os.path.isdir(p)
    ]


# ---------------------------------------------------------------------------
# RF-SEC-01 File Integrity Monitoring
# ---------------------------------------------------------------------------


def fim_scan(
    paths: Optional[List[str]] = None,
    *,
    include_process: bool = True,
) -> Dict[str, Any]:
    """Snapshot FIM: hash SHA-256, usuario dueño y proceso (si hay handle)."""
    try:
        watch = _expand_paths(paths if paths else default_fim_paths())
        files: List[Dict[str, Any]] = []
        for path in watch:
            rec = _file_meta(path)
            if include_process and rec.get("exists") and rec.get("is_file"):
                proc = _process_for_path(path)
                if proc:
                    rec["process"] = proc
            files.append(rec)
        return {
            "tool": "fim_scan",
            "status": "OK",
            "count": len(files),
            "files": files,
            "ts": _now_iso(),
            "error": None,
        }
    except Exception as e:
        return {"tool": "fim_scan", "status": "ERROR", "error": str(e)}


def fim_baseline_from_scan(scan: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Índice path → {sha256, mtime, uid, user} para diffs."""
    out: Dict[str, Dict[str, Any]] = {}
    for rec in scan.get("files") or []:
        path = rec.get("path")
        if not path:
            continue
        out[str(path)] = {
            "sha256": rec.get("sha256"),
            "mtime": rec.get("mtime"),
            "uid": rec.get("uid"),
            "user": rec.get("user"),
            "size": rec.get("size"),
            "exists": rec.get("exists"),
        }
    return out


def fim_diff(
    previous: Dict[str, Dict[str, Any]],
    current: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Cambios created/deleted/modified entre dos baselines FIM."""
    events: List[Dict[str, Any]] = []
    prev_keys = set(previous or {})
    curr_keys = set(current or {})
    for path in sorted(curr_keys - prev_keys):
        rec = current[path]
        events.append(
            {
                "change": "created",
                "path": path,
                "sha256": rec.get("sha256"),
                "user": rec.get("user"),
                "uid": rec.get("uid"),
            }
        )
    for path in sorted(prev_keys - curr_keys):
        rec = previous[path]
        events.append(
            {
                "change": "deleted",
                "path": path,
                "sha256": rec.get("sha256"),
                "user": rec.get("user"),
                "uid": rec.get("uid"),
            }
        )
    for path in sorted(prev_keys & curr_keys):
        old, new = previous[path], current[path]
        if old.get("sha256") != new.get("sha256") or old.get("exists") != new.get(
            "exists"
        ):
            events.append(
                {
                    "change": "modified",
                    "path": path,
                    "sha256": new.get("sha256"),
                    "prev_sha256": old.get("sha256"),
                    "user": new.get("user"),
                    "uid": new.get("uid"),
                }
            )
    return events


# ---------------------------------------------------------------------------
# RF-SEC-02 Persistencia
# ---------------------------------------------------------------------------


def _linux_cron_entries() -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    files = ["/etc/crontab"]
    for folder in (
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/var/spool/cron/crontabs",
        "/var/spool/cron",
    ):
        if os.path.isdir(folder):
            try:
                for name in os.listdir(folder):
                    files.append(os.path.join(folder, name))
            except OSError:
                pass
    for path in files:
        if not os.path.isfile(path):
            continue
        body = _read_text(path) or ""
        items.append(
            {
                "kind": "cron",
                "path": path,
                "sha256": _sha256_text(body),
                "preview": body.strip().splitlines()[:8],
            }
        )
    if shutil.which("crontab"):
        res = _run(["crontab", "-l"], timeout=8)
        if res.returncode == 0 and (res.stdout or "").strip():
            body = res.stdout
            items.append(
                {
                    "kind": "cron",
                    "path": "crontab:current_user",
                    "sha256": _sha256_text(body),
                    "preview": body.strip().splitlines()[:8],
                }
            )
    return items


def _linux_systemd_timers() -> List[Dict[str, Any]]:
    from colsoft_tools.linux_collectors import linux_systemd_units

    scan = linux_systemd_units(max_units=1, max_timers=80)
    items: List[Dict[str, Any]] = []
    for item in scan.get("timers") or []:
        if not isinstance(item, dict):
            continue
        unit = str(item.get("unit") or "")
        if not unit.endswith(".timer"):
            continue
        raw = str(item.get("raw") or unit)
        items.append(
            {
                "kind": "systemd_timer",
                "name": unit,
                "sha256": _sha256_text(raw),
                "raw": raw[:240],
            }
        )
    return items


def _linux_authorized_keys() -> List[Dict[str, Any]]:
    homes: List[str] = ["/root"]
    home_root = "/home"
    if os.path.isdir(home_root):
        try:
            for name in os.listdir(home_root):
                homes.append(os.path.join(home_root, name))
        except OSError:
            pass
    items: List[Dict[str, Any]] = []
    for home in homes:
        path = os.path.join(home, ".ssh", "authorized_keys")
        if not os.path.isfile(path):
            continue
        body = _read_text(path) or ""
        keys = [
            ln.strip()
            for ln in body.splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        items.append(
            {
                "kind": "authorized_keys",
                "path": path,
                "user": os.path.basename(home),
                "count": len(keys),
                "sha256": _sha256_text(body),
            }
        )
    return items


def _win_run_keys() -> List[Dict[str, Any]]:
    try:
        import winreg  # type: ignore
    except ImportError:
        return []
    roots = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]
    items: List[Dict[str, Any]] = []
    for hive, sub in roots:
        try:
            key = winreg.OpenKey(hive, sub)
        except OSError:
            continue
        hive_name = "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"
        i = 0
        while True:
            try:
                name, value, _typ = winreg.EnumValue(key, i)
            except OSError:
                break
            i += 1
            raw = f"{hive_name}\\{sub}\\{name}={value}"
            items.append(
                {
                    "kind": "registry_run",
                    "path": f"{hive_name}\\{sub}",
                    "name": name,
                    "value": str(value)[:400],
                    "sha256": _sha256_text(raw),
                }
            )
        winreg.CloseKey(key)
    return items


def _win_service_image_path(name: str) -> str:
    """ImagePath del SCM (HKLM\\SYSTEM\\CurrentControlSet\\Services)."""
    try:
        import winreg  # type: ignore
    except ImportError:
        return ""
    sub = rf"SYSTEM\CurrentControlSet\Services\{name}"
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sub)
    except OSError:
        return ""
    try:
        value, _typ = winreg.QueryValueEx(key, "ImagePath")
        return str(value or "")
    except OSError:
        return ""
    finally:
        winreg.CloseKey(key)


def _win_services() -> List[Dict[str, Any]]:
    res = _run(["sc", "query", "type=", "service", "state=", "all"], timeout=20)
    items: List[Dict[str, Any]] = []
    name = None
    for line in (res.stdout or "").splitlines():
        line = line.strip()
        if line.upper().startswith("SERVICE_NAME:"):
            name = line.split(":", 1)[-1].strip()
        elif name and line.upper().startswith("STATE"):
            image_path = _win_service_image_path(name)
            items.append(
                {
                    "kind": "service",
                    "name": name,
                    "state": line.split(":", 1)[-1].strip()[:80],
                    "image_path": image_path[:400],
                    "sha256": _sha256_text(f"{name}|{image_path.strip().lower()}"),
                }
            )
            name = None
        if len(items) >= 400:
            break
    return items


def _parse_schtasks_csv_line(line: str) -> Dict[str, str]:
    """Campos de `schtasks /query /fo CSV`: TaskName, Next Run Time, Status.

    Next Run Time (y a menudo Status Ready/Running) cambian en cada disparo;
    la identidad de persistencia es solo el nombre de la tarea.
    """
    raw = (line or "").strip()
    stripped = raw.strip('"')
    parts = [p.strip().strip('"') for p in stripped.split('","')]
    if len(parts) == 1:
        parts = [p.strip() for p in stripped.split(",")]
    return {
        "name": parts[0] if parts else raw[:200],
        "next_run": parts[1] if len(parts) > 1 else "",
        "status": parts[2] if len(parts) > 2 else "",
    }


def _win_scheduled_tasks() -> List[Dict[str, Any]]:
    res = _run(["schtasks", "/query", "/fo", "CSV", "/nh"], timeout=20)
    items: List[Dict[str, Any]] = []
    seen: set = set()
    for line in (res.stdout or "").splitlines():
        if not line.strip():
            continue
        fields = _parse_schtasks_csv_line(line)
        name = fields["name"]
        if not name or name in seen:
            continue
        seen.add(name)
        items.append(
            {
                "kind": "scheduled_task",
                "name": name,
                "task_name": name,
                "next_run": fields["next_run"],
                "status": fields["status"],
                "sha256": _sha256_text(name),
            }
        )
        if len(items) >= 400:
            break
    return items


def persistence_scan() -> Dict[str, Any]:
    """Autoruns / persistencia del host (RF-SEC-02)."""
    try:
        items: List[Dict[str, Any]] = []
        if _is_windows():
            items.extend(_win_run_keys())
            items.extend(_win_services())
            items.extend(_win_scheduled_tasks())
        elif _is_linux():
            items.extend(_linux_cron_entries())
            items.extend(_linux_systemd_timers())
            items.extend(_linux_authorized_keys())
        else:
            return _unsupported("persistence_scan")
        kinds: Dict[str, int] = {}
        for rec in items:
            kinds[str(rec.get("kind"))] = kinds.get(str(rec.get("kind")), 0) + 1
        return {
            "tool": "persistence_scan",
            "status": "OK",
            "os": platform.system(),
            "count": len(items),
            "kinds": kinds,
            "items": items,
            "ts": _now_iso(),
            "error": None,
        }
    except Exception as e:
        return {"tool": "persistence_scan", "status": "ERROR", "error": str(e)}


def persistence_fingerprint(scan: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for rec in scan.get("items") or []:
        key = str(
            rec.get("path")
            or rec.get("name")
            or rec.get("raw")
            or rec.get("sha256")
            or id(rec)
        )
        kind = rec.get("kind")
        fp = f"{kind}:{key}"
        out[fp] = rec
    return out


# ---------------------------------------------------------------------------
# RF-SEC-03 Auditoría de autenticación
# ---------------------------------------------------------------------------

_AUTH_PATTERNS = [
    (
        "login_success",
        "low",
        re.compile(
            r"Accepted\s+(password|publickey|keyboard-interactive).+for\s+(\S+)",
            re.I,
        ),
        "T1078",
    ),
    (
        "login_failure",
        "medium",
        re.compile(
            r"Failed\s+(password|publickey).+for\s+(invalid user\s+)?(\S+)",
            re.I,
        ),
        "T1110",
    ),
    (
        "login_failure",
        "medium",
        re.compile(r"authentication failure.+user=(\S+)", re.I),
        "T1110",
    ),
    (
        "sudo",
        "medium",
        re.compile(r"sudo:.+USER=(\S+).+COMMAND=(.+)$", re.I),
        "T1548.003",
    ),
    (
        "su",
        "medium",
        re.compile(r"su:\s+\(to\s+(\S+)\).+session (opened|closed)", re.I),
        "T1548",
    ),
    (
        "session_open",
        "low",
        re.compile(r"session opened for user (\S+)", re.I),
        "T1078",
    ),
    (
        "session_close",
        "low",
        re.compile(r"session closed for user (\S+)", re.I),
        "T1078",
    ),
]


def _parse_auth_line(line: str, source: str) -> Optional[Dict[str, Any]]:
    text = (line or "").rstrip()
    if not text:
        return None
    for action, severity, rx, mitre in _AUTH_PATTERNS:
        m = rx.search(text)
        if not m:
            continue
        user = None
        for g in m.groups() or ():
            if g and g.lower() not in (
                "password",
                "publickey",
                "keyboard-interactive",
                "invalid user",
                "opened",
                "closed",
            ):
                user = g
                break
        return {
            "action": action,
            "severity": severity,
            "user": user,
            "mitre_technique": mitre,
            "source": source,
            "message": text[:400],
        }
    return None


def _auth_lines_linux(max_lines: int) -> List[Tuple[str, str]]:
    rows: List[Tuple[str, str]] = []
    if shutil.which("journalctl"):
        res = _run(
            [
                "journalctl",
                "-n",
                str(max_lines),
                "-o",
                "short-iso",
                "--no-pager",
                "-u",
                "ssh",
                "-u",
                "sshd",
                "-u",
                "sudo",
                "-t",
                "sudo",
                "-t",
                "su",
                "-t",
                "sshd",
            ],
            timeout=12,
        )
        if res.returncode == 0 and (res.stdout or "").strip():
            for line in res.stdout.splitlines()[-max_lines:]:
                rows.append((line, "journalctl"))
            return rows
    for path in ("/var/log/auth.log", "/var/log/secure"):
        body = _read_text(path, max_bytes=512 * 1024)
        if not body:
            continue
        for line in body.splitlines()[-max_lines:]:
            rows.append((line, path))
        if rows:
            return rows
    return rows


def _auth_lines_windows(max_lines: int) -> List[Tuple[str, str]]:
    if not shutil.which("wevtutil"):
        return []
    q = (
        "*[System[(EventID=4624 or EventID=4625 or EventID=4634 "
        "or EventID=4672 or EventID=4648)]]"
    )
    res = _run(
        [
            "wevtutil",
            "qe",
            "Security",
            "/q:" + q,
            "/c:" + str(max_lines),
            "/f:text",
            "/rd:true",
        ],
        timeout=20,
    )
    return [(line, "Security") for line in (res.stdout or "").splitlines() if line.strip()]


def auth_audit(max_entries: int = 80) -> Dict[str, Any]:
    """Logon/logoff, fallos y sudo/su (RF-SEC-03)."""
    try:
        max_entries = max(1, min(int(max_entries or 80), 500))
        if _is_windows():
            raw = _auth_lines_windows(max_entries)
        elif _is_linux():
            raw = _auth_lines_linux(max_entries * 4)
        else:
            return _unsupported("auth_audit")
        events: List[Dict[str, Any]] = []
        for line, source in raw:
            parsed = _parse_auth_line(line, source)
            if not parsed:
                if _is_windows():
                    low = line.lower()
                    action = None
                    if "4624" in line or "successfully logged on" in low:
                        action, sev, mitre = "login_success", "low", "T1078"
                    elif "4625" in line or "failed" in low:
                        action, sev, mitre = "login_failure", "medium", "T1110"
                    elif "4634" in line or "logoff" in low:
                        action, sev, mitre = "logoff", "low", "T1078"
                    elif "4672" in line or "special privileges" in low:
                        action, sev, mitre = "privilege_escalation", "high", "T1548"
                    if action:
                        parsed = {
                            "action": action,
                            "severity": sev,
                            "mitre_technique": mitre,
                            "source": source,
                            "message": line.strip()[:400],
                        }
            if parsed:
                events.append(parsed)
            if len(events) >= max_entries:
                break
        return {
            "tool": "auth_audit",
            "status": "OK",
            "count": len(events),
            "events": events,
            "ts": _now_iso(),
            "error": None,
        }
    except Exception as e:
        return {"tool": "auth_audit", "status": "ERROR", "error": str(e)}


# ---------------------------------------------------------------------------
# RF-SEC-04 Motor de reglas + MITRE
# ---------------------------------------------------------------------------

DETECTION_RULES: List[Dict[str, Any]] = [
    {
        "id": "SEC-001",
        "name": "encoded_powershell",
        "summary": "PowerShell con comando codificado",
        "severity": "high",
        "mitre_technique": "T1059.001",
        "cmdline": re.compile(
            r"(powershell|pwsh).*"
            r"(-enc(odedcommand)?\s+|FromBase64String|-e(c|n)?\s+[A-Za-z0-9+/=]{12,})",
            re.I | re.S,
        ),
    },
    {
        "id": "SEC-002",
        "name": "curl_pipe_shell",
        "summary": "curl|sh / wget|sh (ejecución remota)",
        "severity": "high",
        "mitre_technique": "T1059.004",
        "cmdline": re.compile(
            r"(curl|wget)\s+[^\n|]{0,200}\|\s*(sudo\s+)?((ba)?sh|zsh|ksh|dash|python)",
            re.I,
        ),
    },
    {
        "id": "SEC-003",
        "name": "exec_from_tmp",
        "summary": "Ejecución desde ruta temporal (/tmp, %TEMP%)",
        "severity": "medium",
        "mitre_technique": "T1036.005",
        "exe_prefixes": (
            "/tmp/",
            "/var/tmp/",
            "/dev/shm/",
            "\\temp\\",
            "/temp/",
            "\\appdata\\local\\temp\\",
        ),
    },
    {
        "id": "SEC-004",
        "name": "bash_reverse_i",
        "summary": "Shell interactivo invertido / bind",
        "severity": "high",
        "mitre_technique": "T1059.004",
        "cmdline": re.compile(
            r"(bash\s+-i\s+>&\s*/dev/tcp/|nc\s+(-e|--exec)\s+|ncat\s+.*-e\s+)",
            re.I,
        ),
    },
]


def _proc_cmdline(proc: Dict[str, Any]) -> str:
    cmd = proc.get("cmdline") or ""
    if isinstance(cmd, list):
        cmd = " ".join(str(x) for x in cmd)
    exe = proc.get("exe") or proc.get("cwd") or ""
    name = proc.get("name") or ""
    return f"{name} {exe} {cmd}".strip()


def match_detection_rules(
    proc: Dict[str, Any],
    rules: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Evalúa un proceso contra el catálogo de reglas (RF-SEC-04)."""
    hits: List[Dict[str, Any]] = []
    blob = _proc_cmdline(proc)
    exe = str(proc.get("exe") or "").lower()
    cmd_lower = blob.lower()
    for rule in rules or DETECTION_RULES:
        rx = rule.get("cmdline")
        if rx is not None and rx.search(blob):
            hits.append(_detection_hit(rule, proc))
            continue
        prefixes = rule.get("exe_prefixes") or ()
        if prefixes:
            hay = f"{exe} {cmd_lower}"
            if any(p.lower() in hay for p in prefixes):
                # Evita el propio agente si solo *vive* en tmp; exige ejecutable.
                if "/tmp/" in exe or "\\temp\\" in exe or "/var/tmp/" in exe or "/dev/shm/" in exe:
                    hits.append(_detection_hit(rule, proc))
                elif any(
                    token.startswith(p.lower())
                    for token in cmd_lower.split()
                    for p in prefixes
                ):
                    hits.append(_detection_hit(rule, proc))
    return hits


def _detection_hit(rule: Dict[str, Any], proc: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "rule_id": rule.get("id"),
        "name": rule.get("name"),
        "summary": rule.get("summary"),
        "severity": rule.get("severity") or "medium",
        "mitre_technique": rule.get("mitre_technique"),
        "pid": proc.get("pid"),
        "ppid": proc.get("ppid"),
        "process": proc.get("name"),
        "user": proc.get("username") or proc.get("user"),
        "cmdline": _proc_cmdline(proc)[:500],
    }


def detection_scan(
    processes: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Pasa el catálogo de reglas sobre procesos actuales (o una lista dada)."""
    try:
        if processes is None:
            from colsoft_tools.observability import snapshot_processes

            processes = list(snapshot_processes().values())
        hits: List[Dict[str, Any]] = []
        for proc in processes:
            hits.extend(match_detection_rules(proc))
        return {
            "tool": "detection_scan",
            "status": "OK",
            "count": len(hits),
            "detections": hits,
            "rules": [
                {
                    "id": r["id"],
                    "name": r["name"],
                    "mitre_technique": r["mitre_technique"],
                    "severity": r["severity"],
                }
                for r in DETECTION_RULES
            ],
            "ts": _now_iso(),
            "error": None,
        }
    except Exception as e:
        return {"tool": "detection_scan", "status": "ERROR", "error": str(e)}


# ---------------------------------------------------------------------------
# RF-SEC-05 Inventario canónico (insumo CVE; motor en backend)
# ---------------------------------------------------------------------------


def cve_inventory(
    include_hash: bool = False, max_hash: int = 20
) -> Dict[str, Any]:
    """Paquetes name+version (+hash opcional) listos para cruzar con NVD/CVE."""
    try:
        from colsoft_tools.observability import get_installed_software

        raw = get_installed_software(include_hash=include_hash, max_hash=max_hash)
        packages = []
        for pkg in raw.get("packages") or []:
            name = str(pkg.get("name") or "").strip()
            version = str(pkg.get("version") or "").strip()
            if not name:
                continue
            rec: Dict[str, Any] = {
                "name": name.lower(),
                "version": version,
                "product": name.lower(),
            }
            if pkg.get("sha256"):
                rec["sha256"] = pkg.get("sha256")
            if pkg.get("path"):
                rec["path"] = pkg.get("path")
            packages.append(rec)
        return {
            "tool": "cve_inventory",
            "status": raw.get("status") or "OK",
            "os": platform.system(),
            "os_version": platform.version(),
            "package_manager": raw.get("package_manager"),
            "count": len(packages),
            "packages": packages,
            "note": "Insumo RF-SEC-05; la correlación CVE vive en el backend.",
            "ts": _now_iso(),
            "error": raw.get("error"),
        }
    except Exception as e:
        return {"tool": "cve_inventory", "status": "ERROR", "error": str(e)}


# ---------------------------------------------------------------------------
# RF-SEC-06 CIS hardening score
# ---------------------------------------------------------------------------


def _cis_ok(passed: bool, check_id: str, title: str, evidence: str = "") -> Dict[str, Any]:
    return {
        "id": check_id,
        "title": title,
        "passed": bool(passed),
        "evidence": (evidence or "")[:240],
    }


def _cis_linux() -> List[Dict[str, Any]]:
    checks: List[Dict[str, Any]] = []

    aslr = _read_text("/proc/sys/kernel/randomize_va_space") or ""
    checks.append(
        _cis_ok(
            aslr.strip() == "2",
            "1.5.1",
            "ASLR habilitado (randomize_va_space=2)",
            aslr.strip(),
        )
    )

    ssh = _read_text("/etc/ssh/sshd_config") or ""
    ssh_l = ssh.lower()
    root_login = True
    if "permitrootlogin" in ssh_l:
        root_login = not re.search(
            r"^\s*PermitRootLogin\s+yes\b", ssh, re.I | re.M
        )
    checks.append(
        _cis_ok(
            root_login,
            "5.2.10",
            "SSH PermitRootLogin no es yes",
            "PermitRootLogin presente" if "permitrootlogin" in ssh_l else "sin sshd_config",
        )
    )
    pwd_auth = True
    m = re.search(r"^\s*PasswordAuthentication\s+(\S+)", ssh, re.I | re.M)
    if m:
        pwd_auth = m.group(1).lower() != "yes"
    checks.append(
        _cis_ok(
            pwd_auth,
            "5.2.7",
            "SSH PasswordAuthentication no es yes (preferible claves)",
            m.group(0) if m else "default",
        )
    )

    login_defs = _read_text("/etc/login.defs") or ""
    max_days = re.search(r"^\s*PASS_MAX_DAYS\s+(\d+)", login_defs, re.M)
    max_ok = False
    if max_days:
        try:
            max_ok = 0 < int(max_days.group(1)) <= 365
        except ValueError:
            max_ok = False
    checks.append(
        _cis_ok(
            max_ok,
            "5.4.1.1",
            "PASS_MAX_DAYS <= 365",
            max_days.group(0) if max_days else "ausente",
        )
    )

    for path, mode_ok, cid, title in (
        ("/etc/passwd", 0o644, "6.1.2", "Permisos /etc/passwd 0644 o más estrictos"),
        ("/etc/shadow", 0o640, "6.1.3", "Permisos /etc/shadow 0640 o más estrictos"),
        ("/etc/group", 0o644, "6.1.4", "Permisos /etc/group 0644 o más estrictos"),
    ):
        try:
            mode = stat.S_IMODE(os.stat(path).st_mode)
            checks.append(_cis_ok(mode <= mode_ok, cid, title, oct(mode)))
        except OSError as e:
            checks.append(_cis_ok(False, cid, title, str(e)))

    fw = bool(
        shutil.which("ufw")
        or shutil.which("nft")
        or shutil.which("iptables")
        or shutil.which("firewall-cmd")
    )
    evidence = "presente" if fw else "no se encontró ufw/nft/iptables"
    if shutil.which("ufw"):
        u = _run(["ufw", "status"], timeout=5)
        evidence = (u.stdout or u.stderr or "")[:120]
        fw = "active" in (u.stdout or "").lower() or fw
    checks.append(_cis_ok(fw, "3.5", "Firewall local presente (ufw/nft/iptables)", evidence))

    checks.append(
        _cis_ok(
            shutil.which("sudo") is not None,
            "5.3.1",
            "sudo instalado",
            shutil.which("sudo") or "ausente",
        )
    )

    empty_pass = False
    shadow = _read_text("/etc/shadow")
    if shadow:
        for line in shadow.splitlines():
            parts = line.split(":")
            if len(parts) >= 2 and parts[0] and parts[1] == "":
                empty_pass = True
                break
        checks.append(
            _cis_ok(
                not empty_pass,
                "6.2.1",
                "Ninguna cuenta con contraseña vacía en /etc/shadow",
                "vacia" if empty_pass else "ok",
            )
        )

    unused = ("cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "udf")
    disabled = 0
    modprobe_dir = "/etc/modprobe.d"
    blob = ""
    if os.path.isdir(modprobe_dir):
        try:
            for name in os.listdir(modprobe_dir):
                blob += _read_text(os.path.join(modprobe_dir, name)) or ""
        except OSError:
            pass
    for fs in unused:
        if re.search(rf"install\s+{fs}\s+/bin/true", blob):
            disabled += 1
    checks.append(
        _cis_ok(
            disabled >= 1,
            "1.1.1",
            "Al menos un FS innecesario bloqueado en modprobe.d",
            f"{disabled}/{len(unused)}",
        )
    )
    return checks


def _cis_windows() -> List[Dict[str, Any]]:
    checks: List[Dict[str, Any]] = []
    res = _run(
        ["powershell", "-NoProfile", "-Command", "Get-NetFirewallProfile | ConvertTo-Json"],
        timeout=15,
    )
    enabled = "true" in (res.stdout or "").lower() and "enabled" in (
        res.stdout or ""
    ).lower()
    if not enabled:
        enabled = "ON" in (_run(["netsh", "advfirewall", "show", "allprofiles"], timeout=10).stdout or "")
    checks.append(
        _cis_ok(enabled, "9.1", "Firewall de Windows habilitado", (res.stdout or "")[:120])
    )

    uac = _run(
        [
            "reg",
            "query",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "/v",
            "EnableLUA",
        ],
        timeout=8,
    )
    checks.append(
        _cis_ok(
            "0x1" in (uac.stdout or ""),
            "2.3.17",
            "UAC (EnableLUA) activo",
            (uac.stdout or uac.stderr or "")[:120],
        )
    )
    smbv1 = _run(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            "(Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State",
        ],
        timeout=20,
    )
    state = (smbv1.stdout or "").strip()
    checks.append(
        _cis_ok(
            state.lower() in ("disabled", "disablepending", ""),
            "18.3.1",
            "SMBv1 deshabilitado",
            state or "desconocido",
        )
    )
    return checks


def cis_score() -> Dict[str, Any]:
    """Score 0-100 sobre un subset CIS Level 1 (RF-SEC-06)."""
    try:
        if _is_windows():
            checks = _cis_windows()
        elif _is_linux():
            checks = _cis_linux()
        else:
            return _unsupported("cis_score")
        total = len(checks) or 1
        passed = sum(1 for c in checks if c.get("passed"))
        score = round(100.0 * passed / total, 1)
        return {
            "tool": "cis_score",
            "status": "OK",
            "os": platform.system(),
            "benchmark": "CIS subset Level 1 (agente)",
            "score": score,
            "passed": passed,
            "total": total,
            "checks": checks,
            "ts": _now_iso(),
            "error": None,
        }
    except Exception as e:
        return {"tool": "cis_score", "status": "ERROR", "error": str(e)}


# ---------------------------------------------------------------------------
# RF-SEC-07 DNS (dominio + proceso)
# ---------------------------------------------------------------------------


def _dns_from_connections() -> List[Dict[str, Any]]:
    if platform.system() == "Linux":
        from colsoft_tools.linux_collectors import linux_connection_rows

        rows: List[Dict[str, Any]] = []
        for c in linux_connection_rows(max_rows=400, include_udp=True):
            raddr = str(c.get("raddr") or "")
            port = None
            if ":" in raddr:
                try:
                    port = int(raddr.rsplit(":", 1)[-1])
                except ValueError:
                    port = None
            if port != 53:
                continue
            rec: Dict[str, Any] = {
                "resolver": raddr.rsplit(":", 1)[0].strip("[]") if raddr else None,
                "port": 53,
                "pid": c.get("pid"),
                "status": c.get("status"),
                "family": c.get("type"),
                "process": c.get("process_name"),
                "source": "/proc/net",
            }
            rows.append(rec)
        return rows
    try:
        from colsoft_tools.observability import _require_psutil

        psutil = _require_psutil()
    except Exception:
        return []
    rows: List[Dict[str, Any]] = []
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        return []
    for c in conns:
        raddr = getattr(c, "raddr", None)
        if not raddr or getattr(raddr, "port", None) != 53:
            continue
        rec: Dict[str, Any] = {
            "resolver": getattr(raddr, "ip", None),
            "port": 53,
            "pid": getattr(c, "pid", None),
            "status": getattr(c, "status", None),
            "family": str(getattr(c, "type", "")),
        }
        pid = rec.get("pid")
        if pid:
            try:
                p = psutil.Process(int(pid))
                rec["process"] = p.name()
                rec["user"] = p.username()
                rec["cmdline"] = " ".join(p.cmdline() or [])[:300]
            except Exception:
                pass
        rows.append(rec)
    return rows


def _dns_cache_windows() -> List[Dict[str, Any]]:
    res = _run(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-DnsClientCache | Select-Object -First 80 Name,Type,Data,Status | ConvertTo-Json -Compress",
        ],
        timeout=15,
    )
    text = (res.stdout or "").strip()
    if not text:
        return []
    try:
        import json

        data = json.loads(text)
    except ValueError:
        return []
    if isinstance(data, dict):
        data = [data]
    rows = []
    for rec in data or []:
        name = rec.get("Name")
        if not name:
            continue
        rows.append(
            {
                "domain": name,
                "record_type": rec.get("Type"),
                "data": rec.get("Data"),
                "status": rec.get("Status"),
                "source": "DnsClientCache",
            }
        )
    return rows


def _dns_cache_linux() -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if shutil.which("resolvectl"):
        res = _run(["resolvectl", "show-cache"], timeout=8)
        for line in (res.stdout or "").splitlines():
            line = line.strip()
            if not line or line.startswith("Query") or "cache" in line.lower() and ":" not in line:
                continue
            # Formatos varían; extrae un FQDN si aparece.
            m = re.search(r"([a-zA-Z0-9_.-]+\.[a-zA-Z]{2,})", line)
            if m:
                rows.append({"domain": m.group(1), "raw": line[:200], "source": "resolvectl"})
            if len(rows) >= 80:
                break
    return rows


def dns_monitor() -> Dict[str, Any]:
    """Consultas DNS observadas: dominio (si hay caché) + proceso origen."""
    try:
        queries = _dns_from_connections()
        if _is_windows():
            queries.extend(_dns_cache_windows())
        elif _is_linux():
            queries.extend(_dns_cache_linux())
        return {
            "tool": "dns_monitor",
            "status": "OK",
            "count": len(queries),
            "queries": queries,
            "ts": _now_iso(),
            "error": None,
        }
    except Exception as e:
        return {"tool": "dns_monitor", "status": "ERROR", "error": str(e)}


# ---------------------------------------------------------------------------
# RF-SEC-08 Heurísticas de rootkit
# ---------------------------------------------------------------------------


def _proc_pids_from_fs() -> List[int]:
    pids: List[int] = []
    proc = "/proc"
    if not os.path.isdir(proc):
        return pids
    try:
        for name in os.listdir(proc):
            if name.isdigit():
                pids.append(int(name))
    except OSError:
        pass
    return pids


def _psutil_pids() -> List[int]:
    try:
        from colsoft_tools.observability import _require_psutil

        return list(_require_psutil().pids())
    except Exception:
        return []


def rootkit_check() -> Dict[str, Any]:
    """Discrepancias procesos /proc vs psutil, sockets ocultos, kernel taint."""
    if not _is_linux():
        return _unsupported("rootkit_check")
    try:
        findings: List[Dict[str, Any]] = []
        proc_pids = set(_proc_pids_from_fs())
        ps_pids = set(_psutil_pids())
        if proc_pids and ps_pids:
            hidden = sorted(proc_pids - ps_pids)[:30]
            missing = sorted(ps_pids - proc_pids)[:30]
            if hidden:
                findings.append(
                    {
                        "id": "RK-01",
                        "severity": "high",
                        "summary": "PIDs en /proc no visibles para psutil",
                        "pids": hidden,
                    }
                )
            if missing:
                findings.append(
                    {
                        "id": "RK-02",
                        "severity": "medium",
                        "summary": "PIDs de psutil ausentes en /proc",
                        "pids": missing,
                    }
                )

        taint = _read_text("/proc/sys/kernel/tainted")
        if taint and taint.strip() not in ("0", ""):
            findings.append(
                {
                    "id": "RK-03",
                    "severity": "medium",
                    "summary": "Kernel tainted (módulos/oops)",
                    "taint": taint.strip(),
                }
            )

        if os.path.isfile("/proc/modules") and shutil.which("lsmod"):
            listed = set()
            body = _read_text("/proc/modules") or ""
            for line in body.splitlines():
                name = line.split()[0] if line.split() else ""
                if name:
                    listed.add(name)
            ls = _run(["lsmod"], timeout=8)
            ls_names = set()
            for line in (ls.stdout or "").splitlines()[1:]:
                name = line.split()[0] if line.split() else ""
                if name:
                    ls_names.add(name)
            extra = sorted(listed - ls_names)[:20]
            if extra:
                findings.append(
                    {
                        "id": "RK-04",
                        "severity": "high",
                        "summary": "Módulos en /proc/modules no listados por lsmod",
                        "modules": extra,
                    }
                )

        suid_tmp: List[str] = []
        for folder in ("/tmp", "/var/tmp", "/dev/shm"):
            if not os.path.isdir(folder):
                continue
            try:
                for name in os.listdir(folder):
                    path = os.path.join(folder, name)
                    try:
                        st = os.lstat(path)
                    except OSError:
                        continue
                    if stat.S_ISREG(st.st_mode) and st.st_mode & stat.S_ISUID:
                        suid_tmp.append(path)
            except OSError:
                pass
        if suid_tmp:
            findings.append(
                {
                    "id": "RK-05",
                    "severity": "high",
                    "summary": "Binarios SUID en directorios temporales",
                    "paths": suid_tmp[:20],
                }
            )

        return {
            "tool": "rootkit_check",
            "status": "OK",
            "count": len(findings),
            "findings": findings,
            "proc_pids": len(proc_pids),
            "psutil_pids": len(ps_pids),
            "ts": _now_iso(),
            "error": None,
        }
    except Exception as e:
        return {"tool": "rootkit_check", "status": "ERROR", "error": str(e)}
