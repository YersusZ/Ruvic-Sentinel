"""Collectors específicos de Linux — SRS §13 (RF-LIN-01..08).

Sin BCC/libbpf: bpftool + tracefs, audit.log, /proc /sys, netlink stdlib,
systemctl, getenforce/aa-status, dpkg/rpm. En Windows/macOS → `UNSUPPORTED`.
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import socket
import struct
import subprocess
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# RF-LIN-01: tracepoints de interés (syscalls, red, exec).
BPF_TRACEPOINTS_OF_INTEREST = (
    "syscalls/sys_enter_execve",
    "syscalls/sys_enter_execveat",
    "syscalls/sys_enter_connect",
    "syscalls/sys_enter_accept",
    "syscalls/sys_enter_accept4",
    "sched/sched_process_exec",
    "sched/sched_process_fork",
    "sock/inet_sock_set_state",
)

# RF-LIN-03: logs tradicionales + analogía Event Viewer (System/Application/
# Security/Setup/Forwarded Events).
SYSLOG_CHANNELS = (
    "system",
    "application",
    "security",
    "setup",
    "forwarded",
)

SYSLOG_ALIASES = {
    "system": "system",
    "journal": "system",
    "journald": "system",
    "application": "application",
    "app": "application",
    "security": "security",
    "auth": "auth",
    "auth.log": "auth",
    "secure": "auth",
    "setup": "setup",
    "forwarded": "forwarded",
    "forwardedevents": "forwarded",
    "forwarded_events": "forwarded",
}

SYSLOG_SOURCES = {
    "syslog": ("/var/log/syslog", "/var/log/messages"),
    "application": ("/var/log/syslog", "/var/log/messages"),
    "auth": ("/var/log/auth.log", "/var/log/secure"),
    "security": ("/var/log/auth.log", "/var/log/secure"),
    "auth.log": ("/var/log/auth.log", "/var/log/secure"),
    "kern": ("/var/log/kern.log",),
    "messages": ("/var/log/messages",),
    "dpkg": ("/var/log/dpkg.log",),
    "apt": ("/var/log/apt/history.log",),
    "yum": ("/var/log/yum.log",),
    "dnf": ("/var/log/dnf.log",),
    "setup": (
        "/var/log/dpkg.log",
        "/var/log/apt/history.log",
        "/var/log/yum.log",
        "/var/log/dnf.log",
        "/var/log/installer/syslog",
    ),
}

_FORWARDED_FILES = (
    "/var/log/remote.log",
    "/var/log/syslog-remote",
)
_FORWARDED_DIRS = (
    "/var/log/journal/remote",
    "/var/log/remote",
    "/var/log/rsyslog/remote",
)


def resolve_syslog_source(name: Optional[str]) -> str:
    raw = (name or "syslog").strip() or "syslog"
    return SYSLOG_ALIASES.get(raw.lower(), raw)


def forwarded_log_spec() -> Dict[str, Any]:
    """Ubica logs reenviados (analogía ForwardedEvents)."""
    journal_remote = "/var/log/journal/remote"
    if os.path.isdir(journal_remote):
        try:
            if os.listdir(journal_remote):
                return {"kind": "journal", "directory": journal_remote}
        except OSError:
            pass
    files: List[str] = []
    for path in _FORWARDED_FILES:
        if os.path.isfile(path):
            files.append(path)
    for directory in _FORWARDED_DIRS:
        if directory == journal_remote or not os.path.isdir(directory):
            continue
        try:
            names = os.listdir(directory)
        except OSError:
            continue
        for name in names:
            path = os.path.join(directory, name)
            if os.path.isfile(path):
                files.append(path)
    if files:
        newest = max(
            files, key=lambda p: os.path.getmtime(p) if os.path.isfile(p) else 0
        )
        return {"kind": "files", "paths": tuple(files), "chosen": newest}
    return {"kind": "missing"}


AUDIT_LOG_PATHS = (
    "/var/log/audit/audit.log",
    "/var/log/audit.log",
)

_AUDIT_KV = re.compile(r'(\w+)=(?:"([^"]*)"|([^\s]+))')


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_linux() -> bool:
    return platform.system() == "Linux"


def _run(cmd: List[str], timeout: int = 20) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        encoding="utf-8",
        errors="replace",
    )


def _unsupported(tool: str) -> Dict[str, Any]:
    return {
        "tool": tool,
        "status": "UNSUPPORTED",
        "os": platform.system(),
        "error": "Requiere Linux",
        "ts": _now_iso(),
    }


def _read_text(path: str, max_bytes: int = 2_000_000) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(max_bytes)
    except OSError:
        return None


def _tail_lines(path: str, max_lines: int) -> List[str]:
    body = _read_text(path)
    if body is None:
        return []
    lines = body.splitlines()
    return lines[-max(1, int(max_lines)) :]


def _exists(path: str) -> bool:
    try:
        return os.path.exists(path)
    except OSError:
        return False


def _tracing_root() -> Optional[str]:
    for path in ("/sys/kernel/tracing", "/sys/kernel/debug/tracing"):
        if _exists(os.path.join(path, "events")):
            return path
    return None


# ---------------------------------------------------------------------------
# RF-LIN-01 eBPF (inventario de programas/tracepoints; no sesión live)
# ---------------------------------------------------------------------------

def _tracepoint_exists(rel: str) -> bool:
    root = _tracing_root()
    if not root:
        return False
    return _exists(os.path.join(root, "events", rel))


def _parse_bpftool_prog(stdout: str) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    current: Dict[str, str] = {}
    for line in (stdout or "").splitlines():
        stripped = line.strip()
        if re.match(r"^\d+:", stripped):
            if current:
                rows.append(current)
            ident, _, rest = stripped.partition(":")
            current = {"id": ident.strip(), "raw": stripped[:200]}
            m = re.search(r"name\s+(\S+)", rest)
            if m:
                current["name"] = m.group(1)
            m = re.search(r"type\s+(\S+)", rest)
            if m:
                current["type"] = m.group(1)
        elif stripped.startswith("name") and current:
            current["name"] = stripped.split(None, 1)[-1]
    if current:
        rows.append(current)
    return rows


def linux_ebpf(max_programs: int = 40) -> Dict[str, Any]:
    """RF-LIN-01: capacidad BPF + programas cargados + tracepoints de interés."""
    if not _is_linux():
        return _unsupported("linux_ebpf")
    max_programs = max(1, min(int(max_programs or 40), 200))
    try:
        tracing = _tracing_root()
        btf = _exists("/sys/kernel/btf/vmlinux")
        fs_bpf = _exists("/sys/fs/bpf")
        unpriv = (_read_text("/proc/sys/kernel/unprivileged_bpf_disabled") or "").strip()
        of_interest = [
            {"id": tp, "present": _tracepoint_exists(tp)}
            for tp in BPF_TRACEPOINTS_OF_INTEREST
        ]
        programs: List[Dict[str, str]] = []
        error = None
        if shutil.which("bpftool"):
            res = _run(["bpftool", "prog", "show"], timeout=15)
            programs = _parse_bpftool_prog(res.stdout or "")[:max_programs]
            if res.returncode != 0:
                error = (res.stderr or "").strip()[:400] or None
        return {
            "tool": "linux_ebpf",
            "status": "OK",
            "btf": btf,
            "bpffs": fs_bpf,
            "tracing": tracing,
            "unprivileged_bpf_disabled": unpriv or None,
            "program_count": len(programs),
            "count": len(programs),
            "programs": programs,
            "of_interest": of_interest,
            "error": error,
            "note": "Snapshot de programas/tracepoints (como logman ETW), no attach live.",
            "ts": _now_iso(),
        }
    except Exception as e:
        return {"tool": "linux_ebpf", "status": "ERROR", "error": str(e)}


# ---------------------------------------------------------------------------
# RF-LIN-02 auditd
# ---------------------------------------------------------------------------

def parse_audit_line(line: str) -> Optional[Dict[str, Any]]:
    line = (line or "").strip()
    if not line or line.startswith("#"):
        return None
    fields: Dict[str, str] = {}
    for m in _AUDIT_KV.finditer(line):
        fields[m.group(1)] = m.group(2) if m.group(2) is not None else (m.group(3) or "")
    if not fields.get("type") and line.startswith("type="):
        return None
    rec: Dict[str, Any] = {
        "type": fields.get("type"),
        "pid": fields.get("pid"),
        "uid": fields.get("uid") or fields.get("auid"),
        "exe": fields.get("exe"),
        "comm": fields.get("comm"),
        "syscall": fields.get("syscall"),
        "success": fields.get("success"),
        "msg": (fields.get("msg") or line)[:240],
        "raw": line[:400],
    }
    ts = None
    msg = fields.get("msg") or ""
    m = re.search(r"audit\(([\d.]+):", msg) or re.search(r"audit\(([\d.]+):", line)
    if m:
        try:
            ts = datetime.fromtimestamp(float(m.group(1)), tz=timezone.utc).isoformat()
        except (ValueError, OSError):
            ts = m.group(1)
    rec["ts"] = ts
    return rec


def _audit_log_path() -> Optional[str]:
    return next((p for p in AUDIT_LOG_PATHS if os.path.isfile(p)), None)


def linux_auditd(max_events: int = 40, **range_kw: Any) -> Dict[str, Any]:
    """RF-LIN-02: estado de auditd + últimas líneas de audit.log / ausearch."""
    if not _is_linux():
        return _unsupported("linux_auditd")
    from colsoft_tools.log_range import (
        filter_entries,
        to_ausearch,
        window_fields,
        window_from_params,
    )

    max_events = max(1, min(int(max_events or 40), 200))
    window = window_from_params(range_kw)
    try:
        active = None
        if shutil.which("systemctl"):
            res = _run(["systemctl", "is-active", "auditd"], timeout=8)
            active = (res.stdout or "").strip() or None
        rules: List[str] = []
        if shutil.which("auditctl"):
            res = _run(["auditctl", "-l"], timeout=10)
            rules = [
                ln.strip()
                for ln in (res.stdout or "").splitlines()
                if ln.strip() and not ln.startswith("No rules")
            ][:80]
        entries: List[Dict[str, Any]] = []
        log_path = _audit_log_path()
        error = None
        if shutil.which("ausearch"):
            cmd = ["ausearch", "-i"]
            if window.start is not None:
                d, t = to_ausearch(window.start)
                cmd += ["-ts", d, t]
            else:
                cmd += ["-ts", "recent"]
            if window.end is not None:
                d, t = to_ausearch(window.end)
                cmd += ["-te", d, t]
            res = _run(cmd, timeout=15)
            for ln in (res.stdout or "").splitlines():
                rec = parse_audit_line(ln)
                if rec:
                    entries.append(rec)
                if len(entries) >= max_events * 5:
                    break
            if res.returncode != 0 and not entries:
                error = (res.stderr or "").strip()[:400] or None
        if not entries and log_path:
            tail_n = max_events * 20 if window.bounded() else max_events * 3
            for ln in _tail_lines(log_path, tail_n):
                rec = parse_audit_line(ln)
                if rec:
                    entries.append(rec)
        entries = filter_entries(entries, window, limit=max_events)
        rec_out: Dict[str, Any] = {
            "tool": "linux_auditd",
            "status": "OK",
            "auditd": active,
            "log_path": log_path,
            "rule_count": len(rules),
            "rules": rules[:20],
            "count": len(entries),
            "entries": entries[:max_events],
            "error": error,
            "ts": _now_iso(),
        }
        if window.bounded():
            rec_out["range"] = window_fields(window)
        return rec_out
    except Exception as e:
        return {"tool": "linux_auditd", "status": "ERROR", "error": str(e)}


def audit_severity(entry: Dict[str, Any]) -> str:
    typ = str(entry.get("type") or "").upper()
    if typ in ("AVC", "USER_AUTH", "USER_LOGIN", "ANOM_ABEND"):
        if str(entry.get("success") or "").lower() in ("no", "0", "failed"):
            return "high"
        if typ == "AVC":
            return "high"
        return "medium"
    if str(entry.get("success") or "").lower() in ("no", "0"):
        return "medium"
    return "info"


# ---------------------------------------------------------------------------
# RF-LIN-03 journald + /var/log/*
# ---------------------------------------------------------------------------

def _list_var_log(limit: int = 40) -> List[Dict[str, Any]]:
    root = "/var/log"
    out: List[Dict[str, Any]] = []
    if not os.path.isdir(root):
        return out
    try:
        names = sorted(os.listdir(root))
    except OSError:
        return out
    for name in names:
        path = os.path.join(root, name)
        try:
            if not os.path.isfile(path):
                continue
            st = os.stat(path)
        except OSError:
            continue
        out.append({"path": path, "bytes": int(st.st_size), "mtime": int(st.st_mtime)})
        if len(out) >= limit:
            break
    return out


def _syslog_level(line: str, default: str = "info") -> str:
    low = line.lower()
    if "emerg" in low or "panic" in low:
        return "critical"
    if "alert" in low or "crit" in low:
        return "critical"
    if "error" in low or "err:" in low or "failed" in low:
        return "error"
    if "warn" in low:
        return "warning"
    if "debug" in low:
        return "debug"
    return default


def linux_syslog(
    source: str = "syslog",
    max_lines: int = 80,
    *,
    include_files: bool = True,
    **range_kw: Any,
) -> Dict[str, Any]:
    """RF-LIN-03: mismo parser que `system_log` (RF-OBS-04), tool=linux_syslog."""
    if not _is_linux():
        return _unsupported("linux_syslog")
    from colsoft_tools.log_range import window_fields, window_from_params
    from colsoft_tools.observability import get_system_log

    src = resolve_syslog_source(source)
    rec = get_system_log(source=src, max_lines=max_lines, **range_kw)
    rec["tool"] = "linux_syslog"
    rec["cross_tool"] = "system_log"
    rec["channel"] = src
    rec["known_channels"] = list(SYSLOG_CHANNELS)
    window = window_from_params(range_kw)
    if window.bounded() and "range" not in rec:
        rec["range"] = window_fields(window)
    if include_files:
        rec["files"] = _list_var_log()
    return rec


def linux_syslog_bundle(max_per_channel: int = 20, **range_kw: Any) -> Dict[str, Any]:
    """Lee los 5 canales clásicos (analogía Event Viewer) en un solo llamado."""
    if not _is_linux():
        return _unsupported("linux_syslog")
    from colsoft_tools.log_range import window_fields, window_from_params

    channels: Dict[str, Any] = {}
    total = 0
    for ch in SYSLOG_CHANNELS:
        rec = linux_syslog(
            ch, max_lines=max_per_channel, include_files=False, **range_kw
        )
        channels[ch] = rec
        total += int(rec.get("count") or 0)
    out = {
        "tool": "linux_syslog",
        "status": "OK",
        "count": total,
        "channels": channels,
        "known_channels": list(SYSLOG_CHANNELS),
        "ts": _now_iso(),
        "error": None,
    }
    window = window_from_params(range_kw)
    if window.bounded():
        out["range"] = window_fields(window)
    return out


# ---------------------------------------------------------------------------
# RF-LIN-04 métricas /proc y /sys (sin psutil)
# ---------------------------------------------------------------------------

def _cpu_count() -> int:
    try:
        online = _read_text("/sys/devices/system/cpu/online") or ""
        # "0-7" o "0,2,4"
        n = 0
        for part in online.strip().split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                a, b = part.split("-", 1)
                n += int(b) - int(a) + 1
            else:
                n += 1
        if n:
            return n
    except (TypeError, ValueError, OSError):
        pass
    return os.cpu_count() or 1


def _cpu_physical_cores() -> Optional[int]:
    """Núcleos físicos desde /proc/cpuinfo (physical id + core id)."""
    body = _read_text("/proc/cpuinfo") or ""
    cores = set()
    phys = None
    core = None
    cpu_cores_field: Optional[int] = None
    sockets: set = set()

    def _flush() -> None:
        nonlocal phys, core
        if phys is not None and core is not None:
            cores.add((phys, core))
        phys = None
        core = None

    for line in body.splitlines():
        if not line.strip():
            _flush()
            continue
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        key = key.strip().lower()
        val = val.strip()
        if key == "physical id":
            phys = val
            sockets.add(val)
        elif key == "core id":
            core = val
        elif key == "cpu cores":
            try:
                cpu_cores_field = int(val)
            except ValueError:
                pass
    _flush()
    if cores:
        return len(cores)
    if cpu_cores_field and sockets:
        return cpu_cores_field * len(sockets)
    return cpu_cores_field


def _khz_to_mhz(raw: str) -> Optional[float]:
    try:
        return round(int(raw.strip()) / 1000.0, 1)
    except (TypeError, ValueError):
        return None


def _cpu_freq() -> Optional[Dict[str, Optional[float]]]:
    """Frecuencia en MHz desde cpufreq (kHz) o `cpu MHz` de cpuinfo."""
    base = "/sys/devices/system/cpu/cpu0/cpufreq"
    max_mhz = _khz_to_mhz(_read_text(f"{base}/cpuinfo_max_freq") or "")
    if max_mhz is None:
        max_mhz = _khz_to_mhz(_read_text(f"{base}/scaling_max_freq") or "")
    cur_mhz = _khz_to_mhz(_read_text(f"{base}/scaling_cur_freq") or "")
    if cur_mhz is None:
        for line in (_read_text("/proc/cpuinfo") or "").splitlines():
            if line.lower().startswith("cpu mhz"):
                try:
                    cur_mhz = round(float(line.split(":", 1)[-1].strip()), 1)
                except ValueError:
                    cur_mhz = None
                break
    if max_mhz is None and cur_mhz is None:
        return None
    return {
        "current_mhz": cur_mhz,
        "min_mhz": _khz_to_mhz(_read_text(f"{base}/cpuinfo_min_freq") or ""),
        "max_mhz": max_mhz or cur_mhz,
    }
    try:
        online = _read_text("/sys/devices/system/cpu/online") or ""
        # "0-7" o "0,2,4"
        n = 0
        for part in online.strip().split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                a, b = part.split("-", 1)
                n += int(b) - int(a) + 1
            else:
                n += 1
        if n:
            return n
    except (TypeError, ValueError, OSError):
        pass
    return os.cpu_count() or 1


def _stat_cpu() -> Tuple[int, int]:
    body = _read_text("/proc/stat") or ""
    line = body.splitlines()[0] if body else ""
    nums = [int(x) for x in line.split()[1:] if x.isdigit()]
    if not nums:
        return 0, 1
    idle = nums[3] + (nums[4] if len(nums) > 4 else 0)
    return idle, sum(nums)


def _meminfo() -> Dict[str, int]:
    out: Dict[str, int] = {}
    for line in (_read_text("/proc/meminfo") or "").splitlines():
        if ":" not in line:
            continue
        key, rest = line.split(":", 1)
        num = rest.strip().split()[0]
        try:
            out[key] = int(num) * (1024 if "kB" in rest else 1)
        except ValueError:
            continue
    return out


def _skip_diskstats_name(name: str) -> bool:
    """True = partición o dispositivo irrelevante (no IOPS de disco de servidor).

    Conserva discos enteros: sda, nvme0n1, mmcblk0, vda, dm-0, md0.
    El regex viejo `[a-z]+n?\\d+$` saltaba mmcblk0 y md0.
    """
    if not name or name.startswith(("loop", "ram", "sr")):
        return True
    if re.match(r"nvme\d+n\d+p\d+$", name):
        return True
    if re.match(r"mmcblk\d+p\d+$", name):
        return True
    if re.match(r"(sd|vd|hd|xvd)[a-z]\d+$", name):
        return True
    return False


def _mount_volumes(limit: int = 64) -> List[Dict[str, Any]]:
    """Uso de filesystem vía statvfs (sin psutil) para alertas `disks.percent`."""
    skip_fs = {
        "proc",
        "sysfs",
        "devtmpfs",
        "tmpfs",
        "cgroup",
        "cgroup2",
        "overlay",
        "squashfs",
        "autofs",
        "debugfs",
        "tracefs",
        "securityfs",
        "pstore",
        "bpf",
        "devpts",
        "mqueue",
        "hugetlbfs",
        "fusectl",
        "configfs",
        "rpc_pipefs",
    }
    out: List[Dict[str, Any]] = []
    try:
        with open("/proc/mounts", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return out
    seen = set()
    for line in lines:
        parts = line.split()
        if len(parts) < 3:
            continue
        dev, mountpoint, fstype = parts[0], parts[1], parts[2]
        if fstype in skip_fs or mountpoint in seen:
            continue
        if not mountpoint.startswith("/"):
            continue
        seen.add(mountpoint)
        try:
            st = os.statvfs(mountpoint)
        except OSError:
            continue
        total = int(st.f_frsize * st.f_blocks)
        free = int(st.f_frsize * st.f_bavail)
        used = max(0, total - free)
        percent = round(100.0 * used / total, 1) if total else None
        out.append(
            {
                "device": dev,
                "mountpoint": mountpoint,
                "fstype": fstype,
                "total": total,
                "used": used,
                "free": free,
                "percent": percent,
            }
        )
        if len(out) >= limit:
            break
    return out


def _net_sys_stats(max_ifaces: Optional[int] = None) -> List[Dict[str, Any]]:
    """Estadísticas /sys/class/net. Omite `lo`. `max_ifaces=None` = todas."""
    root = "/sys/class/net"
    rows: List[Dict[str, Any]] = []
    try:
        names = sorted(os.listdir(root))
    except OSError:
        return rows
    cap = None if max_ifaces is None else max(1, int(max_ifaces))
    for name in names:
        if name == "lo" or name.startswith("lo:"):
            continue
        base = os.path.join(root, name, "statistics")
        if not os.path.isdir(base):
            continue
        rec: Dict[str, Any] = {"iface": name}
        for field in (
            "rx_bytes",
            "tx_bytes",
            "rx_packets",
            "tx_packets",
            "rx_errors",
            "tx_errors",
            "rx_dropped",
            "tx_dropped",
        ):
            raw = _read_text(os.path.join(base, field)) or "0"
            try:
                rec[field] = int(raw.strip() or 0)
            except ValueError:
                rec[field] = 0
        oper = _read_text(os.path.join(root, name, "operstate"))
        if oper:
            rec["operstate"] = oper.strip()
        rows.append(rec)
        if cap is not None and len(rows) >= cap:
            break
    return rows


def linux_proc_metrics(cpu_interval: float = 0.15) -> Dict[str, Any]:
    """RF-LIN-04: CPU/RAM/load/disco/red desde /proc y /sys, sin psutil."""
    if not _is_linux():
        return _unsupported("linux_proc_metrics")
    try:
        i1, t1 = _stat_cpu()
        time.sleep(max(0.05, float(cpu_interval or 0.15)))
        i2, t2 = _stat_cpu()
        dt = max(1, t2 - t1)
        cpu_pct = round(100.0 * (1.0 - (i2 - i1) / dt), 1)
        mem = _meminfo()
        total = mem.get("MemTotal") or 0
        avail = mem.get("MemAvailable") or mem.get("MemFree") or 0
        swap_t = mem.get("SwapTotal") or 0
        swap_f = mem.get("SwapFree") or 0
        load = (_read_text("/proc/loadavg") or "").split()
        uptime_s = 0.0
        up_raw = (_read_text("/proc/uptime") or "0").split()[0]
        try:
            uptime_s = float(up_raw)
        except ValueError:
            pass
        disks: List[Dict[str, Any]] = []
        for line in (_read_text("/proc/diskstats") or "").splitlines():
            parts = line.split()
            if len(parts) < 14:
                continue
            name = parts[2]
            if _skip_diskstats_name(name):
                continue
            disks.append(
                {
                    "name": name,
                    "reads": int(parts[3]),
                    "writes": int(parts[7]),
                    "read_sectors": int(parts[5]),
                    "write_sectors": int(parts[9]),
                    "in_progress": int(parts[11]) if len(parts) > 11 else 0,
                }
            )
            if len(disks) >= 32:
                break
        return {
            "tool": "linux_proc_metrics",
            "status": "OK",
            "cpu": {
                "percent": cpu_pct,
                "logical_cores": _cpu_count(),
                "load_avg_1": float(load[0]) if len(load) > 0 else None,
                "load_avg_5": float(load[1]) if len(load) > 1 else None,
                "load_avg_15": float(load[2]) if len(load) > 2 else None,
            },
            "memory": {
                "total": total,
                "used": max(0, total - avail) if total else None,
                "available": avail,
                "percent": round(100.0 * (1.0 - avail / total), 1) if total else None,
                "swap_total": swap_t,
                "swap_free": swap_f,
                "swap_used": max(0, swap_t - swap_f) if swap_t else 0,
                "swap_percent": (
                    round(100.0 * (swap_t - swap_f) / swap_t, 1) if swap_t else 0.0
                ),
            },
            "uptime_s": uptime_s,
            "disks": disks,
            "volumes": _mount_volumes(),
            "net": _net_sys_stats(),
            "tcp_connections": linux_tcp_connection_counts(),
            "source": "/proc+/sys",
            "error": None,
            "ts": _now_iso(),
        }
    except Exception as e:
        return {"tool": "linux_proc_metrics", "status": "ERROR", "error": str(e)}


# ---------------------------------------------------------------------------
# RF-LIN-05 netlink (RTNETLINK dump + sockets /proc)
# ---------------------------------------------------------------------------

_NLMSG_DONE = 3
_RTM_NEWLINK = 16
_RTM_GETLINK = 18
_NLM_F_REQUEST = 0x1
_NLM_F_DUMP = 0x100
_IFLA_IFNAME = 3


def _nl_dump(msg_type: int, payload: bytes, timeout: float = 1.5) -> bytes:
    if not hasattr(socket, "AF_NETLINK"):
        return b""
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
    try:
        sock.bind((0, 0))
        sock.settimeout(timeout)
        seq = 1
        hdr = struct.pack("=IHHII", 16 + len(payload), msg_type, _NLM_F_REQUEST | _NLM_F_DUMP, seq, 0)
        sock.send(hdr + payload)
        chunks = []
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data = sock.recv(65535)
            except (socket.timeout, BlockingIOError, OSError):
                break
            if not data:
                break
            chunks.append(data)
            if len(data) >= 16:
                _ln, mtype, flags, _seq, _pid = struct.unpack_from("=IHHII", data, 0)
                if mtype == _NLMSG_DONE or not (flags & 0x2):
                    # last message may be DONE in a later recv
                    if mtype == _NLMSG_DONE:
                        break
        return b"".join(chunks)
    finally:
        sock.close()


def _parse_nl_ifnames(blob: bytes) -> List[str]:
    names: List[str] = []
    off = 0
    while off + 16 <= len(blob):
        length, msg_type, _flags, _seq, _pid = struct.unpack_from("=IHHII", blob, off)
        if length < 16 or off + length > len(blob):
            break
        if msg_type == _NLMSG_DONE:
            break
        if msg_type == _RTM_NEWLINK:
            attr_off = off + 32
            end = off + length
            while attr_off + 4 <= end:
                alen, atype = struct.unpack_from("=HH", blob, attr_off)
                if alen < 4:
                    break
                if atype == _IFLA_IFNAME:
                    raw = blob[attr_off + 4 : attr_off + alen]
                    names.append(raw.split(b"\x00", 1)[0].decode("utf-8", "replace"))
                attr_off += (alen + 3) & ~3
        off += (length + 3) & ~3
    return names


def _proc_tcp_sample(max_rows: int = 30) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    body = _read_text("/proc/net/tcp") or ""
    for line in body.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        local, rem, st, inode = parts[1], parts[2], parts[3], parts[9]
        rows.append({"local": local, "remote": rem, "state": st, "inode": inode})
        if len(rows) >= max_rows:
            break
    return rows


_PROC_STATUS = {
    "R": "running",
    "S": "sleeping",
    "D": "disk-sleep",
    "Z": "zombie",
    "T": "stopped",
    "t": "tracing-stop",
    "X": "dead",
    "x": "dead",
    "K": "wakekill",
    "W": "waking",
    "P": "parked",
    "I": "idle",
}

_TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}

_TCP_COUNT_STATE = {
    "01": "established",
    "02": "syn_sent",
    "03": "syn_recv",
    "06": "time_wait",
    "08": "close_wait",
    "0A": "listen",
}


def empty_tcp_connections() -> Dict[str, int]:
    return {
        "tcp": 0,
        "listen": 0,
        "established": 0,
        "time_wait": 0,
        "syn_recv": 0,
        "syn_sent": 0,
        "close_wait": 0,
        "udp": 0,
    }


def linux_tcp_connection_counts() -> Dict[str, int]:
    """Conteos TCP/UDP de /proc/net (sin tope de muestra, sin resolver PID)."""
    out = empty_tcp_connections()
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        for line in (_read_text(path) or "").splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4:
                continue
            out["tcp"] += 1
            key = _TCP_COUNT_STATE.get(parts[3].upper())
            if key:
                out[key] += 1
    for path in ("/proc/net/udp", "/proc/net/udp6"):
        for line in (_read_text(path) or "").splitlines()[1:]:
            if line.split():
                out["udp"] += 1
    return out


def _hex_endpoint(token: str) -> Optional[str]:
    if ":" not in token:
        return None
    ip_hex, port_hex = token.split(":", 1)
    try:
        port = int(port_hex, 16)
    except ValueError:
        return None
    try:
        raw = bytes.fromhex(ip_hex)
    except ValueError:
        return None
    if len(raw) == 4:
        ip = ".".join(str(b) for b in reversed(raw))
        return f"{ip}:{port}"
    if len(raw) == 16:
        words = b"".join(raw[i : i + 4][::-1] for i in range(0, 16, 4))
        try:
            ip = socket.inet_ntop(socket.AF_INET6, words)
        except OSError:
            return None
        return f"[{ip}]:{port}"
    return None


def _inode_to_pid(limit_scan: int = 400) -> Dict[str, int]:
    mapping: Dict[str, int] = {}
    try:
        pids = [n for n in os.listdir("/proc") if n.isdigit()]
    except OSError:
        return mapping
    for name in pids[:limit_scan]:
        fd_dir = f"/proc/{name}/fd"
        try:
            for fd in os.listdir(fd_dir):
                try:
                    target = os.readlink(os.path.join(fd_dir, fd))
                except OSError:
                    continue
                if target.startswith("socket:[") and target.endswith("]"):
                    mapping[target[8:-1]] = int(name)
        except OSError:
            continue
    return mapping


def linux_connection_rows(
    max_rows: int = 300, *, include_udp: bool = False
) -> List[Dict[str, Any]]:
    """Conexiones vía /proc/net (sin psutil). TCP por defecto; UDP opcional."""
    inode_pid = _inode_to_pid()
    rows: List[Dict[str, Any]] = []
    files = [
        ("/proc/net/tcp", "AF_INET", "SOCK_STREAM"),
        ("/proc/net/tcp6", "AF_INET6", "SOCK_STREAM"),
    ]
    if include_udp:
        files.extend(
            [
                ("/proc/net/udp", "AF_INET", "SOCK_DGRAM"),
                ("/proc/net/udp6", "AF_INET6", "SOCK_DGRAM"),
            ]
        )
    for path, family, sock_type in files:
        body = _read_text(path) or ""
        for line in body.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 10:
                continue
            pid = inode_pid.get(parts[9])
            proc_name = None
            if pid:
                proc_name = (_read_text(f"/proc/{pid}/comm") or "").strip() or None
            status = (
                _TCP_STATES.get(parts[3].upper(), parts[3])
                if sock_type == "SOCK_STREAM"
                else "UDP"
            )
            rows.append(
                {
                    "fd": None,
                    "family": family,
                    "type": sock_type,
                    "laddr": _hex_endpoint(parts[1]),
                    "raddr": _hex_endpoint(parts[2]),
                    "status": status,
                    "pid": pid,
                    "process_name": proc_name,
                }
            )
            if len(rows) >= max_rows:
                return rows
    return rows


def _proc_btime() -> float:
    for line in (_read_text("/proc/stat") or "").splitlines():
        if line.startswith("btime "):
            try:
                return float(line.split()[1])
            except (IndexError, ValueError):
                return 0.0
    return 0.0


def _linux_one_proc(
    pid: int, needle: str, clk: float, btime: float
) -> Optional[Dict[str, Any]]:
    import pwd

    stat = _read_text(f"/proc/{pid}/stat")
    if not stat:
        return None
    comm_start = stat.find("(")
    comm_end = stat.rfind(")")
    if comm_start < 0 or comm_end < comm_start:
        return None
    name = stat[comm_start + 1 : comm_end]
    if needle and needle not in name.lower():
        return None
    rest = stat[comm_end + 2 :].split()
    if len(rest) < 20:
        return None
    try:
        ppid = int(rest[1])
        startticks = float(rest[19])
    except (TypeError, ValueError):
        return None
    create_ts = btime + startticks / clk if clk else None
    cmdline = (_read_text(f"/proc/{pid}/cmdline") or "").replace("\x00", " ").strip()[:500]
    uid = None
    for line in (_read_text(f"/proc/{pid}/status") or "").splitlines():
        if line.startswith("Uid:"):
            try:
                uid = int(line.split()[1])
            except (IndexError, ValueError):
                uid = None
            break
    username = None
    if uid is not None:
        try:
            username = pwd.getpwuid(uid).pw_name
        except KeyError:
            username = str(uid)
    return {
        "pid": pid,
        "ppid": ppid,
        "name": name,
        "username": username,
        "status": _PROC_STATUS.get(rest[0], rest[0]),
        "status_code": rest[0],
        "create_time": (
            datetime.fromtimestamp(create_ts, tz=timezone.utc).isoformat()
            if create_ts
            else None
        ),
        "create_time_unix": create_ts,
        "cpu_percent": None,
        "memory_percent": None,
        "cmdline": cmdline,
    }


def linux_process_rows(
    name_filter: Optional[str] = None, limit: int = 300
) -> Tuple[List[Dict[str, Any]], bool]:
    """Snapshot de procesos vía /proc (sin psutil)."""
    needle = (name_filter or "").lower().strip()
    try:
        clk = float(os.sysconf("SC_CLK_TCK") or 100)
    except (ValueError, OSError):
        clk = 100.0
    btime = _proc_btime()
    procs: List[Dict[str, Any]] = []
    truncated = False
    try:
        pids = sorted(int(n) for n in os.listdir("/proc") if n.isdigit())
    except OSError:
        return [], False
    for pid in pids:
        if len(procs) >= max(1, int(limit)):
            truncated = True
            break
        rec = _linux_one_proc(pid, needle, clk, btime)
        if rec:
            procs.append(rec)
    return procs, truncated


def linux_netlink(max_ifaces: int = 32) -> Dict[str, Any]:
    """RF-LIN-05: dump RTNETLINK (links) + muestra de sockets /proc/net/tcp."""
    if not _is_linux():
        return _unsupported("linux_netlink")
    max_ifaces = max(1, min(int(max_ifaces or 32), 128))
    try:
        # ifinfomsg: family, pad, type, index, flags, change
        payload = struct.pack("=BBHiII", 0, 0, 0, 0, 0, 0)
        blob = _nl_dump(_RTM_GETLINK, payload)
        ifaces = _parse_nl_ifnames(blob)[:max_ifaces]
        if not ifaces:
            try:
                ifaces = [
                    n for n in sorted(os.listdir("/sys/class/net")) if n
                ][:max_ifaces]
            except OSError:
                ifaces = []
        sys_net = _net_sys_stats(max_ifaces)
        return {
            "tool": "linux_netlink",
            "status": "OK",
            "via": "AF_NETLINK" if blob else "/sys/class/net",
            "count": len(ifaces),
            "interfaces": [{"name": n} for n in ifaces],
            "stats": sys_net,
            "sockets": _proc_tcp_sample(),
            "error": None,
            "ts": _now_iso(),
        }
    except Exception as e:
        return {"tool": "linux_netlink", "status": "ERROR", "error": str(e)}


# ---------------------------------------------------------------------------
# RF-LIN-06 systemd units / timers
# ---------------------------------------------------------------------------

def _systemctl_rows(
    args: List[str], max_rows: int, *, unit_suffix: Optional[str] = None
) -> List[Dict[str, str]]:
    if not shutil.which("systemctl"):
        return []
    res = _run(["systemctl", *args, "--no-pager", "--no-legend", "--plain"], timeout=15)
    rows: List[Dict[str, str]] = []
    for line in (res.stdout or "").splitlines():
        rec = parse_systemctl_line(line, unit_suffix=unit_suffix)
        if rec:
            rows.append(rec)
    rows.sort(key=lambda r: str(r.get("unit") or ""))
    return rows[: max(1, int(max_rows))]


def parse_systemctl_line(
    line: str, *, unit_suffix: Optional[str] = None
) -> Optional[Dict[str, str]]:
    """Una fila de `systemctl --plain --no-legend`.

    `list-units`: UNIT LOAD ACTIVE SUB …
    `list-timers`: NEXT … UNIT(.timer) ACTIVATES — el unit no es la 1ª columna.
    """
    parts = (line or "").split()
    if not parts:
        return None
    if unit_suffix:
        unit = next((p for p in parts if p.endswith(unit_suffix)), "")
        if not unit:
            return None
        return {"unit": unit, "raw": line.strip()[:240]}
    rec = {"unit": parts[0], "raw": line.strip()[:240]}
    if len(parts) > 1:
        rec["load"] = parts[1]
    if len(parts) > 2:
        rec["active"] = parts[2]
    if len(parts) > 3:
        rec["sub"] = parts[3]
    if len(parts) > 4:
        rec["description"] = " ".join(parts[4:])[:200]
    return rec


def parse_unit_file_line(line: str) -> Optional[Dict[str, str]]:
    """Una fila de `systemctl list-unit-files --plain --no-legend`.

    Columnas: UNIT FILE, STATE, PRESET. No es `list-units` (LOAD/ACTIVE/SUB).
    """
    parts = (line or "").split()
    if not parts:
        return None
    rec: Dict[str, str] = {"unit": parts[0], "raw": line.strip()[:240]}
    if len(parts) > 1:
        rec["state"] = parts[1]
    if len(parts) > 2:
        rec["preset"] = parts[2]
    return rec


def _unit_file_rows(max_rows: int) -> List[Dict[str, str]]:
    if not shutil.which("systemctl"):
        return []
    res = _run(
        [
            "systemctl",
            "list-unit-files",
            "--type=service",
            "--state=enabled",
            "--no-pager",
            "--no-legend",
            "--plain",
        ],
        timeout=15,
    )
    rows: List[Dict[str, str]] = []
    for line in (res.stdout or "").splitlines():
        rec = parse_unit_file_line(line)
        if rec:
            rows.append(rec)
    rows.sort(key=lambda r: str(r.get("unit") or ""))
    return rows[: max(1, int(max_rows))]


def _enrich_enabled(
    enabled: List[Dict[str, str]], units: List[Dict[str, str]]
) -> List[Dict[str, str]]:
    """Copia load/active/sub desde units[] si la unit está cargada."""
    by_unit = {
        str(u.get("unit") or ""): u
        for u in units
        if isinstance(u, dict) and u.get("unit")
    }
    out: List[Dict[str, str]] = []
    for row in enabled:
        rec = dict(row)
        live = by_unit.get(str(rec.get("unit") or "")) or {}
        for key in ("load", "active", "sub"):
            val = live.get(key)
            if val:
                rec[key] = str(val)
        out.append(rec)
    return out


def linux_systemd_units(
    max_units: int = 400, max_timers: int = 200
) -> Dict[str, Any]:
    """RF-LIN-06: servicios y timers systemd (persistencia)."""
    if not _is_linux():
        return _unsupported("linux_systemd_units")
    max_units = max(1, min(int(max_units or 400), 400))
    max_timers = max(1, min(int(max_timers or 200), 200))
    try:
        if not shutil.which("systemctl"):
            return {
                "tool": "linux_systemd_units",
                "status": "ERROR",
                "error": "systemctl no está en PATH",
            }
        units = _systemctl_rows(
            ["list-units", "--type=service", "--all"], max_units
        )
        timers = _systemctl_rows(
            ["list-units", "--type=timer", "--all"], max_timers
        )
        enabled = _enrich_enabled(_unit_file_rows(max_units), units)
        failed = sum(
            1
            for u in units
            if str((u or {}).get("active") or "").lower() == "failed"
        )
        return {
            "tool": "linux_systemd_units",
            "status": "OK",
            "count": len(units),
            "failed": failed,
            "units": units,
            "timers": timers,
            "enabled": enabled,
            "error": None,
            "ts": _now_iso(),
        }
    except Exception as e:
        return {"tool": "linux_systemd_units", "status": "ERROR", "error": str(e)}


def systemd_fingerprint(scan: Optional[Dict[str, Any]] = None) -> Dict[str, Dict[str, Any]]:
    rec = scan if isinstance(scan, dict) else linux_systemd_units()
    out: Dict[str, Dict[str, Any]] = {}
    for key in ("units", "timers", "enabled"):
        for item in rec.get(key) or []:
            name = str(item.get("unit") or "")
            if not name:
                continue
            out[f"{key}:{name}"] = item
    return out


# ---------------------------------------------------------------------------
# RF-LIN-07 SELinux / AppArmor (ok si están off)
# ---------------------------------------------------------------------------

def _selinux_status() -> Dict[str, Any]:
    enforce_path = "/sys/fs/selinux/enforce"
    present = _exists("/sys/fs/selinux") or _exists("/etc/selinux/config")
    mode = None
    if shutil.which("getenforce"):
        res = _run(["getenforce"], timeout=8)
        mode = (res.stdout or "").strip() or None
    elif _exists(enforce_path):
        raw = (_read_text(enforce_path) or "").strip()
        mode = {"1": "Enforcing", "0": "Permissive"}.get(raw, raw or None)
    denials: List[str] = []
    log_path = _audit_log_path()
    if log_path:
        for ln in _tail_lines(log_path, 200):
            if "AVC" in ln or "avc:" in ln:
                denials.append(ln[:240])
            if len(denials) >= 12:
                break
    return {
        "present": present,
        "mode": mode or ("disabled" if not present else "unknown"),
        "denials": denials,
    }


def _apparmor_status() -> Dict[str, Any]:
    enabled_path = "/sys/module/apparmor/parameters/enabled"
    present = _exists("/sys/kernel/security/apparmor") or _exists(enabled_path)
    mode = None
    profiles: List[str] = []
    if shutil.which("aa-status"):
        res = _run(["aa-status"], timeout=10)
        text = res.stdout or ""
        mode = "enabled" if res.returncode == 0 else "unknown"
        for ln in text.splitlines()[:40]:
            if ln.strip():
                profiles.append(ln.strip()[:180])
    elif _exists(enabled_path):
        raw = (_read_text(enabled_path) or "").strip().lower()
        mode = "enabled" if raw in ("y", "1", "yes") else "disabled"
    denials: List[str] = []
    if shutil.which("journalctl"):
        res = _run(
            ["journalctl", "-k", "-n", "80", "--no-pager", "-g", "apparmor"],
            timeout=12,
        )
        for ln in (res.stdout or "").splitlines():
            if "DENIED" in ln or "apparmor" in ln.lower():
                denials.append(ln[:240])
            if len(denials) >= 12:
                break
    return {
        "present": present,
        "mode": mode or ("disabled" if not present else "unknown"),
        "profiles": profiles[:20],
        "denials": denials,
    }


def linux_lsm() -> Dict[str, Any]:
    """RF-LIN-07: SELinux/AppArmor; no falla si están inactivos."""
    if not _is_linux():
        return _unsupported("linux_lsm")
    try:
        selinux = _selinux_status()
        apparmor = _apparmor_status()
        return {
            "tool": "linux_lsm",
            "status": "OK",
            "selinux": selinux,
            "apparmor": apparmor,
            "active": bool(
                str(selinux.get("mode") or "").lower() in ("enforcing", "permissive")
                or str(apparmor.get("mode") or "").lower() == "enabled"
            ),
            "error": None,
            "ts": _now_iso(),
        }
    except Exception as e:
        return {"tool": "linux_lsm", "status": "ERROR", "error": str(e)}


# ---------------------------------------------------------------------------
# RF-LIN-08 dpkg/rpm + hash de binario
# ---------------------------------------------------------------------------

def _sha256_file(path: str) -> Optional[str]:
    import hashlib

    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def hash_linux_package(name: str, manager: str) -> Optional[Dict[str, str]]:
    """SHA-256 del primer ejecutable del paquete (dpkg -L / rpm -ql)."""
    name = (name or "").strip()
    if not name:
        return None
    which = shutil.which(name)
    if which:
        digest = _sha256_file(which)
        if digest:
            return {"path": which, "sha256": digest}
    cmd = ["dpkg", "-L", name] if manager == "dpkg" else ["rpm", "-ql", name]
    if not shutil.which(cmd[0]):
        return None
    res = _run(cmd, timeout=8)
    for path in (res.stdout or "").splitlines():
        path = path.strip()
        if not path.startswith("/"):
            continue
        if "/bin/" not in path and "/sbin/" not in path:
            continue
        if not os.path.isfile(path) or not os.access(path, os.X_OK):
            continue
        digest = _sha256_file(path)
        if digest:
            return {"path": path, "sha256": digest}
    return None


def linux_packages(
    include_hash: bool = False, max_hash: int = 20, max_packages: int = 400
) -> Dict[str, Any]:
    """RF-LIN-08: inventario dpkg o rpm, con hash opcional de binarios."""
    if not _is_linux():
        return _unsupported("linux_packages")
    max_hash = max(0, min(int(max_hash or 20), 80))
    max_packages = max(1, min(int(max_packages or 400), 4000))
    try:
        pkgs: List[Dict[str, Any]] = []
        manager = None
        if shutil.which("dpkg-query"):
            res = _run(["dpkg-query", "-W", "-f=${Package}\\t${Version}\\n"], timeout=30)
            manager = "dpkg"
            for line in (res.stdout or "").splitlines():
                if "\t" not in line:
                    continue
                name, version = line.split("\t", 1)
                pkgs.append({"name": name, "version": version})
                if len(pkgs) >= max_packages:
                    break
        elif shutil.which("rpm"):
            res = _run(
                ["rpm", "-qa", "--qf", "%{NAME}\\t%{VERSION}-%{RELEASE}\\n"],
                timeout=30,
            )
            manager = "rpm"
            for line in (res.stdout or "").splitlines():
                if "\t" not in line:
                    continue
                name, version = line.split("\t", 1)
                pkgs.append({"name": name, "version": version})
                if len(pkgs) >= max_packages:
                    break
        else:
            return {
                "tool": "linux_packages",
                "status": "ERROR",
                "error": "No se encontró dpkg ni rpm",
            }
        hashed = 0
        if include_hash and manager:
            for pkg in pkgs:
                if hashed >= max_hash:
                    break
                info = hash_linux_package(pkg.get("name") or "", manager)
                if info:
                    pkg.update(info)
                    hashed += 1
        return {
            "tool": "linux_packages",
            "status": "OK",
            "package_manager": manager,
            "count": len(pkgs),
            "hashed": hashed,
            "cross_tool": "installed_software",
            "packages": pkgs,
            "error": None,
            "ts": _now_iso(),
        }
    except Exception as e:
        return {"tool": "linux_packages", "status": "ERROR", "error": str(e)}
