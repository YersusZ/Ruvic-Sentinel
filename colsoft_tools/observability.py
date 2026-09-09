"""
Herramientas de observabilidad para el agente de endpoint (Colsoft).

Cubre la categoría "B. Recolección de información" del catálogo de comandos
del SRS (get_process_list, get_service_status, get_network_connections,
get_installed_software, get_disk_usage, get_file_hash,
collect_forensic_snapshot, get_system_log) más `get_system_metrics`
(RF-OBS-01), inventario de hardware (RF-OBS-05) y health probes (RF-OBS-07).
Los logs se normalizan a entradas estructuradas (RF-OBS-04).

Todas las funciones devuelven dicts serializables a JSON y nunca lanzan
excepciones hacia afuera: cualquier error queda en el campo "error" del
resultado, siguiendo el mismo patrón que colsoft_tools.network_checks.

Requiere `psutil` (agregar a requirements.txt). Las funciones que dependen
de psutil hacen el import de forma perezosa y devuelven un error claro si
no está instalado, en vez de romper la carga del módulo completo.
"""

import hashlib
import io
import csv
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from colsoft_tools.event_model import SCHEMA_VERSION


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _require_psutil():
    try:
        import psutil  # type: ignore
        return psutil
    except ImportError as e:
        raise RuntimeError(
            "psutil no está instalado. Agrega 'psutil' a requirements.txt "
            "e inclúyelo como hidden-import en el build de PyInstaller."
        ) from e


def _run(cmd: List[str], timeout: int = 15) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


_TCP_STATUS_COUNT = {
    "LISTEN": "listen",
    "ESTABLISHED": "established",
    "TIME_WAIT": "time_wait",
    "SYN_RECV": "syn_recv",
    "SYN_RECEIVED": "syn_recv",
    "SYN_SENT": "syn_sent",
    "CLOSE_WAIT": "close_wait",
}


def empty_tcp_connections() -> Dict[str, int]:
    from colsoft_tools.linux_collectors import empty_tcp_connections as _empty

    return _empty()


def connection_counts_from_psutil(conns: Any) -> Dict[str, int]:
    """Conteos TCP/UDP desde `psutil.net_connections` (Windows / macOS).

    Mismos campos que `linux_tcp_connection_counts`. UDP = SOCK_DGRAM o status NONE.
    """
    out = empty_tcp_connections()
    for c in conns or []:
        try:
            sock_type = int(getattr(c, "type", socket.SOCK_STREAM))
        except (TypeError, ValueError):
            sock_type = socket.SOCK_STREAM
        status = str(getattr(c, "status", "") or "").upper()
        if sock_type == socket.SOCK_DGRAM or status in ("NONE", "UDP"):
            out["udp"] += 1
            continue
        if sock_type != socket.SOCK_STREAM:
            continue
        out["tcp"] += 1
        key = _TCP_STATUS_COUNT.get(status)
        if key:
            out[key] += 1
    return out


def _psutil_tcp_connection_counts() -> Optional[Dict[str, int]]:
    try:
        psutil = _require_psutil()
        return connection_counts_from_psutil(psutil.net_connections(kind="inet"))
    except Exception:
        return None


def _is_loopback_iface(name: str) -> bool:
    n = (name or "").strip().lower()
    return (
        not n
        or n == "lo"
        or n.startswith("lo:")
        or n.startswith("loopback")
        or n.startswith("isatap")
        or n.startswith("teredo")
    )


def _psutil_network_io(psutil_mod: Any) -> Dict[str, Any]:
    """Totales de NIC sin loopback, alineado con Linux (`lo` omitido)."""
    pernic: Dict[str, Any] = {}
    try:
        pernic = psutil_mod.net_io_counters(pernic=True) or {}
    except Exception:
        pernic = {}
    if pernic:
        sent = recv = pkt_s = pkt_r = errin = errout = dropin = dropout = 0
        interfaces: List[Dict[str, Any]] = []
        for name in sorted(pernic):
            if _is_loopback_iface(str(name)):
                continue
            io = pernic[name]
            rec = {
                "iface": name,
                "bytes_sent": int(getattr(io, "bytes_sent", 0) or 0),
                "bytes_recv": int(getattr(io, "bytes_recv", 0) or 0),
                "packets_sent": int(getattr(io, "packets_sent", 0) or 0),
                "packets_recv": int(getattr(io, "packets_recv", 0) or 0),
                "errin": int(getattr(io, "errin", 0) or 0),
                "errout": int(getattr(io, "errout", 0) or 0),
                "dropin": int(getattr(io, "dropin", 0) or 0),
                "dropout": int(getattr(io, "dropout", 0) or 0),
            }
            sent += rec["bytes_sent"]
            recv += rec["bytes_recv"]
            pkt_s += rec["packets_sent"]
            pkt_r += rec["packets_recv"]
            errin += rec["errin"]
            errout += rec["errout"]
            dropin += rec["dropin"]
            dropout += rec["dropout"]
            interfaces.append(rec)
        return {
            "bytes_sent": sent,
            "bytes_recv": recv,
            "packets_sent": pkt_s,
            "packets_recv": pkt_r,
            "errin": errin,
            "errout": errout,
            "dropin": dropin,
            "dropout": dropout,
            "interfaces": interfaces,
        }
    net_io = psutil_mod.net_io_counters()
    return {
        "bytes_sent": net_io.bytes_sent,
        "bytes_recv": net_io.bytes_recv,
        "packets_sent": net_io.packets_sent,
        "packets_recv": net_io.packets_recv,
        "errin": net_io.errin,
        "errout": net_io.errout,
        "dropin": net_io.dropin,
        "dropout": net_io.dropout,
    }


# ---------------------------------------------------------------------------
# RF-OBS-01: métricas de CPU, memoria, disco, red, uptime
# ---------------------------------------------------------------------------

def _max_mount_percent(volumes: Any) -> Optional[float]:
    """Uso máximo de filesystem; scalar para que el compactador no recorte el max."""
    best: Optional[float] = None
    for row in volumes or []:
        if not isinstance(row, dict):
            continue
        p = row.get("percent")
        if isinstance(p, (int, float)) and not isinstance(p, bool):
            best = float(p) if best is None else max(best, float(p))
    return best


def _diskstats_io_dict(rows: Any) -> Dict[str, Any]:
    """Totales de diskstats (ops/bytes/cola), misma forma que Windows `disk_io`."""
    reads = writes = rbytes = wbytes = 0
    queue = 0.0
    any_ops = any_bytes = any_q = False
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        r = row.get("reads")
        if r is None:
            r = row.get("read_count")
        w = row.get("writes")
        if w is None:
            w = row.get("write_count")
        if isinstance(r, (int, float)) and not isinstance(r, bool):
            reads += int(r)
            any_ops = True
        if isinstance(w, (int, float)) and not isinstance(w, bool):
            writes += int(w)
            any_ops = True
        rb = row.get("read_bytes")
        wb = row.get("write_bytes")
        rs = row.get("read_sectors")
        ws = row.get("write_sectors")
        if isinstance(rb, (int, float)) and not isinstance(rb, bool):
            rbytes += int(rb)
            any_bytes = True
        elif isinstance(rs, (int, float)) and not isinstance(rs, bool):
            rbytes += int(rs) * 512
            any_bytes = True
        if isinstance(wb, (int, float)) and not isinstance(wb, bool):
            wbytes += int(wb)
            any_bytes = True
        elif isinstance(ws, (int, float)) and not isinstance(ws, bool):
            wbytes += int(ws) * 512
            any_bytes = True
        ip = row.get("in_progress")
        if ip is None:
            ip = row.get("ios_in_progress")
        if isinstance(ip, (int, float)) and not isinstance(ip, bool):
            queue += float(ip)
            any_q = True
    out: Dict[str, Any] = {}
    if any_ops:
        out["read_count"] = reads
        out["write_count"] = writes
    if any_bytes:
        out["read_bytes"] = rbytes
        out["write_bytes"] = wbytes
    if any_q:
        out["queue_length"] = queue
    return out


def get_system_metrics(cpu_interval: float = 0.5) -> Dict[str, Any]:
    """
    Snapshot de métricas de sistema: CPU, memoria, discos, I/O de red,
    load average (si aplica) y uptime.

    En Linux usa `/proc`+`/sys` (RF-LIN-04), sin psutil.
    """
    if platform.system() == "Linux":
        from colsoft_tools.linux_collectors import linux_proc_metrics

        rec = linux_proc_metrics(cpu_interval=cpu_interval)
        if rec.get("status") != "OK":
            rec = dict(rec)
            rec["tool"] = "system_metrics"
            rec.setdefault("hostname", platform.node())
            rec.setdefault("os", platform.system())
            return rec
        cpu = dict(rec.get("cpu") or {})
        mem = dict(rec.get("memory") or {})
        cpu["load_avg_1_5_15"] = [
            cpu.get("load_avg_1"),
            cpu.get("load_avg_5"),
            cpu.get("load_avg_15"),
        ]
        volumes = rec.get("volumes") or []
        tcp_connections = rec.get("tcp_connections")
        if not isinstance(tcp_connections, dict):
            from colsoft_tools.linux_collectors import linux_tcp_connection_counts

            tcp_connections = linux_tcp_connection_counts()
        return {
            "tool": "system_metrics",
            "status": "OK",
            "timestamp": rec.get("ts") or _now_iso(),
            "hostname": platform.node(),
            "os": platform.system(),
            "os_version": platform.version(),
            "arch": platform.machine(),
            "cpu": cpu,
            "memory": {
                "total": mem.get("total"),
                "used": mem.get("used"),
                "available": mem.get("available"),
                "percent": mem.get("percent"),
                "swap_total": mem.get("swap_total"),
                "swap_free": mem.get("swap_free"),
                "swap_used": mem.get("swap_used"),
                "swap_percent": mem.get("swap_percent"),
            },
            "disks": volumes,
            "disk_io": _diskstats_io_dict(rec.get("disks") or []),
            "filesystem_percent_max": _max_mount_percent(volumes),
            "network_io": _linux_network_io(rec.get("net") or []),
            "tcp_connections": tcp_connections,
            "uptime_seconds": rec.get("uptime_s"),
            "source": rec.get("source") or "/proc+/sys",
            "error": rec.get("error"),
        }
    try:
        psutil = _require_psutil()

        cpu_percent = psutil.cpu_percent(interval=cpu_interval)
        cpu_percent_per_core = psutil.cpu_percent(interval=None, percpu=True)
        cpu_count_logical = psutil.cpu_count(logical=True)
        cpu_count_physical = psutil.cpu_count(logical=False)

        vm = psutil.virtual_memory()
        swap = psutil.swap_memory()

        disks = []
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
                disks.append({
                    "device": part.device,
                    "mountpoint": part.mountpoint,
                    "fstype": part.fstype,
                    "total": usage.total,
                    "used": usage.used,
                    "free": usage.free,
                    "percent": usage.percent,
                })
            except (PermissionError, OSError):
                continue

        net_io = _psutil_network_io(psutil)
        disk_counters = None
        try:
            disk_counters = psutil.disk_io_counters()
        except Exception:
            disk_counters = None

        load_avg = None
        if hasattr(os, "getloadavg"):
            try:
                load_avg = list(os.getloadavg())
            except OSError:
                load_avg = None

        boot_ts = psutil.boot_time()
        uptime_seconds = time.time() - boot_ts

        queues: Dict[str, Any] = {}
        try:
            from colsoft_tools.windows_collectors import windows_perf_queues

            queues = windows_perf_queues()
        except Exception:
            queues = {}
        pql = queues.get("processor_queue_length")
        tcp_connections = _psutil_tcp_connection_counts()

        out: Dict[str, Any] = {
            "tool": "system_metrics",
            "status": "OK",
            "timestamp": _now_iso(),
            "hostname": platform.node(),
            "os": platform.system(),
            "os_version": platform.version(),
            "arch": platform.machine(),
            "cpu": {
                "percent": cpu_percent,
                "percent_per_core": cpu_percent_per_core,
                "logical_cores": cpu_count_logical,
                "physical_cores": cpu_count_physical,
                "load_avg_1_5_15": load_avg,
                "load_avg_1": load_avg[0] if load_avg else None,
                "load_avg_5": load_avg[1] if load_avg and len(load_avg) > 1 else None,
                "load_avg_15": load_avg[2] if load_avg and len(load_avg) > 2 else None,
                "processor_queue_length": pql,
                "system_processor_queue_length": pql,
            },
            "memory": {
                "total": vm.total,
                "used": vm.used,
                "available": vm.available,
                "percent": vm.percent,
                "swap_total": swap.total,
                "swap_used": swap.used,
                "swap_free": max(0, int(swap.total) - int(swap.used)),
                "swap_percent": swap.percent,
            },
            "disks": disks,
            "filesystem_percent_max": _max_mount_percent(disks),
            "disk_io": {
                "queue_length": queues.get("disk_queue_length"),
                "read_count": getattr(disk_counters, "read_count", None),
                "write_count": getattr(disk_counters, "write_count", None),
                "read_bytes": getattr(disk_counters, "read_bytes", None),
                "write_bytes": getattr(disk_counters, "write_bytes", None),
            },
            "network_io": net_io,
            "boot_time": datetime.fromtimestamp(boot_ts, tz=timezone.utc).isoformat(),
            "uptime_seconds": uptime_seconds,
            "error": None,
        }
        if tcp_connections is not None:
            out["tcp_connections"] = tcp_connections
        return out
    except Exception as e:
        return {"tool": "system_metrics", "status": "ERROR", "error": str(e)}


# ---------------------------------------------------------------------------
# RF-OBS-02 / tabla B: get_process_list
# ---------------------------------------------------------------------------

def get_process_list(name_filter: Optional[str] = None, limit: int = 300) -> Dict[str, Any]:
    """
    Snapshot de procesos activos. `name_filter` filtra por substring
    (case-insensitive) sobre el nombre del proceso.
    """
    limit = max(1, int(limit or 300))
    try:
        if platform.system() == "Linux":
            from colsoft_tools.linux_collectors import linux_process_rows

            procs, truncated = linux_process_rows(name_filter=name_filter, limit=limit)
            return {
                "tool": "process_list",
                "status": "OK",
                "count": len(procs),
                "truncated": truncated,
                "processes": [
                    {k: v for k, v in p.items() if k != "create_time_unix"}
                    for p in procs
                ],
                "source": "/proc",
                "error": None,
            }
        psutil = _require_psutil()
        procs = []
        needle = (name_filter or "").lower().strip()

        for p in psutil.process_iter(
            ["pid", "ppid", "name", "username", "status", "create_time",
             "cpu_percent", "memory_percent", "cmdline"]
        ):
            try:
                info = p.info
                if needle and needle not in (info.get("name") or "").lower():
                    continue
                procs.append({
                    "pid": info.get("pid"),
                    "ppid": info.get("ppid"),
                    "name": info.get("name"),
                    "username": info.get("username"),
                    "status": info.get("status"),
                    "create_time": datetime.fromtimestamp(
                        info["create_time"], tz=timezone.utc
                    ).isoformat() if info.get("create_time") else None,
                    "cpu_percent": info.get("cpu_percent"),
                    "memory_percent": round(info.get("memory_percent") or 0.0, 2),
                    "cmdline": " ".join(info.get("cmdline") or [])[:500],
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        procs.sort(key=lambda x: x.get("cpu_percent") or 0, reverse=True)
        truncated = len(procs) > limit
        procs = procs[:limit]

        return {
            "tool": "process_list",
            "status": "OK",
            "count": len(procs),
            "truncated": truncated,
            "processes": procs,
            "error": None,
        }
    except Exception as e:
        return {"tool": "process_list", "status": "ERROR", "count": 0, "processes": [], "error": str(e)}


# ---------------------------------------------------------------------------
# RF-OBS-03 / tabla B: get_service_status
# ---------------------------------------------------------------------------

def get_service_status(service_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Estado de un servicio/daemon puntual, o listado completo si
    `service_name` es None. Windows -> `sc query`; Linux -> systemctl;
    macOS -> launchctl.
    """
    system = platform.system()
    try:
        if system == "Linux":
            return _service_status_linux(service_name)
        if system == "Windows":
            return _service_status_windows(service_name)
        if system == "Darwin":
            return _service_status_macos(service_name)
        return {"tool": "service_status", "status": "ERROR", "error": f"SO no soportado: {system}"}
    except Exception as e:
        return {"tool": "service_status", "status": "ERROR", "error": str(e)}


def _service_status_linux(service_name: Optional[str]) -> Dict[str, Any]:
    from colsoft_tools.linux_collectors import _systemctl_rows

    if service_name:
        res = _run(["systemctl", "show", service_name, "--no-page",
                     "--property=ActiveState,SubState,LoadState,UnitFileState"])
        if res.returncode != 0:
            return {"tool": "service_status", "status": "ERROR", "service_name": service_name,
                     "error": res.stderr.strip() or "systemctl falló"}
        props = dict(
            line.split("=", 1) for line in res.stdout.strip().splitlines() if "=" in line
        )
        return {
            "tool": "service_status",
            "status": "OK",
            "service_name": service_name,
            "unit": service_name if str(service_name).endswith(".service") else f"{service_name}.service",
            "active_state": props.get("ActiveState"),
            "sub_state": props.get("SubState"),
            "load_state": props.get("LoadState"),
            "enabled": props.get("UnitFileState"),
            "error": None,
        }

    rows = _systemctl_rows(["list-units", "--type=service", "--all"], 400)
    services = [
        {
            "unit": rec.get("unit"),
            "load": rec.get("load"),
            "active": rec.get("active"),
            "sub": rec.get("sub"),
            "active_state": rec.get("active"),
            "sub_state": rec.get("sub"),
            "description": rec.get("description") or "",
        }
        for rec in rows
        if str(rec.get("unit") or "").endswith(".service")
    ]
    return {"tool": "service_status", "status": "OK", "count": len(services), "services": services, "error": None}


def _windows_scm_state(raw: Optional[str]) -> Dict[str, Optional[str]]:
    text = (raw or "").upper()
    if "RUNNING" in text:
        active, sub = "running", "running"
    elif "STOPPED" in text:
        active, sub = "stopped", "dead"
    elif "START_PENDING" in text:
        active, sub = "activating", "start-pending"
    elif "STOP_PENDING" in text:
        active, sub = "deactivating", "stop-pending"
    elif "PAUSED" in text:
        active, sub = "inactive", "paused"
    else:
        active, sub = None, None
    return {"active_state": active, "sub_state": sub, "active": active, "sub": sub, "raw_state": raw}


def _service_status_windows(service_name: Optional[str]) -> Dict[str, Any]:
    if service_name:
        res = _run(["sc", "query", service_name])
        if res.returncode != 0:
            return {"tool": "service_status", "status": "ERROR", "service_name": service_name,
                     "error": res.stderr.strip() or "sc query falló"}
        state = None
        for line in res.stdout.splitlines():
            if "STATE" in line:
                state = line.strip()
        parsed = _windows_scm_state(state)
        return {
            "tool": "service_status",
            "status": "OK",
            "service_name": service_name,
            "unit": service_name,
            "active_state": parsed["active_state"],
            "sub_state": parsed["sub_state"],
            "raw_state": state,
            "error": None,
        }

    res = _run(["sc", "query", "type=", "service", "state=", "all"], timeout=30)
    services = []
    current: Dict[str, Any] = {}
    for line in res.stdout.splitlines():
        line = line.strip()
        if line.startswith("SERVICE_NAME:"):
            if current:
                services.append(current)
            name = line.split(":", 1)[1].strip()
            current = {"service_name": name, "unit": name}
        elif line.startswith("STATE") and current:
            parsed = _windows_scm_state(line)
            current.update(parsed)
    if current:
        services.append(current)
    return {"tool": "service_status", "status": "OK", "count": len(services), "services": services, "error": None}


def snapshot_services() -> Dict[str, Dict[str, Any]]:
    """Mapa unit → estado para ServiceWatcher (RF-OBS-03)."""
    rec = get_service_status()
    out: Dict[str, Dict[str, Any]] = {}
    for item in rec.get("services") or []:
        if not isinstance(item, dict):
            continue
        key = str(item.get("unit") or item.get("service_name") or item.get("label") or "")
        if not key:
            continue
        out[key] = {
            "unit": key,
            "active": item.get("active") or item.get("active_state"),
            "sub": item.get("sub") or item.get("sub_state"),
        }
    return out


def _service_status_macos(service_name: Optional[str]) -> Dict[str, Any]:
    res = _run(["launchctl", "list"], timeout=20)
    lines = res.stdout.strip().splitlines()[1:]
    services = []
    for line in lines:
        parts = line.split(None, 2)
        if len(parts) == 3:
            pid, status, label = parts
            if service_name and service_name not in label:
                continue
            services.append({
                "label": label,
                "unit": label,
                "pid": None if pid == "-" else pid,
                "last_exit_status": status,
                "active": "running" if pid != "-" else "stopped",
                "sub": status,
                "active_state": "running" if pid != "-" else "stopped",
                "sub_state": status,
            })
    if service_name:
        return {"tool": "service_status", "status": "OK" if services else "ERROR",
                 "service_name": service_name, "services": services,
                 "error": None if services else "Servicio no encontrado"}
    return {"tool": "service_status", "status": "OK", "count": len(services), "services": services, "error": None}


# ---------------------------------------------------------------------------
# RF-OBS-06 / tabla B: get_network_connections
# ---------------------------------------------------------------------------

def get_network_connections(kind: str = "inet") -> Dict[str, Any]:
    """
    Snapshot de conexiones de red activas, asociando proceso cuando el
    SO/privilegios lo permiten (RF-OBS-06).
    """
    try:
        if platform.system() == "Linux":
            from colsoft_tools.linux_collectors import (
                linux_connection_rows,
                linux_tcp_connection_counts,
            )

            conns = linux_connection_rows(max_rows=300, include_udp=True)
            counts = linux_tcp_connection_counts()
            listed = len(conns)
            total = int(counts.get("tcp") or 0) + int(counts.get("udp") or 0)
            return {
                "tool": "network_connections",
                "status": "OK",
                "count": listed,
                "truncated": total > listed,
                "tcp_connections": counts,
                "connections": conns,
                "source": "/proc/net",
                "error": None,
            }
        psutil = _require_psutil()
        raw = list(psutil.net_connections(kind=kind))
        counts = connection_counts_from_psutil(raw)
        conns = []
        for c in raw[:300]:
            proc_name = None
            if c.pid:
                try:
                    proc_name = psutil.Process(c.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc_name = None
            try:
                sock_type = int(c.type)
            except (TypeError, ValueError):
                sock_type = socket.SOCK_STREAM
            status = str(c.status or "")
            if sock_type == socket.SOCK_DGRAM or status.upper() in ("NONE", "UDP"):
                status = "UDP"
            conns.append({
                "fd": c.fd,
                "family": str(c.family),
                "type": str(c.type),
                "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                "status": status,
                "pid": c.pid,
                "process_name": proc_name,
            })
        return {
            "tool": "network_connections",
            "status": "OK",
            "count": len(conns),
            "truncated": len(raw) > len(conns),
            "tcp_connections": counts,
            "connections": conns,
            "error": None,
        }
    except Exception as e:
        return {"tool": "network_connections", "status": "ERROR", "count": 0, "connections": [], "error": str(e)}


# ---------------------------------------------------------------------------
# RF-OBS-05 / tabla B: get_installed_software
# ---------------------------------------------------------------------------

def _sha256_file(path: str, max_bytes: int = 50 * 1024 * 1024) -> Optional[str]:
    """SHA-256 de un archivo; None si no es regular, no se puede leer o es enorme."""
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


def get_installed_software(
    include_hash: bool = False, max_hash: int = 40
) -> Dict[str, Any]:
    """
    Inventario de software instalado (RF-OBS-05), vía gestor de paquetes
    nativo. Linux: dpkg o rpm. Windows: registry. macOS: pkgutil.
    Con `include_hash` intenta SHA-256 del ejecutable principal (tope `max_hash`).
    """
    system = platform.system()
    try:
        if system == "Linux":
            return _installed_software_linux(include_hash=include_hash, max_hash=max_hash)
        if system == "Windows":
            return _installed_software_windows(include_hash=include_hash, max_hash=max_hash)
        if system == "Darwin":
            return _installed_software_macos(include_hash=include_hash, max_hash=max_hash)
        return {"tool": "installed_software", "status": "ERROR", "error": f"SO no soportado: {system}"}
    except Exception as e:
        return {"tool": "installed_software", "status": "ERROR", "error": str(e)}


def _hash_executable_for_package(
    name: str, extra_paths: Optional[List[str]] = None
) -> Optional[Dict[str, str]]:
    candidates: List[str] = []
    which = shutil.which(name)
    if which:
        candidates.append(which)
    for p in extra_paths or []:
        if p:
            candidates.append(p)
    seen = set()
    for path in candidates:
        path = os.path.expandvars(str(path).strip().strip('"'))
        if path in seen:
            continue
        seen.add(path)
        digest = _sha256_file(path)
        if digest:
            return {"path": path, "sha256": digest}
    return None


def _installed_software_linux(
    include_hash: bool = False, max_hash: int = 40
) -> Dict[str, Any]:
    from colsoft_tools.linux_collectors import linux_packages

    rec = linux_packages(
        include_hash=include_hash, max_hash=max_hash, max_packages=4000
    )
    rec = dict(rec)
    rec["tool"] = "installed_software"
    rec["native_tool"] = "linux_packages"
    rec.pop("cross_tool", None)
    return rec


def _installed_software_windows(
    include_hash: bool = False, max_hash: int = 40
) -> Dict[str, Any]:
    ps_cmd = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,"
        "HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
        "| Select-Object DisplayName, DisplayVersion, DisplayIcon, InstallLocation "
        "| Where-Object { $_.DisplayName -ne $null } "
        "| ConvertTo-Csv -NoTypeInformation",
    ]
    res = _run(ps_cmd, timeout=30)
    if res.returncode != 0:
        return {
            "tool": "installed_software",
            "status": "ERROR",
            "package_manager": "registry",
            "error": (res.stderr or res.stdout or "powershell falló").strip()[:400],
        }
    pkgs: List[Dict[str, Any]] = []
    seen = set()
    reader = csv.DictReader(io.StringIO(res.stdout or ""))
    for row in reader:
        name = (row.get("DisplayName") or "").strip()
        if not name or name in seen:
            continue
        seen.add(name)
        rec: Dict[str, Any] = {
            "name": name,
            "version": (row.get("DisplayVersion") or "").strip() or None,
        }
        icon = (row.get("DisplayIcon") or "").strip()
        if icon:
            rec["display_icon"] = icon.split(",")[0]
        loc = (row.get("InstallLocation") or "").strip()
        if loc:
            rec["install_location"] = loc
        pkgs.append(rec)
    hashed = 0
    if include_hash:
        for pkg in pkgs:
            if hashed >= max(0, int(max_hash)):
                break
            extras = []
            icon = (pkg.get("display_icon") or "").strip()
            if icon.lower().endswith(".exe"):
                extras.append(icon)
            loc = pkg.get("install_location") or ""
            if loc:
                extras.append(os.path.join(loc, (pkg.get("name") or "") + ".exe"))
            info = _hash_executable_for_package(pkg.get("name") or "", extras)
            if info:
                pkg.update(info)
                hashed += 1
    return {
        "tool": "installed_software",
        "status": "OK",
        "package_manager": "registry",
        "count": len(pkgs),
        "hashed": hashed,
        "packages": pkgs,
        "error": None,
    }


def _installed_software_macos(
    include_hash: bool = False, max_hash: int = 40
) -> Dict[str, Any]:
    res = _run(["pkgutil", "--pkgs"], timeout=30)
    pkgs = [
        {"name": line.strip(), "version": None}
        for line in res.stdout.strip().splitlines()
        if line.strip()
    ]
    hashed = 0
    if include_hash:
        for pkg in pkgs:
            if hashed >= max(0, int(max_hash)):
                break
            info = _hash_executable_for_package(pkg.get("name") or "")
            if info:
                pkg.update(info)
                hashed += 1
    return {
        "tool": "installed_software",
        "status": "OK",
        "package_manager": "pkgutil",
        "count": len(pkgs),
        "hashed": hashed,
        "packages": pkgs,
        "error": None,
    }


# ---------------------------------------------------------------------------
# tabla B: get_disk_usage
# ---------------------------------------------------------------------------

def _linux_network_io(ifaces: Any) -> Dict[str, Any]:
    """Totales e ifaces con las mismas claves que Windows (psutil), más alias rx_/tx_."""
    rows: List[Dict[str, Any]] = []
    for raw in ifaces or []:
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("iface") or raw.get("name") or "")
        if name == "lo" or name.startswith("lo:") or name.lower().startswith("loopback"):
            continue

        def _num(*keys: str) -> int:
            for key in keys:
                val = raw.get(key)
                if val is not None:
                    return int(val or 0)
            return 0

        rec = dict(raw)
        rec["iface"] = name or None
        rec["bytes_sent"] = _num("tx_bytes", "bytes_sent")
        rec["bytes_recv"] = _num("rx_bytes", "bytes_recv")
        rec["packets_sent"] = _num("tx_packets", "packets_sent")
        rec["packets_recv"] = _num("rx_packets", "packets_recv")
        rec["errin"] = _num("rx_errors", "errin")
        rec["errout"] = _num("tx_errors", "errout")
        rec["dropin"] = _num("rx_dropped", "dropin")
        rec["dropout"] = _num("tx_dropped", "dropout")
        rows.append(rec)

    def _sum(key: str) -> int:
        return sum(int(r.get(key) or 0) for r in rows)

    return {
        "bytes_sent": _sum("bytes_sent"),
        "bytes_recv": _sum("bytes_recv"),
        "packets_sent": _sum("packets_sent"),
        "packets_recv": _sum("packets_recv"),
        "errin": _sum("errin"),
        "errout": _sum("errout"),
        "dropin": _sum("dropin"),
        "dropout": _sum("dropout"),
        "interfaces": rows,
    }


def get_disk_usage() -> Dict[str, Any]:
    """Uso de disco por partición (subconjunto enfocado de get_system_metrics)."""
    if platform.system() == "Linux":
        from colsoft_tools.linux_collectors import _mount_volumes

        disks = _mount_volumes(limit=64)
        return {
            "tool": "disk_usage",
            "status": "OK",
            "disks": disks,
            "source": "/proc+/sys",
            "error": None,
        }
    try:
        psutil = _require_psutil()
        disks = []
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
                disks.append({
                    "device": part.device,
                    "mountpoint": part.mountpoint,
                    "fstype": part.fstype,
                    "total": usage.total,
                    "used": usage.used,
                    "free": usage.free,
                    "percent": usage.percent,
                })
            except (PermissionError, OSError):
                continue
        return {"tool": "disk_usage", "status": "OK", "disks": disks, "error": None}
    except Exception as e:
        return {"tool": "disk_usage", "status": "ERROR", "disks": [], "error": str(e)}


# ---------------------------------------------------------------------------
# tabla B: get_file_hash
# ---------------------------------------------------------------------------

def get_file_hash(path: str, algo: str = "sha256") -> Dict[str, Any]:
    """Calcula el hash de un archivo puntual (SHA-256 por defecto)."""
    try:
        if not path:
            return {"tool": "file_hash", "status": "ERROR", "error": "Missing path"}
        if not os.path.isfile(path):
            return {"tool": "file_hash", "status": "ERROR", "path": path, "error": "Archivo no encontrado"}

        algo = (algo or "sha256").lower()
        if algo not in hashlib.algorithms_available:
            return {"tool": "file_hash", "status": "ERROR", "path": path, "error": f"Algoritmo no soportado: {algo}"}

        h = hashlib.new(algo)
        size = 0
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
                size += len(chunk)

        stat = os.stat(path)
        return {
            "tool": "file_hash",
            "status": "OK",
            "path": path,
            "algorithm": algo,
            "hash": h.hexdigest(),
            "size_bytes": size,
            "modified_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            "error": None,
        }
    except Exception as e:
        return {"tool": "file_hash", "status": "ERROR", "path": path, "error": str(e)}


# ---------------------------------------------------------------------------
# RF-OBS-04 / tabla B: get_system_log
# ---------------------------------------------------------------------------

_JOURNAL_PRIORITY = {
    "0": "fatal",
    "1": "fatal",
    "2": "error",
    "3": "error",
    "4": "warning",
    "5": "info",
    "6": "info",
    "7": "debug",
}


def _normalize_log_entry(
    *,
    ts: Any = None,
    level: Optional[str],
    source: Optional[str],
    message: Optional[str],
    pid: Any = None,
    host: Optional[str] = None,
    event_id: Optional[str] = None,
) -> Dict[str, Any]:
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        ts = ts.astimezone(timezone.utc).isoformat()
    return {
        "ts": ts,
        "level": (level or "info").lower(),
        "source": source,
        "message": (message or "")[:2000],
        "pid": int(pid) if str(pid).isdigit() else pid,
        "host": host,
        "event_id": event_id,
    }


def _parse_journalctl_json(stdout: str) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            entries.append(_normalize_log_entry(ts=None, level="info", source="journald", message=line))
            continue
        ts = None
        usec = rec.get("__REALTIME_TIMESTAMP")
        if usec:
            try:
                ts = datetime.fromtimestamp(int(usec) / 1_000_000, tz=timezone.utc).isoformat()
            except (TypeError, ValueError, OSError):
                ts = None
        pid = rec.get("_PID") or rec.get("SYSLOG_PID")
        entries.append(
            _normalize_log_entry(
                ts=ts,
                level=_JOURNAL_PRIORITY.get(str(rec.get("PRIORITY")), "info"),
                source=rec.get("SYSLOG_IDENTIFIER") or rec.get("_COMM"),
                message=rec.get("MESSAGE"),
                pid=pid,
                host=rec.get("_HOSTNAME"),
                event_id=rec.get("SYSLOG_FACILITY"),
            )
        )
    return entries


def _parse_wevtutil_text(stdout: str, log_name: str) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    current: Dict[str, str] = {}
    desc_lines: List[str] = []
    in_desc = False

    def flush() -> None:
        nonlocal current, desc_lines, in_desc
        if not current and not desc_lines:
            return
        entries.append(
            _normalize_log_entry(
                ts=current.get("Date"),
                level=current.get("Level") or "info",
                source=current.get("Source") or log_name,
                message=" ".join(desc_lines).strip() or current.get("Task"),
                pid=None,
                host=current.get("Computer"),
                event_id=current.get("Event ID") or current.get("EventID"),
            )
        )
        current, desc_lines, in_desc = {}, [], False

    for raw in stdout.splitlines():
        line = raw.rstrip()
        if line.startswith("Event["):
            flush()
            continue
        stripped = line.strip()
        if stripped.startswith("Description:") or stripped.startswith("Description :"):
            in_desc = True
            extra = stripped.split(":", 1)[1].strip()
            if extra:
                desc_lines.append(extra)
            continue
        if in_desc:
            if stripped and ":" in stripped and stripped.split(":", 1)[0] in (
                "Log Name", "Source", "Date", "Event ID", "Task", "Level",
                "Opcode", "Keyword", "User", "User Name", "Computer",
            ):
                in_desc = False
            else:
                if stripped:
                    desc_lines.append(stripped)
                continue
        if ":" in stripped:
            key, val = stripped.split(":", 1)
            current[key.strip()] = val.strip()
    flush()
    return entries


def _tail_text_file(path: str, max_lines: int) -> List[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
        return lines[-max_lines:]
    except OSError:
        return []


def get_system_log(source: str = "system", level: str = "warning",
                     since: Optional[str] = None, max_lines: int = 500,
                     until: Optional[str] = None, **range_kw: Any) -> Dict[str, Any]:
    """
    Extrae entradas de log recientes, normalizadas (RF-OBS-04).

    Params SRS §8.4-B: source, level, since, max_lines.
    Rango: date, startHour/endHour, startDate/endDate, until (UTC).
    Linux: journald por defecto; `system`/`application`/`security`/`setup`/
    `forwarded` equivalen a Event Viewer; `syslog`/`auth` leen `/var/log/*`.
    Windows: Event Log XML (RF-WIN-02) cuando el source es un canal conocido.
    """
    from colsoft_tools.log_range import (
        filter_entries,
        journalctl_time_args,
        parse_log_line_ts,
        window_fields,
        window_from_params,
    )

    system = platform.system()
    max_lines = max(1, min(int(max_lines or 500), 5000))
    src = (source or "system").strip()
    window = window_from_params({"since": since, "until": until, **range_kw})
    time_args = journalctl_time_args(window)

    def _with_range(rec: Dict[str, Any]) -> Dict[str, Any]:
        if window.bounded():
            rec["range"] = window_fields(window)
        return rec

    def _from_text_file(chosen: str) -> Dict[str, Any]:
        read_n = max_lines
        if window.bounded():
            read_n = min(20000, max(max_lines * 50, 2000))
        lines = _tail_text_file(chosen, read_n)
        year = window.start.year if window.start else None
        entries = [
            _normalize_log_entry(
                ts=parse_log_line_ts(ln, year=year),
                level=level or "info",
                source=chosen,
                message=ln,
            )
            for ln in lines
        ]
        entries = filter_entries(entries, window, limit=max_lines)
        return _with_range(
            {
                "tool": "system_log",
                "status": "OK",
                "source": chosen,
                "schema_version": SCHEMA_VERSION,
                "count": len(entries),
                "entries": entries,
                "truncated": len(entries) >= max_lines,
                "error": None,
            }
        )

    try:
        if system == "Linux":
            from colsoft_tools.linux_collectors import (
                SYSLOG_SOURCES,
                forwarded_log_spec,
                resolve_syslog_source,
            )

            src = resolve_syslog_source(src or "system")
            if src == "forwarded":
                spec = forwarded_log_spec()
                if spec.get("kind") == "journal":
                    cmd = [
                        "journalctl",
                        f"--directory={spec['directory']}",
                        "-n",
                        str(max_lines),
                        "--no-pager",
                        "-o",
                        "json",
                    ]
                    if level:
                        cmd += ["-p", level]
                    cmd += time_args
                    res = _run(cmd, timeout=20)
                    entries = _parse_journalctl_json(res.stdout)
                    entries = filter_entries(entries, window, limit=max_lines)
                    return _with_range(
                        {
                            "tool": "system_log",
                            "status": "OK",
                            "source": "journal-remote",
                            "schema_version": SCHEMA_VERSION,
                            "count": len(entries),
                            "entries": entries,
                            "truncated": len(entries) >= max_lines,
                            "error": None if res.returncode == 0 else (res.stderr.strip() or None),
                        }
                    )
                if spec.get("kind") == "files":
                    chosen = spec.get("chosen") or (spec.get("paths") or (None,))[0]
                    if chosen and os.path.isfile(chosen):
                        return _from_text_file(chosen)
                return _with_range(
                    {
                        "tool": "system_log",
                        "status": "ERROR",
                        "source": "forwarded",
                        "schema_version": SCHEMA_VERSION,
                        "count": 0,
                        "entries": [],
                        "truncated": False,
                        "error": "no hay logs reenviados (journal remoto o /var/log/remote)",
                    }
                )
            paths = SYSLOG_SOURCES.get(src.lower())
            if src.startswith("/"):
                paths = (src,)
            if paths:
                chosen = next((p for p in paths if os.path.isfile(p)), None)
                if not chosen:
                    return {
                        "tool": "system_log",
                        "status": "ERROR",
                        "source": src,
                        "error": f"archivo de log no encontrado: {paths[0]}",
                    }
                return _from_text_file(chosen)
            cmd = ["journalctl", "-n", str(max_lines), "--no-pager", "-o", "json"]
            if level:
                cmd += ["-p", level]
            cmd += time_args
            res = _run(cmd, timeout=20)
            entries = _parse_journalctl_json(res.stdout)
            entries = filter_entries(entries, window, limit=max_lines)
            return _with_range(
                {
                    "tool": "system_log",
                    "status": "OK",
                    "source": "journald",
                    "schema_version": SCHEMA_VERSION,
                    "count": len(entries),
                    "entries": entries,
                    "truncated": len(entries) >= max_lines,
                    "error": None if res.returncode == 0 else (res.stderr.strip() or None),
                }
            )

        if system == "Darwin":
            cmd = ["log", "show", "--style", "compact"]
            if window.start is not None:
                cmd += ["--start", window.start.strftime("%Y-%m-%d %H:%M:%S")]
            elif window.end is None:
                cmd += ["--last", "1h"]
            if window.end is not None:
                cmd += ["--end", window.end.strftime("%Y-%m-%d %H:%M:%S")]
            if level:
                cmd += ["--predicate", f'messageType == "{level}"']
            res = _run(cmd, timeout=20)
            lines = res.stdout.strip().splitlines()[-max_lines:]
            entries = [
                _normalize_log_entry(ts=None, level=level or "info", source="unified_log", message=ln)
                for ln in lines
            ]
            entries = filter_entries(entries, window, limit=max_lines)
            return _with_range(
                {
                    "tool": "system_log",
                    "status": "OK",
                    "source": "unified_log",
                    "schema_version": SCHEMA_VERSION,
                    "count": len(entries),
                    "entries": entries,
                    "truncated": False,
                    "error": None,
                }
            )

        if system == "Windows":
            from colsoft_tools.log_range import wevtutil_time_query
            from colsoft_tools.windows_collectors import (
                resolve_event_channel,
                windows_event_log,
            )

            log_name = resolve_event_channel(src or "System")
            try:
                raw = windows_event_log(
                    log_name, max_events=max_lines, **{"since": since, "until": until, **range_kw}
                )
                mapped: List[Dict[str, Any]] = []
                for rec in raw.get("entries") or []:
                    data = rec.get("data") if isinstance(rec.get("data"), dict) else {}
                    msg = " ".join(f"{k}={v}" for k, v in list(data.items())[:8]) if data else ""
                    mapped.append(
                        _normalize_log_entry(
                            ts=rec.get("ts"),
                            level=rec.get("level") or level,
                            source=rec.get("provider") or rec.get("channel") or log_name,
                            message=msg,
                            host=rec.get("computer"),
                            event_id=rec.get("event_id"),
                        )
                    )
                mapped = filter_entries(mapped, window, limit=max_lines)
                if mapped or raw.get("status") == "OK":
                    return _with_range(
                        {
                            "tool": "system_log",
                            "status": raw.get("status") or "OK",
                            "source": log_name,
                            "schema_version": SCHEMA_VERSION,
                            "count": len(mapped),
                            "entries": mapped,
                            "truncated": bool(raw.get("truncated")),
                            "error": raw.get("error"),
                        }
                    )
            except Exception:
                pass
            cmd = ["wevtutil", "qe", log_name]
            query = wevtutil_time_query(window.start, window.end)
            if query:
                cmd.append(f"/q:{query}")
            cmd += [f"/c:{max_lines}", "/rd:true", "/f:text"]
            res = _run(cmd, timeout=25)
            entries = _parse_wevtutil_text(res.stdout, log_name)
            entries = filter_entries(entries, window, limit=max_lines)
            return _with_range(
                {
                    "tool": "system_log",
                    "status": "OK",
                    "source": log_name,
                    "schema_version": SCHEMA_VERSION,
                    "count": len(entries),
                    "entries": entries,
                    "truncated": False,
                    "error": None if res.returncode == 0 else (res.stderr.strip() or None),
                }
            )

        return {"tool": "system_log", "status": "ERROR", "error": f"SO no soportado: {system}"}
    except Exception as e:
        return {"tool": "system_log", "status": "ERROR", "error": str(e)}


# ---------------------------------------------------------------------------
# tabla B: collect_forensic_snapshot — bundle de IR
# ---------------------------------------------------------------------------

def collect_forensic_snapshot() -> Dict[str, Any]:
    """
    Bundle rápido de respuesta a incidentes: procesos + conexiones +
    métricas + logs recientes + persistencia. En Windows añade autoruns
    (RF-WIN-03) y Event Log estructurado (RF-WIN-02). En Linux añade
    auditd, unidades systemd y LSM (RF-LIN-02/06/07).
    """
    try:
        started = _now_iso()
        processes = get_process_list(limit=300)
        connections = get_network_connections()
        metrics = get_system_metrics(cpu_interval=0.2)
        logs = get_system_log(max_lines=200)
        try:
            from colsoft_tools.endpoint_security import persistence_scan

            persistence = persistence_scan()
        except Exception as e:
            persistence = {"status": "ERROR", "error": str(e)}
        windows = None
        linux = None
        if platform.system() == "Windows":
            try:
                from colsoft_tools.windows_collectors import (
                    windows_autoruns,
                    windows_event_log,
                )

                windows = {
                    "autoruns": windows_autoruns(),
                    "security_log": windows_event_log("Security", max_events=30),
                }
            except Exception as e:
                windows = {"status": "ERROR", "error": str(e)}
        elif platform.system() == "Linux":
            try:
                from colsoft_tools.linux_collectors import (
                    linux_auditd,
                    linux_lsm,
                    linux_systemd_units,
                )

                linux = {
                    "auditd": linux_auditd(max_events=20),
                    "lsm": linux_lsm(),
                    "systemd": linux_systemd_units(max_units=40, max_timers=20),
                }
            except Exception as e:
                linux = {"status": "ERROR", "error": str(e)}

        return {
            "tool": "forensic_snapshot",
            "status": "OK",
            "started_at": started,
            "completed_at": _now_iso(),
            "processes": processes,
            "network_connections": connections,
            "system_metrics": metrics,
            "recent_logs": logs,
            "persistence": persistence,
            "windows": windows,
            "linux": linux,
            "note": "Persistencia RF-SEC-02; Windows RF-WIN-02/03; Linux RF-LIN-02/06/07.",
            "error": None,
        }
    except Exception as e:
        return {"tool": "forensic_snapshot", "status": "ERROR", "error": str(e)}


# ---------------------------------------------------------------------------
# tabla B: collect_file — recupera un archivo puntual hacia el backend
# ---------------------------------------------------------------------------

def collect_file(path: str, max_size_mb: float = 10.0) -> Dict[str, Any]:
    """
    Recupera un archivo puntual hacia el backend (§8.4-B, Alto², deshabilitado
    por defecto — requiere política explícita por host/grupo).

    Params SRS: path, max_size_mb. Lee como máximo `max_size_mb` (default 10MB)
    y devuelve el contenido en base64 con metadatos (tamaño, SHA-256, si fue
    truncado). Nunca lee archivos que no existan o que no sean regulares.
    """
    try:
        if not path:
            return {"tool": "collect_file", "status": "ERROR", "error": "Missing path"}
        path = os.path.expanduser(path)
        if not os.path.isfile(path):
            return {"tool": "collect_file", "status": "ERROR", "path": path,
                     "error": "Archivo no encontrado o no es un archivo regular"}

        try:
            max_size_mb = float(max_size_mb or 10.0)
        except (TypeError, ValueError):
            max_size_mb = 10.0
        max_bytes = max(1, int(max_size_mb * 1024 * 1024))

        stat = os.stat(path)
        size_total = stat.st_size
        truncated = size_total > max_bytes

        h = hashlib.sha256()
        content = bytearray()
        with open(path, "rb") as f:
            remaining = max_bytes
            while remaining > 0:
                chunk = f.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                h.update(chunk)
                content.extend(chunk)
                remaining -= len(chunk)

        import base64
        return {
            "tool": "collect_file",
            "status": "OK",
            "path": path,
            "size_bytes": size_total,
            "max_size_bytes": max_bytes,
            "truncated": truncated,
            "content_bytes": len(content),
            "sha256": h.hexdigest(),
            "modified_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            "content_b64": base64.b64encode(bytes(content)).decode("ascii"),
            "error": None,
        }
    except Exception as e:
        return {"tool": "collect_file", "status": "ERROR", "path": path, "error": str(e)}


# ---------------------------------------------------------------------------
# RF-OBS-02: snapshot ligero de procesos (clave pid+create_time, sin CPU)
# ---------------------------------------------------------------------------

def snapshot_processes() -> Dict[Tuple[Any, ...], Dict[str, Any]]:
    """Mapa (pid, create_time) → info mínima. Usado por ProcessWatcher."""
    if platform.system() == "Linux":
        from colsoft_tools.linux_collectors import linux_process_rows

        rows, _truncated = linux_process_rows(limit=2000)
        out: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
        for rec in rows:
            ct = rec.get("create_time_unix") or 0.0
            key = (rec.get("pid"), round(float(ct), 3))
            out[key] = {
                "pid": rec.get("pid"),
                "ppid": rec.get("ppid"),
                "name": rec.get("name"),
                "username": rec.get("username"),
                "create_time": ct,
                "cmdline": rec.get("cmdline"),
            }
        return out
    psutil = _require_psutil()
    out: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
    for p in psutil.process_iter(
        ["pid", "ppid", "name", "username", "create_time", "cmdline"]
    ):
        try:
            info = p.info
            ct = float(info.get("create_time") or 0.0)
            key = (info.get("pid"), round(ct, 3))
            out[key] = {
                "pid": info.get("pid"),
                "ppid": info.get("ppid"),
                "name": info.get("name"),
                "username": info.get("username"),
                "create_time": ct,
                "cmdline": " ".join(info.get("cmdline") or [])[:500],
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return out


# ---------------------------------------------------------------------------
# RF-OBS-05: inventario de hardware
# ---------------------------------------------------------------------------

def _read_sys_text(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            value = f.read().strip()
        return value or None
    except OSError:
        return None


def _hardware_dmi_linux() -> Dict[str, Any]:
    base = "/sys/class/dmi/id"
    return {
        "vendor": _read_sys_text(f"{base}/sys_vendor"),
        "product": _read_sys_text(f"{base}/product_name"),
        "version": _read_sys_text(f"{base}/product_version"),
        "serial": _read_sys_text(f"{base}/product_serial"),
        "uuid": _read_sys_text(f"{base}/product_uuid"),
        "board": _read_sys_text(f"{base}/board_name"),
        "machine_id": _read_sys_text("/etc/machine-id"),
    }


def _hardware_windows_cim() -> Dict[str, Any]:
    ps = (
        "$cs = Get-CimInstance Win32_ComputerSystem; "
        "$bios = Get-CimInstance Win32_BIOS; "
        "@{vendor=$cs.Manufacturer; product=$cs.Model; "
        "serial=$bios.SerialNumber; uuid=$cs.Name} | ConvertTo-Json -Compress"
    )
    res = _run(["powershell", "-NoProfile", "-Command", ps], timeout=20)
    if res.returncode != 0 or not res.stdout.strip():
        return {}
    try:
        rec = json.loads(res.stdout)
    except ValueError:
        return {}
    if not isinstance(rec, dict):
        return {}
    return {
        "vendor": rec.get("vendor"),
        "product": rec.get("product"),
        "serial": rec.get("serial"),
        "uuid": rec.get("uuid"),
    }


def get_hardware_inventory() -> Dict[str, Any]:
    """Inventario de hardware (RF-OBS-05): CPU, RAM, discos, NICs y DMI/CIM."""
    if platform.system() == "Linux":
        from colsoft_tools.linux_collectors import (
            _cpu_count,
            _cpu_freq,
            _cpu_physical_cores,
            _meminfo,
            _mount_volumes,
            _net_sys_stats,
            _read_text,
        )

        mem = _meminfo()
        model = None
        for line in (_read_text("/proc/cpuinfo") or "").splitlines():
            if line.lower().startswith("model name"):
                model = line.split(":", 1)[-1].strip()
                break
        disks = [
            {
                "device": d.get("device"),
                "mountpoint": d.get("mountpoint"),
                "fstype": d.get("fstype"),
                "total": d.get("total"),
            }
            for d in _mount_volumes(limit=64)
        ]
        nics = [{"name": row.get("iface"), "addresses": []} for row in _net_sys_stats(32)]
        return {
            "tool": "hardware_inventory",
            "status": "OK",
            "hostname": platform.node(),
            "os": "Linux",
            "os_version": platform.version(),
            "arch": platform.machine(),
            "cpu": {
                "model": model or platform.processor() or None,
                "logical_cores": _cpu_count(),
                "physical_cores": _cpu_physical_cores(),
                "freq": _cpu_freq(),
            },
            "memory": {"total": mem.get("MemTotal")},
            "disks": disks,
            "nics": nics,
            "firmware": _hardware_dmi_linux(),
            "source": "/proc+/sys",
            "error": None,
        }
    try:
        psutil = _require_psutil()
        cpu_freq = None
        try:
            freq = psutil.cpu_freq()
            if freq:
                cpu_freq = {
                    "current_mhz": round(freq.current, 1) if freq.current else None,
                    "min_mhz": round(freq.min, 1) if freq.min else None,
                    "max_mhz": round(freq.max, 1) if freq.max else None,
                }
        except Exception:
            cpu_freq = None

        vm = psutil.virtual_memory()
        disks = []
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
                disks.append({
                    "device": part.device,
                    "mountpoint": part.mountpoint,
                    "fstype": part.fstype,
                    "total": usage.total,
                })
            except OSError:
                continue

        nics = []
        try:
            addrs = psutil.net_if_addrs()
        except Exception:
            addrs = {}
        for name, entries in addrs.items():
            nics.append({
                "name": name,
                "addresses": [
                    {
                        "family": str(getattr(a.family, "name", a.family)),
                        "address": a.address,
                        "netmask": a.netmask,
                    }
                    for a in entries
                ],
            })

        system = platform.system()
        firmware: Dict[str, Any] = {}
        cpu_model = platform.processor() or None
        logical_cores = psutil.cpu_count(logical=True)
        physical_cores = psutil.cpu_count(logical=False)
        if system == "Linux":
            firmware = _hardware_dmi_linux()
        elif system == "Windows":
            firmware = _hardware_windows_cim()
            from colsoft_tools.windows_collectors import windows_cpu_inventory

            win_cpu = windows_cpu_inventory() or {}
            cpu_model = win_cpu.get("model") or cpu_model
            physical_cores = win_cpu.get("physical_cores") or physical_cores
            logical_cores = win_cpu.get("logical_cores") or logical_cores
            win_freq = win_cpu.get("freq") if isinstance(win_cpu.get("freq"), dict) else {}
            if win_freq:
                merged = dict(cpu_freq or {})
                for key in ("current_mhz", "min_mhz", "max_mhz"):
                    val = win_freq.get(key)
                    if isinstance(val, (int, float)) and not isinstance(val, bool) and val > 0:
                        merged[key] = val
                cpu_freq = merged or cpu_freq

        return {
            "tool": "hardware_inventory",
            "status": "OK",
            "hostname": platform.node(),
            "os": system,
            "os_version": platform.version(),
            "arch": platform.machine(),
            "cpu": {
                "model": cpu_model,
                "logical_cores": logical_cores,
                "physical_cores": physical_cores,
                "freq": cpu_freq,
            },
            "memory": {"total": vm.total},
            "disks": disks,
            "nics": nics,
            "firmware": firmware,
            "error": None,
        }
    except Exception as e:
        return {"tool": "hardware_inventory", "status": "ERROR", "error": str(e)}


# ---------------------------------------------------------------------------
# RF-OBS-07: health probes (puerto / HTTP / proceso) — distinto de health_check
# ---------------------------------------------------------------------------

_MAX_HEALTH_CHECKS = 32


def _probe_process_running(name: str) -> Dict[str, Any]:
    needle = (name or "").lower().strip()
    if not needle:
        return {"status": "DOWN", "error": "Missing process name"}
    try:
        if platform.system() == "Linux":
            from colsoft_tools.linux_collectors import linux_process_rows

            rows, _truncated = linux_process_rows(name_filter=needle, limit=10)
            matches = [{"pid": r.get("pid"), "name": r.get("name")} for r in rows]
            return {
                "status": "UP" if matches else "DOWN",
                "matches": len(matches),
                "processes": matches,
                "source": "/proc",
                "error": None if matches else f"proceso {name!r} no encontrado",
            }
        psutil = _require_psutil()
        matches = []
        for p in psutil.process_iter(["pid", "name"]):
            try:
                pname = (p.info.get("name") or "").lower()
                if needle in pname:
                    matches.append({"pid": p.info.get("pid"), "name": p.info.get("name")})
                    if len(matches) >= 10:
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return {
            "status": "UP" if matches else "DOWN",
            "matches": len(matches),
            "processes": matches,
            "error": None if matches else f"proceso {name!r} no encontrado",
        }
    except Exception as e:
        return {"status": "DOWN", "error": str(e)}


def run_health_probes(checks: Optional[List[Any]] = None) -> Dict[str, Any]:
    """Ejecuta health checks configurables: tcp, http, process (RF-OBS-07)."""
    from colsoft_tools.network_checks import check_http_service, check_tcp_port

    if not isinstance(checks, list):
        checks = []
    checks = checks[:_MAX_HEALTH_CHECKS]
    results: List[Dict[str, Any]] = []
    try:
        for i, raw in enumerate(checks):
            if not isinstance(raw, dict):
                results.append({
                    "id": f"check-{i}",
                    "type": "unknown",
                    "status": "DOWN",
                    "error": "check debe ser un objeto",
                })
                continue
            check_id = str(raw.get("id") or f"check-{i}")
            kind = str(raw.get("type") or raw.get("kind") or "").strip().lower()
            timeout = int(raw.get("timeout") or 5)
            rec: Dict[str, Any] = {"id": check_id, "type": kind}

            if kind in ("tcp", "port"):
                host = (raw.get("host") or raw.get("target") or "127.0.0.1").strip()
                try:
                    port = int(raw.get("port"))
                except (TypeError, ValueError):
                    rec.update({"status": "DOWN", "error": "Missing/invalid port"})
                    results.append(rec)
                    continue
                tcp = check_tcp_port(host, port=port, timeout=timeout)
                rec.update({
                    "host": host,
                    "port": port,
                    "status": tcp.get("status"),
                    "response_time": tcp.get("response_time"),
                    "error": tcp.get("error"),
                })
            elif kind == "http":
                url = (raw.get("url") or raw.get("target") or "").strip()
                if not url:
                    host = (raw.get("host") or "").strip()
                    port = raw.get("port")
                    path = (raw.get("path") or "/").strip() or "/"
                    if not path.startswith("/"):
                        path = "/" + path
                    if host and port not in (None, ""):
                        try:
                            scheme = (raw.get("scheme") or "http").strip() or "http"
                            url = f"{scheme}://{host}:{int(port)}{path}"
                        except (TypeError, ValueError):
                            url = ""
                if not url:
                    rec.update({"status": "DOWN", "error": "Missing url"})
                    results.append(rec)
                    continue
                verify = True
                if "verify" in raw:
                    verify = bool(raw.get("verify"))
                elif raw.get("insecure") or raw.get("tls_insecure"):
                    verify = False
                http = check_http_service(url, timeout=timeout, verify=verify)
                rec.update({
                    "url": url,
                    "status": http.get("status"),
                    "status_code": http.get("status_code"),
                    "response_time": http.get("response_time"),
                    "error": http.get("error"),
                })
            elif kind == "process":
                name = (raw.get("name") or raw.get("process") or "").strip()
                proc = _probe_process_running(name)
                rec.update({"name": name, **proc})
            else:
                rec.update({
                    "status": "DOWN",
                    "error": f"tipo no soportado: {kind or '(vacío)'} (tcp|http|process)",
                })
            results.append(rec)

        down = sum(1 for r in results if r.get("status") != "UP")
        latencies = [
            float(r["response_time"])
            for r in results
            if r.get("status") == "UP"
            and isinstance(r.get("response_time"), (int, float))
            and not isinstance(r.get("response_time"), bool)
        ]
        return {
            "tool": "health_probes",
            "status": "OK" if down == 0 else "DOWN",
            "count": len(results),
            "down": down,
            "response_time": (
                round(sum(latencies) / len(latencies), 6) if latencies else None
            ),
            "response_time_max": round(max(latencies), 6) if latencies else None,
            "checks": results,
            "error": None,
        }
    except Exception as e:
        return {"tool": "health_probes", "status": "ERROR", "checks": results, "error": str(e)}


def metric_from_snapshot(metrics: Dict[str, Any], path: str) -> Optional[float]:
    """Lee un valor numérico de system_metrics por ruta (`cpu.percent`, `disks.percent.max`)."""
    path = (path or "").strip()
    if not path or not isinstance(metrics, dict):
        return None
    aliases = {
        "cpu.load1": "cpu.load_avg_1",
        "cpu.load5": "cpu.load_avg_5",
        "cpu.load15": "cpu.load_avg_15",
        "network.bytes_sent": "network_io.bytes_sent",
        "network.bytes_recv": "network_io.bytes_recv",
        "tcp.listen": "tcp_connections.listen",
        "tcp.established": "tcp_connections.established",
        "tcp.time_wait": "tcp_connections.time_wait",
        "tcp.syn_recv": "tcp_connections.syn_recv",
        "tcp.syn_sent": "tcp_connections.syn_sent",
        "tcp.close_wait": "tcp_connections.close_wait",
        "tcp.udp": "tcp_connections.udp",
    }
    path = aliases.get(path, path)
    if path == "disks.percent.max":
        percents = [
            d.get("percent")
            for d in (metrics.get("disks") or [])
            if isinstance(d, dict) and isinstance(d.get("percent"), (int, float))
        ]
        return float(max(percents)) if percents else None
    if path in ("network_io.bytes_sent", "network_io.bytes_recv"):
        net = metrics.get("network_io")
        if isinstance(net, dict) and isinstance(net.get(path.split(".")[-1]), (int, float)):
            return float(net[path.split(".")[-1]])
        rows = net if isinstance(net, list) else (
            net.get("interfaces") if isinstance(net, dict) else None
        )
        if not isinstance(rows, list):
            rows = metrics.get("net") if isinstance(metrics.get("net"), list) else []
        field = "tx_bytes" if path.endswith("sent") else "rx_bytes"
        alt = "bytes_sent" if path.endswith("sent") else "bytes_recv"
        total = 0
        any_row = False
        for row in rows:
            if not isinstance(row, dict):
                continue
            any_row = True
            total += int(row.get(field) or row.get(alt) or 0)
        return float(total) if any_row else None
    if path in ("cpu.load_avg_1", "cpu.load_avg_5", "cpu.load_avg_15"):
        cpu = metrics.get("cpu") if isinstance(metrics.get("cpu"), dict) else {}
        idx = {"cpu.load_avg_1": 0, "cpu.load_avg_5": 1, "cpu.load_avg_15": 2}[path]
        key = path.rsplit(".", 1)[-1]
        raw = cpu.get(key)
        if isinstance(raw, (int, float)) and not isinstance(raw, bool):
            return float(raw)
        series = cpu.get("load_avg_1_5_15")
        if isinstance(series, (list, tuple)) and len(series) > idx:
            val = series[idx]
            if isinstance(val, (int, float)) and not isinstance(val, bool):
                return float(val)
        return None
    if path == "memory.used":
        mem = metrics.get("memory") if isinstance(metrics.get("memory"), dict) else {}
        used = mem.get("used")
        if isinstance(used, (int, float)):
            return float(used)
        if mem.get("total") is not None and mem.get("available") is not None:
            try:
                return float(int(mem["total"]) - int(mem["available"]))
            except (TypeError, ValueError):
                return None
        return None
    cur: Any = metrics
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    if isinstance(cur, bool) or not isinstance(cur, (int, float)):
        return None
    return float(cur)
