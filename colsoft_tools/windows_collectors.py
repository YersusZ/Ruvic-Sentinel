"""Collectors específicos de Windows — SRS §12 (RF-WIN-01..07).

Sin pywin32: wevtutil XML, logman, schtasks, winreg y PowerShell CIM.
En Linux/macOS las tools responden `UNSUPPORTED` (el agente es un solo binario).
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from colsoft_tools.log_range import (
    filter_entries,
    wevtutil_time_query,
    window_fields,
    window_from_params,
)

# RF-WIN-02: Event Viewer clásico (Application/Security/Setup/System/Forwarded
# Events) más canales operativos de interés.
EVENT_CHANNELS = (
    "System",
    "Application",
    "Security",
    "Setup",
    "ForwardedEvents",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-IIS-Configuration/Operational",
)

EVENT_LOG_ALIASES = {
    "system": "System",
    "application": "Application",
    "security": "Security",
    "setup": "Setup",
    "forwarded": "ForwardedEvents",
    "forwardedevents": "ForwardedEvents",
    "forwarded_events": "ForwardedEvents",
    "powershell": "Microsoft-Windows-PowerShell/Operational",
    "defender": "Microsoft-Windows-Windows Defender/Operational",
    "iis": "Microsoft-IIS-Configuration/Operational",
}


def resolve_event_channel(name: Optional[str]) -> str:
    raw = (name or "Security").strip() or "Security"
    return EVENT_LOG_ALIASES.get(raw.lower(), raw)


# RF-WIN-01: proveedores ETW de interés (Kernel-Process, PowerShell, Security).
ETW_PROVIDERS_OF_INTEREST = (
    "Microsoft-Windows-Kernel-Process",
    "Microsoft-Windows-PowerShell",
    "Microsoft-Windows-Security-Auditing",
    "Microsoft-Windows-Sysmon",
    "Microsoft-Windows-Windows Defender",
)

WMI_ALLOWLIST = {
    "Win32_OperatingSystem",
    "Win32_ComputerSystem",
    "Win32_BIOS",
    "Win32_Processor",
    "Win32_LogicalDisk",
    "Win32_Process",
    "Win32_Service",
    "Win32_StartupCommand",
    "Win32_QuickFixEngineering",
    "AntiVirusProduct",
}

_LEVEL_FROM_EVTX = {
    "0": "info",
    "1": "critical",
    "2": "error",
    "3": "warning",
    "4": "info",
    "5": "debug",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_windows() -> bool:
    return platform.system() == "Windows"


def _run(cmd: List[str], timeout: int = 25) -> subprocess.CompletedProcess:
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
        "error": "Requiere Windows",
        "ts": _now_iso(),
    }


def _ps(script: str, timeout: int = 30) -> subprocess.CompletedProcess:
    body = (
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
        + script
    )
    return _run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            body,
        ],
        timeout=timeout,
    )


def _ps_json(script: str, timeout: int = 30) -> Any:
    res = _ps(script, timeout=timeout)
    raw = (res.stdout or "").strip()
    if not raw:
        err = (res.stderr or "").strip()
        if res.returncode not in (0, None) or err:
            return {"_parse_error": True, "_raw": (err or raw)[:2000]}
        return None
    try:
        return json.loads(raw)
    except ValueError:
        for i, ch in enumerate(raw):
            if ch in "[{":
                try:
                    return json.loads(raw[i:])
                except ValueError:
                    break
        return {"_raw": raw[:2000], "_parse_error": True}


def _as_int(value: Any) -> Optional[int]:
    try:
        if value is None or value == "":
            return None
        n = int(float(value))
        return n if n > 0 else None
    except (TypeError, ValueError):
        return None


def _as_mhz(value: Any) -> Optional[float]:
    try:
        if value is None or value == "":
            return None
        n = float(value)
        return round(n, 1) if n > 0 else None
    except (TypeError, ValueError):
        return None


def windows_cpu_inventory() -> Dict[str, Any]:
    """CPU estático via CIM (Win32_Processor): modelo, núcleos, MHz.

    En Linux/macOS devuelve {}. psutil.cpu_freq() en Windows a menudo va 0/None.
    """
    if not _is_windows():
        return {}
    script = (
        "$ErrorActionPreference='Stop'; "
        "$cpus=@(Get-CimInstance Win32_Processor | "
        "Select-Object Name,NumberOfCores,NumberOfLogicalProcessors,"
        "MaxClockSpeed,CurrentClockSpeed); "
        "if($cpus.Count -lt 1){ '{}'; exit 0 }; "
        "$cores=($cpus | Measure-Object NumberOfCores -Sum).Sum; "
        "$logical=($cpus | Measure-Object NumberOfLogicalProcessors -Sum).Sum; "
        "$max=($cpus | Measure-Object MaxClockSpeed -Maximum).Maximum; "
        "$cur=($cpus | Measure-Object CurrentClockSpeed -Average).Average; "
        "@{model=[string]$cpus[0].Name; physical_cores=$cores; "
        "logical_cores=$logical; max_mhz=$max; current_mhz=$cur} | "
        "ConvertTo-Json -Compress"
    )
    try:
        data = _ps_json(script, timeout=20)
    except Exception:
        return {}
    if not isinstance(data, dict) or data.get("_parse_error"):
        return {}
    freq_max = _as_mhz(data.get("max_mhz"))
    freq_cur = _as_mhz(data.get("current_mhz"))
    freq = None
    if freq_max is not None or freq_cur is not None:
        freq = {
            "current_mhz": freq_cur,
            "min_mhz": None,
            "max_mhz": freq_max or freq_cur,
        }
    model = str(data.get("model") or "").strip() or None
    out: Dict[str, Any] = {}
    if model:
        out["model"] = model
    phys = _as_int(data.get("physical_cores"))
    logical = _as_int(data.get("logical_cores"))
    if phys is not None:
        out["physical_cores"] = phys
    if logical is not None:
        out["logical_cores"] = logical
    if freq:
        out["freq"] = freq
    return out


_CIM_META_KEYS = {
    "CimClass",
    "CimInstanceProperties",
    "CimSystemProperties",
    "PSComputerName",
}


def _wmi_scalar(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, list):
        return [_wmi_scalar(v) for v in value[:20]]
    return str(value)[:500]


def flatten_wmi_row(row: Any) -> Optional[Dict[str, Any]]:
    """Quita metadatos CIM (CimClass, …) y deja propiedades de instancia."""
    if not isinstance(row, dict):
        return None
    props = row.get("CimInstanceProperties")
    out: Dict[str, Any] = {}
    if isinstance(props, list):
        for item in props:
            if not isinstance(item, dict):
                continue
            name = item.get("Name")
            if not name:
                continue
            val = item.get("Value")
            if val is None:
                continue
            out[str(name)] = _wmi_scalar(val)
    for key, value in row.items():
        if key in _CIM_META_KEYS or value is None:
            continue
        if key not in out:
            out[str(key)] = _wmi_scalar(value)
    return out or None


# ---------------------------------------------------------------------------
# RF-WIN-02 Event Log estructurado (XML)
# ---------------------------------------------------------------------------

def parse_evtx_xml(blob: str) -> List[Dict[str, Any]]:
    """Parsea uno o más `<Event>` de wevtutil `/f:xml` (con o sin wrapper)."""
    text = (blob or "").strip()
    if not text:
        return []
    if "<Events" not in text[:80]:
        text = f"<Events>{text}</Events>"
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        wrapped = f"<Events>{blob}</Events>"
        try:
            root = ET.fromstring(wrapped)
        except ET.ParseError:
            return []

    def _local(tag: str) -> str:
        return tag.split("}")[-1] if tag else ""

    def _child(parent: ET.Element, name: str) -> Optional[ET.Element]:
        for ch in list(parent):
            if _local(ch.tag) == name:
                return ch
        return None

    events = [el for el in root.iter() if _local(el.tag) == "Event"]
    if _local(root.tag) == "Event" and root not in events:
        events = [root]
    out: List[Dict[str, Any]] = []
    for ev in events:
        sys_el = _child(ev, "System")
        if sys_el is None:
            continue
        provider = _child(sys_el, "Provider")
        eid_el = _child(sys_el, "EventID")
        level_el = _child(sys_el, "Level")
        time_el = _child(sys_el, "TimeCreated")
        chan_el = _child(sys_el, "Channel")
        comp_el = _child(sys_el, "Computer")
        rec_el = _child(sys_el, "EventRecordID")
        data: Dict[str, Any] = {}
        ed = _child(ev, "EventData")
        if ed is not None:
            for item in list(ed):
                name = item.get("Name") or _local(item.tag)
                data[str(name)] = (item.text or "").strip()
        level_n = (level_el.text if level_el is not None else "") or ""
        out.append(
            {
                "ts": (time_el.get("SystemTime") if time_el is not None else None),
                "level": _LEVEL_FROM_EVTX.get(level_n, "info"),
                "level_num": level_n,
                "provider": (
                    provider.get("Name") if provider is not None else None
                ),
                "event_id": (eid_el.text if eid_el is not None else None),
                "channel": (chan_el.text if chan_el is not None else None),
                "computer": (comp_el.text if comp_el is not None else None),
                "record_id": (rec_el.text if rec_el is not None else None),
                "data": data,
            }
        )
    return out


# Tope on-demand de un canal (collector, execute_tool y resumen de logs).
EVENT_LOG_MAX_DEFAULT = 50


def windows_event_log(
    channel: str = "Security",
    max_events: int = EVENT_LOG_MAX_DEFAULT,
    **range_kw: Any,
) -> Dict[str, Any]:
    """RF-WIN-02: Event Log XML. Acepta date/startHour/endHour o startDate/endDate."""
    if not _is_windows():
        return _unsupported("windows_event_log")
    channel = resolve_event_channel(channel)
    max_events = max(1, min(int(max_events or EVENT_LOG_MAX_DEFAULT), 500))
    window = window_from_params(range_kw)
    if not shutil.which("wevtutil"):
        return {
            "tool": "windows_event_log",
            "status": "ERROR",
            "error": "wevtutil no está en PATH",
            "channel": channel,
        }
    try:
        cmd = ["wevtutil", "qe", channel]
        query = wevtutil_time_query(window.start, window.end)
        if query:
            cmd.append(f"/q:{query}")
        cmd += [f"/c:{max_events}", "/rd:true", "/f:xml"]
        res = _run(cmd, timeout=30)
        entries = parse_evtx_xml(res.stdout or "")
        entries = filter_entries(entries, window, limit=max_events)
        rec = {
            "tool": "windows_event_log",
            "status": "OK" if res.returncode == 0 or entries else "ERROR",
            "channel": channel,
            "known_channels": list(EVENT_CHANNELS),
            "count": len(entries),
            "entries": entries,
            "error": None if res.returncode == 0 else (res.stderr or "").strip()[:400],
            "ts": _now_iso(),
        }
        if window.bounded():
            rec["range"] = window_fields(window)
        return rec
    except Exception as e:
        return {"tool": "windows_event_log", "status": "ERROR", "error": str(e)}


def windows_event_log_bundle(max_per_channel: int = 20, **range_kw: Any) -> Dict[str, Any]:
    """Lee los canales RF-WIN-02 (clásicos + operativos) en un solo llamado."""
    if not _is_windows():
        return _unsupported("windows_event_log")
    channels: Dict[str, Any] = {}
    total = 0
    for ch in EVENT_CHANNELS:
        rec = windows_event_log(ch, max_events=max_per_channel, **range_kw)
        channels[ch] = rec
        total += int(rec.get("count") or 0)
    out = {
        "tool": "windows_event_log",
        "status": "OK",
        "count": total,
        "channels": channels,
        "ts": _now_iso(),
        "error": None,
    }
    window = window_from_params(range_kw)
    if window.bounded():
        out["range"] = window_fields(window)
    return out


# ---------------------------------------------------------------------------
# RF-WIN-01 ETW (proveedores + eventos de canales ETW-backed)
# ---------------------------------------------------------------------------

def parse_logman_providers(stdout: str) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for line in (stdout or "").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("-") or stripped.lower().startswith("provider"):
            continue
        guid = ""
        m = re.search(r"(\{[0-9A-Fa-f-]{36}\})", stripped)
        if m:
            guid = m.group(1)
            name = stripped[: m.start()].strip()
        else:
            parts = re.split(r"\s{2,}", stripped, maxsplit=1)
            name = parts[0].strip()
            guid = parts[1].strip() if len(parts) > 1 else ""
        if name:
            rows.append({"name": name, "guid": guid})
    return rows


def windows_etw(max_providers: int = 80) -> Dict[str, Any]:
    """RF-WIN-01: lista proveedores ETW (`logman`) y marca los de interés."""
    if not _is_windows():
        return _unsupported("windows_etw")
    max_providers = max(1, min(int(max_providers or 80), 400))
    try:
        if not shutil.which("logman"):
            return {
                "tool": "windows_etw",
                "status": "ERROR",
                "error": "logman no está en PATH",
            }
        res = _run(["logman", "query", "providers"], timeout=25)
        all_rows = parse_logman_providers(res.stdout or "")
        wanted = {n.lower() for n in ETW_PROVIDERS_OF_INTEREST}
        interesting = [r for r in all_rows if r["name"].lower() in wanted]
        return {
            "tool": "windows_etw",
            "status": "OK" if res.returncode == 0 else "ERROR",
            "provider_count": len(all_rows),
            "providers": all_rows[:max_providers],
            "of_interest": interesting,
            "error": None if res.returncode == 0 else (res.stderr or "").strip()[:400],
            "note": "Consumo de eventos vía canales Event Log ETW-backed (wevtutil XML), no sesión ETL.",
            "ts": _now_iso(),
        }
    except Exception as e:
        return {"tool": "windows_etw", "status": "ERROR", "error": str(e)}


# ---------------------------------------------------------------------------
# RF-WIN-03 Autoruns (Run/RunOnce + Winlogon + Startup + servicios Auto)
# ---------------------------------------------------------------------------

def _reg_values(hive: Any, sub: str) -> List[Dict[str, Any]]:
    import winreg  # type: ignore

    items: List[Dict[str, Any]] = []
    try:
        key = winreg.OpenKey(hive, sub)
    except OSError:
        return items
    hive_name = "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"
    i = 0
    while True:
        try:
            name, value, _typ = winreg.EnumValue(key, i)
        except OSError:
            break
        items.append(
            {
                "kind": "run_key",
                "path": f"{hive_name}\\{sub}",
                "name": str(name),
                "command": str(value)[:500],
            }
        )
        i += 1
        if i >= 200:
            break
    winreg.CloseKey(key)
    return items


def _startup_folder_entries() -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    appdata = os.environ.get("APPDATA") or ""
    program = os.environ.get("PROGRAMDATA") or r"C:\ProgramData"
    folders = []
    if appdata:
        folders.append(os.path.join(appdata, r"Microsoft\Windows\Start Menu\Programs\Startup"))
    folders.append(os.path.join(program, r"Microsoft\Windows\Start Menu\Programs\Startup"))
    for folder in folders:
        if not os.path.isdir(folder):
            continue
        try:
            names = os.listdir(folder)
        except OSError:
            continue
        for fn in names[:80]:
            if fn.startswith("."):
                continue
            items.append(
                {
                    "kind": "startup_folder",
                    "path": os.path.join(folder, fn),
                    "name": fn,
                }
            )
    return items


def windows_autoruns() -> Dict[str, Any]:
    """RF-WIN-03: Run/RunOnce, Winlogon, carpeta Startup y servicios Auto."""
    if not _is_windows():
        return _unsupported("windows_autoruns")
    try:
        import winreg  # type: ignore

        items: List[Dict[str, Any]] = []
        keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
        ]
        for hive, sub in keys:
            items.extend(_reg_values(hive, sub))
        items.extend(_startup_folder_entries())
        from colsoft_tools.endpoint_security import persistence_scan

        pers = persistence_scan()
        for rec in pers.get("items") or []:
            if rec.get("kind") in ("service", "win_service", "scheduled_task"):
                items.append(rec)
        kinds: Dict[str, int] = {}
        for rec in items:
            kinds[str(rec.get("kind"))] = kinds.get(str(rec.get("kind")), 0) + 1
        return {
            "tool": "windows_autoruns",
            "status": "OK",
            "count": len(items),
            "kinds": kinds,
            "items": items,
            "ts": _now_iso(),
            "error": None,
        }
    except Exception as e:
        return {"tool": "windows_autoruns", "status": "ERROR", "error": str(e)}


def autoruns_fingerprint(scan: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for rec in scan.get("items") or []:
        key = "|".join(
            str(rec.get(k) or "")
            for k in ("kind", "path", "name", "command")
        )
        out[key[:400]] = rec
    return out


# ---------------------------------------------------------------------------
# RF-WIN-04 WMI (CIM allowlist)
# ---------------------------------------------------------------------------

def windows_wmi(class_name: str = "Win32_OperatingSystem", max_rows: int = 40) -> Dict[str, Any]:
    """RF-WIN-04: Get-CimInstance de clases allowlist (no WMI arbitrario)."""
    if not _is_windows():
        return _unsupported("windows_wmi")
    cls = (class_name or "Win32_OperatingSystem").strip()
    if cls not in WMI_ALLOWLIST:
        return {
            "tool": "windows_wmi",
            "status": "ERROR",
            "error": f"Clase no permitida: {cls}",
            "allowlist": sorted(WMI_ALLOWLIST),
        }
    max_rows = max(1, min(int(max_rows or 40), 200))
    ns = "root/cimv2"
    if cls == "AntiVirusProduct":
        ns = "root/SecurityCenter2"
    # Hashtables planos: ConvertTo-Json de CimInstance incluye CimClass (~MB).
    script = (
        f"$ErrorActionPreference='Stop'; "
        f"$inst=@(Get-CimInstance -Namespace '{ns}' -ClassName {cls} "
        f"| Select-Object -First {max_rows}); "
        "$plain=[System.Collections.Generic.List[object]]::new(); "
        "foreach($r in $inst){ $h=[ordered]@{}; "
        "foreach($p in $r.PSObject.Properties){ "
        "if(@('CimClass','CimInstanceProperties','CimSystemProperties','PSComputerName') -contains $p.Name){continue}; "
        "$v=$p.Value; if($null -eq $v){continue}; "
        "if($v -is [datetime]){ $h[$p.Name]=$v.ToUniversalTime().ToString('o') } "
        "elseif($v -is [bool] -or $v -is [byte] -or $v -is [int] -or $v -is [long] -or $v -is [double] -or $v -is [decimal]){ $h[$p.Name]=$v } "
        "elseif($v -is [System.Array]){ $h[$p.Name]=@($v | ForEach-Object { \"$_\" } | Select-Object -First 20) } "
        "else { $h[$p.Name]=[string]$v } }; [void]$plain.Add([pscustomobject]$h) }; "
        "if($plain.Count -eq 0){ '[]' } else { @($plain) | ConvertTo-Json -Compress -Depth 2 }"
    )
    try:
        data = _ps_json(script, timeout=40)
        if isinstance(data, dict) and data.get("_parse_error"):
            return {
                "tool": "windows_wmi",
                "status": "ERROR",
                "class_name": cls,
                "namespace": ns,
                "error": str(data.get("_raw") or "PowerShell no devolvió JSON"),
                "allowlist": sorted(WMI_ALLOWLIST),
            }
        if data is None:
            raw_rows: List[Any] = []
        elif isinstance(data, list):
            raw_rows = data
        else:
            raw_rows = [data]
        rows = [r for r in (flatten_wmi_row(x) for x in raw_rows) if r]
        return {
            "tool": "windows_wmi",
            "status": "OK",
            "class_name": cls,
            "namespace": ns,
            "count": len(rows),
            "rows": rows,
            "allowlist": sorted(WMI_ALLOWLIST),
            "ts": _now_iso(),
            "error": None,
        }
    except Exception as e:
        return {"tool": "windows_wmi", "status": "ERROR", "error": str(e)}


def windows_perf_queues(timeout: int = 12) -> Dict[str, Any]:
    """PDH via CIM: Processor Queue Length y Current Disk Queue Length (_Total).

    `Processor Queue Length` y `System Processor Queue Length` son el mismo
    contador `\\System\\Processor Queue Length`.
    """
    if not _is_windows():
        return {}
    script = (
        "$ErrorActionPreference='Stop'; "
        "$sys=Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_System; "
        "$disk=@(Get-CimInstance -ClassName Win32_PerfFormattedData_PerfDisk_PhysicalDisk "
        "| Where-Object { $_.Name -eq '_Total' } | Select-Object -First 1); "
        "$dq=0; if($disk.Count -gt 0){ $dq=[int]$disk[0].CurrentDiskQueueLength }; "
        "@{ processor_queue_length=[int]$sys.ProcessorQueueLength; "
        "disk_queue_length=$dq } | ConvertTo-Json -Compress"
    )
    try:
        data = _ps_json(script, timeout=timeout)
    except Exception:
        return {}
    if not isinstance(data, dict) or data.get("_parse_error"):
        return {}
    out: Dict[str, Any] = {}
    for key in ("processor_queue_length", "disk_queue_length"):
        raw = data.get(key)
        if isinstance(raw, bool) or raw is None:
            continue
        try:
            out[key] = int(raw)
        except (TypeError, ValueError):
            continue
    return out


# ---------------------------------------------------------------------------
# RF-WIN-05 Tareas programadas
# ---------------------------------------------------------------------------

def windows_scheduled_tasks(max_tasks: int = 120) -> Dict[str, Any]:
    """RF-WIN-05: `schtasks /query /fo CSV`."""
    if not _is_windows():
        return _unsupported("windows_scheduled_tasks")
    max_tasks = max(1, min(int(max_tasks or 120), 400))
    try:
        res = _run(["schtasks", "/query", "/fo", "CSV", "/nh"], timeout=25)
        tasks: List[Dict[str, str]] = []
        for line in (res.stdout or "").splitlines():
            line = line.strip().strip('"')
            if not line:
                continue
            parts = [p.strip().strip('"') for p in line.split('","')]
            if len(parts) == 1:
                parts = [p.strip() for p in line.split(",")]
            rec = {
                "task_name": parts[0] if parts else line[:200],
                "next_run": parts[1] if len(parts) > 1 else "",
                "status": parts[2] if len(parts) > 2 else "",
            }
            tasks.append(rec)
            if len(tasks) >= max_tasks:
                break
        return {
            "tool": "windows_scheduled_tasks",
            "status": "OK" if res.returncode == 0 else "ERROR",
            "count": len(tasks),
            "truncated": len(tasks) >= max_tasks,
            "tasks": tasks,
            "error": None if res.returncode == 0 else (res.stderr or "").strip()[:400],
            "ts": _now_iso(),
        }
    except Exception as e:
        return {"tool": "windows_scheduled_tasks", "status": "ERROR", "error": str(e)}


# ---------------------------------------------------------------------------
# RF-WIN-06 Sysmon (opcional)
# ---------------------------------------------------------------------------

def windows_sysmon(max_events: int = 30) -> Dict[str, Any]:
    """RF-WIN-06: detecta el servicio y, si hay canal, lee Operational."""
    if not _is_windows():
        return _unsupported("windows_sysmon")
    try:
        installed = False
        service_name = None
        res = _run(["sc", "query", "Sysmon64"], timeout=8)
        if res.returncode == 0:
            installed, service_name = True, "Sysmon64"
        else:
            res = _run(["sc", "query", "Sysmon"], timeout=8)
            if res.returncode == 0:
                installed, service_name = True, "Sysmon"
        events: List[Dict[str, Any]] = []
        channel = "Microsoft-Windows-Sysmon/Operational"
        if installed and shutil.which("wevtutil"):
            ev = windows_event_log(channel, max_events=max_events)
            events = ev.get("entries") or []
        return {
            "tool": "windows_sysmon",
            "status": "OK",
            "installed": installed,
            "service": service_name,
            "optional": True,
            "count": len(events),
            "entries": events,
            "ts": _now_iso(),
            "error": None if installed else "Sysmon no instalado (opcional)",
        }
    except Exception as e:
        return {"tool": "windows_sysmon", "status": "ERROR", "error": str(e)}


# ---------------------------------------------------------------------------
# RF-WIN-07 Defender (coexistencia: solo lectura, nunca desactiva)
# ---------------------------------------------------------------------------

def windows_defender() -> Dict[str, Any]:
    """RF-WIN-07: Get-MpComputerStatus. No modifica ni deshabilita Defender."""
    if not _is_windows():
        return _unsupported("windows_defender")
    script = (
        "try { "
        "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,"
        "RealTimeProtectionEnabled,IoavProtectionEnabled,AntispywareEnabled,"
        "NISEnabled,AntivirusSignatureLastUpdated | ConvertTo-Json -Compress "
        "} catch { @{ error = $_.Exception.Message } | ConvertTo-Json -Compress }"
    )
    try:
        data = _ps_json(script, timeout=25)
        status = data if isinstance(data, dict) else {}
        return {
            "tool": "windows_defender",
            "status": "OK",
            "coexist": True,
            "disables_defender": False,
            "am_service_enabled": status.get("AMServiceEnabled"),
            "antivirus_enabled": status.get("AntivirusEnabled"),
            "realtime": status.get("RealTimeProtectionEnabled"),
            "details": status,
            "ts": _now_iso(),
            "error": status.get("error"),
        }
    except Exception as e:
        return {"tool": "windows_defender", "status": "ERROR", "error": str(e)}


def event_severity(entry: Dict[str, Any]) -> str:
    """Severity SRS para event_push a partir de un Event Log XML."""
    level = str(entry.get("level") or "info").lower()
    eid = str(entry.get("event_id") or "")
    channel = str(entry.get("channel") or "")
    if level in ("critical", "error"):
        return "high" if level == "error" else "critical"
    if channel.lower() == "security" and eid in {"4625", "4672", "4688", "4720", "4732"}:
        return "high"
    if "sysmon" in channel.lower() and eid in {"1", "3", "8", "10", "11"}:
        return "medium"
    if "defender" in channel.lower() and eid in {"1116", "1117"}:
        return "high"
    return "low" if level in ("info", "debug") else "medium"
