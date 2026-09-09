"""
Correlación CVE en el backend — SRS §11 RF-SEC-05.

El agente solo manda inventario (`cve_inventory` / `installed_software`).
Este módulo cruza name+version contra un catálogo local (JSON opcional +
built-in). No descarga NVD en runtime: el feed se opera fuera del agente.
"""

from __future__ import annotations

import json
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_LOCK = threading.Lock()
_INVENTORY: Dict[str, Dict[str, Any]] = {}

# Producto → aliases frecuentes de gestores de paquetes.
BUILTIN_CATALOG: List[Dict[str, Any]] = [
    {
        "cve": "CVE-2021-44228",
        "product": "log4j",
        "aliases": ["log4j-core", "apache-log4j", "liblog4j"],
        "version_gte": "2.0",
        "version_lt": "2.15.0",
        "severity": "critical",
        "cvss": 10.0,
        "summary": "Log4Shell JNDI RCE",
    },
    {
        "cve": "CVE-2024-6387",
        "product": "openssh",
        "aliases": ["openssh-server", "openssh-client", "ssh"],
        "version_gte": "8.5",
        "version_lt": "9.8",
        "severity": "critical",
        "cvss": 8.1,
        "summary": "regreSSHion signal handler race",
    },
    {
        "cve": "CVE-2021-3156",
        "product": "sudo",
        "aliases": ["sudo-ldap"],
        "version_gte": "1.8.2",
        "version_lte": "1.9.5p1",
        "severity": "high",
        "cvss": 7.8,
        "summary": "Baron Samedit heap overflow",
    },
    {
        "cve": "CVE-2023-38408",
        "product": "openssh",
        "aliases": ["openssh-client", "openssh-server"],
        "version_lt": "9.3p2",
        "severity": "high",
        "cvss": 9.8,
        "summary": "ssh-agent forwarded PKCS11 remote code execution",
    },
    {
        "cve": "CVE-2022-0778",
        "product": "openssl",
        "aliases": ["libssl1.1", "libssl3", "openssl-libs"],
        "version_gte": "1.0.2",
        "version_lt": "1.1.1n",
        "severity": "high",
        "cvss": 7.5,
        "summary": "Infinite loop in BN_mod_sqrt",
    },
    {
        "cve": "CVE-2023-38545",
        "product": "curl",
        "aliases": ["libcurl4", "libcurl3", "curl-minimal"],
        "version_gte": "7.69.0",
        "version_lt": "8.4.0",
        "severity": "high",
        "cvss": 9.8,
        "summary": "SOCKS5 heap overflow",
    },
    {
        "cve": "CVE-2021-4034",
        "product": "polkit",
        "aliases": ["policykit-1", "polkitd"],
        "version_lt": "0.120",
        "severity": "high",
        "cvss": 7.8,
        "summary": "PwnKit pkexec local privilege escalation",
    },
    {
        "cve": "CVE-2022-0847",
        "product": "linux",
        "aliases": ["linux-image", "kernel", "linux-image-generic"],
        "version_gte": "5.8",
        "version_lt": "5.16.11",
        "severity": "high",
        "cvss": 7.8,
        "summary": "Dirty Pipe",
    },
    {
        "cve": "CVE-2024-3094",
        "product": "xz-utils",
        "aliases": ["xz", "liblzma5", "liblzma"],
        "version_gte": "5.6.0",
        "version_lte": "5.6.1",
        "severity": "critical",
        "cvss": 10.0,
        "summary": "xz-utils backdoor",
    },
    {
        "cve": "CVE-2023-44487",
        "product": "nginx",
        "aliases": ["nginx-core", "nginx-full"],
        "version_lt": "1.25.3",
        "severity": "high",
        "cvss": 7.5,
        "summary": "HTTP/2 Rapid Reset (si HTTP/2 está activo)",
    },
    {
        "cve": "CVE-2014-0160",
        "product": "openssl",
        "aliases": ["libssl1.0.0"],
        "version_gte": "1.0.1",
        "version_lt": "1.0.1g",
        "severity": "high",
        "cvss": 7.5,
        "summary": "Heartbleed",
    },
    {
        "cve": "CVE-2022-22965",
        "product": "spring-core",
        "aliases": ["spring-webmvc", "libspring-core-java"],
        "version_gte": "5.3.0",
        "version_lt": "5.3.18",
        "severity": "critical",
        "cvss": 9.8,
        "summary": "Spring4Shell",
    },
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_version(value: str) -> Tuple[int, ...]:
    parts = re.findall(r"\d+", str(value or ""))
    if not parts:
        return (0,)
    return tuple(int(p) for p in parts[:8])


def _cmp(a: Tuple[int, ...], b: Tuple[int, ...]) -> int:
    n = max(len(a), len(b))
    aa = a + (0,) * (n - len(a))
    bb = b + (0,) * (n - len(b))
    if aa < bb:
        return -1
    if aa > bb:
        return 1
    return 0


def version_in_range(version: str, entry: Dict[str, Any]) -> bool:
    ver = _parse_version(version)
    if entry.get("version_eq") is not None:
        return _cmp(ver, _parse_version(str(entry["version_eq"]))) == 0
    if entry.get("version_gte") is not None and _cmp(
        ver, _parse_version(str(entry["version_gte"]))
    ) < 0:
        return False
    if entry.get("version_gt") is not None and _cmp(
        ver, _parse_version(str(entry["version_gt"]))
    ) <= 0:
        return False
    if entry.get("version_lte") is not None and _cmp(
        ver, _parse_version(str(entry["version_lte"]))
    ) > 0:
        return False
    if entry.get("version_lt") is not None and _cmp(
        ver, _parse_version(str(entry["version_lt"]))
    ) >= 0:
        return False
    bounded = any(
        entry.get(k) is not None
        for k in ("version_eq", "version_gte", "version_gt", "version_lte", "version_lt")
    )
    return bounded


def _catalog_path() -> Optional[Path]:
    env = (os.getenv("CVE_CATALOG_PATH") or "").strip()
    if env:
        return Path(env)
    here = Path(__file__).resolve().parent.parent / "data" / "cve_catalog.json"
    return here if here.is_file() else None


def load_catalog() -> List[Dict[str, Any]]:
    catalog = list(BUILTIN_CATALOG)
    path = _catalog_path()
    if path is None:
        return catalog
    try:
        extra = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return catalog
    if isinstance(extra, dict):
        extra = extra.get("cves") or extra.get("catalog") or []
    if isinstance(extra, list):
        catalog.extend(e for e in extra if isinstance(e, dict) and e.get("cve"))
    return catalog


def _product_names(entry: Dict[str, Any]) -> List[str]:
    names = [str(entry.get("product") or "").strip().lower()]
    for alias in entry.get("aliases") or []:
        names.append(str(alias).strip().lower())
    return [n for n in names if n]


def _pkg_matches(pkg_name: str, entry: Dict[str, Any]) -> bool:
    name = (pkg_name or "").strip().lower()
    if not name:
        return False
    for cand in _product_names(entry):
        if name == cand or name.startswith(cand + "-") or cand in name.split("-"):
            return True
        if cand in name:
            return True
    return False


def correlate_packages(
    packages: List[Dict[str, Any]],
    *,
    catalog: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Cruza inventario del agente contra el catálogo CVE local."""
    catalog = catalog if catalog is not None else load_catalog()
    matches: List[Dict[str, Any]] = []
    seen = set()
    for pkg in packages or []:
        if not isinstance(pkg, dict):
            continue
        name = str(pkg.get("name") or pkg.get("product") or "")
        version = str(pkg.get("version") or "")
        if not name or not version:
            continue
        for entry in catalog:
            if not _pkg_matches(name, entry):
                continue
            if not version_in_range(version, entry):
                continue
            key = (entry.get("cve"), name, version)
            if key in seen:
                continue
            seen.add(key)
            matches.append(
                {
                    "cve": entry.get("cve"),
                    "product": name,
                    "version": version,
                    "severity": entry.get("severity") or "medium",
                    "cvss": entry.get("cvss"),
                    "summary": entry.get("summary"),
                    "sha256": pkg.get("sha256"),
                }
            )
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    score = 0
    for m in matches:
        score += 25 * sev_rank.get(str(m.get("severity")).lower(), 1)
    score = min(100, score)
    return {
        "status": "OK",
        "engine": "local-catalog",
        "catalog_size": len(catalog),
        "packages": len(packages or []),
        "count": len(matches),
        "score": score,
        "matches": matches,
        "ts": _now_iso(),
        "note": "Feed local (no NVD en vivo). Ampliar con CVE_CATALOG_PATH.",
    }


def ingest_inventory(
    agent_id: str,
    packages: List[Dict[str, Any]],
    *,
    tenant_id: Optional[str] = None,
    persist_dir: Optional[str] = None,
) -> Dict[str, Any]:
    result = correlate_packages(packages)
    record = {
        "agent_id": agent_id,
        "tenant_id": tenant_id,
        "ingested_at": _now_iso(),
        **result,
    }
    with _LOCK:
        _INVENTORY[agent_id] = record
    base = persist_dir or os.path.join("results_logs", "cve")
    try:
        os.makedirs(base, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", agent_id)[:80]
        path = os.path.join(base, f"{safe}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(record, f, ensure_ascii=False, indent=2)
            f.write("\n")
    except OSError:
        pass
    return record


def get_agent_findings(agent_id: str) -> Optional[Dict[str, Any]]:
    with _LOCK:
        rec = _INVENTORY.get(agent_id)
        if rec:
            return rec
    base = os.path.join("results_logs", "cve")
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", agent_id)[:80]
    path = os.path.join(base, f"{safe}.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            with _LOCK:
                _INVENTORY[agent_id] = data
            return data
    except (OSError, ValueError):
        return None
    return None


def packages_from_result(result: Any) -> List[Dict[str, Any]]:
    if not isinstance(result, dict):
        return []
    pkgs = result.get("packages")
    if isinstance(pkgs, list):
        return [p for p in pkgs if isinstance(p, dict)]
    inner = result.get("result")
    if isinstance(inner, dict) and isinstance(inner.get("packages"), list):
        return [p for p in inner["packages"] if isinstance(p, dict)]
    return []
