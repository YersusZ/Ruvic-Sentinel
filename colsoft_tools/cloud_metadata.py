"""Metadata de instancia cloud — SRS §15 (IMDSv2 / auto-tagging).

Consulta el enlace-local con timeout corto. Fuera de la nube falla en
milisegundos y no bloquea el arranque. El resultado se cachea.

Prioridad: AWS IMDSv2 (token PUT, nunca IMDSv1) → Azure IMDS → GCP.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

AWS_IMDS = "http://169.254.169.254"
AZURE_IMDS = "http://169.254.169.254/metadata/instance"
GCP_IMDS = "http://metadata.google.internal/computeMetadata/v1"

_CACHE: Optional[Dict[str, Any]] = None
_FETCHED = False

DEFAULT_TIMEOUT = 0.4


class _NetMiss(Exception):
    """169.254.169.254 no enruta / timeout: no reintentar Azure en la misma IP."""


def _urlopen(req: urllib.request.Request, timeout: float) -> bytes:
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read() or b""
    except urllib.error.HTTPError:
        raise
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise _NetMiss(str(e)) from e


def _aws_imdsv2(timeout: float) -> Optional[Dict[str, str]]:
    """AWS EC2 Instance Metadata Service v2 (sesión con token)."""
    token_req = urllib.request.Request(
        f"{AWS_IMDS}/latest/api/token",
        method="PUT",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
    )
    try:
        token = _urlopen(token_req, timeout).decode("utf-8", errors="replace").strip()
    except urllib.error.HTTPError:
        return None
    if not token:
        return None

    def _get(path: str) -> str:
        req = urllib.request.Request(
            f"{AWS_IMDS}{path}",
            headers={"X-aws-ec2-metadata-token": token},
        )
        try:
            return _urlopen(req, timeout).decode("utf-8", errors="replace").strip()
        except (urllib.error.HTTPError, _NetMiss, ValueError):
            return ""

    instance_id = _get("/latest/meta-data/instance-id")
    if not instance_id:
        return None
    az = _get("/latest/meta-data/placement/availability-zone")
    region = _get("/latest/meta-data/placement/region") or (
        az[:-1] if az and az[-1].isalpha() else az
    )
    account = ""
    doc_raw = _get("/latest/dynamic/instance-identity/document")
    if doc_raw:
        try:
            doc = json.loads(doc_raw)
            account = str(doc.get("accountId") or "")
            region = str(doc.get("region") or region)
        except ValueError:
            pass
    return {
        "cloud_provider": "aws",
        "instance_id": instance_id,
        "instance_type": _get("/latest/meta-data/instance-type"),
        "region": region,
        "availability_zone": az,
        "account_id": account,
        "imds": "v2",
    }


def _azure_imds(timeout: float) -> Optional[Dict[str, str]]:
    req = urllib.request.Request(
        f"{AZURE_IMDS}?api-version=2021-02-01",
        headers={"Metadata": "true"},
    )
    try:
        raw = _urlopen(req, timeout).decode("utf-8", errors="replace")
        doc = json.loads(raw)
    except (urllib.error.HTTPError, ValueError):
        return None
    compute = doc.get("compute") if isinstance(doc, dict) else None
    if not isinstance(compute, dict) or not compute.get("vmId"):
        return None
    return {
        "cloud_provider": "azure",
        "instance_id": str(compute.get("vmId") or ""),
        "instance_type": str(compute.get("vmSize") or ""),
        "region": str(compute.get("location") or ""),
        "availability_zone": str(compute.get("zone") or ""),
        "account_id": str(compute.get("subscriptionId") or ""),
        "imds": "azure",
    }


def _gcp_imds(timeout: float) -> Optional[Dict[str, str]]:
    def _get(path: str) -> str:
        req = urllib.request.Request(
            f"{GCP_IMDS}/{path}",
            headers={"Metadata-Flavor": "Google"},
        )
        try:
            return _urlopen(req, timeout).decode("utf-8", errors="replace").strip()
        except (urllib.error.HTTPError, _NetMiss, ValueError):
            return ""

    instance_id = _get("instance/id")
    if not instance_id:
        return None
    zone = _get("instance/zone")  # projects/N/zones/REGION-AZ
    az = zone.rsplit("/", 1)[-1] if zone else ""
    region = "-".join(az.split("-")[:-1]) if az else ""
    return {
        "cloud_provider": "gcp",
        "instance_id": instance_id,
        "instance_type": _get("instance/machine-type").rsplit("/", 1)[-1],
        "region": region,
        "availability_zone": az,
        "account_id": _get("project/project-id"),
        "imds": "gcp",
    }


def fetch_cloud_metadata(
    config: Optional[Dict[str, Any]] = None,
    *,
    force: bool = False,
) -> Dict[str, Any]:
    """Devuelve tags de instancia o `{}`. Cacheado. Fail-open."""
    global _CACHE, _FETCHED
    if _FETCHED and not force:
        return dict(_CACHE or {})

    cfg = {}
    if isinstance(config, dict):
        cloud = config.get("cloud")
        if isinstance(cloud, dict):
            cfg = cloud
    if cfg.get("enabled") is False or cfg.get("imds") is False:
        _FETCHED = True
        _CACHE = {}
        return {}

    try:
        timeout = float(cfg.get("timeout_seconds") or DEFAULT_TIMEOUT)
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT
    timeout = min(max(timeout, 0.1), 2.0)

    tags: Optional[Dict[str, str]] = None
    link_local_up = True
    try:
        tags = _aws_imdsv2(timeout)
    except _NetMiss:
        link_local_up = False
        tags = None
    except Exception:
        tags = None
    if not tags and link_local_up:
        try:
            tags = _azure_imds(timeout)
        except _NetMiss:
            tags = None
        except Exception:
            tags = None
    if not tags:
        try:
            tags = _gcp_imds(timeout)
        except (_NetMiss, Exception):
            tags = None
    _CACHE = {k: v for k, v in (tags or {}).items() if v}
    _FETCHED = True
    return dict(_CACHE)


def cloud_otlp_attributes(tags: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Claves semánticas OTLP `cloud.*` / `host.id` a partir de los tags IMDS."""
    info = tags if tags is not None else fetch_cloud_metadata()
    if not info:
        return {}
    out: Dict[str, Any] = {}
    provider = info.get("cloud_provider")
    if provider:
        out["cloud.provider"] = provider
    if info.get("region"):
        out["cloud.region"] = info["region"]
    if info.get("availability_zone"):
        out["cloud.availability_zone"] = info["availability_zone"]
    if info.get("account_id"):
        out["cloud.account.id"] = info["account_id"]
    if info.get("instance_id"):
        out["host.id"] = info["instance_id"]
    if info.get("instance_type"):
        out["host.type"] = info["instance_type"]
    return out


def reset_cloud_metadata_cache() -> None:
    """Solo tests."""
    global _CACHE, _FETCHED
    _CACHE = None
    _FETCHED = False
