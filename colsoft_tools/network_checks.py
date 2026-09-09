import os
import re
import shutil
import socket
import subprocess
import sys
from datetime import datetime
from typing import Any, Dict
from urllib.parse import urlparse
import ssl

import requests


def check_http_service(
    url: str, timeout: int = 10, *, verify: bool = True
) -> Dict[str, Any]:
    """
    Verifica disponibilidad básica de un servicio HTTP/HTTPS.

    HTTPS verifica el certificado (tienda del sistema) salvo `verify=False`
    (opt-in explícito, p.ej. probe a un lab con cert interno).
    """
    try:
        start = datetime.now()
        kwargs: Dict[str, Any] = {"timeout": timeout}
        if urlparse(url).scheme == "https":
            kwargs["verify"] = verify
        resp = requests.get(url, **kwargs)
        elapsed = (datetime.now() - start).total_seconds()
        return {
            "tool": "http_get",
            "url": url,
            "status": "UP" if 200 <= resp.status_code < 400 else "DOWN",
            "status_code": resp.status_code,
            "response_time": elapsed,
            "error": None,
            "tls_verify": bool(kwargs.get("verify", True)) if "verify" in kwargs else None,
        }
    except Exception as e:
        return {
            "tool": "http_get",
            "url": url,
            "status": "DOWN",
            "status_code": None,
            "response_time": None,
            "error": str(e),
        }


def resolve_dns(target: str) -> Dict[str, Any]:
    """
    Resuelve DNS para un hostname (A/AAAA) y devuelve IPs encontradas.
    target puede ser hostname o URL.
    """
    try:
        host = target.strip()
        if "://" in host:
            parsed = urlparse(host)
            host = parsed.hostname or host
        host = host.strip("[]")  # por si viene IPv6 entre corchetes
        if not host:
            return {"tool": "dns_resolve", "target": target, "status": "ERROR", "ips": [], "error": "Empty host"}

        infos = socket.getaddrinfo(host, None)
        ips = sorted({info[4][0] for info in infos if info and info[4]})
        return {
            "tool": "dns_resolve",
            "target": target,
            "host": host,
            "status": "OK" if ips else "EMPTY",
            "ips": ips,
            "error": None,
        }
    except Exception as e:
        return {
            "tool": "dns_resolve",
            "target": target,
            "host": None,
            "status": "ERROR",
            "ips": [],
            "error": str(e),
        }


def check_tls_certificate(target: str, timeout: int = 8) -> Dict[str, Any]:
    """
    Verifica handshake TLS y extrae información básica del certificado.
    target puede ser hostname o URL. Si es URL, usa el puerto indicado o 443 por defecto.
    """
    host = target.strip()
    port = 443
    try:
        if "://" in host:
            parsed = urlparse(host)
            host = parsed.hostname or host
            if parsed.port:
                port = int(parsed.port)

        host = (host or "").strip("[]")
        if not host:
            return {"tool": "tls", "target": target, "status": "ERROR", "error": "Empty host"}

        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        start = datetime.now()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        elapsed = (datetime.now() - start).total_seconds()

        not_after = cert.get("notAfter")
        not_before = cert.get("notBefore")
        subject = cert.get("subject")
        issuer = cert.get("issuer")
        san = cert.get("subjectAltName")

        return {
            "tool": "tls",
            "target": target,
            "host": host,
            "port": port,
            "status": "OK",
            "handshake_time": elapsed,
            "not_before": not_before,
            "not_after": not_after,
            "subject": subject,
            "issuer": issuer,
            "subject_alt_name": san,
            "error": None,
        }
    except Exception as e:
        return {
            "tool": "tls",
            "target": target,
            "host": host or None,
            "port": port,
            "status": "ERROR",
            "error": str(e),
        }


def ping_host(host: str, count: int = 3, timeout: int = 15) -> Dict[str, Any]:
    """
    Ejecuta un ping simple al host (Windows: -n; macOS/Linux/Unix: -c).
    """
    try:
        if sys.platform == "win32":
            cmd = ["ping", "-n", str(max(1, count)), host]
            run_kw: Dict[str, Any] = {
                "capture_output": True,
                "text": True,
                "timeout": timeout,
            }
            if hasattr(subprocess, "CREATE_NO_WINDOW"):
                run_kw["creationflags"] = subprocess.CREATE_NO_WINDOW
            result = subprocess.run(cmd, **run_kw)
        else:
            result = subprocess.run(
                ["ping", "-c", str(max(1, count)), host],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        return {
            "tool": "ping",
            "host": host,
            "success": result.returncode == 0,
            "output": result.stdout,
            "error": result.stderr if result.returncode != 0 else None,
        }
    except Exception as e:
        return {
            "tool": "ping",
            "host": host,
            "success": False,
            "output": None,
            "error": str(e),
        }


def check_tcp_port(host: str, port: int, timeout: int = 5) -> Dict[str, Any]:
    """
    Verifica conectividad TCP a un puerto concreto.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        start = datetime.now()
        code = sock.connect_ex((host, port))
        elapsed = (datetime.now() - start).total_seconds()
        sock.close()
        return {
            "tool": "tcp_connect",
            "host": host,
            "port": port,
            "status": "UP" if code == 0 else "DOWN",
            "response_time": elapsed,
            "error": None,
        }
    except Exception as e:
        return {
            "tool": "tcp_connect",
            "host": host,
            "port": port,
            "status": "DOWN",
            "response_time": None,
            "error": str(e),
        }


def traceroute(target: str, max_hops: int = 30, timeout: float = 0) -> Dict[str, Any]:
    """
    Ruta de red hacia un destino (§8.4-A). Params SRS: target, max_hops.

    Usa la herramienta nativa del SO (traceroute / tracepath) y parsea la salida
    en saltos estructurados (hop, host, ip, rtt1..rtt3). Si la herramienta no
    está disponible (o requiere privilegios), falla con un error claro.

    `timeout` es el tope del subproceso (s). Si es 0 (o no se pasa), se deriva
    del nº de hops: `max(60, max_hops*4)` — un recorrido real a internet supera
    con creces los 30s del default por riesgo "Bajo" (§8.5).
    """
    target = (target or "").strip()
    if not target:
        return {"tool": "traceroute", "status": "ERROR", "error": "Missing target"}
    max_hops = max(1, min(int(max_hops or 30), 64))

    try:
        timeout = float(timeout)
    except (TypeError, ValueError):
        timeout = 0.0
    sub_timeout = min(
        max(60.0, max_hops * 4.0) if timeout <= 0 else timeout,
        300.0,
    )

    if sys.platform == "win32":
        cmd = ["tracert", "-h", str(max_hops), target]
    else:
        binary = shutil.which("traceroute") or shutil.which("tracepath")
        if not binary:
            return {
                "tool": "traceroute",
                "status": "ERROR",
                "target": target,
                "error": "No se encontró 'traceroute' ni 'tracepath'",
            }
        cmd = [binary, "-m", str(max_hops), target]
        if os.path.basename(binary) == "traceroute":
            # 1 sonda por salto y espera corta por sonda: acelera el recorrido
            # (3 sondas × espera por defecto excede fácilmente el timeout).
            cmd += ["-q", "1", "-w", "1"]

    try:
        run_kw: Dict[str, Any] = {
            "capture_output": True,
            "text": True,
            "timeout": sub_timeout,
        }
        if sys.platform == "win32" and hasattr(subprocess, "CREATE_NO_WINDOW"):
            run_kw["creationflags"] = subprocess.CREATE_NO_WINDOW
        result = subprocess.run(cmd, **run_kw)
    except FileNotFoundError:
        return {
            "tool": "traceroute",
            "status": "ERROR",
            "target": target,
            "error": f"Herramienta de traceroute no instalada",
        }
    except subprocess.TimeoutExpired:
        return {
            "tool": "traceroute",
            "status": "ERROR",
            "target": target,
            "error": f"Timeout ({sub_timeout:g}s) excedido",
        }
    except Exception as e:
        return {"tool": "traceroute", "status": "ERROR", "target": target, "error": str(e)}

    output = result.stdout or result.stderr
    hops = _parse_traceroute(output, sys.platform)

    if hops:
        status = "OK"
    elif result.returncode == 0:
        status = "EMPTY"
    else:
        status = "ERROR"

    return {
        "tool": "traceroute",
        "target": target,
        "max_hops": max_hops,
        "status": status,
        "hops": hops,
        "output": output[:6000],
        "error": result.stderr.strip() if result.returncode != 0 else None,
    }


def _parse_traceroute(output: str, platform: str) -> list:
    """Parsea la salida de traceroute/tracert/tracepath en saltos."""
    hops: list = []
    if not output:
        return hops

    # traceroute (Linux/macOS): " 1  192.168.1.1  0.5 ms  0.3 ms  0.4 ms"
    # Windows tracert: "  1     1 ms     1 ms     1 ms  192.168.1.1"
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        # Skip cabeceras
        if re.match(r"^(traceroute|tracert|tracepath|Tracking|Over a maximum)", line, re.I):
            continue

        if platform == "win32":
            m = re.match(
                r"^\s*(\d+)\s+([\d<]*\s*ms)?.*?\s+(\S+)\s*\[([\d.:a-fA-F]+)\]?",
                line,
            )
            if not m:
                m = re.match(r"^\s*(\d+)\s+(.+)$", line)
            if m:
                hop = int(m.group(1))
                rtts = re.findall(r"([\d<]+)\s*ms", line)
                hostname = ip = None
                if "* * *" in line:
                    hostname = ip = None
                else:
                    parts = line.split(None, 3)
                    if len(parts) >= 2:
                        hostname = parts[-1]
                        ip = parts[-1]
                        if "[" in line:
                            im = re.search(r"\[([\d.:a-fA-F]+)\]", line)
                            if im:
                                ip = im.group(1)
                                hostname = parts[-1].replace(f"[{ip}]", "").strip() or ip
                hops.append({
                    "hop": hop,
                    "hostname": hostname,
                    "ip": ip,
                    "rtt_ms": [r for r in rtts[:3]],
                })
        else:
            # traceroute (Linux/macOS): "1  hostname (1.2.3.4)  0.5 ms  0.3 ms"
            # tracepath: "1:  hostname  0.5 ms  0.3 ms" (hostname = IP o nombre)
            if re.match(r"^\s*\d+\?", line):
                # hop no confirmado ("1?: [LOCALHOST]") — se omite
                continue
            m = re.match(r"^\s*(\d+)[:.]?\s*(.*)$", line)
            if not m:
                continue
            hop = int(m.group(1))
            rest = m.group(2).strip()
            if not rest or "* * *" in rest or "no reply" in rest.lower():
                hops.append({"hop": hop, "hostname": None, "ip": None, "rtt_ms": None})
                continue
            rtts = re.findall(r"([\d.]+)\s*ms", rest)
            im = re.search(r"\(([\d.:a-fA-F]+)\)", rest)
            if im:
                ip = im.group(1)
                hostname = rest.split("(")[0].strip() or ip
            else:
                first = rest.split()[0]
                if re.match(r"^[\d.:a-fA-F]+$", first):
                    ip = first.strip("[]")
                    hostname = ip
                else:
                    ip = None
                    hostname = first
            hops.append({
                "hop": hop,
                "hostname": hostname,
                "ip": ip,
                "rtt_ms": [float(r) for r in rtts[:3]] if rtts else None,
            })
    return hops


def dns_lookup(
    hostname: str,
    record_type: str = "A",
    timeout: int = 10,
) -> Dict[str, Any]:
    """
    Resolución DNS nativa (§8.4-A). Params SRS: hostname, record_type.

    A/AAAA se resuelven vía stdlib (socket.getaddrinfo). Para el resto de
    tipos (CNAME, MX, TXT, NS, SOA, PTR) usa `dig` si está disponible, con
    `nslookup` como fallback — devuelve la salida cruda junto a un resumen.
    """
    hostname = (hostname or "").strip()
    if not hostname:
        return {"tool": "dns_lookup", "status": "ERROR", "error": "Missing hostname"}
    record_type = (record_type or "A").strip().upper()
    if record_type == "ANY":
        record_type = "ANY"

    try:
        if record_type in ("A", "AAAA"):
            return _dns_lookup_addr(hostname, record_type)

        dig = shutil.which("dig")
        if dig:
            cmd = [dig, "+short", "+time=5", "+tries=1", hostname, record_type]
            res = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            answers = [
                line.strip()
                for line in res.stdout.strip().splitlines()
                if line.strip()
            ]
            return {
                "tool": "dns_lookup",
                "hostname": hostname,
                "record_type": record_type,
                "status": "OK",
                "answers": answers,
                "output": res.stdout.strip(),
                "error": res.stderr.strip() if res.returncode != 0 else None,
            }

        nslookup = shutil.which("nslookup")
        if nslookup:
            cmd = [nslookup, "-type=" + record_type, hostname]
            res = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            lines = [line.strip() for line in res.stdout.strip().splitlines() if line.strip()]
            return {
                "tool": "dns_lookup",
                "hostname": hostname,
                "record_type": record_type,
                "status": "OK",
                "answers": lines,
                "output": res.stdout.strip(),
                "error": res.stderr.strip() if res.returncode != 0 else None,
            }

        return {
            "tool": "dns_lookup",
            "hostname": hostname,
            "record_type": record_type,
            "status": "ERROR",
            "error": (
                f"record_type={record_type} requiere 'dig' o 'nslookup' "
                "(no encontrados)"
            ),
        }
    except subprocess.TimeoutExpired:
        return {
            "tool": "dns_lookup",
            "hostname": hostname,
            "record_type": record_type,
            "status": "ERROR",
            "error": f"Timeout ({timeout}s) excedido",
        }
    except Exception as e:
        return {
            "tool": "dns_lookup",
            "hostname": hostname,
            "record_type": record_type,
            "status": "ERROR",
            "error": str(e),
        }


def _dns_lookup_addr(hostname: str, record_type: str) -> Dict[str, Any]:
    """Resolución A/AAAA por getaddrinfo (solo stdlib)."""
    family = socket.AF_INET if record_type == "A" else socket.AF_INET6
    try:
        infos = socket.getaddrinfo(hostname, None, family)
        answers = sorted({info[4][0] for info in infos if info and info[4]})
        return {
            "tool": "dns_lookup",
            "hostname": hostname,
            "record_type": record_type,
            "status": "OK" if answers else "EMPTY",
            "answers": answers,
            "output": "\n".join(answers),
            "error": None,
        }
    except socket.gaierror as e:
        return {
            "tool": "dns_lookup",
            "hostname": hostname,
            "record_type": record_type,
            "status": "ERROR",
            "answers": [],
            "error": str(e),
        }
    except Exception as e:
        return {
            "tool": "dns_lookup",
            "hostname": hostname,
            "record_type": record_type,
            "status": "ERROR",
            "answers": [],
            "error": str(e),
        }

