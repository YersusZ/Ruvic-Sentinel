#!/usr/bin/env python3
"""
Enrollment — PKI ligera para mTLS + llaves de firma de comandos (SRS §8.1/§8.2/§8.5).

Genera dos carpetas (no mezclar secretos del servidor con el agente):

  server/       ca.key, ca.crt, server.crt, server.key, signing.key
  enrollment/   ca.crt, agent.crt, agent.key, signing.pub
  config_client.json  (junto a enrollment/; rutas tls_* = enrollment/…)

Uso:
  python scripts/enroll.py --client-name PC_Remota_Test --out-dir ./certs
  python scripts/enroll.py --out-dir ./certs --san 192.168.20.21
  python scripts/enroll.py --server-only --out-dir ./certs --san 192.168.20.21
    # --san SOLO aplica a server.crt (IP/DNS del gateway).
    # POST /api/enroll emite el cert de *cliente* (CN=client_name), sin SAN extra.

El paquete del agente es `config_client.json` + `enrollment/` en la misma
carpeta que el binario (p.ej. `dist/`). `server/` no sale del backend.

Para levantar el servidor con mTLS (desde server/, no el CLI de uvicorn):
  SSL_CERTFILE=../certs/server/server.crt \\
  SSL_KEYFILE=../certs/server/server.key \\
  SSL_CA_CERTS=../certs/server/ca.crt \\
  SSL_CERT_REQS=required \\
  SERVER_SIGNING_KEY=../certs/server/signing.key \\
    python main.py

Requiere: cryptography.
"""

import argparse
import datetime
import json
import ipaddress
import os
import sys
import uuid
from typing import List, Optional, Sequence, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID

VALIDITY_DAYS = 3650
_DEFAULT_SANS = ("localhost", "127.0.0.1")


def _normalize_sans(extra: Optional[Sequence[str]]) -> List[str]:
    """localhost + 127.0.0.1 siempre; `--san` suma IPs/DNS (comas o flags repetidos)."""
    out: List[str] = []
    seen = set()
    chunks: List[str] = list(_DEFAULT_SANS)
    for raw in extra or []:
        chunks.extend(str(raw or "").split(","))
    for part in chunks:
        name = part.strip()
        if not name or name in seen:
            continue
        seen.add(name)
        out.append(name)
    return out


def _ws_host(sans: List[str]) -> str:
    extras = [s for s in sans if s not in _DEFAULT_SANS and s != "::1"]
    return extras[0] if extras else "localhost"


def gen_rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_cert(subject_name, issuer_name, public_key, issuer_key, ca: bool, sans=None):
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name(subject_name) if not isinstance(subject_name, x509.Name) else subject_name)
        .issuer_name(x509.Name(issuer_name) if not isinstance(issuer_name, x509.Name) else issuer_name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=VALIDITY_DAYS)
        )
    )
    if ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=False,
                key_encipherment=False,
                key_cert_sign=True,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
    else:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=True,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH])
            if not sans
            else x509.ExtendedKeyUsage(
                [
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                ]
            ),
            critical=False,
        )
        if sans:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName(s)
                        for s in sans
                        if not _is_ip(s)
                    ]
                    + [x509.IPAddress(ipaddress.ip_address(s)) for s in sans if _is_ip(s)]
                ),
                critical=False,
            )
    # OpenSSL 3.4+ rechaza la cadena sin SKI/AKI (CERTIFICATE_VERIFY_FAILED).
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(public_key),
        critical=False,
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
        critical=False,
    )
    return builder.sign(issuer_key, hashes.SHA256())


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _write(path, data, mode="wb"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, mode) as f:
        f.write(data)
    os.chmod(path, 0o600 if mode == "wb" or path.endswith(".key") else 0o644)
    print(f"  [ok] {path}")


def _mkdir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    return path


def _try_load_ca(server_dir: str) -> Optional[Tuple[object, object, bytes]]:
    """Reusa ca.key/ca.crt si ya existen (para reemitir solo server.crt)."""
    key_path = os.path.join(server_dir, "ca.key")
    crt_path = os.path.join(server_dir, "ca.crt")
    if not (os.path.isfile(key_path) and os.path.isfile(crt_path)):
        return None
    with open(key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(crt_path, "rb") as f:
        ca_crt_pem = f.read()
    ca_cert = x509.load_pem_x509_certificate(ca_crt_pem)
    return ca_key, ca_cert, ca_crt_pem


def main() -> None:
    ap = argparse.ArgumentParser(description="Enrollment PKI para mTLS (SRS §8.2)")
    ap.add_argument("--client-name", default="PC_Remota_Test", help="Nombre del agente")
    ap.add_argument("--out-dir", default="certs", help="Directorio de salida")
    ap.add_argument(
        "--server-only",
        action="store_true",
        help="Solo CA + certificado de servidor (sin agente ni config). "
        "Si ya hay ca.key, la reusa y solo reemite server.crt",
    )
    ap.add_argument(
        "--san",
        action="append",
        default=[],
        metavar="HOST",
        help="SAN extra del server.crt (IP o DNS). Repetible o separado por comas. "
        "No aplica al certificado de cliente ni a POST /api/enroll. "
        "Siempre se incluyen localhost y 127.0.0.1. "
        "Ej: --san 192.168.20.21 --san gateway.lan",
    )
    args = ap.parse_args()
    sans = _normalize_sans(args.san)

    out = os.path.abspath(args.out_dir)
    server_dir = _mkdir(os.path.join(out, "server"))
    print(f"Enrollment → {out}")
    print(f"  SAN server.crt: {', '.join(sans)}")

    # 1. CA autofirmada (llave solo en server/)
    reused = args.server_only and _try_load_ca(server_dir)
    if reused:
        ca_key, ca_cert, ca_crt_pem = reused
        ca_subject = ca_cert.subject
        print("  [ok] reusando CA existente (agentes ya enrolados siguen válidos)")
    else:
        ca_key = gen_rsa_key()
        ca_subject = [x509.NameAttribute(NameOID.COMMON_NAME, "Ruvic Colsoft Agent CA")]
        ca_cert = make_cert(
            ca_subject, ca_subject, ca_key.public_key(), ca_key, ca=True
        )
        ca_key_pem = ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        ca_crt_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
        _write(os.path.join(server_dir, "ca.key"), ca_key_pem)
        _write(os.path.join(server_dir, "ca.crt"), ca_crt_pem)

    # 2. Certificado del servidor
    srv_key = gen_rsa_key()
    srv_subject = [x509.NameAttribute(NameOID.COMMON_NAME, "ws-gateway")]
    srv_cert = make_cert(
        srv_subject,
        ca_subject,
        srv_key.public_key(),
        ca_key,
        ca=False,
        sans=sans,
    )
    _write(os.path.join(server_dir, "server.key"), srv_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    _write(os.path.join(server_dir, "server.crt"), srv_cert.public_bytes(serialization.Encoding.PEM))

    if args.server_only:
        print("Listo (solo servidor). Carpeta:", server_dir)
        print("Reiniciá uvicorn para cargar el server.crt nuevo.")
        return

    # 3. Material del agente → enrollment/ junto al config (nunca signing.key / ca.key / server.*)
    enroll_dir = _mkdir(os.path.join(out, "enrollment"))
    agent_key = gen_rsa_key()
    agent_subject = [
        x509.NameAttribute(NameOID.COMMON_NAME, args.client_name),
    ]
    agent_cert = make_cert(
        agent_subject,
        ca_subject,
        agent_key.public_key(),
        ca_key,
        ca=False,
        sans=None,
    )
    _write(os.path.join(enroll_dir, "ca.crt"), ca_crt_pem)
    _write(os.path.join(enroll_dir, "agent.key"), agent_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    _write(os.path.join(enroll_dir, "agent.crt"), agent_cert.public_bytes(serialization.Encoding.PEM))

    # 4. Llaves Ed25519: privada en server/, pública en enrollment/
    sign_key = ed25519.Ed25519PrivateKey.generate()
    sign_pub = sign_key.public_key()
    _write(os.path.join(server_dir, "signing.key"), sign_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    _write(
        os.path.join(enroll_dir, "signing.pub"),
        sign_pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )

    # 5. Identidad RSA del agente (desafío de autenticación, §8.1)
    ident_key = gen_rsa_key()
    ident_pub_pem = ident_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    ident_priv_pem = ident_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    _write(os.path.join(enroll_dir, "identity.key"), ident_priv_pem.encode())
    _write(os.path.join(enroll_dir, "identity.pub"), ident_pub_pem.encode())

    # 6. Template de config del agente (incluye llave pública de firma del enrollment)
    agent_id = (
        "agt_" + args.client_name.lower().strip().replace(" ", "-")
        + "_" + uuid.uuid4().hex[:6]
    )
    config_template = {
        "agent_id": agent_id,
        "client_name": args.client_name,
        "tenant_id": "",
        "websocket_url": f"wss://{_ws_host(sans)}:8000/ws/colsoft-tools",
        "allow_insecure_ws": False,
        "require_command_signature": True,
        "signing_public_key": "enrollment/signing.pub",
        "private_key": "enrollment/identity.key",
        "public_key": "enrollment/identity.pub",
        "tls_ca_cert": "enrollment/ca.crt",
        "tls_client_cert": "enrollment/agent.crt",
        "tls_client_key": "enrollment/agent.key",
        "heartbeat_interval": 30,
        "policy": {
            "allowed_commands": [],
            "allow_high_risk": False,
        },
        "scripts_catalog": {},
        "audit_log_path": os.path.join("results_logs", "agent_audit.jsonl"),
        "max_command_rate": 20,
        "auto_update": {},
        "telemetry_buffer": {
            "max_age_days": 7.0,
            "max_file_bytes": 8388608,
            "max_total_bytes": 1073741824,
        },
        "tamper": {"allow_rebaseline": False},
        "scheduler": {"interval_seconds": 0, "tools": []},
        "data_plane": {
            "enabled": True,
            "compression": "gzip",
            "batch_size": 32,
            "batch_interval_seconds": 5,
        },
        "process_watch": {"enabled": False},
        "service_watch": {"enabled": False},
        "health_probes": {"interval_seconds": 0, "checks": []},
        "alerts": {"interval_seconds": 30, "cooldown_seconds": 300, "rules": []},
        "security": {
            "fim": {"enabled": False},
            "persistence": {"enabled": False},
            "auth_audit": {"enabled": False},
            "detection": {"enabled": False},
            "dns": {"enabled": False},
            "rootkit": {"enabled": False},
            "cis": {"enabled": False},
            "cve_inventory": {"enabled": False},
            "auto_response": {"enabled": False, "actions": []},
        },
        "windows": {
            "event_log": {"enabled": False},
            "autoruns": {"enabled": False},
            "sysmon": {"enabled": False},
        },
        "linux": {
            "auditd": {"enabled": False},
            "systemd": {"enabled": False},
            "netlink": {"enabled": False},
        },
    }
    cfg_path = os.path.join(out, "config_client.json")
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(config_template, f, ensure_ascii=False, indent=2)
    os.chmod(cfg_path, 0o600)
    print(f"  [ok] {cfg_path}")

    dist_dir = os.path.join(os.path.dirname(out), "dist")
    if os.path.isdir(dist_dir):
        dist_enroll = _mkdir(os.path.join(dist_dir, "enrollment"))
        for name in ("ca.crt", "agent.crt", "agent.key", "signing.pub"):
            src = os.path.join(enroll_dir, name)
            dst = os.path.join(dist_enroll, name)
            with open(src, "rb") as f:
                data = f.read()
            _write(dst, data)
        dist_cfg_path = os.path.join(dist_dir, "config_client.json")
        if os.path.isfile(dist_cfg_path):
            with open(dist_cfg_path, "r", encoding="utf-8") as f:
                dist_cfg = json.load(f)
            dist_cfg["tls_ca_cert"] = "enrollment/ca.crt"
            dist_cfg["tls_client_cert"] = "enrollment/agent.crt"
            dist_cfg["tls_client_key"] = "enrollment/agent.key"
            dist_cfg["signing_public_key"] = "enrollment/signing.pub"
            with open(dist_cfg_path, "w", encoding="utf-8") as f:
                json.dump(dist_cfg, f, ensure_ascii=False, indent=2)
                f.write("\n")
            os.chmod(dist_cfg_path, 0o600)
            print(f"  [ok] {dist_cfg_path} (tls_* → enrollment/)")
        print("  [ok] paquete agente también en", dist_enroll)

    print()
    print("Paquete del agente: config_client.json + enrollment/ (misma carpeta).")
    print("Backend (no copiar al endpoint):", server_dir)
    print()
    print("Para levantar el servidor con mTLS (python main.py, no uvicorn CLI):")
    print(
        f"  SSL_CERTFILE={os.path.join(server_dir, 'server.crt')} "
        f"SSL_KEYFILE={os.path.join(server_dir, 'server.key')} "
        f"SSL_CA_CERTS={os.path.join(server_dir, 'ca.crt')} "
        f"SSL_CERT_REQS=required "
        f"SERVER_SIGNING_KEY={os.path.join(server_dir, 'signing.key')} "
        "python main.py"
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
