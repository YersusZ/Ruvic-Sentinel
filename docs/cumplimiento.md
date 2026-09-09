# Trazabilidad de cumplimiento — SRS §18

Mapeo de controles a evidencia **en este agente** (código y operación).
No es una certificación ISO/CIS/SFC ni un informe de auditoría.

Referencias: SRS v1.0 §15 / §18; [`checklist-pendiente.md`](checklist-pendiente.md);
[`produccion.md`](produccion.md).

---

## ISO 27001:2022 (Anexo A, subset aplicable al endpoint)

| Control | Qué cubre aquí | Evidencia |
|---|---|---|
| A.5.15 Access control | Canal de control autenticado | mTLS (enrollment + `tls_client_*`), desafío RSA, JWT Robin en `/api/*` |
| A.5.16 Identity management | Identidad persistente del host | `POST /api/enroll` (token de un solo uso), `agent_id` en config/identity |
| A.5.17 Authentication information | Secretos de canal | PEMs 0600 en `enrollment/certs/`; `PROTECTED_CONFIG_KEYS` (tls, `websocket_url`, `data_plane`) no se cambian por `update_config` |
| A.8.24 Use of cryptography | TLS y firma de comandos | TLS 1.2+ (`colsoft_tools/tls_util.py`); Ed25519 por comando; `require_command_signature` fail-closed |
| A.8.15 Logging | Quién / cuándo / qué | Auditoría local JSONL (cadena de hashes); RobinLogs (`metrics_logger.py`); `issued_by` |
| A.8.16 Monitoring activities | Observabilidad y detecciones | RF-OBS-01..09, RF-SEC-01..10, monitores Win/Linux |
| A.8.8 Management of technical vulnerabilities | Inventario + CVE | `cve_inventory` + `server/lib/cve_correlator.py` |
| A.8.32 Change management | Config remota acotada | `update_config` con esquema; `PROTECTED_CONFIG_KEYS`; backup atómico |
| A.8.19 Installation of software | Auto-update firmado | `self_update.py` Ed25519 fail-closed + rollback |
| A.8.13 Information backup | Telemetría offline | Buffer disco ≥1 GiB / ≥24 h (`telemetry_buffer.py`) |
| A.8.10 Information deletion | Retención | Prune por edad y por `max_total_bytes` |
| A.5.23 Information security for cloud | Auto-tag de instancia | IMDSv2 (y Azure/GCP) en `host` y atributos OTLP `cloud.*` |
| A.8.2 Privileged access | Remediación Alto/Crítico | `allow_high_risk` off por defecto; doble candado backend + agente |
| A.7.13 Equipment maintenance | Tamper | Baseline SHA-256 de binario/config/certs (`tamper.py`) |

Huecos conscientes (no los cubre este componente): cifrado en reposo del JSONL
de telemetría; DLP; clasificación de datos en el host; SIEM corporativo (RobinLogs
es el destino de *este* agente).

---

## CIS (benchmarks de hardening)

| Pieza | Qué es | Límite |
|---|---|---|
| RF-SEC-06 `cis_score` / `CisLoop` | Score 0–100 sobre un **subset Level 1** Linux/Windows | No es un scan CIS-CAT completo |
| RF-SEC-01 FIM | Rutas por defecto alineadas a CIS (`/etc/passwd`, sshd, …) | `security.fim.paths` |
| Empaquetado | Servicio con recuperación (systemd `Restart=always`, NSSM/`sc failure`) | CIS Windows 9.x / Linux servicios |

Los IDs de check (`1.5.1`, `5.2.10`, `9.1`, …) viven en
`colsoft_tools/endpoint_security.py`. Ampliar el subset es trabajo de producto,
no un gap silencioso del NFR.

---

## SFC (Superintendencia Financiera de Colombia)

Lectura operativa de Circular Externa 007 de 2018 y requisitos habituales de
seguridad de la información / continuidad para entidades vigiladas. **No**
sustituye el programa SARO/SAI de la entidad.

| Expectativa típica | Cómo lo cubre el agente |
|---|---|
| Confidencialidad en tránsito | TLS 1.2+ y mTLS obligatorio si `allow_insecure_ws: false` |
| Integridad de órdenes | Firma Ed25519 por comando; catálogo `run_script` por `script_id` |
| Trazabilidad de acciones | `issued_by` / `issued_at` / `message_id`; auditoría local; RobinLogs `type=audit` |
| Gestión de acceso | Enrollment de un solo uso; JWT en REST; política local fail-closed |
| Disponibilidad / contingencia | Buffer offline 1 GiB / 24 h; backoff de reconexión; servicio con restart |
| Gestión de cambios | `update_config` con claves de seguridad inmutables en remoto |
| Monitoreo de seguridad | RF-SEC + `event_push` de alta prioridad |
| Inventario y vulnerabilidades | `hardware_inventory`, `installed_software`, `cve_inventory` |
| Evidencia para el supervisor | Este documento + [`produccion.md`](produccion.md) + auditoría JSONL |

Lab (`allow_insecure_ws`, JWT off) **no** cumple SFC. Producción:
[`produccion.md`](produccion.md).
