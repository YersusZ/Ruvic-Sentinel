# Checklist de implementación pendiente — Agentes de Endpoint (SRS v1.0)

Referencia: SRS v1.0 — Agentes de Endpoint (§ del SRS en cada ítem).
Estado actualizado el 24 de agosto de 2026. Rama de trabajo:
`features/phase4`.

**Hecho:** Fase 1 completa (§8 plano de control) + core común Fase 2 (RF-CORE-01..08) + data plane OTLP (§7.1 / RF-OBS-08) + observabilidad RF-OBS-01..09 (salvo contenedores) + **Fase 3 seguridad RF-SEC-01..10** + **Fase 4 Windows RF-WIN-01..08** + **Fase 4 Linux RF-LIN-01..08** + **empaquetado §16**.
**Siguiente:** RF-OBS-10 (contenedores/K8s) queda para una fase posterior.

Desvíos vs el SRS (no bloquean el checklist): un solo agente **Python** para
Win/Linux (no core Rust/Go ni dos binarios, §6); el contrato de control del
repo incluye `command_ack` y handshake `auth_challenge`/`auth_response`/
`auth_error` además de la tabla §8.3; mTLS omitible solo con `allow_insecure_ws`
(lab). El NFR de RAM/CPU/boot se validó en CPython idle (no en MSI/PyInstaller).
Helper de privilegio mínimo (§8.5 SYSTEM/root) **no implementado**: el servicio
corre como LocalSystem/root; diferido.

---

## Fase 1 — Formalización del plano de control

### §8.3 Protocolo de mensajes — HECHO
- [x] Esquema de mensajes: `command_request`, `command_ack`, `command_response`, `event_push`, `heartbeat`, `auth_ack` (+ handshake `auth_challenge` / `auth_response` / `auth_error`)
- [x] `message_id` único por comando (idempotencia/dedup)
- [x] Campos `issued_by`, `issued_at`, `expires_at`, `agent_id`, `signature` en `command_request`
- [x] `auth_ack` tras el handshake (confirmación de sesión con `agent_id`)
- [x] Heartbeat bidireccional periódico (cliente + servidor, `heartbeat_interval` en config)
- [x] `event_push` para detecciones de alta prioridad (tamper, alertas, probes). Telemetría de volumen: OTLP/HTTP (`/v1/logs`, `/v1/metrics`), no WS.
- [x] Módulo compartido `colsoft_tools/protocol.py` (tipos, constructores, estados, helpers, alias SRS)
- [x] Alias de comandos SRS §8.4 → tools internos (`get_system_log`, `get_system_metrics`, `dns_lookup`, etc.)
- [x] Dedup de `command_request` por `message_id` en el agente (idempotencia §8.6)
- [x] Manejo de `expires_at`: respuesta `status: expired` en el agente

### Seguridad del canal (§8.2, §8.5) — HECHO
- [x] mTLS: certificado de cliente por agente (enrollment) + `wss://`. Sin `allow_insecure_ws`, el agente no abre WSS/OTLP HTTPS sin `tls_client_cert`/`tls_client_key`. Lab: [`produccion.md`](produccion.md)
- [x] Firma por comando (Ed25519) validada en el agente contra llave pública del enrollment
- [x] Validar realmente la firma RSA del desafío en el servidor (controllers.py)
- [x] Allowlist local de políticas por host/grupo (doble candado) + rechazo reportado
- [x] Regla: comandos Alto/Crítico deshabilitados por defecto
- [x] `run_script` por catálogo firmado (`script_id`), nunca código en payload
- [x] Auditoría local inmutable de ejecuciones (quién/cuándo/qué/resultado, cadena de hashes)
- [x] Rate limiting por agente y tipo de comando
- [x] Timeout obligatorio por comando (riesgo por defecto, tope 300s)

> Implementado con `colsoft_tools/security.py` y `scripts/enroll.py`. Los agentes con
> `signing_public_key` exigen firma (fail-closed). Lab: `allow_insecure_ws: true`;
> `require_command_signature: true` (si viene `false`, se ignora). Arranque TLS del server: `python main.py`
> (Docker CMD), no `uvicorn main:app`. Enroll online: puerto bootstrap loopback o PKI offline.

### Cola y estados (§8.6) — HECHO
- [x] Estados de comando: `pending → sent → acked → running → completed | failed | expired | rejected` (backend, en `server/command_queue.py`)
- [x] Cola en backend con TTL (`expires_at`) y reporte `expired` al reconectar (se descarta, no se ejecuta fuera de contexto)
- [x] Dedup por `message_id` en backend (idempotencia del lado servidor)
- [x] `command_ack` del agente (sent → acked) antes de ejecutar
- [x] Re-despacho de la cola al reconectar (`dispatch_pending`) + identidad estable del agente (`agent_id` en config, query param)
- [x] Cola persistente en disco (`results_logs/queue/<message_id>.json`) + REST: `GET /api/commands`, `GET /api/commands/{message_id}`, `GET /api/agents/{id}/commands`
- [x] POST `/api/agents/{id}/execute` con agente offline → 202 `queued` (antes 404)
- [x] Backoff exponencial + jitter, tope 60s (`run_forever`)

### Catálogo C — remediación (§8.4-C) — HECHO
- [x] `kill_process` (Alto, deshabilitado por defecto) — por PID o nombre, SIGTERM→SIGKILL si force, protege al propio agente
- [x] `start_service` / `stop_service` / `restart_service` (allowlist explícita obligatoria, §8.4-C; systemctl/sc/launchctl)
- [x] `block_ip` / `unblock_ip` (Alto) — Linux iptables; Windows netsh advfirewall; `in`/`out` se normalizan a input/output
- [x] `isolate_host` (Crítico) — Linux iptables / Windows Firewall; exceptúa loopback y manager (`websocket_url` si no se pasa `manager_host`); duración auto-revertible (hilo + al arrancar si expiró). `restore_isolation` es comando remoto (mismo riesgo).
- [x] `run_script` (Crítico, catálogo firmado por `script_id`, nunca código en payload) — ejecución real vía `colsoft_tools/remediation.py`
- [x] Política local aplicada también a la ejecución programada (`AgentScheduler`) — sin bypass §8.5

### Catálogo D — admin del agente (§8.4-D) — HECHO
- [x] `update_config` — diff remoto con validación de esquema (`colsoft_tools/agent_admin.py`), backup + escritura atómica, claves de seguridad protegidas (no modificables en remoto)
- [x] `trigger_update` — auto-update vía `auto_update.script`/`auto_update.command` del config (recibe version/url/channel, timeout 5-300s)
- [x] `restart_agent` — re-exec del proceso con los mismos argumentos (`os.execv`) DESPUÉS de confirmar la respuesta al backend (marker `_agent_restart`)
- [x] `health_check` — uptime, versión, PID, validez del config, etc.
- [x] Integrados en el agente (`ADMIN_TOOLS` en `ws_tools_client_embedded.py`; `ws_tools_client.py` es alias de lab), con firma + política local + auditoría (mismo plano de control §8.2/§8.5)

### Catálogo A y B — completar (§8.4-A/B) — HECHO
- [x] `traceroute` (Bajo, Habilitado; params `target`, `max_hops`) — tool nativa en `colsoft_tools/network_checks.py` (traceroute/tracert/tracepath con parseo de saltos)
- [x] `dns_lookup` (Bajo, Habilitado; params `hostname`, `record_type`) — tool nativa dedicada (A/AAAA por stdlib; CNAME/MX/TXT/NS/SOA/PTR vía dig/nslookup); se quitó el alias a `dns_resolve`
- [x] `collect_file` (Alto², Deshabilitado por defecto; params `path`, `max_size_mb`) — `colsoft_tools/observability.py`, base64 con tope de tamaño y hash SHA-256; requiere política explícita (doble candado backend + agente)
- [x] `collect_forensic_snapshot` — procesos + conexiones + métricas + logs recientes + persistencia (RF-SEC-02). En Windows: autoruns + Event Log Security (RF-WIN-02/03). En Linux: auditd + systemd + LSM (RF-LIN-02/06/07)

### Integraciones laterales (Robin) — HECHO
- [x] JWT RS256 de Robin en la API REST (`server/lib/jwt_auth.py`, `ROBIN_JWT_REQUIRED`) — `issued_by=user:<sub>` en comandos. Claim `roles` exigido; **RBAC en execute**: `ROBIN_JWT_EXECUTE_ROLES` / `ROBIN_JWT_HIGH_RISK_ROLES` (`jwt_can_issue_command`). `jti` no se valida contra blacklist de logout. Prod: [`produccion.md`](produccion.md)
- [x] RobinLogs (`server/lib/metrics_logger.py`, `robin-logger>=0.3.0`) — ingesta `/api/robin-logger/store`; consulta proxy `GET /api/logs`; taxonomía de **este** agente (no la de tickets/SOC): [`agent-telemetry.md`](agent-telemetry.md); `event_push` mapeado (severity→level)

---

## Fase 2 — Observabilidad / core común

### Core común (§9)
- [x] RF-CORE-01/02: enrollment con token de un solo uso + certificado de cliente (identidad persistente, no generada por sesión) — `POST /enroll` y `POST /api/enroll` (server/enrollment.py; host del WS desde `Host`/`ENROLLMENT_PUBLIC_HOST`, no localhost hardcodeado) + `colsoft_tools/enrollment.py`
- [x] RF-CORE-03: gestor de config con validación de esquema previa a aplicar — `colsoft_tools/config_manager.py` (CONFIG_SCHEMA, claves protegidas, `load_config`/`validate_config_diff`/`apply_config_diff`), reutilizado por agent_admin y clientes
- [x] RF-CORE-04: buffer en disco (memoria + disco) para telemetría, retención configurable, reintento al reconectar — `colsoft_tools/telemetry_buffer.py` (JSONL + rotación/prune, `flush_to_ws` al reconectar en auth_ack)
- [x] RF-CORE-05: auto-update con verificación de firma y rollback — `colsoft_tools/self_update.py` (Ed25519 fail-closed, `apply_update_with_rollback`); `trigger_update` delega en él si hay `verify_public_key`/url
- [x] RF-CORE-06: tamper-resistance (detectar detención/modificación de binario/config/cert) — `colsoft_tools/tamper.py` (baseline SHA-256 + fingerprint, `verify_and_rebaseline` al arranque, evento `security.tamper_detected`)
- [x] RF-CORE-07: scheduler interno desacoplado del hilo WS — `colsoft_tools/scheduler.py` (`AgentScheduler` corre en `run_forever`, fuera de la sesión; sink sync/async hacia el buffer)
- [x] RF-CORE-08: `tenant_id` en toda telemetría y comando — `colsoft_tools/protocol.py` (`make_*` con `tenant_id`), clients, `server/controllers.py`, `connection_manager.py`, `metrics_logger.py`

### Data plane (§7.1, RF-OBS-08) — HECHO
- [x] Canal de datos separado del WS (HTTPS/OTLP HTTP JSON, batch + gzip) — `colsoft_tools/data_plane.py` (`DataPlaneExporter` drena el `TelemetryBuffer` independiente del hilo WS; `data_plane` en config; fallback `flush_to_ws` si `enabled: false`)
- [x] Exportación OpenTelemetry (OTLP) — logs `POST /v1/logs` + métricas `POST /v1/metrics` (gzip); receptor en `server/otlp.py` (alias `/otlp/v1/*`); destino por defecto derivado de `websocket_url` o collector 4318

### Observabilidad restante
- [x] RF-OBS-01: métricas CPU/mem/disco/red/I/O — tool `system_metrics` + scheduler
- [x] RF-OBS-02: monitoreo de procesos como evento (creación/fin), no solo snapshot — `colsoft_tools/obs_monitors.py` (`ProcessWatcher`); `process_watch` en config (off por defecto); eventos `process.created` / `process.exited`
- [x] RF-OBS-03: monitoreo de servicios — `ServiceWatcher` (`service_watch`, off); poll `sc`/`systemctl`/`launchctl`, eventos `service.changed`. En Linux `linux.systemd` cubre unidades (RF-LIN-06)
- [x] RF-OBS-04: parsing/normalización de logs — `get_system_log` devuelve `entries[]` con `ts`, `level`, `source`, `message`, `pid`, `host`, `event_id` (journalctl JSON / wevtutil texto / unified log)
- [x] RF-OBS-05: inventario de hardware + hash de software — tool `hardware_inventory`; `installed_software` acepta `include_hash`/`max_hash` (SHA-256 del ejecutable)
- [x] RF-OBS-06: snapshot `get_network_connections` (proceso↔conexión). Sockets TCP nuevos en Linux si `linux.netlink.enabled` (poll `/proc/net/tcp`, no listener live)
- [x] RF-OBS-07: health checks configurables (puerto/proceso/HTTP) — tool `health_probes` + loop `HealthProbeLoop` (`health_probes.checks` en config); distinto de `health_check` (salud del agente)
- [x] RF-OBS-09: motor de alertas por umbral local (edge) — `AlertEngine` sobre `system_metrics` (`alerts.rules`, cooldown); eventos `alert.threshold` / `alert.cleared`
- [ ] RF-OBS-10: contenedores/K8s (fase posterior)

---

## Fase 3 — Seguridad base (§11)
- [x] RF-SEC-01: FIM con hash SHA-256, usuario y proceso responsable — `fim_scan` + `FimWatcher` (`colsoft_tools/endpoint_security.py`, `sec_monitors.py`); `security.fim`
- [x] RF-SEC-02: detección de persistencia (Windows: registry/services/tasks; Linux: cron/timers/authorized_keys) — `persistence_scan` + `PersistenceWatcher`; servicios Win firman `name|ImagePath` (no el estado SCM); tareas por nombre (no Next Run Time)
- [x] RF-SEC-03: auditoría de autenticación (logon/logoff, fallos, sudo/su, escalamiento) — `auth_audit` + `AuthAuditLoop`
- [x] RF-SEC-04: motor de reglas locales (PowerShell codificado, `curl|sh`, ejecución desde /tmp) con MITRE ATT&CK — `DETECTION_RULES` + `DetectionEngine` (`SEC-001` T1059.001, `SEC-002` T1059.004, `SEC-003` T1036.005)
- [x] RF-SEC-05: correlación CVE (insumo; motor vive en backend) — agente `cve_inventory`; backend `server/lib/cve_correlator.py`, `POST /api/cve/correlate`, `GET /api/agents/{id}/vulnerabilities`
- [x] RF-SEC-06: score de hardening CIS — `cis_score` (subset Level 1 Linux/Windows) + `CisLoop`
- [x] RF-SEC-07: monitoreo DNS (dominio + proceso origen) — `dns_monitor` + `DnsWatcher` (conexiones :53 + caché resolvectl/DnsClientCache)
- [x] RF-SEC-08: heurísticas de rootkit — `rootkit_check` + `RootkitLoop` (/proc vs psutil, módulos, SUID en tmp, kernel taint)
- [x] RF-SEC-09: `event_push` para detecciones (canal ya listo en §8.3) — `is_control_plane_event` trata `security.*` como plano de control
- [x] RF-SEC-10: integración respuesta activa (kill/isolate/block) sujeta a política — `security.auto_response` + `ActiveResponse` (CommandPolicy §8.5, fail-closed)

Config: bloque `security` en `config_client.json` (monitores **off** por defecto, igual que `process_watch`). Tools on-demand habilitadas (riesgo bajo/medio).

---

## Fase 4 — Específicos de SO

### Windows (§12)
- [x] RF-WIN-01: ETW — **inventario** `windows_etw` (`logman query providers`); eventos vía canales Event Log ETW-backed (`wevtutil` XML, poll). **No** hay sesión ETL live. Monitor: `windows.event_log.enabled`
- [x] RF-WIN-02: Event Log estructurado (System/Application/Security/Setup/ForwardedEvents + PowerShell/Defender/IIS) — `windows_event_log` parsea XML (`ts`, `level`, `provider`, `event_id`, `channel`, `data`)
- [x] RF-WIN-03: registro de autorun (Run/RunOnce/Winlogon/Startup/servicios/tasks) — `windows_autoruns` + `AutorunWatcher` (`windows.autorun_change`); también en `forensic_snapshot`
- [x] RF-WIN-04: WMI — `windows_wmi` (`Get-CimInstance` allowlist; filas planas sin `CimClass`)
- [x] RF-WIN-05: tareas programadas — `windows_scheduled_tasks` (`schtasks /query /fo CSV`)
- [x] RF-WIN-06: integración Sysmon (opcional) — `windows_sysmon` + `SysmonWatcher`; si no hay servicio, idle (no falla el agente)
- [x] RF-WIN-07: coexistencia con Defender — `windows_defender` (Get-MpComputerStatus, **solo lectura**, no desactiva)
- [x] RF-WIN-08: servicio Windows + MSI — NSSM + `sc failure` (`deploy/install-service-windows.bat`, Inno `install-windows.iss`); plantilla MSI WiX `deploy/robin-client-monitor.wxs` (compilar en Windows). Firma Authenticode: §16

Código: `colsoft_tools/windows_collectors.py`, `colsoft_tools/win_monitors.py`. Config `windows` **off** por defecto (igual que `process_watch`). En Linux las tools responden `UNSUPPORTED`.

### Linux (§13)
- [x] RF-LIN-01: eBPF — tool `linux_ebpf` (`bpftool prog show` + tracepoints syscalls/red/exec en tracefs). **Snapshot, no attach live.** Analogía: `windows_etw`/`logman`.
- [x] RF-LIN-02: auditd — tool `linux_auditd` (estado `systemctl`, reglas `auditctl -l`, eventos `ausearch`/`audit.log`). Monitor: `linux.auditd.enabled`
- [x] RF-LIN-03: journald + `/var/log/*` — `linux_syslog` + `system_log` con canales clásicos `system`/`application`/`security`/`setup`/`forwarded` (analogía Event Viewer) y `source=syslog|auth|kern|dpkg|…`
- [x] RF-LIN-04: métricas `/proc` `/sys` sin psutil — tool `linux_proc_metrics`
- [x] RF-LIN-05: netlink — tool `linux_netlink` (dump RTNETLINK puntual). Monitor `linux.netlink.enabled`: **poll** `/sys/class/net` + `/proc/net/tcp`, no suscripción `AF_NETLINK`
- [x] RF-LIN-06: timers/unidades systemd — tool `linux_systemd_units` + diff en `persistence_scan`. Monitor: `linux.systemd.enabled` (`linux.unit_change`)
- [x] RF-LIN-07: SELinux/AppArmor — tool `linux_lsm` (estado + denials; `OK` si están off)
- [x] RF-LIN-08: inventario dpkg/rpm con hash — tool `linux_packages` (`dpkg -L` / `rpm -ql`); `installed_software` usa el mismo hasher

Código: `colsoft_tools/linux_collectors.py`, `colsoft_tools/linux_monitors.py`. Config `linux` **off** por defecto. En Windows las tools responden `UNSUPPORTED`.

---

## Transversal / despliegue

### Modelo de datos (§14)
- [x] Envelope común (`schema_version`, `timestamp`, `agent_id`, `tenant_id` siempre presente — string vacío si no hay tenant —, `host`, `event_type`, `category`, `severity`, `user`/`process`/`network`/`detection` cuando aplica) en `event_push` y en `compact_event_for_otlp` — `colsoft_tools/event_model.py`

### Empaquetado (§16)
Guía: [`empaquetado.md`](empaquetado.md). La firma usa secretos de CI (PFX / `GPG_KEY_ID`); no hay certificados en el repo.

- [x] MSI firmado (Authenticode) + servicio Windows con recuperación — Inno `deploy/install-windows.iss` + WiX `deploy/robin-client-monitor.wxs`; NSSM + `sc failure` / `failureflag`; firma `deploy/sign-windows.ps1` (`AUTHENTICODE_PFX`)
- [x] `.deb`/`.rpm` firmados (GPG) + unidad systemd — `deploy/pack-linux.sh`, `deploy/robin-client-monitor.service` (`Restart=always`, StartLimit 24h); firma `deploy/sign-linux.sh` (`GPG_KEY_ID`)
- [x] Token/cert de enrollment como parámetro del instalador — `--enroll` / `ROBIN_ENROLL_*` (Linux); `/ENROLL=` Inno y propiedades MSI `ENROLLTOKEN`…; carpeta `enrollment/` opcional. El cert lo emite `POST /api/enroll` (no se embebe un PEM)
- [x] Instalación silenciosa (SCCM/Intune/GPO; Ansible/Chef/Puppet/cloud-init) — Inno `/VERYSILENT`; `msiexec /qn`; `deploy/ansible/install-agent.yml`; `deploy/cloud-init.yaml.example`
- [x] ARM64 (builds actuales solo amd64) — `./build.sh` detecta arch (`dist/robin-client-monitor.arm64`); Docker `linux/arm64`; `ARCH=arm64 ./deploy/pack-linux.sh`. PyInstaller no cruza: hay que compilar en el arch destino

### NFRs (§15)
- [x] TLS 1.2/1.3 + mTLS **obligatorio** si `allow_insecure_ws` es false — `colsoft_tools/tls_util.py` (piso TLS 1.2; fail-closed sin cert de cliente). Servidor: `python main.py` + `SSL_CERT_REQS=required` (el `1` de env también es REQUIRED). Sin `SSL_CA_CERTS` no arranca. Lab: [`produccion.md`](produccion.md)
- [x] Buffer offline ≥1 GiB / ≥24 h — `telemetry_buffer.py` (disco FIFO, `max_total_bytes` 1 GiB, `max_age_days` ≥1). Paquete y lab no ponen `max_events` (tope = bytes/edad)
- [x] Metadata cloud vía IMDSv2 (auto-tagging) — `cloud_metadata.py` (AWS IMDSv2, nunca v1; Azure/GCP si el link-local responde). Tags en `host` del envelope y OTLP `cloud.*` / `host.id`
- [x] CPU <2% / RAM <100 MB / boot <5 s (idle, monitores off) — medido 24 ago 2026 en CPython 3.11 Linux: import del cliente 3.7 s, RSS ~50 MB, CPU 0% (muestra 1 s). `health_check.resources` expone `rss_mb` / `cpu_percent`. No se midió el binario PyInstaller/MSI ni el agente con monitores on

### Cumplimiento (§18)
- [x] Trazabilidad ISO 27001 / CIS / SFC — [`cumplimiento.md`](cumplimiento.md)

---

## Orden sugerido de ataque

1. **§8.2/§8.5 Seguridad del canal** — mTLS + firma por comando + allowlist + auditoría + rate limit (✅ hecho)
2. **§8.6 Estados/cola/TTL** del comando (✅ hecho)
3. **Catálogos A, B, C y D** — diagnóstico de red (§8.4-A), recolección (§8.4-B), remediación (§8.4-C) y admin del agente (§8.4-D) (✅ hecho)
4. **RF-CORE**: enrollment, buffer, config manager, scheduler desacoplado (✅ hecho)
5. Data plane OTLP (§7.1 / RF-OBS-08) (✅ hecho)
6. Fases 2 (RF-OBS restante ✅) → 3 (RF-SEC ✅) → 4 Windows ✅ → 4 Linux ✅
7. Empaquetado (§16) (✅ hecho)
8. NFR §15 (TLS/mTLS, buffer 1 GiB, IMDSv2, idle CPU/RAM/boot) + cumplimiento §18
