# `config_client.json` — referencia de configuración del agente

El agente lee este archivo al **arrancar** (y al aplicar `update_config`). Queda
junto al binario (`robin-client-monitor`) o en la raíz del repo en modo Python.
Si existe `enrollment/identity.json`, sus campos de identidad/certs pisan los
de este JSON; **scheduler, linux.*, windows.*, alerts y data_plane siguen
viniendo de aquí**.

Mapa del producto y docs: [`README.md`](README.md), [`docs/README.md`](docs/README.md).

Mapa del producto y docs: [`README.md`](README.md), [`docs/README.md`](docs/README.md).
Producción (JWT, mTLS, `wss://`): [`docs/produccion.md`](docs/produccion.md).

Tras cambiar el JSON hay que **reiniciar el proceso**. Claves desconocidas se
rechazan (esquema en `colsoft_tools/config_manager.py`). `_docs`, `_comment` y
`_version` se ignoran (solo documentación embebida).

| Tipo en esquema | JSON |
|---|---|
| `str` | string |
| `bool` | `true` / `false` |
| `num` | número |
| `list` | array |
| `dict` | objeto |

Claves **protegidas** (no se pueden cambiar por comando remoto): `private_key`,
`public_key`, `signing_public_key`, `require_command_signature`,
`allow_insecure_ws`, `tls_*`, `websocket_url`, `data_plane`, `policy`,
`scripts_catalog`.

No commitees llaves reales. El enrollment (`--enroll`) rellena identidad y
certs; este archivo cubre el resto.

---

## Identidad y conexión

### `client_name` (str)

Nombre del host/agente. Va como query param del WebSocket (`?client_name=`).
Si `agent_id` está vacío, el server fabrica un id de sesión
`{client_name}-{sufijo}`.

```json
"client_name": "PC_Remota_Test"
```

### `agent_id` (str)

Identidad **estable** entre reconexiones (cola de comandos §8.6). Vacío = id
por sesión (cambia cada vez que conectás). Lo rellena el enrollment.

```json
"agent_id": "agt_pc-remota_a1b2c3"
```

### `tenant_id` (str)

Tenant en toda telemetría (heartbeat, `event_push`, OTLP, comandos) y en el WS.

```json
"tenant_id": "tenant_acme"
```

### `websocket_url` (str)

URL del plano de control. Producción: `wss://`. Lab: `ws://` solo con
`allow_insecure_ws: true`.

```json
"websocket_url": "wss://agentes.ejemplo.com:8000/ws/colsoft-tools"
```

### `private_key` / `public_key` (str)

PEM RSA del agente. Firma el desafío `auth_challenge` del handshake. Las genera
el enrollment, no a mano.

```json
"private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
"public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
```

### `signing_public_key` (str)

PEM Ed25519 **del backend**. Si está presente, todo `command_request` debe
venir firmado (fail-closed). Vacío = no se exige firma.

```json
"signing_public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
```

### `require_command_signature` (bool)

Siempre se verifica la firma Ed25519 del `command_request` (§8.2). El valor
`false` se ignora (queda log de aviso). Enrollment y paquete: `true`.

```json
"require_command_signature": true
```

### `allow_insecure_ws` (bool)

`true` solo para lab: permite `ws://` **y** WSS/HTTPS sin certificado de
cliente. En producción: `false` + `wss://` + mTLS (el agente no arranca el
canal si faltan `tls_client_cert` / `tls_client_key`).

```json
"allow_insecure_ws": true
```

### `tls_ca_cert` / `tls_client_cert` / `tls_client_key` (str)

Rutas a archivos PEM para `wss://`:

- `tls_ca_cert`: CA de confianza (fijación de CA). Vacío = tienda del sistema + certifi.
- `tls_client_cert` + `tls_client_key`: mTLS (certificado de cliente).

```json
"tls_ca_cert": "/opt/robin-client-monitor/certs/ca.crt",
"tls_client_cert": "/opt/robin-client-monitor/certs/client.crt",
"tls_client_key": "/opt/robin-client-monitor/certs/client.key"
```

### `heartbeat_interval` (num)

Segundos entre heartbeats WS. El código aplica un mínimo de **5 s**.

```json
"heartbeat_interval": 7
```

---

## Política, auditoría y rate limit

### `policy` (dict)

Doble candado local (§8.2 / §8.5).

| Campo | Tipo | Qué hace |
|---|---|---|
| `allowed_commands` | list[str] | Allowlist. `[]` = catálogo SRS habilitado por defecto (bajo/medio, sin servicios ni Alto/Crítico). Lista no vacía = **solo** esos nombres. Comandos desconocidos se rechazan. |
| `allow_high_risk` | bool | Necesario **y** el comando listado en `allowed_commands` para Alto/Crítico. **No** desbloquea `start/stop/restart_service`: esos son Medio-Alto y solo exigen estar en `allowed_commands`. |

```json
"policy": {
  "allowed_commands": ["system_metrics", "health_probes", "restart_service"],
  "allow_high_risk": true
}
```

### `scripts_catalog` (dict)

Catálogo de `run_script`. Cada id es `{path, sha256, signature}` (Ed25519 con
la misma llave que los comandos). Un path suelto se rechaza.

```json
"scripts_catalog": {
  "cleanup_tmp": {
    "path": "/opt/robin-client-monitor/scripts/cleanup_tmp.sh",
    "sha256": "<hex>",
    "signature": "<base64 ed25519 de script_id + basename + sha256>"
  }
}
```

### `audit_log_path` (str)

JSONL de auditoría con cadena de hashes. Vacío o ausente =
`results_logs/agent_audit.jsonl` (relativo al cwd / APP_DIR).

```json
"audit_log_path": "results_logs/agent_audit.jsonl"
```

### `max_command_rate` (num)

Comandos por minuto (rate limit local). Default **20**.

```json
"max_command_rate": 20
```

### `max_chars` (num)

Tope de caracteres para stdout/stderr de tools (comandos WS, scheduler y
`trigger_update`). Vacío = 60000 (mismo default que `--max-chars`).

```json
"max_chars": 60000
```

---

## Scheduler periódico (`scheduler`)

Programador genérico (RF-CORE-07). Corre **fuera** del hilo WS. El resultado va
al buffer/OTLP como `telemetry.tool_result`.

Hace falta **tools no vacío** y (`interval_seconds` > 0 **o** `run_once: true`).
Lista vacía / `{}` = apagado.

No sustituye a `process_watch` / `alerts` / `health_probes`: esto dispara tools
del catálogo; aquellos emiten eventos (create/exit, umbrales, probes).

```json
"scheduler": {
  "interval_seconds": 60,
  "tools": [
    { "tool": "system_metrics", "params": { "cpu_interval": 0.2 }, "timeout": 15 },
    { "tool": "disk_usage" },
    "health_check"
  ]
}
```

Una sola pasada al arrancar (inventario estático); no espera el intervalo:

```json
"scheduler": {
  "run_once": true,
  "tools": [
    { "tool": "hardware_inventory" },
    { "tool": "installed_software" }
  ]
}
```

Alias deprecados (siguen funcionando): `scheduler.interval_minutes` (×60),
top-level `minute_interval` (×60) y `tools_execution_interval`. Si existen
`interval_seconds` y `interval_minutes`, gana `interval_seconds`. Si existen
`scheduler` y los alias top-level, gana `scheduler`.

---

## Buffer, tamper, auto-update, data plane

### `telemetry_buffer` (dict)

Buffer en disco (JSONL) si no hay red. OTLP o el WS lo drenan al reconectar.
El disco es la fuente de verdad: no se carga 1 GiB en RAM.

| Campo | Default | Qué hace |
|---|---|---|
| `dir` | (interno) | Carpeta del JSONL |
| `max_events` | 0 (sin tope) | Tope opcional de eventos; 0 = solo bytes/edad |
| `max_age_days` | 7.0 | Retención (≥24 h del NFR §15) |
| `max_file_bytes` | 8388608 | Rotación por archivo (~8 MiB) |
| `max_total_bytes` | 1073741824 | Tope total (≥1 GiB del NFR §15) |

```json
"telemetry_buffer": {
  "max_age_days": 7.0,
  "max_file_bytes": 8388608,
  "max_total_bytes": 1073741824
}
```

### `tamper` (dict)

Baseline SHA-256 de binario/config/certs. Si cambian, evento
`security.tamper_detected`.

| Campo | Qué hace |
|---|---|
| `baseline_file` | Ruta del baseline (opcional) |
| `allow_rebaseline` | `true` = regenera baseline al arrancar tras un tamper |

```json
"tamper": { "allow_rebaseline": true }
```

### `cloud` (dict)

Auto-tag de instancia (SRS §15). AWS IMDSv2 (nunca v1); si el link-local
responde, Azure IMDS o GCP. Timeout corto; fuera de la nube no bloquea.

| Campo | Default | Qué hace |
|---|---|---|
| `enabled` / `imds` | true | `false` desactiva la consulta |
| `timeout_seconds` | 0.4 | Tope por probe (máx. 2 s) |

```json
"cloud": { "imds": true, "timeout_seconds": 0.4 }
```

### `auto_update` (dict)

Usado por el comando `trigger_update`.

| Campo | Qué hace |
|---|---|
| `script` / `command` | Instalador local (recibe version/url/channel) |
| `timeout` | 5–300 s |
| `verify_public_key` | Ed25519 del editor; con esto el update es fail-closed (firma + rollback) |
| `url` | Descarga del binario (si hay `verify_public_key`) |
| `target` | Ruta del binario a reemplazar |
| `verify_command` | Post-check; si falla, rollback |

```json
"auto_update": {
  "verify_public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
  "url": "https://updates.ejemplo.com/robin-client-monitor",
  "target": "/opt/robin-client-monitor/robin-client-monitor",
  "timeout": 120
}
```

Vacío `{}` = `trigger_update` no tiene mecanismo configurado.

### `data_plane` (dict)

OTLP/HTTP (RF-OBS-08). El WS queda para control + `event_push` de alta
prioridad. Métricas y volumen salen por `POST /v1/logs` (y `/v1/metrics`).

| Campo | Default | Qué hace |
|---|---|---|
| `enabled` | true si hay URL | `false` = telemetría por WS |
| `endpoint` | derivado de `websocket_url` | Base (`https://host:8000`) o URL `/v1/logs`. Lab/collector local: `http://127.0.0.1:4318` **exige** `insecure: true` en este JSON (no se activa por `update_config`). Producción: `https://` |
| `compression` | `"gzip"` | `"gzip"` o `"none"` |
| `batch_size` | 32 | Eventos por lote |
| `batch_interval_seconds` | 5 | Flush periódico |
| `timeout_seconds` | 15 | Timeout HTTP |
| `insecure` | hereda `allow_insecure_ws` | Permite `http://` (solo JSON local / lab) |

```json
"data_plane": {
  "enabled": true,
  "compression": "gzip",
  "batch_size": 32,
  "batch_interval_seconds": 5
}
```

---

## Observabilidad en segundo plano

Se leen **solo al arrancar**. Vacío / `enabled: false` / `checks: []` / `rules: []`
= ese monitor no corre. En el log del agente tiene que aparecer
`process_watch activo` / `service_watch activo` / `health_probes activo` / `alerts activo`.

### `process_watch` (dict)

Eventos `process.created` / `process.exited` (no un dump). Primer tick =
baseline (no emite). Poll: procesos más cortos que `interval_seconds` pueden
perderse. Salen por **OTLP** (`[OTLP] ... process.created`), no por `event_push`.

| Campo | Default | Qué hace |
|---|---|---|
| `enabled` | false | Hay que ponerlo en `true` |
| `interval_seconds` | 5 | Cadencia del diff |
| `max_events_per_tick` | 40 | Tope por ciclo (anti fork-bomb) |

```json
"process_watch": {
  "enabled": true,
  "interval_seconds": 5,
  "max_events_per_tick": 40
}
```

Prueba: con el agente corriendo, `sleep 12`.

### `service_watch` (dict)

RF-OBS-03. Eventos `service.changed` (`change`: `added` / `removed` / `state`).
Primer tick = baseline. Poll de `sc query` / `systemctl` / `launchctl`, no
WMI push. Salen por **OTLP**, no por `event_push`.

En Linux, `linux.systemd.enabled` cubre **todas** las unidades (incl. timers)
vía `linux.unit_change`. Este watcher es el equivalente Windows/macOS y, si
ambos están on, los `.service` pueden duplicarse.

| Campo | Default | Qué hace |
|---|---|---|
| `enabled` | false | Hay que ponerlo en `true` |
| `interval_seconds` | 30 | Cadencia del diff |
| `max_events_per_tick` | 40 | Tope por ciclo |

```json
"service_watch": {
  "enabled": true,
  "interval_seconds": 30,
  "max_events_per_tick": 40
}
```

### `health_probes` (dict)

Checks periódicos. Distinto de `health_check` (salud del **agente**).
Emite `health.probe` por WS (`event_push`) al **cambiar** de estado (y la
primera observación). Máximo 32 checks.

| Campo | Default | Qué hace |
|---|---|---|
| `enabled` | true si hay `checks` | `false` apaga el loop aunque haya checks |
| `interval_seconds` | 60 | Cadencia |
| `emit_always` | false | `true` = un evento cada ciclo, no solo al cambiar |
| `checks` | `[]` | Lista vacía = loop apagado |

Cada check:

| `type` | Campos | Ejemplo |
|---|---|---|
| `tcp` (alias `port`) | `host` (o `target`), `port`, `timeout` | SSH local |
| `http` | **`url`** (o `target`), `timeout`, `verify` (default true; `false` / `insecure: true` = no verificar TLS) | Health HTTP. Si no hay `url`, se arma `http://{host}:{port}{path}` |
| `process` | `name` (o `process`, substring) | ¿Está el proceso? |

```json
"health_probes": {
  "enabled": true,
  "interval_seconds": 60,
  "checks": [
    { "id": "ssh", "type": "tcp", "host": "127.0.0.1", "port": 22, "timeout": 3 },
    { "id": "api", "type": "http", "url": "http://127.0.0.1:8000/health", "timeout": 5 },
    { "id": "agent", "type": "process", "name": "robin-client-monitor" }
  ]
}
```

También se puede disparar on-demand: comando `health_probes` /
`run_health_probes` con `params.checks`. Si no mandás `checks`, usa esta lista.

### `alerts` (dict)

Umbrales locales sobre `system_metrics`. Eventos WS `alert.threshold` /
`alert.cleared`. `rules: []` o `{}` = apagado. `enabled: false` apaga el
loop aunque haya reglas (igual que `health_probes.enabled`).

| Campo | Default | Qué hace |
|---|---|---|
| `enabled` | true si hay `rules` | `false` apaga el loop aunque haya reglas |
| `interval_seconds` | 30 | Cada cuánto mide |
| `cooldown_seconds` | 300 | Silencio entre repeats de la misma regla en firing |
| `rules` | `[]` | Lista de umbrales |

Cada regla:

| Campo | Qué hace |
|---|---|
| `id` | Identificador (`high_cpu`) |
| `metric` | `cpu.percent`, `memory.percent`, `memory.used`, `disks.percent.max`, `network_io.bytes_sent` / `bytes_recv` |
| `op` | `gt`, `gte`, `lt`, `lte`, `eq` |
| `threshold` | Número |
| `severity` | `warning` (default), `error`, `info`, … → log del server |

```json
"alerts": {
  "enabled": true,
  "interval_seconds": 30,
  "cooldown_seconds": 300,
  "rules": [
    { "id": "high_cpu", "metric": "cpu.percent", "op": "gt", "threshold": 90, "severity": "warning" },
    { "id": "disk_full", "metric": "disks.percent.max", "op": "gte", "threshold": 95, "severity": "error" }
  ]
}
```

Lab: `"threshold": 1` dispara enseguida. Volvé a 90 en producción.

---

## Seguridad en segundo plano (§11)

Se leen **solo al arrancar**. Cada subclave con `enabled: false` (o ausente) =
ese monitor no corre. Las tools on-demand (`fim_scan`, `persistence_scan`,
`auth_audit`, `detection_scan`, `cis_score`, `cve_inventory`, `rootkit_check`,
`dns_monitor`) funcionan igual con el monitor apagado.

Las detecciones `security.*` salen por **`event_push`** (RF-SEC-09) **y** se
bufferizan hacia OTLP: «no esperan» significa baja latencia por WS, no que
el batch las excluya.

### `security` (dict)

| Subclave | Default | Qué hace |
|---|---|---|
| `fim` | off | RF-SEC-01 FIM (SHA-256 + usuario + proceso). `paths` vacío = rutas CIS típicas (`/etc/passwd`, sshd, …) |
| `persistence` | off | RF-SEC-02 cron/timers/authorized_keys (Linux) o Run/services/tasks (Windows) |
| `auth_audit` | off | RF-SEC-03 logon/logoff, fallos, sudo/su. `max_entries` |
| `detection` | off | RF-SEC-04 reglas (PowerShell -enc, `curl\|sh`, exec desde /tmp) + MITRE. `cooldown_seconds` |
| `dns` | off | RF-SEC-07 consultas DNS (dominio y/o resolver :53) + proceso |
| `rootkit` | off | RF-SEC-08 discrepancias /proc vs psutil, módulos, SUID en tmp |
| `cis` | off | RF-SEC-06 score CIS subset. `min_score` (default 70) dispara `security.cis_finding` |
| `cve_inventory` | off | RF-SEC-05 insumo periódico; el cruce CVE es en el backend |
| `auto_response` | off | RF-SEC-10. `actions`: `[{ "rule_id": "SEC-002", "command": "kill_process" }]`. Sujeto a `policy` §8.5 |

```json
"security": {
  "fim": { "enabled": true, "interval_seconds": 60, "paths": ["/etc/passwd", "/etc/ssh/sshd_config"] },
  "persistence": { "enabled": true, "interval_seconds": 120 },
  "auth_audit": { "enabled": true, "interval_seconds": 30, "max_entries": 80 },
  "detection": { "enabled": true, "interval_seconds": 5, "cooldown_seconds": 300 },
  "dns": { "enabled": true, "interval_seconds": 15 },
  "rootkit": { "enabled": true, "interval_seconds": 300 },
  "cis": { "enabled": false, "interval_seconds": 3600, "min_score": 70 },
  "cve_inventory": { "enabled": false, "interval_seconds": 86400 },
  "auto_response": {
    "enabled": false,
    "actions": [
      { "rule_id": "SEC-001", "command": "kill_process" },
      { "rule_id": "SEC-002", "command": "kill_process" }
    ]
  }
}
```

`auto_response.enabled: true` **no** bypasea la política: `kill_process` /
`isolate_host` / `block_ip` siguen deshabilitados por defecto. Hay que
`allow_high_risk` + allowlist igual que un comando remoto.

El backend correlaciona CVE con `POST /api/cve/correlate` y
`GET /api/agents/{id}/vulnerabilities` (catálogo local; `CVE_CATALOG_PATH`
opcional). El agente solo manda inventario.

---

## Windows (RF-WIN-01..08)

Bloque `windows`. Monitores **off** por defecto; solo arrancan en Windows.
Tools on-demand (`windows_event_log`, `windows_etw` = inventario `logman` **no**
sesión ETL, `windows_autoruns`, `windows_wmi`, `windows_scheduled_tasks`,
`windows_sysmon`, `windows_defender`) responden `UNSUPPORTED` en Linux/macOS.

| Subclave | Default | Qué hace |
|---|---|---|
| `event_log` | off | RF-WIN-02 poll wevtutil XML (canales ETW-backed; **no** es sesión ETW live / RF-WIN-01). `channels` (System, Application, Security, Setup, ForwardedEvents, PowerShell, Defender, IIS). `ignore_event_ids` (default `[4104]`; `[]` lo vuelve a emitir). Eventos `windows.eventlog` |
| `autoruns` | off | RF-WIN-03 diff Run/RunOnce/Startup. Eventos `windows.autorun_change` (event_push) |
| `sysmon` | off | RF-WIN-06. Si Sysmon no está instalado, idle. Eventos `windows.sysmon` |

```json
"windows": {
  "event_log": {
    "enabled": false,
    "interval_seconds": 30,
    "max_events_per_tick": 40,
    "ignore_event_ids": [4104],
    "channels": [
      "System",
      "Application",
      "Security",
      "Setup",
      "ForwardedEvents",
      "Microsoft-Windows-PowerShell/Operational",
      "Microsoft-Windows-Windows Defender/Operational",
      "Microsoft-IIS-Configuration/Operational"
    ]
  },
  "autoruns": { "enabled": false, "interval_seconds": 300 },
  "sysmon": { "enabled": false, "interval_seconds": 30 }
}
```

WMI: `windows_wmi` con `class_name` de allowlist (`Win32_OperatingSystem`,
`Win32_Service`, …). Defender es solo lectura (RF-WIN-07). Servicio:
NSSM + `sc failure` (RF-WIN-08). MSI / Inno / firma: [`docs/empaquetado.md`](docs/empaquetado.md).

---

## Linux (RF-LIN-01..08)

Bloque `linux`. Monitores **off** por defecto; solo arrancan en Linux.
Tools on-demand (`linux_ebpf`, `linux_auditd`, `linux_syslog`,
`linux_proc_metrics`, `linux_netlink`, `linux_systemd_units`, `linux_lsm`,
`linux_packages`) responden `UNSUPPORTED` en Windows/macOS.

| Subclave | Default | Qué hace |
|---|---|---|
| `auditd` | off | RF-LIN-02 poll audit.log / ausearch. Eventos `linux.audit` (high también WS) |
| `systemd` | off | RF-LIN-06 diff de unidades/timers (y `active`/`sub`). Primer tick = baseline (no emite). Eventos `linux.unit_change` (event_push) |
| `netlink` | off | RF-LIN-05 **poll** de `/sys/class/net` y `/proc/net/tcp` (no suscripción AF_NETLINK). Ifaces → WS; sockets TCP nuevos → OTLP. Tool on-demand: un dump RTNETLINK |

```json
"linux": {
  "auditd": { "enabled": false, "interval_seconds": 30, "max_events_per_tick": 40 },
  "systemd": { "enabled": false, "interval_seconds": 300 },
  "netlink": { "enabled": false, "interval_seconds": 15 }
}
```

eBPF es inventario de programas/tracepoints (`bpftool` + tracefs), no attach
live. Métricas `linux_proc_metrics` leen `/proc` y `/sys` sin psutil.
`linux_lsm` reporta SELinux/AppArmor aunque estén off. Inventario dpkg/rpm
con hash: `linux_packages` o `installed_software` con `include_hash`.
`linux_syslog` acepta los mismos nombres de Event Viewer (`system`,
`application`, `security`, `setup`, `forwarded`) y `bundle: true` los lee
juntos. `system` = journald; `application` = syslog/messages; `security` =
auth.log/secure; `setup` = dpkg/apt/yum/dnf; `forwarded` = journal remoto
o `/var/log/remote`.

---

## Ejemplo mínimo de lab

```json
{
  "client_name": "PC_Lab",
  "tenant_id": "",
  "agent_id": "",
  "websocket_url": "ws://localhost:8000/ws/colsoft-tools",
  "allow_insecure_ws": true,
  "require_command_signature": true,
  "signing_public_key": "",
  "private_key": "(PEM RSA)",
  "public_key": "(PEM RSA)",
  "heartbeat_interval": 7,
  "_comment": "LAB: inseguro a propósito. Enrollment de prod: firma, wss, allow_high_risk false.",
  "policy": { "allowed_commands": [], "allow_high_risk": false },
  "scripts_catalog": {},
  "audit_log_path": "",
  "max_command_rate": 20,
  "auto_update": {},
  "telemetry_buffer": { "max_age_days": 7.0, "max_file_bytes": 8388608, "max_total_bytes": 1073741824 },
  "tamper": { "allow_rebaseline": true },
  "scheduler": {},
  "data_plane": { "enabled": true, "compression": "gzip", "batch_size": 32, "batch_interval_seconds": 5 },
  "process_watch": { "enabled": false, "interval_seconds": 5, "max_events_per_tick": 40 },
  "service_watch": { "enabled": false, "interval_seconds": 30, "max_events_per_tick": 40 },
  "health_probes": { "interval_seconds": 60, "checks": [] },
  "alerts": { "interval_seconds": 30, "cooldown_seconds": 300, "rules": [] },
  "security": { "fim": { "enabled": false }, "detection": { "enabled": false }, "auto_response": { "enabled": false } },
  "windows": { "event_log": { "enabled": false }, "autoruns": { "enabled": false }, "sysmon": { "enabled": false } },
  "linux": { "auditd": { "enabled": false }, "systemd": { "enabled": false }, "netlink": { "enabled": false } }
}
```

TLS/certs vacíos se omiten o van `""`.

---

## Dónde se ve cada cosa

| Config | Log del agente al arrancar | Server |
|---|---|---|
| `scheduler.tools` vacío / `scheduler: {}` | `Ejecución periódica no configurada` | — |
| `process_watch.enabled: true` | `process_watch activo cada Ns` | `[OTLP] ... process.created` (solo si hay create/exit) |
| `service_watch.enabled: true` | `service_watch activo` | `[OTLP] ... service.changed` |
| `health_probes.checks` no vacío | `health_probes activo` | `event_push ... health.probe` |
| `alerts.rules` no vacío | `alerts activo` | `event_push ... alert.threshold` |
| `security.detection.enabled` | `detection activo` | `event_push ... security.detection` |
| `security.fim.enabled` | `fim activo` | `event_push ... security.fim_change` |
| `windows.event_log.enabled` | `windows event_log activo` | `windows.eventlog` (OTLP; high/critical también WS) |
| `windows.autoruns.enabled` | `windows autoruns activo` | `event_push ... windows.autorun_change` |
| `windows.sysmon.enabled` | `windows sysmon activo` | `event_push ... windows.sysmon` |
| `linux.auditd.enabled` | `linux auditd activo` | `linux.audit` (OTLP; high también WS) |
| `linux.systemd.enabled` | `linux systemd activo` | `event_push ... linux.unit_change` |
| `linux.netlink.enabled` | `linux netlink activo` | `linux.netlink` (OTLP; iface up/down también WS) |

Guía de instalación del binario: `README_CLIENT.md`.
