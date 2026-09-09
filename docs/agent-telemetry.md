# Agent telemetry taxonomy

Cómo **este** servidor escribe a RobinLogs y cómo consultar esos eventos.

La guía genérica del SDK (RobinTools, tickets/SOC) no aplica aquí: no uses esa
taxonomía (`soporte`, `ticket_creado`, `alerta_escalamiento`) para filtrar logs
de agentes. Aquí las `category` son otras.

Para graficar (campos JSON, ejes, recetas): [`telemetry-json-rdo.md`](telemetry-json-rdo.md).

Código: `server/lib/metrics_logger.py` (`robin-logger>=0.3.0`).

---

## 1. Ingesta vs consulta

| Uso | Endpoint | Quién |
|---|---|---|
| Escribir | `POST /api/robin-logger/store` | Este servidor (`ROBIN_LOGGER_URL`) |
| Leer (upstream) | `GET https://logs.robin-ai.xyz/api/logs` | Operador / scripts |
| Leer (este server) | `GET /api/logs` | Proxy autenticado (`fetch_logs`) |

Si `ROBIN_LOGGER_URL` termina en `/api/logs`, el código la reescribe a `/store`
para ingesta. La consulta deriva `…/api/logs` de esa URL, o de
`ROBIN_LOGGER_QUERY_URL` si está definida.

Auth: API key (`ROBIN_LOGGER_API_KEY`) y/o JWT (`ROBIN_LOGGER_JWT` /
`ROBIN_LOGGER_JWT_TOKEN`). En 0.3.0, si hay JWT gana el JWT. Sin URL o sin
credenciales el logger es **no-op** (no rompe el plano de control).

`ROBIN_LOGGER_AGENT_ID` del `.env.example` es de scripts de sample de RobinTools;
**este servidor no lo usa**. El `agent_id` va dentro de `data`.

---

## 2. Dónde está el `agent_id`

El SDK manda `type` / `category` / `subcategory` / `level` / `data` / `timestamp`.
Este wrapper mete el id del agente en **`data.agent_id`**, no en el campo de
store `agentId`.

Al consultar (`GET /api/logs`):

- Filtros `type`, `category`, `subcategory`, `level` → `metadata.*` (sí aplican).
- `?agentId=` filtra el campo de store **`agentId`**, no `data.agent_id`.
  **No lo uses** para estos eventos; el resultado suele estar vacío o ser de otro productor.
- Negocio (tool, `message_id`, `issued_by`, métricas) → `metadata.data`.

---

## 3. Taxonomía

`level` solo admite `debug` | `info` | `warn` | `error` | `fatal`
(`warning` se normaliza a `warn`).

### 3.1 Ejecución de herramientas (REST / cola WS)

`log_tool_execution`: `type=audit`, `subcategory` = nombre interno de la tool.

| Familia | `category` | `subcategory` (ejemplos) |
|---|---|---|
| Diagnóstico de red | `network_check` | `ping`, `http_get`, `tcp_connect`, `dns_resolve`, `dns_lookup`, `traceroute`, `tls` |
| Observabilidad | `observability` | `system_metrics`, `process_list`, `service_status`, `network_connections`, `installed_software`, `disk_usage`, `file_hash`, `system_log`, `forensic_snapshot`, `collect_file`, `hardware_inventory`, `health_probes` |
| Windows (§12) | `windows` | `windows_event_log`, `windows_etw`, `windows_autoruns`, `windows_wmi`, `windows_scheduled_tasks` |
| Linux (§13) | `linux` | `linux_ebpf`, `linux_auditd`, `linux_syslog`, `linux_proc_metrics`, `linux_netlink`, `linux_systemd_units`, `linux_packages` |
| Remediación | `remediation` | `kill_process`, `start_service`, `stop_service`, `restart_service`, `block_ip`, `unblock_ip`, `isolate_host`, `restore_isolation`, `run_script` |
| Admin del agente | `agent_admin` | `update_config`, `trigger_update`, `restart_agent`, `health_check` |
| Seguridad (§11) | `security` | `fim_scan`, `persistence_scan`, `auth_audit`, `detection_scan`, `cis_score`, `cve_inventory`, `rootkit_check`, `dns_monitor`, `windows_sysmon`, `windows_defender`, `linux_lsm` |

`data` típico: `agent_id`, `message_id`, `tool`, `tool_family`, `target`,
`command_status`, `success`, `issued_by` (y `user_id` = mismo valor), `params`
(truncado), `duration_ms`, `error`, y **`result` compactado** (muestra de
`entries` / `providers` / `tasks` / `rows`; no el Event Log completo).

El comando SRS `get_system_log` se audita como subcategory `system_log` (nombre interno).

On-demand Windows también sale por OTLP como `telemetry.tool_result`
(`type=metrics`, `category=windows`, `subcategory=<tool>`). Lo mismo Linux
(`category=linux`) y `linux_lsm` / Sysmon / Defender (`category=security`).
El `command_response` por WS compacta Event Log **sin** `message`/`EventData`
(blobs); syslog/auditd sí conservan `message`/`type`/`exe`/`comm`.

### 3.2 Conexión del agente (WebSocket)

| `type` | `category` | `subcategory` | Cuándo |
|---|---|---|---|
| `activity` | `system` | `agent_connected` | Handshake OK |
| `activity` | `system` | `agent_disconnected` | WS cae (`level=warn`) |

### 3.3 `event_push` (plano de control)

Mapeo en `log_event_push` (`event.event_type` + `event.severity`):

| `event_type` del WS | `type` RobinLogs | `category` | `subcategory` |
|---|---|---|---|
| `security.*` (p.ej. `security.tamper_detected`, `security.detection`, `security.fim_change`) | `audit` | `security` (o `event.category`) | sufijo (`tamper_detected`, `detection`, `fim_change`, `auth`, `persistence_detected`, `dns_query`, `rootkit_heuristic`, `cis_finding`, `response_executed`, `response_blocked`) |
| `windows.autorun_change` / `windows.sysmon` / `windows.eventlog` high | `audit` | `security` | `autorun_change` / `sysmon` / `eventlog` |
| `windows.eventlog` low/info | `activity` | `windows` | `eventlog` |
| `linux.unit_change` / `linux.audit` high | `audit` | `security` | `unit_change` / `audit` |
| `linux.audit` / `linux.netlink` low/info | `activity` | `linux` | `audit` / `netlink` |
| `alert.threshold` / `alert.cleared` | `activity` | `observability` | `threshold` / `cleared` |
| `health.probe` | `activity` | `observability` | `probe` |
| `telemetry.tool_result` | `metrics` | familia de la tool (`windows` / `linux` / `security` / `observability`) | nombre de la tool |
| `telemetry.*` (otros) | `metrics` | `observability` | sufijo |
| otros | `activity` | `observability` | `event_type` o sufijo |

`event.severity` → `level`: `low`→`info`, `medium`/`warning`→`warn`,
`high`→`error`, `critical`→`fatal`.

### 3.4 Data plane OTLP (`server/otlp.py`)

Los lotes HTTPS `/v1/logs` y `/v1/metrics` se reenvían a RobinLogs. `telemetry.*`
va como `type=metrics`; `process.created` / `process.exited`, `alert.*` y
`health.probe` como `type=activity` (igual que el `event_push` equivalente).
`security.*` (FIM, detección, auth, persistencia, DNS, rootkit) va como
`type=audit`, `category=security`. El inventario `cve_inventory` /
`installed_software` / `linux_packages` se correlaciona en el backend (RF-SEC-05).
Las series de métricas OTLP van como `type=metrics`, `category=observability`,
`subcategory=otlp_metrics` (`data.points[]`: `name` + `value`). Nombres y
widgets: [`telemetry-json-rdo.md`](telemetry-json-rdo.md) §0.1. Un
`windows_event_log` (u otra tool §12) on-demand
va como `type=metrics`, `category=windows`, `subcategory=windows_event_log`
(el `result` va compactado: muestra de `entries`, no el XML completo). Una
tool §13 (`linux_auditd`, `linux_packages`, …) on-demand va igual con
`category=linux`. Un `linux.unit_change`, `linux.audit` high o
`windows.eventlog` high va como `type=audit`, `category=security` (igual que
el `event_push` equivalente); `linux.audit` / `linux.netlink` /
`windows.eventlog` info como `type=activity`. En OTLP los `linux.*` /
`windows.*` usan `subcategory` = sufijo del `event_type` (`audit`,
`eventlog`), igual que el `event_push`.

---

## 4. Consulta

El SDK `robin-logger` **solo hace POST**. Este servidor expone el mismo
contrato que RobinLogs `GET /api/logs` en **`GET /api/logs`** (proxy): mismos
query params (`date`, `startDate`/`endDate`, `page`, `limit`/`per_page`,
`type`, `category`, `subcategory`, `level`, `search`, `tags`, …). Auth de
esta API: JWT Robin si `ROBIN_JWT_REQUIRED=1`. Auth hacia RobinLogs:
`ROBIN_LOGGER_API_KEY` / `ROBIN_LOGGER_JWT` del `server/.env`.

`GET /api/execution-logs` es **otro** recurso: JSON locales en `results_logs/`.

Defaults upstream: últimos 30 días, `page=1`, `limit=50` (máx. 100000),
orden `timestamp` descendente. `date=YYYY-MM-DD` (UTC) ignora
`startDate`/`endDate` **salvo** que vengan `startHour`/`endHour`/`hour`: entonces
este proxy traduce a `startDate`/`endDate` ISO y no manda `date` (si no, RobinLogs
descartaría el rango de horas). `level=warning` se normaliza a `warn`. Alias SRS en
`subcategory` (`get_system_log` → `system_log`) se resuelven antes de filtrar.

```bash
# Vía este servidor (lab: JWT apagado)
curl -sS "http://127.0.0.1:8000/api/logs?category=remediation&limit=20"
curl -sS "http://127.0.0.1:8000/api/logs?date=2026-08-19&category=network_check&subcategory=ping"
curl -sS "http://127.0.0.1:8000/api/logs?date=2026-08-27&startHour=14&endHour=15&category=windows&subcategory=windows_event_log"
curl -sS "http://127.0.0.1:8000/api/logs?date=2026-08-27&startHour=14:00&endHour=15:00&category=linux&subcategory=linux_syslog"
curl -sS "http://127.0.0.1:8000/api/logs?category=linux&subcategory=linux_ebpf&limit=20"
curl -sS "http://127.0.0.1:8000/api/logs?type=activity&category=linux&subcategory=audit&limit=20"
# Producción (ROBIN_JWT_REQUIRED=1)
curl -sS "https://<host>/api/logs?category=system&subcategory=agent_connected&limit=20" \
  -H "Authorization: Bearer $ROBIN_ACCESS_TOKEN"
```

Consulta directa a RobinLogs (misma key que ingesta). Base: `https://logs.robin-ai.xyz`.

```bash
# Remediación (isolate, kill, block, …)
curl -sS "https://logs.robin-ai.xyz/api/logs?category=remediation&limit=20" \
  -H "X-API-Key: $ROBIN_LOGGER_API_KEY" \
  -H "Authorization: Bearer $ROBIN_LOGGER_API_KEY"

# Diagnóstico de red
curl -sS "https://logs.robin-ai.xyz/api/logs?category=network_check&subcategory=ping&limit=20" \
  -H "X-API-Key: $ROBIN_LOGGER_API_KEY" \
  -H "Authorization: Bearer $ROBIN_LOGGER_API_KEY"

# Admin del agente
curl -sS "https://logs.robin-ai.xyz/api/logs?category=agent_admin&limit=20" \
  -H "X-API-Key: $ROBIN_LOGGER_API_KEY" \
  -H "Authorization: Bearer $ROBIN_LOGGER_API_KEY"

# Conexiones / desconexiones
curl -sS "https://logs.robin-ai.xyz/api/logs?category=system&subcategory=agent_connected&limit=20" \
  -H "X-API-Key: $ROBIN_LOGGER_API_KEY" \
  -H "Authorization: Bearer $ROBIN_LOGGER_API_KEY"

# Tamper / detecciones por WS
curl -sS "https://logs.robin-ai.xyz/api/logs?type=audit&category=security&limit=20" \
  -H "X-API-Key: $ROBIN_LOGGER_API_KEY" \
  -H "Authorization: Bearer $ROBIN_LOGGER_API_KEY"

# FIM / reglas MITRE / auth
curl -sS "https://logs.robin-ai.xyz/api/logs?type=audit&category=security&subcategory=fim_change&limit=20" \
  -H "X-API-Key: $ROBIN_LOGGER_API_KEY"
curl -sS "https://logs.robin-ai.xyz/api/logs?category=security&subcategory=detection&limit=20" \
  -H "X-API-Key: $ROBIN_LOGGER_API_KEY"

# Linux §13 (tools on-demand vs eventos de monitor)
curl -sS "https://logs.robin-ai.xyz/api/logs?category=linux&subcategory=linux_ebpf&limit=20" \
  -H "X-API-Key: $ROBIN_LOGGER_API_KEY"
curl -sS "https://logs.robin-ai.xyz/api/logs?type=activity&category=linux&subcategory=audit&limit=20" \
  -H "X-API-Key: $ROBIN_LOGGER_API_KEY"
curl -sS "https://logs.robin-ai.xyz/api/logs?type=audit&category=security&subcategory=unit_change&limit=20" \
  -H "X-API-Key: $ROBIN_LOGGER_API_KEY"
```

En cada fila: `metadata.data.agent_id`, `metadata.data.tool`,
`metadata.data.issued_by`. No filtres con `?agentId=`.
