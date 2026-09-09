# Tool telemetry JSON for reports

Dos capas (no las mezcles):

1. **Ingesta** — qué llega a `POST /api/robin-logger/store` (este documento §0–§9).
2. **Widgets de reporte** — cómo el motor de charts lee esos logs (§0.1). Una
   línea temporal **no** recorre `result.cpu.load_avg_1`; lee
   `otlp_metrics` → `data.points[]` (`name` + `value`).

Código: `log_tool_execution` + OTLP `telemetry.tool_result` +
`events_to_otlp_metrics`. Catálogo: `colsoft_tools/tool_catalog.py`
(`ALLOWED_TOOLS`, 55 names).

**Fuera de las 55 tools** (otro `type` / `subcategory`; ver
[`agent-telemetry.md`](agent-telemetry.md) §3.2–3.4):
`agent_connected`, monitores (`linux.audit`, `alert.threshold`,
`security.fim_change`, `health.probe` → `subcategory=probe`,
`tamper_detected`, `process.created`, …). FIM on-demand = `fim_scan`;
auditd on-demand = `linux_auditd`.

Ingesta: `POST /api/robin-logger/store`. Consulta: `GET /api/logs`.
Agrupá hosts por **`metadata.data.agent_id`**. No uses `?agentId=`.

---

## 0. Cómo llega cada tool

| Camino | `type` | `category` | `subcategory` | Snapshot |
|---|---|---|---|---|
| Comando on-demand (REST / cola WS) | `audit` | familia | nombre interno | `metadata.data.result` |
| Scheduler o export OTLP | `metrics` | familia | nombre interno | `metadata.data.payload.result` (`data.otlp=true`) |

La misma tool on-demand de familias `windows` / `linux` / `security`
(Sysmon, Defender, LSM) **puede aparecer dos veces**: `audit` (respuesta WS)
y `metrics` (OTLP). El scheduler **solo** sale como `metrics`.
Para paneles de comandos usá `type=audit`. Para series periódicas,
`type=metrics` + `data.otlp=true`.

`category` = `tool_category(tool)`:
`network_check` | `observability` | `windows` | `linux` | `remediation` |
`agent_admin` | `security`.

Alias SRS (`get_system_log`, `http_check`, …): `subcategory` y `data.tool`
son el **nombre interno**. `data.command` **solo existe** si el alias ≠ tool.

`level`: `info` si `data.success=true`, `error` si falló.

`data.command_status` (minúsculas, status del WS): `success` | `error` |
`rejected` | `expired`. No llega `"SUCCESS"` ni `"UNKNOWN"`. `failed` se
normaliza a `error`.
`data.success` es **bool** JSON (`true`/`false`); para eje Y casteá a 0/1.

`result.status` de la tool: `OK` / `UP` / `DOWN` / `EMPTY` / `ERROR` /
`UNSUPPORTED`. En el SO incorrecto → `UNSUPPORTED`. Un ping DOWN o un
probe con `down>0` igual puede tener `command_status=success` (el comando
corrió; el hallazgo está en `result`).

Claves **omitidas** si no aplican (no llegan como `null`): `tenant_id`,
`command`, `duration_ms`, `error`, `issued_by`, `user_id`, `params`.

`params` es un **string** JSON (máx. 600 chars), no un objeto.

Listados muestreados (~12 ítems), excepto `packages` (hasta 200).
Usá `result.count`, no `len(array)`. Si `truncated: true` o `*_omitted`,
la muestra está recortada.

Floats no JSON: `"NaN"` / `"Infinity"` / `"-Infinity"` → descartalos.

### Envelope on-demand (`type=audit`)

```json
{
  "type": "audit",
  "category": "<familia>",
  "subcategory": "<tool interna>",
  "level": "info",
  "timestamp": "2026-08-24 15:43:01",
  "data": {
    "agent_id": "<uuid>",
    "tenant_id": "<si hay>",
    "message_id": "<id del comando>",
    "tool": "<tool interna>",
    "tool_family": "<familia>",
    "command_status": "success",
    "success": true,
    "duration_ms": 180,
    "issued_by": "user:alice",
    "user_id": "user:alice",
    "target": "texto corto",
    "params": "{\"host\":\"8.8.8.8\"}",
    "result_summary": "OK",
    "result": { "tool": "<tool interna>", "status": "OK" }
  }
}
```

OTLP (`type=metrics`): mismos campos de `result` en
`data.payload.result`. Extra en `data`: `event_type=telemetry.tool_result`,
`otlp=true`, `scheduled` (bool o ausente), `tool`, `payload.event_type`.

**Medidas comunes:** `data.success`, `data.duration_ms`. Abajo, las del
`result`.

Resolver el snapshot:

```
d = row.metadata.data
root = d.otlp ? (d.payload.result || d.payload) : d.result
```

Filtrá tools por `metadata.subcategory` (nombre interno). `http_check` /
`tcp_check` / `tls_check` se guardan como `http_get` / `tcp_connect` / `tls`.

### 0.1 Cómo graficar (widgets de reporte)

El listado de RobinLogs muestra `type` / `category` / `subcategory` (p.ej.
`metrics/observability/system_metrics`). Eso **no** implica que un widget
`line` sepa leer el JSON de la tool.

| Qué querés pintar | `subcategory` | `field` + `metric` | Snapshot |
|---|---|---|---|
| CPU, load, RAM, swap, disco, colas, IOPS, red (serie) | `otlp_metrics` | `field` y `metric` = `points[].name` | `data.points[]` (`name`, `value`, `unit`) |
| Conteos / comandos / detalle de tool | nombre interno (`system_metrics`, `ping`, …) | campo plano del `result` (`count`, `cpu.percent`, …) | §0 `root` — el motor **a menudo no** arma serie con paths anidados |
| Monitor `health.probe` | `probe` | p.ej. `message` + `count` | `type=activity`, `category=observability` |
| Tamper | `tamper_detected` | p.ej. `agent_id` + `count` | `type=audit`, `category=security` — **no** `type=security.tamper_detected` ni `subcategory=event_push` |

`health_probes` (tool, checks http/tcp) ≠ `probe` (evento `health.probe`) ≠
`health_check` (salud del proceso del agente, `category=agent_admin`).
En lab el loop de probes a veces sale `type=activity` +
`subcategory=health_probes`; filtrá lo que veas en el listado.

**Gauges OTLP** (`type=metrics`, `category=observability`,
`subcategory=otlp_metrics`). Código: `events_to_otlp_metrics`. Un log es un
lote de puntos, no una tool:

```json
{
  "type": "metrics",
  "category": "observability",
  "subcategory": "otlp_metrics",
  "data": {
    "agent_id": "PC_Remota_Test-934f08",
    "otlp": true,
    "points": [
      { "name": "system.cpu.utilization", "value": 12.4, "unit": "%" },
      { "name": "system.cpu.load_average.1m", "value": 0.31, "unit": "1" }
    ]
  }
}
```

| `points[].name` (`field` y `metric` del widget) | Origen | Aggregate | Notas / decisión |
|---|---|---|---|
| `system.cpu.utilization` | `cpu.percent` | `timeseries` | Saturación CPU. Mismo gauge que % Processor Time |
| `system.cpu.logical.count` | `cpu.logical_cores` | `timeseries` | Denominador: load > nCPU ⇒ cola de run |
| `system.cpu.load_average.1m` | `cpu.load_avg_1` | `timeseries` | Linux; Windows solo si `getloadavg` existe |
| `system.cpu.load_average.5m` | `cpu.load_avg_5` | `timeseries` | tendencia (no picos de 1 min) |
| `system.cpu.load_average.15m` | `cpu.load_avg_15` | `timeseries` | ídem |
| `system.processor.queue.length` | `cpu.processor_queue_length` | `timeseries` | Windows: `\System\Processor Queue Length` |
| `system.processor.system_queue.length` | `cpu.system_processor_queue_length` | `timeseries` | **el mismo** PDH (no hay otro contador) |
| `system.disk.queue.length` | `disk_io.queue_length` o `in_progress` | `timeseries` | Win: PhysicalDisk `_Total`; Linux: suma diskstats field 11 |
| `system.memory.utilization` | `memory.percent` | `timeseries` | presión RAM |
| `system.memory.usage` | `memory.used` | `timeseries` | bytes usados |
| `system.memory.available` | `memory.available` | `timeseries` | bytes libres (Linux MemAvailable) |
| `system.memory.available.mbytes` | `memory.available` / 1 MiB | `timeseries` | Available MBytes |
| `system.memory.swap.utilization` | `memory.swap_percent` | `timeseries` | >0 sostenido ⇒ RAM insuficiente |
| `system.memory.swap.usage` | `memory.swap_used` | `timeseries` | bytes en swap |
| `system.filesystem.utilization` | `disks[].percent` / `volumes[]` **max** | `timeseries` | disco lleno (no IOPS) |
| `system.uptime` | `uptime_seconds` o `uptime_s` | `timeseries` | caídas / reboot (reset a ~0) |
| `system.network.io.bytes_sent` | `network_io.bytes_sent` | **`rate`** | By/s salida |
| `system.network.io.bytes_recv` | `network_io.bytes_recv` | **`rate`** | By/s entrada |
| `system.network.packets.sent` | `packets_sent` / `tx_packets` | **`rate`** | pps salida |
| `system.network.packets.recv` | `packets_recv` / `rx_packets` | **`rate`** | pps entrada |
| `system.network.errors` | `errin`+`errout` / `rx_errors`+`tx_errors` | **`rate`** | NIC / medio / driver |
| `system.network.dropped` | `dropin`+`dropout` / `rx_dropped`+`tx_dropped` | **`rate`** | cola NIC llena o pressure |
| `system.network.connections` | `tcp_connections.tcp` | `timeseries` | sockets TCP (Linux `/proc/net/tcp{,6}`; Windows `net_connections`) |
| `system.network.connections.listen` | `tcp_connections.listen` | `timeseries` | puertos en LISTEN |
| `system.network.connections.established` | `tcp_connections.established` | `timeseries` | sesiones activas |
| `system.network.connections.time_wait` | `tcp_connections.time_wait` | `timeseries` | riesgo de agotar puertos efímeros |
| `system.network.connections.syn_recv` | `tcp_connections.syn_recv` | `timeseries` | backlog / SYN flood |
| `system.network.connections.syn_sent` | `tcp_connections.syn_sent` | `timeseries` | connects salientes no completados |
| `system.network.connections.close_wait` | `tcp_connections.close_wait` | `timeseries` | app que no cierra (leak) |
| `system.network.connections.udp` | `tcp_connections.udp` | `timeseries` | sockets UDP |
| `system.disk.operations.read` | `disk_io.read_count` / `reads` | **`rate`** | IOPS lectura (Linux y Windows) |
| `system.disk.operations.write` | `disk_io.write_count` / `writes` | **`rate`** | IOPS escritura |
| `system.disk.io.read` | bytes o sectores × 512 | **`rate`** | throughput lectura |
| `system.disk.io.write` | bytes o sectores × 512 | **`rate`** | throughput escritura |
| `health.probe.count` | `health_probes.count` | `timeseries` | checks configurados (scheduler) |
| `health.probe.down` | `health_probes.down` | `timeseries` | 0 = OK; >0 = servicio caído |
| `health.probe.response_time` | media `checks[].response_time` (solo UP) | `timeseries` | latencia del puerto/HTTP; no hay bytes por puerto |
| `health.probe.response_time.max` | max de esas latencias | `timeseries` | el check más lento |
| `system.systemd.units.failed` | `linux_systemd_units.failed` | `timeseries` | Linux; units `active=failed` |

No existe `system.cpu.load*` ni `cpu.load_avg_1` como `name` OTLP.
`cpu.load_avg_*` solo vive dentro del JSON de `system_metrics`.
No inventes `iops` ni `Available MBytes` como `name`: usá la tabla.
`health.probe.*` **no** sale del loop `health.probe` (ese es `subcategory=probe`
y solo emite al cambiar). Hace falta `health_probes` en el **scheduler**.
`system.systemd.units.failed` igual: `linux_systemd_units` en el scheduler.

En el **RDO de la plataforma** (reporte): `name` + `sections[].widgets[]`.
Cada widget de serie lleva `field` = `metric` = fila de arriba.
`widgets` en la raíz se ignora.

Widget de load (copiar 5m/15m cambiando el `name`):

```json
{
  "id": "load_avg_1",
  "type": "line",
  "title": "Load average 1 min",
  "size": "medium",
  "data_query": {
    "field": "system.cpu.load_average.1m",
    "metric": "system.cpu.load_average.1m",
    "aggregate": "timeseries",
    "group_by": "timestamp",
    "limit": 200,
    "filters": {
      "type": ["metrics"],
      "category": ["observability"],
      "subcategory": ["otlp_metrics"],
      "agent_id": ["PC_Remota_Test-934f08"]
    }
  },
  "chart_options": { "x_label": "Tiempo", "y_label": "Load 1 min" }
}
```

Schema del reporte (el backend rechaza o ignora lo demás):

- **`name`** es el título del RDO (texto visible, no un slug tipo `host_cpu`).
- Gráficos en **`sections`**: `{ "section_id", "title", "widgets": [...] }`.
- Omití claves vacías. **No** mandes `null` (`sort`, `preset`, `filter_rules`
  vacío como `null`, `analytics_options`, `created_at`, ni `data_query` en
  `ai_insight`). `schedule: null` sí se vio aceptado.
- No envíes `report_id` / `owner_id` / `created_at` al **crear**.
- `data_source.time_range`: `last_7d` (no `last_7_days`).
- `distinct_strategy`: `auto`. Host en **cada** widget: `"agent_id": ["…"]`
  (clave plana; no `"data.agent_id"`).
- Líneas de gauge: `aggregate=timeseries`, `group_by=timestamp`.
  Contadores (red, IOPS): `aggregate=rate`.
- `size`: `medium` / `large` / `full`. Theme de lab: `midnight`.
- `ai_insight`: solo `id`, `type`, `title`, `size`.
- No pongas `category: ["observability"]` en `data_source` si el reporte
  también trae `security` / `linux`: el filtro global las oculta.

### 0.2 Tablero de servidor (qué graficar para decidir)

El scheduler mínimo para series host es `system_metrics`. Para disponibilidad
de servicios y systemd, añadí `health_probes` y (Linux) `linux_systemd_units`.

**Capacidad / saturación (¿hay que crecer o el host está mal?)**

| Pregunta | Widgets (`field` = `metric`) | Cómo leerlo |
|---|---|---|
| CPU saturada | `system.cpu.utilization` + load 1/5/15 + `system.cpu.logical.count` | Load 15m > nCPU de forma sostenida ⇒ más núcleos o menos trabajo. Pico de % con load baja ⇒ un proceso bursty |
| Windows: ¿hilos esperando CPU? | `system.processor.queue.length` | Cola > 0–2 por núcleo de forma sostenida ⇒ CPU bound (no dupliques con `system.processor.system_queue.length`: es el mismo PDH) |
| RAM | `system.memory.utilization` + `system.memory.available` + `system.memory.swap.utilization` | Swap % subiendo con available bajo ⇒ falta RAM, no “el disco es lento” |
| Filesystem lleno | `system.filesystem.utilization` | Umbral típico 80/90 %. Es el **max** de volúmenes, no IOPS |

**Disco (¿latencia o espacio?)**

| Pregunta | Widgets | Cómo leerlo |
|---|---|---|
| IOPS | `system.disk.operations.read` / `.write` con `rate` | Sube IOPS y cola ⇒ saturación de disco |
| Throughput | `system.disk.io.read` / `.write` con `rate` | MB/s; útil junto a IOPS (I/O grande vs chico) |
| Cola de disco | `system.disk.queue.length` | Cola alta + IOPS alto = disco lento o RAID saturado |

**Red (¿el servidor no responde o la red?)**

| Pregunta | Widgets | Cómo leerlo |
|---|---|---|
| Ancho de banda | `system.network.io.bytes_*` `rate` | Techo de NIC / backup / DDoS |
| Paquetes | `system.network.packets.*` `rate` | pps alto con bytes bajos ⇒ floods / lots of small pkts |
| Errores / drops | `system.network.errors` y `.dropped` `rate` | Cualquier tasa > 0 sostenida ⇒ NIC, cable, buffer, o pressure |
| Puertos en escucha | `system.network.connections.listen` | Sube de golpe ⇒ servicio nuevo o bind inesperado |
| Concurrencia TCP | `system.network.connections.established` | Techo del servicio / keep-alive |
| TIME_WAIT | `system.network.connections.time_wait` | Alto sostenido ⇒ agotamiento de puertos |
| SYN backlog | `system.network.connections.syn_recv` | Pico ⇒ flood o accept lento |
| CLOSE_WAIT | `system.network.connections.close_wait` | Sube ⇒ leak de sockets en la app |
| UDP | `system.network.connections.udp` | DNS/NTP/quic; mismo contrato Linux/Windows |
| Puerto del servicio vivo | `health.probe.down` + `health.probe.response_time` | UP/DOWN y latencia del check TCP/HTTP (no hay By/s por puerto) |

**Disponibilidad (¿está caído el servicio o el host?)**

| Pregunta | Widget / filtro | Cómo leerlo |
|---|---|---|
| Host reinició | `system.uptime` | Escalón a ~0 = reboot |
| Check HTTP/TCP/proceso | `health.probe.down` (`otlp_metrics`) | Serie periódica si `health_probes` está en el scheduler |
| Cambio UP↔DOWN | `subcategory=probe` (no OTLP) | Eventos, no serie densa |
| systemd failed | `system.systemd.units.failed` | Linux; 0 = OK |
| Agente vivo | `agent_connected` / `health_check` | No mezclar con `observability` en el filtro global del RDO |
| Tamper | `tamper_detected` | `category=security` — otro reporte o sin filtro de category |

No grafiques en el mismo RDO `otlp_metrics` **y** `cpu.percent` sobre
`system_metrics`: el motor de charts lee `points[].name`, no el JSON anidado.

---

## 1. Índice (55 tools)

| Familia (`category`) | `subcategory` (filtro) |
|---|---|
| `network_check` | `ping`, `http_get`, `tcp_connect`, `dns_resolve`, `tls`, `traceroute`, `dns_lookup` |
| `observability` | `system_metrics`, `process_list`, `service_status`, `network_connections`, `installed_software`, `disk_usage`, `file_hash`, `system_log`, `forensic_snapshot`, `collect_file`, `hardware_inventory`, `health_probes` |
| `windows` | `windows_event_log`, `windows_etw`, `windows_autoruns`, `windows_wmi`, `windows_scheduled_tasks` |
| `linux` | `linux_ebpf`, `linux_auditd`, `linux_syslog`, `linux_proc_metrics`, `linux_netlink`, `linux_systemd_units`, `linux_packages` |
| `security` | `fim_scan`, `persistence_scan`, `auth_audit`, `detection_scan`, `cis_score`, `cve_inventory`, `rootkit_check`, `dns_monitor`, `windows_sysmon`, `windows_defender`, `linux_lsm` |
| `remediation` | `kill_process`, `start_service`, `stop_service`, `restart_service`, `block_ip`, `unblock_ip`, `isolate_host`, `restore_isolation`, `run_script` |
| `agent_admin` | `update_config`, `trigger_update`, `restart_agent`, `health_check` |

Consulta: `GET /api/logs?type=audit&category=<familia>&subcategory=<tool>`
(comandos). Series del scheduler: añadí `type=metrics`.

---

## 2. `network_check`

| Tool | `result.tool` | Medidas | Otros campos de `result` |
|---|---|---|---|
| `ping` | `ping` | `data.duration_ms`. **No hay RTT ICMP.** `result.success` (bool) | `host`, `status` (`UP`/`DOWN`, lo pisa el agente), `output` (texto), `error` |
| `http_get` | `http_get` | `response_time` (s), `status_code` | `url`, `status` (`UP`/`DOWN`) |
| `tcp_connect` | `tcp_connect` | `response_time` (s) | `host`, `port`, `status` (`UP`/`DOWN`) |
| `dns_resolve` | `dns_resolve` | `len` vía éxito; IPs no son Y | `target`, `host`, `status` (`OK`/`EMPTY`/`ERROR`), `ips[]` |
| `tls` | `tls` | `handshake_time` (s) | `host`, `port`, `not_before`, `not_after`, `subject`, `issuer`, `subject_alt_name` |
| `traceroute` | `traceroute` | `hops[].rtt1` (si viene); conteo `len(hops)` **no fiable** si hay `hops_omitted` | `target`, `max_hops`, `status`, `hops[]` (`hop`,`host`,`ip`,`rtt1`…), `output` |
| `dns_lookup` | `dns_lookup` | conteo de `answers` (muestra) | `hostname`, `record_type`, `answers[]`, `output` |

```json
{
  "type": "audit",
  "category": "network_check",
  "subcategory": "http_get",
  "data": {
    "agent_id": "agt-1",
    "tool": "http_get",
    "success": true,
    "duration_ms": 210,
    "target": "url=https://example.com",
    "result": {
      "tool": "http_get",
      "url": "https://example.com",
      "status": "UP",
      "status_code": 200,
      "response_time": 0.21
    }
  }
}
```

---

## 3. `observability`

| Tool | Medidas | `result` (claves) |
|---|---|---|
| `system_metrics` | `cpu.percent`, `cpu.logical_cores`, `memory.*`, `uptime_seconds`, `tcp_connections` (`tcp`/`listen`/`established`/`time_wait`/`syn_recv`/`syn_sent`/`close_wait`/`udp`). Linux y Windows: `network_io` totales (sin loopback) + `interfaces[]`. Linux: load, `disks[]` volúmenes, `disk_io` dict de totales (diskstats sumados) + `filesystem_percent_max`. Windows: colas PDH, `disk_io` dict + IOPS psutil. IOPS/red en OTLP con `rate` | `tool`, `status`, `hostname`, `os`, `cpu`, `memory`, `disks`, `disk_io`, `network_io`, `tcp_connections`, `uptime_seconds`, `filesystem_percent_max`, `source` |
| `linux_proc_metrics` | ver §5: **no mezclar** con `system_metrics` | — |
| `process_list` | `count`; `processes[].cpu_percent` / `memory_percent` (Windows). En Linux esos % van `null` | `truncated`, `processes[]` (`pid`,`ppid`,`name`,`username`,`status`,`create_time`,`cmdline`). Linux: `source=/proc`; `status` en vocabulario psutil (`running`/`sleeping`/`zombie`…) y `status_code` con la letra de `/proc` |
| `service_status` | `count` (listado). Puntual: no hay % | Puntual: `service_name`, `unit`, `active_state`, `sub_state`. Linux: `load_state`, `enabled`. Windows: `raw_state`. Listado Linux: `services[]` con `unit`,`load`,`active`,`sub`,`active_state`,`sub_state`. Listado Windows: `service_name`,`unit`,`active_state`,`sub_state`,`active`,`sub` (**sin** `load`) |
| `network_connections` | `count` (muestra ≤300), `tcp_connections.*` (conteo **completo**) | `truncated`, `connections[]` (`laddr`,`raddr`,`status`, pid). Linux: `/proc/net` TCP+UDP IPv4/IPv6. Windows: `psutil.net_connections(inet)` |
| `installed_software` | `count`, `hashed` | `package_manager`, `packages[]` (`name`,`version`,`sha256`…). Linux: `native_tool=linux_packages` (mismo payload que esa tool) |
| `disk_usage` | `disks[].percent` | `disks[]` (`device`,`mountpoint`,`fstype`,`total`,`used`,`free`,`percent`) |
| `file_hash` | `size_bytes` | `path`, `algorithm`, `hash`, `modified_at` |
| `system_log` | `count` | `source`, `schema_version`, `entries[]` (`ts`,`level`,`source`,`message`,`pid`,`host`,`event_id`), `truncated` |
| `forensic_snapshot` | no hay un solo Y; sub-bloques compactados | `started_at`, `completed_at`, `processes`, `network_connections`, `system_metrics`, `recent_logs`, `persistence`, `windows`, `linux` |
| `collect_file` | `size_bytes`, `content_bytes` | `path`, `sha256`, `truncated`, `modified_at`. `content_b64` **casi seguro truncado/omitido** por el tope ~8 KB |
| `hardware_inventory` | `cpu.logical_cores`, `cpu.physical_cores`, `cpu.freq.max_mhz` / `current_mhz`, `memory.total` | `hostname`, `os`, `os_version`, `arch`, `cpu` (`model`, `logical_cores`, `physical_cores`, `freq`), `disks[]`, `nics[]`, `firmware`. Linux: `source=/proc+/sys`. Windows: CPU vía CIM `Win32_Processor` (modelo, núcleos, `MaxClockSpeed`) |
| `health_probes` | `count`, `down`, `response_time` (media UP), `response_time_max`; `checks[].response_time` | `status` (`OK` si `down=0` else `DOWN`), `checks[]` (`id`,`type`,`status` UP/DOWN) |

Los gauges OTLP (`subcategory=otlp_metrics`) salen si el scheduler corrió
`system_metrics` (host), `health_probes` (`health.probe.*`) o
`linux_systemd_units` (`system.systemd.units.failed`).
`linux_proc_metrics` también exporta host (`uptime_s`, `net[]`, `volumes[]`).
**Para series en el reporte usá §0.1** (`points[]`), no `field: cpu.load_avg_1`
sobre `system_metrics`.

```json
{
  "type": "audit",
  "category": "observability",
  "subcategory": "system_metrics",
  "data": {
    "agent_id": "agt-1",
    "tool": "system_metrics",
    "success": true,
    "result": {
      "tool": "system_metrics",
      "status": "OK",
      "cpu": { "percent": 12.4, "load_avg_1": 0.31, "load_avg_5": 0.4, "load_avg_15": 0.38 },
      "memory": { "percent": 41.2, "total": 16000000000, "used": 6600000000, "available": 9400000000 },
      "uptime_seconds": 86400.1,
      "source": "/proc+/sys",
      "disks": [{ "mountpoint": "/", "percent": 67.0 }],
      "disk_io": {
        "read_count": 100,
        "write_count": 40,
        "read_bytes": 409600,
        "write_bytes": 102400,
        "queue_length": 2
      },
      "filesystem_percent_max": 67.0,
      "network_io": {
        "bytes_sent": 2000,
        "bytes_recv": 1000,
        "interfaces": [{ "iface": "eth0", "bytes_sent": 2000, "bytes_recv": 1000, "tx_bytes": 2000, "rx_bytes": 1000 }]
      }
    }
  }
}
```

---

## 4. `windows` (on-demand; `UNSUPPORTED` fuera de Windows)

| Tool | Medidas | `result` |
|---|---|---|
| `windows_event_log` | `count` | `channel`, `known_channels`, `entries[]` (muestra: `ts`,`level`,`provider`,`event_id`,`channel`,`computer`,`record_id`,`message` recortado, `data` slim) |
| `windows_etw` | `provider_count` (total logman; **no hay `count`**) | `providers[]` (muestra), `of_interest[]`, `note` |
| `windows_autoruns` | `count` | `kinds` (mapa kind→n), `items[]` |
| `windows_wmi` | `count` | `class_name`, `namespace`, `rows[]`, `allowlist` |
| `windows_scheduled_tasks` | `count` | `truncated`, `tasks[]` (`task_name`,`next_run`,`status`) |

Sysmon y Defender van en **`category=security`** (§6).

---

## 5. `linux` (on-demand; `UNSUPPORTED` fuera de Linux)

| Tool | Medidas | `result` |
|---|---|---|
| `linux_ebpf` | `count` (= `program_count`) | `btf`, `bpffs`, `tracing`, `unprivileged_bpf_disabled`, `programs[]`, `of_interest[]` (`id`,`present`) |
| `linux_auditd` | `count`, `rule_count` | `auditd` (bool servicio), `log_path`, `rules[]`, `entries[]` (`type`,`pid`,`exe`,`comm`,`syscall`,`success`) |
| `linux_syslog` | `count` | igual que `system_log` + `files` (lista `/var/log`) + `cross_tool=system_log` |
| `linux_proc_metrics` | `cpu.percent`, `cpu.logical_cores`, `memory.percent`, `memory.used`, **`uptime_s`** (no `uptime_seconds`), `volumes[].percent`, `disks[].reads`/`writes`/`in_progress`, `net[]` (bytes/packets/errors/drops), `tcp_connections` | `cpu.load_avg_1/5/15`, `memory.swap_*`, `source=/proc+/sys` |
| `linux_netlink` | `count` (ifaces) | `via`, `interfaces[]`, `stats[]`, `sockets[]` |
| `linux_systemd_units` | `count` (units listadas, tope 400), `failed` (`active=failed`) | `units[]`, `timers[]`, `enabled[]` (`unit`, `state`, `preset` de `list-unit-files`; `load`/`active`/`sub` si la unit está en `units[]`) |
| `linux_packages` | `count`, `hashed` | `package_manager` (`dpkg`/`rpm`), `packages[]`, `cross_tool=installed_software` (mismo payload, otra `subcategory`) |

No mezcles series `linux_proc_metrics` y `system_metrics`: mismo host, nombres
distintos (`uptime_s` vs `uptime_seconds`; `volumes` vs `disks`; `net` vs
`network_io`).

```json
{
  "type": "audit",
  "category": "linux",
  "subcategory": "linux_proc_metrics",
  "data": {
    "agent_id": "agt-1",
    "tool": "linux_proc_metrics",
    "result": {
      "tool": "linux_proc_metrics",
      "status": "OK",
      "cpu": { "percent": 12.4, "logical_cores": 8, "load_avg_1": 0.31 },
      "memory": { "percent": 41.2 },
      "uptime_s": 86400.1,
      "source": "/proc+/sys"
    }
  }
}
```

---

## 6. `security` (tools on-demand)

| Tool | Medidas | `result` |
|---|---|---|
| `fim_scan` | `count` | `files[]` (`path`,`sha256`,`mtime`,`uid`,`user`,`exists`, `process` opcional) |
| `persistence_scan` | `count` | `os`, `kinds`, `items[]` |
| `auth_audit` | `count` | `events[]` (logon/sudo/…) |
| `detection_scan` | `count` | `detections[]`, `rules[]` (`id`,`mitre_technique`,`severity`) |
| `cis_score` | **`score`** (0–100), `passed`, `total` | `os`, `benchmark`, `checks[]` |
| `cve_inventory` | `count` | `os`, `os_version`, `package_manager`, `packages[]`. La correlación CVE **no** es esta tool; el server puede emitir otro log `subcategory=cve_match` (`count`,`score`,`matches`) |
| `rootkit_check` | `count` (findings), `proc_pids`, `psutil_pids` | `findings[]` |
| `dns_monitor` | `count` | `queries[]`. Desde sockets `:53`: `resolver`, `port`, `pid`, `process` (**no siempre `domain`**). Caché resolvectl/DnsClientCache: suele traer `domain` |
| `windows_sysmon` | `count` | `installed`, `service`, `optional`, `entries[]` |
| `windows_defender` | bools 0/1: `antivirus_enabled`, `am_service_enabled`, `realtime` | `coexist`, `disables_defender=false`, `details` |
| `linux_lsm` | `active` (bool) | `selinux` (`mode`,`present`,`denials[]`), `apparmor` (`mode`,`profiles[]`,`denials[]`) |

---

## 7. `remediation`

| Tool | Medidas | `result` |
|---|---|---|
| `kill_process` | `len(killed)` | `killed[]` (PIDs int), `os`, `errors[]` |
| `start_service` / `stop_service` / `restart_service` | — | `action`, `service_name`, `returncode`, `active_state`, `sub_state`, `os`, `backend` |
| `block_ip` / `unblock_ip` | — | `os`, `backend`, `action`, `direction`, `ip`, `rule` (string) y `rules[]` |
| `isolate_host` | `restore_after_s` | `os`, `backend`, `reason`, `manager_host`, `rules[]`, `expires_at` (ISO UTC del fin del aislamiento; `null`/ausente si no hay duración) |
| `restore_isolation` | `restored` (bool) | |
| `run_script` | `returncode`, `duration_ms` (también en envelope) | `script_path`, `args`, `stdout` (puede truncarse), `stderr` |

`result.tool` en servicios = `start_service` / `stop_service` / `restart_service`.
En firewall = `block_ip` / `unblock_ip`.

---

## 8. `agent_admin`

| Tool | Medidas | `result` |
|---|---|---|
| `update_config` | `len(applied)` | `applied[]`, `removed[]`, `backup`, `config_file`, `note` |
| `trigger_update` | `returncode` | output truncado; o campos del updater firmado |
| `restart_agent` | `delay` (s) | `pid`, `message`. La marca `_agent_restart` **no llega** a RobinLogs (el agente la quita antes de responder) |
| `health_check` | **`uptime_s`**, `pid` | `version`, `ppid`, `start_time`, `python_version`, `executable`, `cwd`, `argv`, `config_file`, `config_valid`, `config_mtime`, `tamper`, `control_channel`, `resources` (`rss_mb`, `cpu_percent`), `cloud` |

`health_check` (salud del **agente**) ≠ `health_probes` (checks tcp/http/process).

```json
{
  "type": "audit",
  "category": "agent_admin",
  "subcategory": "health_check",
  "data": {
    "agent_id": "agt-1",
    "tool": "health_check",
    "success": true,
    "result": {
      "tool": "health_check",
      "status": "OK",
      "version": "0.9.0",
      "pid": 1234,
      "uptime_s": 3600.5,
      "config_valid": true
    }
  }
}
```

---

## 9. Compactación (lo que **no** va entero)

`compact_logger_data` (~8 KB). Arrays en
`processes`, `connections`, `entries`, `packages` (tope **200**), `units`,
`timers`, `hops`, `checks`, `disks`, `files`, `items`, `detections`,
`queries`, `findings`, `providers`, `tasks`, `rows`, `programs`, `sockets`,
`services`, `answers`, `applied`, `of_interest`, `volumes`, `net`, `stats`,
`interfaces`, `rules`, `denials`, `events`, … → muestra + `{key}_omitted`.

El scheduler compacta con la receta OTLP (muestra ~12), no la del WebSocket
(~3). Los gauges de host no dependen de esas muestras: `network_io` y
`disk_io` llevan **totales** en el dict; `filesystem_percent_max` es un
escalar (el volumen más lleno).

**Excepción:** `data.points[]` de `otlp_metrics` **no** se recorta (el widget
necesita cada `name`). Tope 200; solo entonces `points_omitted`.

Si el blob sigue grande: `truncated: true` y puede quedar solo
`status`/`count`/`error`. Entonces **no hay medidas dentro de `result`**.

`collect_file.content_b64` y `ping.output` / `run_script.stdout` no son
graficables.

---

## 10. Lo que este RDO no lista como *tool*

No son tools del catálogo (otro JSON; filtros en
[`agent-telemetry.md`](agent-telemetry.md) §3.3–3.4):

- `agent_connected` / `agent_disconnected` (`category=system`)
- monitores: `linux.audit`, `linux.netlink`, `linux.unit_change`,
  `windows.eventlog`, `windows.sysmon`, `windows.autorun_change`,
  `fim_change`, `detection`, `threshold` / `cleared`, `probe`,
  `tamper_detected`, `process.created`, …
- gauges `otlp_metrics`: **sí se grafican**; el contrato está en §0.1
  (no hay tool `otlp_metrics`)
