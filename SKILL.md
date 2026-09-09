---
name: ruvic-sentinel
description: >
  Usa ruvic_sentinel_connector para hablar con el plano de control de Ruvic Sentinel:
  listar agentes de endpoint (robin-client-monitor), ejecutar tools firmadas
  (health_check, system_metrics, ping, …) y emitir tokens de enrollment enr_….
  Actívalo cuando el usuario pida agentes Sentinel, hosts enrolados, comandos
  al endpoint o inventario de robin-client-monitor.
triggers:
- sentinel
- ruvic sentinel
- ruvic_sentinel
- robin-client-monitor
- agente endpoint
- enrollment
- health_check
---

# Conector Ruvic Sentinel (`ruvic_sentinel_connector`)

Cliente HTTP **solo REST** contra el plano de control. No instala el binario
`robin-client-monitor` ni abre WebSockets: eso lo hace el agente en el host.

La librería está **preinstalada en el runtime** cuando el conector `ruvic_sentinel`
está configurado. Si no:

```bash
pip install git+https://github.com/YersusZ/Ruvic-Sentinel.git#subdirectory=lib
```

Menciona el id del conector (`ruvic_sentinel`) al hablar de Settings.

## Regla crítica de credenciales

El código generado **NUNCA hardcodea** URL ni JWT. Siempre lee:

| Variable | Contenido |
|----------|-----------|
| `RUVIC_SENTINEL_BASE_URL` | Origen HTTPS del control (sin `/` final) |
| `RUVIC_SENTINEL_TOKEN` | JWT Robin (Bearer) |
| `RUVIC_SENTINEL_TIMEOUT` | (opcional) timeout HTTP en segundos, default 30 |
| `RUVIC_SENTINEL_VERIFY_TLS` | (opcional) `true`/`false`, default `true` |

Si no existen, el conector no está configurado: no generes código que lo use;
indica al usuario que lo configure en **Settings → Conectores**.

El código generado **NUNCA** usa nombres con segmento de alias (`_DEFAULT_`,
`_PRODUCCION_`, etc.) salvo que aparezcan en la sección autogenerada al final
de este skill.

## Autenticación / conexión (siempre igual)

```python
from ruvic_sentinel_connector import SentinelClient, setup_logging

setup_logging("INFO")
client = SentinelClient()  # lee RUVIC_SENTINEL_* del entorno
health = client.health()
print(health["status"], health.get("agents"))
```

## Capacidad 1 — Listar agentes

```python
agents = client.list_agents()
for row in agents:
    print(row["agent_id"], row.get("hostname"), row.get("online"))
```

## Capacidad 2 — Ficha de un agente

```python
detail = client.get_agent("agt_xxxxxxxx")
print(detail.get("os_name"), detail.get("last_seen"), detail.get("online"))
```

## Capacidad 3 — Ejecutar una tool

```python
result = client.execute(
    "agt_xxxxxxxx",
    "health_check",
    params={},
)
print(result.get("ok"), result.get("queued"), result.get("result") or result.get("error"))
```

Si el agente está offline, `queued` puede ser `true` (HTTP 202): consulta luego
con `client.get_command(agent_id, result["id"])`. `GET /health` no exige JWT;
con mTLS en el puerto de control puede fallar aunque el JWT sea válido — usa
`list_agents()` como prueba real de credenciales.

Otras tools habituales (el nombre interno va en `tool`): `system_metrics`,
`process_list`, `ping` (`params={"target": "8.8.8.8", "count": 3}`),
`hardware_inventory`. Remediación (`isolate_host`, `kill_process`, …) exige
roles JWT altos.

## Capacidad 4 — Token de enrollment

```python
minted = client.create_enrollment_token()
print(minted.get("token"), minted.get("expires_at"))
```

Ese `token` (`enr_…`) es de **un solo uso** para el CLI del host
(`robin-client-monitor --enroll …`). No lo sustituyas por el JWT.

## Manejo de errores

```python
from ruvic_sentinel_connector import (
    SentinelAuthError,
    SentinelDataError,
    SentinelNetworkError,
)

try:
    client.list_agents()
except SentinelAuthError:
    print("JWT inválido o sin permiso — revisa Settings → Conectores")
except SentinelNetworkError:
    print("No se alcanzó el plano de control — revisa BASE_URL / TLS / red")
except SentinelDataError as exc:
    print(f"Error de datos: {exc}")
```

## Buenas prácticas al generar código

1. Lee credenciales SOLO de `RUVIC_SENTINEL_*` (`SentinelClient()` ya lo hace).
2. Nunca imprimas `RUVIC_SENTINEL_TOKEN` ni tokens `enr_…` completos.
3. No importes `colsoft_tools`, `server` ni el binario del agente en el sandbox.
4. Cierra el cliente si abres varios: `with SentinelClient() as client:`.
5. Timeouts: el HTTP del conector es `RUVIC_SENTINEL_TIMEOUT`; el de la tool
   en el host es el argumento `timeout` de `execute`.
