# Conector Ruvic Sentinel (`ruvic_sentinel`)

Cliente HTTP **solo REST** para el plano de control de Ruvic Sentinel.
No instala `robin-client-monitor` ni abre WebSockets: eso lo hace el agente
en el host. El LLM de OpenHands usa `ruvic_sentinel_connector` con variables
`RUVIC_SENTINEL_*`.

## Entregables

| Archivo | Rol |
|---|---|
| `manifest.json` | Formulario Settings → Conectores (`library`, `auth_modes`, `env_prefix`, `icon`) |
| `lib/ruvic_sentinel_connector/` | Paquete pip (`SentinelClient`) |
| `SKILL.md` | Manual del LLM (`name: ruvic-sentinel`) |
| `test_connection.py` | Botón «Probar conexión» (`GET /api/agents`) |
| `docs/assets/icon.svg` | Icono del catálogo |

## Instalación de la librería

```bash
pip install git+https://github.com/YersusZ/Ruvic-Sentinel.git#subdirectory=lib

# Desarrollo local
pip install -e ./lib
export RUVIC_SENTINEL_BASE_URL=https://sentinel.ejemplo.com
export RUVIC_SENTINEL_TOKEN=eyJ…
python test_connection.py
```

**Python:** ≥ 3.10 · **HTTP:** `httpx>=0.27,<1.0`

## Variables de entorno (runtime)

| Variable | Contenido |
|----------|-----------|
| `RUVIC_SENTINEL_BASE_URL` | Origen HTTPS del control (sin `/` final). No uses `127.0.0.1` en producción. |
| `RUVIC_SENTINEL_TOKEN` | JWT Robin (Bearer) para `/api/*`. No es el token `enr_…`. |
| `RUVIC_SENTINEL_TIMEOUT` | Timeout HTTP en segundos (default `30`) |
| `RUVIC_SENTINEL_VERIFY_TLS` | `true` / `false` (default `true`) |

## Permisos del JWT

El Bearer debe poder:

- `GET /api/agents` y `GET /api/agents/{id}`
- `POST /api/agents/{id}/execute` (roles `ROBIN_JWT_EXECUTE_ROLES`; remediación exige roles altos)
- `POST /api/enrollment-tokens` (claim `sub` identificable)

## Integración en OpenHands

```bash
# Empaquetar solo los entregables del conector (no todo el repo del agente)
python -m scripts.integrate_connector conector-ruvic_sentinel.zip --copy-lib --force
```

Tras integrar: Settings → Conectores → **Ruvic Sentinel**. Cierra sesión y vuelve a
entrar si el catálogo no aparece. El runtime instala la librería con
`library.install` del manifest (hace falta que `lib/` esté publicado en GitHub).

## Capacidades

```python
from ruvic_sentinel_connector import SentinelClient, setup_logging

setup_logging("INFO")
with SentinelClient() as client:
    client.list_agents()
    client.execute("agt_xxxxxxxx", "health_check", params={})
    client.create_enrollment_token()
```

Si el agente está offline, `execute` puede devolver `queued=true` (HTTP 202).
Consulta luego `client.get_command(agent_id, result["id"])`.
