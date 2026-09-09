# Producción — JWT, mTLS y plano de control

Checklist para un despliegue que no sea lab. Detalle de env: [`.env.example`](../.env.example).
Implementación JWT: `server/lib/jwt_auth.py`.
Config del agente: [`README_CONFIG.md`](../README_CONFIG.md).

**Despliegue en Robin** (ingress `:8444`, enrollment, conexión de agentes, inventario
multi-usuario): [`robin-plataforma-agentes.md`](robin-plataforma-agentes.md).

El default del repo (`ROBIN_JWT_REQUIRED=0`, `allow_insecure_ws` en el config de
lab) es para desarrollo. En producción hay que **cambiarlo**.

Arranque del servidor: **`python main.py`** (Docker CMD). `uvicorn main:app`
**no** lee `SSL_*` y deja el socket en HTTP.

---

## 1. JWT de Robin en la API REST

Rutas `/api/*` (ejecutar comandos, listar cola, consultar RobinLogs en
`GET /api/logs`, etc.). El WebSocket del agente
**no** usa este JWT: se autentica con desafío RSA + (en prod) mTLS.

| Variable | Lab | Producción |
|---|---|---|
| `ROBIN_JWT_REQUIRED` | `0` | **`1`** |
| `ROBIN_API_URL` | `https://back.ruvic.xyz/api` | mismo, u host de staging |
| `ROBIN_JWT_ISSUER` | vacío (no se valida `iss`) | **el mismo `JWT_ISSUER` / `APP_URL` de Robin** |

Con `=1`, un `POST /api/agents/{id}/execute` sin `Authorization: Bearer <jwt>`
responde 401. `issued_by` del comando queda `user:<sub>`.

Sin JWT (`=0`), `issued_by` es `api:user`.

**RBAC:** el claim `roles` autoriza `POST /api/agents/{id}/execute`:

- `ROBIN_JWT_EXECUTE_ROLES` (default `admin,operator,analyst,soc,gestor`) — cualquier comando del catálogo habilitado.
- `ROBIN_JWT_HIGH_RISK_ROLES` (default `admin,soc,operator`) — Alto/Crítico (`kill_process`, `isolate_host`, `run_script`, …).

Sin esos roles → **403**. Consultas GET siguen exigiendo solo un JWT válido cuando `ROBIN_JWT_REQUIRED=1`. Con `=0` (lab) no hay JWT ni RBAC.

**`jti`:** se acepta si viene; no se consulta la blacklist de logout de Robin
(la guía JWT §6: un validador externo no ve esa lista). Basta firma + `exp`.

JWKS (`.well-known/jwks.json`) no está implementado; se usa
`GET …/auth/public-key` con cache 1 h.

**Inventario (tablas `users` y `agents`):** el dueño no sale del WebSocket.
El server hace `GET https://logs.robin-ai.xyz/api/logs` (misma auth que
RobinLogs: `ROBIN_LOGGER_API_KEY` / JWT) y toma `userId` / `agentId` del
documento. El GET de logs no trae email ni nombre. El
host va en `agents`: OS, versión, arch, CPU, RAM total GB, disco, firmware.
Esa ficha se pide **en cada conexión** (`hardware_inventory` +
`health_check`) y se **actualiza** el mismo `agent_id` (no se duplica).
Si cambia la RAM u otro dato estático, el registro se refresca. Enroll (si hay Bearer) y `POST …/execute`
adjuntan el dueño. `GET /api/agents` lista el inventario filtrado por
cliente/usuario del **JWT** (`sub` / `modelBotId`, o `/auth/me`). Requiere
`MYSQL_HOST`; sin él el inventario no se guarda.
ORM: SQLAlchemy (`User` / `Agent` en `server/lib/agent_store.py`), driver `pymysql`.

---

## 2. mTLS y WebSocket

SRS §8.2 / §15: TLS 1.2+ y mTLS obligatorio en producción.

El agente **exige** certificado de cliente si `allow_insecure_ws` es `false`
(`colsoft_tools/tls_util.py`, piso `TLSv1_2`). El servidor, con
`SSL_CA_CERTS` y `SSL_CERT_REQS=required`, rechaza el handshake sin cert de
cliente. Sin CA **no arranca** (no degrada a `CERT_NONE`).

Lab: `allow_insecure_ws: true` (puede ser `ws://` o WSS sin mTLS, p.ej. ngrok).
TLS de servidor sin mTLS: `SSL_CERT_REQS=none` (sigue haciendo falta
`SSL_CERTFILE` / `SSL_KEYFILE`).

`SSL_CERT_REQS=1` (string) es **REQUIRED** en `python main.py`. No uses
`uvicorn --ssl-cert-reqs 1` (en stdlib ese 1 es OPTIONAL).

### Enrollment con el puerto ya en mTLS

`POST /api/enroll` no puede presentar un cert de cliente que aún no existe.
Opciones:

1. **PKI offline** (producción): `scripts/enroll.py` emite PEMs y se copian a
   `enrollment/` del host. No toca el socket de control.
2. **Bootstrap loopback**: con TLS, `python main.py` abre
   `127.0.0.1:8001` (`ENROLLMENT_BOOTSTRAP_PORT`, `ENROLLMENT_BOOTSTRAP_HOST`)
   solo con `/health`, `/enroll` y `/api/enroll`, **sin** mTLS. El 8000 sigue
   en CERT_REQUIRED. Para enrolar desde otra máquina hay que publicar 8001 con
   firewall o usar (1). Desactivar: `ENROLLMENT_BOOTSTRAP_PORT=0`.
3. Re-enroll: `--enroll-cert` / `--enroll-key` contra el 8000.

HTTPS de enroll debe pinnear la CA: `--enroll-ca` / `ROBIN_ENROLL_CA` o
`enrollment/certs/ca.crt`. `--enroll-insecure` solo baja el WS a `ws://` (lab).

Cabeceras `X-Forwarded-*` **no** se usan salvo `ENROLLMENT_TRUST_FORWARDED=1`
(proxy de confianza + `ENROLLMENT_PUBLIC_HOST` / `ENROLLMENT_WS_URL`).

### Servidor (`server/.env`)

```bash
SSL_CERTFILE=/ruta/certs/server/server.crt
SSL_KEYFILE=/ruta/certs/server/server.key
SSL_CA_CERTS=/ruta/certs/server/ca.crt
SSL_CERT_REQS=required   # o 2 o 1 — CERT_REQUIRED. none/0 = TLS sin mTLS (lab)
SERVER_SIGNING_KEY=/ruta/certs/server/signing.key
# ENROLLMENT_BOOTSTRAP_PORT=8001   # default si hay SSL_CERTFILE
# ENROLLMENT_BOOTSTRAP_HOST=127.0.0.1
# ENROLLMENT_TRUST_FORWARDED=0
```

`SSL_CERT_REQS=none` es lab (TLS sin cert de cliente).

### Agente (`config_client.json`)

```json
"websocket_url": "wss://agentes.ejemplo.com:8000/ws/colsoft-tools",
"allow_insecure_ws": false,
"require_command_signature": true,
"signing_public_key": "-----BEGIN PUBLIC KEY-----\n…Ed25519 del backend…\n-----END PUBLIC KEY-----\n",
"tls_ca_cert": "/opt/robin-client-monitor/certs/ca.crt",
"tls_client_cert": "/opt/robin-client-monitor/certs/client.crt",
"tls_client_key": "/opt/robin-client-monitor/certs/client.key"
```

Identidad y certs salen del enrollment (`--enroll` / `POST /api/enroll`), no a
mano. `allow_insecure_ws: true` + `ws://` solo en lab.

---

## 3. RobinLogs

```bash
ROBIN_LOGGER_URL=https://logs.robin-ai.xyz/api/robin-logger/store
ROBIN_LOGGER_API_KEY=rk_...
# o ROBIN_LOGGER_JWT=eyJ...   (gana sobre API key en 0.3.0)
```

Sin esto el control plane funciona; no hay auditoría central. Consulta:
[`agent-telemetry.md`](agent-telemetry.md).

---

## 4. Lista corta antes de salir a prod

- [ ] `ROBIN_JWT_REQUIRED=1` y `ROBIN_JWT_ISSUER` definido
- [ ] `wss://` + `allow_insecure_ws: false`
- [ ] Arranque con `python main.py` (o imagen Docker); **no** `uvicorn main:app`
- [ ] `SSL_CERT_REQS=required` + `SSL_CA_CERTS` y cada agente con `tls_client_cert` / `tls_client_key`
- [ ] Enrollment: `scripts/enroll.py` o bootstrap 8001; `--enroll-ca` en HTTPS
- [ ] `require_command_signature: true` + `signing_public_key` del enrollment
- [ ] `SERVER_SIGNING_KEY` persistente (sin archivo no se despachan comandos; no hay llave efímera)
- [ ] `ALLOW_HIGH_RISK_COMMANDS` solo lo necesario (vacío = alto/crítico off)
- [ ] Política local del agente: `allow_high_risk` acorde al host
- [ ] `ROBIN_LOGGER_URL` + credenciales
- [ ] `data_plane` hacia HTTPS (no `http://` salvo collector interno)
