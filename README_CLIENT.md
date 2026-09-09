# Robin Client Monitor - Guia para cliente final (solo ejecutable)

Este documento esta pensado para quien recibe un binario ya compilado y necesita:

- Ejecutarlo manualmente.
- Dejarlo corriendo como servicio al iniciar el sistema.
- Revisar logs y validar funcionamiento.

El ejecutable se llama **robin-client-monitor**; en systemd (Linux) el servicio recomendado se llama igual: **robin-client-monitor**.

---

## 1) Archivos que debes recibir

Segun tu sistema operativo, deberias recibir uno de estos:

- Linux/macOS: `robin-client-monitor`
- Windows: `robin-client-monitor.exe`

Ademas necesitas `config_client.json` (clave y URL WebSocket) **en la misma carpeta que el ejecutable** cuando lo instales.

Opcionalmente, te pueden indicar parametros como:

- `--max-chars 60000`
- `--concurrency 10`
- `--max-retries -1`
- `--retry-delay 2`
- `--verbose` o `-v` (más líneas en log: parámetros del comando y mensajes WebSocket sin `id`)

> Recomendacion: usa `--max-retries -1` para reconexion indefinida.

---

## 1.1) Provision de identidad (enrollment RF-CORE-01/02) — RECOMENDADO

La forma recomendada de instalar es que el agente **provisione su identidad
persistente** contra el backend con un **token de un solo uso** (te lo debe
entregar quien administra el servidor). No es necesario generar llaves ni
certificados a mano.

Ejemplo:

```bash
/opt/robin-client-monitor/robin-client-monitor \
  --enroll <TOKEN_DE_UN_SOLO_USO> \
  --enroll-server https://host:8000 \
  --enroll-tenant <tenant_id> \
  --enroll-name PC_Cliente \
  --enroll-ca /opt/robin-client-monitor/enrollment/certs/ca.crt
```

- Si omites `--enroll-server`, se deriva de la URL WebSocket (`wss://…` → `https://…`).
- HTTPS: pinneá la CA con `--enroll-ca` / `ROBIN_ENROLL_CA` (o `enrollment/certs/ca.crt`).
- Si el servidor ya exige mTLS en el 8000, el primer enroll va al **bootstrap**
  (`https://host:8001`, solo loopback por defecto) o usá PKI offline
  (`scripts/enroll.py`). Re-enroll: `--enroll-cert` + `--enroll-key`.
- La identidad queda en la carpeta del binario (`enrollment/identity.json`) y se
  reutiliza en arranques posteriores (no se regenera por sesión).
- El flujo continúa y el agente arranca conectándose de inmediato.
- Reintentar con el mismo token da error (es de un solo uso); el agente detecta
  que ya tiene identidad y la reutiliza.

> Dev/local sin TLS: añade `--enroll-insecure` (ajusta la identidad a `ws://`).
> **Nunca** en producción.

Para validar la instalación sin tocar el backend:

```bash
/opt/robin-client-monitor/robin-client-monitor --self-test
```

Imprime el estado de config/identidad y de los módulos del core común
(buffer, scheduler, tamper). Sale 0 si todo está sano.

---

## 1.2) Instalacion automatizada (scripts incluidos en el repo)

- **Linux**: `sudo ./deploy/install-linux.sh <binario> [config]
  [--enroll TOKEN --enroll-server URL --enroll-tenant TENANT]` — o el `.deb`/`.rpm`
  de `deploy/pack-linux.sh`. Detalle: [`docs/empaquetado.md`](docs/empaquetado.md).
- **Windows (instalador)**: `deploy/install-windows.iss` →
  `dist/robin-client-monitor-setup.exe`. Silencioso (Intune/SCCM):
  `/VERYSILENT /ENROLL=TOKEN /ENROLLSERVER=https://host:8000`.
- **Windows (servicio manual)**: `deploy\install-service-windows.bat` — NSSM +
  `sc failure` (reinicio en fallo). MSI: `deploy/robin-client-monitor.wxs`.
- Unidad systemd: `deploy/robin-client-monitor.service`.

> El token de enrollment es de un solo uso; en el instalador el admin lo
> preconfigura en `config_client.json` (y opcionalmente la identidad ya
> provisionada en `enrollment/`), así el usuario final no necesita ejecutar
> `--enroll`.

---

## 1.3) Verificacion TLS y fijacion de CA (wss://)

El agente solo conecta por `wss://` verificando la identidad del servidor
(§8.2). El comportamiento depende de `tls_ca_cert` en `config_client.json`:

- **`tls_ca_cert` con ruta a tu CA** (recomendado en despliegue): el cliente
  confía **SOLO en tu CA** (fijación de CA). Si alguien suplanta el servidor con
  un certificado de otra CA, el handshake falla. Tambien aplica mTLS si
  configuras `tls_client_cert`/`tls_client_key`.
- **`tls_ca_cert` vacio**: el cliente verifica contra la tienda de CA del
  sistema **y** el bundle de CA de `certifi` (raíces actualizadas, incluye
  Let's Encrypt ISRG Root X1). Esto cubre túneles públicos (por ejemplo ngrok)
  o servidores con certificados de CA publica. En este modo el agente imprime
  al arrancar:

  ```
  [robin-client-tools] AVISO: wss:// sin tls_ca_cert (sin fijacion de CA; se
  verifica contra tienda del sistema + certifi).
  ```

  Es un aviso de que no hay fijacion de CA, no un error: la conexion continua.

> Con certificados de tu propia CA, el fallback a `certifi` **no se activa**
> (solo ocurre cuando `tls_ca_cert` esta vacio). La fijacion de CA siempre
> tiene prioridad.

---

## 1.4) Plano de datos (OTLP, RF-OBS-08)

El WebSocket solo lleva **control** (comandos, heartbeat). Las métricas y
resultados programados salen por **HTTPS OTLP** (JSON + gzip), en batch, al
mismo servidor (`/v1/logs` y `/v1/metrics`) o a un collector OpenTelemetry
(puerto 4318).

En `config_client.json`:

```json
"data_plane": {
  "enabled": true,
  "compression": "gzip",
  "batch_size": 32,
  "batch_interval_seconds": 5
}
```

Si `endpoint` está vacío se deriva de `websocket_url` (`wss://host` →
`https://host/v1/logs`). Sin red, el buffer de disco reintenta solo.

Para desactivar y volver a mandar telemetría por el WebSocket:
`"data_plane": { "enabled": false }`.

---

## 2) Ejecucion manual (sin servicio)

En los comandos siguientes, **origen del binario**: el archivo que te entregaron, o —si acabas de compilar en este repo— `./dist/robin-client-monitor`.

### Linux/macOS

1. Copia el binario y el config a una carpeta estable:

```bash
sudo mkdir -p /opt/robin-client-monitor
sudo cp robin-client-monitor /opt/robin-client-monitor/robin-client-monitor
# o: sudo cp ./dist/robin-client-monitor /opt/robin-client-monitor/robin-client-monitor
sudo cp config_client.json /opt/robin-client-monitor/config_client.json
sudo chmod +x /opt/robin-client-monitor/robin-client-monitor
```

2. Ejecuta:

```bash
/opt/robin-client-monitor/robin-client-monitor
```

Con parametros:

```bash
/opt/robin-client-monitor/robin-client-monitor --max-chars 60000 --concurrency 10 --max-retries -1 --retry-delay 2
```

### Windows

1. Crea carpeta y copia el ejecutable y el config:

- `C:\Program Files\robin-client-monitor\robin-client-monitor.exe`
- `C:\Program Files\robin-client-monitor\config_client.json`

2. Ejecuta en PowerShell o CMD:

```powershell
& "C:\Program Files\robin-client-monitor\robin-client-monitor.exe"
```

Con parametros:

```powershell
& "C:\Program Files\robin-client-monitor\robin-client-monitor.exe" --max-chars 60000 --concurrency 10 --max-retries -1 --retry-delay 2
```

---

## 3) Instalar como servicio

## Linux (systemd)

1. Copia binario y config:

```bash
sudo mkdir -p /opt/robin-client-monitor
sudo cp robin-client-monitor /opt/robin-client-monitor/robin-client-monitor
# o: sudo cp ./dist/robin-client-monitor /opt/robin-client-monitor/robin-client-monitor
sudo cp config_client.json /opt/robin-client-monitor/config_client.json
sudo chmod +x /opt/robin-client-monitor/robin-client-monitor
```

2. Crea archivo de servicio:

Ruta: `/etc/systemd/system/robin-client-monitor.service`

Contenido:

Preferí copiar `deploy/robin-client-monitor.service` (hardening incluido).
Contenido equivalente:

```ini
[Unit]
Description=Robin Client Monitor (WebSocket agent)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=86400
StartLimitBurst=20

[Service]
Type=simple
User=root
WorkingDirectory=/opt/robin-client-monitor
Environment=PYTHONUNBUFFERED=1
ExecStart=/opt/robin-client-monitor/robin-client-monitor --max-retries -1 --retry-delay 2
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=/opt/robin-client-monitor /opt/robin-client-monitor/enrollment

[Install]
WantedBy=multi-user.target
```

3. Activar y arrancar:

```bash
sudo systemctl daemon-reload
sudo systemctl enable robin-client-monitor
sudo systemctl start robin-client-monitor
sudo systemctl status robin-client-monitor
```

4. Ver logs:

```bash
journalctl -u robin-client-monitor -f
```

### Logs: ver pings y demás comandos

Todo va a **stdout/stderr** (en servicio: `journalctl` los muestra como el mismo stream del proceso).

- Cada herramienta que pida el servidor genera líneas con prefijo `[robin-client-monitor]`, por ejemplo:
  - `Comando remoto id=… tool='ping' target=… count=… timeout=…`
  - `Resultado id=… tool='ping' → …`
  - `Respuesta enviada al servidor id=…`
- Para **más detalle** (JSON de `params` y mensajes del socket que no traen `id`, por ejemplo heartbeats), arranca con **`--verbose`** (o **`-v`**):

```bash
/opt/robin-client-monitor/robin-client-monitor --max-retries -1 --retry-delay 2 --verbose
```

En el `.service` de systemd, añade `--verbose` al final de `ExecStart=` si quieres ese nivel de traza también en producción (los logs serán más largos).

Si en consola sigues viendo `[ws-tools-client-embedded]`, es un **binario antiguo**: vuelve a compilar con `./build.sh` y copia de nuevo el ejecutable.

---

## macOS (launchd)

1. Copia binario y config:

```bash
sudo mkdir -p /opt/robin-client-monitor
sudo cp robin-client-monitor /opt/robin-client-monitor/robin-client-monitor
# o: sudo cp ./dist/robin-client-monitor /opt/robin-client-monitor/robin-client-monitor
sudo cp config_client.json /opt/robin-client-monitor/config_client.json
sudo chmod +x /opt/robin-client-monitor/robin-client-monitor
```

2. Crea el archivo:

Ruta: `~/Library/LaunchAgents/com.colsoft.robin-client-monitor.plist`

Contenido:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>com.colsoft.robin-client-monitor</string>

    <key>ProgramArguments</key>
    <array>
      <string>/opt/robin-client-monitor/robin-client-monitor</string>
      <string>--max-retries</string>
      <string>-1</string>
      <string>--retry-delay</string>
      <string>2</string>
    </array>

    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>

    <key>StandardOutPath</key>
    <string>/tmp/robin-client-monitor.out.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/robin-client-monitor.err.log</string>
  </dict>
</plist>
```

3. Cargar servicio:

```bash
launchctl unload ~/Library/LaunchAgents/com.colsoft.robin-client-monitor.plist 2>/dev/null || true
launchctl load ~/Library/LaunchAgents/com.colsoft.robin-client-monitor.plist
launchctl list | rg robin-client-monitor
```

4. Ver logs:

```bash
tail -f /tmp/robin-client-monitor.out.log /tmp/robin-client-monitor.err.log
```

---

## Windows (servicio con NSSM)

Windows no siempre instala este tipo de ejecutable como servicio de forma simple, por eso se recomienda NSSM.

1. Copia ejecutable y config:

- `C:\Program Files\robin-client-monitor\robin-client-monitor.exe`
- `C:\Program Files\robin-client-monitor\config_client.json`

2. Descarga e instala NSSM:

- [https://nssm.cc/download](https://nssm.cc/download)

3. Abre PowerShell como Administrador y ejecuta:

```powershell
nssm install robin-client-monitor "C:\Program Files\robin-client-monitor\robin-client-monitor.exe" --max-retries -1 --retry-delay 2
nssm set robin-client-monitor Start SERVICE_AUTO_START
nssm start robin-client-monitor
```

4. Ver estado:

```powershell
sc.exe query robin-client-monitor
```

---

## 4) Comandos utiles de operacion

### Linux (systemd)

- Reiniciar:
```bash
sudo systemctl restart robin-client-monitor
```

- Detener:
```bash
sudo systemctl stop robin-client-monitor
```

- Deshabilitar en arranque:
```bash
sudo systemctl disable robin-client-monitor
```

### macOS (launchd)

- Descargar servicio:
```bash
launchctl unload ~/Library/LaunchAgents/com.colsoft.robin-client-monitor.plist
```

- Volver a cargar:
```bash
launchctl load ~/Library/LaunchAgents/com.colsoft.robin-client-monitor.plist
```

### Windows (NSSM)

- Detener:
```powershell
nssm stop robin-client-monitor
```

- Reiniciar:
```powershell
nssm restart robin-client-monitor
```

- Eliminar servicio:
```powershell
nssm remove robin-client-monitor confirm
```

---

## 5) Recomendaciones importantes

- Usa una ruta fija para el ejecutable y el config (ej. `/opt/robin-client-monitor` o `C:\Program Files\robin-client-monitor`).
- Evita ejecutar desde Desktop/Descargas.
- Si necesitas proxy/firewall corporativo, valida conectividad al endpoint WebSocket.
- Si hay politicas de seguridad, ejecuta con usuario de servicio dedicado en lugar de `root`.
- Mantener `Restart`/`KeepAlive` habilitado para recuperacion automatica.

---

## 6) Checklist rapido de validacion

- El proceso inicia sin error.
- Se reconecta automaticamente si cae la red.
- El servicio queda en estado "running".
- Se generan logs y no muestran errores repetitivos.
- Reinicias el equipo y el cliente vuelve a iniciar solo.

### Errores frecuentes de conexion

- **`SSLCertVerificationError: CERTIFICATE_VERIFY_FAILED`**: el cliente no
  confia en el certificado del servidor. Verifica que `tls_ca_cert` apunte a la
  CA correcta (tu CA o vacio para CA publica/certifi). No uses `ws://` en
  produccion.
- **`ConnectionRefusedError` / timeout**: el endpoint WebSocket no responde.
  Confirma `websocket_url` (debe terminar en `/ws/colsoft-tools`), el puerto y
  que el servidor este accesible (firewall/proxy/ngrok).
- **`403` / token invalido en enrollment**: el token ya fue usado (es de un
  solo uso) o no existe en `ENROLLMENT_TOKENS` del servidor.
