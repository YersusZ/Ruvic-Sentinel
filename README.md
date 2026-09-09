# Robin Client Monitor — agente de endpoint

Agente (Linux / Windows / macOS) + servidor FastAPI: plano de **control** por
WebSocket (comandos firmados), plano de **datos** OTLP/HTTPS, API REST con JWT
de Robin y auditoría en RobinLogs.

Requerimientos: SRS v1.0 (agentes de endpoint). Estado:
[`docs/checklist-pendiente.md`](docs/checklist-pendiente.md). Índice:
[`docs/README.md`](docs/README.md).

```
Ruvic / este servidor
  REST /api/*  + JWT Robin (RS256)     → comandos, cola, GET /api/logs
  WSS  /ws/colsoft-tools               → control (comandos, heartbeat, event_push)
  HTTPS /v1/logs  /v1/metrics          → data plane OTLP (batch)
  RobinLogs POST .../store             → auditoría (taxonomía propia)

Agente (ws_tools_client_embedded.py → binario robin-client-monitor)
  identity, config, buffer, scheduler, collectors
```

| Pieza | Doc |
|---|---|
| Claves de `config_client.json` | [`README_CONFIG.md`](README_CONFIG.md) |
| Binario / servicio (usuario final) | [`README_CLIENT.md`](README_CLIENT.md) |
| Instalación sin GUI | [`docs/instalacion-consola.md`](docs/instalacion-consola.md) |
| JWT Robin en `/api/*` | [`docs/produccion.md`](docs/produccion.md) |
| Robin prod (enrollment + agentes) | [`docs/robin-plataforma-agentes.md`](docs/robin-plataforma-agentes.md) |
| Telemetry filters for **this** agent | [`docs/agent-telemetry.md`](docs/agent-telemetry.md) |
| Env del servidor | [`.env.example`](.env.example) |

Lab: JWT apagado (`ROBIN_JWT_REQUIRED=0`) y `allow_insecure_ws` en el config.
Producción: [`docs/produccion.md`](docs/produccion.md) (`JWT=1`, `wss://`, mTLS).

## Requisitos

- Python 3.10+ (recomendado 3.11)
- `pip`
- Linux/macOS/Windows

## Ejecutarlo en modo Python (sin compilar)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install aiohttp requests
python ws_tools_client_embedded.py
```

Parámetros opcionales:

```bash
python ws_tools_client_embedded.py --max-chars 60000 --concurrency 10 --max-retries -1 --retry-delay 2
```

## Crear ejecutable (script `.sh`)

Este proyecto incluye `build.sh`.

Uso:

```bash
chmod +x build.sh
./build.sh
```

En **Windows** (Git Bash, no PowerShell/cmd): `bash build.sh`. El script usa
`python -m PyInstaller` (el comando `pyinstaller` en Git Bash suele salir **126**).

Resultado esperado:

- Binario en `dist/robin-client-monitor`
- Carpeta de build en `build/`

Notas:

- El script usa `PyInstaller --onefile`.
- El icono base es `assets/ws-client-icon.svg`. En **Windows** va dentro del `.exe`. En **Linux** el ELF no puede llevarlo: `build.sh` deja `dist/robin-client-monitor.png` + `.desktop`, y el `.deb`/`.rpm` instalan el icono en hicolor.

### Linux: glibc y “un solo exe para todo”

PyInstaller genera un ELF enlazado contra la **glibc del sistema donde compilas**. Esa glibc es un **mínimo**: el binario pide símbolos (por ejemplo `GLIBC_2.35`); en un servidor con glibc más vieja falla con `version 'GLIBC_2.xx' not found`.

- **No** existe un único binario nativo “universal” para cualquier glibc.
- **Sí** puedes **ampliar compatibilidad**: compila en una distro con glibc **tan antigua como el host más viejo** que quieras soportar; ese binario suele correr en distros **más nuevas** (misma arquitectura, p. ej. `x86_64`).
- Si compilas en Ubuntu 22.04, muchas veces quedas atado a **GLIBC_2.35+**; Oracle/RHEL más viejos no servirán.

Para un artefacto orientado a **RHEL 8 / Oracle Linux 8 / Rocky 8** (glibc ~2.28) y muchos Ubuntu 20.04+:

```bash
chmod +x build-linux-el8-docker.sh
./build-linux-el8-docker.sh
```

Genera `dist/robin-client-monitor.linux-el8-glibc28` (Docker + Rocky Linux 8). En Mac con Apple Silicon, si necesitas `amd64`:

```bash
DOCKER_DEFAULT_PLATFORM=linux/amd64 ./build-linux-el8-docker.sh
```

Para **Oracle Linux 7 / CentOS 7** haría falta otra imagen base (glibc 2.17) y suele ser más incómodo (Python viejo, ruedas, etc.).

## Ejecutar el binario compilado

```bash
./dist/robin-client-monitor
```

Con flags:

```bash
./dist/robin-client-monitor --max-chars 60000 --concurrency 10 --max-retries -1 --retry-delay 2
```

---

## Ejecutarlo como servicio

### Linux (systemd)

1) Copia el binario a una ruta estable:

```bash
sudo mkdir -p /opt/robin-client-monitor
sudo cp dist/robin-client-monitor /opt/robin-client-monitor/robin-client-monitor
sudo chmod +x /opt/robin-client-monitor/robin-client-monitor
```

2) Crea `/etc/systemd/system/robin-client-monitor.service`:

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

3) Activa y arranca:

```bash
sudo systemctl daemon-reload
sudo systemctl enable robin-client-monitor
sudo systemctl start robin-client-monitor
sudo systemctl status robin-client-monitor
```

Logs:

```bash
journalctl -u robin-client-monitor -f
```

### macOS (launchd)

1) Copia binario:

```bash
sudo mkdir -p /opt/robin-client-monitor
sudo cp dist/robin-client-monitor /opt/robin-client-monitor/robin-client-monitor
sudo chmod +x /opt/robin-client-monitor/robin-client-monitor
```

2) Crea `~/Library/LaunchAgents/com.colsoft.robin-client-monitor.plist`:

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

3) Cargar servicio:

```bash
launchctl unload ~/Library/LaunchAgents/com.colsoft.robin-client-monitor.plist 2>/dev/null || true
launchctl load ~/Library/LaunchAgents/com.colsoft.robin-client-monitor.plist
launchctl list | rg robin-client-monitor
```

### Windows (Servicio con NSSM)

Windows no incluye un mecanismo nativo simple para cualquier exe Python-like como servicio, por eso se recomienda NSSM:

1) Copia `robin-client-monitor.exe` a `C:\Program Files\robin-client-monitor\`.
2) Instala NSSM: [https://nssm.cc/download](https://nssm.cc/download)
3) Crea servicio (PowerShell admin):

```powershell
nssm install robin-client-monitor "C:\Program Files\robin-client-monitor\robin-client-monitor.exe" --max-retries -1 --retry-delay 2
nssm set robin-client-monitor Start SERVICE_AUTO_START
nssm start robin-client-monitor
```

Ver estado:

```powershell
sc.exe query robin-client-monitor
```

---

## Icono del ejecutable

Fuente: `assets/ws-client-icon.svg`. PyInstaller **no** embebe SVG.

`./build.sh` genera `assets/ws-client-icon.png` y `.ico` (ImageMagick si está,
si no Pillow). **Windows** usa el `.ico` en el `.exe`. **macOS** intenta `.icns`
con `qlmanage`/`iconutil`. **Linux:** PyInstaller no puede pegar un icono en el
ELF. El build copia `dist/robin-client-monitor.png` y un `.desktop`; en este
host Nautilus puede mostrar el icono vía `gio` (no viaja al copiar el archivo).
`install-linux.sh` y `pack-linux.sh` instalan el PNG en
`/usr/share/icons/hicolor` y el launcher en `/usr/share/applications`.

Conversión manual (opcional, si tienes ImageMagick):

```bash
magick assets/ws-client-icon.svg assets/ws-client-icon.png
magick assets/ws-client-icon.svg assets/ws-client-icon.ico
magick assets/ws-client-icon.svg assets/ws-client-icon.icns
```

## Estructura útil

- `ws_tools_client_embedded.py` — entrypoint del agente (binario / Docker)
- `ws_tools_client.py` — alias de lab (`--url`); mismo `main()`
- `colsoft_tools/` — protocolo, seguridad, observabilidad, remediación, OTLP
- `server/` — gateway WS, cola de comandos, REST, receptor OTLP, JWT, RobinLogs
- `build.sh` — binario `dist/robin-client-monitor`
- `assets/ws-client-icon.*` — iconos
