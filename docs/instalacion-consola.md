# Instalar Robin Client Monitor (consola)

Esta guía es para quien recibe el paquete y lo instala **sin ventanas**: servidor Linux, Windows Server Core, o una máquina a la que entras por SSH o PowerShell.

Si el equipo es **Windows con escritorio**, usa la [guía con instalador gráfico](instalacion-windows-usuario.md).

**Qué vas a instalar:** un programa que se conecta al servidor de monitoreo y queda como servicio (arranca solo al reiniciar).

El administrador ya dejó listos la configuración y los certificados. Tú copias los archivos y activas el servicio. No hace falta un token ni editar nada a mano.

---

## Qué debes recibir

Te deben pasar **juntos**, en una carpeta:

| Qué es | Linux | Windows |
|---|---|---|
| Programa | `robin-client-monitor` | `robin-client-monitor.exe` |
| Configuración | `config_client.json` | `config_client.json` |
| Identidad | carpeta `enrollment` | carpeta `enrollment` |
| Servicio | `robin-client-monitor.service` | `nssm.exe` e `install-service-windows.ps1` |

Necesitas permiso de administrador (`sudo` en Linux, PowerShell **como Administrator** en Windows) y red hasta el servidor de monitoreo.

Si falta algún archivo, no sigas: pide el paquete de nuevo.

---

## Linux

Carpeta de instalación: `/opt/robin-client-monitor`  
Servicio: `robin-client-monitor`

Abre una terminal **en la carpeta donde dejaste el paquete** (no en `/` ni en otro sitio).

### 1. Copiar archivos

```bash
sudo mkdir -p /opt/robin-client-monitor
sudo cp robin-client-monitor /opt/robin-client-monitor/robin-client-monitor
sudo cp config_client.json /opt/robin-client-monitor/config_client.json
sudo cp -a enrollment /opt/robin-client-monitor/enrollment
sudo chmod 0755 /opt/robin-client-monitor/robin-client-monitor
sudo chmod 0600 /opt/robin-client-monitor/config_client.json
sudo chmod 0700 /opt/robin-client-monitor/enrollment
```

### 2. Comprobar

```bash
sudo /opt/robin-client-monitor/robin-client-monitor --self-test
```

Debe terminar sin error. Si falla, avisa a quien te envió el paquete.

### 3. Activar el servicio

```bash
sudo cp robin-client-monitor.service /etc/systemd/system/robin-client-monitor.service
sudo systemctl daemon-reload
sudo systemctl enable --now robin-client-monitor
sudo systemctl status robin-client-monitor --no-pager
```

Tiene que verse `active (running)`.

### 4. Ver que se conecta

```bash
sudo journalctl -u robin-client-monitor -n 50 --no-pager
```

Busca: `Socket conectado` y `Autenticación confirmada`. Para seguir en vivo:

```bash
sudo journalctl -u robin-client-monitor -f
```

(`Ctrl+C` solo corta el seguimiento; el servicio sigue.)

---

## Windows (sin escritorio)

Carpeta de instalación: `C:\Program Files\robin-client-monitor`  
Servicio: `robin-client-monitor`

Abre PowerShell **como Administrator**. Esa ventana empieza en `C:\Windows\system32`: no copies archivos desde ahí.

Pon en `$src` la carpeta **donde está el `.exe`** (Downloads, el escritorio, un USB, etc.). Copia **el bloque entero**, incluida la primera línea.

### 1. Copiar archivos

```powershell
$src = "C:\Users\Administrator\Desktop\paquete"   # cambia esto a tu carpeta
$dst = "C:\Program Files\robin-client-monitor"

if (-not (Test-Path "$src\robin-client-monitor.exe")) {
  throw "No hay robin-client-monitor.exe en $src. Corrige la ruta de `$src."
}

New-Item -ItemType Directory -Force -Path $dst | Out-Null
Copy-Item "$src\robin-client-monitor.exe" $dst\
Copy-Item "$src\config_client.json" $dst\
New-Item -ItemType Directory -Force -Path "$dst\nssm" | Out-Null
Copy-Item "$src\nssm.exe" "$dst\nssm\nssm.exe"
Copy-Item "$src\install-service-windows.ps1" $dst\
Copy-Item "$src\install-service-windows.bat" $dst\
Copy-Item -Recurse "$src\enrollment" "$dst\enrollment"
```

Si no sabes dónde está el `.exe`:

```powershell
Get-ChildItem C:\Users, C:\Temp -Filter robin-client-monitor.exe -Recurse -ErrorAction SilentlyContinue |
  Select-Object -ExpandProperty DirectoryName
```

Esa ruta es la que pones en `$src`.

### 2. Comprobar

```powershell
& "C:\Program Files\robin-client-monitor\robin-client-monitor.exe" --self-test
```

### 3. Activar el servicio

Usa el `.ps1` (PowerShell). El archivo ya está en `C:\Program Files\robin-client-monitor` (lo copiaste en el paso 1):

```powershell
cd "C:\Program Files\robin-client-monitor"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install-service-windows.ps1
```

El estado debe ser `RUNNING`:

```powershell
sc.exe query robin-client-monitor
```

---

## Día a día

### Linux

```bash
sudo systemctl status robin-client-monitor
sudo systemctl restart robin-client-monitor
sudo systemctl stop robin-client-monitor
sudo journalctl -u robin-client-monitor -f
```

### Windows

```powershell
sc.exe query robin-client-monitor
& "C:\Program Files\robin-client-monitor\nssm\nssm.exe" status robin-client-monitor
& "C:\Program Files\robin-client-monitor\nssm\nssm.exe" restart robin-client-monitor
& "C:\Program Files\robin-client-monitor\nssm\nssm.exe" stop robin-client-monitor
```

---

## Desinstalar

### Linux

```bash
sudo systemctl disable --now robin-client-monitor
sudo rm -f /etc/systemd/system/robin-client-monitor.service
sudo systemctl daemon-reload
sudo rm -rf /opt/robin-client-monitor
```

### Windows

```powershell
& "C:\Program Files\robin-client-monitor\nssm\nssm.exe" stop robin-client-monitor
& "C:\Program Files\robin-client-monitor\nssm\nssm.exe" remove robin-client-monitor confirm
Remove-Item -Recurse -Force "C:\Program Files\robin-client-monitor"
```

---

## Si algo falla

| Qué ves | Qué hacer |
|---|---|
| `Cannot find path ...\system32\robin-client-monitor.exe` | Estás usando `.\` desde `C:\Windows\system32`. Usa `$src` y copia el bloque entero. |
| `Cannot find path 'C:\Program Files\robin-client-monitor.exe'` | `$src` está vacío. Ejecuta primero `$src = "C:\ruta\donde\está\el\exe"`. |
| `install-service-windows.bat is not recognized` / `No se esperaba .` | Entra a `"C:\Program Files\robin-client-monitor"` y ejecuta `.\install-service-windows.ps1`. |
| `--self-test` distinto de 0 | El paquete está incompleto. Pídelo de nuevo. |
| Acceso denegado / Permission denied | Repite los comandos como Administrator / `sudo`. |
| `Connection refused` o timeout | El servidor no es alcanzable (red, firewall). Avísale al administrador. |
| El servicio arranca y se cae | Avísale a quien te entregó el paquete (casi siempre es red o certificados). |

No edites `config_client.json` ni los certificados. Si el servicio está en ejecución y el equipo no sale en la consola de monitoreo, es red o servidor: avisa a quien te entregó el paquete.
