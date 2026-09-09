# Empaquetado e instalación masiva — SRS §16

Cómo se **construye, firma e instala** el agente (no la taxonomía de logs).
Binario: `./build.sh`. Identidad: enrollment (`--enroll`, RF-CORE-01/02).

Versión de paquete: **0.9.0** (`colsoft_tools.agent_admin.AGENT_VERSION`).

La firma (Authenticode / GPG) ocurre en CI con secretos; **no** hay PFX ni
claves GPG en el repo.

---

## 1. Windows — MSI / Inno + servicio con recuperación

| Artefacto | Dónde |
|---|---|
| Servicio NSSM + `sc failure` | `deploy/install-service-windows.bat` |
| Instalador gráfico / silencioso | `deploy/install-windows.iss` → `dist/robin-client-monitor-setup.exe` |
| MSI (WiX 4) | `deploy/robin-client-monitor.wxs` |
| Firma Authenticode | `deploy/sign-windows.ps1` |

Compilar Inno (en un packager Windows, junto al `.iss`: exe, `nssm.exe`, config):

```
ISCC.exe deploy\install-windows.iss
```

MSI:

```
copy /Y deploy\config_client.packaged.json dist\config_client.json
wix build deploy/robin-client-monitor.wxs -o dist/robin-client-monitor.msi -d SourceDir=dist
```

`SourceDir` debe incluir `config_client.json` (Inno sí tiene fallback a
`config_client.packaged.json`; WiX no) y `nssm.exe` (Inno y WiX lo instalan
en `nssm\nssm.exe` junto al exe). El CustomAction de enrollment cita
las propiedades MSI (`set "ENROLLTOKEN=..."`) y llama
`install-service-windows.bat` con `INSTALLFOLDER` (Program Files).

Firmar:

```
$env:AUTHENTICODE_PFX = "C:\certs\code-sign.pfx"
$env:AUTHENTICODE_PASSWORD = "..."
.\deploy\sign-windows.ps1 dist\robin-client-monitor.exe dist\robin-client-monitor-setup.exe dist\robin-client-monitor.msi
```

Recuperación del servicio: NSSM `AppExit Default Restart` **y**
`sc failure … restart/3s/10s/30s` (`failureflag 1`).

---

## 2. Linux — `.deb` / `.rpm` + systemd

```
./build.sh
./deploy/pack-linux.sh dist/robin-client-monitor
# opcional:
GPG_KEY_ID=0x… ./deploy/sign-linux.sh dist/robin-client-monitor_0.9.0_amd64.deb
```

Salida típica:

- `dist/robin-client-monitor_0.9.0_amd64.deb` (o `_arm64.deb`)
- `dist/robin-client-monitor-0.9.0-1.x86_64.rpm` (o `.aarch64.rpm`)

Unidad: `deploy/robin-client-monitor.service` (`Restart=always`,
`StartLimitBurst=20` / 24 h). Icono: `deploy/robin-client-monitor.desktop` +
PNG en `/usr/share/icons/hicolor` (hace falta haber corrido `./build.sh` para
rasterizar el SVG). Instalar a mano:

```
sudo ./deploy/install-linux.sh dist/robin-client-monitor \
  deploy/config_client.packaged.json \
  --enroll TOKEN --enroll-server https://host:8000 --enroll-tenant TENANT
```

El paquete **no** lleva llaves de lab; usa `deploy/config_client.packaged.json`
(`allow_insecure_ws: false`, `require_command_signature: true`).

---

## 3. Token / cert de enrollment como parámetro

El token es de **un solo uso**. El cert de cliente lo emite el backend en
`POST /api/enroll` (puerto bootstrap si el 8000 ya está en mTLS) o
`scripts/enroll.py` (PKI offline); no se embebe un PEM en el MSI.

| Canal | Parámetros |
|---|---|
| Linux script | `--enroll` `--enroll-server` `--enroll-tenant` `--enroll-name` |
| Linux env / postinst | `ROBIN_ENROLL_TOKEN` `ROBIN_ENROLL_SERVER` `ROBIN_ENROLL_TENANT` `ROBIN_ENROLL_NAME` |
| Inno silencioso | `/ENROLL=` `/ENROLLSERVER=` `/ENROLLTENANT=` `/ENROLLNAME=` |
| MSI | propiedades `ENROLLTOKEN` `ENROLLSERVER` `ENROLLTENANT` `ENROLLNAME` |
| Windows bat | las mismas variables de entorno (`ENROLLTOKEN`, …) |
| Identidad ya hecha | carpeta `enrollment/` junto al instalador (Inno la copia) |

`--enroll-insecure` / `ROBIN_ENROLL_INSECURE=1` / `/ENROLLINSECURE=1` **solo lab**.

---

## 4. Instalación silenciosa

### Inno (SCCM / Intune / GPO)

```
robin-client-monitor-setup.exe /VERYSILENT /NORESTART ^
  /ENROLL=TOKEN /ENROLLSERVER=https://host:8000 /ENROLLTENANT=acme
```

### MSI

```
msiexec /i robin-client-monitor.msi /qn /norestart ^
  ENROLLTOKEN=TOKEN ENROLLSERVER=https://host:8000 ENROLLTENANT=acme
```

### apt / dnf (Ansible, cloud-init)

```
sudo ROBIN_ENROLL_TOKEN=TOKEN \
  ROBIN_ENROLL_SERVER=https://host:8000 \
  ROBIN_ENROLL_TENANT=acme \
  apt-get install -y ./robin-client-monitor_0.9.0_amd64.deb
```

Playbook: [`../deploy/ansible/install-agent.yml`](../deploy/ansible/install-agent.yml).  
cloud-init: [`../deploy/cloud-init.yaml.example`](../deploy/cloud-init.yaml.example).

Chef/Puppet: mismo paquete + las env `ROBIN_ENROLL_*` en el recurso `package`
o un `execute` de `install-linux.sh`.

---

## 5. ARM64

PyInstaller **no cruza** bien amd64↔arm64. Hay que **compilar en el arch destino**
(o Docker `--platform`).

| Arch | Cómo |
|---|---|
| Host arm64 | `./build.sh` → `dist/robin-client-monitor.arm64` |
| Host amd64 | `./build.sh` → `dist/robin-client-monitor.amd64` |
| Docker EL8 arm64 | `DOCKER_DEFAULT_PLATFORM=linux/arm64 TARGET_ARCH=aarch64 ./build-linux-el8-docker.sh` |
| Paquetes | `ARCH=arm64 ./deploy/pack-linux.sh dist/robin-client-monitor.arm64` |
| Inno | `ArchitecturesAllowed=x64compatible arm64` (el `.exe` debe ser arm64) |

---

## 6. Qué no va en el paquete

- `config_client.json` de lab (PEM, `allow_insecure_ws`, monitores on)
- PFX Authenticode / clave GPG
- Token de enrollment (solo parámetro de instalación, un uso)
