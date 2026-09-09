#!/usr/bin/env python3
"""Genera docs/instalacion-consola.pdf."""
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "instalacion-consola.pdf"

W, H = 1240, 1754
MARGIN = 64
CONTENT_W = W - 2 * MARGIN
NAVY = (15, 55, 95)
TEAL = (0, 110, 140)
GRAY = (50, 50, 50)
MUTED = (90, 90, 90)
LINE = (210, 218, 226)
WHITE = (255, 255, 255)
SOFT = (245, 248, 251)
CODE_BG = (28, 36, 46)
CODE_FG = (230, 236, 242)
RED = (140, 40, 40)

FONT_R = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
FONT_B = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
FONT_M = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"


def fnt(size, *, bold=False, mono=False):
    path = FONT_M if mono else (FONT_B if bold else FONT_R)
    return ImageFont.truetype(path, size)


class Doc:
    def __init__(self):
        self.pages = []
        self._new()

    def _new(self):
        self.img = Image.new("RGB", (W, H), WHITE)
        self.d = ImageDraw.Draw(self.img)
        self.d.rectangle([0, 0, W, 16], fill=NAVY)
        self.d.rectangle([0, H - 48, W, H], fill=SOFT)
        self.d.text(
            (MARGIN, H - 34),
            "Robin Client Monitor  ·  Guía de instalación por consola",
            font=fnt(14),
            fill=MUTED,
        )
        self.y = 48
        self.pages.append(self.img)

    def ensure(self, need=80):
        if self.y + need > H - 70:
            self._new()

    def wrap(self, text, font, max_w):
        words = text.split()
        lines, cur = [], ""
        for w in words:
            trial = (cur + " " + w).strip()
            if self.d.textlength(trial, font=font) <= max_w:
                cur = trial
            else:
                if cur:
                    lines.append(cur)
                cur = w
        if cur:
            lines.append(cur)
        return lines or [""]

    def heading(self, text, size=22):
        self.ensure(70)
        self.y += 6
        self.d.text((MARGIN, self.y), text, font=fnt(size, bold=True), fill=NAVY)
        self.y += size + 12
        self.d.line([MARGIN, self.y, W - MARGIN, self.y], fill=LINE, width=2)
        self.y += 14

    def para(self, text, *, size=16, bold=False, fill=GRAY):
        font = fnt(size, bold=bold)
        for line in self.wrap(text, font, CONTENT_W):
            self.ensure(size + 14)
            self.d.text((MARGIN, self.y), line, font=font, fill=fill)
            self.y += int(size * 1.4)
        self.y += 6

    def bullets(self, items, size=16):
        font = fnt(size)
        for item in items:
            lines = self.wrap(item, font, CONTENT_W - 28)
            self.ensure(len(lines) * int(size * 1.4) + 12)
            self.d.ellipse(
                [MARGIN + 4, self.y + 7, MARGIN + 14, self.y + 17], fill=TEAL
            )
            for line in lines:
                self.d.text((MARGIN + 28, self.y), line, font=font, fill=GRAY)
                self.y += int(size * 1.4)
            self.y += 4

    def steps(self, items, size=16):
        font = fnt(size)
        for n, item in enumerate(items, 1):
            lines = self.wrap(item, font, CONTENT_W - 36)
            self.ensure(len(lines) * int(size * 1.4) + 12)
            self.d.text(
                (MARGIN, self.y), f"{n}.", font=fnt(size, bold=True), fill=TEAL
            )
            for line in lines:
                self.d.text((MARGIN + 36, self.y), line, font=font, fill=GRAY)
                self.y += int(size * 1.4)
            self.y += 4

    def code(self, text, size=13):
        font = fnt(size, mono=True)
        lines = []
        for raw in text.split("\n"):
            if not raw:
                lines.append("")
                continue
            # wrap long lines on spaces if needed
            if self.d.textlength(raw, font=font) <= CONTENT_W - 24:
                lines.append(raw)
            else:
                chunk = ""
                for ch in raw:
                    trial = chunk + ch
                    if self.d.textlength(trial, font=font) <= CONTENT_W - 24:
                        chunk = trial
                    else:
                        lines.append(chunk)
                        chunk = ch
                if chunk:
                    lines.append(chunk)
        line_h = int(size * 1.45)
        box_h = 16 + line_h * max(1, len(lines))
        self.ensure(box_h + 12)
        self.d.rounded_rectangle(
            [MARGIN, self.y, W - MARGIN, self.y + box_h],
            radius=8,
            fill=CODE_BG,
        )
        yy = self.y + 8
        for line in lines:
            self.d.text((MARGIN + 12, yy), line, font=font, fill=CODE_FG)
            yy += line_h
        self.y += box_h + 12

    def table(self, rows):
        col1 = int(CONTENT_W * 0.36)
        col2 = CONTENT_W - col1
        rf, hf = fnt(13), fnt(13, bold=True)
        for i, (a, b) in enumerate(rows):
            fa, fb = (hf, hf) if i == 0 else (rf, rf)
            la = self.wrap(a, fa, col1 - 16)
            lb = self.wrap(b, fb, col2 - 16)
            rh = max(len(la), len(lb)) * 20 + 12
            self.ensure(rh + 4)
            bg = NAVY if i == 0 else (WHITE if i % 2 else SOFT)
            fg = WHITE if i == 0 else GRAY
            self.d.rectangle([MARGIN, self.y, W - MARGIN, self.y + rh], fill=bg)
            ya, yb = self.y + 6, self.y + 6
            for line in la:
                self.d.text((MARGIN + 8, ya), line, font=fa, fill=fg)
                ya += 20
            for line in lb:
                self.d.text((MARGIN + col1 + 8, yb), line, font=fb, fill=fg)
                yb += 20
            self.y += rh
        self.y += 12


def build():
    d = Doc()
    d.y = 52
    d.d.text(
        (MARGIN, d.y), "Robin Client Monitor", font=fnt(34, bold=True), fill=NAVY
    )
    d.y += 48
    d.d.text(
        (MARGIN, d.y),
        "Guía de instalación por consola",
        font=fnt(22),
        fill=TEAL,
    )
    d.y += 38
    d.d.line([MARGIN, d.y, W - MARGIN, d.y], fill=TEAL, width=3)
    d.y += 22
    d.para(
        "Para quien recibe el paquete e instala sin ventanas: servidor Linux, "
        "Windows Server Core, o una máquina a la que entras por SSH o PowerShell."
    )
    d.para(
        "Qué vas a instalar: un programa que se conecta al servidor de monitoreo "
        "y queda como servicio (arranca solo al reiniciar)."
    )
    d.para(
        "El administrador ya dejó listos la configuración y los certificados. "
        "Tú copias los archivos y activas el servicio. No hace falta un token ni editar nada a mano.",
        bold=True,
        fill=NAVY,
    )

    d.heading("Qué debes recibir")
    d.para("Te deben pasar juntos, en una carpeta:")
    d.bullets(
        [
            "Linux: robin-client-monitor, config_client.json, carpeta enrollment y robin-client-monitor.service.",
            "Windows: robin-client-monitor.exe, config_client.json, carpeta enrollment, nssm.exe e install-service-windows.ps1.",
        ]
    )
    d.para(
        "Necesitas permiso de administrador (sudo / PowerShell como Administrator) "
        "y red hasta el servidor de monitoreo. Si falta algún archivo, pide el paquete de nuevo."
    )

    d.heading("Linux")
    d.para("Carpeta: /opt/robin-client-monitor    Servicio: robin-client-monitor")
    d.para("Abre la terminal en la carpeta donde dejaste el paquete.")
    d.para("1. Copiar archivos", bold=True, fill=NAVY)
    d.code(
        "sudo mkdir -p /opt/robin-client-monitor\n"
        "sudo cp robin-client-monitor /opt/robin-client-monitor/robin-client-monitor\n"
        "sudo cp config_client.json /opt/robin-client-monitor/config_client.json\n"
        "sudo cp -a enrollment /opt/robin-client-monitor/enrollment\n"
        "sudo chmod 0755 /opt/robin-client-monitor/robin-client-monitor\n"
        "sudo chmod 0600 /opt/robin-client-monitor/config_client.json\n"
        "sudo chmod 0700 /opt/robin-client-monitor/enrollment"
    )
    d.para("2. Comprobar", bold=True, fill=NAVY)
    d.code("sudo /opt/robin-client-monitor/robin-client-monitor --self-test")
    d.para("Debe terminar sin error. Si falla, avisa a quien te envió el paquete.")
    d.para("3. Activar el servicio", bold=True, fill=NAVY)
    d.code(
        "sudo cp robin-client-monitor.service /etc/systemd/system/robin-client-monitor.service\n"
        "sudo systemctl daemon-reload\n"
        "sudo systemctl enable --now robin-client-monitor\n"
        "sudo systemctl status robin-client-monitor --no-pager"
    )
    d.para("Tiene que verse active (running). Logs:")
    d.code(
        "sudo journalctl -u robin-client-monitor -n 50 --no-pager\n"
        "sudo journalctl -u robin-client-monitor -f"
    )
    d.para(
        "Busca «Socket conectado» y «Autenticación confirmada». "
        "Ctrl+C solo corta el seguimiento; el servicio sigue."
    )

    d.heading("Windows (sin escritorio)")
    d.para(
        "Carpeta: C:\\Program Files\\robin-client-monitor    "
        "Servicio: robin-client-monitor"
    )
    d.para(
        "Abre PowerShell como Administrator. Empieza en C:\\Windows\\system32: "
        "no copies desde ahí. Pon en $src la carpeta donde está el .exe y copia el bloque entero."
    )
    d.para("1. Copiar archivos", bold=True, fill=NAVY)
    d.code(
        "$src = \"C:\\Users\\Administrator\\Desktop\\paquete\"   # carpeta del .exe\n"
        "$dst = \"C:\\Program Files\\robin-client-monitor\"\n"
        "if (-not (Test-Path \"$src\\robin-client-monitor.exe\")) {\n"
        "  throw \"No hay robin-client-monitor.exe en $src. Corrige `$src.\"\n"
        "}\n"
        "New-Item -ItemType Directory -Force -Path $dst | Out-Null\n"
        "Copy-Item \"$src\\robin-client-monitor.exe\" $dst\\\n"
        "Copy-Item \"$src\\config_client.json\" $dst\\\n"
        "New-Item -ItemType Directory -Force -Path \"$dst\\nssm\" | Out-Null\n"
        "Copy-Item \"$src\\nssm.exe\" \"$dst\\nssm\\nssm.exe\"\n"
        "Copy-Item \"$src\\install-service-windows.ps1\" $dst\\\n"
        "Copy-Item \"$src\\install-service-windows.bat\" $dst\\\n"
        "Copy-Item -Recurse \"$src\\enrollment\" \"$dst\\enrollment\""
    )
    d.para("Si no sabes dónde está el .exe:")
    d.code(
        "Get-ChildItem C:\\Users, C:\\Temp -Filter robin-client-monitor.exe "
        "-Recurse -ErrorAction SilentlyContinue |\n"
        "  Select-Object -ExpandProperty DirectoryName"
    )
    d.para("2. Comprobar", bold=True, fill=NAVY)
    d.code(
        "& \"C:\\Program Files\\robin-client-monitor\\robin-client-monitor.exe\" --self-test"
    )
    d.para("3. Activar el servicio", bold=True, fill=NAVY)
    d.para(
        "En PowerShell escribe .\\ delante del .ps1. El archivo ya está en "
        "C:\\Program Files\\robin-client-monitor:"
    )
    d.code(
        "cd \"C:\\Program Files\\robin-client-monitor\"\n"
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\\install-service-windows.ps1\n"
        "sc.exe query robin-client-monitor"
    )
    d.para("El estado debe ser RUNNING.")

    d.heading("Día a día")
    d.para("Linux:", bold=True, fill=NAVY)
    d.code(
        "sudo systemctl status robin-client-monitor\n"
        "sudo systemctl restart robin-client-monitor\n"
        "sudo systemctl stop robin-client-monitor\n"
        "sudo journalctl -u robin-client-monitor -f"
    )
    d.para("Windows:", bold=True, fill=NAVY)
    d.code(
        "sc.exe query robin-client-monitor\n"
        "& \"C:\\Program Files\\robin-client-monitor\\nssm\\nssm.exe\" status robin-client-monitor\n"
        "& \"C:\\Program Files\\robin-client-monitor\\nssm\\nssm.exe\" restart robin-client-monitor\n"
        "& \"C:\\Program Files\\robin-client-monitor\\nssm\\nssm.exe\" stop robin-client-monitor"
    )

    d.heading("Desinstalar")
    d.para("Linux:", bold=True, fill=NAVY)
    d.code(
        "sudo systemctl disable --now robin-client-monitor\n"
        "sudo rm -f /etc/systemd/system/robin-client-monitor.service\n"
        "sudo systemctl daemon-reload\n"
        "sudo rm -rf /opt/robin-client-monitor"
    )
    d.para("Windows:", bold=True, fill=NAVY)
    d.code(
        "& \"C:\\Program Files\\robin-client-monitor\\nssm\\nssm.exe\" stop robin-client-monitor\n"
        "& \"C:\\Program Files\\robin-client-monitor\\nssm\\nssm.exe\" remove robin-client-monitor confirm\n"
        "Remove-Item -Recurse -Force \"C:\\Program Files\\robin-client-monitor\""
    )

    d.heading("Si algo falla")
    d.table(
        [
            ("Qué ves", "Qué hacer"),
            (
                "Cannot find path ...\\system32\\robin-client-monitor.exe",
                "Estás en C:\\Windows\\system32. Usa $src y copia el bloque entero.",
            ),
            (
                "Cannot find path C:\\Program Files\\robin-client-monitor.exe",
                "$src está vacío. Ejecuta primero $src = \"C:\\ruta\\del\\exe\".",
            ),
            (
                "install-service-windows.bat is not recognized",
                "cd \"C:\\Program Files\\robin-client-monitor\" y ejecuta .\\install-service-windows.ps1",
            ),
            (
                "--self-test distinto de 0",
                "El paquete está incompleto. Pídelo de nuevo.",
            ),
            (
                "Acceso denegado / Permission denied",
                "Repite los comandos como Administrator / sudo.",
            ),
            (
                "Connection refused o timeout",
                "El servidor no es alcanzable. Avísale al administrador.",
            ),
            (
                "El servicio arranca y se cae",
                "Avísale a quien te entregó el paquete (red o certificados).",
            ),
        ]
    )
    d.para(
        "No edites config_client.json ni los certificados. Si el servicio corre y el equipo "
        "no sale en la consola de monitoreo, es red o servidor: avisa a quien te entregó el paquete.",
        fill=MUTED,
        size=15,
    )

    total = len(d.pages)
    for i, page in enumerate(d.pages, 1):
        draw = ImageDraw.Draw(page)
        label = f"{i} / {total}"
        font = fnt(13)
        tw = draw.textlength(label, font=font)
        draw.text((W - MARGIN - tw, H - 34), label, font=font, fill=MUTED)

    first, rest = d.pages[0], d.pages[1:]
    first.save(OUT, save_all=True, append_images=rest, resolution=150.0)
    print(f"OK {OUT} ({total} páginas)")


if __name__ == "__main__":
    build()
