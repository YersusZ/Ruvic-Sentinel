#!/usr/bin/env python3
"""Genera docs/instalacion-windows-usuario.pdf a partir de las capturas."""
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent
IMG = ROOT / "images" / "instalacion-windows"
OUT = ROOT / "instalacion-windows-usuario.pdf"

# A4 @ 150 dpi
W, H = 1240, 1754
MARGIN = 72
CONTENT_W = W - 2 * MARGIN
NAVY = (15, 55, 95)
TEAL = (0, 110, 140)
GRAY = (55, 55, 55)
MUTED = (90, 90, 90)
LINE = (210, 218, 226)
WHITE = (255, 255, 255)
SOFT = (245, 248, 251)
RED = (140, 40, 40)

FONT_R = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
FONT_B = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"


def font(size, bold=False):
    return ImageFont.truetype(FONT_B if bold else FONT_R, size)


def new_page():
    img = Image.new("RGB", (W, H), WHITE)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 18], fill=NAVY)
    d.rectangle([0, H - 48, W, H], fill=SOFT)
    d.text(
        (MARGIN, H - 34),
        "Robin Client Monitor  ·  Guía de instalación para Windows",
        font=font(14),
        fill=MUTED,
    )
    return img, d


def wrap(draw, text, fnt, max_w):
    words = text.split()
    lines, cur = [], ""
    for w in words:
        trial = (cur + " " + w).strip()
        if draw.textlength(trial, font=fnt) <= max_w:
            cur = trial
        else:
            if cur:
                lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return lines or [""]


def add_text(draw, y, text, *, size=18, bold=False, fill=GRAY, width=None):
    fnt = font(size, bold)
    max_w = width or CONTENT_W
    lines = wrap(draw, text, fnt, max_w)
    for line in lines:
        draw.text((MARGIN, y), line, font=fnt, fill=fill)
        y += int(size * 1.45)
    return y


def add_bullets(draw, y, items, *, size=17):
    fnt = font(size)
    for item in items:
        lines = wrap(draw, item, fnt, CONTENT_W - 28)
        draw.ellipse([MARGIN + 4, y + 8, MARGIN + 14, y + 18], fill=TEAL)
        for i, line in enumerate(lines):
            x = MARGIN + 28
            draw.text((x, y), line, font=fnt, fill=GRAY)
            y += int(size * 1.45)
        y += 6
    return y


def add_steps(draw, y, items, *, size=17):
    fnt = font(size)
    n = 1
    for item in items:
        lines = wrap(draw, item, fnt, CONTENT_W - 36)
        draw.text((MARGIN, y), f"{n}.", font=font(size, True), fill=TEAL)
        for line in lines:
            draw.text((MARGIN + 36, y), line, font=fnt, fill=GRAY)
            y += int(size * 1.45)
        y += 6
        n += 1
    return y


def add_heading(draw, y, text):
    y += 8
    draw.text((MARGIN, y), text, font=font(22, True), fill=NAVY)
    y += 34
    draw.line([MARGIN, y, W - MARGIN, y], fill=LINE, width=2)
    return y + 16


def paste_shot(page, y, path, caption, max_h=620):
    d = ImageDraw.Draw(page)
    shot = Image.open(path).convert("RGB")
    max_w = CONTENT_W
    ratio = min(max_w / shot.width, max_h / shot.height)
    nw, nh = max(1, int(shot.width * ratio)), max(1, int(shot.height * ratio))
    shot = shot.resize((nw, nh), Image.Resampling.LANCZOS)
    x = MARGIN + (CONTENT_W - nw) // 2
    d.rectangle([x - 2, y - 2, x + nw + 2, y + nh + 2], outline=LINE, width=2)
    page.paste(shot, (x, y))
    y = y + nh + 10
    cap_f = font(13)
    tw = d.textlength(caption, font=cap_f)
    d.text(((W - tw) / 2, y), caption, font=cap_f, fill=MUTED)
    return y + 28


def footer_page(page, num, total):
    d = ImageDraw.Draw(page)
    label = f"{num} / {total}"
    fnt = font(13)
    tw = d.textlength(label, font=fnt)
    d.text((W - MARGIN - tw, H - 34), label, font=fnt, fill=MUTED)


def build():
    pages = []

    # --- Portada / intro ---
    p, d = new_page()
    y = 56
    d.text((MARGIN, y), "Robin Client Monitor", font=font(36, True), fill=NAVY)
    y += 50
    d.text((MARGIN, y), "Guía de instalación para Windows", font=font(22), fill=TEAL)
    y += 40
    d.line([MARGIN, y, W - MARGIN, y], fill=TEAL, width=3)
    y += 28
    y = add_text(
        d,
        y,
        "Esta guía es para quien recibe el instalador. No hace falta configurar "
        "certificados, tokens ni la línea de comandos: el administrador ya dejó "
        "eso listo en el paquete.",
        size=18,
    )
    y += 10
    y = add_text(
        d,
        y,
        "Qué vas a instalar: un programa que se conecta al servidor de monitoreo "
        "y queda corriendo en segundo plano, también al reiniciar el PC.",
        size=18,
    )
    y += 10
    y = add_text(
        d,
        y,
        "Qué debes recibir: un solo archivo, robin-client-monitor-setup.exe.",
        size=18,
        bold=True,
        fill=NAVY,
    )
    y = add_heading(d, y + 8, "Antes de empezar")
    y = add_bullets(
        d,
        y,
        [
            "Windows 10 u 11, 64 bits.",
            "Cuenta con permiso de administrador (Windows lo pedirá al iniciar).",
            "Conexión a internet o a la red de la empresa, según te indique quien te entregó el instalador.",
        ],
    )
    y += 8
    y = add_text(
        d,
        y,
        "Si Windows Defender o SmartScreen avisa que el origen es desconocido, "
        "elige Más información → Ejecutar de todas formas (solo si el archivo te lo dio tu administrador).",
        size=16,
        fill=MUTED,
    )
    y = add_heading(d, y + 12, "Paso 1 — Abrir el instalador")
    y = add_steps(
        d,
        y,
        [
            "Localiza robin-client-monitor-setup (puede verse sin la extensión .exe).",
            "Haz doble clic.",
            "Si aparece el control de cuentas de usuario (UAC), pulsa Sí.",
        ],
    )
    y = paste_shot(
        p, y, IMG / "01-ejecutar-setup.png", "Archivo del instalador"
    )
    pages.append(p)

    # --- Paso 2 ---
    p, d = new_page()
    y = add_heading(d, 50, "Paso 2 — Listo para instalar")
    y = add_text(
        d,
        y,
        "Cuando veas Listo para Instalar, pulsa Instalar. La carpeta por defecto "
        "es C:\\Program Files\\robin-client-monitor. No hace falta cambiarla.",
        size=18,
    )
    y += 8
    y = paste_shot(
        p, y, IMG / "02-listo-para-instalar.png", "Pantalla «Listo para Instalar»", max_h=900
    )
    pages.append(p)

    # --- Paso 3 ---
    p, d = new_page()
    y = add_heading(d, 50, "Paso 3 — Esperar a que termine")
    y = add_text(
        d,
        y,
        "Verás Instalando y una barra de progreso. En este momento el instalador "
        "copia el programa, crea el servicio de Windows Robin Client Monitor y lo arranca solo.",
        size=18,
    )
    y += 6
    y = add_text(
        d,
        y,
        "No cierres la ventana ni pulses Cancelar.",
        size=18,
        bold=True,
        fill=RED,
    )
    y += 8
    y = paste_shot(
        p, y, IMG / "03-instalando.png", "Copia de archivos en curso", max_h=860
    )
    pages.append(p)

    # --- Paso 4 ---
    p, d = new_page()
    y = add_heading(d, 50, "Paso 4 — Finalizar")
    y = add_text(
        d,
        y,
        "Cuando aparezca Completando la instalación de Robin Client Monitor, pulsa Finalizar.",
        size=18,
    )
    y += 8
    y = paste_shot(
        p, y, IMG / "04-finalizar.png", "Instalación completada", max_h=780
    )
    y = add_text(
        d,
        y,
        "Listo. El monitor ya está en ejecución. No hace falta abrirlo a mano ni dejar una ventana abierta.",
        size=18,
        bold=True,
        fill=NAVY,
    )
    pages.append(p)

    # --- Comprobar ---
    p, d = new_page()
    y = add_heading(d, 50, "Comprobar que funciona")
    y = add_steps(
        d,
        y,
        [
            "Pulsa Win y escribe Servicios.",
            "Abre Servicios.",
            "Busca Robin Client Monitor.",
            "Debe estar seleccionado y, a la izquierda, deben aparecer Detener el servicio y Reiniciar el servicio. Eso significa que está en ejecución.",
        ],
    )
    y += 4
    y = paste_shot(
        p, y, IMG / "05-servicio.png", "Servicio Robin Client Monitor en ejecución", max_h=780
    )
    y = add_text(
        d,
        y,
        "Si no aparece, vuelve a ejecutar el setup como administrador. Si aparece detenido: clic derecho → Iniciar.",
        size=16,
        fill=MUTED,
    )
    pages.append(p)

    # --- Extra ---
    p, d = new_page()
    y = add_heading(d, 50, "Qué no hace falta")
    y = add_bullets(
        d,
        y,
        [
            "No ejecutes el programa a mano en el día a día.",
            "No cambies archivos dentro de C:\\Program Files\\robin-client-monitor (config, certificados, carpeta enrollment).",
            "No hace falta un token ni un comando de registro: eso ya viene en el instalador.",
        ],
    )
    y = add_heading(d, y + 8, "Desinstalar")
    y = add_steps(
        d,
        y,
        [
            "Configuración → Aplicaciones → Aplicaciones instaladas.",
            "Busca Robin Client Monitor.",
            "Desinstalar. Eso detiene y elimina el servicio.",
        ],
    )
    y = add_heading(d, y + 8, "Si algo falla")

    rows = [
        ("Qué ves", "Qué hacer"),
        (
            "Windows pide administrador y cancelas",
            "Vuelve a abrir el setup y acepta. Sin eso no se crea el servicio.",
        ),
        (
            "SmartScreen bloquea el archivo",
            "Más información → Ejecutar de todas formas (si el archivo es de confianza).",
        ),
        (
            "El servicio no está en ejecución",
            "Inícialo desde Servicios, o reinstala.",
        ),
        (
            "El PC no tiene red",
            "El monitor reintenta solo cuando vuelva la conexión.",
        ),
    ]
    col1, col2 = int(CONTENT_W * 0.38), int(CONTENT_W * 0.62)
    row_f = font(14)
    header_f = font(14, True)
    for i, (a, b) in enumerate(rows):
        lines_a = wrap(d, a, header_f if i == 0 else row_f, col1 - 16)
        lines_b = wrap(d, b, header_f if i == 0 else row_f, col2 - 16)
        rh = max(len(lines_a), len(lines_b)) * 22 + 14
        bg = NAVY if i == 0 else (WHITE if i % 2 else SOFT)
        fg = WHITE if i == 0 else GRAY
        d.rectangle([MARGIN, y, W - MARGIN, y + rh], fill=bg)
        ya, yb = y + 8, y + 8
        for line in lines_a:
            d.text((MARGIN + 8, ya), line, font=header_f if i == 0 else row_f, fill=fg)
            ya += 22
        for line in lines_b:
            d.text((MARGIN + col1 + 8, yb), line, font=header_f if i == 0 else row_f, fill=fg)
            yb += 22
        y += rh

    y += 20
    y = add_text(
        d,
        y,
        "Si el servicio corre y aun así no aparece el equipo en la consola, avisa a quien te entregó el instalador (es un tema de red o de servidor, no de estos pasos).",
        size=16,
        fill=MUTED,
    )
    pages.append(p)

    total = len(pages)
    for i, page in enumerate(pages, 1):
        footer_page(page, i, total)

    first, rest = pages[0], pages[1:]
    first.save(OUT, save_all=True, append_images=rest, resolution=150.0)
    print(f"OK {OUT} ({total} páginas)")


if __name__ == "__main__":
    build()
