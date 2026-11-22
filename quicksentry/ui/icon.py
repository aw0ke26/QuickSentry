"""The QuickSentry icon: a chrome-bezel radar dome with a lime sweep and the violet sentry eye.

One renderer for every place the icon appears (window, tray, exe, installer), so they always
match. Small sizes drop fine detail and enlarge the eye so it still reads at 16 px.
Regenerate assets/QuickSentry.ico with:  python tools/make_icon.py
"""
from __future__ import annotations

import math

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import (QColor, QConicalGradient, QIcon, QImage, QLinearGradient, QPainter, QPainterPath,
                           QPen, QPixmap, QRadialGradient)

LIME = QColor("#b6ff3b")
VIOLET = QColor("#8b5cff")
MAGENTA = QColor("#ff3fd2")
SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)


def _c(hex_, a=255):
    q = QColor(hex_)
    q.setAlpha(a)
    return q


def render(size: int) -> QImage:
    img = QImage(size, size, QImage.Format_ARGB32_Premultiplied)
    img.fill(Qt.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.Antialiasing)
    p.scale(size / 256.0, size / 256.0)          # draw on a 256 canvas
    small = size <= 32
    tiny = size <= 20

    c = QPointF(128, 128)
    R_out = 124.0
    bezel = 22.0 if small else 16.0
    R = R_out - bezel                              # glass radius

    # --- drop shadow (big sizes only)
    if size >= 48:
        sh = QRadialGradient(QPointF(128, 136), R_out + 4)
        sh.setColorAt(0.85, _c("#000000", 110)); sh.setColorAt(1.0, _c("#000000", 0))
        p.setPen(Qt.NoPen); p.setBrush(sh)
        p.drawEllipse(QPointF(128, 136), R_out + 4, R_out + 4)

    # --- chrome bezel (conical metal)
    bz = QConicalGradient(c, 40)
    for t, col in ((0.0, "#e8edff"), (0.18, "#5d6a92"), (0.38, "#1a2140"), (0.55, "#c9d2ee"),
                   (0.72, "#38436a"), (0.9, "#9aa7cc"), (1.0, "#e8edff")):
        bz.setColorAt(t, _c(col))
    p.setBrush(bz)
    p.setPen(QPen(_c("#05070d"), 6 if small else 4))
    p.drawEllipse(c, R_out, R_out)
    # inner lip of the bezel
    p.setBrush(Qt.NoBrush)
    p.setPen(QPen(_c("#05070d"), 5 if small else 3))
    p.drawEllipse(c, R + 1, R + 1)

    # --- radar glass
    glass = QPainterPath()
    glass.addEllipse(c, R, R)
    g = QRadialGradient(QPointF(128, 150), R * 1.1)
    g.setColorAt(0.0, _c("#1f5a14")); g.setColorAt(0.55, _c("#082010")); g.setColorAt(1.0, _c("#010402"))
    p.fillPath(glass, g)

    p.save()
    p.setClipPath(glass)
    if not small:
        p.setBrush(Qt.NoBrush)
        p.setPen(QPen(_c("#b6ff3b", 70), 2.2))
        for k in (0.36, 0.68):
            p.drawEllipse(c, R * k, R * k)
        p.drawLine(QPointF(128 - R, 128), QPointF(128 + R, 128))
        p.drawLine(QPointF(128, 128 - R), QPointF(128, 128 + R))
    # sweep wedge (trailing fade), pointing up-right
    sweep = QConicalGradient(c, 52)
    sweep.setColorAt(0.0, _c("#b6ff3b", 235))
    sweep.setColorAt(0.16, _c("#b6ff3b", 40))
    sweep.setColorAt(0.25, _c("#b6ff3b", 0))
    sweep.setColorAt(1.0, _c("#b6ff3b", 0))
    p.setPen(Qt.NoPen); p.setBrush(sweep)
    p.drawEllipse(c, R, R)
    # leading edge line
    a = math.radians(52)
    p.setPen(QPen(_c("#eaffc0", 230), 6 if small else 3.5, Qt.SolidLine, Qt.RoundCap))
    p.drawLine(c, QPointF(128 + math.cos(a) * R, 128 - math.sin(a) * R))
    # blips
    if not tiny:
        for ang, dist, col, rad in ((30, 0.74, "#b6ff3b", 9), (160, 0.62, "#ff3fd2", 10), (250, 0.8, "#b6ff3b", 6)):
            if small and col == "#b6ff3b" and rad < 8:
                continue
            x = 128 + math.cos(math.radians(ang)) * R * dist
            y = 128 - math.sin(math.radians(ang)) * R * dist
            r = rad * (1.6 if small else 1.0)
            hal = QRadialGradient(QPointF(x, y), r * 2.2)
            hal.setColorAt(0, _c(col, 255)); hal.setColorAt(0.45, _c(col, 160)); hal.setColorAt(1, _c(col, 0))
            p.setBrush(hal); p.setPen(Qt.NoPen)
            p.drawEllipse(QPointF(x, y), r * 2.2, r * 2.2)
    p.restore()

    # --- sentry eye
    er = R * (0.5 if small else 0.36)
    eye = QPainterPath(); eye.addEllipse(c, er, er)
    eg = QRadialGradient(QPointF(128, 128 + er * 0.45), er * 1.25)
    eg.setColorAt(0, _c("#ffffff")); eg.setColorAt(0.7, _c("#dfe4f5")); eg.setColorAt(1, _c("#8790b0"))
    p.fillPath(eye, eg)
    ic = QPointF(128 + er * 0.12, 128 + er * 0.05)
    iris = QRadialGradient(ic, er * 0.62)
    iris.setColorAt(0, _c("#d9caff")); iris.setColorAt(0.55, VIOLET); iris.setColorAt(1, _c("#3a1a8f"))
    p.setBrush(iris); p.setPen(Qt.NoPen)
    p.drawEllipse(ic, er * 0.6, er * 0.6)
    p.setBrush(_c("#05030c"))
    p.drawEllipse(ic, er * 0.26, er * 0.26)
    p.setBrush(_c("#ffffff", 235))
    p.drawEllipse(QPointF(ic.x() - er * 0.2, ic.y() - er * 0.22), er * 0.11, er * 0.11)
    p.setBrush(Qt.NoBrush)
    p.setPen(QPen(_c("#05070d"), 5 if small else 3))
    p.drawEllipse(c, er, er)

    # --- glass dome highlight (the 'bubble')
    hl = QPainterPath()
    hl.addEllipse(QRectF(128 - R * 0.78, 128 - R * 0.95, R * 1.15, R * 0.62))
    hg = QLinearGradient(QPointF(128, 128 - R), QPointF(128, 128 - R * 0.35))
    hg.setColorAt(0, _c("#ffffff", 150 if small else 125)); hg.setColorAt(1, _c("#ffffff", 0))
    p.fillPath(hl.intersected(glass), hg)
    # lime rim glow
    rim = QRadialGradient(c, R)
    rim.setColorAt(0.82, _c("#b6ff3b", 0)); rim.setColorAt(1.0, _c("#b6ff3b", 110))
    p.fillPath(glass, rim)
    p.end()
    return img


def app_icon() -> QIcon:
    icon = QIcon()
    for s in SIZES:
        icon.addPixmap(QPixmap.fromImage(render(s)))
    return icon


def write_ico(path: str, sizes=(16, 20, 24, 32, 40, 48, 64, 128, 256)):
    """Multi-resolution .ico with PNG-compressed entries (Windows Vista+)."""
    import struct
    from PySide6.QtCore import QBuffer, QByteArray, QIODevice
    blobs = []
    for s in sizes:
        ba = QByteArray()
        buf = QBuffer(ba)
        buf.open(QIODevice.WriteOnly)
        render(s).save(buf, "PNG")
        blobs.append((s, bytes(ba)))
    header = struct.pack("<HHH", 0, 1, len(blobs))
    offset = 6 + 16 * len(blobs)
    entries, data = b"", b""
    for s, png in blobs:
        dim = 0 if s >= 256 else s
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(png), offset + len(data))
        data += png
    with open(path, "wb") as f:
        f.write(header + entries + data)
