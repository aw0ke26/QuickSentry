"""Hand-painted widgets for the dark Y2K 'hacker' look.

Bubbly bits: the radar dome, gel capsule nav pods, gel buttons, LED orbs,
the threat tube. Hard bits: chamfered gunmetal panels with HUD brackets.
"""
from __future__ import annotations

import math
import random

from PySide6.QtCore import (Property, QEasingCurve, QPointF, QPropertyAnimation, QRectF, Qt, QTimer,
                            Signal)
from PySide6.QtGui import (QConicalGradient, QCursor, QFontMetricsF, QLinearGradient, QPainter,
                           QPainterPath, QPen, QRadialGradient)
from PySide6.QtWidgets import QAbstractButton, QWidget

from .theme import (AMBER, BG1, DIM, LEVEL, LIME, MAGENTA, RED, STEEL, STEEL_HI, TEXT, THREAT, VIOLET, col,
                    mono, tech)


def chamfer(r: QRectF, c: float, corners=(1, 1, 1, 1)) -> QPainterPath:
    """Rect with 45° cut corners (tl, tr, br, bl)."""
    tl, tr, br, bl = [c * k for k in corners]
    p = QPainterPath()
    p.moveTo(r.left() + tl, r.top())
    p.lineTo(r.right() - tr, r.top())
    p.lineTo(r.right(), r.top() + tr)
    p.lineTo(r.right(), r.bottom() - br)
    p.lineTo(r.right() - br, r.bottom())
    p.lineTo(r.left() + bl, r.bottom())
    p.lineTo(r.left(), r.bottom() - bl)
    p.lineTo(r.left(), r.top() + tl)
    p.closeSubpath()
    return p


def gel(p: QPainter, path: QPainterPath, r: QRectF, color: str, alpha=255, shine=170):
    """Glossy gel fill: dark core, bright lip at the bottom, glass highlight on top."""
    c = col(color, alpha)
    g = QLinearGradient(r.topLeft(), r.bottomLeft())
    g.setColorAt(0, c.lighter(150))
    g.setColorAt(0.48, c)
    g.setColorAt(0.52, c.darker(135))
    g.setColorAt(1, c.lighter(125))
    p.fillPath(path, g)
    glow = QRadialGradient(QPointF(r.center().x(), r.bottom()), r.width() * 0.55)
    glow.setColorAt(0, col("#ffffff", 90))
    glow.setColorAt(1, col("#ffffff", 0))
    p.fillPath(path, glow)
    hl = QPainterPath()
    hl.addRoundedRect(QRectF(r.left() + r.height() * 0.25, r.top() + 2, r.width() - r.height() * 0.5,
                             r.height() * 0.42), r.height() * 0.2, r.height() * 0.2)
    hl = hl.intersected(path)
    hg = QLinearGradient(r.topLeft(), QPointF(r.left(), r.top() + r.height() * 0.45))
    hg.setColorAt(0, col("#ffffff", shine))
    hg.setColorAt(1, col("#ffffff", 10))
    p.fillPath(hl, hg)


def neon_text(p: QPainter, rect: QRectF, text: str, font, color: str, glow=True, align=Qt.AlignLeft | Qt.AlignVCenter):
    p.setFont(font)
    if glow:
        for dx, dy, a in ((0, 0, 70), (1, 0, 40), (-1, 0, 40), (0, 1, 40), (0, -1, 40)):
            p.setPen(col(color, a))
            p.drawText(rect.translated(dx * 1.5, dy * 1.5), align, text)
    p.setPen(col(color))
    p.drawText(rect, align, text)


def scanlines(p: QPainter, r: QRectF, alpha=14, step=3):
    p.setPen(QPen(col("#000000", alpha), 1))
    y = r.top()
    while y < r.bottom():
        p.drawLine(QPointF(r.left(), y), QPointF(r.right(), y))
        y += step


# =========================================================================== buttons
class GelButton(QAbstractButton):
    def __init__(self, text, color=VIOLET, parent=None, h=32, w=None):
        super().__init__(parent)
        self.setText(text)
        self._color = color
        self._hover = 0.0
        self.setCursor(Qt.PointingHandCursor)
        self.setFixedHeight(h)
        fm = QFontMetricsF(tech(9))
        self.setMinimumWidth(w or int(fm.horizontalAdvance(text.upper()) + 44))
        self._a = QPropertyAnimation(self, b"hover", self)
        self._a.setDuration(150)

    def _gh(self):
        return self._hover

    def _sh(self, v):
        self._hover = v
        self.update()

    hover = Property(float, _gh, _sh)

    def setColor(self, c):  # noqa: N802
        self._color = c
        self.update()

    def enterEvent(self, e):
        self._a.stop(); self._a.setEndValue(1.0); self._a.start()

    def leaveEvent(self, e):
        self._a.stop(); self._a.setEndValue(0.0); self._a.start()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = QRectF(self.rect()).adjusted(3, 3, -3, -3)
        if self.isDown():
            r.adjust(2, 1, -2, 0)
        rad = r.height() / 2
        path = QPainterPath()
        path.addRoundedRect(r, rad, rad)
        c = self._color if self.isEnabled() else STEEL
        if self._hover > 0:
            p.setPen(QPen(col(c, int(110 * self._hover)), 5))
            p.drawPath(path)
        gel(p, path, r, c, 235 if self.isEnabled() else 160)
        p.setPen(QPen(col("#000000", 160), 1))
        p.drawPath(path)
        p.setPen(QPen(col("#ffffff", 70), 1))
        p.drawRoundedRect(r.adjusted(1, 1, -1, -1), rad - 1, rad - 1)
        p.setFont(tech(9))
        p.setPen(col("#000000", 120))
        p.drawText(r.translated(0, 1), Qt.AlignCenter, self.text().upper())
        p.setPen(col("#ffffff" if self.isEnabled() else DIM))
        p.drawText(r, Qt.AlignCenter, self.text().upper())


class HexButton(QAbstractButton):
    """Chrome hexagon for window controls."""

    def __init__(self, glyph, color, parent=None, size=30):
        super().__init__(parent)
        self._g, self._c = glyph, color
        self.setFixedSize(size, size)
        self.setCursor(Qt.PointingHandCursor)
        self._hov = False

    def enterEvent(self, e):
        self._hov = True; self.update()

    def leaveEvent(self, e):
        self._hov = False; self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = QRectF(self.rect()).adjusted(2, 2, -2, -2)
        cx, cy, R = r.center().x(), r.center().y(), r.width() / 2
        path = QPainterPath()
        for i in range(6):
            a = math.radians(60 * i + 30)
            pt = QPointF(cx + R * math.cos(a), cy + R * math.sin(a))
            path.moveTo(pt) if i == 0 else path.lineTo(pt)
        path.closeSubpath()
        g = QLinearGradient(r.topLeft(), r.bottomLeft())
        g.setColorAt(0, col(STEEL_HI)); g.setColorAt(0.5, col(STEEL)); g.setColorAt(1, col("#1b2138"))
        p.fillPath(path, g)
        p.setPen(QPen(col(self._c if self._hov else "#000000", 255), 1.5))
        p.drawPath(path)
        p.setPen(QPen(col(self._c), 2.4, Qt.SolidLine, Qt.RoundCap))
        s = R * 0.35
        if self._g == "x":
            p.drawLine(QPointF(cx - s, cy - s), QPointF(cx + s, cy + s))
            p.drawLine(QPointF(cx + s, cy - s), QPointF(cx - s, cy + s))
        else:
            p.drawLine(QPointF(cx - s, cy + s * 0.5), QPointF(cx + s, cy + s * 0.5))


class LedOrb(QWidget):
    def __init__(self, color=LIME, parent=None, size=14):
        super().__init__(parent)
        self.color = color
        self.setFixedSize(size, size)
        self.blink = False
        self._on = True
        self._t = QTimer(self)
        self._t.timeout.connect(self._tick)
        self._t.start(450)

    def _tick(self):
        if self.blink:
            self._on = not self._on
            self.update()
        elif not self._on:
            self._on = True
            self.update()

    def set(self, color, blink=False):
        self.color, self.blink = color, blink
        self.update()

    def paintEvent(self, e):
        draw_led(QPainter(self), QRectF(self.rect()).adjusted(1, 1, -1, -1), self.color if self._on else STEEL)


def draw_led(p: QPainter, r: QRectF, color):
    p.setRenderHint(QPainter.Antialiasing)
    c = col(color)
    halo = QRadialGradient(r.center(), r.width())
    halo.setColorAt(0, col(color, 90)); halo.setColorAt(1, col(color, 0))
    p.setPen(Qt.NoPen)
    p.setBrush(halo)
    p.drawEllipse(r.center(), r.width() * 0.9, r.height() * 0.9)
    g = QRadialGradient(QPointF(r.center().x(), r.bottom() - r.height() * 0.2), r.width() * 0.7)
    g.setColorAt(0, c.lighter(170)); g.setColorAt(0.6, c); g.setColorAt(1, c.darker(200))
    p.setBrush(g)
    p.setPen(QPen(col("#000000", 200), 1))
    p.drawEllipse(r)
    p.setPen(Qt.NoPen)
    p.setBrush(col("#ffffff", 200))
    p.drawEllipse(QRectF(r.left() + r.width() * 0.22, r.top() + r.height() * 0.12, r.width() * 0.5, r.height() * 0.32))


class NavPod(QAbstractButton):
    """Capsule nav button with an LED that reflects that section's status."""

    def __init__(self, text, parent=None):
        super().__init__(parent)
        self.setText(text)
        self.setCheckable(True)
        self.setCursor(Qt.PointingHandCursor)
        self.setFixedHeight(44)
        self.led = LIME
        self.badge = 0
        self._hov = False

    def set_status(self, color, badge=0):
        self.led, self.badge = color, badge
        self.update()

    def enterEvent(self, e):
        self._hov = True; self.update()

    def leaveEvent(self, e):
        self._hov = False; self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = QRectF(self.rect()).adjusted(3, 4, -3, -4)
        rad = r.height() / 2
        path = QPainterPath()
        path.addRoundedRect(r, rad, rad)
        if self.isChecked():
            p.setPen(QPen(col(LIME, 90), 6)); p.drawPath(path)
            gel(p, path, r, "#4f8f00", 255, 140)
            p.setPen(QPen(col(LIME), 1.4))
        else:
            g = QLinearGradient(r.topLeft(), r.bottomLeft())
            g.setColorAt(0, col("#1e2744")); g.setColorAt(1, col("#0b1020"))
            p.fillPath(path, g)
            gel_hl = QPainterPath(); gel_hl.addRoundedRect(QRectF(r.left() + 14, r.top() + 2, r.width() - 28, r.height() * 0.4), 8, 8)
            p.fillPath(gel_hl.intersected(path), col("#ffffff", 22 if not self._hov else 45))
            p.setPen(QPen(col(VIOLET if self._hov else STEEL), 1.2))
        p.drawPath(path)
        draw_led(p, QRectF(r.left() + 12, r.center().y() - 6, 12, 12), self.led)
        p.setFont(tech(10))
        p.setPen(col("#ffffff" if self.isChecked() else TEXT))
        p.drawText(r.adjusted(34, 0, -8, 0), Qt.AlignVCenter | Qt.AlignLeft, self.text().upper())
        if self.badge:
            br = QRectF(r.right() - 34, r.center().y() - 9, 28, 18)
            bp = QPainterPath(); bp.addRoundedRect(br, 9, 9)
            gel(p, bp, br, MAGENTA, 255, 150)
            p.setFont(tech(8)); p.setPen(col("#ffffff"))
            p.drawText(br, Qt.AlignCenter, str(min(self.badge, 99)))


class GelToggle(QAbstractButton):
    def __init__(self, label, hint="", parent=None):
        super().__init__(parent)
        self.setCheckable(True)
        self._label, self._hint = label, hint
        self._pos = 0.0
        self.setCursor(Qt.PointingHandCursor)
        self.setFixedHeight(42 if hint else 30)
        self.setMinimumWidth(240)
        self._a = QPropertyAnimation(self, b"knob", self)
        self._a.setDuration(200)
        self._a.setEasingCurve(QEasingCurve.OutBack)
        self.toggled.connect(lambda on: (self._a.stop(), self._a.setEndValue(1.0 if on else 0.0), self._a.start()))
        if hint:
            self.setToolTip(hint)

    def _g(self):
        return self._pos

    def _s(self, v):
        self._pos = v; self.update()

    knob = Property(float, _g, _s)

    def setChecked(self, on):  # noqa: N802
        super().setChecked(on)
        self._a.stop(); self._pos = 1.0 if on else 0.0; self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        t = QRectF(2, 5, 46, 20)
        path = QPainterPath(); path.addRoundedRect(t, 10, 10)
        g = QLinearGradient(t.topLeft(), t.bottomLeft())
        g.setColorAt(0, col("#03050b")); g.setColorAt(1, col("#18203a"))
        p.fillPath(path, g)
        if self._pos > 0.02:
            fill = QRectF(t.left(), t.top(), t.width() * max(0.0, min(1.0, self._pos)), t.height())
            fp = QPainterPath(); fp.addRoundedRect(fill, 10, 10)
            gel(p, fp, fill, "#6fbf00", 255, 120)
        p.setPen(QPen(col(LIME if self.isChecked() else STEEL), 1)); p.drawPath(path)
        kx = t.left() + 1 + (t.width() - 20) * self._pos
        draw_led(p, QRectF(kx, t.top() + 1, 18, 18), "#e9ffe0" if self.isChecked() else "#8d96b4")
        p.setFont(tech(9.5)); p.setPen(col(TEXT))
        p.drawText(QRectF(58, 0, self.width() - 58, 30 if not self._hint else 22), Qt.AlignLeft | Qt.AlignVCenter,
                   self._label.upper())
        if self._hint:
            p.setFont(mono(7.5)); p.setPen(col(DIM))
            p.drawText(QRectF(58, 20, self.width() - 58, 18), Qt.AlignLeft | Qt.AlignVCenter, self._hint)


# =========================================================================== panels
class HudPanel(QWidget):
    """Chamfered smoked-glass slab with HUD corner brackets and a title tab."""

    def __init__(self, title="", parent=None, accent=VIOLET):
        super().__init__(parent)
        self.title, self.accent = title, accent

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = QRectF(self.rect()).adjusted(1, 1, -1, -1)
        body = chamfer(r.adjusted(0, 12 if self.title else 0, 0, 0), 14, (0, 1, 1, 1))
        g = QLinearGradient(r.topLeft(), r.bottomLeft())
        g.setColorAt(0, col("#10172c", 235)); g.setColorAt(1, col("#070a15", 235))
        p.fillPath(body, g)
        p.save(); p.setClipPath(body); scanlines(p, r, 22); p.restore()
        p.setPen(QPen(col(self.accent, 120), 1)); p.drawPath(body)
        # HUD brackets
        p.setPen(QPen(col(LIME, 200), 2))
        br = r.adjusted(4, (12 if self.title else 0) + 4, -4, -4)
        L = 14
        for (x, y, dx, dy) in ((br.right(), br.top(), -1, 1), (br.left(), br.bottom(), 1, -1)):
            p.drawLine(QPointF(x, y), QPointF(x + dx * L, y))
            p.drawLine(QPointF(x, y), QPointF(x, y + dy * L))
        if self.title:
            fm = QFontMetricsF(tech(9.5))
            tw = fm.horizontalAdvance(self.title.upper()) + 40
            tab = QRectF(r.left(), r.top(), tw, 26)
            tp = chamfer(tab, 10, (0, 1, 0, 0))
            gel(p, tp, tab, self.accent, 240, 120)
            p.setPen(QPen(col("#000000", 160), 1)); p.drawPath(tp)
            p.setFont(tech(9.5)); p.setPen(col("#ffffff"))
            p.drawText(tab.adjusted(12, 0, 0, 0), Qt.AlignVCenter | Qt.AlignLeft, "▸ " + self.title.upper())


class StatusPod(QWidget):
    """Gel capsule summarising one area (Network / Hardware / Connections)."""
    clicked = Signal()

    def __init__(self, title, parent=None):
        super().__init__(parent)
        self.title, self.level, self.line = title, "unknown", "standing by"
        self.setFixedHeight(64)
        self.setCursor(Qt.PointingHandCursor)

    def set(self, level, line):
        self.level, self.line = level, line
        self.update()

    def mousePressEvent(self, e):
        self.clicked.emit()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = QRectF(self.rect()).adjusted(3, 3, -3, -3)
        path = QPainterPath(); path.addRoundedRect(r, r.height() / 2, r.height() / 2)
        c = LEVEL.get(self.level, LEVEL["unknown"])[0]
        g = QLinearGradient(r.topLeft(), r.bottomLeft())
        g.setColorAt(0, col("#1b2340")); g.setColorAt(1, col("#070a15"))
        p.fillPath(path, g)
        tint = QRadialGradient(QPointF(r.left() + 30, r.center().y()), r.width() * 0.6)
        tint.setColorAt(0, col(c, 70)); tint.setColorAt(1, col(c, 0))
        p.fillPath(path, tint)
        hl = QPainterPath(); hl.addRoundedRect(QRectF(r.left() + 20, r.top() + 2, r.width() - 40, r.height() * 0.38), 10, 10)
        p.fillPath(hl.intersected(path), col("#ffffff", 26))
        p.setPen(QPen(col(c, 200), 1.4)); p.drawPath(path)
        draw_led(p, QRectF(r.left() + 16, r.center().y() - 10, 20, 20), c)
        neon_text(p, QRectF(r.left() + 46, r.top() + 6, r.width() - 50, 24), self.title.upper(), tech(10.5), c)
        p.setFont(mono(8)); p.setPen(col(TEXT, 210))
        fm = QFontMetricsF(mono(8))
        p.drawText(QRectF(r.left() + 46, r.top() + 30, r.width() - 56, 22), Qt.AlignLeft | Qt.AlignVCenter,
                   fm.elidedText(self.line, Qt.ElideRight, r.width() - 60))


class ThreatTube(QWidget):
    """Segmented gel tube: THREAT LEVEL."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.level = "unknown"
        self._t = 0.0
        self.setFixedSize(250, 54)
        tm = QTimer(self); tm.timeout.connect(self._tick); tm.start(60)

    def _tick(self):
        self._t += 0.06
        if self.level == "alert":
            self.update()

    def set(self, level):
        self.level = level
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        c = LEVEL.get(self.level, LEVEL["unknown"])[0]
        p.setFont(tech(8)); p.setPen(col(DIM))
        p.drawText(QRectF(4, 0, 120, 16), Qt.AlignLeft | Qt.AlignVCenter, "THREAT LEVEL")
        neon_text(p, QRectF(100, 0, 146, 18), THREAT.get(self.level, "STANDBY"), tech(10), c, align=Qt.AlignRight | Qt.AlignVCenter)
        tube = QRectF(2, 22, self.width() - 4, 26)
        tp = QPainterPath(); tp.addRoundedRect(tube, 13, 13)
        p.fillPath(tp, col("#03050b"))
        n = 10
        lit = {"ok": 3, "info": 3, "warn": 6, "alert": 10}.get(self.level, 0)
        pulse = 0.55 + 0.45 * abs(math.sin(self._t * 3)) if self.level == "alert" else 1.0
        sw = (tube.width() - 8) / n
        for i in range(n):
            seg = QRectF(tube.left() + 4 + i * sw, tube.top() + 4, sw - 3, tube.height() - 8)
            sp = QPainterPath(); sp.addRoundedRect(seg, 5, 5)
            if i < lit:
                sc = LIME if i < 3 else (AMBER if i < 6 else RED)
                gel(p, sp, seg, sc, int(255 * pulse), 150)
            else:
                p.fillPath(sp, col("#151b30"))
        hl = QPainterPath(); hl.addRoundedRect(QRectF(tube.left() + 10, tube.top() + 2, tube.width() - 20, 8), 4, 4)
        p.fillPath(hl, col("#ffffff", 40))
        p.setPen(QPen(col(STEEL_HI, 180), 1.2)); p.drawPath(tp)


class Ticker(QWidget):
    """Scrolling mono marquee of recent events — very 'hacker movie'."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.items = ["QUICKSENTRY v3 ONLINE", "ARP // ROUTE // DNS // TLS // USB // HID // NIC // PORTS"]
        self._x = 0.0
        self.setFixedHeight(22)
        tm = QTimer(self); tm.timeout.connect(self._tick); tm.start(30)

    def push(self, text, level="info"):
        self.items.append(("!! " if level == "alert" else "") + text.upper())
        self.items[:] = self.items[-8:]

    def _tick(self):
        self._x -= 1.2
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = QRectF(self.rect())
        path = QPainterPath(); path.addRoundedRect(r, 11, 11)
        p.fillPath(path, col("#02040a", 230))
        p.setPen(QPen(col(LIME, 80), 1)); p.drawPath(path)
        p.save(); p.setClipPath(path)
        text = "   ◆   ".join(self.items) + "   ◆   "
        f = mono(8.5)
        fm = QFontMetricsF(f)
        w = fm.horizontalAdvance(text)
        if self._x < -w:
            self._x += w
        p.setFont(f)
        x = self._x + 10
        while x < r.width():
            p.setPen(col(LIME, 70)); p.drawText(QPointF(x + 0.8, 15.8), text)
            p.setPen(col(LIME)); p.drawText(QPointF(x, 15), text)
            x += w
        scanlines(p, r, 60, 2)
        p.restore()


class RadarDome(QWidget):
    """The big glass bubble: a sweeping radar with a sentry eye in the middle."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.level = "unknown"
        self._ang = 0.0
        self._blips: list[list[float]] = []
        self._blink = 0.0
        self._look = QPointF(0, 0)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        tm = QTimer(self); tm.timeout.connect(self._tick); tm.start(33)

    def set_level(self, lvl):
        self.level = lvl

    def blip(self, level="info"):
        self._blips.append([random.uniform(0, 360), random.uniform(0.35, 0.92), 1.0,
                            LEVEL.get(level, LEVEL["info"])[0]])
        self._blips[:] = self._blips[-24:]

    def _tick(self):
        self._ang = (self._ang + 3.2) % 360
        for b in self._blips:
            b[2] = max(0.0, b[2] - 0.004)
        self._blips[:] = [b for b in self._blips if b[2] > 0]
        if self._blink > 0:
            self._blink = max(0.0, self._blink - 0.2)
        elif random.random() < 0.01:
            self._blink = 1.0
        c = self.mapToGlobal(self.rect().center())
        cur = QCursor.pos()
        dx, dy = cur.x() - c.x(), cur.y() - c.y()
        d = math.hypot(dx, dy) or 1
        k = min(1.0, d / 400)
        self._look = QPointF(self._look.x() + (dx / d * k - self._look.x()) * 0.2,
                             self._look.y() + (dy / d * k - self._look.y()) * 0.2)
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        s = min(self.width(), self.height()) - 8
        cx, cy, R = self.width() / 2, self.height() / 2, s / 2
        lc = LEVEL.get(self.level, LEVEL["unknown"])[0]
        dome = QPainterPath(); dome.addEllipse(QPointF(cx, cy), R, R)
        # chrome bezel
        bz = QConicalGradient(QPointF(cx, cy), 45)
        for i, c in enumerate((STEEL_HI, "#1a2038", "#c7d0ea", "#252d4a", STEEL_HI)):
            bz.setColorAt(i / 4, col(c))
        p.setPen(Qt.NoPen); p.setBrush(bz)
        p.drawEllipse(QPointF(cx, cy), R + 4, R + 4)
        # dark glass
        g = QRadialGradient(QPointF(cx, cy + R * 0.2), R * 1.1)
        g.setColorAt(0, col("#0d2a12")); g.setColorAt(0.7, col("#040b08")); g.setColorAt(1, col("#000000"))
        p.fillPath(dome, g)
        p.save(); p.setClipPath(dome)
        p.setPen(QPen(col(LIME, 55), 1)); p.setBrush(Qt.NoBrush)
        for k in (0.33, 0.66, 1.0):
            p.drawEllipse(QPointF(cx, cy), R * k, R * k)
        p.drawLine(QPointF(cx - R, cy), QPointF(cx + R, cy)); p.drawLine(QPointF(cx, cy - R), QPointF(cx, cy + R))
        sweep = QConicalGradient(QPointF(cx, cy), -self._ang)
        sweep.setColorAt(0.0, col(lc, 170)); sweep.setColorAt(0.12, col(lc, 0)); sweep.setColorAt(1.0, col(lc, 0))
        p.setBrush(sweep); p.setPen(Qt.NoPen)
        p.drawEllipse(QPointF(cx, cy), R, R)
        for a, dist, life, c in self._blips:
            x = cx + math.cos(math.radians(a)) * R * dist
            y = cy - math.sin(math.radians(a)) * R * dist
            hal = QRadialGradient(QPointF(x, y), 9)
            hal.setColorAt(0, col(c, int(220 * life))); hal.setColorAt(1, col(c, 0))
            p.setBrush(hal); p.drawEllipse(QPointF(x, y), 9, 9)
        scanlines(p, QRectF(cx - R, cy - R, 2 * R, 2 * R), 70, 2)
        p.restore()
        # sentry eye
        er = R * 0.26
        eye = QPainterPath(); eye.addEllipse(QPointF(cx, cy), er, er)
        eg = QRadialGradient(QPointF(cx, cy + er * 0.4), er * 1.2)
        eg.setColorAt(0, col("#ffffff")); eg.setColorAt(1, col("#9aa3c0"))
        p.fillPath(eye, eg)
        open_k = 1 - self._blink
        ix, iy = cx + self._look.x() * er * 0.38, cy + self._look.y() * er * 0.38
        if open_k > 0.25:
            iris = QRadialGradient(QPointF(ix, iy), er * 0.6)
            ic = {"alert": RED, "warn": AMBER}.get(self.level, VIOLET)
            iris.setColorAt(0, col(ic).lighter(160)); iris.setColorAt(0.7, col(ic)); iris.setColorAt(1, col(ic).darker(200))
            p.setBrush(iris); p.setPen(Qt.NoPen)
            p.drawEllipse(QPointF(ix, iy), er * 0.55, er * 0.55 * open_k)
            p.setBrush(col("#000000"))
            p.drawEllipse(QPointF(ix, iy), er * 0.22, er * 0.22 * open_k)
            p.setBrush(col("#ffffff", 220))
            p.drawEllipse(QPointF(ix - er * 0.15, iy - er * 0.18), er * 0.1, er * 0.1)
        if self._blink > 0:
            p.setBrush(col("#3a4566")); p.setPen(Qt.NoPen)
            lid = QRectF(cx - er, cy - er, 2 * er, 2 * er * self._blink)
            lp = QPainterPath(); lp.addRect(lid)
            p.fillPath(lp.intersected(eye), col("#3a4566"))
        p.setPen(QPen(col("#000000"), 1.5)); p.setBrush(Qt.NoBrush); p.drawEllipse(QPointF(cx, cy), er, er)
        # glass reflection (the 'bubble')
        hl = QPainterPath()
        hl.addEllipse(QRectF(cx - R * 0.62, cy - R * 0.9, R * 0.95, R * 0.5))
        hg = QLinearGradient(QPointF(cx, cy - R), QPointF(cx, cy - R * 0.2))
        hg.setColorAt(0, col("#ffffff", 75)); hg.setColorAt(1, col("#ffffff", 0))
        p.fillPath(hl.intersected(dome), hg)
        rim = QRadialGradient(QPointF(cx, cy), R)
        rim.setColorAt(0.85, col(lc, 0)); rim.setColorAt(1, col(lc, 120))
        p.fillPath(dome, rim)
