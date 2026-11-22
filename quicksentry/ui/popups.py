"""Always-on-top popups: keyboard freeze, device hold, and alert toasts."""
from __future__ import annotations

import math
import time

from PySide6.QtCore import QPointF, QRectF, Qt, QTimer, Signal
from PySide6.QtGui import QGuiApplication, QLinearGradient, QPainter, QPainterPath, QPen, QRadialGradient
from PySide6.QtWidgets import QHBoxLayout, QLabel, QVBoxLayout, QWidget

from ..guard.win32dev import CATEGORY_LABELS
from .theme import AMBER, DIM, LEVEL, LIME, MAGENTA, RED, TEXT, VIOLET, col, mono, tech
from .widgets import GelButton, chamfer, gel, neon_text, scanlines


class _Frameless(QWidget):
    def __init__(self, w, h):
        super().__init__(None, Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.Tool)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setFixedSize(w, h)
        self._t = 0.0
        self._tm = QTimer(self)
        self._tm.timeout.connect(self._tick)

    def _tick(self):
        self._t += 0.04
        self.update()

    def center_on_screen(self):
        scr = QGuiApplication.primaryScreen().availableGeometry()
        self.move(scr.center().x() - self.width() // 2, scr.center().y() - self.height() // 2)

    def frame(self, p, accent, cut=26):
        r = QRectF(self.rect()).adjusted(8, 8, -8, -8)
        path = chamfer(r, cut)
        a = int(90 + 80 * abs(math.sin(self._t * 3)))
        for wpx, al in ((16, a // 5), (9, a // 2)):
            p.setPen(QPen(col(accent, al), wpx)); p.drawPath(path)
        g = QLinearGradient(r.topLeft(), r.bottomLeft())
        g.setColorAt(0, col("#151032")); g.setColorAt(1, col("#05040d"))
        p.fillPath(path, g)
        p.save(); p.setClipPath(path)
        p.setPen(QPen(col(accent, 18), 12))
        off = (self._t * 40) % 36
        for x in range(-self.height(), self.width() + 36, 36):
            p.drawLine(QPointF(x + off, self.height()), QPointF(x + off + self.height(), 0))
        scanlines(p, r, 50, 3)
        p.restore()
        p.setPen(QPen(col(accent), 2)); p.drawPath(path)
        return r


class KbLockPopup(_Frameless):
    allow = Signal()
    block = Signal()

    def __init__(self):
        super().__init__(640, 430)
        self.code, self.reason = "----", ""
        self.b_allow = GelButton("It's mine — unlock", "#3f9d00", self, h=42, w=230)
        self.b_block = GelButton("Block this device", RED, self, h=42, w=230)
        self.b_allow.move(80, 352); self.b_block.move(330, 352)
        self.b_allow.clicked.connect(self.allow.emit)
        self.b_block.clicked.connect(self.block.emit)

    def show_lock(self, reason, code):
        self.reason, self.code = reason, code
        self.center_on_screen()
        self._tm.start(40)
        self.show(); self.raise_()

    def hide_lock(self):
        self._tm.stop()
        self.hide()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = self.frame(p, MAGENTA)
        w = self.width()
        blink = int(self._t * 3) % 2 == 0
        neon_text(p, QRectF(0, 34, w, 30), ("▲ " if blink else "  ") + "INJECTION GUARD ENGAGED" + (" ▲" if blink else "  "),
                  tech(17), MAGENTA, align=Qt.AlignHCenter | Qt.AlignVCenter)
        p.setFont(tech(10)); p.setPen(col(AMBER))
        p.drawText(QRectF(30, 70, w - 60, 22), Qt.AlignCenter, self.reason.upper())
        p.setFont(mono(9)); p.setPen(col(TEXT, 220))
        p.drawText(QRectF(50, 96, w - 100, 40), Qt.AlignCenter | Qt.TextWordWrap,
                   "ALL KEYSTROKES ARE BEING DROPPED. A FAKE KEYBOARD CAN'T SEE THIS SCREEN —\n"
                   "PROVE YOU'RE HUMAN: TYPE THE CODE BELOW (OR CLICK UNLOCK).")
        n = len(self.code)
        tw, gap = 70, 16
        x0 = w / 2 - (n * tw + (n - 1) * gap) / 2
        for i, ch in enumerate(self.code):
            tr = QRectF(x0 + i * (tw + gap), 150, tw, 90)
            tp = QPainterPath(); tp.addRoundedRect(tr, 16, 16)
            g = QLinearGradient(tr.topLeft(), tr.bottomLeft())
            g.setColorAt(0, col("#0c1a05")); g.setColorAt(1, col("#020502"))
            p.fillPath(tp, g)
            hl = QPainterPath(); hl.addRoundedRect(QRectF(tr.left() + 8, tr.top() + 3, tr.width() - 16, 26), 10, 10)
            p.fillPath(hl, col("#ffffff", 30))
            p.setPen(QPen(col(LIME, 200), 2)); p.drawPath(tp)
            neon_text(p, tr, ch, tech(40), LIME, align=Qt.AlignCenter)
        p.setFont(mono(8)); p.setPen(col(DIM))
        p.drawText(QRectF(40, 262, w - 80, 70), Qt.AlignCenter | Qt.TextWordWrap,
                   "Stuck? Ctrl+Alt+Del → Task Manager → end QuickSentry releases the keyboard.\n"
                   "BLOCK disables the device and remembers its ID.")


class DevicePrompt(_Frameless):
    """Lists devices on hold; one row per device with Allow / Always / Block."""
    allow = Signal(int, bool)
    block = Signal(int)

    def __init__(self):
        super().__init__(600, 200)
        self.lay = QVBoxLayout(self)
        self.lay.setContentsMargins(34, 74, 34, 28)
        self.lay.setSpacing(8)
        self.rows = []

    def set_pending(self, pending):
        for w in self.rows:
            w.setParent(None)
            w.deleteLater()
        self.rows = []
        for rec in pending[:5]:
            row = QWidget(self)
            h = QHBoxLayout(row); h.setContentsMargins(0, 0, 0, 0); h.setSpacing(6)
            lab = QLabel(f"<b style='color:{LIME}'>{CATEGORY_LABELS.get(rec['category'], rec['category']).upper()}</b>"
                         f"<br><span style='color:{TEXT}'>{rec['name'][:42]}</span> "
                         f"<span style='color:{DIM}'>{rec['vidpid']} · {rec['bus']}</span>")
            lab.setStyleSheet("font-family: Consolas; font-size: 8.5pt;")
            h.addWidget(lab, 1)
            for text, color, fn in (("Allow", "#3f9d00", lambda _=False, i=rec["id"]: self.allow.emit(i, False)),
                                    ("Always", VIOLET, lambda _=False, i=rec["id"]: self.allow.emit(i, True)),
                                    ("Block", RED, lambda _=False, i=rec["id"]: self.block.emit(i))):
                b = GelButton(text, color, row, h=32, w=78)
                b.clicked.connect(fn)
                h.addWidget(b)
            self.lay.addWidget(row)
            self.rows.append(row)
        if pending:
            self.setFixedSize(640, 120 + 54 * min(len(pending), 5))
            if not self.isVisible():
                self.center_on_screen()
            self._tm.start(40)
            self.show(); self.raise_()
        else:
            self._tm.stop()
            self.hide()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        self.frame(p, AMBER, 20)
        neon_text(p, QRectF(34, 22, self.width() - 68, 30), "NEW HARDWARE ON HOLD", tech(15), AMBER)
        p.setFont(mono(8)); p.setPen(col(DIM))
        p.drawText(QRectF(34, 48, self.width() - 68, 18), Qt.AlignLeft | Qt.AlignVCenter,
                   "Disabled until you decide. Didn't plug anything in? Block it.")


class AlertToast(_Frameless):
    """Bottom-right toast for alerts (replaces the old blocking MessageBox)."""
    clicked = Signal()

    def __init__(self):
        super().__init__(420, 150)
        self.title = self.msg = ""
        self.level = "alert"
        self._hide = QTimer(self); self._hide.setSingleShot(True); self._hide.timeout.connect(self.hide)

    def pop(self, e):
        self.title, self.msg, self.level = e["title"], e["message"], e["level"]
        scr = QGuiApplication.primaryScreen().availableGeometry()
        self.move(scr.right() - self.width() - 16, scr.bottom() - self.height() - 16)
        self._tm.start(40)
        self.show(); self.raise_()
        self._hide.start(12000)

    def mousePressEvent(self, e):
        self.hide()
        self.clicked.emit()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        c = LEVEL.get(self.level, LEVEL["alert"])[0]
        r = self.frame(p, c, 18)
        orb = QRectF(r.left() + 16, r.top() + 18, 34, 34)
        op = QPainterPath(); op.addEllipse(orb)
        gel(p, op, orb, c, 255, 200)
        p.setFont(tech(16)); p.setPen(col("#ffffff")); p.drawText(orb, Qt.AlignCenter, "!")
        neon_text(p, QRectF(r.left() + 62, r.top() + 14, r.width() - 72, 22), self.title.upper(), tech(10.5), c)
        p.setFont(mono(8.5)); p.setPen(col(TEXT))
        p.drawText(QRectF(r.left() + 62, r.top() + 40, r.width() - 76, r.height() - 52),
                   Qt.AlignLeft | Qt.AlignTop | Qt.TextWordWrap, self.msg[:220])
        p.setFont(mono(7.5)); p.setPen(col(DIM))
        p.drawText(QRectF(r.left(), r.bottom() - 18, r.width() - 14, 14), Qt.AlignRight, "click to open QuickSentry")
