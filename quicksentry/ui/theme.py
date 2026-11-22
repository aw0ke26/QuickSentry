"""'Y2K hacker' palette: gunmetal chrome, acid lime, ultraviolet, hot magenta."""
from PySide6.QtGui import QColor, QFont

BG0 = "#05070d"
BG1 = "#0b1020"
BG2 = "#121a30"
STEEL_HI = "#8e9bbd"
STEEL = "#3a4566"
STEEL_LO = "#161d33"
LIME = "#b6ff3b"
VIOLET = "#8b5cff"
MAGENTA = "#ff3fd2"
AMBER = "#ffb627"
RED = "#ff3358"
TEXT = "#dfe6ff"
DIM = "#7f8bb3"

LEVEL = {  # level -> (color, word)
    "ok": (LIME, "SECURE"),
    "info": ("#8fa6ff", "INFO"),
    "warn": (AMBER, "CAUTION"),
    "alert": (RED, "ALERT"),
    "unknown": (DIM, "…"),
    "off": (DIM, "OFF"),
}
THREAT = {"ok": "LOW", "info": "LOW", "warn": "ELEVATED", "alert": "CRITICAL", "unknown": "STANDBY", "off": "STANDBY"}
RANK = {"off": 0, "unknown": 0, "ok": 1, "info": 1, "warn": 2, "alert": 3}


def col(c, a=255):
    q = QColor(c)
    q.setAlpha(a)
    return q


def tech(size, bold=True):
    f = QFont("Bahnschrift")
    f.setFamilies(["Bahnschrift", "Eurostile", "Segoe UI", "DejaVu Sans"])
    f.setPointSizeF(size)
    f.setBold(bold)
    f.setLetterSpacing(QFont.AbsoluteSpacing, 1.2)
    return f


def mono(size):
    f = QFont("Consolas")
    f.setFamilies(["Consolas", "Lucida Console", "DejaVu Sans Mono"])
    f.setPointSizeF(size)
    return f


def body(size, bold=False):
    f = QFont("Segoe UI")
    f.setFamilies(["Segoe UI", "DejaVu Sans"])
    f.setPointSizeF(size)
    f.setBold(bold)
    return f


QSS = f"""
QWidget {{ color: {TEXT}; font-family: 'Segoe UI'; font-size: 9pt; }}
QTreeWidget, QPlainTextEdit, QTextEdit {{
  background: rgba(4,7,16,190); border: 1px solid rgba(139,92,255,90); border-radius: 6px;
  selection-background-color: rgba(139,92,255,140); selection-color: white;
  alternate-background-color: rgba(255,255,255,8); font-family: Consolas; font-size: 9pt;
}}
QTreeWidget::item {{ padding: 3px 2px; border: none; }}
QTreeWidget::item:selected {{ background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 rgba(139,92,255,170), stop:1 rgba(255,63,210,60)); }}
QHeaderView::section {{
  background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #2a3352, stop:0.5 #1a2038, stop:1 #10152a);
  color: {LIME}; border: none; border-right: 1px solid #05070d; padding: 4px 6px;
  font-family: Bahnschrift; font-weight: bold; font-size: 8.5pt; letter-spacing: 1px;
}}
QLineEdit, QSpinBox, QComboBox {{
  background: #070b17; border: 1px solid {STEEL}; border-radius: 10px; padding: 4px 10px;
  color: {LIME}; font-family: Consolas; selection-background-color: {VIOLET};
}}
QLineEdit:focus, QSpinBox:focus, QComboBox:focus {{ border: 1px solid {LIME}; }}
QComboBox::drop-down {{ border: none; width: 18px; }}
QComboBox QAbstractItemView {{ background: #0b1020; border: 1px solid {VIOLET}; color: {TEXT};
  selection-background-color: {VIOLET}; }}
QSpinBox::up-button, QSpinBox::down-button {{ width: 0; }}
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{ border-radius: 4px; min-height: 26px;
  background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 {VIOLET}, stop:1 {MAGENTA}); }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle:horizontal {{ border-radius: 4px; min-width: 26px; background: {VIOLET}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: none; }}
QSplitter::handle {{ background: transparent; }}
QProgressBar {{ background: #070b17; border: 1px solid {STEEL}; border-radius: 8px; height: 14px;
  text-align: center; color: white; font-family: Consolas; font-size: 8pt; }}
QProgressBar::chunk {{ border-radius: 7px;
  background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #e4ff9e, stop:0.5 {LIME}, stop:0.51 #8fd61a, stop:1 #c9ff6b); }}
QToolTip {{ background: #0b1020; color: {TEXT}; border: 1px solid {VIOLET}; padding: 4px; }}
QMenu {{ background: #0b1020; border: 1px solid {VIOLET}; }}
QMenu::item:selected {{ background: {VIOLET}; }}
QLabel#dim {{ color: {DIM}; }}
"""
