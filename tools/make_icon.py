"""Regenerate assets/QuickSentry.ico from quicksentry/ui/icon.py.  Run: python tools/make_icon.py"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from PySide6.QtGui import QGuiApplication  # noqa: E402

app = QGuiApplication.instance() or QGuiApplication(sys.argv)
from quicksentry.ui.icon import write_ico  # noqa: E402

out = os.path.join(ROOT, "assets", "QuickSentry.ico")
write_ico(out)
print("wrote", out)
