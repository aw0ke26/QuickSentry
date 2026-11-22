"""QuickSentry v3 entry point.

    QuickSentry.exe                 normal run (requires administrator; the exe asks via UAC)
    QuickSentry.exe --demo          UI preview with fake data; touches nothing, no admin needed
    QuickSentry.exe --diagnostics   write a diagnostics report and exit
    QuickSentry.exe --tray          start hidden in the system tray (used by the sign-in autostart)
    QuickSentry.exe --cleanup       release quarantined drives + undo Strict mode, then exit (uninstaller)
"""
import ctypes
import os
import subprocess
import sys


_MUTEX = None   # held for the life of the process


def _relaunch_elevated():
    if getattr(sys, "frozen", False):
        exe, args = sys.executable, sys.argv[1:]
    else:
        exe, args = sys.executable, sys.argv
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, subprocess.list2cmdline(args), None, 1)
    return rc > 32


def main():
    demo = "--demo" in sys.argv or sys.platform != "win32"
    if demo:
        import tempfile
        os.environ.setdefault("QUICKSENTRY_DATA", os.path.join(tempfile.gettempdir(), "QuickSentry-demo"))

    from . import actions, storage, winapi
    if "--diagnostics" in sys.argv:
        out = actions.diagnostics()
        path = os.path.join(storage.reports_dir(), "diagnostics.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(out)
        try:
            print(out)
        except Exception:
            pass
        return 0

    if "--cleanup" in sys.argv:
        if sys.platform == "win32" and not winapi.is_admin():
            return 1
        from .guard.hardware import cleanup_system
        for line in cleanup_system():
            storage.log_line("[CLEANUP] " + line)
        return 0

    if not demo and not winapi.is_admin():
        if _relaunch_elevated():
            return 0
        ctypes.windll.user32.MessageBoxW(
            0, "QuickSentry needs administrator rights to guard USB/hardware, watch connections and "
               "protect its own logs.\n\nRight-click QuickSentry.exe > Run as administrator.\n"
               "(To just preview the interface, run it with --demo.)", "QuickSentry", 0x30)
        return 1

    if not demo:
        # one copy only: two keyboard hooks / device gates would fight each other
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateMutexW.restype = ctypes.c_void_p
        global _MUTEX
        _MUTEX = k32.CreateMutexW(None, False, "Global\\QuickSentry.SingleInstance")
        if ctypes.get_last_error() == 183:   # ERROR_ALREADY_EXISTS
            ctypes.windll.user32.MessageBoxW(
                0, "QuickSentry is already running. Look for its icon in the system tray.", "QuickSentry", 0x40)
            return 0

    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication(sys.argv)
    app.setApplicationName("QuickSentry")
    app.setQuitOnLastWindowClosed(False)

    from .ui.main_window import MainWindow
    from .ui.theme import QSS
    app.setStyleSheet(QSS)
    app.setWindowIcon(MainWindow.app_icon())
    win = MainWindow(demo=demo)
    if "--tray" in sys.argv and win.tray:
        win.winId()                     # create the native window so device events still arrive
    else:
        win.show()
    win.register_device_events()
    rc = app.exec()
    os._exit(rc)   # don't let a stuck helper thread keep the process alive


if __name__ == "__main__":
    sys.exit(main())
