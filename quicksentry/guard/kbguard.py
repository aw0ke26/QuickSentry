"""Keyboard guard: a low-level keyboard hook that can freeze all typing.

Why: a BadUSB / Rubber Ducky is a "keyboard" that types an attack in
milliseconds. File scanning never sees it. So when a new keyboard shows up
(or typing is inhumanly fast) we swallow every keystroke until a human
proves themselves by typing a random code shown on screen, or clicking
Unlock with the mouse.
"""
from __future__ import annotations

import collections
import ctypes
import random
import statistics
import threading

from PySide6.QtCore import QObject, Signal

from .win32dev import IS_WINDOWS

WH_KEYBOARD_LL = 13
HC_ACTION = 0
WM_KEYDOWN, WM_KEYUP, WM_SYSKEYDOWN, WM_SYSKEYUP = 0x0100, 0x0101, 0x0104, 0x0105
WM_QUIT = 0x0012
LLKHF_INJECTED = 0x10
VK_BACK = 0x08

CODE_ALPHABET = "ACDEFHJKLMNPRTUVWXY3479"   # no look-alikes (0/O, 1/I, 5/S ...)
SPEED_WINDOW = 12            # keystrokes considered
SPEED_TRIP_MS = 12           # median gap below this = not a human
HUMAN_MIN_GAP_MS = 35        # unlock code must be typed at least this slowly

if IS_WINDOWS:
    from ctypes import wintypes

    LRESULT = ctypes.c_ssize_t

    class KBDLLHOOKSTRUCT(ctypes.Structure):
        _fields_ = [("vkCode", wintypes.DWORD), ("scanCode", wintypes.DWORD),
                    ("flags", wintypes.DWORD), ("time", wintypes.DWORD),
                    ("dwExtraInfo", ctypes.c_size_t)]

    HOOKPROC = ctypes.WINFUNCTYPE(LRESULT, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM)
    _user32 = ctypes.WinDLL("user32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _user32.SetWindowsHookExW.argtypes = [ctypes.c_int, HOOKPROC, wintypes.HINSTANCE, wintypes.DWORD]
    _user32.SetWindowsHookExW.restype = wintypes.HHOOK
    _user32.CallNextHookEx.argtypes = [wintypes.HHOOK, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM]
    _user32.CallNextHookEx.restype = LRESULT
    _user32.UnhookWindowsHookEx.argtypes = [wintypes.HHOOK]
    _user32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
    _user32.PostThreadMessageW.argtypes = [wintypes.DWORD, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    _kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    _kernel32.GetModuleHandleW.restype = wintypes.HMODULE


def _vk_to_char(vk: int) -> str | None:
    if 0x30 <= vk <= 0x39 or 0x41 <= vk <= 0x5A:
        return chr(vk)
    if 0x60 <= vk <= 0x69:       # numpad digits
        return chr(vk - 0x30)
    return None


def new_code(n: int = 4) -> str:
    return "".join(random.SystemRandom().choice(CODE_ALPHABET) for _ in range(n))


class KeyboardGuard(QObject):
    locked_changed = Signal(bool, str, str)   # locked?, reason, code
    unlocked_by_code = Signal()
    hook_failed = Signal(str)

    def __init__(self):
        super().__init__()
        self.locked = False
        self.code = ""
        self.speed_trap = True
        self._buf: collections.deque = collections.deque(maxlen=8)
        self._times: collections.deque = collections.deque(maxlen=SPEED_WINDOW + 1)
        self._down: set[int] = set()
        self._thread: threading.Thread | None = None
        self._tid = 0
        self._hook = None
        self._proc_ref = None

    # -- public API (called from the Qt thread) --
    def start(self):
        if not IS_WINDOWS or self._thread:
            return
        self._thread = threading.Thread(target=self._run, name="kbguard", daemon=True)
        self._thread.start()

    def stop(self):
        self.locked = False
        if IS_WINDOWS and self._tid:
            _user32.PostThreadMessageW(self._tid, WM_QUIT, 0, 0)

    def lock(self, reason: str):
        if self.locked:
            return
        self.code = new_code()
        self._buf.clear()
        self.locked = True
        self.locked_changed.emit(True, reason, self.code)

    def unlock(self):
        if not self.locked:
            return
        self.locked = False
        self._times.clear()
        self.locked_changed.emit(False, "", "")

    # -- hook thread --
    def _run(self):
        self._tid = _kernel32.GetCurrentThreadId()
        self._proc_ref = HOOKPROC(self._proc)
        self._hook = _user32.SetWindowsHookExW(WH_KEYBOARD_LL, self._proc_ref,
                                               _kernel32.GetModuleHandleW(None), 0)
        if not self._hook:
            self.hook_failed.emit(f"SetWindowsHookEx failed ({ctypes.get_last_error()})")
            return
        msg = wintypes.MSG()
        while _user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            _user32.TranslateMessage(ctypes.byref(msg))
            _user32.DispatchMessageW(ctypes.byref(msg))
        _user32.UnhookWindowsHookEx(self._hook)
        self._hook = None

    def _proc(self, n_code, w_param, l_param):
        try:
            if n_code == HC_ACTION:
                kb = KBDLLHOOKSTRUCT.from_address(l_param)
                down = w_param in (WM_KEYDOWN, WM_SYSKEYDOWN)
                injected = bool(kb.flags & LLKHF_INJECTED)
                if not down:
                    self._down.discard(kb.vkCode)

                if self.locked:
                    if down and not injected:
                        self._feed_code(kb.vkCode, kb.time)
                    return 1                       # swallow everything

                if down and not injected and kb.vkCode not in self._down:
                    self._down.add(kb.vkCode)
                    if self.speed_trap and self._too_fast(kb.time):
                        # Freeze immediately (inside the hook), then tell the UI.
                        self.code = new_code()
                        self._buf.clear()
                        self.locked = True
                        self.locked_changed.emit(True, "Inhumanly fast typing detected", self.code)
                        return 1
        except Exception:
            pass
        return _user32.CallNextHookEx(None, n_code, w_param, l_param)

    def _too_fast(self, t_ms: int) -> bool:
        self._times.append(t_ms)
        if len(self._times) <= SPEED_WINDOW:
            return False
        ts = list(self._times)
        gaps = [(b - a) & 0xFFFFFFFF for a, b in zip(ts, ts[1:])]
        return statistics.median(gaps) < SPEED_TRIP_MS

    def _feed_code(self, vk: int, t_ms: int):
        if vk == VK_BACK:
            self._buf.clear()
            return
        ch = _vk_to_char(vk)
        if not ch:
            return
        self._buf.append((ch, t_ms))
        n = len(self.code)
        if len(self._buf) < n:
            return
        tail = list(self._buf)[-n:]
        if "".join(c for c, _ in tail) != self.code:
            return
        gaps = [((b - a) & 0xFFFFFFFF) for (_, a), (_, b) in zip(tail, tail[1:])]
        if all(g >= HUMAN_MIN_GAP_MS for g in gaps):
            self.locked = False
            self._times.clear()
            self.unlocked_by_code.emit()
            self.locked_changed.emit(False, "", "")
        else:
            self._buf.clear()
