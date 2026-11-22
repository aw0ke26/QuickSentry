"""File-level scanning: heuristics + Microsoft Defender + optional YARA."""
from __future__ import annotations

import glob
import os
import re
import stat
import subprocess
import sys
import threading
from dataclasses import dataclass, field

HIGH, MEDIUM, LOW = "high", "medium", "low"

EXEC_EXT = {
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".ps1", ".psm1", ".hta", ".msi", ".msp", ".jar", ".dll", ".cpl",
    ".reg", ".inf", ".application", ".appref-ms", ".gadget", ".msc", ".scf", ".url",
}
MACRO_EXT = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".ppam", ".sldm"}
DECOY_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt",
             ".mp3", ".mp4", ".zip", ".ppt", ".pptx", ".gif"}
LOLBINS = [b"cmd.exe", b"powershell", b"pwsh", b"rundll32", b"mshta", b"wscript", b"cscript",
           b"regsvr32", b"certutil", b"bitsadmin", b"msiexec", b"schtasks", b"curl", b"-enc"]
RTLO = "‮"

MAX_FILES = 25_000
MAX_SNIFF = 64 * 1024
MAX_YARA_BYTES = 50 * 1024 * 1024


@dataclass
class Finding:
    severity: str
    path: str
    reason: str

    def to_text(self) -> str:
        return f"[{self.severity.upper()}] {self.reason} — {self.path}"


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    truncated: bool = False
    defender: str = "not run"          # "clean" | "threats" | "unavailable" | "error: ..."
    defender_threats: list[str] = field(default_factory=list)
    cancelled: bool = False

    @property
    def verdict(self) -> str:
        if self.defender == "threats" or any(f.severity == HIGH for f in self.findings):
            return "dangerous"
        if any(f.severity == MEDIUM for f in self.findings):
            return "suspicious"
        return "clean"


def _lower_ext(name: str) -> str:
    return os.path.splitext(name)[1].lower()


def _is_hidden(path: str) -> bool:
    try:
        attrs = os.stat(path, follow_symlinks=False).st_file_attributes  # Windows only
        return bool(attrs & (stat.FILE_ATTRIBUTE_HIDDEN | stat.FILE_ATTRIBUTE_SYSTEM))
    except (AttributeError, OSError):
        return os.path.basename(path).startswith(".")


def _sniff(path: str, n: int = MAX_SNIFF) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(n)
    except OSError:
        return b""


def _contains_lolbin(data: bytes) -> list[str]:
    low = data.lower()
    utf16 = data.replace(b"\x00", b"").lower()
    return sorted({b.decode() for b in LOLBINS if b in low or b in utf16})


def heuristic_scan(root: str, cancel: threading.Event | None = None,
                   progress=None) -> ScanResult:
    res = ScanResult()
    root = os.path.abspath(root)
    root_entries = set()
    try:
        root_entries = {e.lower() for e in os.listdir(root)}
    except OSError:
        pass

    # Classic USB worm trick: hide real folders, drop same-named .lnk files.
    for name in root_entries:
        if name.endswith(".lnk"):
            stem = name[:-4]
            full = os.path.join(root, stem)
            if stem in root_entries and os.path.isdir(full) and _is_hidden(full):
                res.findings.append(Finding(HIGH, os.path.join(root, name),
                                            "Shortcut impersonating a hidden folder (USB worm pattern)"))

    for dirpath, dirnames, filenames in os.walk(root):
        if cancel and cancel.is_set():
            res.cancelled = True
            return res
        dirnames[:] = [d for d in dirnames if d.lower() != "system volume information"]
        at_root = os.path.normcase(dirpath) == os.path.normcase(root)
        for fn in filenames:
            if res.files_scanned >= MAX_FILES:
                res.truncated = True
                return res
            res.files_scanned += 1
            if progress and res.files_scanned % 200 == 0:
                progress(res.files_scanned)
            path = os.path.join(dirpath, fn)
            low = fn.lower()
            ext = _lower_ext(low)

            if RTLO in fn:
                res.findings.append(Finding(HIGH, path, "Right-to-left override in filename (disguised extension)"))

            if at_root and low == "autorun.inf":
                txt = _sniff(path, 8192).decode("utf-8", "ignore").lower()
                cmd = re.findall(r"^\s*(open|shellexecute|shell\\[^=]*\\command)\s*=\s*(.+)$", txt, re.M)
                detail = f" (launches: {cmd[0][1].strip()[:60]})" if cmd else ""
                res.findings.append(Finding(HIGH if cmd else MEDIUM, path, "autorun.inf present" + detail))
                continue

            stem_ext = _lower_ext(os.path.splitext(low)[0])
            if ext in EXEC_EXT and stem_ext in DECOY_EXT:
                res.findings.append(Finding(HIGH, path, f"Double extension ({stem_ext}{ext}) — disguised executable"))
                continue

            if ext == ".lnk":
                hits = _contains_lolbin(_sniff(path))
                if hits:
                    res.findings.append(Finding(HIGH, path, "Shortcut runs " + ", ".join(hits)))
                elif at_root:
                    res.findings.append(Finding(LOW, path, "Shortcut at drive root"))
                continue

            if ext in EXEC_EXT:
                sev = MEDIUM
                why = f"Executable/script ({ext})"
                if ext in {".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".wsf"}:
                    hits = _contains_lolbin(_sniff(path, 16384))
                    if "-enc" in hits or ("powershell" in hits and ext != ".ps1"):
                        sev, why = HIGH, f"Script launches {', '.join(hits)}"
                if at_root and _is_hidden(path):
                    sev, why = HIGH, why + ", hidden at drive root"
                res.findings.append(Finding(sev, path, why))
                continue

            if ext in MACRO_EXT:
                res.findings.append(Finding(MEDIUM, path, "Macro-enabled Office document"))
                continue

            head = _sniff(path, 2)
            if head == b"MZ":
                res.findings.append(Finding(HIGH, path, f"Windows executable hiding as '{ext or 'no extension'}'"))
    return res


# ---- Microsoft Defender ------------------------------------------------------
def find_mpcmdrun() -> str | None:
    if sys.platform != "win32":
        return None
    platform_dirs = sorted(glob.glob(os.path.expandvars(
        r"%ProgramData%\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe")), reverse=True)
    for c in platform_dirs + [os.path.expandvars(r"%ProgramFiles%\Windows Defender\MpCmdRun.exe")]:
        if os.path.isfile(c):
            return c
    return None


def defender_scan(path: str, res: ScanResult, timeout: int = 900) -> None:
    exe = find_mpcmdrun()
    if not exe:
        res.defender = "unavailable"
        return
    target = path if path.endswith("\\") else path + "\\"
    try:
        cp = subprocess.run(
            [exe, "-Scan", "-ScanType", "3", "-File", target, "-DisableRemediation"],
            capture_output=True, text=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except subprocess.TimeoutExpired:
        res.defender = "error: timed out"
        return
    except OSError as e:
        res.defender = f"error: {e}"
        return
    out = (cp.stdout or "") + (cp.stderr or "")
    if cp.returncode == 0:
        res.defender = "clean"
    elif cp.returncode == 2:
        res.defender = "threats"
        res.defender_threats = [ln.strip() for ln in out.splitlines()
                                if ln.strip().lower().startswith(("threat", "file", "resources"))][:20]
    else:
        msg = out.strip().splitlines()[-1] if out.strip() else f"exit {cp.returncode}"
        # 0x80508023 = Defender not the active AV (third-party AV installed)
        res.defender = "unavailable" if "0x80508023" in out else f"error: {msg[:120]}"


# ---- YARA (optional) ----------------------------------------------------------
def yara_scan(root: str, rules_dir: str, res: ScanResult, cancel: threading.Event | None = None) -> None:
    try:
        import yara  # type: ignore
    except ImportError:
        return
    files = glob.glob(os.path.join(rules_dir, "*.yar")) + glob.glob(os.path.join(rules_dir, "*.yara"))
    if not files:
        return
    try:
        rules = yara.compile(filepaths={os.path.basename(f): f for f in files})
    except Exception:
        return
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            if cancel and cancel.is_set():
                return
            p = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(p) > MAX_YARA_BYTES:
                    continue
                for m in rules.match(p, timeout=20):
                    res.findings.append(Finding(HIGH, p, f"YARA rule '{m.rule}' matched"))
            except Exception:
                continue


def full_scan(root: str, rules_dir: str, use_defender: bool = True,
              cancel: threading.Event | None = None, progress=None) -> ScanResult:
    res = heuristic_scan(root, cancel, progress)
    if res.cancelled:
        return res
    yara_scan(root, rules_dir, res, cancel)
    if use_defender and not (cancel and cancel.is_set()):
        if progress:
            progress(-1)  # signal "Defender pass"
        defender_scan(root, res)
    return res
