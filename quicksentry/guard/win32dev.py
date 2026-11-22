"""Win32 plumbing for the hardware guard (ctypes only, no extra packages).

Device notifications, device classification, enable/disable, volume mount
points, storage bus type, and the Kernel DMA Protection status.
Everything is guarded so the module imports on non-Windows (demo/tests).
"""
from __future__ import annotations

import ctypes
import string
import subprocess
import sys
import uuid

IS_WINDOWS = sys.platform == "win32"

WM_DEVICECHANGE = 0x0219
DBT_DEVICEARRIVAL = 0x8000
DBT_DEVICEREMOVECOMPLETE = 0x8004
DBT_DEVTYP_VOLUME = 0x0002
DBT_DEVTYP_DEVICEINTERFACE = 0x0005
DEVICE_NOTIFY_WINDOW_HANDLE = 0x0000
DEVICE_NOTIFY_ALL_INTERFACE_CLASSES = 0x0004

# Interface class GUIDs -> category
GUID_KEYBOARD = "884b96c3-56ef-11d1-bc8c-00a0c91405dd"
GUID_MOUSE = "378de44c-56ef-11d1-bc8c-00a0c91405dd"
GUID_NET = "cac88484-7515-4c03-82e6-71a87abac361"
GUID_VOLUME = "53f5630d-b6bf-11d0-94f2-00a0c91efb8b"
GUID_DISK = "53f56307-b6bf-11d0-94f2-00a0c91efb8b"
GUID_WPD = "6ac27878-a6fa-4155-ba85-f98f491d4f33"
GUID_CAMERA = "e5323777-f976-4f5b-9b55-b94699c46e44"
GUID_AUDIO = "6994ad04-93ef-11d0-a3cc-00a0c9223196"
GUID_MONITOR = "e6f07b5f-ee97-4a90-b076-33f57bf4eaa7"
GUID_COMPORT = "86e0d1e0-8089-11d0-9ce4-08003e301f73"
GUID_USBPRINT = "28d78fad-5a12-11d1-ae5b-0000f803a8c2"
GUID_SMARTCARD = "50dd5230-ba8a-11d1-bf5d-0000f805f530"
GUID_USB_DEVICE = "a5dcbf10-6530-11d2-901f-00c04fb951ed"
GUID_USB_HUB = "f18a0e88-c30c-11d0-8815-00a0c906bed8"

CATEGORY_BY_GUID = {
    GUID_KEYBOARD: "keyboard", GUID_MOUSE: "mouse", GUID_NET: "network", GUID_VOLUME: "storage",
    GUID_WPD: "phone", GUID_CAMERA: "camera", GUID_AUDIO: "audio", GUID_MONITOR: "display",
    GUID_COMPORT: "serial", GUID_USBPRINT: "printer", GUID_SMARTCARD: "smartcard",
    GUID_USB_DEVICE: "usb_other",
}
CATEGORY_LABELS = {
    "keyboard": "Keyboard", "mouse": "Mouse / pointer", "network": "Network adapter",
    "storage": "Storage drive", "phone": "Phone / camera (MTP)", "thunderbolt": "Thunderbolt / PCIe",
    "bluetooth": "Bluetooth device", "camera": "Webcam", "audio": "Audio device",
    "display": "Display", "serial": "Serial / COM port", "printer": "Printer",
    "smartcard": "Smart card reader", "usb_other": "Other USB device",
}
SOFTWARE_BUSES = ("ROOT", "SWD", "HTREE", "SW", "ACPI", "UMB", "STORAGE")

BUS_USB, BUS_SD, BUS_MMC = 0x07, 0x0C, 0x0D
PORTABLE_BUSES = {BUS_USB, BUS_SD, BUS_MMC}
BUS_NAMES = {BUS_USB: "USB", BUS_SD: "SD card", BUS_MMC: "MMC"}
DRIVE_REMOVABLE = 2


class GUID(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_ulong), ("Data2", ctypes.c_ushort),
                ("Data3", ctypes.c_ushort), ("Data4", ctypes.c_ubyte * 8)]

    @classmethod
    def from_str(cls, s):
        g = cls()
        ctypes.memmove(ctypes.byref(g), uuid.UUID(s).bytes_le, 16)
        return g

    def __str__(self):
        return str(uuid.UUID(bytes_le=bytes(self)))


class DEV_BROADCAST_HDR(ctypes.Structure):
    _fields_ = [("dbch_size", ctypes.c_ulong), ("dbch_devicetype", ctypes.c_ulong),
                ("dbch_reserved", ctypes.c_ulong)]


class DEV_BROADCAST_DEVICEINTERFACE_W(ctypes.Structure):
    _fields_ = [("dbcc_size", ctypes.c_ulong), ("dbcc_devicetype", ctypes.c_ulong),
                ("dbcc_reserved", ctypes.c_ulong), ("dbcc_classguid", GUID),
                ("dbcc_name", ctypes.c_wchar * 1)]


class DEV_BROADCAST_VOLUME(ctypes.Structure):
    _fields_ = [("dbcv_size", ctypes.c_ulong), ("dbcv_devicetype", ctypes.c_ulong),
                ("dbcv_reserved", ctypes.c_ulong), ("dbcv_unitmask", ctypes.c_ulong),
                ("dbcv_flags", ctypes.c_ushort)]


class STORAGE_PROPERTY_QUERY(ctypes.Structure):
    _fields_ = [("PropertyId", ctypes.c_ulong), ("QueryType", ctypes.c_ulong),
                ("AdditionalParameters", ctypes.c_ubyte * 1)]


class STORAGE_DEVICE_DESCRIPTOR(ctypes.Structure):
    _fields_ = [("Version", ctypes.c_ulong), ("Size", ctypes.c_ulong),
                ("DeviceType", ctypes.c_ubyte), ("DeviceTypeModifier", ctypes.c_ubyte),
                ("RemovableMedia", ctypes.c_ubyte), ("CommandQueueing", ctypes.c_ubyte),
                ("VendorIdOffset", ctypes.c_ulong), ("ProductIdOffset", ctypes.c_ulong),
                ("ProductRevisionOffset", ctypes.c_ulong), ("SerialNumberOffset", ctypes.c_ulong),
                ("BusType", ctypes.c_ulong), ("RawPropertiesLength", ctypes.c_ulong)]


if IS_WINDOWS:
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    cfgmgr32 = ctypes.WinDLL("cfgmgr32")
    ntdll = ctypes.WinDLL("ntdll")

    user32.RegisterDeviceNotificationW.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
    user32.RegisterDeviceNotificationW.restype = wintypes.HANDLE
    user32.UnregisterDeviceNotification.argtypes = [wintypes.HANDLE]
    kernel32.GetVolumeNameForVolumeMountPointW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    kernel32.DeleteVolumeMountPointW.argtypes = [wintypes.LPCWSTR]
    kernel32.SetVolumeMountPointW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
    kernel32.GetVolumePathNamesForVolumeNameW.argtypes = [
        wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
    kernel32.GetLogicalDrives.restype = wintypes.DWORD
    kernel32.GetVolumeInformationW.argtypes = [
        wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]
    kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                     wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                         ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                                         ctypes.c_void_p]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    cfgmgr32.CM_Locate_DevNodeW.argtypes = [ctypes.POINTER(wintypes.DWORD), wintypes.LPCWSTR, wintypes.ULONG]
    cfgmgr32.CM_Get_Parent.argtypes = [ctypes.POINTER(wintypes.DWORD), wintypes.DWORD, wintypes.ULONG]
    cfgmgr32.CM_Get_Device_IDW.argtypes = [wintypes.DWORD, wintypes.LPWSTR, wintypes.ULONG, wintypes.ULONG]
    cfgmgr32.CM_Get_DevNode_Registry_PropertyW.argtypes = [
        wintypes.DWORD, wintypes.ULONG, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.POINTER(wintypes.ULONG), wintypes.ULONG]
    cfgmgr32.CM_Disable_DevNode.argtypes = [wintypes.DWORD, wintypes.ULONG]
    cfgmgr32.CM_Enable_DevNode.argtypes = [wintypes.DWORD, wintypes.ULONG]

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400
CM_LOCATE_DEVNODE_NORMAL = 0
CM_DRP_DEVICEDESC, CM_DRP_FRIENDLYNAME, CM_DRP_MFG = 0x01, 0x0D, 0x0C
CM_DISABLE_PERSIST = 0x08
CR_SUCCESS = 0


def _quiet(args, timeout=30):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception:
        return None


# ---------------------------------------------------------------- notifications
def register_all_interfaces(hwnd: int):
    """One registration that delivers arrivals for EVERY device interface class."""
    if not IS_WINDOWS:
        return None
    f = DEV_BROADCAST_DEVICEINTERFACE_W()
    f.dbcc_size = ctypes.sizeof(DEV_BROADCAST_DEVICEINTERFACE_W)
    f.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE
    return user32.RegisterDeviceNotificationW(
        hwnd, ctypes.byref(f), DEVICE_NOTIFY_WINDOW_HANDLE | DEVICE_NOTIFY_ALL_INTERFACE_CLASSES)


def unregister(handle):
    if IS_WINDOWS and handle:
        user32.UnregisterDeviceNotification(handle)


def letters_from_mask(mask: int):
    return [string.ascii_uppercase[i] for i in range(26) if mask & (1 << i)]


def parse_device_change(wparam: int, lparam: int):
    """-> ("arrival"|"removal", "volume", [letters]) or (..., "interface", (guid, path)) or None"""
    if wparam == DBT_DEVICEARRIVAL:
        event = "arrival"
    elif wparam == DBT_DEVICEREMOVECOMPLETE:
        event = "removal"
    else:
        return None
    if not lparam:
        return None
    hdr = DEV_BROADCAST_HDR.from_address(lparam)
    if hdr.dbch_devicetype == DBT_DEVTYP_VOLUME:
        return event, "volume", letters_from_mask(DEV_BROADCAST_VOLUME.from_address(lparam).dbcv_unitmask)
    if hdr.dbch_devicetype == DBT_DEVTYP_DEVICEINTERFACE:
        di = DEV_BROADCAST_DEVICEINTERFACE_W.from_address(lparam)
        name = ctypes.wstring_at(lparam + DEV_BROADCAST_DEVICEINTERFACE_W.dbcc_name.offset)
        return event, "interface", (str(di.dbcc_classguid).lower(), name)
    return None


# ---------------------------------------------------------------- classification
def interface_path_to_instance_id(path: str) -> str:
    r"""'\\?\HID#VID_1234&PID_5678#7&abc&0&0000#{guid}' -> 'HID\VID_1234&PID_5678\7&abc&0&0000'"""
    p = path
    for prefix in ("\\\\?\\", "\\??\\", "\\\\.\\"):
        if p.startswith(prefix):
            p = p[len(prefix):]
    parts = p.split("#")
    if len(parts) >= 4 and parts[-1].startswith("{"):
        parts = parts[:-1]
    return "\\".join(parts[:3]).upper() if len(parts) >= 3 else p.upper()


def bus_of(instance_id: str) -> str:
    return instance_id.split("\\", 1)[0].upper()


def vid_pid(s: str) -> str:
    up = s.upper()
    vid = up.split("VID_", 1)[1][:4] if "VID_" in up else ""
    pid = up.split("PID_", 1)[1][:4] if "PID_" in up else ""
    return f"{vid}:{pid}" if vid else ""


def categorize(class_guid: str, instance_id: str) -> str | None:
    """Map an interface arrival to a guard category, or None to ignore."""
    bus = bus_of(instance_id)
    if class_guid in (GUID_USB_HUB, GUID_DISK):
        return None
    cat = CATEGORY_BY_GUID.get(class_guid)
    if cat in ("keyboard", "mouse", "audio", "network", "storage", "phone", "camera", "display",
               "serial", "printer", "smartcard"):
        return cat
    if bus.startswith("BTH"):
        return "bluetooth"
    if bus in ("PCI", "THUNDERBOLT", "USB4"):
        return "thunderbolt"
    if cat == "usb_other":
        return cat
    return None


def is_software(instance_id: str) -> bool:
    return bus_of(instance_id) in SOFTWARE_BUSES


# ---------------------------------------------------------------- devnodes
def _devnode(instance_id: str):
    if not IS_WINDOWS:
        return None
    dn = wintypes.DWORD(0)
    if cfgmgr32.CM_Locate_DevNodeW(ctypes.byref(dn), instance_id, CM_LOCATE_DEVNODE_NORMAL) == CR_SUCCESS:
        return dn.value
    return None


def _device_id(dn: int) -> str:
    buf = ctypes.create_unicode_buffer(512)
    if cfgmgr32.CM_Get_Device_IDW(dn, buf, 512, 0) == CR_SUCCESS:
        return buf.value
    return ""


def device_name(instance_id: str) -> str:
    dn = _devnode(instance_id)
    if dn is None:
        return ""
    for prop in (CM_DRP_FRIENDLYNAME, CM_DRP_DEVICEDESC):
        buf = ctypes.create_unicode_buffer(512)
        size = wintypes.ULONG(ctypes.sizeof(buf))
        if cfgmgr32.CM_Get_DevNode_Registry_PropertyW(dn, prop, None, buf, ctypes.byref(size), 0) == CR_SUCCESS:
            if buf.value:
                return buf.value
    return ""


def physical_root(instance_id: str) -> str:
    """Walk up the device tree to the physical USB device (the composite parent),
    so a 'flash drive' that is secretly also a keyboard groups as ONE thing."""
    dn = _devnode(instance_id)
    if dn is None:
        return instance_id
    best = instance_id
    for _ in range(8):
        did = _device_id(dn).upper()
        if did.startswith("USB\\") and "&MI_" not in did:
            return did
        if did.startswith(("BTHENUM\\", "BTHLE\\", "BTHLEDEVICE\\", "PCI\\", "THUNDERBOLT\\")):
            best = did
        parent = wintypes.DWORD(0)
        if cfgmgr32.CM_Get_Parent(ctypes.byref(parent), dn, 0) != CR_SUCCESS:
            break
        dn = parent.value
        if _device_id(dn).upper().startswith("HTREE"):
            break
    return best


def set_device_enabled(instance_id: str, enabled: bool, persist: bool = False) -> bool:
    """Disable/enable a device. Tries cfgmgr32 first, then pnputil."""
    if not IS_WINDOWS:
        return False
    dn = _devnode(instance_id)
    if dn is not None:
        rc = (cfgmgr32.CM_Enable_DevNode(dn, 0) if enabled
              else cfgmgr32.CM_Disable_DevNode(dn, CM_DISABLE_PERSIST if persist else 0))
        if rc == CR_SUCCESS:
            return True
    cp = _quiet(["pnputil", "/enable-device" if enabled else "/disable-device", instance_id])
    return bool(cp and cp.returncode == 0)


def dma_protection() -> bool | None:
    """Kernel DMA Protection (blocks Thunderbolt/PCIe memory attacks). None = unknown."""
    if not IS_WINDOWS:
        return None
    try:
        val = ctypes.c_ubyte(0)
        ret = ctypes.c_ulong(0)
        status = ntdll.NtQuerySystemInformation(202, ctypes.byref(val), 1, ctypes.byref(ret))
        return bool(val.value) if status == 0 else None
    except Exception:
        return None


# ---------------------------------------------------------------- volumes
def get_volume_guid(mount_point: str):
    if not IS_WINDOWS:
        return None
    buf = ctypes.create_unicode_buffer(64)
    if not mount_point.endswith("\\"):
        mount_point += "\\"
    return buf.value if kernel32.GetVolumeNameForVolumeMountPointW(mount_point, buf, 64) else None


def get_volume_paths(vol_guid: str):
    if not IS_WINDOWS:
        return []
    size = wintypes.DWORD(0)
    buf = ctypes.create_unicode_buffer(1024)
    if not kernel32.GetVolumePathNamesForVolumeNameW(vol_guid, buf, 1024, ctypes.byref(size)):
        return []
    return [p for p in ctypes.wstring_at(ctypes.addressof(buf), size.value).split("\x00") if p]


def delete_mount_point(path: str) -> bool:
    if not IS_WINDOWS:
        return False
    return bool(kernel32.DeleteVolumeMountPointW(path if path.endswith("\\") else path + "\\"))


def set_mount_point(path: str, vol_guid: str) -> bool:
    if not IS_WINDOWS:
        return False
    return bool(kernel32.SetVolumeMountPointW(path if path.endswith("\\") else path + "\\", vol_guid))


def used_letters():
    return set(letters_from_mask(kernel32.GetLogicalDrives())) if IS_WINDOWS else set()


def free_letter(preferred=None):
    used = used_letters()
    if preferred and preferred not in used:
        return preferred
    return next((L for L in "DEFGHIJKLMNOPQRSTUVWXYZ" if L not in used), None)


def drive_type(root: str) -> int:
    return kernel32.GetDriveTypeW(root) if IS_WINDOWS else 0


def volume_label(root: str):
    if not IS_WINDOWS:
        return "", ""
    label, fs = ctypes.create_unicode_buffer(261), ctypes.create_unicode_buffer(261)
    if kernel32.GetVolumeInformationW(root, label, 261, None, None, None, fs, 261):
        return label.value, fs.value
    return "", ""


def storage_info(vol_guid: str) -> dict:
    info = {"bus": None, "removable": False, "vendor": "", "product": ""}
    if not IS_WINDOWS:
        return info
    h = kernel32.CreateFileW(vol_guid.rstrip("\\"), 0, 3, None, 3, 0, None)
    if not h or h == INVALID_HANDLE_VALUE:
        return info
    try:
        q = STORAGE_PROPERTY_QUERY(0, 0)
        out = ctypes.create_string_buffer(1024)
        got = wintypes.DWORD(0)
        if kernel32.DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, ctypes.byref(q), ctypes.sizeof(q),
                                    out, 1024, ctypes.byref(got), None):
            d = STORAGE_DEVICE_DESCRIPTOR.from_buffer(out)
            info["bus"], info["removable"] = d.BusType, bool(d.RemovableMedia)

            def _s(off):
                if off and off < got.value:
                    return out.raw[off:].split(b"\x00", 1)[0].decode("ascii", "ignore").strip()
                return ""
            info["vendor"], info["product"] = _s(d.VendorIdOffset), _s(d.ProductIdOffset)
    finally:
        kernel32.CloseHandle(h)
    return info


def is_portable_volume(vol_guid: str, root: str | None = None):
    info = storage_info(vol_guid)
    if info["bus"] in PORTABLE_BUSES:
        return True, info
    for r in (root, vol_guid):
        if r and drive_type(r) == DRIVE_REMOVABLE:
            return True, info
    return False, info
