"""Window icon and monitor-aware placement helpers."""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes
from pathlib import Path
from tkinter import TclError


MONITOR_DEFAULTTONEAREST = 2


class _Point(ctypes.Structure):
    _fields_ = [("x", wintypes.LONG), ("y", wintypes.LONG)]


class _MonitorInfo(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("rcMonitor", wintypes.RECT),
        ("rcWork", wintypes.RECT),
        ("dwFlags", wintypes.DWORD),
    ]


def resource_path(*parts: str) -> Path:
    """Resolve a source or PyInstaller-bundled application resource."""
    bundle_root = getattr(sys, "_MEIPASS", None)
    base = Path(bundle_root) if bundle_root else Path(__file__).resolve().parents[1]
    return base.joinpath(*parts)


def apply_window_icon(window) -> Path | None:
    """Apply the NetRecon ICO to the current and future Tk windows."""
    icon = resource_path("packaging", "NetRecon.ico")
    if not icon.is_file():
        return None
    try:
        window.iconbitmap(str(icon))
        if sys.platform.startswith("win"):
            window.iconbitmap(default=str(icon))
    except Exception:
        return None
    return icon


def calculate_centered_geometry(
    width: int,
    height: int,
    work_area: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    """Return width, height, x, and y centered inside a monitor work area."""
    left, top, right, bottom = (int(value) for value in work_area)
    available_width = right - left
    available_height = bottom - top
    if available_width <= 0 or available_height <= 0:
        raise ValueError("Monitor work area must have positive dimensions")

    fitted_width = min(max(int(width), 1), available_width)
    fitted_height = min(max(int(height), 1), available_height)
    x = left + (available_width - fitted_width) // 2
    y = top + (available_height - fitted_height) // 2
    return fitted_width, fitted_height, x, y


def _geometry_string(width: int, height: int, x: int, y: int) -> str:
    x_part = f"+{x}" if x >= 0 else str(x)
    y_part = f"+{y}" if y >= 0 else str(y)
    return f"{width}x{height}{x_part}{y_part}"


def _windows_work_area(
    anchor: tuple[int, int] | None,
) -> tuple[int, int, int, int] | None:
    if not sys.platform.startswith("win"):
        return None
    try:
        user32 = ctypes.windll.user32
        user32.MonitorFromPoint.argtypes = [_Point, wintypes.DWORD]
        user32.MonitorFromPoint.restype = wintypes.HANDLE
        user32.GetMonitorInfoW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_MonitorInfo)]
        user32.GetMonitorInfoW.restype = wintypes.BOOL
        user32.GetCursorPos.argtypes = [ctypes.POINTER(_Point)]
        user32.GetCursorPos.restype = wintypes.BOOL

        if anchor is None:
            point = _Point()
            if not user32.GetCursorPos(ctypes.byref(point)):
                return None
        else:
            point = _Point(int(anchor[0]), int(anchor[1]))

        monitor = user32.MonitorFromPoint(point, MONITOR_DEFAULTTONEAREST)
        if not monitor:
            return None
        info = _MonitorInfo()
        info.cbSize = ctypes.sizeof(_MonitorInfo)
        if not user32.GetMonitorInfoW(monitor, ctypes.byref(info)):
            return None
        work = info.rcWork
        return work.left, work.top, work.right, work.bottom
    except (AttributeError, OSError, TypeError, ValueError):
        return None


def center_window(
    window,
    width: int,
    height: int,
    anchor: tuple[int, int] | None = None,
) -> tuple[int, int, int, int]:
    """Center a Tk window on the monitor nearest the saved anchor."""
    work_area = _windows_work_area(anchor)
    if work_area is None:
        work_area = (0, 0, window.winfo_screenwidth(), window.winfo_screenheight())
    try:
        scaling = max(float(window._get_window_scaling()), 0.1)
    except (AttributeError, TypeError, ValueError):
        scaling = 1.0
    physical_width = round(width * scaling)
    physical_height = round(height * scaling)
    fitted_width, fitted_height, x, y = calculate_centered_geometry(
        physical_width, physical_height, work_area
    )
    logical_width = max(int(fitted_width / scaling), 1)
    logical_height = max(int(fitted_height / scaling), 1)
    window.geometry(_geometry_string(logical_width, logical_height, x, y))
    return logical_width, logical_height, x, y


def center_mapped_window(
    window,
    anchor: tuple[int, int] | None = None,
) -> bool:
    """Precisely center the complete mapped Windows frame, including borders."""
    work_area = _windows_work_area(anchor)
    if work_area is None or not sys.platform.startswith("win"):
        return False
    try:
        user32 = ctypes.windll.user32
        user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
        user32.GetWindowRect.restype = wintypes.BOOL
        user32.SetWindowPos.argtypes = [
            wintypes.HWND,
            wintypes.HWND,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            wintypes.UINT,
        ]
        user32.SetWindowPos.restype = wintypes.BOOL

        frame_text = str(window.tk.call("wm", "frame", window._w))
        frame_handle = wintypes.HWND(int(frame_text, 0))
        rect = wintypes.RECT()
        if not user32.GetWindowRect(frame_handle, ctypes.byref(rect)):
            return False
        frame_width = rect.right - rect.left
        frame_height = rect.bottom - rect.top
        _, _, x, y = calculate_centered_geometry(frame_width, frame_height, work_area)
        flags = 0x0001 | 0x0004 | 0x0010  # no size, no z-order, no activate
        return bool(user32.SetWindowPos(frame_handle, None, x, y, 0, 0, flags))
    except (AttributeError, OSError, TclError, TypeError, ValueError):
        return False


def current_window_center(window) -> tuple[int, int] | None:
    """Return the visible window center for use as the next monitor anchor."""
    try:
        if str(window.state()) in {"withdrawn", "iconic"}:
            return None
        window.update_idletasks()
        width = int(window.winfo_width())
        height = int(window.winfo_height())
        if width <= 1 or height <= 1:
            return None
        return (
            int(window.winfo_rootx()) + width // 2,
            int(window.winfo_rooty()) + height // 2,
        )
    except Exception:
        return None
