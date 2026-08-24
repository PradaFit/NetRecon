import os
import sys
import ctypes
import shutil
# Required for fixed local utility commands that never invoke a shell.
import subprocess  # nosec B404
import platform as _platform

from .logger import get_logger


log = get_logger("platform")


class PlatformInfo:
    """
    Caches OS details on first access.
    Import `platform_info` from this module rather than instantiating.
    """

    def __init__(self):
        self.system = _platform.system().lower()
        self.is_windows = self.system == "windows"
        self.is_linux = self.system == "linux"
        self.is_mac = self.system == "darwin"
        self.arch = _platform.machine()
        self.python_version = sys.version
        self.release = _platform.release()
        self._nmap_path = None
        self._nmap_version = None

    @property
    def is_admin(self):
        if self.is_windows:
            try:
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                return False
        else:
            return os.geteuid() == 0

    def find_nmap(self):
        """Locate the nmap binary, cached after first lookup."""
        if self._nmap_path is not None:
            return self._nmap_path if self._nmap_path else None

        found = shutil.which("nmap")
        if found:
            self._nmap_path = found
            return found

        if self.is_windows:
            candidates = [
                r"C:\Program Files (x86)\Nmap\nmap.exe",
                r"C:\Program Files\Nmap\nmap.exe",
                os.path.expandvars(r"%LOCALAPPDATA%\Nmap\nmap.exe"),
            ]
        elif self.is_linux:
            candidates = ["/usr/bin/nmap", "/usr/local/bin/nmap", "/snap/bin/nmap"]
        elif self.is_mac:
            candidates = ["/usr/local/bin/nmap", "/opt/homebrew/bin/nmap"]
        else:
            candidates = []

        for path in candidates:
            if os.path.isfile(path):
                self._nmap_path = path
                return path

        self._nmap_path = ""
        return None

    def get_nmap_version(self):
        if self._nmap_version is not None:
            return self._nmap_version
        nmap_path = self.find_nmap()
        if not nmap_path:
            return None
        try:
            creation_flags = subprocess.CREATE_NO_WINDOW if self.is_windows else 0
            out = subprocess.check_output(  # nosec
                [nmap_path, "--version"],
                stdin=subprocess.DEVNULL,
                stderr=subprocess.STDOUT,
                timeout=5,
                creationflags=creation_flags,
            ).decode("utf-8", errors="replace")
            for line in out.splitlines():
                if "nmap" in line.lower():
                    self._nmap_version = line.strip()
                    return self._nmap_version
        except Exception as exc:
            log.debug("Could not read Nmap version: %s", type(exc).__name__)
        return None

    def get_install_instructions(self):
        if self.is_windows:
            return (
                "Download Nmap from https://nmap.org/download.html\n"
                "Or use: winget install Insecure.Nmap"
            )
        elif self.is_linux:
            return (
                "Install Nmap with your package manager:\n"
                "  Debian/Ubuntu:  sudo apt install nmap\n"
                "  Fedora/RHEL:    sudo dnf install nmap\n"
                "  Arch:           sudo pacman -S nmap"
            )
        elif self.is_mac:
            return "Install Nmap with:  brew install nmap"
        return "Visit https://nmap.org/download.html"

    # memory monitoring (no psutil needed)

    @staticmethod
    def get_process_memory_mb():
        """Current process RSS in megabytes."""
        try:
            if sys.platform == "win32":
                from ctypes import wintypes

                class PMC(ctypes.Structure):
                    _fields_ = [
                        ("cb", wintypes.DWORD),
                        ("PageFaultCount", wintypes.DWORD),
                        ("PeakWorkingSetSize", ctypes.c_size_t),
                        ("WorkingSetSize", ctypes.c_size_t),
                        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                        ("PagefileUsage", ctypes.c_size_t),
                        ("PeakPagefileUsage", ctypes.c_size_t),
                    ]

                pmc = PMC()
                pmc.cb = ctypes.sizeof(PMC)
                handle = ctypes.windll.kernel32.GetCurrentProcess()
                if ctypes.windll.psapi.GetProcessMemoryInfo(
                    handle, ctypes.byref(pmc), pmc.cb
                ):
                    return pmc.WorkingSetSize / (1024 * 1024)
            else:
                with open("/proc/self/status", "r") as f:
                    for line in f:
                        if line.startswith("VmRSS:"):
                            return int(line.split()[1]) / 1024
        except Exception as exc:
            log.debug("Could not read process memory: %s", type(exc).__name__)
        return 0.0

    @staticmethod
    def get_system_memory_mb():
        """Total system RAM in MB."""
        try:
            if sys.platform == "win32":

                class MSEX(ctypes.Structure):
                    _fields_ = [
                        ("dwLength", ctypes.c_uint32),
                        ("dwMemoryLoad", ctypes.c_uint32),
                        ("ullTotalPhys", ctypes.c_uint64),
                        ("ullAvailPhys", ctypes.c_uint64),
                        ("ullTotalPageFile", ctypes.c_uint64),
                        ("ullAvailPageFile", ctypes.c_uint64),
                        ("ullTotalVirtual", ctypes.c_uint64),
                        ("ullAvailVirtual", ctypes.c_uint64),
                        ("ullAvailExtendedVirtual", ctypes.c_uint64),
                    ]

                ms = MSEX()
                ms.dwLength = ctypes.sizeof(MSEX)
                ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms))
                return ms.ullTotalPhys / (1024 * 1024)
            else:
                with open("/proc/meminfo", "r") as f:
                    for line in f:
                        if line.startswith("MemTotal:"):
                            return int(line.split()[1]) / 1024
        except Exception as exc:
            log.debug("Could not read system memory: %s", type(exc).__name__)
        return 0.0

    def open_file(self, filepath):
        filepath = str(filepath)
        try:
            if self.is_windows:
                # Open an explicitly selected local export with its associated app.
                os.startfile(filepath)  # nosec B606
            elif self.is_mac:
                subprocess.Popen(["open", filepath])  # nosec B603 B607
            else:
                subprocess.Popen(["xdg-open", filepath])  # nosec B603 B607
            return True
        except Exception:
            return False

    def __repr__(self):
        return (
            f"PlatformInfo(os={self.system}, arch={self.arch}, "
            f"admin={self.is_admin}, nmap={'yes' if self.find_nmap() else 'no'})"
        )


platform_info = PlatformInfo()
