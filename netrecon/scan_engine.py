"""
Port scanning engine: dual backend architecture.

1. Native async TCP connect scanner  (fast, no dependencies, no admin needed)
2. Nmap wrapper                      (deep fingerprinting, OS detect, scripts)

CLI and GUI can choose either backend or let the engine auto-select:
  - native:  raw speed, banner grabbing, up to 50k concurrent sockets
  - nmap:    service version probing, OS detection, vuln scripts, UDP
"""

import time
import threading
import nmap
from dataclasses import dataclass, field, asdict
from datetime import datetime

from .platform_utils import platform_info
from .validator import (
    sanitize_target,
    sanitize_port_spec,
    sanitize_nmap_args,
    InputError,
)
from .async_scanner import AsyncPortScanner, NativeScanResult


SCAN_PROFILES = {
    "quick": {
        "name": "Quick Scan",
        "description": "Top 100 ports, fast timing",
        "args": "-T4 -F",
    },
    "default": {
        "name": "Default Scan",
        "description": "Top 1000 ports with service detection",
        "args": "-T3 -sV",
    },
    "intense": {
        "name": "Intense Scan",
        "description": "All ports, service + OS detection, default scripts",
        "args": "-T4 -A -p-",
        "requires_admin": True,
    },
    "stealth": {
        "name": "Stealth SYN Scan",
        "description": "Half-open SYN scan, harder to detect",
        "args": "-sS -T2",
        "requires_admin": True,
    },
    "udp": {
        "name": "UDP Scan",
        "description": "Top 100 UDP ports",
        "args": "-sU -T4 --top-ports 100",
        "requires_admin": True,
    },
    "vuln": {
        "name": "Vulnerability Scan",
        "description": "Service detection plus vulnerability scripts",
        "args": "-sV --script=vuln",
        "requires_admin": True,
    },
    "ping_sweep": {
        "name": "Ping Sweep",
        "description": "Host discovery only, no port scan",
        "args": "-sn",
    },
    "os_detect": {
        "name": "OS Detection",
        "description": "Operating system fingerprinting",
        "args": "-O --osscan-guess",
        "requires_admin": True,
    },
    "service_version": {
        "name": "Service Version",
        "description": "Detailed service and version detection",
        "args": "-sV --version-intensity 5",
    },
    "comprehensive": {
        "name": "Comprehensive",
        "description": "Full port range, all detection, default + vuln scripts",
        "args": "-T4 -A -p- --script=default,vuln",
        "requires_admin": True,
    },
    # native scanner profiles (no nmap required)
    "native_quick": {
        "name": "Native Quick",
        "description": "Top 1000 ports via async TCP connect (no nmap needed)",
        "args": "",
        "native": True,
    },
    "native_full": {
        "name": "Native Full Range",
        "description": "All 65535 ports via async TCP connect",
        "args": "",
        "native": True,
    },
    "native_custom": {
        "name": "Native Custom",
        "description": "Specify ports for native async scan",
        "args": "",
        "native": True,
    },
}


@dataclass
class ScanResult:
    target: str
    profile: str
    arguments: str
    hosts: list = field(default_factory=list)
    scan_time: float = 0.0
    error: str = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    command_line: str = ""
    nmap_version: str = ""

    def to_dict(self):
        return asdict(self)

    @property
    def total_hosts(self):
        return len(self.hosts)

    @property
    def total_open_ports(self):
        return sum(
            len([p for p in h.get("ports", []) if p.get("state") == "open"])
            for h in self.hosts
        )


class ScanEngine:
    """
    Dual-backend scan engine.
    Prefer native scanner for speed; fall back to nmap for advanced features.
    """

    def __init__(self):
        self._nmap_scanner = None
        self._native_scanner = AsyncPortScanner()
        self._lock = threading.Lock()
        self._cancel = threading.Event()
        self.nmap_path = platform_info.find_nmap()

    @property
    def is_available(self):
        """True if nmap is installed (native scanner is always available)."""
        return self.nmap_path is not None

    @property
    def native_available(self):
        return True

    def _get_nmap(self):
        if self._nmap_scanner is None:
            search = (self.nmap_path,) if self.nmap_path else ()
            try:
                self._nmap_scanner = nmap.PortScanner(nmap_search_path=search)
            except nmap.PortScannerError:
                self._nmap_scanner = nmap.PortScanner()
        return self._nmap_scanner

    # native scan entry point

    def native_scan(
        self,
        target,
        ports=None,
        port_spec=None,
        concurrency=None,
        timeout=None,
        grab_banners=True,
        callback=None,
    ):
        self._cancel.clear()

        try:
            target = sanitize_target(target)
            if port_spec:
                port_spec = sanitize_port_spec(port_spec)
        except InputError as exc:
            return ScanResult(
                target=target, profile="Native", arguments="", error=str(exc)
            )

        scanner = AsyncPortScanner(
            concurrency=concurrency or 8000,
            connect_timeout=timeout or 1.5,
            grab_banners=grab_banners,
        )
        self._native_scanner = scanner
        native_result = scanner.scan(
            target, ports=ports, port_spec=port_spec, callback=callback
        )

        if native_result.error:
            return ScanResult(
                target=target,
                profile="Native Scan",
                arguments="",
                error=native_result.error,
            )

        host_ports = []
        for pr in native_result.open_ports:
            host_ports.append(
                {
                    "port": pr.port,
                    "protocol": "tcp",
                    "state": "open",
                    "service": pr.service,
                    "version": "",
                    "product": pr.banner[:80] if pr.banner else "",
                    "extra_info": "",
                    "cpe": "",
                }
            )

        hosts = [
            {
                "ip": native_result.ip,
                "hostname": target if target != native_result.ip else "N/A",
                "state": "up" if host_ports else "down",
                "ports": host_ports,
                "os_matches": [],
                "scripts": {},
            }
        ]

        label = f"Native Scan ({native_result.total_scanned} ports)"
        return ScanResult(
            target=target,
            profile=label,
            arguments=f"concurrency={scanner._concurrency}, timeout={scanner._connect_timeout}s",
            hosts=hosts,
            scan_time=native_result.scan_time,
            command_line=f"PradaFit native scanner -> {native_result.ip}",
        )

    # nmap scan entry point

    def scan(
        self, target, profile="default", custom_args=None, ports=None, callback=None
    ):
        """
        Run an nmap scan.  Validates inputs before touching the network.
        """
        self._cancel.clear()

        try:
            target = sanitize_target(target)
            if ports:
                ports = sanitize_port_spec(ports)
            if custom_args:
                custom_args = sanitize_nmap_args(custom_args)
        except InputError as exc:
            return ScanResult(
                target=target, profile=profile, arguments="", error=str(exc)
            )

        # handle native profiles transparently
        prof_data = SCAN_PROFILES.get(profile, {})
        if prof_data.get("native"):
            port_list = None
            pspec = ports
            if profile == "native_full":
                port_list = list(range(1, 65536))
                pspec = None
            return self.native_scan(
                target, ports=port_list, port_spec=pspec, callback=callback
            )

        if not self.is_available:
            return ScanResult(
                target=target,
                profile=profile,
                arguments="",
                error=f"Nmap not found.\n{platform_info.get_install_instructions()}",
            )

        # build nmap args
        if custom_args:
            args = custom_args
            profile_name = "Custom"
        elif profile in SCAN_PROFILES:
            prof = SCAN_PROFILES[profile]
            args = prof["args"]
            profile_name = prof["name"]
            if prof.get("requires_admin") and not platform_info.is_admin:
                if callback:
                    callback(
                        "[!] Some features of this profile require elevated privileges."
                    )
        else:
            args = "-T3 -sV"
            profile_name = "Default"

        if ports and "-p" not in args:
            args += f" -p {ports}"

        if callback:
            callback(f"[*] Starting {profile_name} scan on {target} ...")

        try:
            scanner = self._get_nmap()
            t0 = time.perf_counter()

            with self._lock:
                scanner.scan(hosts=target, arguments=args)

            elapsed = time.perf_counter() - t0

            if self._cancel.is_set():
                return ScanResult(
                    target=target,
                    profile=profile_name,
                    arguments=args,
                    error="Scan cancelled by user",
                )

            hosts = self._parse_nmap_hosts(scanner)

            result = ScanResult(
                target=target,
                profile=profile_name,
                arguments=args,
                hosts=hosts,
                scan_time=round(elapsed, 2),
                command_line=scanner.command_line(),
                nmap_version=scanner.nmap_version(),
            )

            if callback:
                callback(
                    f"[+] Done: {result.total_hosts} host(s), "
                    f"{result.total_open_ports} open port(s) in {result.scan_time}s"
                )
            return result

        except nmap.PortScannerError as exc:
            return ScanResult(
                target=target,
                profile=profile_name,
                arguments=args,
                error=f"Nmap error: {exc}",
            )
        except Exception as exc:
            return ScanResult(
                target=target,
                profile=profile_name,
                arguments=args,
                error=f"Scan failed: {exc}",
            )

    def cancel(self):
        self._cancel.set()
        if self._native_scanner:
            self._native_scanner.cancel()

    def quick_scan(self, target, callback=None):
        return self.scan(target, profile="quick", callback=callback)

    def intense_scan(self, target, callback=None):
        return self.scan(target, profile="intense", callback=callback)

    def stealth_scan(self, target, callback=None):
        return self.scan(target, profile="stealth", callback=callback)

    def vuln_scan(self, target, callback=None):
        return self.scan(target, profile="vuln", callback=callback)

    def os_detect(self, target, callback=None):
        return self.scan(target, profile="os_detect", callback=callback)

    def service_scan(self, target, ports=None, callback=None):
        return self.scan(
            target, profile="service_version", ports=ports, callback=callback
        )

    def ping_sweep(self, target, callback=None):
        return self.scan(target, profile="ping_sweep", callback=callback)

    def native_quick_scan(self, target, callback=None):
        return self.native_scan(target, callback=callback)

    def native_full_scan(self, target, callback=None):
        return self.native_scan(target, ports=list(range(1, 65536)), callback=callback)

    # nmap output parser

    @staticmethod
    def _parse_nmap_hosts(scanner):
        hosts = []
        for host in scanner.all_hosts():
            hdata = {
                "ip": host,
                "hostname": scanner[host].hostname() or "N/A",
                "state": scanner[host].state(),
                "ports": [],
                "os_matches": [],
                "scripts": {},
            }

            for proto in scanner[host].all_protocols():
                for port in sorted(scanner[host][proto].keys()):
                    info = scanner[host][proto][port]
                    hdata["ports"].append(
                        {
                            "port": port,
                            "protocol": proto,
                            "state": info.get("state", "unknown"),
                            "service": info.get("name", "unknown"),
                            "version": info.get("version", ""),
                            "product": info.get("product", ""),
                            "extra_info": info.get("extrainfo", ""),
                            "cpe": info.get("cpe", ""),
                        }
                    )

            if "osmatch" in scanner[host]:
                for match in scanner[host]["osmatch"]:
                    hdata["os_matches"].append(
                        {
                            "name": match.get("name", ""),
                            "accuracy": match.get("accuracy", ""),
                        }
                    )

            if "script" in scanner[host]:
                hdata["scripts"] = dict(scanner[host]["script"])

            hosts.append(hdata)
        return hosts
