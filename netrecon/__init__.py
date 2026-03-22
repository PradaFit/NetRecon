"""
NetRecon -- Network Reconnaissance Toolkit v2
DNS, port scanning (native async + nmap), and IP geolocation.
Developed by PradaFit.
"""

from .dns_engine import DNSEngine, DNSResult, RECORD_TYPES, PUBLIC_DNS_SERVERS
from .scan_engine import ScanEngine, ScanResult, SCAN_PROFILES
from .async_scanner import AsyncPortScanner, NativeScanResult, PortResult
from .geo_engine import GeoEngine, GeoResult
from .export_engine import ExportEngine
from .db_manager import DatabaseManager
from .platform_utils import platform_info, PlatformInfo
from .validator import (
    InputError,
    sanitize_target,
    sanitize_port_spec,
    sanitize_nmap_args,
    sanitize_dns_type,
    sanitize_nameserver,
    resolve_to_ip,
    parse_port_list,
)

__version__ = "2.0.0"
__app_name__ = "NetRecon"
__author__ = "PradaFit"

__all__ = [
    "DNSEngine",
    "DNSResult",
    "ScanEngine",
    "ScanResult",
    "AsyncPortScanner",
    "NativeScanResult",
    "PortResult",
    "GeoEngine",
    "GeoResult",
    "ExportEngine",
    "DatabaseManager",
    "platform_info",
    "PlatformInfo",
    "InputError",
    "sanitize_target",
    "sanitize_port_spec",
    "sanitize_nmap_args",
    "sanitize_dns_type",
    "sanitize_nameserver",
    "resolve_to_ip",
    "parse_port_list",
    "RECORD_TYPES",
    "PUBLIC_DNS_SERVERS",
    "SCAN_PROFILES",
]
