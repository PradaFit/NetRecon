"""NetRecon public package interface with lazy engine imports."""

from importlib import import_module

__version__ = "2.0.5"
__app_name__ = "NetRecon"
__author__ = "PradaFit"


_LAZY_EXPORTS = {
    "DNSEngine": (".dns_engine", "DNSEngine"),
    "DNSResult": (".dns_engine", "DNSResult"),
    "RECORD_TYPES": (".dns_engine", "RECORD_TYPES"),
    "PUBLIC_DNS_SERVERS": (".dns_engine", "PUBLIC_DNS_SERVERS"),
    "ScanEngine": (".scan_engine", "ScanEngine"),
    "ScanResult": (".scan_engine", "ScanResult"),
    "SCAN_PROFILES": (".scan_engine", "SCAN_PROFILES"),
    "AsyncPortScanner": (".async_scanner", "AsyncPortScanner"),
    "NativeScanResult": (".async_scanner", "NativeScanResult"),
    "PortResult": (".async_scanner", "PortResult"),
    "GeoEngine": (".geo_engine", "GeoEngine"),
    "GeoResult": (".geo_engine", "GeoResult"),
    "ExportEngine": (".export_engine", "ExportEngine"),
    "DatabaseManager": (".db_manager", "DatabaseManager"),
    "platform_info": (".platform_utils", "platform_info"),
    "PlatformInfo": (".platform_utils", "PlatformInfo"),
    "InputError": (".validator", "InputError"),
    "sanitize_target": (".validator", "sanitize_target"),
    "sanitize_port_spec": (".validator", "sanitize_port_spec"),
    "sanitize_nmap_args": (".validator", "sanitize_nmap_args"),
    "sanitize_dns_type": (".validator", "sanitize_dns_type"),
    "sanitize_nameserver": (".validator", "sanitize_nameserver"),
    "resolve_to_ip": (".validator", "resolve_to_ip"),
    "parse_port_list": (".validator", "parse_port_list"),
}


def __getattr__(name):
    """Load public engines only when the caller first uses them."""
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute_name = target
    value = getattr(import_module(module_name, __name__), attribute_name)
    globals()[name] = value
    return value


def __dir__():
    return sorted(set(globals()) | set(_LAZY_EXPORTS))

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
