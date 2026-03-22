#!/usr/bin/env python3
"""
NetRecon: Network Reconnaissance Toolkit v2
=============================================
DNS lookup, port scanning (native async + nmap), IP geolocation.
Cross-platform: Windows 11, any Linux distro, macOS.
Developed by PradaFit.

Usage:
    python main.py                              Launch the GUI (default)
    python main.py --cli                        Interactive terminal mode
    python main.py dns example.com              Quick DNS lookup
    python main.py dns example.com --type MX    DNS lookup with record type
    python main.py scan 192.168.1.1             Quick native TCP scan
    python main.py scan 192.168.1.1 --nmap      Quick nmap scan (requires nmap)
    python main.py scan 192.168.1.0/24 -p quick Scan with profile
    python main.py geo 8.8.8.8                  Geolocate an IP
    python main.py geo --myip                   Show your public IP info
"""

import sys
import argparse
import json

from netrecon import (
    DNSEngine,
    ScanEngine,
    GeoEngine,
    ExportEngine,
    DatabaseManager,
    platform_info,
    RECORD_TYPES,
    SCAN_PROFILES,
    __version__,
)


BANNER = r"""
 ________              _________      ___________________
 ___  __ \____________ ______  /_____ ___  ____/__(_)_  /_
 __  /_/ /_  ___/  __ `/  __  /_  __ `/_  /_   __  /_  __/
 _  ____/_  /   / /_/ // /_/ / / /_/ /_  __/   _  / / /_
 /_/     /_/    \__,_/ \__,_/  \__,_/ /_/      /_/  \__/
"""


def _show_banner():
    print(BANNER)
    print(f"  NetRecon v{__version__} | Network Reconnaissance Toolkit")
    print(f"  by PradaFit")
    print(f"  Platform: {platform_info.system.title()} {platform_info.release}")
    nmap_ver = platform_info.get_nmap_version()
    if nmap_ver:
        print(f"  Nmap: {nmap_ver}")
    else:
        print("  Nmap: not found (native scanner available)")
    print()


def cli_dns(args):
    engine = DNSEngine()
    target = args.target

    if args.reverse:
        result = engine.reverse_lookup(target)
    elif args.all:
        results = engine.get_all_records(target)
        for r in sorted(results, key=lambda x: x.record_type):
            _print_dns(r)
        return
    elif args.propagation:
        results = engine.propagation_check(target, args.type)
        for r in results:
            if r.error:
                print(f"  {r.server:<24}  ERROR: {r.error}")
            else:
                vals = ", ".join(rec["value"] for rec in r.records)
                print(f"  {r.server:<24}  {vals:<30}  {r.response_time_ms} ms")
        return
    elif args.whois:
        data = engine.whois_lookup(target)
        print(json.dumps(data, indent=2, default=str))
        return
    else:
        ns = args.server if args.server else None
        result = engine.resolve(target, args.type, ns)

    _print_dns(result)


def cli_scan(args):
    engine = ScanEngine()

    profile = args.profile
    use_nmap = getattr(args, "nmap", False)

    if use_nmap and not engine.is_available:
        print(f"[!] Nmap not found.\n{platform_info.get_install_instructions()}")
        sys.exit(1)

    # Default to native scanner unless --nmap flag or nmap profile selected
    if not use_nmap and not profile.startswith("native_"):
        if profile in ("quick", "default"):
            profile = "native_quick"
        elif profile == "full":
            profile = "native_full"

    def callback(msg):
        print(msg)

    result = engine.scan(
        args.target,
        profile=profile,
        ports=args.ports,
        callback=callback,
    )

    if result.error:
        print(f"[!] {result.error}")
        return

    print(f"\nResults for {result.target} ({result.profile})")
    if result.command_line:
        print(f"Command: {result.command_line}")
    print(f"Duration: {result.scan_time}s\n")

    for host in result.hosts:
        print(f"Host: {host['ip']} ({host['hostname']}) [{host['state']}]")
        if host.get("ports"):
            print(f"  {'PORT':<10} {'STATE':<12} {'SERVICE':<16} VERSION")
            for p in host["ports"]:
                ver = f"{p['product']} {p['version']}".strip()
                print(
                    f"  {p['port']}/{p['protocol']:<6} {p['state']:<12} {p['service']:<16} {ver}"
                )
        if host.get("os_matches"):
            for om in host["os_matches"]:
                print(f"  OS: {om['name']} ({om['accuracy']}%)")
        print()


def cli_geo(args):
    engine = GeoEngine()

    if args.myip:
        ip = engine.get_my_ip()
        if ip:
            print(f"Public IP: {ip}")
            target = ip
        else:
            print("[!] Could not detect public IP")
            return
    else:
        target = args.target

    result = engine.locate(target)
    if result.error:
        print(f"[!] {result.error}")
        return

    fields = [
        ("IP", result.ip),
        ("Country", f"{result.country} ({result.country_code})"),
        ("Region", result.region),
        ("City", result.city),
        ("ZIP", result.zip_code),
        ("Latitude", result.latitude),
        ("Longitude", result.longitude),
        ("Timezone", result.timezone),
        ("ISP", result.isp),
        ("Organization", result.org),
        ("ASN", result.asn),
        ("Reverse DNS", result.reverse_dns),
    ]
    for label, value in fields:
        if value:
            print(f"  {label:<16}  {value}")


def cli_interactive():
    """REPL-style interactive mode."""
    _show_banner()
    print("  Type 'help' for commands, 'quit' to exit.\n")

    dns_engine = DNSEngine()
    scan_engine = ScanEngine()
    geo_engine = GeoEngine()

    while True:
        try:
            cmd = input("netrecon> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not cmd:
            continue
        if cmd in ("quit", "exit", "q"):
            break
        if cmd == "help":
            print("  dns <domain> [type]    DNS lookup")
            print("  rev <ip>               Reverse DNS")
            print("  scan <target> [ports]  Native TCP scan (fast)")
            print("  nmap <target>          Nmap scan (requires nmap)")
            print("  geo <ip/domain>        Geolocate")
            print("  myip                   Show public IP")
            print("  whois <domain>         WHOIS lookup")
            print("  quit                   Exit")
            continue

        parts = cmd.split()
        action = parts[0].lower()

        try:
            if action == "dns" and len(parts) >= 2:
                rtype = parts[2].upper() if len(parts) > 2 else "A"
                result = dns_engine.resolve(parts[1], rtype)
                _print_dns(result)

            elif action == "rev" and len(parts) >= 2:
                result = dns_engine.reverse_lookup(parts[1])
                _print_dns(result)

            elif action == "scan" and len(parts) >= 2:
                ports = parts[2] if len(parts) > 2 else None
                result = scan_engine.native_quick_scan(
                    parts[1],
                    ports=ports,
                    callback=lambda m: print(m),
                )
                if result.error:
                    print(f"[!] {result.error}")
                else:
                    for host in result.hosts:
                        print(f"  {host['ip']} [{host['state']}]")
                        for p in host.get("ports", []):
                            print(
                                f"    {p['port']}/{p['protocol']} {p['state']} {p['service']}"
                            )

            elif action == "nmap" and len(parts) >= 2:
                if not scan_engine.is_available:
                    print(
                        f"[!] Nmap not found.\n{platform_info.get_install_instructions()}"
                    )
                    continue
                result = scan_engine.quick_scan(
                    parts[1],
                    callback=lambda m: print(m),
                )
                if result.error:
                    print(f"[!] {result.error}")
                else:
                    for host in result.hosts:
                        print(f"  {host['ip']} [{host['state']}]")
                        for p in host.get("ports", []):
                            print(
                                f"    {p['port']}/{p['protocol']} {p['state']} {p['service']}"
                            )

            elif action == "geo" and len(parts) >= 2:
                r = geo_engine.locate(parts[1])
                if r.error:
                    print(f"[!] {r.error}")
                else:
                    print(f"  {r.ip} - {r.location_string} | ISP: {r.isp}")

            elif action == "myip":
                ip = geo_engine.get_my_ip()
                print(f"  Public IP: {ip}" if ip else "  [!] Could not detect")

            elif action == "whois" and len(parts) >= 2:
                data = dns_engine.whois_lookup(parts[1])
                print(json.dumps(data, indent=2, default=str))

            else:
                print("  Unknown command. Type 'help'.")

        except Exception as e:
            print(f"  [!] {e}")


def _print_dns(result):
    print(
        f"\n  {result.query} ({result.record_type}) via {result.server}  [{result.response_time_ms} ms]"
    )
    if result.error:
        print(f"  Error: {result.error}")
    else:
        for rec in result.records:
            print(f"  {rec.get('value', '')}")
    print()


def main():
    parser = argparse.ArgumentParser(
        prog="netrecon",
        description="NetRecon: Network Reconnaissance Toolkit (by PradaFit)",
    )
    parser.add_argument("--cli", action="store_true", help="Interactive terminal mode")
    parser.add_argument(
        "--version", action="version", version=f"NetRecon {__version__} (by PradaFit)"
    )

    sub = parser.add_subparsers(dest="command")

    # DNS subcommand
    dns_p = sub.add_parser("dns", help="DNS lookup")
    dns_p.add_argument("target", help="Domain or IP to query")
    dns_p.add_argument(
        "--type", "-t", default="A", choices=RECORD_TYPES, help="Record type"
    )
    dns_p.add_argument("--server", "-s", help="DNS server to use")
    dns_p.add_argument(
        "--reverse", "-r", action="store_true", help="Reverse DNS lookup"
    )
    dns_p.add_argument(
        "--all", "-a", action="store_true", help="Query all record types"
    )
    dns_p.add_argument(
        "--propagation", action="store_true", help="Check DNS propagation"
    )
    dns_p.add_argument("--whois", "-w", action="store_true", help="WHOIS lookup")

    # Scan subcommand
    scan_p = sub.add_parser("scan", help="Port scan (native async or nmap)")
    scan_p.add_argument("target", help="Target IP, hostname, or CIDR")
    scan_p.add_argument(
        "--profile",
        "-p",
        default="native_quick",
        choices=list(SCAN_PROFILES.keys()),
        help="Scan profile",
    )
    scan_p.add_argument("--ports", help="Port specification")
    scan_p.add_argument("--nmap", action="store_true", help="Force nmap backend")

    # Geo subcommand
    geo_p = sub.add_parser("geo", help="IP geolocation")
    geo_p.add_argument("target", nargs="?", help="IP or domain to geolocate")
    geo_p.add_argument("--myip", action="store_true", help="Locate your own public IP")

    args = parser.parse_args()

    if args.cli:
        cli_interactive()
    elif args.command == "dns":
        cli_dns(args)
    elif args.command == "scan":
        cli_scan(args)
    elif args.command == "geo":
        cli_geo(args)
    else:
        # Default: launch GUI
        _show_banner()
        try:
            from gui.app import launch_gui

            launch_gui()
        except ImportError as e:
            print(f"[!] GUI dependencies missing: {e}")
            print("    Install with: pip install customtkinter")
            print("    Or run with --cli for terminal mode.")
            sys.exit(1)


if __name__ == "__main__":
    main()
