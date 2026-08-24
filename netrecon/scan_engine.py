"""Port scanning engine with native TCP and cancellable Nmap backends."""

import html
import ipaddress
import os
import queue
import re
import shlex
# Required for the local Nmap backend, which never invokes a shell.
import subprocess  # nosec B404
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from defusedxml import ElementTree as ET

from .async_scanner import AsyncPortScanner
from .config import get_section
from .platform_utils import platform_info
from .validator import InputError, sanitize_nmap_args, sanitize_port_spec, sanitize_target


SAFE_VULN_SCRIPTS = "vuln and safe and not external and not broadcast"
SAFE_COMPREHENSIVE_SCRIPTS = (
    "(default or vuln) and safe and not external and not broadcast"
)


SCAN_PROFILES = {
    "quick": {
        "name": "Quick Scan",
        "description": "Nmap's most common 100 TCP ports",
        "args": "-n -T4 -F",
    },
    "default": {
        "name": "Default Scan",
        "description": "Nmap's default TCP ports with service detection",
        "args": "-n -T3 -sV",
    },
    "intense": {
        "name": "Intense Scan",
        "description": "All TCP ports with service, OS, script, and route detection",
        "args": "-n -T4 -A -p-",
        "requires_admin": True,
    },
    "stealth": {
        "name": "SYN Scan",
        "description": "TCP SYN scan with conservative timing",
        "args": "-n -sS -T2",
        "requires_admin": True,
    },
    "udp": {
        "name": "UDP Scan",
        "description": "Nmap's 100 most common UDP ports",
        "args": "-n -sU -T4 --top-ports 100",
        "requires_admin": True,
    },
    "vuln": {
        "name": "Vulnerability Checks",
        "description": "Service detection plus safe, target-scoped vulnerability checks",
        "args": f'-n -sV --script="{SAFE_VULN_SCRIPTS}"',
    },
    "vuln_extended": {
        "name": "Extended Vulnerability Checks",
        "description": "Full Nmap vuln category, including potentially intrusive checks",
        "args": (
            "-n -sV --script=vuln --script-timeout 15m "
            "--host-timeout 60m"
        ),
        "requires_admin": True,
        "extended": True,
    },
    "ping_sweep": {
        "name": "Ping Sweep",
        "description": "Host discovery only, with no port scan",
        "args": "-n -sn",
    },
    "os_detect": {
        "name": "OS Detection",
        "description": "Operating-system fingerprinting",
        "args": "-n -O --osscan-guess",
        "requires_admin": True,
    },
    "service_version": {
        "name": "Service Version",
        "description": "Detailed service and version detection",
        "args": "-n -sV --version-intensity 5",
    },
    "comprehensive": {
        "name": "Comprehensive",
        "description": "All TCP ports with detection and safe, target-scoped scripts",
        "args": f'-n -T4 -A -p- --script="{SAFE_COMPREHENSIVE_SCRIPTS}"',
        "requires_admin": True,
    },
    "comprehensive_extended": {
        "name": "Extended Comprehensive",
        "description": "All TCP ports plus the full default and vuln script categories",
        "args": (
            "-n -T4 -A -p- --script=default,vuln --script-timeout 15m "
            "--host-timeout 60m"
        ),
        "requires_admin": True,
        "extended": True,
    },
    "native_quick": {
        "name": "Native Quick",
        "description": "Top 1000 TCP ports on one host without Nmap",
        "args": "",
        "native": True,
    },
    "native_full": {
        "name": "Native Full Range",
        "description": "All 65535 TCP ports on one host without Nmap",
        "args": "",
        "native": True,
    },
    "native_custom": {
        "name": "Native Custom",
        "description": "User-selected TCP ports on one host without Nmap",
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
    cancelled: bool = False
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
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
    """Dual-backend scanner with prompt, thread-safe cancellation."""

    def __init__(self):
        settings = get_section("scan")
        try:
            self._native_concurrency = max(
                1,
                min(
                    int(settings.get("native_concurrency", 4000)),
                    AsyncPortScanner.MAX_CONCURRENCY,
                ),
            )
            self._native_timeout = max(
                0.05, min(float(settings.get("native_timeout", 1.5)), 30.0)
            )
        except (TypeError, ValueError):
            self._native_concurrency = AsyncPortScanner.DEFAULT_CONCURRENCY
            self._native_timeout = AsyncPortScanner.DEFAULT_TIMEOUT
        self._native_scanner = AsyncPortScanner(
            concurrency=self._native_concurrency,
            connect_timeout=self._native_timeout,
        )
        self._nmap_stats_interval = self._validated_duration(
            settings.get("nmap_stats_interval", "1s"), "1s"
        )
        self._nmap_host_timeout = self._validated_duration(
            settings.get("nmap_host_timeout", "30m"), "30m"
        )
        self._nmap_script_timeout = self._validated_duration(
            settings.get("nmap_script_timeout", "5m"), "5m"
        )
        self._cancel = threading.Event()
        self._active = threading.Event()
        self._scan_lock = threading.Lock()
        self._process_lock = threading.Lock()
        self._nmap_process = None
        self.nmap_path = platform_info.find_nmap()

    @staticmethod
    def _validated_duration(value, fallback):
        value = str(value).strip()
        return value if re.fullmatch(r"\d+(?:ms|s|m|h)", value) else fallback

    @property
    def is_available(self):
        """True when the local Nmap executable is available."""
        return self.nmap_path is not None

    @property
    def native_available(self):
        return True

    @property
    def is_scanning(self):
        return self._active.is_set()

    def _begin_scan(self):
        if not self._scan_lock.acquire(blocking=False):
            return False
        self._cancel.clear()
        self._active.set()
        return True

    def _end_scan(self):
        self._active.clear()
        self._scan_lock.release()

    def native_scan(
        self,
        target,
        ports=None,
        port_spec=None,
        concurrency=None,
        timeout=None,
        grab_banners=True,
        callback=None,
        profile_name="Native Scan",
    ):
        if not self._begin_scan():
            return ScanResult(
                target=str(target),
                profile=profile_name,
                arguments="",
                error="Another scan is already running",
            )
        try:
            return self._native_scan_impl(
                target,
                ports=ports,
                port_spec=port_spec,
                concurrency=concurrency,
                timeout=timeout,
                grab_banners=grab_banners,
                callback=callback,
                profile_name=profile_name,
            )
        finally:
            self._end_scan()

    def _native_scan_impl(
        self,
        target,
        ports=None,
        port_spec=None,
        concurrency=None,
        timeout=None,
        grab_banners=True,
        callback=None,
        profile_name="Native Scan",
    ):
        try:
            target = sanitize_target(target)
            if port_spec:
                port_spec = sanitize_port_spec(port_spec)
        except InputError as exc:
            return ScanResult(
                target=str(target), profile=profile_name, arguments="", error=str(exc)
            )

        try:
            scanner = AsyncPortScanner(
                concurrency=concurrency or self._native_concurrency,
                connect_timeout=timeout or self._native_timeout,
                grab_banners=grab_banners,
            )
        except (TypeError, ValueError) as exc:
            return ScanResult(
                target=target, profile=profile_name, arguments="", error=str(exc)
            )

        # Reset before publishing the scanner reference. A concurrent cancel
        # after this assignment can then stop the same scanner without having
        # its cancellation flag cleared again inside scan().
        scanner.reset()
        self._native_scanner = scanner
        if self._cancel.is_set():
            return self._cancelled_result(target, profile_name, "")
        native_result = scanner.scan(
            target,
            ports=ports,
            port_spec=port_spec,
            callback=callback,
            reset_cancel=False,
        )

        scanner_args = (
            f"concurrency={scanner._concurrency}, "
            f"timeout={scanner._connect_timeout}s"
        )
        if native_result.cancelled:
            return ScanResult(
                target=target,
                profile=profile_name,
                arguments=scanner_args,
                scan_time=native_result.scan_time,
                error="Scan cancelled by user",
                cancelled=True,
            )
        if native_result.error:
            return ScanResult(
                target=target,
                profile=profile_name,
                arguments=scanner_args,
                scan_time=native_result.scan_time,
                error=native_result.error,
            )

        host_ports = [
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
            for pr in native_result.open_ports
        ]
        host_replied = any(pr.state in {"open", "closed"} for pr in native_result.ports)
        hosts = [
            {
                "ip": native_result.ip,
                "hostname": target if target != native_result.ip else "N/A",
                "state": "up" if host_replied else "unknown",
                "ports": host_ports,
                "os_matches": [],
                "scripts": {},
            }
        ]

        return ScanResult(
            target=target,
            profile=profile_name,
            arguments=scanner_args,
            hosts=hosts,
            scan_time=native_result.scan_time,
            command_line=f"NetRecon native TCP scanner -> {native_result.ip}",
        )

    def build_nmap_arguments(self, profile="default", custom_args=None, ports=None, timing=None):
        """Return validated Nmap arguments and the display profile name."""
        if custom_args:
            args = sanitize_nmap_args(custom_args)
            profile_name = "Custom"
            requires_admin = False
        else:
            profile_data = SCAN_PROFILES.get(profile)
            if not profile_data or profile_data.get("native"):
                raise InputError(f"Unknown Nmap profile: {profile}")
            args = profile_data["args"]
            profile_name = profile_data["name"]
            requires_admin = bool(profile_data.get("requires_admin"))

        tokens = self._split_nmap_arguments(args)
        if timing is not None:
            if not re.fullmatch(r"T[0-5]", str(timing)):
                raise InputError("Nmap timing must be T0 through T5")
            tokens = [token for token in tokens if not re.fullmatch(r"-T[0-5]", token)]
            tokens.append(f"-{timing}")

        if ports and profile != "ping_sweep":
            port_spec = sanitize_port_spec(ports)
            tokens = self._remove_profile_port_selection(tokens)
            tokens.extend(["-p", port_spec])

        return subprocess.list2cmdline(tokens), profile_name, requires_admin

    @staticmethod
    def _split_nmap_arguments(args):
        try:
            return shlex.split(args, posix=True)
        except ValueError as exc:
            raise InputError(f"Invalid Nmap arguments: {exc}") from exc

    @staticmethod
    def _has_nmap_option(tokens, option):
        return option in tokens or any(token.startswith(f"{option}=") for token in tokens)

    def _add_runtime_controls(self, tokens):
        controlled = list(tokens)
        if not self._has_nmap_option(controlled, "--stats-every"):
            controlled.extend(["--stats-every", self._nmap_stats_interval])
        if not self._has_nmap_option(controlled, "--host-timeout"):
            controlled.extend(["--host-timeout", self._nmap_host_timeout])
        if not self._has_nmap_option(controlled, "--script-timeout"):
            controlled.extend(["--script-timeout", self._nmap_script_timeout])
        return controlled

    @staticmethod
    def _remove_profile_port_selection(tokens):
        cleaned = []
        skip_next = False
        for token in tokens:
            if skip_next:
                skip_next = False
                continue
            if token in {"-F", "-p", "--top-ports"}:
                skip_next = token in {"-p", "--top-ports"}
                continue
            if token.startswith("--top-ports="):
                continue
            # The literal below is Nmap's all-ports flag, not a password.
            if token == "-p-" or re.fullmatch(  # nosec
                r"-p(?:[TUS]:)?[0-9,-]+", token
            ):
                continue
            cleaned.append(token)
        return cleaned

    def scan(
        self,
        target,
        profile="default",
        custom_args=None,
        ports=None,
        callback=None,
        timing=None,
        concurrency=None,
        timeout=None,
    ):
        """Run a validated native or Nmap scan."""
        if not self._begin_scan():
            return ScanResult(
                target=str(target),
                profile=str(profile),
                arguments="",
                error="Another scan is already running",
            )
        try:
            return self._scan_impl(
                target,
                profile=profile,
                custom_args=custom_args,
                ports=ports,
                callback=callback,
                timing=timing,
                concurrency=concurrency,
                timeout=timeout,
            )
        finally:
            self._end_scan()

    def _scan_impl(
        self,
        target,
        profile,
        custom_args,
        ports,
        callback,
        timing,
        concurrency,
        timeout,
    ):
        try:
            target = sanitize_target(target)
            if ports:
                ports = sanitize_port_spec(ports)
            if custom_args:
                custom_args = sanitize_nmap_args(custom_args)
        except InputError as exc:
            return ScanResult(
                target=str(target), profile=str(profile), arguments="", error=str(exc)
            )

        profile_data = SCAN_PROFILES.get(profile, {})
        if profile_data.get("native"):
            if "/" in target:
                return ScanResult(
                    target=target,
                    profile=profile_data["name"],
                    arguments="",
                    error=(
                        "Native profiles scan one host at a time; select an Nmap "
                        "profile for CIDR targets"
                    ),
                )
            if profile == "native_custom" and not ports:
                return ScanResult(
                    target=target,
                    profile=profile_data["name"],
                    arguments="",
                    error="Native Custom requires a port selection",
                )
            port_list = range(1, 65536) if profile == "native_full" else None
            port_spec = None if profile == "native_full" else ports
            return self._native_scan_impl(
                target,
                ports=port_list,
                port_spec=port_spec,
                concurrency=concurrency,
                timeout=timeout,
                callback=callback,
                profile_name=profile_data["name"],
            )

        if not self.is_available:
            return ScanResult(
                target=target,
                profile=str(profile),
                arguments="",
                error=f"Nmap not found.\n{platform_info.get_install_instructions()}",
            )

        try:
            args, profile_name, requires_admin = self.build_nmap_arguments(
                profile=profile,
                custom_args=custom_args,
                ports=ports,
                timing=timing,
            )
        except InputError as exc:
            return ScanResult(
                target=target, profile=str(profile), arguments="", error=str(exc)
            )

        try:
            tokens = self._split_nmap_arguments(args)
        except InputError as exc:
            return ScanResult(
                target=target, profile=profile_name, arguments=args, error=str(exc)
            )
        try:
            address = ipaddress.ip_network(target, strict=False)
            if address.version == 6 and "-6" not in tokens:
                tokens.append("-6")
        except ValueError:
            pass

        tokens = self._add_runtime_controls(tokens)
        args = subprocess.list2cmdline(tokens)

        if requires_admin and not platform_info.is_admin and callback:
            callback("[!] This profile may need elevated privileges for full results.")
        if callback:
            callback(f"[*] Starting {profile_name} on {target} ...")

        command = [self.nmap_path, *tokens, "-oX", "-", target]
        display_command = subprocess.list2cmdline([self.nmap_path, *tokens, target])
        creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        t0 = time.perf_counter()

        try:
            if self._cancel.is_set():
                return self._cancelled_result(target, profile_name, args)
            # Executable, options, and target are validated argv entries.
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=creation_flags,
            )  # nosec B603
            with self._process_lock:
                self._nmap_process = process
                cancel_pending = self._cancel.is_set()
            if cancel_pending and process.poll() is None:
                process.terminate()
            stdout, stderr = self._collect_nmap_output(process, callback)
        except OSError as exc:
            return ScanResult(
                target=target,
                profile=profile_name,
                arguments=args,
                error=f"Could not start Nmap: {exc}",
            )
        finally:
            with self._process_lock:
                self._nmap_process = None

        elapsed = round(time.perf_counter() - t0, 3)
        if self._cancel.is_set():
            result = self._cancelled_result(target, profile_name, args)
            result.scan_time = elapsed
            return result
        if process.returncode != 0:
            detail = (stderr or "Nmap exited with an error").strip()[:1200]
            return ScanResult(
                target=target,
                profile=profile_name,
                arguments=args,
                scan_time=elapsed,
                error=f"Nmap error: {detail}",
                command_line=display_command,
            )

        try:
            hosts, nmap_version, xml_elapsed = self._parse_nmap_xml(stdout)
        except (ET.ParseError, ValueError, TypeError, AttributeError) as exc:
            return ScanResult(
                target=target,
                profile=profile_name,
                arguments=args,
                scan_time=elapsed,
                error=f"Could not parse Nmap results: {exc}",
                command_line=display_command,
            )

        result = ScanResult(
            target=target,
            profile=profile_name,
            arguments=args,
            hosts=hosts,
            scan_time=xml_elapsed or elapsed,
            command_line=display_command,
            nmap_version=nmap_version,
        )
        if callback:
            callback(
                f"[+] Done: {result.total_hosts} host(s), "
                f"{result.total_open_ports} open port(s) in {result.scan_time}s"
            )
        return result

    @staticmethod
    def _read_nmap_stream(stream, stream_name, output_queue):
        try:
            for line in iter(stream.readline, ""):
                output_queue.put((stream_name, line))
        finally:
            try:
                stream.close()
            finally:
                output_queue.put((stream_name, None))

    @staticmethod
    def _nmap_progress_message(line):
        match = re.search(r"<taskprogress\b([^>]*)/?>", line)
        if not match:
            return None
        attributes = dict(re.findall(r'(\w+)="([^"]*)"', match.group(1)))
        try:
            percent = max(0.0, min(float(attributes["percent"]), 100.0))
        except (KeyError, TypeError, ValueError):
            return None

        task = html.unescape(attributes.get("task", "Nmap scan"))
        suffix = ""
        try:
            remaining = max(0, int(attributes.get("remaining", "0")))
        except (TypeError, ValueError):
            remaining = 0
        if remaining:
            minutes, seconds = divmod(remaining, 60)
            suffix = f"; about {minutes}m {seconds:02d}s remaining"
        return f"  [{percent:5.1f}%] Nmap {task}{suffix}"

    def _collect_nmap_output(self, process, callback):
        output_queue = queue.Queue()
        stdout_parts = []
        stderr_parts = []
        readers = [
            threading.Thread(
                target=self._read_nmap_stream,
                args=(process.stdout, "stdout", output_queue),
                daemon=True,
            ),
            threading.Thread(
                target=self._read_nmap_stream,
                args=(process.stderr, "stderr", output_queue),
                daemon=True,
            ),
        ]
        for reader in readers:
            reader.start()

        finished_streams = set()
        last_progress = None
        while len(finished_streams) < len(readers):
            try:
                stream_name, line = output_queue.get(timeout=0.2)
            except queue.Empty:
                continue
            if line is None:
                finished_streams.add(stream_name)
                continue

            if stream_name == "stdout":
                stdout_parts.append(line)
            else:
                stderr_parts.append(line)

            progress = self._nmap_progress_message(line)
            if callback and progress and progress != last_progress:
                callback(progress)
                last_progress = progress

        process.wait()
        for reader in readers:
            reader.join(timeout=1)
        return "".join(stdout_parts), "".join(stderr_parts)

    @staticmethod
    def _cancelled_result(target, profile_name, args):
        return ScanResult(
            target=target,
            profile=profile_name,
            arguments=args,
            error="Scan cancelled by user",
            cancelled=True,
        )

    def cancel(self):
        """Cancel the current native task group or terminate the live Nmap process."""
        was_active = self._active.is_set()
        self._cancel.set()
        self._native_scanner.cancel()
        with self._process_lock:
            process = self._nmap_process
        if process is not None and process.poll() is None:
            try:
                process.terminate()
            except OSError:
                pass

            def ensure_stopped():
                try:
                    process.wait(timeout=0.75)
                except subprocess.TimeoutExpired:
                    try:
                        process.kill()
                    except OSError:
                        pass

            threading.Thread(target=ensure_stopped, daemon=True).start()
        return was_active

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

    def native_quick_scan(self, target, ports=None, callback=None):
        return self.scan(
            target, profile="native_quick", ports=ports, callback=callback
        )

    def native_full_scan(self, target, callback=None):
        return self.scan(target, profile="native_full", callback=callback)

    @staticmethod
    def _parse_nmap_xml(xml_text):
        root = ET.fromstring(xml_text)
        if root.tag != "nmaprun":
            raise ValueError("unexpected XML root")

        hosts = []
        for host_node in root.findall("host"):
            status_node = host_node.find("status")
            addresses = host_node.findall("address")
            primary_address = next(
                (
                    node.get("addr", "")
                    for node in addresses
                    if node.get("addrtype") in {"ipv4", "ipv6"}
                ),
                "",
            )
            hostname_node = host_node.find("./hostnames/hostname")
            host_data = {
                "ip": primary_address,
                "hostname": (
                    hostname_node.get("name", "N/A") if hostname_node is not None else "N/A"
                ),
                "state": status_node.get("state", "unknown") if status_node is not None else "unknown",
                "ports": [],
                "os_matches": [],
                "scripts": {},
            }

            for port_node in host_node.findall("./ports/port"):
                state_node = port_node.find("state")
                service_node = port_node.find("service")
                service_attrs = service_node.attrib if service_node is not None else {}
                state = state_node.get("state", "unknown") if state_node is not None else "unknown"
                host_data["ports"].append(
                    {
                        "port": int(port_node.get("portid", "0")),
                        "protocol": port_node.get("protocol", ""),
                        "state": state,
                        "service": service_attrs.get("name", "unknown"),
                        "version": service_attrs.get("version", ""),
                        "product": service_attrs.get("product", ""),
                        "extra_info": service_attrs.get("extrainfo", ""),
                        "cpe": (
                            (service_node.findtext("cpe") or "")
                            if service_node is not None
                            else ""
                        ),
                    }
                )
                for script in port_node.findall("script"):
                    key = (
                        f"{port_node.get('portid', '')}/{port_node.get('protocol', '')}:"
                        f"{script.get('id', 'script')}"
                    )
                    host_data["scripts"][key] = script.get("output", "")

            for match in host_node.findall("./os/osmatch"):
                host_data["os_matches"].append(
                    {"name": match.get("name", ""), "accuracy": match.get("accuracy", "")}
                )
            for script in host_node.findall("./hostscript/script"):
                host_data["scripts"][script.get("id", "script")] = script.get("output", "")
            hosts.append(host_data)

        elapsed = 0.0
        finished_node = root.find("./runstats/finished")
        if finished_node is not None:
            try:
                elapsed = round(float(finished_node.get("elapsed", "0")), 3)
            except ValueError:
                elapsed = 0.0
        return hosts, root.get("version", ""), elapsed
