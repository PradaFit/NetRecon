"""
IP geolocation engine with multi-provider failover.
Uses HTTPS providers in a cascade so one rate limit or outage does not break the workflow.
All user inputs pass through the validator before they hit any network call.
"""

import ipaddress
import json
import os
import re
# Required for a fixed local traceroute command that never invokes a shell.
import subprocess  # nosec B404
import threading
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime

from .validator import resolve_to_ip, InputError
from .config import get_section
from .logger import get_logger


log = get_logger("geo")


@dataclass
class GeoResult:
    ip: str
    country: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    zip_code: str = ""
    latitude: float = None
    longitude: float = None
    timezone: str = ""
    isp: str = ""
    org: str = ""
    asn: str = ""
    as_name: str = ""
    reverse_dns: str = ""
    is_proxy: bool = False
    is_mobile: bool = False
    is_hosting: bool = False
    error: str = None
    source: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self):
        return asdict(self)

    @property
    def coordinates(self):
        if self.latitude is not None and self.longitude is not None:
            return (self.latitude, self.longitude)
        return None

    @property
    def location_string(self):
        parts = [p for p in [self.city, self.region, self.country] if p]
        return ", ".join(parts) if parts else "Unknown"


class GeoEngine:
    PROVIDERS = ["ipwhois", "ipapi_co"]
    MAX_BULK_TARGETS = 1000
    MAX_RESPONSE_BYTES = 1024 * 1024

    def __init__(self, timeout=None):
        settings = get_section("geo")
        self.timeout = max(1.0, min(float(timeout or settings.get("timeout", 10)), 30.0))
        self._thread_local = threading.local()

    def _session(self):
        session = getattr(self._thread_local, "session", None)
        if session is None:
            session = requests.Session()
            session.headers.update(
                {
                    "User-Agent": "NetRecon Desktop",
                    "Accept": "application/json",
                }
            )
            self._thread_local.session = session
        return session

    def _get_json(self, url):
        response = self._session().get(
            url,
            timeout=(3.05, self.timeout),
            allow_redirects=False,
        )
        response.raise_for_status()
        content_length = response.headers.get("Content-Length")
        if content_length and int(content_length) > self.MAX_RESPONSE_BYTES:
            raise RuntimeError("Provider response was unexpectedly large")
        payload = response.content
        if len(payload) > self.MAX_RESPONSE_BYTES:
            raise RuntimeError("Provider response was unexpectedly large")
        data = json.loads(payload.decode("utf-8"))
        if not isinstance(data, dict):
            raise RuntimeError("Provider returned an invalid JSON object")
        return data

    @staticmethod
    def _coordinate(value, minimum, maximum):
        if value is None or value == "":
            return None
        number = float(value)
        if not minimum <= number <= maximum:
            raise RuntimeError("Provider returned invalid coordinates")
        return number

    def locate(self, target, provider=None):
        """
        Geolocate an IP or hostname.
        Cycles through providers on failure until one succeeds.
        """
        try:
            ip = resolve_to_ip(target)
        except InputError:
            return GeoResult(ip=target, error=f"Cannot resolve '{target}'")

        try:
            if not ipaddress.ip_address(ip).is_global:
                return GeoResult(
                    ip=ip,
                    error="Geolocation is available only for public IP addresses",
                )
        except ValueError:
            return GeoResult(ip=ip, error=f"Invalid resolved IP address: {ip}")

        if provider and provider not in self.PROVIDERS:
            return GeoResult(ip=ip, error=f"Unknown geolocation provider: {provider}")
        providers = [provider] if provider else self.PROVIDERS
        last_err = ""

        for prov in providers:
            try:
                if prov == "ipapi_co":
                    return self._query_ipapi_co(ip)
                elif prov == "ipwhois":
                    return self._query_ipwhois(ip)
            except Exception as exc:
                last_err = str(exc)
                log.debug("Geolocation provider failed: %s", type(exc).__name__)
                continue

        return GeoResult(ip=ip, error=f"All providers failed -- last error: {last_err}")

    def bulk_locate(self, targets, provider=None):
        clean = list(dict.fromkeys(t.strip() for t in targets if t.strip()))
        if len(clean) > self.MAX_BULK_TARGETS:
            raise InputError(
                f"Bulk lookup is limited to {self.MAX_BULK_TARGETS} unique targets"
            )
        results = []
        workers = min(15, max(1, len(clean)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(self.locate, t, provider): t for t in clean}
            for f in as_completed(futs):
                target = futs[f]
                try:
                    results.append(f.result())
                except Exception as exc:
                    results.append(GeoResult(ip=target, error=f"Lookup failed: {exc}"))
        return results

    def traceroute_geo(self, target):
        from .platform_utils import platform_info

        try:
            ip = resolve_to_ip(target)
        except InputError:
            return [GeoResult(ip=target, error="Cannot resolve target")]

        if platform_info.is_windows:
            # -d  : no reverse DNS (saves seconds per hop)
            # -w  : 500 ms per-hop timeout (default is 4000)
            # -h  : cap at 20 hops (public targets are almost never deeper)
            cmd = ["tracert", "-d", "-w", "500", "-h", "20", ip]
            run_timeout = 45
        else:
            # -n : no reverse DNS
            # -w : 1 s wait per probe
            # -q 1 : only one probe per hop (default is 3)
            # -m 20 : cap at 20 hops
            cmd = ["traceroute", "-n", "-w", "1", "-q", "1", "-m", "20", ip]
            run_timeout = 30

        try:
            creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            # The validated IP is passed as a separate argument.
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=run_timeout,
                creationflags=creation_flags,
            )  # nosec B603
            raw = proc.stdout
        except subprocess.TimeoutExpired:
            return [GeoResult(ip=ip, error="Traceroute timed out")]
        except FileNotFoundError:
            return [GeoResult(ip=ip, error="Traceroute not found on this system")]

        hops = self._parse_traceroute(raw, platform_info.is_windows)
        hop_ips = [h["ip"] for h in hops if h["ip"] and h["ip"] != "*"]

        if not hop_ips:
            return [GeoResult(ip=ip, error="No hops detected")]

        geo_map = {}
        for gr in self.bulk_locate(hop_ips):
            geo_map[gr.ip] = gr

        out = []
        for hop in hops:
            if hop["ip"] in geo_map:
                out.append(geo_map[hop["ip"]])
            else:
                out.append(GeoResult(ip=hop.get("ip", "*")))
        return out

    def get_my_ip(self):
        endpoints = [
            "https://api.ipify.org?format=json",
            "https://ifconfig.me/ip",
            "https://icanhazip.com",
        ]
        for url in endpoints:
            try:
                resp = self._session().get(
                    url, timeout=(3.05, self.timeout), allow_redirects=False
                )
                resp.raise_for_status()
                if "json" in url:
                    candidate = resp.json().get("ip")
                else:
                    candidate = resp.text.strip()
                if candidate and ipaddress.ip_address(candidate).is_global:
                    return candidate
            except Exception as exc:
                log.debug("Public IP provider failed: %s", type(exc).__name__)
                continue
        return None

    def _query_ipapi_co(self, ip):
        url = f"https://ipapi.co/{ip}/json/"
        d = self._get_json(url)

        if "error" in d:
            raise RuntimeError(d.get("reason", "ipapi.co returned error"))

        return GeoResult(
            ip=d.get("ip", ip),
            country=d.get("country_name", ""),
            country_code=d.get("country_code", ""),
            region=d.get("region", ""),
            city=d.get("city", ""),
            zip_code=d.get("postal", ""),
            latitude=self._coordinate(d.get("latitude"), -90, 90),
            longitude=self._coordinate(d.get("longitude"), -180, 180),
            timezone=d.get("timezone", ""),
            isp=d.get("org", ""),
            org=d.get("org", ""),
            asn=d.get("asn", ""),
            as_name=d.get("org", ""),
            source="ipapi.co",
        )

    def _query_ipwhois(self, ip):
        url = f"https://ipwho.is/{ip}"
        d = self._get_json(url)

        if not d.get("success", True):
            raise RuntimeError(d.get("message", "ipwhois returned error"))

        return GeoResult(
            ip=d.get("ip", ip),
            country=d.get("country", ""),
            country_code=d.get("country_code", ""),
            region=d.get("region", ""),
            city=d.get("city", ""),
            zip_code=d.get("postal", ""),
            latitude=self._coordinate(d.get("latitude"), -90, 90),
            longitude=self._coordinate(d.get("longitude"), -180, 180),
            timezone=(d.get("timezone") or {}).get("id", ""),
            isp=(d.get("connection") or {}).get("isp", ""),
            org=(d.get("connection") or {}).get("org", ""),
            asn=(d.get("connection") or {}).get("asn", ""),
            as_name=(d.get("connection") or {}).get("domain", ""),
            source="ipwho.is",
        )

    # traceroute parser

    @staticmethod
    def _parse_traceroute(output, is_windows=False):
        hops = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            if is_windows:
                ip_match = re.search(r"(\d+)\s+.*?(\d+\.\d+\.\d+\.\d+)", line)
                star_match = re.match(r"\s*(\d+)\s+\*\s+\*\s+\*", line)
                if ip_match:
                    hops.append(
                        {"hop": int(ip_match.group(1)), "ip": ip_match.group(2)}
                    )
                elif star_match:
                    hops.append({"hop": int(star_match.group(1)), "ip": "*"})
            else:
                match = re.match(r"\s*(\d+)\s+(\S+)", line)
                if match:
                    num = int(match.group(1))
                    host = match.group(2)
                    if host == "*":
                        hops.append({"hop": num, "ip": "*"})
                    else:
                        ip_hit = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                        hops.append(
                            {"hop": num, "ip": ip_hit.group(1) if ip_hit else host}
                        )

        return hops
