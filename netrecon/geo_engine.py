"""
IP geolocation engine with multi-provider failover.
Uses three free APIs in a cascade so one rate-limit or outage doesn't break the entire workflow.  
All user inputs pass through the validator before they hit any network call.
"""

import re
import subprocess
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime

from .validator import sanitize_target, resolve_to_ip, InputError


@dataclass
class GeoResult:
    ip: str
    country: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    zip_code: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
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
        if self.latitude and self.longitude:
            return (self.latitude, self.longitude)
        return None

    @property
    def location_string(self):
        parts = [p for p in [self.city, self.region, self.country] if p]
        return ", ".join(parts) if parts else "Unknown"


class GeoEngine:
    PROVIDERS = ["ip-api", "ipapi_co", "ipwhois"]

    def __init__(self, timeout=10):
        self.timeout = timeout
        self._session = requests.Session()
        self._session.headers.update(
            {
                "User-Agent": "PradaFit/2.0",
                "Accept": "application/json",
            }
        )

    def locate(self, target, provider=None):
        """
        Geolocate an IP or hostname.
        Cycles through providers on failure until one succeeds.
        """
        try:
            ip = resolve_to_ip(target)
        except InputError:
            return GeoResult(ip=target, error=f"Cannot resolve '{target}'")

        providers = [provider] if provider else self.PROVIDERS
        last_err = ""

        for prov in providers:
            try:
                if prov == "ip-api":
                    return self._query_ip_api(ip)
                elif prov == "ipapi_co":
                    return self._query_ipapi_co(ip)
                elif prov == "ipwhois":
                    return self._query_ipwhois(ip)
            except Exception as exc:
                last_err = str(exc)
                continue

        return GeoResult(ip=ip, error=f"All providers failed -- last error: {last_err}")

    def bulk_locate(self, targets, provider=None):
        clean = [t.strip() for t in targets if t.strip()]
        results = []
        workers = min(15, max(1, len(clean)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(self.locate, t, provider): t for t in clean}
            for f in as_completed(futs):
                results.append(f.result())
        return results

    def traceroute_geo(self, target):
        from .platform_utils import platform_info

        try:
            ip = resolve_to_ip(target)
        except InputError:
            return [GeoResult(ip=target, error="Cannot resolve target")]

        if platform_info.is_windows:
            cmd = ["tracert", "-d", "-w", "2000", "-h", "30", ip]
        else:
            cmd = ["traceroute", "-n", "-w", "2", "-m", "30", ip]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
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
                resp = self._session.get(url, timeout=self.timeout)
                if "json" in url:
                    return resp.json().get("ip")
                return resp.text.strip()
            except Exception:
                continue
        return None


    def _query_ip_api(self, ip):
        fields = (
            "status,message,country,countryCode,region,regionName,"
            "city,zip,lat,lon,timezone,isp,org,as,asname,reverse,"
            "proxy,mobile,hosting,query"
        )
        url = f"http://ip-api.com/json/{ip}?fields={fields}"
        resp = self._session.get(url, timeout=self.timeout)
        d = resp.json()

        if d.get("status") == "fail":
            raise RuntimeError(d.get("message", "ip-api returned failure"))

        return GeoResult(
            ip=d.get("query", ip),
            country=d.get("country", ""),
            country_code=d.get("countryCode", ""),
            region=d.get("regionName", ""),
            city=d.get("city", ""),
            zip_code=d.get("zip", ""),
            latitude=d.get("lat", 0.0),
            longitude=d.get("lon", 0.0),
            timezone=d.get("timezone", ""),
            isp=d.get("isp", ""),
            org=d.get("org", ""),
            asn=d.get("as", ""),
            as_name=d.get("asname", ""),
            reverse_dns=d.get("reverse", ""),
            is_proxy=d.get("proxy", False),
            is_mobile=d.get("mobile", False),
            is_hosting=d.get("hosting", False),
            source="ip-api.com",
        )

    def _query_ipapi_co(self, ip):
        url = f"https://ipapi.co/{ip}/json/"
        resp = self._session.get(url, timeout=self.timeout)
        d = resp.json()

        if "error" in d:
            raise RuntimeError(d.get("reason", "ipapi.co returned error"))

        return GeoResult(
            ip=d.get("ip", ip),
            country=d.get("country_name", ""),
            country_code=d.get("country_code", ""),
            region=d.get("region", ""),
            city=d.get("city", ""),
            zip_code=d.get("postal", ""),
            latitude=d.get("latitude", 0.0),
            longitude=d.get("longitude", 0.0),
            timezone=d.get("timezone", ""),
            isp=d.get("org", ""),
            org=d.get("org", ""),
            asn=d.get("asn", ""),
            as_name=d.get("org", ""),
            source="ipapi.co",
        )

    def _query_ipwhois(self, ip):
        url = f"https://ipwhois.app/json/{ip}"
        resp = self._session.get(url, timeout=self.timeout)
        d = resp.json()

        if not d.get("success", True):
            raise RuntimeError(d.get("message", "ipwhois returned error"))

        return GeoResult(
            ip=d.get("ip", ip),
            country=d.get("country", ""),
            country_code=d.get("country_code", ""),
            region=d.get("region", ""),
            city=d.get("city", ""),
            zip_code=d.get("postal", ""),
            latitude=d.get("latitude", 0.0),
            longitude=d.get("longitude", 0.0),
            timezone=d.get("timezone", ""),
            isp=d.get("isp", ""),
            org=d.get("org", ""),
            asn=d.get("asn", ""),
            as_name=d.get("as", ""),
            source="ipwhois.app",
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
