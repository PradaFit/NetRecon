"""
DNS resolution engine with async batch support, multi-server propagation
checks, zone transfers, and WHOIS lookups.

Uses dnspython for queries and the concurrent.futures pool for parallel
operations that the GUI and CLI both rely on.  Input validation runs
through netrecon.validator before any query touches the wire.
"""

import time
import socket
import dns.resolver
import dns.reversename
import dns.zone
import dns.query
import dns.rdatatype
import dns.exception
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime

from .validator import (
    sanitize_target,
    sanitize_dns_type,
    sanitize_nameserver,
    InputError,
)


PUBLIC_DNS_SERVERS = {
    "Google": "8.8.8.8",
    "Google Secondary": "8.8.4.4",
    "Cloudflare": "1.1.1.1",
    "Cloudflare Secondary": "1.0.0.1",
    "Quad9": "9.9.9.9",
    "OpenDNS": "208.67.222.222",
    "OpenDNS Secondary": "208.67.220.220",
    "Comodo Secure": "8.26.56.26",
    "Level3": "4.2.2.2",
    "Verisign": "64.6.64.6",
}

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "PTR", "SRV", "CAA"]


@dataclass
class DNSResult:
    query: str
    record_type: str
    records: list = field(default_factory=list)
    server: str = "System Default"
    response_time_ms: float = 0.0
    error: str = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self):
        return asdict(self)


class DNSEngine:
    """
    Thread-safe DNS engine.  Each public method validates its inputs,
    builds a fresh resolver instance, and returns DNSResult objects.
    """

    def __init__(self, timeout=5, lifetime=10):
        self.timeout = timeout
        self.lifetime = lifetime

    def _resolver(self, nameserver=None):
        r = dns.resolver.Resolver()
        r.timeout = self.timeout
        r.lifetime = self.lifetime
        if nameserver:
            r.nameservers = [nameserver]
        return r

    # single lookups

    def resolve(self, domain, record_type="A", nameserver=None):
        try:
            domain = sanitize_target(domain)
            record_type = sanitize_dns_type(record_type)
            nameserver = sanitize_nameserver(nameserver)
        except InputError as exc:
            return DNSResult(query=domain, record_type=record_type, error=str(exc))

        resolver = self._resolver(nameserver)
        server_label = nameserver or "System Default"
        t0 = time.perf_counter()

        try:
            answers = resolver.resolve(domain, record_type)
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)

            records = []
            for rdata in answers:
                rec = {"value": str(rdata)}
                if record_type == "MX":
                    rec["preference"] = rdata.preference
                    rec["exchange"] = str(rdata.exchange)
                elif record_type == "SOA":
                    rec.update(
                        {
                            "mname": str(rdata.mname),
                            "rname": str(rdata.rname),
                            "serial": rdata.serial,
                            "refresh": rdata.refresh,
                            "retry": rdata.retry,
                            "expire": rdata.expire,
                            "minimum": rdata.minimum,
                        }
                    )
                elif record_type == "SRV":
                    rec.update(
                        {
                            "priority": rdata.priority,
                            "weight": rdata.weight,
                            "port": rdata.port,
                            "target": str(rdata.target),
                        }
                    )
                records.append(rec)

            return DNSResult(
                query=domain,
                record_type=record_type,
                records=records,
                server=server_label,
                response_time_ms=elapsed_ms,
            )

        except dns.resolver.NXDOMAIN:
            return DNSResult(
                query=domain,
                record_type=record_type,
                server=server_label,
                error="NXDOMAIN -- domain does not exist",
            )
        except dns.resolver.NoAnswer:
            return DNSResult(
                query=domain,
                record_type=record_type,
                server=server_label,
                error=f"No {record_type} records found",
            )
        except dns.resolver.NoNameservers:
            return DNSResult(
                query=domain,
                record_type=record_type,
                server=server_label,
                error="No nameservers reachable",
            )
        except dns.exception.Timeout:
            return DNSResult(
                query=domain,
                record_type=record_type,
                server=server_label,
                error="Query timed out",
            )
        except Exception as exc:
            return DNSResult(
                query=domain,
                record_type=record_type,
                server=server_label,
                error=str(exc),
            )

    def reverse_lookup(self, ip_address):
        try:
            sanitize_target(ip_address)
        except InputError as exc:
            return DNSResult(
                query=ip_address, record_type="PTR (Reverse)", error=str(exc)
            )

        try:
            rev = dns.reversename.from_address(ip_address)
            t0 = time.perf_counter()
            answers = dns.resolver.resolve(rev, "PTR")
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
            records = [{"value": str(rdata)} for rdata in answers]
            return DNSResult(
                query=ip_address,
                record_type="PTR (Reverse)",
                records=records,
                response_time_ms=elapsed_ms,
            )
        except Exception as exc:
            return DNSResult(
                query=ip_address, record_type="PTR (Reverse)", error=str(exc)
            )

    # batch / concurrent operations

    def get_all_records(self, domain):
        out = []
        with ThreadPoolExecutor(max_workers=len(RECORD_TYPES)) as pool:
            futs = {pool.submit(self.resolve, domain, rt): rt for rt in RECORD_TYPES}
            for f in as_completed(futs):
                result = f.result()
                if result.records:
                    out.append(result)
        return out

    def propagation_check(self, domain, record_type="A"):
        results = []
        with ThreadPoolExecutor(max_workers=len(PUBLIC_DNS_SERVERS)) as pool:
            futs = {
                pool.submit(self.resolve, domain, record_type, ip): name
                for name, ip in PUBLIC_DNS_SERVERS.items()
            }
            for f in as_completed(futs):
                results.append(f.result())
        return sorted(results, key=lambda r: r.server)

    def bulk_resolve(self, domains, record_type="A"):
        clean = [d.strip() for d in domains if d.strip()]
        results = []
        workers = min(30, max(1, len(clean)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(self.resolve, d, record_type): d for d in clean}
            for f in as_completed(futs):
                results.append(f.result())
        return results

    # zone transfer

    def zone_transfer(self, domain, nameserver=None):
        try:
            domain = sanitize_target(domain)
        except InputError as exc:
            return {"success": False, "error": str(exc)}

        try:
            if not nameserver:
                ns_result = self.resolve(domain, "NS")
                if ns_result.error:
                    return {
                        "success": False,
                        "error": f"NS lookup failed: {ns_result.error}",
                    }
                nameserver = str(ns_result.records[0]["value"]).rstrip(".")

            zone = dns.zone.from_xfr(
                dns.query.xfr(nameserver, domain, timeout=self.timeout)
            )
            records = []
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        records.append(
                            {
                                "name": str(name),
                                "type": dns.rdatatype.to_text(rdataset.rdtype),
                                "ttl": rdataset.ttl,
                                "value": str(rdata),
                            }
                        )
            return {"success": True, "records": records, "total": len(records)}
        except dns.xfr.TransferError:
            return {"success": False, "error": "Zone transfer refused by server"}
        except Exception as exc:
            return {"success": False, "error": f"Zone transfer failed: {exc}"}

    # WHOIS

    def whois_lookup(self, target):
        try:
            target = sanitize_target(target)
        except InputError as exc:
            return {"error": str(exc)}

        try:
            import whois

            w = whois.whois(target)
            return {
                "domain": w.domain_name,
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "updated_date": str(w.updated_date),
                "name_servers": w.name_servers,
                "status": w.status,
                "org": getattr(w, "org", "N/A"),
                "country": getattr(w, "country", "N/A"),
                "emails": w.emails,
            }
        except ImportError:
            return {"error": "python-whois is not installed (pip install python-whois)"}
        except Exception as exc:
            return {"error": f"WHOIS lookup failed: {exc}"}

    # utility

    @staticmethod
    def resolve_hostname(hostname):
        try:
            results = socket.getaddrinfo(hostname, None)
            ips = sorted(set(addr[4][0] for addr in results))
            return {"hostname": hostname, "addresses": ips}
        except socket.gaierror as exc:
            return {"hostname": hostname, "error": str(exc)}
