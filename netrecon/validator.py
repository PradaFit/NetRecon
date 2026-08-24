"""
Input validation and sanitization for all user-facing entry points.
Prevents injection, malformed data, and resource abuse before anything
touches dns/scan/geo engines.
"""

import re
import ipaddress
import socket


# compile once, reuse everywhere
_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)
_PORT_RANGE_RE = re.compile(r"^(\d{1,5}(-\d{1,5})?,?\s*)+$")
_SAFE_NMAP_RE = re.compile(r"^[A-Za-z0-9\s\-.,:=_]+$")


class InputError(ValueError):
    """Raised when user input fails validation."""

    pass


def sanitize_target(raw):
    """
    Accept an IP, CIDR block, or domain name.  Strips whitespace and
    validates format.  Returns the cleaned string or raises InputError.
    """
    if not raw or not isinstance(raw, str):
        raise InputError("Target cannot be empty")

    cleaned = raw.strip().lower()

    # reject anything with shell-dangerous characters right away
    if any(
        ch in cleaned
        for ch in (";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "\n", "\r")
    ):
        raise InputError(f"Invalid characters in target: {cleaned}")

    if len(cleaned) > 253:
        raise InputError("Target string exceeds maximum domain length")

    # try parsing as IP or CIDR first
    try:
        ipaddress.ip_address(cleaned)
        return cleaned
    except ValueError:
        pass

    try:
        net = ipaddress.ip_network(cleaned, strict=False)
        # cap the subnet to prevent accidental /8 scans eating all memory
        if net.prefixlen < 16:
            raise InputError(
                f"Subnet /{net.prefixlen} is too broad -- minimum prefix is /16"
            )
        return cleaned
    except ValueError:
        pass

    if _DOMAIN_RE.match(cleaned):
        return cleaned

    # last resort like maybe it's a bare hostname (single label)
    if re.match(r"^[A-Za-z0-9][A-Za-z0-9-]{0,62}$", cleaned):
        return cleaned

    raise InputError(f"Cannot parse target: {raw}")


def sanitize_port_spec(raw):
    """
    Validate and clean a port specification like '22,80,443' or '1-1024'.
    Returns cleaned string or raises InputError.
    """
    if not raw:
        return None

    cleaned = raw.strip().replace(" ", "")
    if not _PORT_RANGE_RE.match(cleaned):
        raise InputError(f"Bad port specification: {raw}")

    for segment in cleaned.split(","):
        if not segment:
            continue
        parts = segment.split("-")
        for p in parts:
            num = int(p)
            if num < 1 or num > 65535:
                raise InputError(f"Port {num} out of range (1-65535)")
        if len(parts) == 2 and int(parts[0]) > int(parts[1]):
            raise InputError(f"Invalid port range: {segment}")

    return cleaned


def sanitize_nmap_args(raw):
    """
    Validate custom Nmap arguments against a deliberately small allowlist.

    Nmap is launched without a shell, but restricting options also prevents
    local file reads/writes, proxying, external data files, and arbitrary NSE
    script paths from being introduced through the GUI.
    """
    if not raw:
        return None

    cleaned = raw.strip()
    if not _SAFE_NMAP_RE.match(cleaned):
        raise InputError("Nmap arguments contain disallowed characters")

    tokens = cleaned.split()
    flag_options = {
        "-sS",
        "-sT",
        "-sU",
        "-sV",
        "-sC",
        "-sn",
        "-O",
        "-A",
        "-F",
        "-Pn",
        "-n",
        "-R",
        "-6",
        "--open",
        "--reason",
        "--osscan-guess",
        "--osscan-limit",
        "--version-light",
        "--version-all",
    }
    value_options = {
        "-p",
        "--top-ports",
        "--version-intensity",
        "--max-retries",
        "--host-timeout",
        "--script-timeout",
        "--script",
    }

    def validate_value(option, value):
        if option == "-p":
            if value == "-":
                return
            sanitize_port_spec(value)
        elif option == "--top-ports":
            if not value.isdigit() or not 1 <= int(value) <= 65535:
                raise InputError("--top-ports must be between 1 and 65535")
        elif option == "--version-intensity":
            if not value.isdigit() or not 0 <= int(value) <= 9:
                raise InputError("--version-intensity must be between 0 and 9")
        elif option == "--max-retries":
            if not value.isdigit() or not 0 <= int(value) <= 10:
                raise InputError("--max-retries must be between 0 and 10")
        elif option in {"--host-timeout", "--script-timeout"}:
            if not re.fullmatch(r"\d+(?:ms|s|m|h)?", value):
                raise InputError(f"{option} must be a number with ms, s, m, or h")
        elif option == "--script":
            categories = value.split(",")
            if not categories or any(
                category not in {"default", "safe", "vuln"}
                for category in categories
            ):
                raise InputError(
                    "--script is limited to the default, safe, and vuln categories"
                )

    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in flag_options or re.fullmatch(r"-T[0-5]", token):
            index += 1
            continue
        if token in value_options:
            if index + 1 >= len(tokens):
                raise InputError(f"Nmap argument '{token}' requires a value")
            validate_value(token, tokens[index + 1])
            index += 2
            continue
        matched = False
        for option in value_options:
            prefix = option + "="
            if token.startswith(prefix):
                validate_value(option, token[len(prefix) :])
                matched = True
                break
        if matched:
            index += 1
            continue
        if token.startswith("-p") and len(token) > 2:
            validate_value("-p", token[2:])
            index += 1
            continue
        raise InputError(f"Nmap argument '{token}' is not in the safe allowlist")

    return " ".join(tokens)


def sanitize_dns_type(raw):
    """Validate DNS record type string."""
    allowed = {"A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "PTR", "SRV", "CAA"}
    if not raw:
        return "A"
    val = raw.strip().upper()
    if val not in allowed:
        raise InputError(f"Unsupported DNS record type: {raw}")
    return val


def sanitize_nameserver(raw):
    """Validate a nameserver IP address."""
    if not raw:
        return None
    cleaned = raw.strip()
    try:
        ipaddress.ip_address(cleaned)
        return cleaned
    except ValueError:
        raise InputError(f"Invalid nameserver IP: {raw}")


def resolve_to_ip(target):
    """
    Resolve a target (IP or hostname) to an IP address string.
    Used internally before raw socket scanning.
    """
    cleaned = sanitize_target(target)
    try:
        ipaddress.ip_address(cleaned)
        return cleaned
    except ValueError:
        pass
    try:
        return socket.gethostbyname(cleaned)
    except socket.gaierror:
        raise InputError(f"Cannot resolve hostname: {cleaned}")


def parse_port_list(spec):
    """
    Parse a port specification into a sorted list of integers.
    Supports '22,80,443' and '1-1024' and combinations like '22,80,100-200'.
    """
    if not spec:
        return []

    spec = sanitize_port_spec(spec)
    if spec is None:
        return []

    ports = set()
    for segment in spec.split(","):
        if not segment:
            continue
        if "-" in segment:
            lo, hi = segment.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(segment))

    return sorted(ports)
