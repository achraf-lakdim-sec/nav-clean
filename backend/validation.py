"""Input validation for everything that ends up on the Nmap command line.

The API builds Nmap commands as argument lists, so shell injection is not
possible. Argument injection still is: a "target" such as `--script=...` or
`-iL /etc/passwd` would be parsed by Nmap as an option. Every user-supplied
target and port specification therefore goes through these allow-lists first.
"""
import ipaddress
import re

from fastapi import HTTPException

# Largest network the API will scan in one request (a /16 is 65,536 addresses).
MIN_IPV4_PREFIX = 16
MIN_IPV6_PREFIX = 112

_HOSTNAME_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HOSTNAME = re.compile(rf"^{_HOSTNAME_LABEL}(?:\.{_HOSTNAME_LABEL})*\.?$")
_PORT_ITEM = re.compile(r"^(\d{1,5})(?:-(\d{1,5}))?$")


def validate_target(target: str) -> str:
    """Accept a single IP address, a CIDR network or a hostname, nothing else."""
    value = (target or "").strip()
    if not value or len(value) > 253:
        raise HTTPException(status_code=422, detail="Invalid target")

    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        network = None

    if network is not None:
        minimum = MIN_IPV4_PREFIX if network.version == 4 else MIN_IPV6_PREFIX
        if network.prefixlen < minimum:
            raise HTTPException(
                status_code=422,
                detail=f"Network too large: use a /{minimum} or smaller range",
            )
        return str(network) if network.num_addresses > 1 else str(network.network_address)

    if _HOSTNAME.match(value):
        return value

    raise HTTPException(status_code=422, detail="Invalid target")


def validate_ports(ports: str) -> str:
    """Accept a comma-separated list of ports or port ranges, such as 22,80,8000-8100."""
    value = (ports or "").replace(" ", "")
    if not value or len(value) > 512:
        raise HTTPException(status_code=422, detail="Invalid port specification")

    for item in value.split(","):
        match = _PORT_ITEM.match(item)
        if not match:
            raise HTTPException(status_code=422, detail="Invalid port specification")
        start = int(match.group(1))
        end = int(match.group(2) or start)
        if not (1 <= start <= end <= 65535):
            raise HTTPException(status_code=422, detail="Port out of range")
    return value
