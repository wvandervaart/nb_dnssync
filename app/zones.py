"""Zone matching: which configured zone (if any) owns a given name/IP."""
from __future__ import annotations

import logging
import re
from ipaddress import ip_address, ip_network
from typing import NamedTuple

import dns.reversename

from app.config import ReverseZoneEntry

logger = logging.getLogger(__name__)

_LABEL_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


class ForwardMatch(NamedTuple):
    zone: str
    owner_fqdn: str  # absolute, trailing dot


class ReverseMatch(NamedTuple):
    zone: str
    owner_fqdn: str  # absolute, trailing dot


def _normalize(name: str) -> str:
    return name.strip().rstrip(".").lower()


def is_valid_dns_name(fqdn: str) -> bool:
    """RFC 1123 hostname syntax check (letters/digits/hyphens per label, no
    leading/trailing hyphen, 63 octets per label, 253 chars overall).

    NetBox lets `dns_name` and device `name` be arbitrary free text - values
    with spaces, underscores, or punctuation are common typos/labels that
    would otherwise get pushed into BIND unchanged. dnspython/BIND don't
    reject these outright (DNS wire format allows arbitrary label bytes),
    so this is an explicit choke point to keep synced records to legal
    hostnames rather than relying on the DNS server to catch it.
    """
    name = fqdn.strip().rstrip(".")
    if not name or len(name) > 253:
        return False
    return all(_LABEL_RE.match(label) is not None for label in name.split("."))


def match_forward_zone(
    dns_name: str | None, forward_zones: list[str]
) -> ForwardMatch | None:
    """Find the most specific configured forward zone that `dns_name` falls
    within. Returns None if dns_name is empty, matches no configured zone,
    or isn't a legal DNS hostname.
    """
    if not dns_name:
        return None

    name = _normalize(dns_name)
    best_zone: str | None = None

    for configured in forward_zones:
        zone = _normalize(configured)
        if not zone:
            continue
        if name == zone or name.endswith("." + zone):
            if best_zone is None or len(zone) > len(best_zone):
                best_zone = zone

    if best_zone is None:
        return None

    owner_fqdn = name + "."
    if not is_valid_dns_name(owner_fqdn):
        logger.warning("skipping dns_name %r: not a legal DNS hostname", dns_name)
        return None

    return ForwardMatch(zone=best_zone, owner_fqdn=owner_fqdn)


def match_reverse_zone(
    ip_str: str, reverse_zones: list[ReverseZoneEntry]
) -> ReverseMatch | None:
    """Find the configured reverse zone containing `ip_str`. Returns None if
    no configured network contains the address.
    """
    addr = ip_address(ip_str)
    best: ReverseZoneEntry | None = None

    for entry in reverse_zones:
        network = ip_network(entry.network)
        if addr in network:
            if best is None or network.prefixlen > ip_network(best.network).prefixlen:
                best = entry

    if best is None:
        return None

    owner_fqdn = str(dns.reversename.from_address(str(addr)))
    return ReverseMatch(zone=_normalize(best.zone), owner_fqdn=owner_fqdn)


def rdtype_for_address(ip_str: str) -> str:
    return "AAAA" if ip_address(ip_str).version == 6 else "A"
