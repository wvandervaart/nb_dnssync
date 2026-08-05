"""The one NetBox REST callback the service needs: given an IP address id,
is it *currently* a device's primary IPv4/IPv6? This can't be derived from
the ipaddress webhook payload alone (that relation lives on the Device
object), and we don't want to wait for a separate device webhook to arrive
before deciding PTR ownership.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

import pynetbox

from app.config import NetboxConfig

logger = logging.getLogger(__name__)

# Devices in these statuses are never synced, regardless of primary IP.
EXCLUDED_DEVICE_STATUSES = frozenset({"offline", "inventory"})

# IP addresses are only synced if in one of these statuses.
ALLOWED_IP_STATUSES = frozenset({"active", "reserved"})


def _status_value(status: object) -> str | None:
    """Normalize a NetBox `status` field to its lowercase value.

    Shapes seen in the wild: a plain string (rare), a nested dict
    {"value": "offline", "label": "Offline", ...} (webhook JSON payloads),
    or a pynetbox Record with a `.value` attribute (bulk REST listings).
    Applies equally to device and IP address status fields - both use the
    same NetBox choice-field shape.
    """
    if status is None:
        return None
    if isinstance(status, str):
        return status.lower()
    if isinstance(status, dict):
        value = status.get("value")
    else:
        value = getattr(status, "value", None)
    return str(value).lower() if value is not None else None


def is_excluded_device_status(status: object) -> bool:
    return _status_value(status) in EXCLUDED_DEVICE_STATUSES


def is_allowed_ip_status(status: object) -> bool:
    return _status_value(status) in ALLOWED_IP_STATUSES


@dataclass(frozen=True)
class IpAddressRecord:
    id: int
    address: str  # prefix stripped, e.g. "10.0.0.5"
    dns_name: str  # always non-empty


@dataclass(frozen=True)
class DeviceRecord:
    id: int
    name: str | None
    primary_ip4: str | None
    primary_ip4_id: int | None
    primary_ip6: str | None
    primary_ip6_id: int | None


class NetboxClient:
    def __init__(self, cfg: NetboxConfig):
        self._api = pynetbox.api(cfg.url, token=cfg.token)
        self._api.http_session.verify = cfg.verify_ssl

    def list_dns_ip_addresses(self) -> list[IpAddressRecord]:
        """All IP addresses with a non-empty dns_name and status active or
        reserved (see ALLOWED_IP_STATUSES).

        Tries a server-side filter first (less data over the wire on large
        IPAM tables), but never trusts it alone: some NetBox versions reject
        an unrecognized filter param, others silently ignore it - the
        client-side checks below are the actual correctness guarantee
        either way.

        Unlike is_primary_ip/resolve_ip_address, this does NOT swallow
        exceptions: a bootstrap run that silently reports "nothing to sync"
        because NetBox was unreachable is worse than a loud failure.
        """
        try:
            raw = list(self._api.ipam.ip_addresses.filter(dns_name__empty=False))
        except Exception:
            logger.warning(
                "ip_addresses.filter(dns_name__empty=False) failed "
                "(unsupported on this NetBox version?) - falling back to a full listing",
                exc_info=True,
            )
            raw = list(self._api.ipam.ip_addresses.all())

        out: list[IpAddressRecord] = []
        for ip in raw:
            dns_name = (ip.dns_name or "").strip()
            if not dns_name:
                continue
            if not is_allowed_ip_status(ip.status):
                continue
            out.append(
                IpAddressRecord(
                    id=ip.id, address=str(ip.address).split("/")[0], dns_name=dns_name
                )
            )
        return out

    def list_devices_with_primary_ip(self) -> list[DeviceRecord]:
        """All devices with a primary IPv4 and/or IPv6, excluding devices in
        status offline or inventory (see EXCLUDED_DEVICE_STATUSES).

        Fetched in full and filtered client-side: devices are a much smaller
        table than IP addresses, and this avoids depending on exact
        primary_ip4/primary_ip6 filter-lookup names across NetBox versions.
        Exceptions are not swallowed - see list_dns_ip_addresses.
        """
        out: list[DeviceRecord] = []
        for dev in self._api.dcim.devices.all():
            if is_excluded_device_status(dev.status):
                continue
            ip4, ip6 = dev.primary_ip4, dev.primary_ip6
            if ip4 is None and ip6 is None:
                continue
            out.append(
                DeviceRecord(
                    id=dev.id,
                    name=dev.name,
                    primary_ip4=str(ip4.address).split("/")[0] if ip4 else None,
                    primary_ip4_id=ip4.id if ip4 else None,
                    primary_ip6=str(ip6.address).split("/")[0] if ip6 else None,
                    primary_ip6_id=ip6.id if ip6 else None,
                )
            )
        return out

    def is_primary_ip(self, ip_id: int) -> bool:
        try:
            v4_hit = self._api.dcim.devices.filter(primary_ip4_id=ip_id)
            if len(list(v4_hit)) > 0:
                return True
            v6_hit = self._api.dcim.devices.filter(primary_ip6_id=ip_id)
            return len(list(v6_hit)) > 0
        except Exception:
            logger.exception("failed to check primary-IP status for ip_id=%s", ip_id)
            return False

    def resolve_ip_address(self, ip_id: int) -> str | None:
        """Best-effort lookup of an IP's address string by id, used for
        cleanup when a stale snapshot only gives us a primary_ip PK.
        """
        try:
            ip = self._api.ipam.ip_addresses.get(ip_id)
        except Exception:
            logger.exception("failed to resolve ip address for ip_id=%s", ip_id)
            return None
        if ip is None:
            return None
        return str(ip.address).split("/")[0]
