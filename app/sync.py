"""Orchestration: turn a NetBox webhook event into nsupdate calls.

Two independent behaviors, each triggered by its own NetBox event rule:
  (a) dns_name sync   - ipam.ipaddress created/updated/deleted
  (b) device-name sync - dcim.device created/updated/deleted (primary IP
                          assignment)

Both converge on the same BIND zones via `DnsUpdater.replace_record` /
`delete_record`, which are idempotent, so at-least-once webhook delivery is
safe as long as out-of-order delivery is filtered out first (see state.py).
"""
from __future__ import annotations

import logging
from typing import Any

from app import zones
from app.config import Settings
from app.dns_update import DnsUpdater
from app.models import WebhookEnvelope
from app.netbox_client import NetboxClient, is_allowed_ip_status, is_excluded_device_status
from app.state import EventStateStore

logger = logging.getLogger(__name__)


def _strip_prefix(address: str | None) -> str | None:
    if not address:
        return None
    return address.split("/")[0]


def _extract_ip_from_field(value: Any) -> str | None:
    """primary_ip4/primary_ip6 snapshot values may be a nested dict (from
    `data`, reliable) or a raw PK / absent (from older snapshot shapes) -
    only destructure the dict form here; PK-only values must be resolved via
    NetboxClient by the caller.
    """
    if isinstance(value, dict):
        return _strip_prefix(value.get("address"))
    return None


class SyncService:
    def __init__(
        self,
        cfg: Settings,
        dns_updater: DnsUpdater,
        netbox: NetboxClient,
        state: EventStateStore,
    ):
        self._cfg = cfg
        self._dns = dns_updater
        self._netbox = netbox
        self._state = state

    def handle_ipaddress_event(self, envelope: WebhookEnvelope) -> None:
        cfg = self._cfg
        pre = envelope.prechange
        data = envelope.data or {}
        object_id = data.get("id") or pre.get("id")
        if object_id is None:
            logger.warning("ipaddress webhook missing id, skipping")
            return
        if self._state.is_stale("ipaddress", object_id, envelope.timestamp):
            logger.info("skipping stale ipaddress event id=%s", object_id)
            return

        event = envelope.event
        old_dns_name = pre.get("dns_name")
        new_dns_name = (
            data.get("dns_name")
            if event != "deleted" and is_allowed_ip_status(data.get("status"))
            else None
        )
        if (
            event != "deleted"
            and data.get("dns_name")
            and not is_allowed_ip_status(data.get("status"))
        ):
            logger.info(
                "skipping ipaddress id=%s: status %r not in allowed set",
                object_id, data.get("status"),
            )

        old_addr = _strip_prefix(pre.get("address"))
        new_addr = _strip_prefix(data.get("address")) if event != "deleted" else None

        old_match = zones.match_forward_zone(old_dns_name, cfg.forward_zones)
        new_match = (
            zones.match_forward_zone(new_dns_name, cfg.forward_zones)
            if event != "deleted"
            else None
        )

        old_rdtype = zones.rdtype_for_address(old_addr) if old_addr else None
        new_rdtype = zones.rdtype_for_address(new_addr) if new_addr else None

        if old_match and (event == "deleted" or not new_match or old_match != new_match):
            self._dns.delete_record(old_match.zone, old_match.owner_fqdn, old_rdtype)

        if event != "deleted" and new_match:
            self._dns.replace_record(
                new_match.zone, new_match.owner_fqdn, new_rdtype, cfg.dns.ttl, [new_addr]
            )

        is_primary = self._netbox.is_primary_ip(object_id) if event != "deleted" else False
        owns_ptr = not (cfg.ptr_priority == "primary_ip_first" and is_primary)

        if owns_ptr:
            old_rmatch = zones.match_reverse_zone(old_addr, cfg.reverse_zones) if old_addr else None
            new_rmatch = (
                zones.match_reverse_zone(new_addr, cfg.reverse_zones)
                if (new_addr and event != "deleted")
                else None
            )

            if old_rmatch and (
                event == "deleted"
                or not new_rmatch
                or old_rmatch != new_rmatch
                or not new_match
            ):
                self._dns.delete_record(old_rmatch.zone, old_rmatch.owner_fqdn, "PTR")

            if event != "deleted" and new_rmatch and new_match:
                self._dns.replace_record(
                    new_rmatch.zone,
                    new_rmatch.owner_fqdn,
                    "PTR",
                    cfg.dns.ttl,
                    [new_match.owner_fqdn],
                )

        self._state.record("ipaddress", object_id, envelope.timestamp)

    def handle_device_event(self, envelope: WebhookEnvelope) -> None:
        cfg = self._cfg
        pre = envelope.prechange
        data = envelope.data or {}
        object_id = data.get("id") or pre.get("id")
        if object_id is None:
            logger.warning("device webhook missing id, skipping")
            return
        if self._state.is_stale("device", object_id, envelope.timestamp):
            logger.info("skipping stale device event id=%s", object_id)
            return

        event = envelope.event
        new_name = data.get("name")
        old_name = pre.get("name", new_name)

        old_fqdn_base = f"{old_name}.{cfg.device_zone}." if old_name else None
        if old_fqdn_base and not zones.is_valid_dns_name(old_fqdn_base):
            old_fqdn_base = None

        new_fqdn_base = f"{new_name}.{cfg.device_zone}." if new_name else None
        if new_fqdn_base and not zones.is_valid_dns_name(new_fqdn_base):
            logger.warning(
                "skipping device id=%s name=%r: %r is not a legal DNS hostname",
                object_id, new_name, new_fqdn_base,
            )
            new_fqdn_base = None
        elif new_fqdn_base and event != "deleted" and is_excluded_device_status(data.get("status")):
            logger.info(
                "skipping device id=%s name=%r: status %r is excluded",
                object_id, new_name, data.get("status"),
            )
            new_fqdn_base = None

        for rdtype, ip_field in (("A", "primary_ip4"), ("AAAA", "primary_ip6")):
            old_had = ip_field in pre and pre.get(ip_field) is not None
            new_has = event != "deleted" and data.get(ip_field) is not None

            old_fqdn = old_fqdn_base if old_had else None
            new_fqdn = new_fqdn_base if new_has else None

            if old_fqdn and (event == "deleted" or not new_has or old_fqdn != new_fqdn):
                self._dns.delete_record(cfg.device_zone, old_fqdn, rdtype)

            if new_has and new_fqdn:
                new_ip = _extract_ip_from_field(data.get(ip_field))
                if new_ip:
                    self._dns.replace_record(cfg.device_zone, new_fqdn, rdtype, cfg.dns.ttl, [new_ip])
                    rmatch = zones.match_reverse_zone(new_ip, cfg.reverse_zones)
                    if rmatch:
                        self._dns.replace_record(
                            rmatch.zone, rmatch.owner_fqdn, "PTR", cfg.dns.ttl, [new_fqdn]
                        )
            elif old_had:
                old_ip = _extract_ip_from_field(pre.get(ip_field))
                if old_ip is None:
                    raw = pre.get(ip_field)
                    if isinstance(raw, int):
                        old_ip = self._netbox.resolve_ip_address(raw)
                if old_ip:
                    rmatch = zones.match_reverse_zone(old_ip, cfg.reverse_zones)
                    if rmatch:
                        self._dns.delete_record(rmatch.zone, rmatch.owner_fqdn, "PTR")

        self._state.record("device", object_id, envelope.timestamp)
