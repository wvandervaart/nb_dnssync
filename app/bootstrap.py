"""Bulk/init sync: pull all currently-relevant NetBox data (IPs with a
dns_name matching a configured forward zone, devices with a primary IP) and
push the corresponding DNS records to BIND in one pass - to bootstrap a zone
the first time nb_dnssync is pointed at it, rather than waiting for every
object to be touched again in NetBox before a webhook fires for it.

Two modes:
  - backfill (default): only ever creates/updates matching records. Safe to
    run against a zone with no allow-transfer configured yet - if a zone's
    current state can't be read via AXFR, records are written unconditionally.
  - --prune: also deletes BIND A/AAAA/PTR records no longer backed by
    NetBox data. Requires allow-transfer for the TSIG key on every
    configured zone; aborts the whole run with no changes if any zone's
    transfer fails (no partial pruning).

Either mode only ever touches A, AAAA, and PTR records - nothing else in a
zone is read, created, or deleted.

Usage: python -m app.bootstrap [--dry-run] [--prune] [--config PATH]
"""
from __future__ import annotations

import argparse
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app import zones
from app.config import Settings, load_settings
from app.dns_update import DnsUpdater
from app.logging_conf import configure_logging
from app.netbox_client import NetboxClient
from app.state import EventStateStore

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DesiredRecord:
    zone: str
    owner_fqdn: str
    rdtype: str  # "A" | "AAAA" | "PTR"
    values: list[str]
    source_type: str  # "ipaddress" | "device"
    source_id: int


@dataclass(frozen=True)
class PlanAction:
    kind: str  # "create" | "update" | "apply" | "unchanged" | "delete"
    zone: str
    owner_fqdn: str
    rdtype: str
    values: list[str]
    source_type: str | None  # None for "delete" (no live NetBox object)
    source_id: int | None


@dataclass
class Summary:
    created: int = 0
    updated: int = 0
    applied: int = 0
    deleted: int = 0
    unchanged: int = 0
    per_zone: dict[str, dict[str, int]] = field(default_factory=dict)


class BootstrapAxfrError(RuntimeError):
    def __init__(self, zone: str, cause: Exception):
        self.zone = zone
        self.cause = cause
        super().__init__(f"AXFR of zone {zone!r} failed: {cause}")


def _add_desired(
    desired: dict[tuple[str, str, str], DesiredRecord], record: DesiredRecord
) -> None:
    key = (record.zone, record.owner_fqdn, record.rdtype)
    existing = desired.get(key)
    if existing is not None and sorted(existing.values) != sorted(record.values):
        logger.warning(
            "desired-state collision zone=%s owner=%s type=%s: %s (%s:%s) overrides %s (%s:%s)",
            record.zone,
            record.owner_fqdn,
            record.rdtype,
            record.values,
            record.source_type,
            record.source_id,
            existing.values,
            existing.source_type,
            existing.source_id,
        )
    desired[key] = record


def build_desired_state(
    cfg: Settings, netbox: NetboxClient
) -> dict[tuple[str, str, str], DesiredRecord]:
    """Compute every (zone, owner_fqdn, rdtype) -> DesiredRecord that should
    exist in BIND per current NetBox data. Mirrors the record-selection
    logic in SyncService (app/sync.py) exactly, just computed from a live
    bulk listing instead of a webhook event diff.
    """
    device_records = netbox.list_devices_with_primary_ip()
    ip_records = netbox.list_dns_ip_addresses()

    # Replaces the webhook path's per-IP is_primary_ip() call: built once
    # from the (small) devices listing instead of one API call per IP.
    primary_ip_ids: set[int] = set()
    for dev in device_records:
        if dev.primary_ip4_id:
            primary_ip_ids.add(dev.primary_ip4_id)
        if dev.primary_ip6_id:
            primary_ip_ids.add(dev.primary_ip6_id)

    desired: dict[tuple[str, str, str], DesiredRecord] = {}

    for ip in ip_records:
        fmatch = zones.match_forward_zone(ip.dns_name, cfg.forward_zones)
        if not fmatch:
            continue
        rdtype = zones.rdtype_for_address(ip.address)
        _add_desired(
            desired,
            DesiredRecord(
                fmatch.zone, fmatch.owner_fqdn, rdtype, [ip.address], "ipaddress", ip.id
            ),
        )

        owns_ptr = not (cfg.ptr_priority == "primary_ip_first" and ip.id in primary_ip_ids)
        if owns_ptr:
            rmatch = zones.match_reverse_zone(ip.address, cfg.reverse_zones)
            if rmatch:
                _add_desired(
                    desired,
                    DesiredRecord(
                        rmatch.zone,
                        rmatch.owner_fqdn,
                        "PTR",
                        [fmatch.owner_fqdn],
                        "ipaddress",
                        ip.id,
                    ),
                )

    # Runs after the IP pass: on a same-owner PTR collision (only possible
    # with ptr_priority="dns_name_first"), the device record wins - matching
    # SyncService.handle_device_event, which writes device PTRs
    # unconditionally regardless of ptr_priority. Not "fixing" that
    # asymmetry here, just mirroring already-shipped behavior.
    for dev in device_records:
        if not dev.name:
            continue
        fqdn = f"{dev.name}.{cfg.device_zone}."
        if not zones.is_valid_dns_name(fqdn):
            logger.warning(
                "skipping device id=%s name=%r: %r is not a legal DNS hostname",
                dev.id, dev.name, fqdn,
            )
            continue
        for rdtype, addr in (("A", dev.primary_ip4), ("AAAA", dev.primary_ip6)):
            if not addr:
                continue
            _add_desired(
                desired,
                DesiredRecord(cfg.device_zone, fqdn, rdtype, [addr], "device", dev.id),
            )
            rmatch = zones.match_reverse_zone(addr, cfg.reverse_zones)
            if rmatch:
                _add_desired(
                    desired,
                    DesiredRecord(
                        rmatch.zone, rmatch.owner_fqdn, "PTR", [fqdn], "device", dev.id
                    ),
                )

    return desired


def _normalize_zone(name: str) -> str:
    return name.strip().rstrip(".").lower()


def _configured_zones(cfg: Settings) -> list[str]:
    all_zones = set(cfg.forward_zones) | {cfg.device_zone} | {
        rz.zone for rz in cfg.reverse_zones
    }
    return sorted({_normalize_zone(z) for z in all_zones if z})


def diff_zone(
    zone: str,
    desired_in_zone: dict[tuple[str, str], DesiredRecord],
    current_in_zone: dict[tuple[str, str], list[str]] | None,
    prune: bool,
) -> list[PlanAction]:
    actions: list[PlanAction] = []
    seen: set[tuple[str, str]] = set()

    for key, rec in desired_in_zone.items():
        seen.add(key)
        desired_values = sorted(rec.values)
        if current_in_zone is None:
            kind = "apply"  # whole-zone current state unknown
        elif key not in current_in_zone:
            kind = "create"
        elif current_in_zone[key] == desired_values:
            kind = "unchanged"
        else:
            kind = "update"
        actions.append(
            PlanAction(kind, zone, key[0], key[1], desired_values, rec.source_type, rec.source_id)
        )

    if prune and current_in_zone is not None:
        for key, values in current_in_zone.items():
            if key not in seen:
                actions.append(PlanAction("delete", zone, key[0], key[1], values, None, None))

    return actions


def compute_plan(
    cfg: Settings, netbox: NetboxClient, dns_updater: DnsUpdater, prune: bool
) -> list[PlanAction]:
    desired = build_desired_state(cfg, netbox)

    desired_by_zone: dict[str, dict[tuple[str, str], DesiredRecord]] = {}
    for (zone, owner, rdtype), rec in desired.items():
        desired_by_zone.setdefault(zone, {})[(owner, rdtype)] = rec

    actions: list[PlanAction] = []
    for zone in _configured_zones(cfg):
        try:
            current = dns_updater.current_managed_records(zone)
        except Exception as exc:
            if prune:
                raise BootstrapAxfrError(zone, exc) from exc
            logger.warning(
                "AXFR of zone %s failed (%s); writing matching records unconditionally",
                zone,
                exc,
            )
            current = None
        actions.extend(diff_zone(zone, desired_by_zone.get(zone, {}), current, prune))

    return actions


_FIELD_FOR_KIND = {
    "create": "created",
    "update": "updated",
    "apply": "applied",
    "delete": "deleted",
    "unchanged": "unchanged",
}


def _now_netbox_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def apply_plan(
    actions: list[PlanAction],
    dns_updater: DnsUpdater,
    state: EventStateStore,
    cfg: Settings,
    dry_run: bool,
) -> Summary:
    run_ts = _now_netbox_ts()
    summary = Summary()

    for action in actions:
        field_name = _FIELD_FOR_KIND[action.kind]
        setattr(summary, field_name, getattr(summary, field_name) + 1)
        zone_counts = summary.per_zone.setdefault(action.zone, {})
        zone_counts[action.kind] = zone_counts.get(action.kind, 0) + 1

        prefix = "[DRY-RUN] would " if dry_run else ""

        if action.kind in ("create", "update", "apply"):
            logger.info(
                "%s%s %s %s %s -> %s",
                prefix,
                action.kind,
                action.zone,
                action.owner_fqdn,
                action.rdtype,
                action.values,
            )
            if not dry_run:
                dns_updater.replace_record(
                    action.zone, action.owner_fqdn, action.rdtype, cfg.dns.ttl, action.values
                )
                if action.source_type and action.source_id is not None:
                    state.record(action.source_type, action.source_id, run_ts)
        elif action.kind == "delete":
            logger.info(
                "%sdelete %s %s %s (was %s)",
                prefix,
                action.zone,
                action.owner_fqdn,
                action.rdtype,
                action.values,
            )
            if not dry_run:
                dns_updater.delete_record(action.zone, action.owner_fqdn, action.rdtype)
        elif action.kind == "unchanged":
            if not dry_run and action.source_type and action.source_id is not None:
                # Already correct in BIND - still record state so a later
                # stale webhook retry for this object can't undo it.
                state.record(action.source_type, action.source_id, run_ts)

    return summary


def print_summary(summary: Summary, dry_run: bool) -> None:
    prefix = "[DRY-RUN] " if dry_run else ""
    print(f"\n{prefix}nb_dnssync bootstrap summary")
    print("-" * 60)
    for zone, counts in sorted(summary.per_zone.items()):
        counts_text = " ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        print(f"{zone}: {counts_text}")
    print("-" * 60)
    print(
        f"TOTAL: created={summary.created} updated={summary.updated} "
        f"applied={summary.applied} deleted={summary.deleted} unchanged={summary.unchanged}"
    )
    if dry_run:
        print("Dry run - no changes were made to BIND.")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m app.bootstrap",
        description="Backfill (and optionally prune) BIND records from NetBox.",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="report changes without touching BIND"
    )
    parser.add_argument(
        "--prune",
        action="store_true",
        help="also delete orphaned A/AAAA/PTR records (default: backfill-only)",
    )
    parser.add_argument(
        "--config", default=None, help="path to config.yaml (overrides CONFIG_PATH)"
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    cfg = load_settings(args.config)
    configure_logging(cfg.logging.level)

    netbox = NetboxClient(cfg.netbox)
    dns_updater = DnsUpdater(cfg.dns)
    state = EventStateStore(cfg.state_db_path)

    try:
        actions = compute_plan(cfg, netbox, dns_updater, prune=args.prune)
    except BootstrapAxfrError as exc:
        logger.error(
            "zone transfer failed for zone=%s; --prune requires allow-transfer "
            "granted for the TSIG key on every configured zone. Aborting "
            "without making any changes. (%s)",
            exc.zone,
            exc.cause,
        )
        return 1

    summary = apply_plan(actions, dns_updater=dns_updater, state=state, cfg=cfg, dry_run=args.dry_run)
    print_summary(summary, dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
