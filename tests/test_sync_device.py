from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.models import WebhookEnvelope
from app.state import EventStateStore
from app.sync import SyncService


@pytest.fixture
def deps(settings):
    dns_updater = MagicMock()
    netbox = MagicMock()
    state = EventStateStore(settings.state_db_path)
    service = SyncService(cfg=settings, dns_updater=dns_updater, netbox=netbox, state=state)
    return service, dns_updater, netbox, state


def _envelope(event, data=None, prechange=None, timestamp="2026-08-05T10:00:00.000000Z"):
    return WebhookEnvelope(
        event=event,
        timestamp=timestamp,
        model="device",
        data=data,
        snapshots={"prechange": prechange, "postchange": data},
    )


def test_created_with_primary_ip4_creates_a_and_ptr(deps):
    service, dns_updater, _, _ = deps
    envelope = _envelope(
        "created",
        data={
            "id": 1,
            "name": "sw01",
            "primary_ip4": {"id": 100, "address": "10.0.0.20/24"},
        },
        prechange=None,
    )

    service.handle_device_event(envelope)

    dns_updater.replace_record.assert_any_call(
        "devices.example.com", "sw01.devices.example.com.", "A", 300, ["10.0.0.20"]
    )
    dns_updater.replace_record.assert_any_call(
        "0.0.10.in-addr.arpa",
        "20.0.0.10.in-addr.arpa.",
        "PTR",
        300,
        ["sw01.devices.example.com."],
    )


def test_rename_moves_record(deps):
    service, dns_updater, _, _ = deps
    envelope = _envelope(
        "updated",
        data={
            "id": 2,
            "name": "sw02-new",
            "primary_ip4": {"id": 101, "address": "10.0.0.21/24"},
        },
        prechange={
            "id": 2,
            "name": "sw02-old",
            "primary_ip4": {"id": 101, "address": "10.0.0.21/24"},
        },
    )

    service.handle_device_event(envelope)

    dns_updater.delete_record.assert_any_call(
        "devices.example.com", "sw02-old.devices.example.com.", "A"
    )
    dns_updater.replace_record.assert_any_call(
        "devices.example.com", "sw02-new.devices.example.com.", "A", 300, ["10.0.0.21"]
    )


def test_primary_ip_unassigned_deletes_record_and_ptr(deps):
    service, dns_updater, _, _ = deps
    envelope = _envelope(
        "updated",
        data={"id": 3, "name": "sw03", "primary_ip4": None},
        prechange={
            "id": 3,
            "name": "sw03",
            "primary_ip4": {"id": 102, "address": "10.0.0.22/24"},
        },
    )

    service.handle_device_event(envelope)

    dns_updater.delete_record.assert_any_call(
        "devices.example.com", "sw03.devices.example.com.", "A"
    )
    dns_updater.delete_record.assert_any_call(
        "0.0.10.in-addr.arpa", "22.0.0.10.in-addr.arpa.", "PTR"
    )


def test_deleted_event_cleans_up(deps):
    service, dns_updater, _, _ = deps
    envelope = _envelope(
        "deleted",
        data=None,
        prechange={
            "id": 4,
            "name": "sw04",
            "primary_ip4": {"id": 103, "address": "10.0.0.23/24"},
        },
    )

    service.handle_device_event(envelope)

    dns_updater.delete_record.assert_any_call(
        "devices.example.com", "sw04.devices.example.com.", "A"
    )


def test_raw_pk_snapshot_falls_back_to_netbox_lookup(deps):
    service, dns_updater, netbox, _ = deps
    netbox.resolve_ip_address.return_value = "10.0.0.24"

    envelope = _envelope(
        "updated",
        data={"id": 5, "name": "sw05", "primary_ip4": None},
        prechange={"id": 5, "name": "sw05", "primary_ip4": 104},
    )

    service.handle_device_event(envelope)

    netbox.resolve_ip_address.assert_called_once_with(104)
    dns_updater.delete_record.assert_any_call(
        "0.0.10.in-addr.arpa", "24.0.0.10.in-addr.arpa.", "PTR"
    )


def test_no_primary_ip_no_calls(deps):
    service, dns_updater, _, _ = deps
    envelope = _envelope(
        "created",
        data={"id": 6, "name": "sw06", "primary_ip4": None, "primary_ip6": None},
        prechange=None,
    )

    service.handle_device_event(envelope)

    dns_updater.replace_record.assert_not_called()
    dns_updater.delete_record.assert_not_called()


def test_illegal_device_name_is_skipped(deps, caplog):
    service, dns_updater, _, _ = deps
    envelope = _envelope(
        "created",
        data={
            "id": 7,
            "name": "esxi31 - J701KBFT",
            "primary_ip4": {"id": 200, "address": "10.0.0.30/24"},
        },
        prechange=None,
    )

    with caplog.at_level("WARNING"):
        service.handle_device_event(envelope)

    dns_updater.replace_record.assert_not_called()
    dns_updater.delete_record.assert_not_called()
    assert any("not a legal DNS hostname" in r.message for r in caplog.records)


def test_rename_from_illegal_to_legal_name_only_creates(deps):
    service, dns_updater, _, _ = deps
    envelope = _envelope(
        "updated",
        data={
            "id": 8,
            "name": "sw08",
            "primary_ip4": {"id": 201, "address": "10.0.0.31/24"},
        },
        prechange={
            "id": 8,
            "name": "bad name!",
            "primary_ip4": {"id": 201, "address": "10.0.0.31/24"},
        },
    )

    service.handle_device_event(envelope)

    # the old (illegal) name was never a real record, so there's nothing to
    # delete for it - only the new, legal name gets created
    dns_updater.delete_record.assert_not_called()
    dns_updater.replace_record.assert_any_call(
        "devices.example.com", "sw08.devices.example.com.", "A", 300, ["10.0.0.31"]
    )


def test_offline_device_status_is_skipped(deps, caplog):
    service, dns_updater, _, _ = deps
    envelope = _envelope(
        "created",
        data={
            "id": 9,
            "name": "sw09",
            "status": {"value": "offline", "label": "Offline"},
            "primary_ip4": {"id": 202, "address": "10.0.0.32/24"},
        },
        prechange=None,
    )

    with caplog.at_level("INFO"):
        service.handle_device_event(envelope)

    dns_updater.replace_record.assert_not_called()
    dns_updater.delete_record.assert_not_called()
    assert any("status" in r.message and "excluded" in r.message for r in caplog.records)


def test_inventory_device_status_is_skipped(deps):
    service, dns_updater, _, _ = deps
    envelope = _envelope(
        "created",
        data={
            "id": 10,
            "name": "sw10",
            "status": {"value": "inventory"},
            "primary_ip4": {"id": 203, "address": "10.0.0.33/24"},
        },
        prechange=None,
    )

    service.handle_device_event(envelope)

    dns_updater.replace_record.assert_not_called()
    dns_updater.delete_record.assert_not_called()


def test_device_status_change_to_offline_deletes_existing_record(deps):
    service, dns_updater, _, _ = deps
    envelope = _envelope(
        "updated",
        data={
            "id": 11,
            "name": "sw11",
            "status": {"value": "offline"},
            "primary_ip4": {"id": 204, "address": "10.0.0.34/24"},
        },
        prechange={
            "id": 11,
            "name": "sw11",
            "status": {"value": "active"},
            "primary_ip4": {"id": 204, "address": "10.0.0.34/24"},
        },
    )

    service.handle_device_event(envelope)

    dns_updater.delete_record.assert_any_call(
        "devices.example.com", "sw11.devices.example.com.", "A"
    )
    dns_updater.replace_record.assert_not_called()


def test_device_with_active_status_still_syncs(deps):
    service, dns_updater, _, _ = deps
    envelope = _envelope(
        "created",
        data={
            "id": 12,
            "name": "sw12",
            "status": {"value": "active"},
            "primary_ip4": {"id": 205, "address": "10.0.0.35/24"},
        },
        prechange=None,
    )

    service.handle_device_event(envelope)

    dns_updater.replace_record.assert_any_call(
        "devices.example.com", "sw12.devices.example.com.", "A", 300, ["10.0.0.35"]
    )
