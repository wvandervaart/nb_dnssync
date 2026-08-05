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
    netbox.is_primary_ip.return_value = False
    state = EventStateStore(settings.state_db_path)
    service = SyncService(cfg=settings, dns_updater=dns_updater, netbox=netbox, state=state)
    return service, dns_updater, netbox, state


def _envelope(event, data=None, prechange=None, timestamp="2026-08-05T10:00:00.000000Z"):
    return WebhookEnvelope(
        event=event,
        timestamp=timestamp,
        model="ipaddress",
        data=data,
        snapshots={"prechange": prechange, "postchange": data},
    )


def test_created_with_matching_dns_name_creates_forward_and_ptr(deps):
    service, dns_updater, netbox, _ = deps
    envelope = _envelope(
        "created",
        data={
            "id": 1,
            "address": "10.0.0.5/24",
            "dns_name": "host1.example.com",
            "status": {"value": "active", "label": "Active"},
        },
        prechange=None,
    )

    service.handle_ipaddress_event(envelope)

    dns_updater.replace_record.assert_any_call(
        "example.com", "host1.example.com.", "A", 300, ["10.0.0.5"]
    )
    dns_updater.replace_record.assert_any_call(
        "0.0.10.in-addr.arpa", "5.0.0.10.in-addr.arpa.", "PTR", 300, ["host1.example.com."]
    )


def test_created_with_unmatched_dns_name_does_nothing(deps):
    service, dns_updater, _, _ = deps
    envelope = _envelope(
        "created",
        data={
            "id": 2,
            "address": "10.0.0.6/24",
            "dns_name": "host2.unmanaged.com",
            "status": {"value": "active"},
        },
        prechange=None,
    )

    service.handle_ipaddress_event(envelope)

    dns_updater.replace_record.assert_not_called()
    dns_updater.delete_record.assert_not_called()


def test_update_dns_name_moves_record(deps):
    service, dns_updater, _, _ = deps
    envelope = _envelope(
        "updated",
        data={
            "id": 3,
            "address": "10.0.0.7/24",
            "dns_name": "host3.corp.example.com",
            "status": {"value": "active"},
        },
        prechange={"id": 3, "address": "10.0.0.7/24", "dns_name": "host3.example.com"},
    )

    service.handle_ipaddress_event(envelope)

    dns_updater.delete_record.assert_any_call("example.com", "host3.example.com.", "A")
    dns_updater.replace_record.assert_any_call(
        "corp.example.com", "host3.corp.example.com.", "A", 300, ["10.0.0.7"]
    )


def test_update_dns_name_cleared_deletes_only(deps):
    service, dns_updater, _, _ = deps
    envelope = _envelope(
        "updated",
        data={
            "id": 4,
            "address": "10.0.0.8/24",
            "dns_name": "",
            "status": {"value": "active"},
        },
        prechange={"id": 4, "address": "10.0.0.8/24", "dns_name": "host4.example.com"},
    )

    service.handle_ipaddress_event(envelope)

    dns_updater.delete_record.assert_any_call("example.com", "host4.example.com.", "A")
    forward_replace_calls = [
        c for c in dns_updater.replace_record.call_args_list if c.args[2] == "A"
    ]
    assert forward_replace_calls == []


def test_deleted_event_cleans_up_forward_and_ptr(deps):
    service, dns_updater, _, _ = deps
    envelope = _envelope(
        "deleted",
        data=None,
        prechange={"id": 5, "address": "10.0.0.9/24", "dns_name": "host5.example.com"},
    )

    service.handle_ipaddress_event(envelope)

    dns_updater.delete_record.assert_any_call("example.com", "host5.example.com.", "A")
    dns_updater.delete_record.assert_any_call("0.0.10.in-addr.arpa", "9.0.0.10.in-addr.arpa.", "PTR")


def test_primary_ip_true_skips_ptr_ownership(deps):
    service, dns_updater, netbox, _ = deps
    netbox.is_primary_ip.return_value = True

    envelope = _envelope(
        "created",
        data={
            "id": 6,
            "address": "10.0.0.10/24",
            "dns_name": "host6.example.com",
            "status": {"value": "active"},
        },
        prechange=None,
    )

    service.handle_ipaddress_event(envelope)

    dns_updater.replace_record.assert_any_call(
        "example.com", "host6.example.com.", "A", 300, ["10.0.0.10"]
    )
    ptr_calls = [c for c in dns_updater.replace_record.call_args_list if c.args[2] == "PTR"]
    assert ptr_calls == []


def test_stale_event_is_skipped(deps):
    service, dns_updater, _, state = deps
    state.record("ipaddress", 7, "2026-08-05T12:00:00.000000Z")

    envelope = _envelope(
        "updated",
        data={"id": 7, "address": "10.0.0.11/24", "dns_name": "host7.example.com"},
        prechange={"id": 7, "address": "10.0.0.11/24", "dns_name": None},
        timestamp="2026-08-05T11:00:00.000000Z",
    )

    service.handle_ipaddress_event(envelope)

    dns_updater.replace_record.assert_not_called()
    dns_updater.delete_record.assert_not_called()


def test_disallowed_status_skips_forward_and_ptr(deps):
    service, dns_updater, _, _ = deps
    envelope = _envelope(
        "created",
        data={
            "id": 8,
            "address": "10.0.0.12/24",
            "dns_name": "host8.example.com",
            "status": {"value": "deprecated"},
        },
        prechange=None,
    )

    service.handle_ipaddress_event(envelope)

    dns_updater.replace_record.assert_not_called()
    dns_updater.delete_record.assert_not_called()


def test_status_change_to_disallowed_deletes_existing_record(deps):
    service, dns_updater, _, _ = deps
    envelope = _envelope(
        "updated",
        data={
            "id": 9,
            "address": "10.0.0.13/24",
            "dns_name": "host9.example.com",
            "status": {"value": "dhcp"},
        },
        prechange={"id": 9, "address": "10.0.0.13/24", "dns_name": "host9.example.com"},
    )

    service.handle_ipaddress_event(envelope)

    dns_updater.delete_record.assert_any_call("example.com", "host9.example.com.", "A")
    dns_updater.replace_record.assert_not_called()


def test_reserved_status_is_allowed(deps):
    service, dns_updater, _, _ = deps
    envelope = _envelope(
        "created",
        data={
            "id": 10,
            "address": "10.0.0.14/24",
            "dns_name": "host10.example.com",
            "status": {"value": "reserved"},
        },
        prechange=None,
    )

    service.handle_ipaddress_event(envelope)

    dns_updater.replace_record.assert_any_call(
        "example.com", "host10.example.com.", "A", 300, ["10.0.0.14"]
    )
