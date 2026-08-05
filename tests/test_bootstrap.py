from __future__ import annotations

import re
from unittest.mock import MagicMock

import pytest

from app.bootstrap import (
    BootstrapAxfrError,
    DesiredRecord,
    PlanAction,
    _configured_zones,
    _now_netbox_ts,
    apply_plan,
    build_desired_state,
    compute_plan,
    diff_zone,
)
from app.netbox_client import DeviceRecord, IpAddressRecord
from app.state import EventStateStore


def _netbox(ip_records=(), device_records=()):
    netbox = MagicMock()
    netbox.list_dns_ip_addresses.return_value = list(ip_records)
    netbox.list_devices_with_primary_ip.return_value = list(device_records)
    return netbox


# --- build_desired_state -----------------------------------------------


def test_matching_ip_creates_forward_and_ptr(settings):
    netbox = _netbox(
        ip_records=[IpAddressRecord(id=1, address="10.0.0.5", dns_name="host1.example.com")]
    )

    desired = build_desired_state(settings, netbox)

    assert desired[("example.com", "host1.example.com.", "A")].values == ["10.0.0.5"]
    assert desired[("0.0.10.in-addr.arpa", "5.0.0.10.in-addr.arpa.", "PTR")].values == [
        "host1.example.com."
    ]


def test_unmatched_dns_name_is_skipped(settings):
    netbox = _netbox(
        ip_records=[IpAddressRecord(id=1, address="10.0.0.5", dns_name="host1.unmanaged.com")]
    )

    desired = build_desired_state(settings, netbox)

    assert desired == {}


def test_primary_ip_first_skips_ip_side_ptr(settings):
    assert settings.ptr_priority == "primary_ip_first"
    netbox = _netbox(
        ip_records=[IpAddressRecord(id=1, address="10.0.0.5", dns_name="host1.example.com")],
        device_records=[
            DeviceRecord(
                id=10, name="sw1", primary_ip4="10.0.0.5", primary_ip4_id=1,
                primary_ip6=None, primary_ip6_id=None,
            )
        ],
    )

    desired = build_desired_state(settings, netbox)

    ptr = desired[("0.0.10.in-addr.arpa", "5.0.0.10.in-addr.arpa.", "PTR")]
    assert ptr.values == ["sw1.devices.example.com."]
    assert ptr.source_type == "device"


def test_dns_name_first_ip_ptr_then_overridden_by_device(settings, caplog):
    settings.ptr_priority = "dns_name_first"
    netbox = _netbox(
        ip_records=[IpAddressRecord(id=1, address="10.0.0.5", dns_name="host1.example.com")],
        device_records=[
            DeviceRecord(
                id=10, name="sw1", primary_ip4="10.0.0.5", primary_ip4_id=1,
                primary_ip6=None, primary_ip6_id=None,
            )
        ],
    )

    with caplog.at_level("WARNING"):
        desired = build_desired_state(settings, netbox)

    ptr = desired[("0.0.10.in-addr.arpa", "5.0.0.10.in-addr.arpa.", "PTR")]
    assert ptr.values == ["sw1.devices.example.com."]
    assert ptr.source_type == "device"
    assert any("collision" in rec.message for rec in caplog.records)


def test_device_creates_forward_and_ptr_for_v4_and_v6(settings):
    netbox = _netbox(
        device_records=[
            DeviceRecord(
                id=10, name="sw1",
                primary_ip4="10.0.0.5", primary_ip4_id=1,
                primary_ip6="2001:db8::5", primary_ip6_id=2,
            )
        ]
    )

    desired = build_desired_state(settings, netbox)

    assert desired[("devices.example.com", "sw1.devices.example.com.", "A")].values == ["10.0.0.5"]
    assert desired[("devices.example.com", "sw1.devices.example.com.", "AAAA")].values == [
        "2001:db8::5"
    ]
    assert desired[
        ("0.0.10.in-addr.arpa", "5.0.0.10.in-addr.arpa.", "PTR")
    ].values == ["sw1.devices.example.com."]
    assert (
        "0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
        "5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
        "PTR",
    ) in desired


def test_device_without_name_contributes_nothing(settings):
    netbox = _netbox(
        device_records=[
            DeviceRecord(id=10, name=None, primary_ip4="10.0.0.5", primary_ip4_id=1, primary_ip6=None, primary_ip6_id=None)
        ]
    )

    desired = build_desired_state(settings, netbox)

    assert desired == {}


def test_ip_with_illegal_dns_name_is_skipped(settings):
    netbox = _netbox(
        ip_records=[
            IpAddressRecord(id=1, address="10.0.0.5", dns_name="esxi31 - J701KBFT.example.com")
        ]
    )

    desired = build_desired_state(settings, netbox)

    assert desired == {}


def test_device_with_illegal_name_is_skipped(settings, caplog):
    netbox = _netbox(
        device_records=[
            DeviceRecord(
                id=10, name="bad name!", primary_ip4="10.0.0.5", primary_ip4_id=1,
                primary_ip6=None, primary_ip6_id=None,
            )
        ]
    )

    with caplog.at_level("WARNING"):
        desired = build_desired_state(settings, netbox)

    assert desired == {}
    assert any("not a legal DNS hostname" in r.message for r in caplog.records)


# --- diff_zone / compute_plan -------------------------------------------


def _rec(zone="example.com", owner="host1.example.com.", rdtype="A", values=None):
    return DesiredRecord(zone, owner, rdtype, values or ["10.0.0.5"], "ipaddress", 1)


def test_diff_zone_unknown_current_is_apply():
    desired = {("host1.example.com.", "A"): _rec()}
    actions = diff_zone("example.com", desired, None, prune=False)
    assert [a.kind for a in actions] == ["apply"]


def test_diff_zone_create_update_unchanged():
    desired = {
        ("new.example.com.", "A"): _rec(owner="new.example.com."),
        ("changed.example.com.", "A"): _rec(owner="changed.example.com.", values=["10.0.0.9"]),
        ("same.example.com.", "A"): _rec(owner="same.example.com.", values=["10.0.0.5"]),
    }
    current = {
        ("changed.example.com.", "A"): ["10.0.0.1"],
        ("same.example.com.", "A"): ["10.0.0.5"],
    }
    actions = diff_zone("example.com", desired, current, prune=False)
    kinds = {a.owner_fqdn: a.kind for a in actions}
    assert kinds["new.example.com."] == "create"
    assert kinds["changed.example.com."] == "update"
    assert kinds["same.example.com."] == "unchanged"


def test_diff_zone_delete_only_when_prune():
    desired: dict = {}
    current = {("orphan.example.com.", "A"): ["10.0.0.1"]}

    actions_no_prune = diff_zone("example.com", desired, current, prune=False)
    assert actions_no_prune == []

    actions_prune = diff_zone("example.com", desired, current, prune=True)
    assert [a.kind for a in actions_prune] == ["delete"]
    assert actions_prune[0].owner_fqdn == "orphan.example.com."


def test_compute_plan_backfill_degrades_on_axfr_failure(settings):
    netbox = _netbox(
        ip_records=[IpAddressRecord(id=1, address="10.0.0.5", dns_name="host1.example.com")]
    )
    dns_updater = MagicMock()

    def fake_current(zone):
        if zone == "example.com":
            raise RuntimeError("transfer refused")
        return {}

    dns_updater.current_managed_records.side_effect = fake_current

    actions = compute_plan(settings, netbox, dns_updater, prune=False)

    apply_actions = [a for a in actions if a.zone == "example.com"]
    assert [a.kind for a in apply_actions] == ["apply"]


def test_compute_plan_prune_raises_on_axfr_failure(settings):
    netbox = _netbox(
        ip_records=[IpAddressRecord(id=1, address="10.0.0.5", dns_name="host1.example.com")]
    )
    dns_updater = MagicMock()
    dns_updater.current_managed_records.side_effect = RuntimeError("transfer refused")

    with pytest.raises(BootstrapAxfrError) as exc_info:
        compute_plan(settings, netbox, dns_updater, prune=True)

    assert exc_info.value.zone == _configured_zones(settings)[0]


def test_compute_plan_prune_axfrs_every_configured_zone_even_when_empty(settings):
    netbox = _netbox()
    dns_updater = MagicMock()
    dns_updater.current_managed_records.return_value = {}

    compute_plan(settings, netbox, dns_updater, prune=True)

    called_zones = {c.args[0] for c in dns_updater.current_managed_records.call_args_list}
    assert called_zones == set(_configured_zones(settings))


# --- apply_plan -----------------------------------------------------------


@pytest.fixture
def state(settings):
    return EventStateStore(settings.state_db_path)


def test_apply_plan_dry_run_makes_no_calls(settings, state):
    dns_updater = MagicMock()
    actions = [
        PlanAction("create", "example.com", "host1.example.com.", "A", ["10.0.0.5"], "ipaddress", 1),
        PlanAction("delete", "example.com", "old.example.com.", "A", ["10.0.0.1"], None, None),
    ]

    apply_plan(actions, dns_updater, state, settings, dry_run=True)

    dns_updater.replace_record.assert_not_called()
    dns_updater.delete_record.assert_not_called()
    assert state.is_stale("ipaddress", 1, "2099-01-01T00:00:00.000000Z") is False


def test_apply_plan_create_writes_record_and_state(settings, state):
    dns_updater = MagicMock()
    actions = [
        PlanAction("create", "example.com", "host1.example.com.", "A", ["10.0.0.5"], "ipaddress", 1),
    ]

    apply_plan(actions, dns_updater, state, settings, dry_run=False)

    dns_updater.replace_record.assert_called_once_with(
        "example.com", "host1.example.com.", "A", settings.dns.ttl, ["10.0.0.5"]
    )
    # state now reflects this object as synced "now" - an older timestamp is stale
    assert state.is_stale("ipaddress", 1, "2020-01-01T00:00:00.000000Z") is True


def test_apply_plan_delete_does_not_touch_state(settings, state):
    dns_updater = MagicMock()
    actions = [
        PlanAction("delete", "example.com", "old.example.com.", "A", ["10.0.0.1"], None, None),
    ]

    apply_plan(actions, dns_updater, state, settings, dry_run=False)

    dns_updater.delete_record.assert_called_once_with("example.com", "old.example.com.", "A")


def test_apply_plan_unchanged_records_state_without_dns_call(settings, state):
    dns_updater = MagicMock()
    actions = [
        PlanAction("unchanged", "example.com", "host1.example.com.", "A", ["10.0.0.5"], "ipaddress", 1),
    ]

    apply_plan(actions, dns_updater, state, settings, dry_run=False)

    dns_updater.replace_record.assert_not_called()
    dns_updater.delete_record.assert_not_called()
    assert state.is_stale("ipaddress", 1, "2020-01-01T00:00:00.000000Z") is True


def test_apply_plan_summary_counts(settings, state):
    dns_updater = MagicMock()
    actions = [
        PlanAction("create", "example.com", "a.example.com.", "A", ["10.0.0.1"], "ipaddress", 1),
        PlanAction("update", "example.com", "b.example.com.", "A", ["10.0.0.2"], "ipaddress", 2),
        PlanAction("apply", "example.com", "c.example.com.", "A", ["10.0.0.3"], "ipaddress", 3),
        PlanAction("unchanged", "example.com", "d.example.com.", "A", ["10.0.0.4"], "ipaddress", 4),
        PlanAction("delete", "example.com", "e.example.com.", "A", ["10.0.0.5"], None, None),
    ]

    summary = apply_plan(actions, dns_updater, state, settings, dry_run=False)

    assert summary.created == 1
    assert summary.updated == 1
    assert summary.applied == 1
    assert summary.unchanged == 1
    assert summary.deleted == 1
    assert summary.per_zone["example.com"] == {
        "create": 1,
        "update": 1,
        "apply": 1,
        "unchanged": 1,
        "delete": 1,
    }


# --- misc -------------------------------------------------------------


def test_now_netbox_ts_format():
    ts = _now_netbox_ts()
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", ts)
