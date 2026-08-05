from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.netbox_client import (
    NetboxClient,
    is_allowed_ip_status,
    is_excluded_device_status,
)


def _status(value):
    return SimpleNamespace(value=value)  # mimics a pynetbox Record's status field


def _ip(id, address, dns_name, status="active"):
    return SimpleNamespace(id=id, address=address, dns_name=dns_name, status=_status(status))


def _ip_ref(id, address):
    return SimpleNamespace(id=id, address=address)


def _device(id, name, primary_ip4=None, primary_ip6=None, status="active"):
    return SimpleNamespace(
        id=id, name=name, primary_ip4=primary_ip4, primary_ip6=primary_ip6, status=_status(status)
    )


def make_client(settings) -> NetboxClient:
    client = NetboxClient(settings.netbox)
    client._api = MagicMock()
    return client


def test_list_dns_ip_addresses_uses_server_filter_when_supported(settings):
    client = make_client(settings)
    client._api.ipam.ip_addresses.filter.return_value = [
        _ip(1, "10.0.0.5/24", "host1.example.com"),
    ]

    result = client.list_dns_ip_addresses()

    client._api.ipam.ip_addresses.filter.assert_called_once_with(dns_name__empty=False)
    client._api.ipam.ip_addresses.all.assert_not_called()
    assert len(result) == 1
    assert result[0].id == 1
    assert result[0].address == "10.0.0.5"
    assert result[0].dns_name == "host1.example.com"


def test_list_dns_ip_addresses_excludes_blank_dns_name_client_side(settings):
    client = make_client(settings)
    client._api.ipam.ip_addresses.filter.return_value = [
        _ip(1, "10.0.0.5/24", "host1.example.com"),
        _ip(2, "10.0.0.6/24", ""),
        _ip(3, "10.0.0.7/24", None),
        _ip(4, "10.0.0.8/24", "   "),
    ]

    result = client.list_dns_ip_addresses()

    assert [r.id for r in result] == [1]


def test_list_dns_ip_addresses_falls_back_when_filter_raises(settings):
    client = make_client(settings)
    client._api.ipam.ip_addresses.filter.side_effect = RuntimeError("400 bad filter")
    client._api.ipam.ip_addresses.all.return_value = [
        _ip(1, "10.0.0.5/24", "host1.example.com"),
        _ip(2, "10.0.0.6/24", ""),
    ]

    result = client.list_dns_ip_addresses()

    client._api.ipam.ip_addresses.all.assert_called_once()
    assert [r.id for r in result] == [1]


def test_list_devices_with_primary_ip_filters_client_side(settings):
    client = make_client(settings)
    client._api.dcim.devices.all.return_value = [
        _device(1, "sw01", primary_ip4=_ip_ref(100, "10.0.0.10/24")),
        _device(2, "sw02", primary_ip6=_ip_ref(101, "2001:db8::1/64")),
        _device(3, "sw03"),  # no primary IP at all - excluded
        _device(
            4,
            "sw04",
            primary_ip4=_ip_ref(102, "10.0.0.12/24"),
            primary_ip6=_ip_ref(103, "2001:db8::2/64"),
        ),
    ]

    result = client.list_devices_with_primary_ip()

    assert [d.id for d in result] == [1, 2, 4]

    v4_only = result[0]
    assert v4_only.primary_ip4 == "10.0.0.10"
    assert v4_only.primary_ip4_id == 100
    assert v4_only.primary_ip6 is None
    assert v4_only.primary_ip6_id is None

    v6_only = result[1]
    assert v6_only.primary_ip4 is None
    assert v6_only.primary_ip6 == "2001:db8::1"
    assert v6_only.primary_ip6_id == 101

    dual = result[2]
    assert dual.primary_ip4 == "10.0.0.12"
    assert dual.primary_ip6 == "2001:db8::2"


def test_list_dns_ip_addresses_excludes_disallowed_status(settings):
    client = make_client(settings)
    client._api.ipam.ip_addresses.filter.return_value = [
        _ip(1, "10.0.0.5/24", "host1.example.com", status="active"),
        _ip(2, "10.0.0.6/24", "host2.example.com", status="reserved"),
        _ip(3, "10.0.0.7/24", "host3.example.com", status="deprecated"),
        _ip(4, "10.0.0.8/24", "host4.example.com", status="dhcp"),
    ]

    result = client.list_dns_ip_addresses()

    assert [r.id for r in result] == [1, 2]


def test_list_devices_with_primary_ip_excludes_offline_and_inventory(settings):
    client = make_client(settings)
    client._api.dcim.devices.all.return_value = [
        _device(1, "sw01", primary_ip4=_ip_ref(100, "10.0.0.10/24"), status="active"),
        _device(2, "sw02", primary_ip4=_ip_ref(101, "10.0.0.11/24"), status="offline"),
        _device(3, "sw03", primary_ip4=_ip_ref(102, "10.0.0.12/24"), status="inventory"),
        _device(4, "sw04", primary_ip4=_ip_ref(103, "10.0.0.13/24"), status="staged"),
    ]

    result = client.list_devices_with_primary_ip()

    assert [d.id for d in result] == [1, 4]


@pytest.mark.parametrize(
    "status,expected",
    [
        (_status("active"), True),
        (_status("reserved"), True),
        (_status("deprecated"), False),
        ({"value": "active", "label": "Active"}, True),
        ({"value": "dhcp"}, False),
        ("active", True),
        ("ACTIVE", True),
        ("offline", False),
        (None, False),
    ],
)
def test_is_allowed_ip_status(status, expected):
    assert is_allowed_ip_status(status) is expected


@pytest.mark.parametrize(
    "status,expected",
    [
        (_status("offline"), True),
        (_status("inventory"), True),
        (_status("active"), False),
        ({"value": "offline", "label": "Offline"}, True),
        ({"value": "active"}, False),
        ("inventory", True),
        ("INVENTORY", True),
        ("active", False),
        (None, False),
    ],
)
def test_is_excluded_device_status(status, expected):
    assert is_excluded_device_status(status) is expected
