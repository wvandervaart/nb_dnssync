from __future__ import annotations

import pytest

from app.config import ReverseZoneEntry
from app.zones import (
    is_valid_dns_name,
    match_forward_zone,
    match_reverse_zone,
    rdtype_for_address,
)

FORWARD_ZONES = ["example.com", "corp.example.com"]

REVERSE_ZONES = [
    ReverseZoneEntry(network="10.0.0.0/24", zone="0.0.10.in-addr.arpa"),
    # RFC 2317 classless delegation: a /25 sub-block of a /24
    ReverseZoneEntry(network="10.0.1.0/25", zone="0-127.1.0.10.in-addr.arpa"),
    ReverseZoneEntry(network="2001:db8::/64", zone="0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"),
]


@pytest.mark.parametrize(
    "dns_name,expected_zone,expected_owner",
    [
        ("host1.example.com", "example.com", "host1.example.com."),
        # trailing dot on input is normalized away
        ("host1.example.com.", "example.com", "host1.example.com."),
        # case-insensitive
        ("Host1.Example.Com", "example.com", "host1.example.com."),
        # longest / most specific zone wins
        ("host1.corp.example.com", "corp.example.com", "host1.corp.example.com."),
        # apex match
        ("example.com", "example.com", "example.com."),
        # label-boundary safe: must not match "notexample.com" against "example.com"
        ("notexample.com", None, None),
        (None, None, None),
        ("", None, None),
        ("host1.other.com", None, None),
        # illegal hostnames are rejected even though they'd otherwise match
        ("esxi31 - J701KBFT.example.com", None, None),
        ("edgeware (retrans).example.com", None, None),
        ("-leadinghyphen.example.com", None, None),
        ("trailinghyphen-.example.com", None, None),
        ("under_score.example.com", None, None),
    ],
)
def test_match_forward_zone(dns_name, expected_zone, expected_owner):
    result = match_forward_zone(dns_name, FORWARD_ZONES)
    if expected_zone is None:
        assert result is None
    else:
        assert result is not None
        assert result.zone == expected_zone
        assert result.owner_fqdn == expected_owner


def test_match_reverse_zone_v4():
    result = match_reverse_zone("10.0.0.5", REVERSE_ZONES)
    assert result is not None
    assert result.zone == "0.0.10.in-addr.arpa"
    assert result.owner_fqdn == "5.0.0.10.in-addr.arpa."


def test_match_reverse_zone_rfc2317_classless():
    # .10 falls in the /25 sub-delegation, not the parent /24
    result = match_reverse_zone("10.0.1.10", REVERSE_ZONES)
    assert result is not None
    assert result.zone == "0-127.1.0.10.in-addr.arpa"

    # .200 falls outside the /25 sub-delegation and has no configured zone
    result = match_reverse_zone("10.0.1.200", REVERSE_ZONES)
    assert result is None


def test_match_reverse_zone_v6():
    result = match_reverse_zone("2001:db8::1", REVERSE_ZONES)
    assert result is not None
    assert result.zone == "0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
    assert result.owner_fqdn.endswith("ip6.arpa.")


def test_match_reverse_zone_no_match():
    assert match_reverse_zone("192.168.1.1", REVERSE_ZONES) is None


def test_rdtype_for_address():
    assert rdtype_for_address("10.0.0.1") == "A"
    assert rdtype_for_address("2001:db8::1") == "AAAA"


@pytest.mark.parametrize(
    "fqdn,expected",
    [
        ("host1.example.com.", True),
        ("host1.example.com", True),  # trailing dot optional
        ("HOST1.example.com.", True),
        ("a.example.com.", True),  # single-char label
        ("host-1.example.com.", True),
        ("17ai001.example.com.", True),  # leading digit allowed (RFC 1123)
        ("esxi31 - J701KBFT.example.com.", False),  # spaces
        ("edgeware (retrans).example.com.", False),  # parens
        ("under_score.example.com.", False),  # underscore
        ("-leading.example.com.", False),
        ("trailing-.example.com.", False),
        ("", False),
        (".", False),
        ("a" * 64 + ".example.com.", False),  # label too long (>63)
        ("a" * 260 + ".com.", False),  # overall too long (>253)
    ],
)
def test_is_valid_dns_name(fqdn, expected):
    assert is_valid_dns_name(fqdn) is expected
