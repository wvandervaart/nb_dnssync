from __future__ import annotations

from unittest.mock import MagicMock

import dns.rcode
import dns.zone
import pytest

from app.dns_update import DnsUpdater, DnsUpdateError


@pytest.fixture
def updater(settings):
    return DnsUpdater(settings.dns)


def _fake_response(rcode=dns.rcode.NOERROR):
    resp = MagicMock()
    resp.rcode.return_value = rcode
    return resp


def test_replace_record_sends_update(monkeypatch, updater, settings):
    captured = {}

    def fake_tcp(update, server, port, timeout):
        captured["update"] = update
        captured["server"] = server
        captured["port"] = port
        return _fake_response()

    monkeypatch.setattr("app.dns_update.dns.query.tcp", fake_tcp)

    updater.replace_record("example.com", "host1.example.com.", "A", 300, ["10.0.0.5"])

    assert captured["server"] == settings.dns.server
    assert captured["port"] == settings.dns.port
    update = captured["update"]
    # Update.replace() emits a delete-then-add pair for the RRset
    assert len(update.authority) == 2


def test_delete_record_sends_update(monkeypatch, updater):
    captured = {}

    def fake_tcp(update, server, port, timeout):
        captured["update"] = update
        return _fake_response()

    monkeypatch.setattr("app.dns_update.dns.query.tcp", fake_tcp)

    updater.delete_record("example.com", "host1.example.com.", "A")

    assert "update" in captured


def test_nonzero_rcode_raises(monkeypatch, updater):
    def fake_tcp(update, server, port, timeout):
        return _fake_response(dns.rcode.REFUSED)

    monkeypatch.setattr("app.dns_update.dns.query.tcp", fake_tcp)

    with pytest.raises(DnsUpdateError):
        updater.replace_record("example.com", "host1.example.com.", "A", 300, ["10.0.0.5"])


def test_uses_udp_when_configured(monkeypatch, settings):
    settings.dns.use_tcp = False
    updater = DnsUpdater(settings.dns)

    called = {}

    def fake_udp(update, server, port, timeout):
        called["hit"] = True
        return _fake_response()

    monkeypatch.setattr("app.dns_update.dns.query.udp", fake_udp)

    updater.replace_record("example.com", "host1.example.com.", "A", 300, ["10.0.0.5"])

    assert called.get("hit") is True


def test_axfr_uses_resolved_server_and_configured_key(monkeypatch, updater, settings):
    xfr_calls = {}
    from_xfr_calls = {}

    def fake_xfr(server_ip, zone, **kwargs):
        xfr_calls["server_ip"] = server_ip
        xfr_calls["zone"] = zone
        xfr_calls.update(kwargs)
        return "sentinel-xfr-generator"

    def fake_from_xfr(xfr, relativize):
        from_xfr_calls["xfr"] = xfr
        from_xfr_calls["relativize"] = relativize
        return MagicMock()

    monkeypatch.setattr("app.dns_update.dns.query.xfr", fake_xfr)
    monkeypatch.setattr("app.dns_update.dns.zone.from_xfr", fake_from_xfr)

    updater.axfr("example.com")

    assert xfr_calls["server_ip"] == settings.dns.server
    assert xfr_calls["zone"] == "example.com"
    assert xfr_calls["port"] == settings.dns.port
    assert xfr_calls["relativize"] is False
    assert xfr_calls["keyring"] is updater._keyring
    assert xfr_calls["keyalgorithm"] is updater._keyalgorithm
    assert xfr_calls["keyname"].to_text() == settings.dns.tsig.key_name + "."

    assert from_xfr_calls["xfr"] == "sentinel-xfr-generator"
    assert from_xfr_calls["relativize"] is False


def _zone_with_glue(monkeypatch, updater, zone_text):
    zone = dns.zone.from_text(zone_text, origin="example.com.", relativize=False)
    monkeypatch.setattr("app.dns_update.dns.query.xfr", lambda *a, **kw: object())
    monkeypatch.setattr("app.dns_update.dns.zone.from_xfr", lambda xfr, relativize: zone)
    return updater.current_managed_records("example.com")


def test_current_managed_records_filters_to_a_aaaa_ptr(monkeypatch, updater):
    zone_text = """
$ORIGIN example.com.
$TTL 300
@       IN SOA ns.example.com. admin.example.com. ( 1 3600 900 604800 300 )
        IN NS  ns.example.com.
ns      IN A   127.0.0.1
host1   IN A   10.0.0.5
host1   IN AAAA 2001:db8::5
"""
    result = _zone_with_glue(monkeypatch, updater, zone_text)

    assert result == {
        ("host1.example.com.", "A"): ["10.0.0.5"],
        ("host1.example.com.", "AAAA"): ["2001:db8::5"],
    }
    assert ("example.com.", "SOA") not in result
    assert ("example.com.", "NS") not in result


def test_current_managed_records_excludes_ns_target_glue(monkeypatch, updater):
    # A/AAAA at a name targeted by the zone's own NS record is nameserver
    # glue - BIND itself refuses to delete it via dynamic update in some
    # configurations, so it must never appear as a prune candidate.
    zone_text = """
$ORIGIN example.com.
$TTL 300
@       IN SOA ns.example.com. admin.example.com. ( 1 3600 900 604800 300 )
        IN NS  ns.example.com.
ns      IN A   127.0.0.1
ns      IN AAAA ::1
"""
    result = _zone_with_glue(monkeypatch, updater, zone_text)

    assert result == {}


def test_axfr_propagates_transfer_errors(monkeypatch, updater):
    def fake_xfr(*args, **kwargs):
        raise RuntimeError("transfer refused")

    monkeypatch.setattr("app.dns_update.dns.query.xfr", fake_xfr)

    with pytest.raises(RuntimeError, match="transfer refused"):
        updater.axfr("example.com")
