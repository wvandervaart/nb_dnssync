from __future__ import annotations

import pytest

from app.config import DnsConfig, NetboxConfig, Settings, TsigConfig, WebhookConfig


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        netbox=NetboxConfig(url="https://netbox.example.com", token="nbtoken"),
        webhook=WebhookConfig(secret="webhooksecret"),
        dns=DnsConfig(
            server="127.0.0.1",
            port=53,
            tsig=TsigConfig(key_name="test-key", algorithm="hmac-sha256", secret="c2VjcmV0"),
        ),
        forward_zones=["example.com", "corp.example.com"],
        device_zone="devices.example.com",
        reverse_zones=[
            {"network": "10.0.0.0/24", "zone": "0.0.10.in-addr.arpa"},
            {"network": "2001:db8::/64", "zone": "0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"},
        ],
        ptr_priority="primary_ip_first",
        state_db_path=str(tmp_path / "state.sqlite3"),
    )
