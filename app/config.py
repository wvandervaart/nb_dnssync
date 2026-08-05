"""Application configuration.

Structural config comes from a YAML file (path via CONFIG_PATH env var,
default ./config.yaml). Secrets are never read from YAML - they come
exclusively from environment variables and are merged in after the YAML is
parsed.
"""
from __future__ import annotations

import os
from functools import lru_cache
from ipaddress import ip_network
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator


class NetboxConfig(BaseModel):
    url: str
    verify_ssl: bool = True
    token: str = ""  # from NETBOX_TOKEN


class WebhookConfig(BaseModel):
    path_ipaddress: str = "/webhook/netbox/ipaddress"
    path_device: str = "/webhook/netbox/device"
    secret: str = ""  # from NETBOX_WEBHOOK_SECRET


class TsigConfig(BaseModel):
    key_name: str
    algorithm: str = "hmac-sha256"
    secret: str = ""  # from TSIG_SECRET


class DnsConfig(BaseModel):
    server: str
    port: int = 53
    use_tcp: bool = True
    timeout: float = 5
    ttl: int = 300
    tsig: TsigConfig


class ReverseZoneEntry(BaseModel):
    network: str
    zone: str

    @field_validator("network")
    @classmethod
    def _validate_network(cls, v: str) -> str:
        ip_network(v)  # raises ValueError if invalid
        return v


class LoggingConfig(BaseModel):
    model_config = {"populate_by_name": True}

    level: str = "INFO"
    json_format: bool = Field(default=True, alias="json")


class Settings(BaseModel):
    netbox: NetboxConfig
    webhook: WebhookConfig
    dns: DnsConfig
    forward_zones: list[str] = Field(default_factory=list)
    device_zone: str
    reverse_zones: list[ReverseZoneEntry] = Field(default_factory=list)
    ptr_priority: str = "primary_ip_first"
    state_db_path: str = "/data/state.sqlite3"
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

    @field_validator("ptr_priority")
    @classmethod
    def _validate_ptr_priority(cls, v: str) -> str:
        if v not in ("primary_ip_first", "dns_name_first"):
            raise ValueError(
                "ptr_priority must be 'primary_ip_first' or 'dns_name_first'"
            )
        return v


def _load_yaml(config_path: Path) -> dict:
    with config_path.open("r") as f:
        return yaml.safe_load(f) or {}


def load_settings(config_path: str | Path | None = None) -> Settings:
    path = Path(config_path or os.environ.get("CONFIG_PATH", "config.yaml"))
    raw = _load_yaml(path)

    raw.setdefault("netbox", {})["token"] = os.environ.get("NETBOX_TOKEN", "")
    raw.setdefault("webhook", {})["secret"] = os.environ.get(
        "NETBOX_WEBHOOK_SECRET", ""
    )
    raw.setdefault("dns", {}).setdefault("tsig", {})["secret"] = os.environ.get(
        "TSIG_SECRET", ""
    )

    return Settings.model_validate(raw)


@lru_cache
def get_settings() -> Settings:
    return load_settings()
