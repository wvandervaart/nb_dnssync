"""NetBox webhook payload envelope.

`data` and `snapshots` are kept as loosely-typed dicts rather than strict
models: NetBox's snapshot serialization of FK fields (e.g. a Device's
primary_ip4) varies between a raw PK and a nested dict depending on version,
and deleted-event `data` content is not guaranteed. Downstream code (sync.py)
only ever does presence/`.get()` access on these, and only destructures
values it knows are plain scalars (dns_name, address, name) - see the plan
for the rationale.
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import AliasChoices, BaseModel, Field


class WebhookEnvelope(BaseModel):
    event: Literal["created", "updated", "deleted"]
    timestamp: str
    # NetBox renamed this field from `model` (e.g. "ipaddress") to
    # `object_type` (e.g. "ipam.ipaddress") in newer versions - accept
    # either so the app isn't pinned to one NetBox release.
    object_type: str = Field(validation_alias=AliasChoices("object_type", "model"))
    username: str | None = None
    request_id: str | None = None
    data: dict[str, Any] | None = None
    snapshots: dict[str, Any] | None = None

    @property
    def prechange(self) -> dict[str, Any]:
        return (self.snapshots or {}).get("prechange") or {}

    @property
    def postchange(self) -> dict[str, Any]:
        return (self.snapshots or {}).get("postchange") or {}

    @property
    def effective_data(self) -> dict[str, Any]:
        """Current object state to read new values from. Falls back to the
        prechange snapshot on deletes, where NetBox may omit `data`.
        """
        return self.data or self.prechange
