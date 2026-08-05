from __future__ import annotations

import logging

from fastapi import FastAPI, Request

from app.config import Settings, get_settings
from app.dns_update import DnsUpdater
from app.logging_conf import configure_logging
from app.netbox_client import NetboxClient
from app.state import EventStateStore
from app.sync import SyncService
from app.webhook import handle_webhook_request

logger = logging.getLogger(__name__)


def create_app(cfg: Settings | None = None) -> FastAPI:
    cfg = cfg or get_settings()
    configure_logging(cfg.logging.level)

    app = FastAPI(title="nb_dnssync")

    app.state.settings = cfg
    app.state.dns_updater = DnsUpdater(cfg.dns)
    app.state.netbox_client = NetboxClient(cfg.netbox)
    app.state.event_state = EventStateStore(cfg.state_db_path)
    app.state.sync_service = SyncService(
        cfg=cfg,
        dns_updater=app.state.dns_updater,
        netbox=app.state.netbox_client,
        state=app.state.event_state,
    )

    async def ipaddress_webhook(request: Request):
        return await handle_webhook_request(request, "handle_ipaddress_event")

    async def device_webhook(request: Request):
        return await handle_webhook_request(request, "handle_device_event")

    app.add_api_route(cfg.webhook.path_ipaddress, ipaddress_webhook, methods=["POST"])
    app.add_api_route(cfg.webhook.path_device, device_webhook, methods=["POST"])

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    return app


def __getattr__(name: str):
    # Lazily build the default app (reads config.yaml + env) only when
    # actually asked for - e.g. by `uvicorn app.main:app`. This lets test
    # modules import `create_app` from this file without requiring a real
    # config file to exist.
    if name == "app":
        return create_app()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
