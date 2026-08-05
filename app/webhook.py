"""NetBox webhook receiver: signature verification + dispatch to SyncService.

Route registration lives in main.py (paths are configurable), this module
holds the shared request-handling logic.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging

from fastapi import HTTPException, Request
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool

from app.models import WebhookEnvelope

logger = logging.getLogger(__name__)


def verify_signature(secret: str, raw_body: bytes, signature: str | None) -> bool:
    """Verify NetBox's X-Hook-Signature header against the raw request body.

    Must be computed over the raw bytes exactly as received - re-serializing
    the parsed JSON before verifying would produce different bytes (key
    ordering/whitespace) and break the signature.
    """
    if not signature:
        return False
    expected = hmac.new(secret.encode(), raw_body, hashlib.sha512).hexdigest()
    return hmac.compare_digest(expected, signature)


async def handle_webhook_request(request: Request, handler_name: str) -> dict:
    cfg = request.app.state.settings
    raw_body = await request.body()
    signature = request.headers.get("X-Hook-Signature")

    if not verify_signature(cfg.webhook.secret, raw_body, signature):
        raise HTTPException(status_code=403, detail="invalid signature")

    try:
        payload = json.loads(raw_body)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="invalid JSON") from exc

    try:
        envelope = WebhookEnvelope.model_validate(payload)
    except ValidationError:
        logger.exception("invalid webhook payload, raw body: %s", raw_body.decode(errors="replace"))
        raise HTTPException(status_code=400, detail="invalid webhook payload") from None

    sync_service = request.app.state.sync_service
    handler = getattr(sync_service, handler_name)

    try:
        await run_in_threadpool(handler, envelope)
    except Exception:
        logger.exception(
            "failed to process %s webhook event=%s", handler_name, envelope.event
        )
        raise HTTPException(status_code=500, detail="sync failed") from None

    return {"status": "ok"}
