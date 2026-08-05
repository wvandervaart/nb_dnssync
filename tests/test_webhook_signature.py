from __future__ import annotations

import hashlib
import hmac
import json
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.webhook import verify_signature


def _sign(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha512).hexdigest()


def test_verify_signature_valid():
    body = b'{"event": "created"}'
    sig = _sign("s3cret", body)
    assert verify_signature("s3cret", body, sig) is True


def test_verify_signature_invalid():
    body = b'{"event": "created"}'
    sig = _sign("wrong-secret", body)
    assert verify_signature("s3cret", body, sig) is False


def test_verify_signature_missing():
    assert verify_signature("s3cret", b"{}", None) is False


def test_verify_signature_uses_raw_bytes_not_reserialized_json():
    # A body with different whitespace/key order must produce a different
    # signature than the "equivalent" re-serialized JSON would.
    body = b'{"a": 1, "b": 2}'
    reserialized = json.dumps(json.loads(body)).encode()
    sig_for_body = _sign("s3cret", body)
    assert verify_signature("s3cret", reserialized, sig_for_body) is (reserialized == body)


@pytest.fixture
def client(settings):
    app = create_app(cfg=settings)
    app.state.sync_service = MagicMock()
    return TestClient(app)


def test_webhook_rejects_bad_signature(client):
    body = json.dumps({"event": "created", "timestamp": "t", "model": "ipaddress", "data": {"id": 1}}).encode()
    resp = client.post(
        "/webhook/netbox/ipaddress",
        content=body,
        headers={"X-Hook-Signature": "deadbeef", "Content-Type": "application/json"},
    )
    assert resp.status_code == 403


def test_webhook_accepts_valid_signature(client, settings):
    payload = {"event": "created", "timestamp": "t", "model": "ipaddress", "data": {"id": 1}}
    body = json.dumps(payload).encode()
    sig = _sign(settings.webhook.secret, body)

    resp = client.post(
        "/webhook/netbox/ipaddress",
        content=body,
        headers={"X-Hook-Signature": sig, "Content-Type": "application/json"},
    )
    assert resp.status_code == 200
    client.app.state.sync_service.handle_ipaddress_event.assert_called_once()


def test_device_webhook_route(client, settings):
    payload = {"event": "created", "timestamp": "t", "model": "device", "data": {"id": 1}}
    body = json.dumps(payload).encode()
    sig = _sign(settings.webhook.secret, body)

    resp = client.post(
        "/webhook/netbox/device",
        content=body,
        headers={"X-Hook-Signature": sig, "Content-Type": "application/json"},
    )
    assert resp.status_code == 200
    client.app.state.sync_service.handle_device_event.assert_called_once()


def test_healthz(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
