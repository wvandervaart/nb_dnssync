# nb_dnssync

Keeps BIND DNS records in sync with NetBox IPAM/DCIM data:

- When an IP address's **DNS Name** field is filled in and falls within a configured forward zone, an A/AAAA record is created for it.
- When an IP is a device's **primary IPv4/IPv6** address, an A/AAAA record using the **device's name** is created in a dedicated device zone.
- Forward records are matched by corresponding **PTR** records in configured reverse zones.
- Records are kept fully in sync: clearing a DNS Name, changing a zone, renaming a device, or unassigning a primary IP removes the old record.

Updates are pushed to BIND via **RFC2136 dynamic updates (nsupdate) over TSIG** - no filesystem or SSH access to the BIND host is needed. The service is triggered by **NetBox outgoing webhooks**.

## How it works

Two independent NetBox event rules point at this service:

| NetBox object | Events | Route |
|---|---|---|
| IPAM > IP address | Create/Update/Delete | `POST /webhook/netbox/ipaddress` |
| DCIM > Device | Create/Update/Delete | `POST /webhook/netbox/device` |

Both should use the default full-object webhook body and share the same HMAC secret (`NETBOX_WEBHOOK_SECRET`), verified against NetBox's `X-Hook-Signature` header.

## Configuration

Structural config lives in a YAML file (default `config.yaml`, override with `CONFIG_PATH`); secrets come only from environment variables. See `config.example.yaml` for the full schema and `.env.example` for the required secrets:

- `NETBOX_TOKEN` - NetBox API token (needs read access to `dcim.device` and `ipam.ipaddress`)
- `NETBOX_WEBHOOK_SECRET` - shared secret configured on the NetBox webhooks
- `TSIG_SECRET` - base64 TSIG key secret matching the key configured on BIND

Key config fields:
- `forward_zones` - zones an IP's `dns_name` may target
- `device_zone` - single zone used for `<device-name>` records
- `reverse_zones` - explicit `{network, zone}` list (supports RFC 2317 classless delegation)
- `ptr_priority` - when an IP is both in a synced zone and a device's primary IP, `primary_ip_first` (default) makes the device name own the PTR record

## Running locally

```bash
python -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
cp config.example.yaml config.yaml   # edit for your environment
cp .env.example .env                 # fill in secrets
set -a; source .env; set +a
.venv/bin/uvicorn app.main:app --reload
```

Run the unit tests:

```bash
.venv/bin/pytest
```

## Bootstrap / initial sync

The webhook flow above only reacts to *future* NetBox changes - pointing it at a zone that already has NetBox data does nothing until each object is touched again. `python -m app.bootstrap` does a one-off bulk sync instead: it pulls every IP address with a matching `dns_name` and every device with a primary IP straight from the NetBox API and pushes the corresponding records to BIND in one pass.

Both `dns_name` and device names are checked against RFC 1123 hostname syntax first (letters/digits/hyphens only) - anything illegal (spaces, underscores, punctuation) is skipped with a logged warning rather than pushed into BIND or crashing the run.

```bash
# against the prod stack:
docker compose -f docker-compose.prod.yml exec app python -m app.bootstrap [--dry-run] [--prune] [--config PATH]
# against the dev stack:
docker compose -f docker-compose.dev.yml exec app python -m app.bootstrap [--dry-run] [--prune] [--config PATH]
```

- **Default (no flags)**: backfill-only and safe - only ever creates/updates records that match current NetBox data. Never deletes anything. Works out of the box even if BIND has no `allow-transfer` configured yet (falls back to writing unconditionally for any zone it can't read).
- **`--dry-run`**: reports what would change (per zone, with counts) without writing to BIND. Recommended before the first real run on a zone.
- **`--prune`**: also deletes BIND A/AAAA/PTR records that are no longer backed by any NetBox object - use this for a full reconciliation, e.g. to clean up records left behind by manual edits or a previous configuration. Requires **`allow-transfer`** granted for the TSIG key on every zone in `forward_zones`, `device_zone`, and `reverse_zones`:
  ```
  zone "example.com" {
      ...
      allow-transfer { key "nb-dnssync-key"; };
  };
  ```
  If any configured zone's transfer fails, `--prune` aborts the **entire run with no changes made** - it never prunes only part of a zone set.

Either mode only ever reads, creates, or deletes **A, AAAA, and PTR** records - nothing else in a zone (SOA, NS, MX, TXT, CNAME, ...) is ever touched.

## Docker: production deployment

`docker-compose.prod.yml` runs just the app - talking to your real NetBox and real BIND server, nothing else bundled:

```bash
cp config.example.yaml config.yaml   # edit: real forward_zones/device_zone/reverse_zones,
                                      # dns.server pointing at your actual BIND host, etc.
cp .env.example .env                 # fill in NETBOX_TOKEN, NETBOX_WEBHOOK_SECRET, TSIG_SECRET
docker compose -f docker-compose.prod.yml up -d --build
```

`config.yaml` and `.env` are both gitignored - never commit real secrets or infrastructure details. The container runs as a non-root user, persists its dedup state (`app/state.py`) in a named volume (`dnssync-state`), and restarts automatically (`restart: unless-stopped`). Point your NetBox webhook event rules at `http://<host>:8080/webhook/netbox/ipaddress` and `.../device` (see "How it works" above) - typically behind a reverse proxy for TLS, since NetBox needs HTTPS to deliver webhooks in most setups.

Without compose, the equivalent plain `docker run`:

```bash
docker build -t nb_dnssync .
docker run -d --restart unless-stopped -p 8080:8080 \
  -v $(pwd)/config.yaml:/app/config.yaml:ro \
  -v nb_dnssync-state:/data \
  --env-file .env \
  nb_dnssync
```

## Docker: dev stack / end-to-end test

`docker-compose.dev.yml` brings up the app alongside a throwaway BIND instance (`docker/bind/`) pre-configured with a matching TSIG key (including `allow-transfer`, for `--prune`) and test zones (`example.com`, `devices.example.com`, `0.0.10.in-addr.arpa`), plus a minimal stdlib-only `netbox-stub` (`docker/netbox-stub/`) that always reports "NetBox has nothing" so `python -m app.bootstrap --prune` has a reachable NetBox to query in this dev environment. This is all for local dev/testing only - not production config, and entirely separate from `docker-compose.prod.yml`.

```bash
docker compose -f docker-compose.dev.yml up -d --build
./scripts/integration_test.sh
docker compose -f docker-compose.dev.yml down
```

The script fires literal webhook payloads at the running app and queries BIND directly (via `docker compose exec bind dig`) to confirm records are actually created, moved, and deleted, then exercises `python -m app.bootstrap --dry-run --prune` / `--prune` against the records left behind to confirm orphan detection and cleanup work end to end. It defaults `COMPOSE_FILE=docker-compose.dev.yml` so its internal `docker compose exec ...` calls target the right stack automatically.

## Health check

`GET /healthz` returns `200 {"status": "ok"}` when the service is up.
