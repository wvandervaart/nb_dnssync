#!/usr/bin/env bash
# End-to-end check against the dev compose stack: fires literal NetBox
# webhook payloads at the running app, then queries the compose BIND
# instance directly to confirm records were actually created/updated/deleted.
#
# Usage: docker compose -f docker-compose.dev.yml up -d --build && ./scripts/integration_test.sh
set -euo pipefail

export COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.dev.yml}"

APP_URL="${APP_URL:-http://localhost:8080}"
WEBHOOK_SECRET="${NETBOX_WEBHOOK_SECRET:-dev-webhook-secret}"

pass=0
fail=0

# The app persists a last-seen-timestamp per object id (see app/state.py) to
# guard against out-of-order webhook retries, so replaying identical fixed
# timestamps across repeated runs of this script would get skipped as stale.
# Use fresh, increasing timestamps each run instead.
now_ts() {
    date -u +"%Y-%m-%dT%H:%M:%S.000000Z"
}

sign_and_post() {
    local path="$1" body="$2"
    local sig
    sig=$(printf '%s' "$body" | openssl dgst -sha512 -hmac "$WEBHOOK_SECRET" | sed 's/^.* //')
    curl -sf -X POST "$APP_URL$path" \
        -H "Content-Type: application/json" \
        -H "X-Hook-Signature: $sig" \
        --data-binary "$body" >/dev/null
}

check() {
    local desc="$1" expected="$2" actual="$3"
    if [[ "$actual" == "$expected" ]]; then
        echo "OK   - $desc"
        pass=$((pass + 1))
    else
        echo "FAIL - $desc (expected '$expected', got '$actual')"
        fail=$((fail + 1))
    fi
}

# Queried via `docker compose exec bind` rather than the host-published
# port: host -> container UDP/TCP port publishing for an emulated-platform
# BIND image is unreliable on some Docker Desktop setups (e.g. amd64 image
# under qemu on Apple Silicon). Querying from inside the bind container
# itself is what actually exercises the same nsupdate path and is portable.
dig_a() {
    docker compose exec -T bind dig @127.0.0.1 +short A "$1"
}

dig_ptr() {
    docker compose exec -T bind dig @127.0.0.1 +short PTR "$1"
}

# Unique-ish IDs/IPs per run so this script is safely repeatable without
# clearing app state between runs.
run_id="${RANDOM}"
ip_id=$((1000 + run_id % 1000))
device_id=$((2000 + run_id % 1000))
last_octet=$((10 + run_id % 200))

echo "== dns_name sync: create =="
sign_and_post /webhook/netbox/ipaddress "{
  \"event\": \"created\", \"timestamp\": \"$(now_ts)\", \"model\": \"ipaddress\",
  \"data\": {\"id\": $ip_id, \"address\": \"10.0.0.$last_octet/24\", \"dns_name\": \"host$run_id.example.com\", \"status\": {\"value\": \"active\"}}
}"
sleep 1
check "A record created" "10.0.0.$last_octet" "$(dig_a host$run_id.example.com)"
check "PTR record created" "host$run_id.example.com." "$(dig_ptr $last_octet.0.0.10.in-addr.arpa)"

echo "== dns_name sync: delete =="
sign_and_post /webhook/netbox/ipaddress "{
  \"event\": \"deleted\", \"timestamp\": \"$(now_ts)\", \"model\": \"ipaddress\",
  \"snapshots\": {\"prechange\": {\"id\": $ip_id, \"address\": \"10.0.0.$last_octet/24\", \"dns_name\": \"host$run_id.example.com\"}}
}"
sleep 1
check "A record removed" "" "$(dig_a host$run_id.example.com)"
check "PTR record removed" "" "$(dig_ptr $last_octet.0.0.10.in-addr.arpa)"

echo "== device primary-IP sync: create =="
device_octet=$((last_octet + 1))
sign_and_post /webhook/netbox/device "{
  \"event\": \"created\", \"timestamp\": \"$(now_ts)\", \"model\": \"device\",
  \"data\": {\"id\": $device_id, \"name\": \"sw$run_id\", \"primary_ip4\": {\"id\": $((ip_id + 1)), \"address\": \"10.0.0.$device_octet/24\"}}
}"
sleep 1
check "device A record created" "10.0.0.$device_octet" "$(dig_a sw$run_id.devices.example.com)"
check "device PTR record created" "sw$run_id.devices.example.com." "$(dig_ptr $device_octet.0.0.10.in-addr.arpa)"

echo "== device primary-IP sync: unassign =="
sign_and_post /webhook/netbox/device "{
  \"event\": \"updated\", \"timestamp\": \"$(now_ts)\", \"model\": \"device\",
  \"data\": {\"id\": $device_id, \"name\": \"sw$run_id\", \"primary_ip4\": null},
  \"snapshots\": {\"prechange\": {\"id\": $device_id, \"name\": \"sw$run_id\", \"primary_ip4\": {\"id\": $((ip_id + 1)), \"address\": \"10.0.0.$device_octet/24\"}}}
}"
sleep 1
check "device A record removed" "" "$(dig_a sw$run_id.devices.example.com)"
check "device PTR record removed" "" "$(dig_ptr $device_octet.0.0.10.in-addr.arpa)"

# The dev netbox-stub always reports "NetBox has nothing", so anything left
# in BIND by the webhook flow above reads as an orphan from bootstrap's
# point of view - perfect for exercising --prune without a real NetBox.
bootstrap() {
    docker compose exec -T app python -m app.bootstrap "$@"
}

echo "== bootstrap --dry-run --prune: reports orphan without deleting =="
orphan_octet=$((device_octet + 1))
orphan_ip_id=$((ip_id + 2))
sign_and_post /webhook/netbox/ipaddress "{
  \"event\": \"created\", \"timestamp\": \"$(now_ts)\", \"model\": \"ipaddress\",
  \"data\": {\"id\": $orphan_ip_id, \"address\": \"10.0.0.$orphan_octet/24\", \"dns_name\": \"orphan$run_id.example.com\", \"status\": {\"value\": \"active\"}}
}"
sleep 1
check "orphan A record exists before prune" "10.0.0.$orphan_octet" "$(dig_a orphan$run_id.example.com)"

dry_run_output=$(bootstrap --dry-run --prune 2>&1)
if echo "$dry_run_output" | grep -q "orphan$run_id.example.com"; then
    echo "OK   - dry-run reports the orphan"
    pass=$((pass + 1))
else
    echo "FAIL - dry-run did not mention the orphan"
    echo "$dry_run_output"
    fail=$((fail + 1))
fi
check "orphan still present after dry-run" "10.0.0.$orphan_octet" "$(dig_a orphan$run_id.example.com)"

echo "== bootstrap --prune: actually removes the orphan =="
bootstrap --prune >/dev/null
sleep 1
check "orphan A record removed by prune" "" "$(dig_a orphan$run_id.example.com)"
check "orphan PTR record removed by prune" "" "$(dig_ptr $orphan_octet.0.0.10.in-addr.arpa)"

echo "== bootstrap (backfill-only, no --prune) never deletes =="
keep_octet=$((orphan_octet + 1))
keep_ip_id=$((ip_id + 3))
sign_and_post /webhook/netbox/ipaddress "{
  \"event\": \"created\", \"timestamp\": \"$(now_ts)\", \"model\": \"ipaddress\",
  \"data\": {\"id\": $keep_ip_id, \"address\": \"10.0.0.$keep_octet/24\", \"dns_name\": \"keep$run_id.example.com\", \"status\": {\"value\": \"active\"}}
}"
sleep 1
bootstrap >/dev/null
check "backfill-only run leaves unrelated record intact" "10.0.0.$keep_octet" "$(dig_a keep$run_id.example.com)"

echo
echo "$pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
