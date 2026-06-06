#!/usr/bin/env bash
# One-command end-to-end demo of the content-as-a-service revenue loop.
#
# Proves, on a laptop, with no cloud and no Stripe account:
#   1. a Stripe subscription webhook mints a signed licence key
#   2. that key unlocks the LIVE channel + this week's pack
#   3. a free (no-key) request gets only the lagged SNAPSHOT (one version behind)
#   4. a tampered pack byte is refused by the ed25519 verifier
#   5. cancelling the subscription revokes the key -> falls back to free
#
# Signing happens in a throwaway temp dir so the tracked packs/ are never mutated.
# Implements docs/design/signed-feed.md Parts 3-6. See scripts/{pack_sign,licence,
# stripe_pricing}.py and src/tinysocs/api/feed.py.
#
# Usage:  scripts/demo_feed.sh
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
PY="${PY:-.venv/bin/python}"
KEY_DIR="$ROOT/keys"
PORT="${FEED_PORT:-8095}"
BASE_URL="http://127.0.0.1:$PORT"

# Secrets live only in this shell -- nothing price- or secret-shaped is committed.
export TINYSOCS_FEED_URL_SECRET="demo-url-secret-$RANDOM"
export TINYSOCS_STRIPE_WEBHOOK_SECRET="whsec_demo_$RANDOM"
export TINYSOCS_PRICE_PRO="price_demo_pro"        # opaque id; no dollar figure
export TINYSOCS_KEY_DIR="$KEY_DIR"

hr()  { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
note(){ printf '   %s\n' "$1"; }

# ---- 0. keys (generate throwaway demo keys if absent) -----------------------
hr "0. signing keys"
for kid in tinysocs-2026 licensing-2026; do
  if [[ ! -f "$KEY_DIR/$kid.key" ]]; then
    "$PY" scripts/pack_sign.py gen-key --key-id "$kid" >/dev/null
    note "generated demo key $kid"
  else
    note "using existing demo key $kid"
  fi
done

# ---- 1. sign packs into a temp feed root (tracked packs/ stay clean) ---------
hr "1. sign packs (temp feed root, tracked tree untouched)"
FEED_ROOT="$(mktemp -d)"
cp -R packs/* "$FEED_ROOT/"
export TINYSOCS_PACKS_DIR="$FEED_ROOT"
for ver in 2026.23 2026.22; do
  "$PY" scripts/pack_sign.py sign "$FEED_ROOT/base/$ver/pack.yml" --key-id tinysocs-2026 \
    | sed 's/^/   /'
done

# ---- 2. start the feed server ----------------------------------------------
hr "2. start feed server on :$PORT"
"$PY" -m tinysocs.api.feed >/tmp/tinysocs_feed_demo.log 2>&1 &
FEED_PID=$!
cleanup() { kill "$FEED_PID" 2>/dev/null || true; rm -rf "$FEED_ROOT"; }
trap cleanup EXIT
for _ in $(seq 1 50); do
  curl -fsS "$BASE_URL/healthz" >/dev/null 2>&1 && break || sleep 0.1
done
note "up (pid $FEED_PID); log: /tmp/tinysocs_feed_demo.log"

# resolve which pack_version a feed redirect points at (bash 3.2 safe)
feed_version() { # $1=pack $2=channel [$3=licence-key]
  local url
  if [[ -n "${3:-}" ]]; then
    url=$(curl -fsS -o /dev/null -w '%{redirect_url}' \
      -H "X-TinySOCS-Licence: $3" "$BASE_URL/feed/$1/$2" 2>/dev/null)
  else
    url=$(curl -fsS -o /dev/null -w '%{redirect_url}' \
      "$BASE_URL/feed/$1/$2" 2>/dev/null)
  fi
  sed -E 's#.*/base/([^/]+)/.*#\1#' <<<"$url"
}

# ---- 3. Stripe webhook mints a pro licence ----------------------------------
hr "3. Stripe 'subscription.created' webhook -> mint licence key"
EVENT='{"type":"customer.subscription.created","data":{"object":{"customer":"cus_acme","current_period_end":'"$(($(date +%s)+2592000))"',"items":{"data":[{"price":{"id":"price_demo_pro"},"quantity":1}]}}}}'
TS=$(date +%s)
SIG=$(printf '%s.%s' "$TS" "$EVENT" \
  | openssl dgst -sha256 -hmac "$TINYSOCS_STRIPE_WEBHOOK_SECRET" -r | awk '{print $1}')
RESP=$(curl -fsS -X POST "$BASE_URL/stripe/webhook" \
  -H "Stripe-Signature: t=$TS,v1=$SIG" -H "Content-Type: application/json" -d "$EVENT")
KEY=$("$PY" -c "import sys,json;print(json.load(sys.stdin)['licence_key'])" <<<"$RESP")
note "tier:  $("$PY" -c "import sys,json;print(json.load(sys.stdin)['tier'])" <<<"$RESP")"
note "key:   ${KEY:0:48}..."

# ---- 4. entitlement: pro gets live, free gets the lagged snapshot -----------
hr "4. same pack, two tiers"
note "pro  (with key)  GET /feed/base/live     -> base $(feed_version base live "$KEY")   (this week)"
note "free (no key)    GET /feed/base/snapshot -> base $(feed_version base snapshot)   (one version behind)"
FREE_LIVE=$(curl -fsS -o /dev/null -w '%{http_code}' "$BASE_URL/feed/base/live" 2>/dev/null || true)
note "free (no key)    GET /feed/base/live     -> HTTP $FREE_LIVE   (denied: live is paid)"

# ---- 5. tamper a byte -> ed25519 refuses ------------------------------------
hr "5. tamper detection (ed25519 verify, scripts/pack_sign.py)"
"$PY" scripts/pack_sign.py verify "$FEED_ROOT/base/2026.23/pack.yml" --key-id tinysocs-2026 | sed 's/^/   /'
# flip one byte of the signed pack and re-verify
"$PY" - "$FEED_ROOT/base/2026.23/pack.yml" <<'PY' | sed 's/^/   /'
import sys, yaml, pathlib
p = pathlib.Path(sys.argv[1]); d = yaml.safe_load(p.read_text())
d["rules"][0]["detection"]["threshold"] = 999  # silent tamper of a trusted field
p.write_text(yaml.safe_dump(d, sort_keys=False, allow_unicode=True))
print("tampered: set TS rule[0] threshold -> 999")
PY
"$PY" scripts/pack_sign.py verify "$FEED_ROOT/base/2026.23/pack.yml" --key-id tinysocs-2026 \
  | sed 's/^/   /' || true

# ---- 6. cancel -> revoke -> back to free ------------------------------------
hr "6. Stripe 'subscription.deleted' -> revoke key"
CANCEL='{"type":"customer.subscription.deleted","data":{"object":{"customer":"cus_acme"}}}'
TS=$(date +%s)
SIG=$(printf '%s.%s' "$TS" "$CANCEL" \
  | openssl dgst -sha256 -hmac "$TINYSOCS_STRIPE_WEBHOOK_SECRET" -r | awk '{print $1}')
curl -fsS -X POST "$BASE_URL/stripe/webhook" \
  -H "Stripe-Signature: t=$TS,v1=$SIG" -H "Content-Type: application/json" -d "$CANCEL" >/dev/null
REVOKED_LIVE=$(curl -fsS -o /dev/null -w '%{http_code}' \
  -H "X-TinySOCS-Licence: $KEY" "$BASE_URL/feed/base/live" 2>/dev/null || true)
note "revoked key      GET /feed/base/live     -> HTTP $REVOKED_LIVE   (downgraded to free)"

hr "done"
note "The platform is free; the live, continuously-validated feed is the product."
