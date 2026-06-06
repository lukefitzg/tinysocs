# Signed Rules Feed + Licence Gate — Design

**Status**: draft
**Author**: Luke FitzGerald + Claude session, 2026-06-06.
**Depends on**: `docs/design/rule-format-v2.md` (pack envelope, `metadata.signature`, `metadata.tier`, `pack_id`+`pack_version`). This doc does **not** restate the pack schema; it specifies how packs are signed, distributed, verified, and paywalled.
**Covers strategic gaps**: #3 (signed rules feed) and #4 (Stripe + licence-key gate). They are one revenue mechanic and are designed together.

---

## Why this exists

The pivot's entire revenue thesis is: *the platform is free; customers pay for continuously-validated detection content delivered automatically.* That sentence implies four mechanisms that don't exist yet:

1. A way to **sign** a content pack so a customer's agent can trust it came from us and wasn't tampered with.
2. A way to **distribute** packs and **version** them so an agent knows when newer content exists and can pin/roll back.
3. A way to **gate** that distribution by tier (`free` / `pro` / `msp`) so the free tier gets a stale snapshot and paying tiers get the live feed + premium packs.
4. A way to **issue and activate** the licence key that drives the gate, fed by **Stripe** subscriptions.

This doc designs all four. Code lands incrementally; the cryptographic core (sign/verify) and the entitlement logic are buildable now because they're self-contained. The live HTTP feed server and the Stripe webhook are designed here but deliberately *not* built in the first pass (see "Build sequencing").

## Non-goals

- Pack *schema* — owned by `rule-format-v2.md`.
- The C# engine's pack-load/verify integration — designed here at the protocol level; the C# implementation is a separate gap (it depends on the v2 loader work).
- Prices. Tier *architecture* is locked (`free`/`pro`/`msp`); numbers wait for first customer conversations. No price appears in this doc, the schema, or any code path.
- FP telemetry back-channel (deferred; see `CLAUDE.md`).

---

## Part 1 — What gets signed

### Signing target: the canonical pack

The unit of signing is a single pack file (`pack.yml`, the v2 envelope). The signature covers a **canonical JSON serialisation** of the pack with the signature *value* cleared, so the signature can live inside the object it signs.

Canonicalisation rules (must be identical on signer and verifier):

1. Load the pack YAML into a data structure.
2. Set `metadata.signature.value` to the empty string `""` (keep `algorithm` and `key_id` — they are signed, so an attacker can't swap the declared algorithm).
3. Serialise to JSON with: keys sorted lexicographically, no insignificant whitespace (`separators=(",", ":")`), UTF-8, `ensure_ascii=false`.
4. The signed message is the UTF-8 bytes of that JSON string.

Rationale for JSON-not-YAML canonicalisation: YAML has too many ways to represent the same value (quoting, anchors, flow vs block) to canonicalise safely. JSON with sorted keys is a single deterministic byte string. The pack is *authored* and *shipped* as YAML (round-trips through YamlDotNet per `rule-format-v2.md`), but *signed* over its JSON projection.

### Algorithm: ed25519

- `metadata.signature.algorithm: ed25519` (already in the v2 envelope).
- 64-byte signature, base64-encoded into `metadata.signature.value`.
- `metadata.signature.key_id` names the keypair (e.g. `tinysocs-2026`), enabling rotation (Part 5).
- Library: `cryptography` (Python, vendor side); the C# agent verifies with **BouncyCastle.Cryptography** (MIT) — .NET 8's BCL has no Ed25519. *Implemented:* `src/TinySocs.Agent/Detection/{Ed25519Verifier,PackLoader,LicenceReader}.cs`.

### Detached signature and the canonical sidecar

Alongside the in-band `metadata.signature.value`, the signer (`scripts/pack_sign.py`) emits two sidecars:

- `pack.yml.sig` — the raw 64-byte signature (base64), for out-of-band tooling and CDN/object-store integrity checks.
- `pack.yml.canonical` — **the exact canonical bytes that were signed.**

The agent verifies and loads rules from `pack.yml.canonical`, *not* by reconstructing the canonical JSON from `pack.yml`. This was a deliberate refinement (2026-06-06): asking the C# verifier to reproduce Python's `json.dumps` byte-for-byte from YAML is fragile (PyYAML vs YamlDotNet scalar-type inference, future floats/unicode/big-ints would silently break verification). Signing and verifying the *same persisted byte string* removes all cross-language canonicalisation risk. The YAML stays the human-readable in-repo source; the `.canonical` JSON is the machine trust path. Proven end-to-end: Python `cryptography` signs, C# `BouncyCastle` verifies, byte-identical.

### What is NOT signed

- The customer-local `allowlists.yml` (unsigned by design — `rule-format-v2.md`).
- Baseline data (customer-local).
- TinyDocs *content* is inside the pack directory and **is** covered: TinyDocs files referenced by `docs:` paths are hashed and the manifest of `{path: sha256}` is included in `metadata` so doc tampering is detectable. (TinyDocs authoring is a separate gap; the hash-manifest slot is reserved here.)

---

## Part 2 — Distribution and versioning

### Version identity

`(pack_id, pack_version)` is the immutable coordinate (from `rule-format-v2.md`). `pack_version` is `year.weeknum` (e.g. `2026.23`). A given coordinate's bytes never change once published — fixes ship as a new `pack_version`, never an in-place edit. This is what makes client caching and rollback safe.

### Feed layout (vendor side)

Static object store (S3/R2/equivalent) behind a CDN. No application server is required for *delivery* — only for *entitlement* (Part 4). Layout mirrors the on-disk pack layout in `rule-format-v2.md`:

```
feed.tinysocs.io/
├── packs/
│   ├── base/
│   │   ├── 2026.23/pack.yml          (+ .sig, tinydocs/, validation.json)
│   │   ├── 2026.22/pack.yml
│   │   └── index.json                # {latest, snapshot, versions[]}
│   ├── m365-pack/
│   │   └── 2026.23/...
│   └── demo/...
└── keys/
    └── tinysocs-2026.pub             # public verify key, by key_id
```

### Two channels: live vs stale snapshot

This is the free/paid line, expressed in the feed itself:

| Channel | Pointer | Who gets it | Cadence |
|---|---|---|---|
| **live** | `index.json#latest` → newest `pack_version` | `pro`, `msp` | within the weekly cadence, immediately on publish |
| **snapshot** | `index.json#snapshot` → a deliberately-lagged `pack_version` | `free` | promoted to the *previous* week's pack on a 1-week delay |

`free` is not "no updates" — it's *delayed* updates of `base` only. The snapshot pointer lags `latest` by one published version. Premium packs (`m365-pack`, `persistence-premium`, …) have no `snapshot` pointer at all — they're paid-only.

### Client poll / pull flow (agent side)

1. Agent knows its entitlement (Part 4): which `pack_id`s, and `live` vs `snapshot`.
2. For each entitled pack, GET `index.json`, read the right pointer (`latest` or `snapshot`).
3. If that `pack_version` ≠ the locally-cached version, GET the new `pack.yml`.
4. **Verify signature** (Part 3) against the embedded public key for the declared `key_id`.
5. Only if verification passes *and* `schema_version` is compatible: atomically swap the active pack. On any failure: keep the last-good pack, log loudly, surface a dashboard warning. **The agent never runs unverified or unparseable content.**
6. Cache is keyed by `(pack_id, pack_version)`; old versions retained for N (rollback).

Polling interval is conservative (e.g. daily) — content cadence is weekly, so there's no reason to hammer the feed. Exact interval is an operational knob, not a protocol decision.

---

## Part 3 — Client verification

The agent ships with one or more **trusted public keys**, indexed by `key_id`, baked into the build (not fetched at runtime — fetching the verify key from the same server that serves the content defeats the purpose). The `keys/<key_id>.pub` endpoint exists for tooling and new-key bootstrap, not for the trust root.

Verify algorithm (mirror of the signer):

1. Load downloaded `pack.yml`.
2. Read `metadata.signature.{algorithm, key_id, value}`.
3. Reject if `algorithm` ≠ `ed25519` or `key_id` not in the trusted set.
4. Canonicalise (clear `value`, sorted-key compact JSON — *byte-identical* to the signer's rule).
5. ed25519-verify `base64decode(value)` over the canonical bytes with the trusted public key for `key_id`.
6. Pass → accept. Fail → reject, keep last-good, warn.

Verification is offline and deterministic. No network call, no clock dependence (signatures don't expire; *entitlement* does — Part 4).

---

## Part 4 — Licence key and entitlement gate

### The shape of the gate

Two enforcement points, defence-in-depth:

- **Server-side (authoritative):** the feed's entitlement check. A request for a premium pack or the `live` channel must present a valid licence key whose tier grants it. The static object store sits behind a thin auth layer (signed-URL minting or a small FastAPI gate following `src/tinysocs/api/` patterns) that checks the key → tier → entitlement before serving/redirecting. `metadata.tier` in the pack is *advisory* (it documents intent); the server is the truth.
- **Client-side (advisory/UX):** the agent knows its own tier from the key so it requests the right channel and shows the right UI, but it does not *self-enforce* — a tampered client still can't get premium bytes because the server won't serve them.

### Licence key format

A licence key is a **signed, self-describing token** — not a random opaque string checked against a database. This lets the *agent* read the tier offline (for channel selection and UI) while the *server* still verifies authenticity. Structure (compact, ed25519-signed, base64url, dot-separated like a mini-JWT):

```
payload  = {"k": "<key_id>", "tier": "pro", "sub": "<stripe_customer_id>",
            "sites": 5, "iat": 1717632000, "exp": 1749168000, "nonce": "<rand>"}
licence  = base64url(payload) + "." + base64url(ed25519_sign(payload_bytes))
```

- Signed with a **licensing** ed25519 key (separate from the *pack-signing* key — different blast radius, different rotation cadence).
- `tier` ∈ `free | pro | msp`. `sites` bounds endpoint count for `msp`/`pro` bands (no price, just a capacity integer).
- `exp` is the subscription period end. Expiry is a *soft* gate with grace (below).
- `nonce` makes each issued key unique even for identical payloads (supports revocation lists).

The agent verifies the key's signature with the embedded licensing public key, reads `tier`/`exp`/`sites` offline. The server does the same *plus* a revocation-list check (a key can be killed mid-period on refund/chargeback — the offline token can't self-revoke, so the authoritative server holds the revocation set).

### Entitlement resolution (pure function)

`entitlement(tier) -> { packs: [...], channel: live|snapshot, premium: bool }`:

| tier | packs | channel | premium packs |
|---|---|---|---|
| `free` | `base` | `snapshot` (1-week lag) | none |
| `pro` | `base` + premium | `live` | yes |
| `msp` | `base` + premium + federation/multi-tenant | `live` | yes |

This is deliberately a small, total, side-effect-free function — easy to unit-test and to demo on the CLI. It's the part built in the first pass.

### Offline grace and failure modes

- **Key expired (`exp` passed):** enter a **grace window** (e.g. 14 days) during which the agent keeps using the last-good packs and warns; after grace, premium packs freeze at last-good (never deleted — security tooling must not silently degrade) and the live channel falls back to snapshot. Free-tier content always keeps flowing.
- **No key / invalid key:** treated as `free`. Agent gets the `base` snapshot. No hard lockout — a SIEM that stops detecting because billing lapsed is a liability, not a feature.
- **Revoked key (server-side):** server stops serving premium/live; client falls to snapshot on next poll.

Principle: **billing state degrades the *freshness and breadth* of content, never the *function* of the agent.** This is both an ethics call and a support-load call (a hard lockout generates angry tickets and churn).

---

## Part 4.5 — Feed server auth layer

Open question #1 from the first draft — *signed-URL minting vs always-on gate* — is resolved here: **a thin always-on minting endpoint that issues short-TTL signed URLs; the bulk bytes are served by the CDN/object store directly.** This gets the best of both: the licensing decision is made by code we control (immediate revocation, stateful checks), but we don't proxy multi-MB pack downloads through an app server.

### Topology

```
                         ┌─────────────────────────────┐
   agent ──(1) GET ─────►│  mint endpoint (FastAPI)     │   small, always-on
   licence key in header │  - verify licence token      │   src/tinysocs/api/ style
                         │  - check revocation list     │
                         │  - entitlement(tier)         │
                         │  - can_access(pack, channel) │
                         └──────────────┬──────────────┘
                                        │ (2) 302 -> signed URL (TTL ~120s)
                                        ▼
   agent ──(3) GET signed URL ──► CDN / object store (static pack bytes)
                                        │
                                        ▼
                              (4) verify signature offline (Part 3)
```

1. Agent presents its licence key (the Part 4 token) to `GET /feed/{pack_id}/{channel}` (`channel` ∈ `live|snapshot`).
2. Mint endpoint runs the gate (below). On allow, it resolves the concrete `pack_version` from `index.json` and returns a **302 redirect to a signed, short-TTL object-store URL** for that exact `pack.yml`.
3. Agent follows the redirect, pulls bytes straight from the CDN — the app server never touches pack payload.
4. Agent verifies the ed25519 pack signature offline. Two independent trust checks: the URL proves *entitlement*, the signature proves *authenticity*. A leaked URL still yields only authentic content the leaker was already entitled to, and it expires in ~2 minutes.

### The gate (reuses `licence.py`, no new logic)

```python
# pseudocode — the decision is exactly scripts/licence.py, server-side
def mint(pack_id: str, channel: str, licence_key: str) -> Response:
    ok, reason, payload = verify_key(licence_key, KEY_DIR)        # signature + exp
    tier = payload.get("tier", "free")
    if not ok and reason == "expired":
        tier, _ = effective_tier(licence_key, KEY_DIR)            # apply grace
    elif not ok:
        tier = "free"                                             # never hard-lock
    if payload.get("nonce") in REVOCATION_SET:                    # server-only check
        tier = "free"
    if not can_access(tier, pack_id, channel):
        return 403
    version = resolve_version(pack_id, channel)                   # index.json pointer
    return redirect(sign_object_url(f"packs/{pack_id}/{version}/pack.yml", ttl=120))
```

The authoritative server runs the *same* `entitlement()` / `can_access()` the agent uses for UI — single source of truth, no drift. The one thing the server has that the agent doesn't is the **revocation set** (`nonce`s killed on refund/chargeback), because an offline self-describing token can't self-revoke.

### Why not pure signed-URLs (no server)

A purely CDN-native scheme (pre-shared signing secret, agent mints its own URLs) can't revoke a key mid-period and can't apply the revocation set — billing fraud would be unstoppable until `exp`. The always-on endpoint is small (one route, stateless except a revocation lookup) and is the natural home for the Stripe-issued revocation set anyway.

### Build note

**Built (2026-06-06):** `src/tinysocs/api/feed.py` — a FastAPI app with the mint route `GET /feed/{pack_id}/{channel}`. It runs the gate above verbatim (`scripts/licence.py` `verify_key` / `effective_tier` / `can_access`), adds the server-only revocation check (`src/tinysocs/api/feed_store.py`), resolves the `pack_version` from `index.json` (with a filesystem fallback for the demo), and 302-redirects to a short-TTL HMAC-signed URL. A `GET /feed/blob/...` route stands in for the CDN/object store so the feed is demoable end-to-end without cloud infra; in production the redirect points at S3/R2 and that route drops away. URL-signing secret comes from `TINYSOCS_FEED_URL_SECRET` (fail-closed). Covered by `tests/test_feed_server.py`.

## Part 5 — Key management and rotation

Two distinct keypairs, both ed25519, both with `key_id`:

| Key | Signs | Lives | Rotation trigger |
|---|---|---|---|
| **pack-signing** | content packs | offline / HSM-ish; never in repo | suspected compromise; scheduled (e.g. yearly `tinysocs-2027`) |
| **licensing** | licence keys | vendor licensing service only | suspected compromise; rare |

Rotation process (pack-signing, documented operationally — small runbook, not code):

1. Generate new keypair `tinysocs-<year+1>`.
2. Ship an agent build that trusts **both** old and new `key_id`s (overlap window).
3. Start signing new packs with the new key.
4. Once the fleet has the new-trusting build, retire the old key.

`metadata.signature.key_id` and the keys-by-id layout exist precisely to make this a non-event. Private keys: gitignored (`.gitignore` already excludes `*.key` and has a keys section). Real keys live in the founder's secrets store, never the repo — only `.pub` and `.sig` artifacts are committed.

---

## Part 6 — Stripe → licence issuance

**Built (2026-06-06):** the `POST /stripe/webhook` route in `src/tinysocs/api/feed.py`. It verifies the `Stripe-Signature` HMAC (`t=…,v1=…` scheme, `{t}.{body}` signed with `TINYSOCS_STRIPE_WEBHOOK_SECRET`, constant-time compare, 5-min tolerance) **without the Stripe SDK**; maps `price_id → tier` and `quantity → sites` via `scripts/stripe_pricing.py`; mints + signs a key via `scripts/licence.py issue`; and records the `nonce` in the revocation store. `subscription.updated` revokes the customer's prior key before minting the replacement; `subscription.deleted` revokes; `payment_failed` is acknowledged but not acted on (rely on `exp` + grace). Unknown `price_id` → 422 (never mints a "free" key). Webhook secret + price ids are env-only — no secrets or prices in the repo. Covered by `tests/test_feed_server.py`.

Flow:

```
Stripe Checkout (tier = pro/msp, qty = sites)
        │  customer.subscription.created / .updated
        ▼
Stripe webhook  ──►  licensing service (small FastAPI)
        │  1. verify Stripe webhook signature
        │  2. map price_id -> tier, quantity -> sites
        │  3. mint licence token (Part 4), sign with licensing key
        │  4. store {key_id, nonce, stripe_customer_id, exp} for revocation
        ▼
deliver key to customer (email + dashboard "copy your licence key")
        │
        ▼
customer pastes key into agent/dashboard -> agent reads tier offline,
feed server honours it until exp / revocation
```

Subscription lifecycle → key lifecycle:

- `subscription.updated` (tier change / seat change) → mint a new key with updated `tier`/`sites`/`exp`, revoke the old `nonce`.
- `subscription.deleted` (cancel) → revoke; customer falls to `free` after grace.
- `invoice.payment_failed` → no immediate revoke; rely on `exp` + grace so a transient card failure doesn't blind a customer's SOC.

`price_id → tier` is a small server-side map. **No prices in the repo** — the map keys are opaque Stripe price IDs, the values are tier names. The actual dollar figures live in the Stripe dashboard, set after first customer conversations.

---

## Build sequencing (what's code now vs design-only)

| Component | This pass | Why |
|---|---|---|
| ed25519 pack sign/verify (`scripts/pack_sign.py`) | **build** | self-contained trust primitive; the demo-able core |
| v2 migration → real signable `base`/`demo` packs (`scripts/migrate_rules_to_v2.py`) | **build** | mechanical (`rule-format-v2.md`); produces the bytes to sign |
| Licence token mint/verify + `entitlement()` (`scripts/licence.py`) | **build** | pure local logic; demo-able; no secrets/network |
| Feed HTTP server + entitlement enforcement | **build (2026-06-06)** | `src/tinysocs/api/feed.py` mint route runs the licence gate + revocation and 302s to a short-TTL signed URL; blob route stands in for the CDN |
| Stripe webhook → key issuance | **build (2026-06-06)** | `src/tinysocs/api/feed.py` `/stripe/webhook` verifies the HMAC (no SDK), maps price→tier, mints + records a key, revokes on update/cancel |
| C# agent pack-load/verify integration | **build** (2026-06-06) | the agent now verifies a signed pack and refuses tampered/untrusted content; reads tier from the licence offline |

The built pieces let a founder watch, on the CLI: **migrate the 39 live rules into a signed `base` pack → verify it → tamper one byte and watch verification reject it → check that a `pro` key unlocks `m365-pack` while a `free` key gets only the lagged `base` snapshot.** That is the revenue mechanic, demonstrated end-to-end, without a server or a Stripe account.

As of 2026-06-06 the **C# agent itself** is on the trust path: with `detection.pack.enabled`, `OpenSearchBulkShipper` loads rules via `PackLoader`, which ed25519-verifies the signed `.canonical` bytes, pins the signing `key_id`, gates by licence entitlement, and **refuses to load (leaves rules unchanged) on any verification failure**. So the story is no longer "scripts prove the protocol" — the running agent enforces it.

Also as of 2026-06-06 the **vendor side is built**: `src/tinysocs/api/feed.py` is a small FastAPI app serving the entitlement-gated feed (mint → signed-URL redirect → blob) and the Stripe webhook that issues + revokes licence keys, both reusing the same `licence.py` decision the agent uses. The full revenue mechanic — *Stripe subscription mints a key → key unlocks the live channel and premium packs → cancel revokes it → the agent verifies the signed pack offline* — now runs locally end-to-end, no cloud account required. What remains is operational, not protocol: the real object store (S3/R2 URL-signing call in place of the blob stand-in) and the Stripe dashboard prices.

---

## Open questions

1. ~~**Server auth mechanism:** signed-URL minting vs always-on gate.~~ **Resolved (Part 4.5):** thin always-on mint endpoint issues short-TTL signed URLs; CDN serves the bytes. Gate reuses `licence.py`. Remaining sub-question: object-store choice (S3 vs R2 vs Backblaze) drives the exact URL-signing call.
2. **Revocation list distribution:** how does the *agent* learn a key was revoked if enforcement is server-side only? Probably it doesn't need to — the server simply stops serving, and the agent degrades to snapshot. But if we ever want client-side revocation awareness (e.g. to show "your licence was revoked" in the dashboard), the agent needs a revocation feed. Defer until there's a reason.
3. **TinyDocs hash manifest:** confirmed slot in `metadata`, but the exact shape (`{path: sha256}` vs a Merkle root) waits on the TinyDocs gap landing.
4. **Snapshot lag policy:** one published version (≈1 week) is the starting assumption. Is one week the right free-tier handicap, or does it make free useless / make free too good? Revisit with customer conversations — it's a pricing-adjacent lever, so it's deliberately not locked here.
5. **`sites` enforcement:** the key carries a `sites` capacity but nothing counts live endpoints yet. Soft (honour-system, display only) at first; hard enforcement needs the federation/heartbeat count, which exists for `msp`. Decide whether `pro` even needs hard seat-counting at launch.
6. **Key delivery UX:** email vs dashboard-only vs both. Founder/ops call, not a protocol decision.
