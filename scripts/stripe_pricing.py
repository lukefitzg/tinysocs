#!/usr/bin/env python3
"""Stripe price_id -> tier mapping and subscription -> licence resolution.

This is the seam between Stripe billing and the licence gate (scripts/licence.py).
It is the small, pure, server-side map referenced in docs/design/signed-feed.md
-> "Part 6: Stripe -> licence issuance". It does NOT call the Stripe API and
holds NO prices: the dollar figures live in the Stripe dashboard, and the
opaque Stripe price IDs are injected via environment so nothing price-shaped is
committed to the repo (tier architecture is locked; numbers wait for first
customer conversations -- see CLAUDE.md).

What it does:
  - map an opaque Stripe price_id -> (tier, sites_per_unit)
  - resolve a (subset of a) Stripe subscription object into the parameters
    licence.issue() needs: tier, sites, subscription period end (exp), customer.

The actual webhook endpoint that *calls* this (verify webhook signature -> mint
key -> store nonce for revocation -> deliver) is design-only this pass.

Environment (set per-deployment, e.g. from the founder's Stripe dashboard):
    TINYSOCS_PRICE_PRO=price_xxx        # opaque Stripe price id for the pro tier
    TINYSOCS_PRICE_MSP=price_yyy        # opaque Stripe price id for the msp tier
    # free has no Stripe price -- it's the default for anyone without a key.

Demo (no Stripe needed):
    TINYSOCS_PRICE_PRO=price_demo_pro \\
    python3 scripts/stripe_pricing.py resolve --price price_demo_pro --qty 5 \\
        --customer cus_acme --period-end 1781000000
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass

# Number of endpoint "sites" one unit of quantity grants, per tier. Capacity
# integers only -- not prices. msp sells in larger site bundles than pro.
_SITES_PER_UNIT = {"pro": 1, "msp": 5}


def price_map() -> dict[str, str]:
    """Opaque Stripe price_id -> tier, built from env. Missing env => not sold.

    Kept as a function (not a module constant) so it re-reads env in tests and
    so an unconfigured tier simply doesn't appear, rather than mapping to a
    placeholder that could ship by accident.
    """
    m: dict[str, str] = {}
    for tier, var in (("pro", "TINYSOCS_PRICE_PRO"), ("msp", "TINYSOCS_PRICE_MSP")):
        pid = os.environ.get(var)
        if pid:
            m[pid] = tier
    return m


def tier_for_price(price_id: str) -> str:
    """Resolve a Stripe price_id to a tier. Unknown price => 'free' (fail safe)."""
    return price_map().get(price_id, "free")


@dataclass(frozen=True)
class LicenceRequest:
    """Exactly what scripts/licence.py issue() needs to mint a key."""
    tier: str
    sites: int
    sub: str           # Stripe customer id (opaque)
    exp: int           # subscription current_period_end (unix seconds)

    def to_issue_kwargs(self) -> dict:
        # period_days is derived by licence.issue() from `now`; here we pass exp
        # through so the issued key matches the Stripe billing period exactly.
        return {"tier": self.tier, "sites": self.sites, "sub": self.sub, "exp": self.exp}


def resolve_subscription(price_id: str, quantity: int, customer_id: str,
                         current_period_end: int) -> LicenceRequest:
    """Map the fields we care about from a Stripe subscription into a LicenceRequest.

    Mirrors what the webhook handler would extract from a
    customer.subscription.created / .updated event:
      item.price.id -> tier, item.quantity -> sites, current_period_end -> exp.
    """
    tier = tier_for_price(price_id)
    sites = quantity * _SITES_PER_UNIT.get(tier, 0)
    return LicenceRequest(tier=tier, sites=sites, sub=customer_id, exp=current_period_end)


def cmd_resolve(args) -> int:
    req = resolve_subscription(args.price, args.qty, args.customer, args.period_end)
    print(json.dumps({"tier": req.tier, "sites": req.sites, "sub": req.sub, "exp": req.exp}, indent=2))
    if req.tier == "free":
        print(f"note: price_id {args.price!r} not in configured price map "
              f"(set TINYSOCS_PRICE_PRO / TINYSOCS_PRICE_MSP)", file=sys.stderr)
        return 1
    return 0


def cmd_map(_args) -> int:
    m = price_map()
    if not m:
        print("price map empty -- set TINYSOCS_PRICE_PRO / TINYSOCS_PRICE_MSP", file=sys.stderr)
        return 1
    print(json.dumps(m, indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("resolve", help="resolve a subscription into a licence request")
    r.add_argument("--price", required=True, help="Stripe price_id (opaque)")
    r.add_argument("--qty", type=int, default=1, help="subscription item quantity")
    r.add_argument("--customer", default="cus_demo", help="Stripe customer id")
    r.add_argument("--period-end", type=int, required=True, help="current_period_end (unix seconds)")
    r.set_defaults(func=cmd_resolve)

    m = sub.add_parser("map", help="print the configured price_id -> tier map")
    m.set_defaults(func=cmd_map)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
