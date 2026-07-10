import collections
from typing import Any

import yaml

from ..adapters.select import make_client

client = make_client()

def run_detections(rules_path="agent/detections/rules.yaml") -> list[dict[str, Any]]:
    rules = yaml.safe_load(open(rules_path, encoding="utf-8"))
    findings: list[dict[str, Any]] = []

    for r in rules:
        hits = client.search_kql(r.get("index",""), r["kql"], size=2000)
        assert isinstance(hits, list)  # size > 0 always returns a doc list, never the count-only dict/int

        if r.get("threshold"):
            # count by (source.ip, user.name)
            ctr = collections.Counter(
                ( (d.get("source") or {}).get("ip"),
                  (d.get("user") or {}).get("name") )
                for d in hits
            )
            for (ip, user), n in ctr.items():
                if ip and n >= r["threshold"]:
                    findings.append({
                        "rule": r["id"],
                        "summary": r["description"],
                        "evidence": {"ip": ip, "user": user, "count": n},
                        "sample": hits[:10],
                    })
        else:
            if hits:
                findings.append({
                    "rule": r["id"],
                    "summary": r["description"],
                    "count": len(hits),
                    "sample": hits[:10],
                })

    return findings
