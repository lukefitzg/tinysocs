import collections
from typing import Any, Dict, List

import yaml

from ..adapters.select import make_client

client = make_client()

def run_detections(rules_path="agent/detections/rules.yaml") -> List[Dict[str, Any]]:
    rules = yaml.safe_load(open(rules_path, encoding="utf-8"))
    findings: List[Dict[str, Any]] = []

    for r in rules:
        hits = client.search_kql(r.get("index",""), r["kql"], size=2000)

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
