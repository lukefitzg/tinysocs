# src/tinysocs/agent/detections/registry.py
from dataclasses import dataclass
from typing import List, Dict, Optional
import yaml
from importlib import resources


@dataclass
class Rule:
    """Product-mode detection rule, loaded from rules.yaml.

    These rules are meant to be referenced by ID (e.g. "auth_failed_burst")
    from the TinySocs node /agg endpoint. The fields map directly to the
    OpenSearch query that the node will run.
    """

    id: str
    description: str
    index: str
    time_field: str
    kql: str
    group_by: List[str]
    threshold: int
    severity: str
    category: str
    tuning_envvars: Optional[List[str]] = None


def _load_rules_from_yaml() -> Dict[str, Rule]:
    """Load rules from rules.yaml into a dict keyed by rule id.

    rules.yaml lives alongside this module in tinysocs/agent/detections/.
    The file is expected to contain a list of mapping objects; each mapping
    must at least contain an "id" field plus any other Rule dataclass fields.
    Unknown fields are ignored.
    """

    pkg = "tinysocs.agent.detections"
    text = resources.files(pkg).joinpath("rules.yaml").read_text(encoding="utf-8")
    raw = yaml.safe_load(text) or []

    rules: Dict[str, Rule] = {}
    for r in raw:
        rid = r.get("id")
        if not rid:
            continue
        # Only pass fields that exist on the dataclass
        allowed = {k: v for k, v in r.items() if k in Rule.__dataclass_fields__}
        rules[rid] = Rule(**allowed)

    return rules


# Global registry used by the node /agg endpoint
RULES: Dict[str, Rule] = _load_rules_from_yaml()


def get_rule(rule_id: str) -> Optional[Rule]:
    """Convenience accessor for a single rule by id.

    Returns None if the rule is not found.
    """

    return RULES.get(rule_id)