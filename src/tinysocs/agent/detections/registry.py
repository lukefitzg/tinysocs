# src/tinysocs/agent/detections/registry.py
import json
import os
from dataclasses import dataclass
from dataclasses import fields as dc_fields
from importlib import resources

import yaml


@dataclass
class Rule:
    """Product-mode detection rule, loaded from rules.yaml or custom_rules.json.

    These rules are meant to be referenced by ID (e.g. "auth_failed_burst")
    from the TinySocs node /agg endpoint. The fields map directly to the
    OpenSearch query that the node will run.
    """

    id: str
    description: str
    index: str = "tinysocs-winlog-*"
    time_field: str = "@timestamp"
    kql: str = "*"
    group_by: list[str] = None  # type: ignore[assignment]
    threshold: int = 1
    severity: str = "medium"
    category: str = "custom"
    tuning_envvars: list[str] | None = None

    def __post_init__(self):
        if self.group_by is None:
            self.group_by = []


def _load_rules_from_yaml() -> dict[str, Rule]:
    """Load rules from rules.yaml into a dict keyed by rule id.

    rules.yaml lives alongside this module in tinysocs/agent/detections/.
    The file is expected to contain a list of mapping objects; each mapping
    must at least contain an "id" field plus any other Rule dataclass fields.
    Unknown fields are ignored.
    """

    pkg = "tinysocs.agent.detections"
    text = resources.files(pkg).joinpath("rules.yaml").read_text(encoding="utf-8")
    raw = yaml.safe_load(text) or []

    rules: dict[str, Rule] = {}
    allowed_fields = {f.name for f in dc_fields(Rule)}
    for r in raw:
        rid = r.get("id")
        if not rid:
            continue
        # Only pass fields that exist on the dataclass
        allowed = {k: v for k, v in r.items() if k in allowed_fields}
        rules[rid] = Rule(**allowed)

    return rules


def _resolve_custom_rules_path() -> str | None:
    """Find the custom_rules.json file.

    Search order:
    1. TINYSOCS_CUSTOM_RULES env var
    2. %PROGRAMDATA%/TinySocs/custom_rules.json  (Windows production)
    3. ./custom_rules.json  (development fallback)
    """
    env = os.getenv("TINYSOCS_CUSTOM_RULES")
    if env and os.path.isfile(env):
        return env

    pd = os.getenv("PROGRAMDATA", "")
    if pd:
        candidate = os.path.join(pd, "TinySocs", "custom_rules.json")
        if os.path.isfile(candidate):
            return candidate

    if os.path.isfile("custom_rules.json"):
        return "custom_rules.json"

    return None


def load_custom_rules() -> dict[str, Rule]:
    """Load custom rules from custom_rules.json.

    Returns a dict keyed by rule id. Rules with enabled=False are excluded.
    """
    path = _resolve_custom_rules_path()
    if not path:
        return {}

    try:
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[tinysocs-registry] failed to load custom rules from {path}: {exc}",
              flush=True)
        return {}

    rules: dict[str, Rule] = {}
    allowed_fields = {f.name for f in dc_fields(Rule)}
    for r in raw:
        if not isinstance(r, dict):
            continue
        rid = r.get("id")
        if not rid:
            continue
        # Skip disabled rules
        if r.get("enabled") is False:
            continue
        allowed = {k: v for k, v in r.items() if k in allowed_fields}
        try:
            rules[rid] = Rule(**allowed)
        except TypeError:
            print(f"[tinysocs-registry] skipping malformed custom rule: {rid}",
                  flush=True)
            continue

    return rules


def reload_rules() -> None:
    """Reload both built-in and custom rules into the global RULES dict.

    Call this after custom rules are modified to pick up changes.
    """
    RULES.clear()
    RULES.update(_load_rules_from_yaml())
    custom = load_custom_rules()
    # Custom rules can override built-in rules with the same ID
    RULES.update(custom)
    print(f"[tinysocs-registry] loaded {len(RULES)} rules "
          f"({len(RULES) - len(custom)} built-in, {len(custom)} custom)",
          flush=True)


# Global registry used by the node /agg endpoint
RULES: dict[str, Rule] = _load_rules_from_yaml()

# Merge in any custom rules on first import
_custom = load_custom_rules()
if _custom:
    RULES.update(_custom)
    print(f"[tinysocs-registry] loaded {len(_custom)} custom rule(s) on startup",
          flush=True)


def get_rule(rule_id: str) -> Rule | None:
    """Convenience accessor for a single rule by id.

    Returns None if the rule is not found.
    """

    return RULES.get(rule_id)
