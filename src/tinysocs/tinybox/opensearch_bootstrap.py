# tinysocs/tinybox/opensearch_bootstrap.py
#
# TinyBox OpenSearch bootstrap:
# - Ensures index template for tinysocs-winlog-* with sane settings/mappings.
# - Ensures alias tinysocs-winlog exists and is attached to winlog indices.
# - Idempotent: safe to run multiple times.

import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, Tuple, List


TEMPLATE_NAME = "tinysocs-winlog-template"
INDEX_PATTERN = "tinysocs-winlog-*"
ALIAS_NAME = "tinysocs-winlog"


def _get_base_url() -> str:
    base = os.environ.get("SIEM_URL", "http://127.0.0.1:9200").strip()
    if base.endswith("/"):
        base = base[:-1]
    return base


def _http_json(method: str, path: str, body: Dict[str, Any] = None) -> Tuple[int, Dict[str, Any]]:
    base = _get_base_url()
    url = f"{base}/{path.lstrip('/')}"
    data_bytes = None

    if body is not None:
        data_bytes = json.dumps(body).encode("utf-8")

    req = urllib.request.Request(url, data=data_bytes, method=method.upper())
    req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read().decode("utf-8")
            if not raw.strip():
                return resp.getcode(), {}
            try:
                return resp.getcode(), json.loads(raw)
            except json.JSONDecodeError:
                # Non-JSON response; return as text payload in case we need it.
                return resp.getcode(), {"_raw": raw}
    except urllib.error.HTTPError as e:
        # Try to parse JSON error body, but always return status code.
        try:
            raw = e.read().decode("utf-8")
            data = json.loads(raw) if raw.strip() else {}
        except Exception:
            data = {"error": str(e)}
        return e.code, data
    except urllib.error.URLError as e:
        print(f"[tinybox-bootstrap] ERROR: Failed HTTP {method} {url}: {e}", file=sys.stderr)
        sys.exit(1)


def _check_cluster() -> None:
    status, body = _http_json("GET", "/")
    if status != 200:
        print(f"[tinybox-bootstrap] ERROR: OpenSearch not healthy (status {status}): {body}", file=sys.stderr)
        sys.exit(1)

    name = body.get("name")
    cluster = body.get("cluster_name")
    print(f"[tinybox-bootstrap] Connected to OpenSearch node={name!r} cluster={cluster!r}")


def _ensure_winlog_template() -> None:
    """
    Always PUT the template. Overwriting is fine and idempotent.
    Template also defines alias tinysocs-winlog so future indices get it automatically.
    """
    template_body: Dict[str, Any] = {
        "index_patterns": [INDEX_PATTERN],
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
            },
            "mappings": {
                "dynamic": True,
                "properties": {
                    "@timestamp": {"type": "date"},
                    "tinysocs_source": {"type": "keyword"},
                    "tinysocs_node": {"type": "keyword"},
                },
            },
            "aliases": {
                ALIAS_NAME: {}
            },
        },
        "priority": 500,
        "_meta": {
            "managed_by": "tinysocs",
            "description": "TinySocs winlogbeat index template for TinyBox local SIEM",
        },
    }

    status, body = _http_json("PUT", f"_index_template/{TEMPLATE_NAME}", template_body)
    if 200 <= status < 300:
        print(f"[tinybox-bootstrap] Index template {TEMPLATE_NAME!r} ensured (status={status}).")
    else:
        print(f"[tinybox-bootstrap] ERROR: Failed to ensure index template {TEMPLATE_NAME!r} (status={status}): {body}", file=sys.stderr)
        sys.exit(1)


def _get_existing_winlog_indices() -> List[str]:
    status, body = _http_json("GET", f"_cat/indices/{INDEX_PATTERN}?format=json")
    if status == 404:
        return []

    if not isinstance(body, list):
        # Unexpected, but don't crash the bootstrap.
        print(f"[tinybox-bootstrap] WARN: Unexpected _cat/indices response: {body}", file=sys.stderr)
        return []

    indices: List[str] = []
    for row in body:
        name = row.get("index")
        if isinstance(name, str):
            indices.append(name)
    return indices


def _ensure_alias_on_existing_indices() -> None:
    indices = _get_existing_winlog_indices()
    if not indices:
        print("[tinybox-bootstrap] No existing tinysocs-winlog-* indices; "
              "alias will be applied automatically to future indices via template.")
        return

    actions = []
    for idx in indices:
        actions.append({
            "add": {
                "index": idx,
                "alias": ALIAS_NAME,
            }
        })

    payload = {"actions": actions}
    status, body = _http_json("POST", "_aliases", payload)
    if 200 <= status < 300:
        print(f"[tinybox-bootstrap] Alias {ALIAS_NAME!r} ensured on indices: {', '.join(indices)}")
    else:
        print(f"[tinybox-bootstrap] ERROR: Failed to update alias {ALIAS_NAME!r} on indices (status={status}): {body}", file=sys.stderr)
        sys.exit(1)


def main(argv: list[str] | None = None) -> int:
    print("[tinybox-bootstrap] Starting TinyBox OpenSearch bootstrap...")
    _check_cluster()
    _ensure_winlog_template()
    _ensure_alias_on_existing_indices()
    print("[tinybox-bootstrap] Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))