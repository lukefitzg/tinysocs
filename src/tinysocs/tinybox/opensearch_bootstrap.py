# tinysocs/tinybox/opensearch_bootstrap.py
#
# TinyBox OpenSearch bootstrap:
# - Ensures ALL index templates shipped as *.json under a templates directory.
# - Seeds aliases onto any existing indices matched by each template's index_patterns.
# - Idempotent: safe to run multiple times.
#
# Env:
#   SIEM_URL              (default http://127.0.0.1:9200)
#   SIEM_USER / SIEM_PASS (optional; enables Basic auth)
#   SIEM_SSL_VERIFY       ("1"/"true" to verify; "0"/"false" to skip; default "1")
#   SIEM_CA_CERT          (optional path to CA PEM/CRT; used when verifying)
#   TINYSOCS_OS_TEMPLATES_DIR (optional override templates dir)

import base64
import json
import os
import sys
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Tuple, List, Optional


DEFAULT_TIMEOUT_SEC = 15


def _get_base_url() -> str:
    base = os.environ.get("SIEM_URL", "http://127.0.0.1:9200").strip()
    if base.endswith("/"):
        base = base[:-1]
    return base


def _bool_env(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    v = v.strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off"):
        return False
    return default


def _ssl_context_for_url(url: str) -> Optional[ssl.SSLContext]:
    if not url.lower().startswith("https://"):
        return None

    verify = _bool_env("SIEM_SSL_VERIFY", True)
    if not verify:
        return ssl._create_unverified_context()

    ca_path = os.environ.get("SIEM_CA_CERT")
    if ca_path and Path(ca_path).exists():
        ctx = ssl.create_default_context(cafile=ca_path)
        return ctx

    return ssl.create_default_context()


def _basic_auth_header() -> Optional[str]:
    user = os.environ.get("SIEM_USER")
    pw = os.environ.get("SIEM_PASS")
    if not user or not pw:
        return None
    token = base64.b64encode(f"{user}:{pw}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def _http_json(method: str, path: str, body: Any = None, timeout: int = DEFAULT_TIMEOUT_SEC) -> Tuple[int, Any]:
    base = _get_base_url()
    url = f"{base}/{path.lstrip('/')}"
    data_bytes = None

    if body is not None:
        data_bytes = json.dumps(body).encode("utf-8")

    req = urllib.request.Request(url, data=data_bytes, method=method.upper())
    req.add_header("Content-Type", "application/json")

    auth = _basic_auth_header()
    if auth:
        req.add_header("Authorization", auth)

    ctx = _ssl_context_for_url(url)

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            if not raw.strip():
                return resp.getcode(), {}
            try:
                return resp.getcode(), json.loads(raw)
            except json.JSONDecodeError:
                return resp.getcode(), {"_raw": raw}
    except urllib.error.HTTPError as e:
        try:
            raw = e.read().decode("utf-8", errors="replace")
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


def _find_templates_dir() -> Optional[Path]:
    override = os.environ.get("TINYSOCS_OS_TEMPLATES_DIR")
    if override:
        p = Path(override)
        if p.exists() and p.is_dir():
            return p

    here = Path(__file__).resolve()
    candidates = [
        # repo layouts
        here.parents[3] / "packaging" / "opensearch" / "templates",  # src/tinysocs/tinybox -> repo
        here.parents[2] / "packaging" / "opensearch" / "templates",
        here.parents[3] / "opensearch" / "templates",
        # install layouts (best-effort)
        Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "TinySocs" / "OpenSearch" / "templates",
        Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "TinySocs" / "opensearch" / "templates",
    ]
    for c in candidates:
        try:
            if c.exists() and c.is_dir():
                return c
        except Exception:
            continue
    return None


def _list_template_files(templates_dir: Path) -> List[Path]:
    files = sorted([p for p in templates_dir.glob("*.json") if p.is_file()])
    return files


def _put_index_template(name: str, body: Dict[str, Any]) -> None:
    status, resp = _http_json("PUT", f"/_index_template/{name}", body)
    if 200 <= status < 300:
        print(f"[tinybox-bootstrap] Template ensured: {name} (status={status})")
        return
    print(f"[tinybox-bootstrap] ERROR: Template ensure failed: {name} (status={status}) :: {resp}", file=sys.stderr)
    sys.exit(1)


def _get_indices_for_pattern(pattern: str) -> List[str]:
    # _cat returns 404 if no indices match in some configurations; treat as "none"
    status, body = _http_json("GET", f"/_cat/indices/{pattern}?format=json", timeout=DEFAULT_TIMEOUT_SEC)
    if status == 404:
        return []
    if not isinstance(body, list):
        return []
    out: List[str] = []
    for row in body:
        if isinstance(row, dict):
            nm = row.get("index")
            if isinstance(nm, str) and nm:
                out.append(nm)
    return out


def _seed_aliases_for_template(template_body: Dict[str, Any]) -> None:
    pats = template_body.get("index_patterns")
    if not isinstance(pats, list):
        return

    tmpl = template_body.get("template")
    if not isinstance(tmpl, dict):
        return

    aliases = tmpl.get("aliases")
    if not isinstance(aliases, dict) or not aliases:
        return

    alias_names = [a for a in aliases.keys() if isinstance(a, str) and a.strip()]
    if not alias_names:
        return

    # Seed aliases onto any existing indices matching the patterns.
    for pat in pats:
        if not isinstance(pat, str) or not pat.strip():
            continue
        indices = _get_indices_for_pattern(pat.strip())
        if not indices:
            continue

        actions: List[Dict[str, Any]] = []
        for idx in indices:
            for a in alias_names:
                actions.append({"add": {"index": idx, "alias": a}})

        status, resp = _http_json("POST", "/_aliases", {"actions": actions}, timeout=DEFAULT_TIMEOUT_SEC)
        if 200 <= status < 300:
            print(f"[tinybox-bootstrap] Aliases seeded: pattern={pat} aliases={','.join(alias_names)} indices={len(indices)}")
        else:
            # Non-fatal warning (alias may already exist / races), but do show it.
            print(
                f"[tinybox-bootstrap] WARN: Alias seed failed: pattern={pat} (status={status}) :: {resp}",
                file=sys.stderr,
            )


def _ensure_templates_and_aliases() -> None:
    templates_dir = _find_templates_dir()
    if not templates_dir:
        print("[tinybox-bootstrap] WARN: No templates dir found; skipping template bootstrap.")
        return

    files = _list_template_files(templates_dir)
    if not files:
        print(f"[tinybox-bootstrap] WARN: No *.json templates in {templates_dir}; skipping.")
        return

    print(f"[tinybox-bootstrap] Ensuring index templates from: {templates_dir}")
    for f in files:
        try:
            raw = f.read_text(encoding="utf-8")
            body = json.loads(raw)
            if not isinstance(body, dict):
                print(f"[tinybox-bootstrap] WARN: Skipping {f.name} (not a JSON object).", file=sys.stderr)
                continue
            name = f.stem  # filename without .json
            _put_index_template(name, body)
            _seed_aliases_for_template(body)
        except Exception as e:
            print(f"[tinybox-bootstrap] ERROR: Failed processing template {f}: {e}", file=sys.stderr)
            sys.exit(1)


def main(argv: list[str] | None = None) -> int:
    print("[tinybox-bootstrap] Starting TinyBox OpenSearch bootstrap...")
    _check_cluster()
    _ensure_templates_and_aliases()
    print("[tinybox-bootstrap] Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))