import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse as urlparse
import requests
import re

# ==== target & tuning ====
TARGET = "http://127.0.0.1:9200"  # TinyBox OpenSearch endpoint
VERIFY_TLS = False                # TLS off for TinyBox local
TIMEOUT = 30                      # a bit more generous for bulk

# Safe destination for any wildcard write targets (env overrides)
SAFE_WRITE_INDEX = os.getenv("SIEM_INDEX_WRITE", "siem_index")

# ---- helpers ---------------------------------------------------------------

def _strip_query_param(path: str, name: str) -> str:
    """Return path with given query parameter removed."""
    if "?" not in path:
        return path
    base, qs = path.split("?", 1)
    q = urlparse.parse_qsl(qs, keep_blank_values=True)
    q = [(k, v) for (k, v) in q if k.lower() != name.lower()]
    return base if not q else base + "?" + urlparse.urlencode(q)

def _sanitize_outbound_headers(hdrs: dict) -> dict:
    """Drop hop-by-hop/problematic headers; requests will set correct Host/CL."""
    drop = {"host", "content-length", "connection", "accept-encoding"}
    return {k: v for k, v in hdrs.items() if k.lower() not in drop}

def _try_json_loads(blob: bytes):
    try:
        return json.loads(blob.decode("utf-8"))
    except Exception:
        return None

def _flatten_typeful_mappings(body_bytes: bytes) -> bytes:
    """
    If payload has mappings under a single type key like {"mappings":{"_doc":{...}}},
    convert to typeless {"mappings":{...}} for OS/ES 8+.
    """
    obj = _try_json_loads(body_bytes)
    if not isinstance(obj, dict):
        return body_bytes
    m = obj.get("mappings")
    if isinstance(m, dict) and len(m) == 1:
        # grab the lone inner object (commonly "_doc")
        inner_key = next(iter(m.keys()))
        inner_val = m.get(inner_key)
        if isinstance(inner_val, dict):
            obj["mappings"] = inner_val
            return json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return body_bytes

def _rewrite_index_wildcards_in_path(path: str) -> str:
    """
    For write endpoints that include the index in the URL, replace wildcard indices
    (e.g. 'tinysocs-winlog-*' or anything with '*') with SAFE_WRITE_INDEX.
    Handles: /{index}/_bulk, /{index}/_doc, /{index}/_create, /{index}/_update, /{index}/_delete
    """
    def _fix_segment(seg: str) -> str:
        return SAFE_WRITE_INDEX if "*" in seg else seg

    # Split off query first
    base, q = (path.split("?", 1) + [""])[:2]
    parts = [p for p in base.split("/") if p != ""]

    # Nothing to do if too short
    if not parts:
        return path

    # Rewrite known write forms
    # Examples:
    #   /tinysocs-winlog-*/_bulk
    #   /tinysocs-winlog-*/_doc[/id]
    #   /tinysocs-winlog-*/_create[/id]
    #   /tinysocs-winlog-*/_update[/id]
    #   /tinysocs-winlog-*/_delete[/id]
    if len(parts) >= 2 and parts[1] in ("_bulk", "_doc", "_create", "_update", "_delete"):
        parts[0] = _fix_segment(parts[0])

    # Rebuild
    new_base = "/" + "/".join(parts)
    if q:
        return new_base + "?" + q
    return new_base

def _rewrite_bulk_typeless(ndjson: bytes) -> bytes:
    """
    Read bulk NDJSON and remove `_type`/`type` from action metadata lines.
    Also replace wildcard _index values with SAFE_WRITE_INDEX.
    Keeps final trailing newline, as required by bulk API.
    """
    out_lines = []
    lines = ndjson.splitlines()
    i = 0
    while i < len(lines):
        raw = lines[i]
        line = raw if isinstance(raw, (bytes, bytearray)) else str(raw).encode("utf-8")
        stripped = line.strip()

        if not stripped:
            out_lines.append(b"")
            i += 1
            continue

        # header line
        try:
            meta = json.loads(stripped.decode("utf-8"))
        except Exception:
            # if parsing fails, pass-through (safer)
            out_lines.append(line)
            i += 1
            continue

        if isinstance(meta, dict) and len(meta) == 1:
            action = next(iter(meta.keys()))
            meta_body = meta[action]
            if isinstance(meta_body, dict):
                # drop legacy types
                meta_body.pop("_type", None)
                meta_body.pop("type", None)
                # fix wildcard index targets (e.g. "_index": "tinysocs-winlog-*")
                idx = meta_body.get("_index")
                if isinstance(idx, str) and "*" in idx:
                    meta_body["_index"] = SAFE_WRITE_INDEX
            # re-serialize compactly
            out_lines.append(json.dumps({action: meta_body}, separators=(",", ":")).encode("utf-8"))
        else:
            out_lines.append(line)

        i += 1
        # If action expects a source line (index/create/update), copy next line as-is
        if 'action' in locals() and action in ("index", "create", "update"):
            if i < len(lines):
                src = lines[i]
                out_lines.append(src if isinstance(src, (bytes, bytearray)) else str(src).encode("utf-8"))
                i += 1

    # Ensure final newline (bulk requires it)
    blob = b"\n".join(out_lines)
    if not blob.endswith(b"\n"):
        blob += b"\n"
    return blob

# ---- server ----------------------------------------------------------------

class Shim(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _reply(self, code, body, headers=None):
        b = body if isinstance(body, (bytes, bytearray)) else str(body).encode("utf-8")
        try:
            self.send_response(code)
            if headers:
                for k, v in headers.items():
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(b)))
            # be conservative with connection reuse to avoid noisy broken pipes
            self.send_header("Connection", "close")
            self.end_headers()
            try:
                self.wfile.write(b)
            except BrokenPipeError:
                pass
        except BrokenPipeError:
            pass

    def _proxy(self, method):
        # Fake license to satisfy beats
        if self.path.startswith("/_license"):
            payload = {"license": {"status": "active", "type": "basic"}, "features": {}}
            return self._reply(200, json.dumps(payload), {"Content-Type": "application/json"})

        # strip include_type_name if present, then rewrite wildcard index in path for writes
        path = _strip_query_param(self.path, "include_type_name")
        path = _rewrite_index_wildcards_in_path(path)
        url = TARGET + path

        # read inbound body
        length = int(self.headers.get("Content-Length", "0") or "0")
        data = self.rfile.read(length) if length > 0 else None

        # transform body for legacy typeful payloads
        content_type = (self.headers.get("Content-Type") or "").lower()

        # Special handling for bulk NDJSON
        if data and "/_bulk" in path:
            data = _rewrite_bulk_typeless(data)
            content_type = "application/x-ndjson"

        # Flatten legacy mappings payloads on template/index creation
        elif data and any(s in path for s in ("/_template", "/_index_template", "/_component_template", "/_index")):
            if "json" in content_type or path.endswith((".json",)):
                data = _flatten_typeful_mappings(data)

        headers = _sanitize_outbound_headers({k: v for k, v in self.headers.items()})
        if data is not None:
            headers["Content-Length"] = str(len(data))
        if content_type:
            headers["Content-Type"] = content_type

        try:
            resp = requests.request(
                method,
                url,
                headers=headers,
                data=data,
                verify=VERIFY_TLS,
                timeout=TIMEOUT,
            )
            # propagate content-type back
            resp_ct = resp.headers.get("Content-Type", "application/octet-stream")
            return self._reply(resp.status_code, resp.content, {"Content-Type": resp_ct})
        except requests.exceptions.RequestException as e:
            return self._reply(502, json.dumps({"error": str(e)}), {"Content-Type": "application/json"})

    # Methods
    def do_GET(self):    self._proxy("GET")
    def do_POST(self):   self._proxy("POST")
    def do_PUT(self):    self._proxy("PUT")
    def do_HEAD(self):   self._proxy("HEAD")
    def do_DELETE(self): self._proxy("DELETE")
    def log_message(self, fmt, *args):  # quiet logs
        pass

if __name__ == "__main__":
    port = 40001
    httpd = HTTPServer(("127.0.0.1", port), Shim)
    print(f"OpenSearch shim listening on http://127.0.0.1:{port} -> {TARGET} (safe_write_index={SAFE_WRITE_INDEX})", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass