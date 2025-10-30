# tinysocs/orchestrator/ensure_anchors.py
from datetime import datetime
import os, sys, json
from opensearchpy import OpenSearch, RequestsHttpConnection

ALIAS = os.getenv("TINYSOCS_ANCHOR_ALIAS", "tinysocs_anchors")
INDEX = os.getenv("TINYSOCS_ANCHOR_INDEX", f"{ALIAS}_v001")

MAPPING = {
  "mappings": {
    "dynamic": True,
    "properties": {
      "node_url": {"type":"keyword"},
      "node_id": {"type":"keyword"},
      "ok": {"type":"boolean"},
      "sequence": {"type":"long"},
      "head_sha256": {"type":"keyword"},
      "capability": {"type":"keyword"},
      "anchored_at": {"type":"date"},
      "run": {
        "properties": {
          "rules": {"type":"keyword"},
          "window": {"type":"keyword"},
          "items": {"type":"long"},
          "privacy_mode": {"type":"keyword"}
        }
      }
    }
  }
}

def main():
  url = os.getenv("SIEM_URL", "http://127.0.0.1:9200")
  user = os.getenv("SIEM_USER")
  pw   = os.getenv("SIEM_PASS")
  verify = os.getenv("SIEM_SSL_VERIFY", "true").lower() in ("1","true","yes")
  client = OpenSearch(hosts=[url], http_auth=(user, pw) if user else None,
                      use_ssl=url.startswith("https"), verify_certs=verify,
                      connection_class=RequestsHttpConnection)

  if not client.indices.exists_alias(name=ALIAS):
    if not client.indices.exists(index=INDEX):
      client.indices.create(index=INDEX, body=MAPPING)
    client.indices.put_alias(index=INDEX, name=ALIAS)
    print(json.dumps({"created": True, "alias": ALIAS, "index": INDEX}))
  else:
    print(json.dumps({"created": False, "alias": ALIAS}))

if __name__ == "__main__":
  sys.exit(main())