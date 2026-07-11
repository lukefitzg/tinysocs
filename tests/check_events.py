#!/usr/bin/env python3
"""Quick diagnostic: check actual event structure in OpenSearch."""
import base64
import json
import ssl
import urllib.request

ctx = ssl._create_unverified_context()
base_url = "https://localhost:9201"
auth = "Basic " + base64.b64encode(b"admin:secret").decode()
headers = {"Content-Type": "application/json", "Authorization": auth}


def query(path, body=None):
    url = base_url + path
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, headers=headers)
    resp = urllib.request.urlopen(req, context=ctx, timeout=10)
    return json.loads(resp.read())


# 1. What indices exist?
print("=== INDICES ===")
try:
    indices = query("/_cat/indices/tinysocs-*?format=json&h=index,docs.count,store.size")
    for idx in sorted(indices, key=lambda x: x.get("index", "")):
        print(f"  {idx.get('index', '?'):50s}  docs={idx.get('docs.count', '?'):>8s}  size={idx.get('store.size', '?')}")
except Exception as e:
    print(f"  Error: {e}")

# 2. Get a sample event to see the actual field structure
print("\n=== SAMPLE EVENT (first 1 from tinysocs-winlog-*) ===")
try:
    result = query("/tinysocs-winlog-*/_search", {"size": 1, "sort": [{"@timestamp": {"order": "desc"}}]})
    hits = result.get("hits", {}).get("hits", [])
    total = result.get("hits", {}).get("total", {})
    print(f"Total docs in tinysocs-winlog-*: {total}")
    if hits:
        src = hits[0].get("_source", {})
        print(f"\nFull event source (keys): {sorted(src.keys())}")
        print("\nFull event JSON:")
        print(json.dumps(src, indent=2, default=str)[:3000])
    else:
        print("No events found!")
except Exception as e:
    print(f"  Error: {e}")

# 3. Check field mapping for event_id
print("\n=== FIELD MAPPING for 'event_id' and 'event.code' ===")
try:
    mapping = query("/tinysocs-winlog-*/_mapping")
    for idx_name, idx_data in mapping.items():
        props = idx_data.get("mappings", {}).get("properties", {})
        # Check for winlog.event_id
        winlog = props.get("winlog", {}).get("properties", {})
        if "event_id" in winlog:
            print(f"  {idx_name}: winlog.event_id = {winlog['event_id']}")
        # Check for event.code
        event = props.get("event", {}).get("properties", {})
        if "code" in event:
            print(f"  {idx_name}: event.code = {event['code']}")
        # Check for EventId at root
        if "EventId" in props:
            print(f"  {idx_name}: EventId = {props['EventId']}")
        if "event_id" in props:
            print(f"  {idx_name}: event_id = {props['event_id']}")
        break  # just check first index
except Exception as e:
    print(f"  Error: {e}")

# 4. Aggregate by channel and event code
print("\n=== EVENTS BY CHANNEL ===")
try:
    result = query("/tinysocs-winlog-*/_search", {
        "size": 0,
        "aggs": {"channels": {"terms": {"field": "winlog.channel", "size": 20}}}
    })
    for b in result.get("aggregations", {}).get("channels", {}).get("buckets", []):
        print(f"  {b['key']:55s}  {b['doc_count']:>6} events")
except Exception as e:
    print(f"  Error: {e}")

print("\n=== TOP 20 EVENT CODES (event.code) ===")
try:
    result = query("/tinysocs-winlog-*/_search", {
        "size": 0,
        "aggs": {"codes": {"terms": {"field": "event.code", "size": 20}}}
    })
    for b in result.get("aggregations", {}).get("codes", {}).get("buckets", []):
        print(f"  event.code={b['key']:>6}  {b['doc_count']:>6} events")
except Exception as e:
    print(f"  Error: {e}")

# 5. Specifically check for our target event codes
print("\n=== TARGET EVENT CODES (4698, 1102, 13) via event.code ===")
for eid in [4698, 1102, 13, 1, 4625, 4624]:
    try:
        result = query("/tinysocs-winlog-*/_search", {
            "size": 0,
            "query": {"term": {"event.code": eid}}
        })
        total = result.get("hits", {}).get("total", {}).get("value", 0)
        print(f"  event.code={eid:>6}  {total:>6} events")
    except Exception as e:
        print(f"  event.code={eid:>6}  Error: {e}")
