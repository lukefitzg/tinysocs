#!/usr/bin/env python3
"""Quick diagnostic: check if specific event IDs exist in OpenSearch."""
import json, ssl, urllib.request

ctx = ssl._create_unverified_context()
url = "https://localhost:9201/tinysocs-winlog-*/_search"
headers = {
    "Content-Type": "application/json",
    "Authorization": "Basic " + __import__("base64").b64encode(b"admin:secret").decode(),
}

# Search for the 3 event IDs that should have fired during ART tests
query = {
    "query": {
        "bool": {
            "should": [
                {"match": {"winlog.event_id": 4698}},
                {"match": {"winlog.event_id": 1102}},
                {"match": {"winlog.event_id": 13}},
            ],
            "minimum_should_match": 1,
        }
    },
    "size": 5,
    "sort": [{"@timestamp": {"order": "desc"}}],
}

req = urllib.request.Request(url, data=json.dumps(query).encode(), headers=headers)
try:
    resp = urllib.request.urlopen(req, context=ctx, timeout=10)
    data = json.loads(resp.read())
    hits = data.get("hits", {}).get("hits", [])
    total = data.get("hits", {}).get("total", {})
    print(f"Total matching events: {total}")
    print(f"Returned: {len(hits)} events\n")
    for h in hits:
        src = h.get("_source", {})
        eid = src.get("winlog", {}).get("event_id", "?")
        chan = src.get("winlog", {}).get("channel", "?")
        ts = src.get("@timestamp", "?")
        host = src.get("host", {}).get("name", "?")
        print(f"  EventID={eid}  Channel={chan}  Host={host}  Time={ts}")
    if not hits:
        print("No events found for IDs 4698, 1102, or 13.")
        print("\nChecking what event IDs DO exist...")
        # Get top event IDs via aggregation
        agg_query = {
            "size": 0,
            "aggs": {
                "top_event_ids": {
                    "terms": {"field": "winlog.event_id", "size": 20}
                }
            },
        }
        req2 = urllib.request.Request(url, data=json.dumps(agg_query).encode(), headers=headers)
        resp2 = urllib.request.urlopen(req2, context=ctx, timeout=10)
        data2 = json.loads(resp2.read())
        buckets = data2.get("aggregations", {}).get("top_event_ids", {}).get("buckets", [])
        print(f"\nTop {len(buckets)} event IDs in OpenSearch:")
        for b in buckets:
            print(f"  EventID {b['key']:>6} : {b['doc_count']} events")
except Exception as e:
    print(f"Error: {e}")
