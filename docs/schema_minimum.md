\# TinySocs Minimum Guaranteed Event Schema (Phase 8 freeze)



This is the minimum stable contract that detections, anchors, and downstream tooling may rely on.

Fields listed here MUST remain present across versions (nullable allowed) unless a migration is performed.



\## Envelope (top-level)

\- ts (date, ISO8601) — TinySocs ingest/collection time

\- input (string) — input name (e.g. win-events)

\- channel (string) — Windows channel (e.g. Security)

\- eventId (int) — primary event id (mirrors body.event.id)

\- openSearchIndex (string) — optional/derived (may be empty)

\- body (object) — event payload



\## Payload (body.\*)

\- body.@timestamp (date, ISO8601) — original event time

\- body.message (string)

\- body.event.id (int)

\- body.event.code (int)

\- body.event.level (string)

\- body.event.provider (string)

\- body.event.record\_id (int)

\- body.winlog.channel (string)

\- body.winlog.computer\_name (string)

\- body.winlog.provider\_name (string)

\- body.winlog.record\_id (int)

\- body.tinysocs.input\_name (string)



\## Notes

\- Canonical event time is body.@timestamp.

\- Canonical ingest time is ts.

\- Detections should prefer body.event.\* + body.winlog.\* and treat body.message as auxiliary.

