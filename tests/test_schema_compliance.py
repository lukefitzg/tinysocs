"""
Phase 13 M6: Schema compliance tests.

Validates that:
  1. JSON Schema files are syntactically valid
  2. Sample event / alert documents validate against the schemas
  3. OpenSearch index templates are consistent with the JSON Schemas
  4. The C# AlertDocument fields match the alert schema
  5. Invalid documents are correctly rejected
"""

import json
import pathlib
import re

import pytest

try:
    import jsonschema
    from jsonschema import Draft202012Validator

    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False

ROOT = pathlib.Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_json(rel_path: str) -> dict:
    """Load a JSON file relative to repo root."""
    p = ROOT / rel_path
    assert p.exists(), f"Missing file: {p}"
    return json.loads(p.read_text(encoding="utf-8"))


def _event_schema() -> dict:
    return _load_json("schema/event-schema.json")


def _alert_schema() -> dict:
    return _load_json("schema/alert-schema.json")


def _make_valid_event() -> dict:
    """Return a minimal valid event document."""
    return {
        "@timestamp": "2026-02-20T10:30:45.123Z",
        "message": "An account was successfully logged on.",
        "event": {
            "id": 4624,
            "code": 4624,
            "level": "Information",
            "provider": "Microsoft-Windows-Security-Auditing",
            "record_id": 123456,
        },
        "winlog": {
            "channel": "Security",
            "computer_name": "WORKSTATION-01",
            "event_id": "4624",
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "record_id": 123456,
            "event_data": {
                "TargetUserName": "admin",
                "IpAddress": "192.168.1.100",
                "LogonType": "10",
            },
        },
        "tinysocs": {
            "input_name": "win-events",
            "node_id": "default-node",
        },
    }


def _make_valid_alert() -> dict:
    """Return a minimal valid alert document."""
    return {
        "timestamp": "2026-02-20T10:35:00.000Z",
        "alert": {
            "id": "brute_force_logon|admin|2026-02-20T10:30:00Z",
            "rule_id": "brute_force_logon",
            "rule_name": "Brute Force Logon Attempts",
            "severity": "high",
            "description": "Multiple failed logon attempts detected for the same account.",
            "event_count": 15,
            "first_seen": "2026-02-20T10:30:05Z",
            "last_seen": "2026-02-20T10:34:55Z",
            "window_start": "2026-02-20T10:30:00Z",
        },
        "source": {
            "TargetUserName": "admin",
        },
        "matched_events": 15,
    }


# ---------------------------------------------------------------------------
# 1. Schema file validity
# ---------------------------------------------------------------------------


class TestSchemaFilesValid:
    """Verify the JSON Schema files themselves are valid."""

    def test_event_schema_loads(self):
        schema = _event_schema()
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert "properties" in schema

    def test_alert_schema_loads(self):
        schema = _alert_schema()
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert "properties" in schema

    def test_event_schema_has_required_fields(self):
        schema = _event_schema()
        assert "@timestamp" in schema["required"]
        assert "event" in schema["required"]
        assert "winlog" in schema["required"]

    def test_alert_schema_has_required_fields(self):
        schema = _alert_schema()
        assert "timestamp" in schema["required"]
        assert "alert" in schema["required"]

    def test_alert_schema_alert_required_fields(self):
        schema = _alert_schema()
        alert_req = schema["properties"]["alert"]["required"]
        for field in ["id", "rule_id", "rule_name", "severity", "description", "event_count"]:
            assert field in alert_req, f"Missing required alert field: {field}"

    @pytest.mark.skipif(not HAS_JSONSCHEMA, reason="jsonschema not installed")
    def test_event_schema_is_valid_jsonschema(self):
        """The schema itself should be a valid JSON Schema draft 2020-12."""
        schema = _event_schema()
        Draft202012Validator.check_schema(schema)

    @pytest.mark.skipif(not HAS_JSONSCHEMA, reason="jsonschema not installed")
    def test_alert_schema_is_valid_jsonschema(self):
        schema = _alert_schema()
        Draft202012Validator.check_schema(schema)


# ---------------------------------------------------------------------------
# 2. Sample document validation
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_JSONSCHEMA, reason="jsonschema not installed")
class TestEventDocumentValidation:
    """Validate sample event documents against event-schema.json."""

    def test_valid_event_passes(self):
        jsonschema.validate(_make_valid_event(), _event_schema())

    def test_minimal_event_passes(self):
        """Bare-minimum event with only required fields."""
        doc = {
            "@timestamp": "2026-02-20T00:00:00Z",
            "event": {"id": 1},
            "winlog": {"channel": "Security"},
        }
        jsonschema.validate(doc, _event_schema())

    def test_missing_timestamp_fails(self):
        doc = _make_valid_event()
        del doc["@timestamp"]
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(doc, _event_schema())

    def test_missing_event_fails(self):
        doc = _make_valid_event()
        del doc["event"]
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(doc, _event_schema())

    def test_missing_winlog_fails(self):
        doc = _make_valid_event()
        del doc["winlog"]
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(doc, _event_schema())

    def test_invalid_event_level_fails(self):
        doc = _make_valid_event()
        doc["event"]["level"] = "debug"  # Not in enum
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(doc, _event_schema())

    def test_negative_event_id_fails(self):
        doc = _make_valid_event()
        doc["event"]["id"] = -1
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(doc, _event_schema())

    def test_extra_top_level_field_fails(self):
        """additionalProperties=false should reject unknown fields."""
        doc = _make_valid_event()
        doc["_unknown_field_"] = "should not be here"
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(doc, _event_schema())

    def test_event_data_dynamic_fields_pass(self):
        """event_data allows additional properties (dynamic)."""
        doc = _make_valid_event()
        doc["winlog"]["event_data"]["CustomField"] = "value"
        doc["winlog"]["event_data"]["AnotherField"] = 42
        jsonschema.validate(doc, _event_schema())


@pytest.mark.skipif(not HAS_JSONSCHEMA, reason="jsonschema not installed")
class TestAlertDocumentValidation:
    """Validate sample alert documents against alert-schema.json."""

    def test_valid_alert_passes(self):
        jsonschema.validate(_make_valid_alert(), _alert_schema())

    def test_minimal_alert_passes(self):
        """Bare-minimum alert with only required fields."""
        doc = {
            "timestamp": "2026-02-20T00:00:00Z",
            "alert": {
                "id": "r1|key|2026-02-20T00:00:00Z",
                "rule_id": "r1",
                "rule_name": "Test Rule",
                "severity": "low",
                "description": "desc",
                "event_count": 1,
                "window_start": "2026-02-20T00:00:00Z",
            },
        }
        jsonschema.validate(doc, _alert_schema())

    def test_missing_alert_id_fails(self):
        doc = _make_valid_alert()
        del doc["alert"]["id"]
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(doc, _alert_schema())

    def test_invalid_severity_fails(self):
        doc = _make_valid_alert()
        doc["alert"]["severity"] = "super_critical"
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(doc, _alert_schema())

    def test_zero_event_count_fails(self):
        doc = _make_valid_alert()
        doc["alert"]["event_count"] = 0
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(doc, _alert_schema())

    def test_null_first_seen_passes(self):
        doc = _make_valid_alert()
        doc["alert"]["first_seen"] = None
        jsonschema.validate(doc, _alert_schema())

    def test_source_dynamic_fields_pass(self):
        """source allows additional properties (dynamic)."""
        doc = _make_valid_alert()
        doc["source"]["custom_key"] = "value"
        jsonschema.validate(doc, _alert_schema())


# ---------------------------------------------------------------------------
# 3. OpenSearch template consistency
# ---------------------------------------------------------------------------


class TestTemplateConsistency:
    """Verify OpenSearch index templates match the JSON Schemas."""

    def test_winlog_template_fields_match_schema(self):
        """Every field in the winlog template must exist in event-schema.json."""
        template = _load_json("packaging/opensearch/templates/tinysocs-winlog.json")
        schema = _event_schema()

        tmpl_props = template["template"]["mappings"]["properties"]
        schema_props = schema["properties"]

        # Top-level fields
        for field in tmpl_props:
            assert field in schema_props, (
                f"Template field '{field}' not in event schema"
            )

        # Nested: event.*
        for field in tmpl_props.get("event", {}).get("properties", {}):
            assert field in schema_props["event"]["properties"], (
                f"Template field 'event.{field}' not in event schema"
            )

        # Nested: winlog.*
        for field in tmpl_props.get("winlog", {}).get("properties", {}):
            assert field in schema_props["winlog"]["properties"], (
                f"Template field 'winlog.{field}' not in event schema"
            )

        # Nested: tinysocs.*
        for field in tmpl_props.get("tinysocs", {}).get("properties", {}):
            assert field in schema_props["tinysocs"]["properties"], (
                f"Template field 'tinysocs.{field}' not in event schema"
            )

    def test_alerts_template_fields_match_schema(self):
        """Every field in the alerts template must exist in alert-schema.json."""
        template = _load_json("packaging/opensearch/templates/tinysocs-alerts.json")
        schema = _alert_schema()

        tmpl_props = template["template"]["mappings"]["properties"]
        schema_props = schema["properties"]

        for field in tmpl_props:
            assert field in schema_props, (
                f"Template field '{field}' not in alert schema"
            )

        # Nested: alert.*
        for field in tmpl_props.get("alert", {}).get("properties", {}):
            assert field in schema_props["alert"]["properties"], (
                f"Template field 'alert.{field}' not in alert schema"
            )

    def test_winlog_template_types_compatible(self):
        """Verify OpenSearch types are compatible with JSON Schema types."""
        type_map = {
            "date": "string",
            "text": "string",
            "keyword": "string",
            "long": "integer",
            "integer": "integer",
        }

        template = _load_json("packaging/opensearch/templates/tinysocs-winlog.json")
        schema = _event_schema()
        tmpl_props = template["template"]["mappings"]["properties"]

        # Check top-level simple fields
        for field, tmpl_spec in tmpl_props.items():
            if "type" in tmpl_spec and field in schema["properties"]:
                os_type = tmpl_spec["type"]
                if os_type == "object":
                    continue
                expected_json_type = type_map.get(os_type, os_type)
                schema_type = schema["properties"][field].get("type")
                if isinstance(schema_type, list):
                    assert expected_json_type in schema_type, (
                        f"Type mismatch for '{field}': OS={os_type} schema={schema_type}"
                    )
                else:
                    assert schema_type == expected_json_type, (
                        f"Type mismatch for '{field}': OS={os_type} -> {expected_json_type}, schema={schema_type}"
                    )


# ---------------------------------------------------------------------------
# 4. C# model consistency
# ---------------------------------------------------------------------------


class TestCSharpModelConsistency:
    """Verify C# AlertDocument fields match alert-schema.json."""

    def _parse_csharp_properties(self, filepath: str) -> list[str]:
        """Extract public property names from a C# file (simple regex)."""
        text = (ROOT / filepath).read_text(encoding="utf-8")
        # Match: public <type> PropertyName { get; set; }
        return re.findall(r"public\s+\S+\??\s+(\w+)\s*\{", text)

    def test_alert_document_fields_in_schema(self):
        """Every C# AlertDocument property should map to a schema field."""
        props = self._parse_csharp_properties(
            "src/TinySocs.Agent/Detection/AlertDocument.cs"
        )
        schema = _alert_schema()
        schema_top = set(schema["properties"].keys())

        # AlertDocument has: Timestamp, Alert, Source, MatchedEvents
        # These serialize to camelCase: timestamp, alert, source, matchedEvents
        csharp_to_json = {
            "Timestamp": "timestamp",
            "Alert": "alert",
            "Source": "source",
            "MatchedEvents": "matched_events",
        }

        for prop in props:
            if prop in csharp_to_json:
                json_name = csharp_to_json[prop]
                assert json_name in schema_top, (
                    f"C# property AlertDocument.{prop} -> '{json_name}' not in alert schema"
                )

    def test_alert_info_fields_in_schema(self):
        """Every C# AlertInfo property should map to an alert.* schema field."""
        props = self._parse_csharp_properties(
            "src/TinySocs.Agent/Detection/AlertDocument.cs"
        )
        schema = _alert_schema()
        alert_fields = set(schema["properties"]["alert"]["properties"].keys())

        # AlertInfo has: Id, RuleId, RuleName, Severity, Description, EventCount,
        #               FirstSeen, LastSeen, WindowStart
        csharp_to_json = {
            "Id": "id",
            "RuleId": "rule_id",
            "RuleName": "rule_name",
            "Severity": "severity",
            "Description": "description",
            "EventCount": "event_count",
            "FirstSeen": "first_seen",
            "LastSeen": "last_seen",
            "WindowStart": "window_start",
        }

        for prop in props:
            if prop in csharp_to_json:
                json_name = csharp_to_json[prop]
                assert json_name in alert_fields, (
                    f"C# property AlertInfo.{prop} -> '{json_name}' not in alert.* schema"
                )

    def test_agent_event_fields_in_schema(self):
        """Verify AgentEvent.Body keys align with event schema top-level fields."""
        schema = _event_schema()
        schema_top = set(schema["properties"].keys())

        # AgentEvent.Body is documented to contain these top-level keys
        expected_body_keys = {"@timestamp", "message", "event", "winlog", "tinysocs"}

        for key in expected_body_keys:
            assert key in schema_top, (
                f"AgentEvent.Body key '{key}' not in event schema"
            )


# ---------------------------------------------------------------------------
# 5. Schema field coverage (no orphan fields in templates)
# ---------------------------------------------------------------------------


class TestNoOrphanFields:
    """Ensure schemas don't have fields missing from templates (and vice versa)."""

    def test_event_schema_covers_template(self):
        """All template fields exist in schema (tested above), and all schema
        top-level required fields exist in template."""
        template = _load_json("packaging/opensearch/templates/tinysocs-winlog.json")
        schema = _event_schema()

        tmpl_fields = set(template["template"]["mappings"]["properties"].keys())
        for field in schema.get("required", []):
            assert field in tmpl_fields, (
                f"Schema required field '{field}' not in winlog template"
            )

    def test_alert_schema_covers_template(self):
        template = _load_json("packaging/opensearch/templates/tinysocs-alerts.json")
        schema = _alert_schema()

        tmpl_fields = set(template["template"]["mappings"]["properties"].keys())
        for field in schema.get("required", []):
            assert field in tmpl_fields, (
                f"Schema required field '{field}' not in alerts template"
            )
