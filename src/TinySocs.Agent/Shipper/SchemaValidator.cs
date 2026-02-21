using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace TinySocs.Agent.Shipper
{
    /// <summary>
    /// Validates event and alert documents against the TinySocs schemas before
    /// they are shipped to OpenSearch.  Uses lightweight hand-coded checks
    /// (no external JSON-Schema library required) that mirror the constraints
    /// defined in schema/event-schema.json and schema/alert-schema.json.
    ///
    /// Phase 13 (M6): Event Schema Formalisation.
    /// </summary>
    public sealed class SchemaValidator
    {
        private readonly ILogger<SchemaValidator> _logger;
        private readonly bool _failFast;

        private int _eventPassCount;
        private int _eventFailCount;
        private int _alertPassCount;
        private int _alertFailCount;

        /// <summary>
        /// Creates a new SchemaValidator.
        /// </summary>
        /// <param name="logger">Logger instance.</param>
        /// <param name="failFast">When true, returns on first error.  When false,
        /// collects all validation errors before returning.</param>
        public SchemaValidator(ILogger<SchemaValidator> logger, bool failFast = false)
        {
            _logger = logger;
            _failFast = failFast;
        }

        // ---------------------------------------------------------------
        //  Public API
        // ---------------------------------------------------------------

        /// <summary>
        /// Validate a single event document (Dictionary&lt;string, object?&gt;
        /// — the <c>AgentEvent.Body</c> payload).
        /// </summary>
        public ValidationResult ValidateEvent(IDictionary<string, object?> body)
        {
            var errors = new List<string>();

            // Required top-level fields
            RequireField(body, "@timestamp", errors);
            RequireField(body, "event", errors);
            RequireField(body, "winlog", errors);

            // @timestamp format
            if (body.TryGetValue("@timestamp", out var tsVal) && tsVal != null)
                ValidateIso8601(tsVal, "@timestamp", errors);

            // message (optional, max 32768)
            if (body.TryGetValue("message", out var msgVal) && msgVal is string msg)
            {
                if (msg.Length > 32768)
                    errors.Add("message: length exceeds 32768.");
            }

            // event object
            if (body.TryGetValue("event", out var evtObj) && evtObj != null)
            {
                var evt = CoerceDict(evtObj);
                if (evt == null) { errors.Add("event: must be an object."); }
                else
                {
                    RequireField(evt, "id", errors, "event.");

                    if (evt.TryGetValue("id", out var eid))
                        ValidateNonNegativeInt(eid, "event.id", errors);
                    if (evt.TryGetValue("code", out var ec))
                        ValidateNonNegativeInt(ec, "event.code", errors);
                    if (evt.TryGetValue("record_id", out var erid))
                        ValidateNonNegativeInt(erid, "event.record_id", errors);
                    if (evt.TryGetValue("level", out var lvl) && lvl is string ls)
                        ValidateEnum(ls, _eventLevels, "event.level", errors);

                    ValidateNoExtra(evt, _eventAllowed, "event", errors);
                }
            }

            // winlog object
            if (body.TryGetValue("winlog", out var wlObj) && wlObj != null)
            {
                var wl = CoerceDict(wlObj);
                if (wl == null) { errors.Add("winlog: must be an object."); }
                else
                {
                    RequireField(wl, "channel", errors, "winlog.");

                    if (wl.TryGetValue("record_id", out var wrid))
                        ValidateNonNegativeInt(wrid, "winlog.record_id", errors);

                    // event_data is allowed to have any keys (additionalProperties: true)
                    // but the winlog object itself is strict
                    ValidateNoExtra(wl, _winlogAllowed, "winlog", errors);
                }
            }

            // tinysocs object (optional)
            if (body.TryGetValue("tinysocs", out var tsObj) && tsObj != null)
            {
                var ts = CoerceDict(tsObj);
                if (ts == null) { errors.Add("tinysocs: must be an object."); }
                else
                    ValidateNoExtra(ts, _tinySocsAllowed, "tinysocs", errors);
            }

            // additionalProperties: false at root
            ValidateNoExtra(body, _rootAllowed, "(root)", errors);

            var ok = errors.Count == 0;
            if (ok) _eventPassCount++; else _eventFailCount++;

            if (!ok)
                _logger.LogDebug("Event validation failed ({Count} error(s)): {Errors}",
                    errors.Count, string.Join("; ", errors));

            return new ValidationResult(ok, errors);
        }

        /// <summary>
        /// Validate an alert document.  Accepts a <c>Dictionary&lt;string, object?&gt;</c>
        /// or the anonymous-type document built by AlertWriter (serialised as JSON first).
        /// </summary>
        public ValidationResult ValidateAlert(IDictionary<string, object?> doc)
        {
            var errors = new List<string>();

            // Required top-level
            RequireField(doc, "timestamp", errors);
            RequireField(doc, "alert", errors);

            if (doc.TryGetValue("timestamp", out var ts) && ts != null)
                ValidateIso8601(ts, "timestamp", errors);

            if (doc.TryGetValue("alert", out var aObj) && aObj != null)
            {
                var a = CoerceDict(aObj);
                if (a == null) { errors.Add("alert: must be an object."); }
                else
                {
                    foreach (var f in _alertRequired)
                        RequireField(a, f, errors, "alert.");

                    // alert.id pattern: .+|.+|.+
                    if (a.TryGetValue("id", out var aid) && aid is string aidStr)
                    {
                        var parts = aidStr.Split('|');
                        if (parts.Length < 3 || parts.Any(string.IsNullOrEmpty))
                            errors.Add("alert.id: must match pattern '{rule_id}|{group_key}|{window_start}'.");
                    }

                    // rule_id / rule_name minLength: 1
                    if (a.TryGetValue("rule_id", out var rid) && rid is string ridStr && ridStr.Length == 0)
                        errors.Add("alert.rule_id: must not be empty.");
                    if (a.TryGetValue("rule_name", out var rn) && rn is string rnStr && rnStr.Length == 0)
                        errors.Add("alert.rule_name: must not be empty.");

                    // severity enum
                    if (a.TryGetValue("severity", out var sev) && sev is string sevStr)
                        ValidateEnum(sevStr, _alertSeverities, "alert.severity", errors);

                    // event_count >= 1
                    if (a.TryGetValue("event_count", out var ec))
                        ValidateMinInt(ec, 1, "alert.event_count", errors);

                    // first_seen / last_seen: string|null
                    if (a.TryGetValue("first_seen", out var fs) && fs != null)
                        ValidateIso8601(fs, "alert.first_seen", errors);
                    if (a.TryGetValue("last_seen", out var ls) && ls != null)
                        ValidateIso8601(ls, "alert.last_seen", errors);
                    if (a.TryGetValue("window_start", out var ws) && ws != null)
                        ValidateIso8601(ws, "alert.window_start", errors);

                    ValidateNoExtra(a, _alertAllowed, "alert", errors);
                }
            }

            // matched_events >= 0
            if (doc.TryGetValue("matched_events", out var me))
                ValidateMinInt(me, 0, "matched_events", errors);

            // source: additionalProperties true, no further validation needed

            ValidateNoExtra(doc, _alertRootAllowed, "(root)", errors);

            var ok = errors.Count == 0;
            if (ok) _alertPassCount++; else _alertFailCount++;

            if (!ok)
                _logger.LogDebug("Alert validation failed ({Count} error(s)): {Errors}",
                    errors.Count, string.Join("; ", errors));

            return new ValidationResult(ok, errors);
        }

        /// <summary>
        /// Log cumulative validation statistics at Info level.
        /// </summary>
        public void LogStats()
        {
            _logger.LogInformation(
                "SchemaValidator stats: events={EventPass} pass / {EventFail} fail, alerts={AlertPass} pass / {AlertFail} fail",
                _eventPassCount, _eventFailCount, _alertPassCount, _alertFailCount);
        }

        // ---------------------------------------------------------------
        //  Allowed-field sets
        // ---------------------------------------------------------------

        private static readonly HashSet<string> _rootAllowed = new(StringComparer.Ordinal)
        {
            "@timestamp", "message", "event", "winlog", "tinysocs"
        };

        private static readonly HashSet<string> _eventAllowed = new(StringComparer.Ordinal)
        {
            "id", "code", "level", "provider", "record_id"
        };

        private static readonly HashSet<string> _winlogAllowed = new(StringComparer.Ordinal)
        {
            "channel", "computer_name", "event_id", "provider_name", "record_id", "event_data"
        };

        private static readonly HashSet<string> _tinySocsAllowed = new(StringComparer.Ordinal)
        {
            "input_name", "node_id"
        };

        private static readonly HashSet<string> _alertRootAllowed = new(StringComparer.Ordinal)
        {
            "timestamp", "alert", "source", "matched_events"
        };

        private static readonly HashSet<string> _alertAllowed = new(StringComparer.Ordinal)
        {
            "id", "rule_id", "rule_name", "severity", "description",
            "event_count", "first_seen", "last_seen", "window_start"
        };

        private static readonly string[] _alertRequired = new[]
        {
            "id", "rule_id", "rule_name", "severity", "description", "event_count"
        };

        private static readonly HashSet<string> _eventLevels = new(StringComparer.Ordinal)
        {
            "Critical", "Error", "Warning", "Information", "Verbose"
        };

        private static readonly HashSet<string> _alertSeverities = new(StringComparer.Ordinal)
        {
            "low", "medium", "high", "critical"
        };

        // ---------------------------------------------------------------
        //  Helpers
        // ---------------------------------------------------------------

        private void RequireField(IDictionary<string, object?> dict, string key,
            List<string> errors, string prefix = "")
        {
            if (!dict.ContainsKey(key))
            {
                errors.Add($"{prefix}{key}: required field is missing.");
                if (_failFast) return;
            }
        }

        private void ValidateIso8601(object? value, string path, List<string> errors)
        {
            var s = value?.ToString();
            if (string.IsNullOrEmpty(s))
            {
                errors.Add($"{path}: timestamp must not be empty.");
                return;
            }

            if (!DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture,
                    DateTimeStyles.RoundtripKind, out _))
            {
                errors.Add($"{path}: not a valid ISO 8601 date-time (got '{s}').");
            }
        }

        private static void ValidateNonNegativeInt(object? value, string path, List<string> errors)
        {
            var n = CoerceInt(value);
            if (n == null) { errors.Add($"{path}: must be a non-negative integer."); return; }
            if (n < 0) errors.Add($"{path}: must be >= 0 (got {n}).");
        }

        private static void ValidateMinInt(object? value, int min, string path, List<string> errors)
        {
            var n = CoerceInt(value);
            if (n == null) { errors.Add($"{path}: must be an integer."); return; }
            if (n < min) errors.Add($"{path}: must be >= {min} (got {n}).");
        }

        private static void ValidateEnum(string value, HashSet<string> allowed, string path, List<string> errors)
        {
            if (!allowed.Contains(value))
                errors.Add($"{path}: invalid value '{value}'. Allowed: [{string.Join(", ", allowed)}].");
        }

        private static void ValidateNoExtra(IDictionary<string, object?> dict,
            HashSet<string> allowed, string section, List<string> errors)
        {
            foreach (var key in dict.Keys)
            {
                if (!allowed.Contains(key))
                    errors.Add($"{section}: unexpected field '{key}'.");
            }
        }

        /// <summary>
        /// Try to view an object as a string-keyed dictionary.  Handles
        /// Dictionary&lt;string, object?&gt;, JsonElement (from deserialization),
        /// and similar types.
        /// </summary>
        private static IDictionary<string, object?>? CoerceDict(object? value)
        {
            if (value is IDictionary<string, object?> d) return d;
            if (value is Dictionary<string, object> d2) return d2.ToDictionary(kv => kv.Key, kv => (object?)kv.Value);

            // Handle System.Text.Json's JsonElement
            if (value is JsonElement je && je.ValueKind == JsonValueKind.Object)
            {
                var dict = new Dictionary<string, object?>();
                foreach (var prop in je.EnumerateObject())
                    dict[prop.Name] = JsonElementToObject(prop.Value);
                return dict;
            }

            return null;
        }

        private static long? CoerceInt(object? value)
        {
            if (value is int i) return i;
            if (value is long l) return l;
            if (value is short s) return s;
            if (value is byte b) return b;
            if (value is double dbl && dbl == Math.Floor(dbl)) return (long)dbl;
            if (value is float f && f == MathF.Floor(f)) return (long)f;
            if (value is decimal m && m == Math.Floor(m)) return (long)m;

            if (value is JsonElement je)
            {
                if (je.ValueKind == JsonValueKind.Number && je.TryGetInt64(out var jl)) return jl;
            }

            if (value is string str && long.TryParse(str, out var parsed)) return parsed;
            return null;
        }

        private static object? JsonElementToObject(JsonElement el)
        {
            return el.ValueKind switch
            {
                JsonValueKind.Object => el.EnumerateObject()
                    .ToDictionary(p => p.Name, p => JsonElementToObject(p.Value)) as object,
                JsonValueKind.Array => el.EnumerateArray()
                    .Select(JsonElementToObject).ToList() as object,
                JsonValueKind.String => el.GetString(),
                JsonValueKind.Number => el.TryGetInt64(out var l) ? l : (object)el.GetDouble(),
                JsonValueKind.True => true,
                JsonValueKind.False => false,
                _ => null
            };
        }
    }

    /// <summary>
    /// Result of a schema validation check.
    /// </summary>
    public sealed class ValidationResult
    {
        public bool IsValid { get; }
        public IReadOnlyList<string> Errors { get; }

        public ValidationResult(bool isValid, IReadOnlyList<string>? errors = null)
        {
            IsValid = isValid;
            Errors = errors ?? Array.Empty<string>();
        }

        public override string ToString()
            => IsValid ? "VALID" : $"INVALID ({Errors.Count} error(s)): {string.Join("; ", Errors)}";
    }
}
