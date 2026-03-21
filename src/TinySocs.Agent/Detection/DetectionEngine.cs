using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using TinySocs.Agent.Models;

namespace TinySocs.Agent.Detection
{
    /// <summary>
    /// Detection engine that evaluates events against loaded rules.
    /// Maintains in-memory state for threshold_by_key rules (sliding windows).
    /// </summary>
    public sealed class DetectionEngine
    {
        private readonly ILogger<DetectionEngine> _logger;
        private volatile List<DetectionRule> _rules;

        // Lock protects all mutable state (_windows, _lastAlertTime, pruning counters).
        // The engine may be called from concurrent event processing pipelines.
        private readonly object _stateLock = new object();

        // In-memory sliding windows: ruleId -> groupKey -> list of event timestamps
        private readonly Dictionary<string, Dictionary<string, List<EventOccurrence>>> _windows;

        // Cooldown tracking: "{ruleId}|{groupKey}" -> last alert fire time
        private readonly Dictionary<string, DateTime> _lastAlertTime;

        // Pruning: track last prune pass to avoid pruning every single event
        private DateTime _lastPruneTime;
        private int _evaluationsSincePrune;
        private const int PruneEveryNEvaluations = 500;

        public DetectionEngine(ILogger<DetectionEngine> logger)
        {
            _logger = logger;
            _rules = new List<DetectionRule>();
            _windows = new Dictionary<string, Dictionary<string, List<EventOccurrence>>>();
            _lastAlertTime = new Dictionary<string, DateTime>();
            _lastPruneTime = DateTime.UtcNow;
            _evaluationsSincePrune = 0;
        }

        public void UpdateRules(List<DetectionRule> rules)
        {
            _rules = rules;
            _logger.LogInformation("Detection engine updated with {Count} rule(s).", rules.Count);
        }

        /// <summary>
        /// Evaluate a single event against all enabled rules.
        /// Returns list of alerts that should be fired.
        /// </summary>
        public List<AlertDocument> EvaluateEvent(AgentEvent evt)
        {
            var alerts = new List<AlertDocument>();

            lock (_stateLock)
            {
                // Periodic window pruning to prevent unbounded memory growth
                _evaluationsSincePrune++;
                if (_evaluationsSincePrune >= PruneEveryNEvaluations)
                {
                    PruneExpiredWindows();
                    _evaluationsSincePrune = 0;
                }

                foreach (var rule in _rules)
                {
                    if (!rule.Enabled)
                    {
                        continue;
                    }

                    if (rule.Type == "threshold_by_key")
                    {
                        var alert = EvaluateThresholdByKey(rule, evt);
                        if (alert != null)
                        {
                            alerts.Add(alert);
                        }
                    }
                    // Future: add other rule types (match_single, cardinality, etc.)
                }
            }

            return alerts;
        }

        /// <summary>
        /// Prune expired windows across all rules to prevent unbounded memory growth.
        /// Removes event occurrences older than each rule's window_minutes.
        /// Removes empty group keys and rule entries entirely.
        /// </summary>
        private void PruneExpiredWindows()
        {
            var now = DateTime.UtcNow;
            int totalPruned = 0;
            int keysRemoved = 0;

            // Build a lookup of rule window durations for fast access
            var ruleWindowMinutes = new Dictionary<string, int>();
            foreach (var rule in _rules)
            {
                ruleWindowMinutes[rule.Id] = rule.Condition.WindowMinutes;
            }

            var emptyRuleIds = new List<string>();

            foreach (var ruleEntry in _windows)
            {
                var ruleId = ruleEntry.Key;
                var groupWindows = ruleEntry.Value;

                // Use the rule's configured window, or default to 10 minutes for unknown rules
                var windowMinutes = ruleWindowMinutes.ContainsKey(ruleId) ? ruleWindowMinutes[ruleId] : 10;
                var cutoff = now.AddMinutes(-windowMinutes);

                var emptyKeys = new List<string>();

                foreach (var groupEntry in groupWindows)
                {
                    var occurrences = groupEntry.Value;
                    var before = occurrences.Count;
                    occurrences.RemoveAll(e => e.Timestamp < cutoff);
                    totalPruned += before - occurrences.Count;

                    if (occurrences.Count == 0)
                    {
                        emptyKeys.Add(groupEntry.Key);
                    }
                }

                foreach (var key in emptyKeys)
                {
                    groupWindows.Remove(key);
                    keysRemoved++;
                }

                if (groupWindows.Count == 0)
                {
                    emptyRuleIds.Add(ruleId);
                }
            }

            foreach (var ruleId in emptyRuleIds)
            {
                _windows.Remove(ruleId);
            }

            // Log periodically for observability
            var totalWindows = 0;
            foreach (var ruleEntry in _windows)
            {
                totalWindows += ruleEntry.Value.Count;
            }

            // Prune stale cooldown entries (older than 2x the longest effective cooldown)
            var maxCooldownMinutes = 60;
            foreach (var rule in _rules)
            {
                var cd = rule.Condition.CooldownMinutes > 0
                    ? rule.Condition.CooldownMinutes
                    : rule.Condition.WindowMinutes;
                if (cd > maxCooldownMinutes) maxCooldownMinutes = cd;
            }
            var cooldownCutoff = now.AddMinutes(-maxCooldownMinutes * 2);
            var staleCooldownKeys = new List<string>();
            foreach (var entry in _lastAlertTime)
            {
                if (entry.Value < cooldownCutoff)
                {
                    staleCooldownKeys.Add(entry.Key);
                }
            }
            foreach (var key in staleCooldownKeys)
            {
                _lastAlertTime.Remove(key);
            }

            _logger.LogDebug(
                "Window prune: removed {Pruned} expired events, {KeysRemoved} empty keys. Active windows: {WindowCount} across {RuleCount} rules. Cooldown entries: {CooldownCount}.",
                totalPruned, keysRemoved, totalWindows, _windows.Count, _lastAlertTime.Count);

            _lastPruneTime = now;
        }

        private AlertDocument? EvaluateThresholdByKey(DetectionRule rule, AgentEvent evt)
        {
            // Check if event matches rule conditions
            if (!EventMatchesCondition(rule.Condition, evt))
            {
                return null;
            }

            var groupKey = ExtractGroupKey(rule.Condition.GroupBy, evt);
            if (string.IsNullOrWhiteSpace(groupKey))
            {
                // Fallback: use computer_name as group key when the configured
                // group_by field is missing from the event. This prevents silently
                // dropping threshold-1 events where the field path doesn't resolve
                // (e.g. after queue serialization or unusual event structures).
                groupKey = ExtractGroupKey("winlog.computer_name", evt);
                if (string.IsNullOrWhiteSpace(groupKey))
                {
                    return null;
                }
                _logger.LogDebug(
                    "Rule {RuleId}: group_by field '{GroupBy}' not found in event {EventId}; falling back to computer_name '{Key}'.",
                    rule.Id, rule.Condition.GroupBy, evt.EventId, groupKey);
            }

            var now = DateTime.UtcNow;
            var windowMinutes = rule.Condition.WindowMinutes;

            // Get or create window for this rule
            if (!_windows.ContainsKey(rule.Id))
            {
                _windows[rule.Id] = new Dictionary<string, List<EventOccurrence>>();
            }

            if (!_windows[rule.Id].ContainsKey(groupKey))
            {
                _windows[rule.Id][groupKey] = new List<EventOccurrence>();
            }

            var window = _windows[rule.Id][groupKey];

            // Add current event to window
            window.Add(new EventOccurrence
            {
                Timestamp = evt.Ts.UtcDateTime,
                Event = evt
            });

            // For threshold == 1, fire immediately on any matching event.
            // No window pruning needed — a single occurrence is sufficient.
            // This avoids false negatives when events are processed with delay
            // (e.g. after queue backlog or shipper retries).
            if (rule.Condition.Threshold <= 1)
            {
                // Skip window cleanup — go straight to threshold check below
            }
            else
            {
                // Clean up old events outside the window
                var cutoff = now.AddMinutes(-windowMinutes);
                window.RemoveAll(e => e.Timestamp < cutoff);
            }

            // Check if threshold is met
            if (window.Count >= rule.Condition.Threshold)
            {
                // Cooldown check: suppress re-firing for the same rule+key
                var cooldownKey = $"{rule.Id}|{groupKey}";
                var effectiveCooldown = rule.Condition.CooldownMinutes > 0
                    ? rule.Condition.CooldownMinutes
                    : rule.Condition.WindowMinutes;

                if (_lastAlertTime.TryGetValue(cooldownKey, out var lastFire))
                {
                    var elapsed = (now - lastFire).TotalMinutes;
                    if (elapsed < effectiveCooldown)
                    {
                        // Still in cooldown — suppress alert but clear the window
                        window.Clear();
                        _logger.LogDebug(
                            "Rule {RuleId} suppressed for {GroupKey}: cooldown {Remaining:F1}min remaining ({Cooldown}min total)",
                            rule.Id, groupKey, effectiveCooldown - elapsed, effectiveCooldown);
                        return null;
                    }
                }

                // Record fire time for cooldown tracking
                _lastAlertTime[cooldownKey] = now;

                // Threshold met! Fire alert
                var firstSeen = window.Min(e => e.Timestamp);
                var lastSeen = window.Max(e => e.Timestamp);
                var windowStart = RoundDownToMinute(firstSeen);

                // Build deterministic alert ID
                var alertId = $"{rule.Id}|{groupKey}|{windowStart:yyyy-MM-ddTHH:mm:00Z}";

                // Extract source information from the event
                var source = ExtractSourceInfo(evt, rule.Condition.GroupBy, groupKey);

                var alert = new AlertDocument
                {
                    Timestamp = now.ToString("o"),
                    Alert = new AlertInfo
                    {
                        Id = alertId,
                        RuleId = rule.Id,
                        RuleName = rule.Name,
                        Severity = rule.Severity,
                        Description = $"{window.Count} {GetEventDescription(rule)} for {GetGroupByLabel(rule.Condition.GroupBy)} '{groupKey}' in {windowMinutes} minutes",
                        EventCount = window.Count,
                        FirstSeen = firstSeen.ToString("o"),
                        LastSeen = lastSeen.ToString("o"),
                        WindowStart = windowStart.ToString("o")
                    },
                    Source = source,
                    MatchedEvents = window.Count,
                    Mitre = rule.Mitre != null ? new MitreAlertInfo
                    {
                        TechniqueId = rule.Mitre.TechniqueId,
                        TechniqueName = rule.Mitre.TechniqueName,
                        Tactic = rule.Mitre.Tactic
                    } : null
                };

                // Clear the window so we don't fire duplicate alerts
                window.Clear();

                _logger.LogInformation(
                    "Alert fired: {RuleId} ({RuleName}) - {EventCount} events for {GroupKey}",
                    rule.Id,
                    rule.Name,
                    alert.Alert.EventCount,
                    groupKey);

                return alert;
            }

            return null;
        }

        private bool EventMatchesCondition(RuleCondition condition, AgentEvent evt)
        {
            // Check event ID
            if (condition.EventId.HasValue && evt.EventId != condition.EventId.Value)
            {
                return false;
            }

            // Check channel
            if (!string.IsNullOrWhiteSpace(condition.Channel) &&
                !string.Equals(evt.Channel, condition.Channel, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            // Content-based field_match filter
            if (condition.FieldMatch != null &&
                !string.IsNullOrWhiteSpace(condition.FieldMatch.Field) &&
                condition.FieldMatch.Values?.Count > 0)
            {
                var fieldValue = ExtractGroupKey(condition.FieldMatch.Field, evt);
                if (string.IsNullOrWhiteSpace(fieldValue))
                {
                    return false;
                }

                bool anyMatch = false;
                foreach (var pattern in condition.FieldMatch.Values)
                {
                    if (fieldValue.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        anyMatch = true;
                        break;
                    }
                }

                if (!anyMatch)
                {
                    return false;
                }
            }

            return true;
        }

        private string? ExtractGroupKey(string? groupByField, AgentEvent evt)
        {
            if (string.IsNullOrWhiteSpace(groupByField))
            {
                return null;
            }

            // Support nested field paths like "winlog.event_data.TargetUserName"
            var parts = groupByField.Split('.');
            object? current = evt.Body;

            foreach (var part in parts)
            {
                if (current is Dictionary<string, object?> dict)
                {
                    if (dict.TryGetValue(part, out var next))
                    {
                        current = next;
                    }
                    else
                    {
                        return null;
                    }
                }
                else if (current is JsonElement je && je.ValueKind == JsonValueKind.Object)
                {
                    // After queue round-trip, nested objects are JsonElement, not Dictionary
                    if (je.TryGetProperty(part, out var child))
                    {
                        current = child;
                    }
                    else
                    {
                        return null;
                    }
                }
                else
                {
                    return null;
                }
            }

            // Resolve final value
            if (current is JsonElement finalJe)
            {
                return finalJe.ValueKind == JsonValueKind.String
                    ? finalJe.GetString()
                    : finalJe.ToString();
            }

            return current?.ToString();
        }

        private Dictionary<string, object?> ExtractSourceInfo(AgentEvent evt, string? groupByField, string groupKey)
        {
            var source = new Dictionary<string, object?>();

            // Add the group key field
            if (!string.IsNullOrWhiteSpace(groupByField))
            {
                var label = GetGroupByLabel(groupByField);
                source[label] = groupKey;
            }

            // Add computer name
            if (evt.Body != null && evt.Body.TryGetValue("winlog", out var winlogObj) && winlogObj is Dictionary<string, object?> winlog)
            {
                if (winlog.TryGetValue("computer_name", out var computerName))
                {
                    source["computer_name"] = computerName;
                }

                // Try to extract additional useful fields from event_data
                if (winlog.TryGetValue("event_data", out var eventDataObj) && eventDataObj is Dictionary<string, object?> eventData)
                {
                    // Add WorkstationName if present
                    if (eventData.TryGetValue("WorkstationName", out var workstation))
                    {
                        source["workstation"] = workstation;
                    }

                    // Add IpAddress if present
                    if (eventData.TryGetValue("IpAddress", out var ipAddress))
                    {
                        source["ip_address"] = ipAddress;
                    }
                }
            }

            return source;
        }

        private string GetGroupByLabel(string? groupByField)
        {
            if (string.IsNullOrWhiteSpace(groupByField))
            {
                return "key";
            }

            // Extract the last part of the path (e.g., "TargetUserName" from "winlog.event_data.TargetUserName")
            var parts = groupByField.Split('.');
            return parts.Length > 0 ? parts[parts.Length - 1] : groupByField;
        }

        private string GetEventDescription(DetectionRule rule)
        {
            if (rule.Condition.EventId == 4625)
            {
                return "failed logons";
            }

            return "events";
        }

        private DateTime RoundDownToMinute(DateTime dt)
        {
            return new DateTime(dt.Year, dt.Month, dt.Day, dt.Hour, dt.Minute, 0, DateTimeKind.Utc);
        }

        private sealed class EventOccurrence
        {
            public DateTime Timestamp { get; set; }
            public AgentEvent Event { get; set; } = null!;
        }
    }
}
