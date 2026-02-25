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
        private List<DetectionRule> _rules;

        // In-memory sliding windows: ruleId -> groupKey -> list of event timestamps
        private readonly Dictionary<string, Dictionary<string, List<EventOccurrence>>> _windows;

        // Pruning: track last prune pass to avoid pruning every single event
        private DateTime _lastPruneTime;
        private int _evaluationsSincePrune;
        private const int PruneEveryNEvaluations = 500;

        public DetectionEngine(ILogger<DetectionEngine> logger)
        {
            _logger = logger;
            _rules = new List<DetectionRule>();
            _windows = new Dictionary<string, Dictionary<string, List<EventOccurrence>>>();
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

            _logger.LogDebug(
                "Window prune: removed {Pruned} expired events, {KeysRemoved} empty keys. Active windows: {WindowCount} across {RuleCount} rules.",
                totalPruned, keysRemoved, totalWindows, _windows.Count);

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
                return null;
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

            // Clean up old events outside the window
            var cutoff = now.AddMinutes(-windowMinutes);
            window.RemoveAll(e => e.Timestamp < cutoff);

            // Check if threshold is met
            if (window.Count >= rule.Condition.Threshold)
            {
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

            // Future: add more filter checks from condition.Filters

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
