using System;
using System.Collections.Generic;
using System.Linq;
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

        public DetectionEngine(ILogger<DetectionEngine> logger)
        {
            _logger = logger;
            _rules = new List<DetectionRule>();
            _windows = new Dictionary<string, Dictionary<string, List<EventOccurrence>>>();
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
                // Cannot group without a key
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
                    MatchedEvents = window.Count
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
                else
                {
                    return null;
                }
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
