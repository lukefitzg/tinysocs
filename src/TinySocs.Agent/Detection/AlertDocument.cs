using System;
using System.Collections.Generic;

namespace TinySocs.Agent.Detection
{
    /// <summary>
    /// Alert document structure (written to tinysocs-alerts-* index).
    /// </summary>
    public sealed class AlertDocument
    {
        public string Timestamp { get; set; } = string.Empty;
        public AlertInfo Alert { get; set; } = new();
        public Dictionary<string, object?> Source { get; set; } = new();
        public int MatchedEvents { get; set; }
        public MitreAlertInfo? Mitre { get; set; }
    }

    public sealed class MitreAlertInfo
    {
        public string TechniqueId { get; set; } = string.Empty;
        public string TechniqueName { get; set; } = string.Empty;
        public string Tactic { get; set; } = string.Empty;
    }

    public sealed class AlertInfo
    {
        public string Id { get; set; } = string.Empty;          // Deterministic: {rule_id}|{group_key}|{window_start}
        public string RuleId { get; set; } = string.Empty;
        public string RuleName { get; set; } = string.Empty;
        public string Severity { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public int EventCount { get; set; }
        public string? FirstSeen { get; set; }
        public string? LastSeen { get; set; }
        public string WindowStart { get; set; } = string.Empty;
    }
}
