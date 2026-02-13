using System.Collections.Generic;

namespace TinySocs.Agent.Detection
{
    /// <summary>
    /// Detection rule definition (loaded from rules.yml).
    /// </summary>
    public sealed class DetectionRule
    {
        public string Id { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Severity { get; set; } = "medium";  // low/medium/high/critical
        public bool Enabled { get; set; } = true;
        public string Type { get; set; } = string.Empty;  // threshold_by_key, match_single, cardinality
        public RuleCondition Condition { get; set; } = new();
        public List<string> Actions { get; set; } = new();
    }

    public sealed class RuleCondition
    {
        // Common filters
        public int? EventId { get; set; }
        public string? Channel { get; set; }

        // threshold_by_key specific
        public string? GroupBy { get; set; }
        public int Threshold { get; set; }
        public int WindowMinutes { get; set; } = 5;

        // Additional filter fields (extensible)
        public Dictionary<string, object>? Filters { get; set; }
    }

    public sealed class RulesFile
    {
        public List<DetectionRule> Rules { get; set; } = new();
    }
}
