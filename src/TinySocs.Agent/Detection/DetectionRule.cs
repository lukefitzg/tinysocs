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
        public MitreInfo? Mitre { get; set; }
    }

    /// <summary>
    /// MITRE ATT&CK mapping for a detection rule.
    /// </summary>
    public sealed class MitreInfo
    {
        public string TechniqueId { get; set; } = string.Empty;
        public string TechniqueName { get; set; } = string.Empty;
        public string Tactic { get; set; } = string.Empty;
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

        // Content-based filter: require a field path to contain one of these substrings (case-insensitive).
        // YAML example:
        //   field_match:
        //     field: "winlog.event_data.NewProcessName"
        //     values: ["rundll32.exe", "regsvr32.exe"]
        public FieldMatchFilter? FieldMatch { get; set; }
    }

    /// <summary>
    /// Content-based filter: matches when the specified field contains one of the values.
    /// </summary>
    public sealed class FieldMatchFilter
    {
        public string Field { get; set; } = string.Empty;
        public List<string> Values { get; set; } = new();
    }

    public sealed class RulesFile
    {
        public List<DetectionRule> Rules { get; set; } = new();
    }
}
