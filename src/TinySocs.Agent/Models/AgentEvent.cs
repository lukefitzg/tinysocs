using System;
using System.Collections.Generic;

namespace TinySocs.Agent.Models
{
    /// <summary>
    /// Normalized event envelope that the agent writes to the queue.
    /// One instance corresponds to one JSONL line.
    /// </summary>
    public sealed class AgentEvent
    {
        /// <summary>UTC timestamp of the event as seen by the agent.</summary>
        public DateTimeOffset Ts { get; set; }

        /// <summary>Logical input name (e.g. "win-events").</summary>
        public string Input { get; set; } = string.Empty;

        /// <summary>Source channel (e.g. "Security", "Microsoft-Windows-Sysmon/Operational").</summary>
        public string Channel { get; set; } = string.Empty;

        /// <summary>Numeric event id if applicable (e.g. 4624 for Security logon).</summary>
        public int? EventId { get; set; }

        /// <summary>Index name to route this event to in OpenSearch.</summary>
        public string OpenSearchIndex { get; set; } = string.Empty;

        /// <summary>
        /// Fully normalized event body that will go into _source.
        /// Typically a nested dictionary structure.
        /// </summary>
        public Dictionary<string, object?> Body { get; set; } = new();
    }
}