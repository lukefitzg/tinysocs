using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TinySocs.Agent.Configuration;
using TinySocs.Agent.Models;

namespace TinySocs.Agent.Shipper
{
    /// <summary>
    /// v1 queue reader:
    /// - Reads oldest segment file line by line
    /// - Parses AgentEvent JSON
    /// - Does not delete files yet (Acknowledge will be wired later)
    /// </summary>
    public sealed class FileQueueReader : IQueueReader
    {
        private readonly ILogger<FileQueueReader> _logger;
        private readonly AgentConfig _config;

        private static readonly JsonSerializerOptions _jsonOptions = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        };

        public FileQueueReader(
            ILogger<FileQueueReader> logger,
            AgentConfig config)
        {
            _logger = logger;
            _config = config;
        }

        public Task<IReadOnlyList<AgentEvent>> ReadBatchAsync(
            int maxEvents,
            int maxBytes,
            CancellationToken cancellationToken)
        {
            var results = new List<AgentEvent>();
            var dir = _config.Queue.Path;

            if (!Directory.Exists(dir))
                return Task.FromResult((IReadOnlyList<AgentEvent>)results);

            var segments = Directory.GetFiles(dir, "segment-*.jsonl");
            Array.Sort(segments, StringComparer.Ordinal); // oldest first

            if (segments.Length == 0)
                return Task.FromResult((IReadOnlyList<AgentEvent>)results);

            var path = segments[0];

            try
            {
                // Open with FileShare.ReadWrite so the writer can keep appending
                var fs = new FileStream(
                    path,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.ReadWrite
                );

                using var reader = new StreamReader(fs);

                int count = 0;
                int totalBytes = 0;

                while (!reader.EndOfStream)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    if (count >= maxEvents || totalBytes >= maxBytes)
                        break;

                    var line = reader.ReadLine();
                    if (string.IsNullOrWhiteSpace(line))
                        continue;

                    try
                    {
                        var evt = ParseAgentEvent(line);
                        if (evt != null)
                        {
                            results.Add(evt);
                            count++;
                            totalBytes += line.Length; // rough; fine for v1
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to parse event from line in {Path}", path);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error reading queue segment {Path}", path);
            }

            return Task.FromResult((IReadOnlyList<AgentEvent>)results);
        }

        private static AgentEvent? ParseAgentEvent(string line)
        {
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;

            // ts: stored as ISO8601 string in the queue; fall back to now on parse failure.
            DateTimeOffset ts;
            if (root.TryGetProperty("ts", out var tsProp) && tsProp.ValueKind == JsonValueKind.String)
            {
                var tsString = tsProp.GetString();
                if (!DateTimeOffset.TryParse(tsString, out ts))
                {
                    ts = DateTimeOffset.UtcNow;
                }
            }
            else
            {
                ts = DateTimeOffset.UtcNow;
            }

            // Basic primitives
            string input = root.TryGetProperty("input", out var inputProp) && inputProp.ValueKind == JsonValueKind.String
                ? (inputProp.GetString() ?? string.Empty)
                : string.Empty;

            string channel = root.TryGetProperty("channel", out var chProp) && chProp.ValueKind == JsonValueKind.String
                ? (chProp.GetString() ?? string.Empty)
                : string.Empty;

            int? eventId = null;
            if (root.TryGetProperty("eventId", out var evtIdProp) &&
                evtIdProp.ValueKind == JsonValueKind.Number &&
                evtIdProp.TryGetInt32(out var tmpId))
            {
                eventId = tmpId;
            }

            string openSearchIndex = root.TryGetProperty("openSearchIndex", out var idxProp) && idxProp.ValueKind == JsonValueKind.String
                ? (idxProp.GetString() ?? string.Empty)
                : string.Empty;

            // Body: deserialize into a dictionary so the shipper can flatten/forward it as-is.
            Dictionary<string, object?> body = new Dictionary<string, object?>();
            if (root.TryGetProperty("body", out var bodyProp) &&
                bodyProp.ValueKind != JsonValueKind.Null &&
                bodyProp.ValueKind != JsonValueKind.Undefined)
            {
                var raw = bodyProp.GetRawText();
                var parsed = JsonSerializer.Deserialize<Dictionary<string, object?>>(raw, _jsonOptions);
                if (parsed != null)
                {
                    body = parsed;
                }
            }

            return new AgentEvent
            {
                Ts = ts,
                Input = input,
                Channel = channel,
                EventId = eventId,
                OpenSearchIndex = openSearchIndex,
                Body = body
            };
        }

        public Task AcknowledgeAsync(int count, CancellationToken cancellationToken)
        {
            // v1: no-op. Later:
            // - track per-segment offsets
            // - delete segment once fully acknowledged
            return Task.CompletedTask;
        }
    }
}