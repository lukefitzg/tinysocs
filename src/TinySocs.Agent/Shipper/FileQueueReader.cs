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
                using var reader = new StreamReader(path);

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
                        var evt = JsonSerializer.Deserialize<AgentEvent>(line);
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

        public Task AcknowledgeAsync(int count, CancellationToken cancellationToken)
        {
            // v1: no-op. Later:
            // - track per-segment offsets
            // - delete segment once fully acknowledged
            return Task.CompletedTask;
        }
    }
}