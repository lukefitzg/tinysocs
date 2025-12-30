using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TinySocs.Agent.Configuration;
using TinySocs.Agent.Models;
using TinySocs.Agent.Queueing;

namespace TinySocs.Agent.Inputs
{
    /// <summary>
    /// Windows Event Log input.
    /// - Only runs on Windows.
    /// - Subscribes to the configured channels in agent-config.yml
    ///   and pushes basic winlog-style events into the queue.
    ///
    /// Patch notes:
    /// - Honour per-channel start_from: now | beginning
    /// - Tail-prime (now) by setting lastSeen to current newest record_id and emitting nothing.
    /// - Read newest->older on subsequent passes and break once <= lastSeen.
    /// - Emit in chronological order (oldest->newest) within each batch.
    /// </summary>
    public sealed class EventLogInput : IInput
    {
        private readonly ILogger<EventLogInput> _logger;
        private readonly AgentConfig _config;
        private readonly IQueueWriter _queueWriter;
        private readonly HashSet<string> _missingChannels = new(StringComparer.OrdinalIgnoreCase);

        // Track last seen EventRecordID per channel so we don't re-read the same
        // events on every polling iteration. This is an in-memory bookmark only
        // (resets on agent restart).
        private readonly Dictionary<string, long?> _lastRecordIds = new(StringComparer.OrdinalIgnoreCase);

        public EventLogInput(
            ILogger<EventLogInput> logger,
            AgentConfig config,
            IQueueWriter queueWriter)
        {
            _logger = logger;
            _config = config;
            _queueWriter = queueWriter;
        }

        public Task RunAsync(CancellationToken stoppingToken)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                _logger.LogWarning(
                    "EventLogInput cannot run on non-Windows platform. Current OS: {OSDescription}",
                    RuntimeInformation.OSDescription);

                throw new PlatformNotSupportedException(
                    "EventLogInput requires Windows (Event Log / wevtapi).");
            }

            _logger.LogInformation("EventLogInput starting on Windows.");

            // Run the synchronous loop on a background thread so that we can
            // honour the CancellationToken.
            return Task.Run(() => RunOnWindows(stoppingToken), stoppingToken);
        }

        private void RunOnWindows(CancellationToken stoppingToken)
        {
            if (_config.Inputs == null || _config.Inputs.Count == 0)
            {
                _logger.LogInformation("No inputs configured – EventLogInput will not subscribe to any channels.");
                return;
            }

            // Find the first eventlog-type input; later you might support multiple.
            var evInput = _config.Inputs.Find(i => string.Equals(i.Type, "eventlog", StringComparison.OrdinalIgnoreCase));
            if (evInput == null)
            {
                _logger.LogInformation("No eventlog input found in configuration – EventLogInput exiting.");
                return;
            }

            if (evInput.Channels == null || evInput.Channels.Count == 0)
            {
                _logger.LogInformation("EventLog input has no channels configured – nothing to read.");
                return;
            }

            _logger.LogInformation("EventLogInput will poll {ChannelCount} channel(s).", evInput.Channels.Count);

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    foreach (var ch in evInput.Channels)
                    {
                        var channelName = ch.Name;
                        if (string.IsNullOrWhiteSpace(channelName))
                        {
                            continue;
                        }

                        if (_missingChannels.Contains(channelName))
                        {
                            // Channel was previously marked as missing; skip it for the rest of this run.
                            continue;
                        }

                        try
                        {
                            long? lastSeen;
                            lock (_lastRecordIds)
                            {
                                _lastRecordIds.TryGetValue(channelName, out lastSeen);
                            }

                            //
                            // FIRST PASS FOR THIS CHANNEL: honour start_from.
                            //
                            if (lastSeen == null)
                            {
                                var startFrom = (ch.StartFrom ?? "now").Trim().ToLowerInvariant();

                                if (startFrom == "beginning")
                                {
                                    // Ingest full history from record_id 0 upwards.
                                    lock (_lastRecordIds)
                                    {
                                        _lastRecordIds[channelName] = 0;
                                    }

                                    _logger.LogInformation(
                                        "Channel {Channel} configured start_from=beginning; initial record_id set to 0.",
                                        channelName);

                                    // Continue to normal read path in the same iteration.
                                    lastSeen = 0;
                                }
                                else
                                {
                                    // Default (and "now"): prime at current tail – discover newest record_id
                                    // but do not emit historical events.
                                    var primeQuery = new EventLogQuery(channelName, PathType.LogName)
                                    {
                                        ReverseDirection = true // newest -> older
                                    };

                                    long primedRecordId = 0;

                                    using (var primeReader = new EventLogReader(primeQuery))
                                    {
                                        EventRecord? first = null;
                                        try
                                        {
                                            first = primeReader.ReadEvent();
                                            if (first != null)
                                            {
                                                try
                                                {
                                                    primedRecordId = first.RecordId ?? 0;
                                                }
                                                catch
                                                {
                                                    primedRecordId = 0;
                                                }
                                            }
                                        }
                                        finally
                                        {
                                            first?.Dispose();
                                        }
                                    }

                                    lock (_lastRecordIds)
                                    {
                                        _lastRecordIds[channelName] = primedRecordId;
                                    }

                                    _logger.LogInformation(
                                        "Primed EventLog channel {Channel} at record_id {RecordId} (start_from={StartFrom}).",
                                        channelName,
                                        primedRecordId,
                                        startFrom);

                                    // Do NOT emit anything on the priming pass.
                                    continue;
                                }
                            }

                            //
                            // SUBSEQUENT PASSES: read newest->older and stop once we hit lastSeen.
                            //
                            var query = new EventLogQuery(channelName, PathType.LogName)
                            {
                                ReverseDirection = true // newest -> older
                            };

                            using (var logReader = new EventLogReader(query))
                            {
                                var newEvents = new List<(AgentEvent Ev, long RecordId)>();
                                var currentLastSeen = lastSeen ?? 0;
                                int readCount = 0;
                                EventRecord? record;

                                while (!stoppingToken.IsCancellationRequested &&
                                       readCount < 200 &&
                                       (record = logReader.ReadEvent()) != null)
                                {
                                    using (record)
                                    {
                                        long? recordId = null;
                                        try
                                        {
                                            recordId = record.RecordId;
                                        }
                                        catch
                                        {
                                            recordId = null;
                                        }

                                        if (!recordId.HasValue)
                                        {
                                            continue;
                                        }

                                        // Because we're reading newest->older, as soon as we hit
                                        // a record_id we've already seen (or older), we can stop.
                                        if (recordId.Value <= currentLastSeen)
                                        {
                                            break;
                                        }

                                        var ev = MapRecordToAgentEvent(evInput.Name ?? "win-events", channelName, record);
                                        newEvents.Add((ev, recordId.Value));
                                        readCount++;
                                    }
                                }

                                if (newEvents.Count > 0)
                                {
                                    // We collected events newest->older; emit oldest->newest for nicer ordering.
                                    newEvents.Sort((a, b) => a.RecordId.CompareTo(b.RecordId));

                                    long maxRecordId = currentLastSeen;
                                    foreach (var (ev, recordId) in newEvents)
                                    {
                                        WriteToQueue(_queueWriter, ev, stoppingToken);
                                        if (recordId > maxRecordId)
                                        {
                                            maxRecordId = recordId;
                                        }
                                    }

                                    lock (_lastRecordIds)
                                    {
                                        _lastRecordIds[channelName] = maxRecordId;
                                    }

                                    _logger.LogDebug(
                                        "Read {Count} new event(s) from channel {Channel}. Advanced record_id from {Old} to {New}.",
                                        newEvents.Count,
                                        channelName,
                                        currentLastSeen,
                                        maxRecordId);
                                }
                            }
                        }
                        catch (EventLogNotFoundException ex)
                        {
                            if (_missingChannels.Add(channelName))
                            {
                                _logger.LogWarning(
                                    ex,
                                    "Windows Event Log channel {Channel} not found. It will be skipped for the remainder of this run.",
                                    channelName);
                            }
                            else
                            {
                                _logger.LogDebug(
                                    ex,
                                    "Windows Event Log channel {Channel} is still not found; continuing to skip.",
                                    channelName);
                            }

                            continue;
                        }
                        catch (Exception ex)
                        {
                            _logger.LogError(ex, "Error while reading Windows Event Log channel {Channel}.", channelName);
                        }
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "EventLogInput outer loop error. Will sleep briefly and retry.");
                }

                try
                {
                    Task.Delay(TimeSpan.FromSeconds(2), stoppingToken).Wait(stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }

            _logger.LogInformation("EventLogInput stopping (cancellation requested).");
        }

        /// <summary>
        /// Small shim so EventLogInput doesn't have to know the exact method name
        /// on the concrete IQueueWriter implementation. It will try a few common
        /// candidates and invoke the first one it finds.
        /// </summary>
        private static void WriteToQueue(IQueueWriter writer, AgentEvent ev, CancellationToken token)
        {
            var writerType = writer.GetType();
            var candidates = new[]
            {
                "WriteAsync",
                "Write",
                "EnqueueAsync",
                "Enqueue"
            };

            foreach (var name in candidates)
            {
                var method = writerType.GetMethod(
                    name,
                    new[] { typeof(AgentEvent), typeof(CancellationToken) });

                if (method == null)
                {
                    continue;
                }

                var result = method.Invoke(writer, new object[] { ev, token });
                if (result is Task t)
                {
                    t.GetAwaiter().GetResult();
                }

                return;
            }

            throw new InvalidOperationException(
                $"IQueueWriter implementation '{writerType.FullName}' does not expose a suitable write method taking (AgentEvent, CancellationToken).");
        }

        private static AgentEvent MapRecordToAgentEvent(string inputName, string channel, EventRecord record)
        {
            DateTime ts;
            try
            {
                if (record.TimeCreated.HasValue && record.TimeCreated.Value.Year > 1900)
                {
                    ts = record.TimeCreated.Value.ToUniversalTime();
                }
                else
                {
                    ts = DateTime.UtcNow;
                }
            }
            catch
            {
                ts = DateTime.UtcNow;
            }

            string message;
            try
            {
                message = record.FormatDescription() ?? string.Empty;
            }
            catch
            {
                message = string.Empty;
            }

            object? level = null;
            try
            {
                level = record.LevelDisplayName;
            }
            catch
            {
                level = null;
            }

            string? providerName = null;
            try
            {
                providerName = record.ProviderName;
            }
            catch
            {
                providerName = null;
            }

            long? recordId = null;
            try
            {
                recordId = record.RecordId;
            }
            catch
            {
                recordId = null;
            }

            string? machineName = null;
            try
            {
                machineName = record.MachineName;
            }
            catch
            {
                machineName = null;
            }

            var body = new Dictionary<string, object?>
            {
                ["@timestamp"] = ts.ToString("o"),
                ["message"] = message,
                ["event"] = new Dictionary<string, object?>
                {
                    ["id"] = record.Id,
                    ["code"] = record.Id,
                    ["level"] = level,
                    ["provider"] = providerName,
                    ["record_id"] = recordId
                },
                ["winlog"] = new Dictionary<string, object?>
                {
                    ["channel"] = channel,
                    ["computer_name"] = machineName,
                    ["provider_name"] = providerName,
                    ["record_id"] = recordId
                },
                ["tinysocs"] = new Dictionary<string, object?>
                {
                    ["input_name"] = inputName
                }
            };

            return new AgentEvent
            {
                Ts = ts,
                Input = inputName,
                Channel = channel,
                EventId = record.Id,
                OpenSearchIndex = string.Empty, // shipper decides final index from config
                Body = body
            };
        }
    }
}