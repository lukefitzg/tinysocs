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
    /// This is intentionally minimal: enough to prove that a real
    /// Windows Event Log pipeline works end-to-end.
    /// </summary>
    public sealed class EventLogInput : IInput
    {
        private readonly ILogger<EventLogInput> _logger;
        private readonly AgentConfig _config;
        private readonly IQueueWriter _queueWriter;
        private readonly HashSet<string> _missingChannels = new(StringComparer.OrdinalIgnoreCase);

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

            // For now we do a very simple polling reader per configured channel.
            // Eventually you can switch this to an event-driven subscription with
            // EventLogWatcher and bookmarks.
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

            // Very simple polling loop: each iteration reads the most recent events
            // from each channel and pushes them into the queue.
            // NOTE: This is deliberately naive – no bookmarks, no duplicate
            // suppression – because you just need a working spine first.
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
                            using var logReader = new EventLogReader(channelName, PathType.LogName);
                            EventRecord? record;
                            int readCount = 0;

                            // Read a small batch each pass so we don't block forever.
                            while (!stoppingToken.IsCancellationRequested &&
                                   readCount < 50 &&
                                   (record = logReader.ReadEvent()) != null)
                            {
                                using (record)
                                {
                                    var ev = MapRecordToAgentEvent(evInput.Name ?? "win-events", channelName, record);

                                    // Use a helper that knows how to talk to whatever
                                    // write method the underlying queue writer actually exposes.
                                    WriteToQueue(_queueWriter, ev, stoppingToken);

                                    readCount++;
                                }
                            }

                            if (readCount > 0)
                            {
                                _logger.LogDebug("Read {Count} event(s) from channel {Channel}.", readCount, channelName);
                            }
                        }
                        catch (EventLogNotFoundException ex)
                        {
                            // If this is the first time we've seen this channel fail, log a warning and mark it as missing.
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

                            // Skip further processing for this channel in this iteration.
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
                    // Small delay to avoid a tight loop; bookmarks will replace this later.
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
            // Extremely minimal mapping – enough for OpenSearch to have something useful.
            var ts = record.TimeCreated ?? DateTime.UtcNow;

            var body = new System.Collections.Generic.Dictionary<string, object?>
            {
                ["@timestamp"] = ts.ToUniversalTime().ToString("o"),
                ["message"] = record.FormatDescription() ?? string.Empty,
                ["event"] = new System.Collections.Generic.Dictionary<string, object?>
                {
                    ["id"] = record.Id,
                    ["code"] = record.Id,
                    ["level"] = record.LevelDisplayName,
                    ["provider"] = record.ProviderName,
                    ["record_id"] = record.RecordId
                },
                ["winlog"] = new System.Collections.Generic.Dictionary<string, object?>
                {
                    ["channel"] = channel,
                    ["computer_name"] = record.MachineName,
                    ["provider_name"] = record.ProviderName,
                    ["record_id"] = record.RecordId
                },
                ["tinysocs"] = new System.Collections.Generic.Dictionary<string, object?>
                {
                    ["input_name"] = inputName
                }
            };

            return new AgentEvent
            {
                Ts = ts.ToUniversalTime(),
                Input = inputName,
                Channel = channel,
                EventId = record.Id,
                OpenSearchIndex = string.Empty,
                Body = body
            };
        }
    }
}