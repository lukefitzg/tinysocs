using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TinySocs.Agent.Configuration;
using TinySocs.Agent.Models;
using TinySocs.Agent.Queueing;

namespace TinySocs.Agent.Inputs
{
    /// <summary>
    /// Synthetic input that continuously generates fake events.
    /// Used to exercise the queue + shipper pipeline end-to-end
    /// without depending on Windows Event Log.
    ///
    /// Events are shaped to look like a plausible winlog-style document
    /// so downstream parsing / dashboards can be developed before
    /// EventLogInput is fully implemented.
    /// </summary>
    public sealed class FakeInput : IInput
    {
        private readonly ILogger<FakeInput> _logger;
        private readonly AgentConfig _config;
        private readonly IQueueWriter _queueWriter;
        private int _counter = 0;

        public FakeInput(
            ILogger<FakeInput> logger,
            AgentConfig config,
            IQueueWriter queueWriter)
        {
            _logger = logger;
            _config = config;
            _queueWriter = queueWriter;
        }

        public async Task RunAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("FakeInput starting. Generating synthetic events for testing.");

            var hostName = Environment.MachineName;
            var nodeId = _config.Agent.NodeId ?? "default-node";
            var agentName = _config.Agent.Name ?? "TinySocsAgent";

            while (!stoppingToken.IsCancellationRequested)
            {
                var now = DateTimeOffset.UtcNow;
                var seq = Interlocked.Increment(ref _counter);

                var evt = new AgentEvent
                {
                    Ts = now,
                    Input = "fake-test",
                    Channel = "Fake",
                    EventId = 9000,
                    OpenSearchIndex = string.Empty,
                    Body = new Dictionary<string, object?>
                    {
                        ["message"] = $"TinySocs FakeInput synthetic event #{seq}",
                        ["@timestamp"] = now,
                        ["event"] = new Dictionary<string, object?>
                        {
                            ["id"] = 9000,
                            ["code"] = 9000,
                            ["kind"] = "event",
                            ["category"] = "test",
                            ["type"] = "info"
                        },
                        ["host"] = new Dictionary<string, object?>
                        {
                            ["name"] = hostName
                        },
                        ["agent"] = new Dictionary<string, object?>
                        {
                            ["name"] = agentName,
                            ["id"] = nodeId,
                            ["type"] = "tinysocs-fake",
                            ["version"] = "0.1.0"
                        },
                        ["winlog"] = new Dictionary<string, object?>
                        {
                            ["provider_name"] = "TinySocs-Fake",
                            ["channel"] = "Fake",
                            ["record_id"] = seq
                        },
                        ["tinysocs"] = new Dictionary<string, object?>
                        {
                            ["node_id"] = nodeId,
                            ["input_name"] = "fake-test"
                        }
                    }
                };

                try
                {
                    await _queueWriter.EnqueueAsync(evt, stoppingToken).ConfigureAwait(false);
                    _logger.LogDebug("Enqueued synthetic event #{Seq} at {Timestamp}.", seq, now);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error enqueuing synthetic event #{Seq}.", seq);
                }

                try
                {
                    // 1 event per second is plenty to prove the pipeline works.
                    await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }

            _logger.LogInformation("FakeInput stopping.");
        }
    }
}