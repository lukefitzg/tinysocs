using System;
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
    /// </summary>
    public sealed class FakeInput : IInput
    {
        private readonly ILogger<FakeInput> _logger;
        private readonly AgentConfig _config;
        private readonly IQueueWriter _queueWriter;

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

            while (!stoppingToken.IsCancellationRequested)
            {
                var evt = new AgentEvent
                {
                    EventId = 9000
                };

                try
                {
                    await _queueWriter.EnqueueAsync(evt, stoppingToken).ConfigureAwait(false);
                    _logger.LogDebug("Enqueued synthetic event at {Timestamp}.", DateTimeOffset.UtcNow);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error enqueuing synthetic event.");
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