using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TinySocs.Agent.Configuration;
using TinySocs.Agent.Queueing;

namespace TinySocs.Agent.Inputs
{
    /// <summary>
    /// Windows Event Log input. On non-Windows platforms this will refuse to run.
    /// The actual EventLog subscription code will be implemented on Windows.
    /// </summary>
    public sealed class EventLogInput : IInput
    {
        private readonly ILogger<EventLogInput> _logger;
        private readonly AgentConfig _config;
        private readonly IQueueWriter _queueWriter;

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

            // TODO (on Windows): implement EventLog subscriptions using
            // System.Diagnostics.Eventing.Reader APIs and push into _queueWriter.

            _logger.LogInformation("EventLogInput RunAsync called, but implementation is pending.");
            return Task.CompletedTask;
        }
    }
}