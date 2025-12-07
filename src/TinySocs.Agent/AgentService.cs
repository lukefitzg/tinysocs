using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using TinySocs.Agent.Configuration;
using TinySocs.Agent.Inputs;
using TinySocs.Agent.Queueing;
using TinySocs.Agent.Shipper;

namespace TinySocs.Agent
{
    /// <summary>
    /// Main orchestration service for TinySocsAgent.
    /// - Builds inputs from configuration
    /// - Starts the shipper
    /// - Maintains a heartbeat loop
    /// </summary>
    public sealed class AgentService : BackgroundService
    {
        private readonly ILogger<AgentService> _logger;
        private readonly AgentConfig _config;
        private readonly ILoggerFactory _loggerFactory;
        private readonly IQueueWriter _queueWriter;
        private readonly IShipper _shipper;

        public AgentService(
            ILogger<AgentService> logger,
            AgentConfig config,
            ILoggerFactory loggerFactory,
            IQueueWriter queueWriter,
            IShipper shipper)
        {
            _logger = logger;
            _config = config;
            _loggerFactory = loggerFactory;
            _queueWriter = queueWriter;
            _shipper = shipper;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation(
                "TinySocsAgent starting. OS={OS}",
                RuntimeInformation.OSDescription);

            // 1) Build inputs from configuration
            IReadOnlyList<IInput> inputs;
            try
            {
                inputs = InputFactory.CreateInputs(_config, _queueWriter, _loggerFactory);

                if (inputs.Count == 0)
                {
                    _logger.LogInformation("No inputs configured. Agent will remain idle (ingestion-wise).");
                }
                else
                {
                    _logger.LogInformation("Prepared {Count} input(s) from configuration.", inputs.Count);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create inputs from configuration. Agent will run shipper/heartbeat only.");
                inputs = Array.Empty<IInput>();
            }

            // 2) Start shipper and inputs as background tasks.
            //    We do NOT await them here; instead we keep a heartbeat loop until cancellation.
            var backgroundTasks = new List<Task>
            {
                Task.Run(() => RunShipperSafeAsync(stoppingToken), CancellationToken.None)
            };

            foreach (var input in inputs)
            {
                backgroundTasks.Add(Task.Run(() => RunInputSafeAsync(input, stoppingToken), CancellationToken.None));
            }

            // 3) Heartbeat loop (represents service lifetime).
            try
            {
                while (!stoppingToken.IsCancellationRequested)
                {
                    _logger.LogDebug(
                        "TinySocsAgent heartbeat. OS={OS}",
                        RuntimeInformation.OSDescription);

                    try
                    {
                        await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        // Expected on shutdown
                        break;
                    }
                }
            }
            finally
            {
                _logger.LogInformation("TinySocsAgent stopping, waiting for background tasks to observe cancellation.");
                // We don't await backgroundTasks here; they should honour stoppingToken and complete quickly.
            }

            _logger.LogInformation("TinySocsAgent has stopped.");
        }

        private async Task RunShipperSafeAsync(CancellationToken stoppingToken)
        {
            try
            {
                _logger.LogInformation("Starting shipper loop.");
                await _shipper.RunAsync(stoppingToken).ConfigureAwait(false);
                _logger.LogInformation("Shipper loop completed.");
            }
            catch (OperationCanceledException)
            {
                _logger.LogInformation("Shipper loop cancelled.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Shipper loop terminated with an unhandled exception.");
            }
        }

        private async Task RunInputSafeAsync(IInput input, CancellationToken stoppingToken)
        {
            var inputTypeName = input.GetType().Name;

            try
            {
                _logger.LogInformation("Starting input {InputType}.", inputTypeName);
                await input.RunAsync(stoppingToken).ConfigureAwait(false);
                _logger.LogInformation("Input {InputType} completed.", inputTypeName);
            }
            catch (PlatformNotSupportedException ex)
            {
                // This will be the case for EventLogInput on non-Windows platforms.
                _logger.LogWarning(ex, "Input {InputType} is not supported on this platform. It will be disabled.", inputTypeName);
            }
            catch (OperationCanceledException)
            {
                _logger.LogInformation("Input {InputType} cancelled.", inputTypeName);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Input {InputType} terminated with an unhandled exception.", inputTypeName);
            }
        }
    }
}