using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TinySocs.Agent.Configuration;
using TinySocs.Agent.Models;

namespace TinySocs.Agent.Shipper
{
    /// <summary>
    /// Shipper implementation that will use the OpenSearch _bulk API.
    /// v1: reads batches from the queue and logs what would be sent.
    /// HTTP POST to OpenSearch will be added in a later step.
    /// </summary>
    public sealed class OpenSearchBulkShipper : IShipper
    {
        private readonly ILogger<OpenSearchBulkShipper> _logger;
        private readonly AgentConfig _config;
        private readonly IQueueReader _queueReader;

        public OpenSearchBulkShipper(
            ILogger<OpenSearchBulkShipper> logger,
            AgentConfig config,
            IQueueReader queueReader)
        {
            _logger = logger;
            _config = config;
            _queueReader = queueReader;
        }

        public async Task RunAsync(CancellationToken stoppingToken)
        {
            var output = _config.Output;

            _logger.LogInformation(
                "OpenSearchBulkShipper initialised with url={Url}, indexPattern={IndexPattern}, sslVerify={SslVerify}, batchSizeEvents={BatchSizeEvents}, batchSizeBytes={BatchSizeBytes}, flushIntervalMs={FlushIntervalMs}",
                output.Url,
                output.IndexPattern,
                output.SslVerify,
                output.Bulk.BatchSizeEvents,
                output.Bulk.BatchSizeBytes,
                output.Bulk.FlushIntervalMs);

            // Main shipper loop: read from queue, (eventually) send to OpenSearch, acknowledge.
            while (!stoppingToken.IsCancellationRequested)
            {
                IReadOnlyList<AgentEvent> batch;

                try
                {
                    // Clamp bytes to int range for the reader
                    var maxBytes = output.Bulk.BatchSizeBytes > int.MaxValue
                        ? int.MaxValue
                        : (int)output.Bulk.BatchSizeBytes;

                    batch = await _queueReader.ReadBatchAsync(
                            output.Bulk.BatchSizeEvents,
                            maxBytes,
                            stoppingToken)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // Expected on shutdown
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error reading from queue. Will retry after a short delay.");
                    await DelayWithTokenAsync(output.Bulk.FlushIntervalMs, stoppingToken).ConfigureAwait(false);
                    continue;
                }

                if (batch.Count == 0)
                {
                    // Nothing to ship, wait a bit and try again.
                    await DelayWithTokenAsync(output.Bulk.FlushIntervalMs, stoppingToken).ConfigureAwait(false);
                    continue;
                }

                try
                {
                    // v1: just log what we would send. HTTP to OpenSearch comes later.
                    _logger.LogInformation(
                        "Read {Count} event(s) from queue. Would ship to OpenSearch at {Url}.",
                        batch.Count,
                        output.Url);

                    // TODO: build _bulk payload and POST to OpenSearch.
                    // For now, we treat this as successfully "shipped".
                    await _queueReader.AcknowledgeAsync(batch.Count, stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // Expected on shutdown
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error while processing or acknowledging batch. Events will be retried.");
                    // Do not acknowledge on failure; they will be re-read next loop.
                }
            }

            _logger.LogInformation("OpenSearchBulkShipper loop exiting.");
        }

        private static async Task DelayWithTokenAsync(int milliseconds, CancellationToken token)
        {
            if (milliseconds <= 0)
            {
                return;
            }

            try
            {
                await Task.Delay(TimeSpan.FromMilliseconds(milliseconds), token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // ignore; caller will handle cancellation
            }
        }
    }
}