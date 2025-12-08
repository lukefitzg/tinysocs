using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TinySocs.Agent.Configuration;
using TinySocs.Agent.Models;

namespace TinySocs.Agent.Shipper
{
    /// <summary>
    /// Shipper implementation that uses the OpenSearch _bulk API.
    /// - Reads batches from the queue
    /// - Builds NDJSON bulk payload
    /// - POSTs to {url}/_bulk
    /// - On success: acknowledges the batch
    /// - On failure: leaves the batch in the queue and backs off
    /// </summary>
    public sealed class OpenSearchBulkShipper : IShipper
    {
        private readonly ILogger<OpenSearchBulkShipper> _logger;
        private readonly AgentConfig _config;
        private readonly IQueueReader _queueReader;
        private readonly HttpClient _httpClient;
        private readonly Uri _bulkUri;
        private readonly JsonSerializerOptions _jsonOptions;

        public OpenSearchBulkShipper(
            ILogger<OpenSearchBulkShipper> logger,
            AgentConfig config,
            IQueueReader queueReader)
        {
            _logger = logger;
            _config = config;
            _queueReader = queueReader;

            var output = _config.Output;

            var handler = new HttpClientHandler();
            if (!output.SslVerify)
            {
                // Dangerous by design, controlled via config.
                handler.ServerCertificateCustomValidationCallback =
                    HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
            }

            _httpClient = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(30)
            };

            var baseUri = new Uri(output.Url);
            _bulkUri = new Uri(baseUri, "/_bulk");

            _jsonOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
            };
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

            var failureCount = 0;

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

                var indexName = ResolveIndexName(output.IndexPattern, DateTimeOffset.UtcNow);

                try
                {
                    var payload = BuildBulkPayload(batch, indexName);
                    var content = new StringContent(payload, Encoding.UTF8, "application/x-ndjson");

                    _logger.LogInformation(
                        "Shipping {Count} event(s) to OpenSearch index {Index} at {Url}.",
                        batch.Count,
                        indexName,
                        output.Url);

                    using var response = await _httpClient.PostAsync(_bulkUri, content, stoppingToken)
                        .ConfigureAwait(false);

                    if (!response.IsSuccessStatusCode)
                    {
                        var body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                        _logger.LogError(
                            "OpenSearch _bulk request failed with status {StatusCode}. Body: {Body}",
                            (int)response.StatusCode,
                            Truncate(body, 4096));

                        failureCount++;
                        await BackoffAsync(failureCount, _config.Output.Retry, stoppingToken).ConfigureAwait(false);
                        // Do NOT acknowledge; events will be retried.
                        continue;
                    }

                    // TODO: parse response JSON and check "errors":false for extra safety.
                    failureCount = 0;

                    await _queueReader.AcknowledgeAsync(batch.Count, stoppingToken).ConfigureAwait(false);
                    _logger.LogInformation(
                        "Successfully shipped {Count} event(s) to OpenSearch index {Index}.",
                        batch.Count,
                        indexName);
                }
                catch (OperationCanceledException)
                {
                    // Expected on shutdown
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error while shipping or acknowledging batch. Events will be retried.");
                    failureCount++;
                    await BackoffAsync(failureCount, _config.Output.Retry, stoppingToken).ConfigureAwait(false);
                    // Do not acknowledge on failure; they will be re-read next loop.
                }
            }

            _logger.LogInformation("OpenSearchBulkShipper loop exiting.");
        }

        private string BuildBulkPayload(IReadOnlyList<AgentEvent> batch, string indexName)
        {
            var sb = new StringBuilder(capacity: batch.Count * 256);

            foreach (var evt in batch)
            {
                var action = new
                {
                    index = new
                    {
                        _index = indexName
                    }
                };

                sb.AppendLine(JsonSerializer.Serialize(action, _jsonOptions));
                sb.AppendLine(JsonSerializer.Serialize(evt, _jsonOptions));
            }

            return sb.ToString();
        }

        private static string ResolveIndexName(string pattern, DateTimeOffset now)
        {
            // Minimal implementation: replace {yyyy.MM.dd} with today's UTC date.
            var date = now.UtcDateTime.ToString("yyyy.MM.dd");
            return pattern.Replace("{yyyy.MM.dd}", date);
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

        private static async Task BackoffAsync(int failureCount, RetryConfig retry, CancellationToken token)
        {
            var initial = retry.InitialBackoffMs <= 0 ? 1000 : retry.InitialBackoffMs;
            var max = retry.MaxBackoffMs <= 0 ? 60000 : retry.MaxBackoffMs;

            // exponential: initial * 2^(n-1), capped at max
            var factor = failureCount - 1;
            if (factor < 0) factor = 0;
            double rawDelay = initial * Math.Pow(2, factor);
            var delayMs = (int)Math.Min(rawDelay, max);

            await DelayWithTokenAsync(delayMs, token).ConfigureAwait(false);
        }

        private static string Truncate(string value, int maxLength)
        {
            if (string.IsNullOrEmpty(value) || value.Length <= maxLength)
            {
                return value;
            }

            return value.Substring(0, maxLength) + "...(truncated)";
        }
    }
}