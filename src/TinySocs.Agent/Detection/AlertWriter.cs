using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace TinySocs.Agent.Detection
{
    /// <summary>
    /// Writes alerts to:
    /// 1. OpenSearch (tinysocs-alerts-* index with deterministic ID)
    /// 2. Local log file (alerts.log)
    /// </summary>
    public sealed class AlertWriter
    {
        private readonly ILogger<AlertWriter> _logger;
        private readonly HttpClient _httpClient;
        private readonly Uri _bulkUri;
        private readonly string _alertLogPath;
        private readonly JsonSerializerOptions _jsonOptions;
        private readonly HashSet<string> _writtenAlertIds; // Track written alerts to prevent duplicates

        public AlertWriter(
            ILogger<AlertWriter> logger,
            HttpClient httpClient,
            Uri bulkUri,
            string alertLogPath)
        {
            _logger = logger;
            _httpClient = httpClient;
            _bulkUri = bulkUri;
            _alertLogPath = alertLogPath;
            _writtenAlertIds = new HashSet<string>();

            _jsonOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
            };

            // Ensure alert log directory exists
            var logDir = Path.GetDirectoryName(_alertLogPath);
            if (!string.IsNullOrEmpty(logDir) && !Directory.Exists(logDir))
            {
                try
                {
                    Directory.CreateDirectory(logDir);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to create alert log directory: {Dir}", logDir);
                }
            }
        }

        public async Task WriteAlertsAsync(List<AlertDocument> alerts, CancellationToken cancellationToken)
        {
            if (alerts == null || alerts.Count == 0)
            {
                return;
            }

            foreach (var alert in alerts)
            {
                // Skip if we've already written this alert (prevent duplicates)
                if (_writtenAlertIds.Contains(alert.Alert.Id))
                {
                    continue;
                }

                await WriteAlertToIndexAsync(alert, cancellationToken).ConfigureAwait(false);
                WriteAlertToLogFile(alert);

                _writtenAlertIds.Add(alert.Alert.Id);

                // Limit the in-memory set size to prevent unbounded growth
                if (_writtenAlertIds.Count > 10000)
                {
                    _writtenAlertIds.Clear();
                }
            }
        }

        private async Task WriteAlertToIndexAsync(AlertDocument alert, CancellationToken cancellationToken)
        {
            try
            {
                var indexName = $"tinysocs-alerts-{DateTimeOffset.UtcNow:yyyy.MM.dd}";

                var action = new
                {
                    index = new
                    {
                        _index = indexName,
                        _id = alert.Alert.Id  // Deterministic ID prevents duplicates
                    }
                };

                // Map AlertDocument to the schema expected by OpenSearch
                var doc = new
                {
                    timestamp = alert.Timestamp,
                    alert = new
                    {
                        id = alert.Alert.Id,
                        rule_id = alert.Alert.RuleId,
                        rule_name = alert.Alert.RuleName,
                        severity = alert.Alert.Severity,
                        description = alert.Alert.Description,
                        event_count = alert.Alert.EventCount,
                        first_seen = alert.Alert.FirstSeen,
                        last_seen = alert.Alert.LastSeen,
                        window_start = alert.Alert.WindowStart
                    },
                    source = alert.Source,
                    matched_events = alert.MatchedEvents
                };

                var ndjson = JsonSerializer.Serialize(action, _jsonOptions) + "\n" +
                             JsonSerializer.Serialize(doc, _jsonOptions) + "\n";

                var content = new StringContent(ndjson, Encoding.UTF8, "application/x-ndjson");

                var response = await _httpClient.PostAsync(_bulkUri, content, cancellationToken)
                    .ConfigureAwait(false);

                if (!response.IsSuccessStatusCode)
                {
                    var body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    _logger.LogWarning(
                        "Failed to write alert {AlertId} to OpenSearch: {Status} - {Body}",
                        alert.Alert.Id,
                        (int)response.StatusCode,
                        body.Length > 500 ? body.Substring(0, 500) : body);
                }
                else
                {
                    _logger.LogInformation(
                        "Alert {AlertId} written to OpenSearch index {Index}",
                        alert.Alert.Id,
                        indexName);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to write alert {AlertId} to OpenSearch", alert.Alert.Id);
            }
        }

        private void WriteAlertToLogFile(AlertDocument alert)
        {
            try
            {
                var logLine = FormatAlertLogLine(alert);

                // Append to log file (thread-safe via file system locking)
                File.AppendAllText(_alertLogPath, logLine + Environment.NewLine);

                _logger.LogDebug("Alert {AlertId} written to log file: {LogPath}", alert.Alert.Id, _alertLogPath);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to write alert {AlertId} to log file: {LogPath}", alert.Alert.Id, _alertLogPath);
            }
        }

        private string FormatAlertLogLine(AlertDocument alert)
        {
            // Format: [timestamp] [severity] [rule_id] description (count=N, key=value, window=start..end)
            var timestamp = alert.Timestamp;
            var severity = alert.Alert.Severity.ToUpperInvariant();
            var ruleId = alert.Alert.RuleId;
            var description = alert.Alert.Description;
            var count = alert.Alert.EventCount;
            var windowStart = alert.Alert.WindowStart;

            // Extract key from source
            var key = "";
            if (alert.Source != null && alert.Source.Count > 0)
            {
                var firstKey = "";
                foreach (var kvp in alert.Source)
                {
                    if (!string.IsNullOrEmpty(kvp.Key))
                    {
                        firstKey = kvp.Key;
                        break;
                    }
                }

                if (!string.IsNullOrEmpty(firstKey) && alert.Source.TryGetValue(firstKey, out var value))
                {
                    key = $"{firstKey}={value}";
                }
            }

            return $"[{timestamp}] [{severity}] [{ruleId}] {description} (count={count}, {key}, window={windowStart})";
        }
    }
}
