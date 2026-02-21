using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Mail;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TinySocs.Agent.Configuration;
using TinySocs.Agent.Notification;

namespace TinySocs.Agent.Detection
{
    /// <summary>
    /// Writes alerts to:
    /// 1. OpenSearch (tinysocs-alerts-* index with deterministic ID)
    /// 2. Local log file (alerts.log)
    /// 3. Webhook (Slack-compatible JSON POST) — if configured
    /// 4. Email (SMTP) — if configured
    /// </summary>
    public sealed class AlertWriter
    {
        private readonly ILogger<AlertWriter> _logger;
        private readonly HttpClient _httpClient;
        private readonly Uri _bulkUri;
        private readonly string _alertLogPath;
        private readonly JsonSerializerOptions _jsonOptions;
        private readonly HashSet<string> _writtenAlertIds; // Track written alerts to prevent duplicates

        // Notification config
        private readonly NotificationConfig _notification;

        // Webhook: dedicated HttpClient with short timeout (fire-and-forget)
        private readonly HttpClient? _webhookClient;

        // Email: rate limiter — max 1 email per rule per 5 minutes
        private readonly ConcurrentDictionary<string, DateTime> _lastEmailPerRule;

        // Phase 13 (M4): Retry queue for failed notifications
        private readonly RetryQueue? _retryQueue;

        public AlertWriter(
            ILogger<AlertWriter> logger,
            HttpClient httpClient,
            Uri bulkUri,
            string alertLogPath,
            NotificationConfig? notification = null,
            RetryQueue? retryQueue = null)
        {
            _logger = logger;
            _httpClient = httpClient;
            _bulkUri = bulkUri;
            _alertLogPath = alertLogPath;
            _notification = notification ?? new NotificationConfig();
            _retryQueue = retryQueue;
            _writtenAlertIds = new HashSet<string>();
            _lastEmailPerRule = new ConcurrentDictionary<string, DateTime>();

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

            // Create a dedicated webhook HttpClient with 5s timeout
            if (!string.IsNullOrWhiteSpace(_notification.WebhookUrl))
            {
                _webhookClient = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
                _logger.LogInformation("Webhook notifications enabled: {Url}", _notification.WebhookUrl);
            }

            // Log email config status
            if (!string.IsNullOrWhiteSpace(_notification.Email?.SmtpHost))
            {
                _logger.LogInformation(
                    "Email notifications enabled: host={Host}, port={Port}, from={From}, to={To}",
                    _notification.Email.SmtpHost,
                    _notification.Email.SmtpPort,
                    _notification.Email.From,
                    _notification.Email.To);
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

                // Fire-and-forget notification channels (don't block pipeline)
                _ = TrySendWebhookAsync(alert);
                _ = TrySendEmailAsync(alert);

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

        // ---------------------------------------------------------------
        // M0: Webhook notifications (Slack-compatible JSON POST)
        // ---------------------------------------------------------------

        private async Task TrySendWebhookAsync(AlertDocument alert)
        {
            if (_webhookClient == null || string.IsNullOrWhiteSpace(_notification.WebhookUrl))
            {
                return;
            }

            // Build payload before try block so it's accessible in catch for retry
            var severity = alert.Alert.Severity.ToUpperInvariant();
            var emoji = severity switch
            {
                "HIGH" => "\U0001f534",
                "CRITICAL" => "\U0001f6a8",
                "MEDIUM" => "\U0001f7e0",
                _ => "\U0001f7e1"
            };

            var text = $"{emoji} *[TinySocs] [{severity}] {alert.Alert.RuleName}*\n" +
                       $"{alert.Alert.Description}\n" +
                       $"Events: {alert.Alert.EventCount} | Window: {alert.Alert.WindowStart}";

            var payload = JsonSerializer.Serialize(new { text });

            try
            {
                var content = new StringContent(payload, Encoding.UTF8, "application/json");

                var response = await _webhookClient.PostAsync(_notification.WebhookUrl, content).ConfigureAwait(false);

                if (response.IsSuccessStatusCode)
                {
                    _logger.LogDebug("Webhook sent for alert {AlertId}", alert.Alert.Id);
                }
                else
                {
                    _logger.LogWarning(
                        "Webhook POST failed for alert {AlertId}: HTTP {StatusCode} — queuing for retry",
                        alert.Alert.Id, (int)response.StatusCode);
                    _retryQueue?.EnqueueWebhook(_notification.WebhookUrl!, payload);
                }
            }
            catch (TaskCanceledException)
            {
                _logger.LogWarning("Webhook timed out for alert {AlertId} — queuing for retry", alert.Alert.Id);
                _retryQueue?.EnqueueWebhook(_notification.WebhookUrl!, payload);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Webhook failed for alert {AlertId} — queuing for retry", alert.Alert.Id);
                _retryQueue?.EnqueueWebhook(_notification.WebhookUrl!, payload);
            }
        }

        // ---------------------------------------------------------------
        // M1: Email notifications (SMTP)
        // ---------------------------------------------------------------

        private async Task TrySendEmailAsync(AlertDocument alert)
        {
            var email = _notification.Email;
            if (email == null ||
                string.IsNullOrWhiteSpace(email.SmtpHost) ||
                string.IsNullOrWhiteSpace(email.From) ||
                string.IsNullOrWhiteSpace(email.To))
            {
                return;
            }

            // Rate limit: max 1 email per rule per 5 minutes
            var ruleId = alert.Alert.RuleId;
            var now = DateTime.UtcNow;
            if (_lastEmailPerRule.TryGetValue(ruleId, out var lastSent) &&
                (now - lastSent).TotalMinutes < 5)
            {
                _logger.LogDebug(
                    "Email rate-limited for rule {RuleId} (last sent {Ago}s ago)",
                    ruleId, (int)(now - lastSent).TotalSeconds);
                return;
            }

            // Build subject and body before try block for retry access
            var severity = alert.Alert.Severity.ToUpperInvariant();
            var subject = $"[TinySocs] [{severity}] {alert.Alert.RuleName} \u2014 {alert.Alert.Description}";
            if (subject.Length > 200)
            {
                subject = subject.Substring(0, 197) + "...";
            }
            var body = BuildEmailBody(alert);

            try
            {
                using var message = new MailMessage(email.From, email.To, subject, body);
                message.IsBodyHtml = true;

                using var smtp = new SmtpClient(email.SmtpHost, email.SmtpPort);
                smtp.EnableSsl = email.SmtpPort == 587 || email.SmtpPort == 465;
                smtp.Timeout = 10_000; // 10s timeout

                await Task.Run(() => smtp.Send(message)).ConfigureAwait(false);

                _lastEmailPerRule[ruleId] = now;
                _logger.LogDebug("Email sent for alert {AlertId} to {To}", alert.Alert.Id, email.To);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Email failed for alert {AlertId} — queuing for retry", alert.Alert.Id);
                _retryQueue?.EnqueueEmail(subject, body, email.From, email.To, email.SmtpHost, email.SmtpPort);
            }
        }

        private static string BuildEmailBody(AlertDocument alert)
        {
            var severity = alert.Alert.Severity.ToUpperInvariant();
            var badgeColor = severity switch
            {
                "HIGH" => "#dc3545",
                "CRITICAL" => "#721c24",
                "MEDIUM" => "#fd7e14",
                _ => "#ffc107"
            };

            var sourceInfo = "";
            if (alert.Source != null && alert.Source.Count > 0)
            {
                var sb = new StringBuilder();
                foreach (var kvp in alert.Source)
                {
                    sb.Append($"<tr><td style=\"padding:4px 8px;font-weight:bold;\">{EscapeHtml(kvp.Key)}</td>" +
                              $"<td style=\"padding:4px 8px;\">{EscapeHtml(kvp.Value?.ToString() ?? "")}</td></tr>");
                }
                sourceInfo = $"<table style=\"border-collapse:collapse;margin-top:8px;\">{sb}</table>";
            }

            return $@"
<div style=""font-family:sans-serif;max-width:600px;"">
  <h2 style=""margin-bottom:4px;"">TinySocs Alert</h2>
  <span style=""display:inline-block;padding:2px 8px;border-radius:4px;color:#fff;background:{badgeColor};font-weight:bold;"">{severity}</span>
  <h3 style=""margin-top:12px;"">{EscapeHtml(alert.Alert.RuleName)}</h3>
  <p>{EscapeHtml(alert.Alert.Description)}</p>
  <table style=""border-collapse:collapse;"">
    <tr><td style=""padding:4px 8px;font-weight:bold;"">Rule ID</td><td style=""padding:4px 8px;"">{EscapeHtml(alert.Alert.RuleId)}</td></tr>
    <tr><td style=""padding:4px 8px;font-weight:bold;"">Event Count</td><td style=""padding:4px 8px;"">{alert.Alert.EventCount}</td></tr>
    <tr><td style=""padding:4px 8px;font-weight:bold;"">First Seen</td><td style=""padding:4px 8px;"">{EscapeHtml(alert.Alert.FirstSeen ?? "")}</td></tr>
    <tr><td style=""padding:4px 8px;font-weight:bold;"">Last Seen</td><td style=""padding:4px 8px;"">{EscapeHtml(alert.Alert.LastSeen ?? "")}</td></tr>
    <tr><td style=""padding:4px 8px;font-weight:bold;"">Window Start</td><td style=""padding:4px 8px;"">{EscapeHtml(alert.Alert.WindowStart)}</td></tr>
  </table>
  {sourceInfo}
  <p style=""margin-top:16px;color:#666;font-size:12px;"">Alert ID: {EscapeHtml(alert.Alert.Id)}</p>
</div>";
        }

        private static string EscapeHtml(string text)
        {
            if (string.IsNullOrEmpty(text)) return "";
            return text.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");
        }
    }
}
