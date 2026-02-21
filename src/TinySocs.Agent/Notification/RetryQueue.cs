using System;
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

namespace TinySocs.Agent.Notification
{
    /// <summary>
    /// Disk-backed retry queue for failed webhook and email notifications.
    /// Persists pending notifications as JSONL to survive process restarts.
    /// Uses exponential backoff: 30s → 60s → 120s (configurable).
    /// Entries older than max_age_seconds are discarded.
    ///
    /// Phase 13 (M4): Replaces fire-and-forget with reliable delivery.
    /// </summary>
    public sealed class RetryQueue : IDisposable
    {
        private readonly ILogger<RetryQueue> _logger;
        private readonly NotificationRetryConfig _config;
        private readonly NotificationConfig _notification;
        private readonly string _queueFilePath;
        private readonly HttpClient _webhookClient;
        private readonly object _fileLock = new();
        private readonly Timer _retryTimer;

        private int _retryCount;
        private int _discardCount;

        public RetryQueue(
            ILogger<RetryQueue> logger,
            NotificationConfig notification,
            string queueDirectory)
        {
            _logger = logger;
            _notification = notification;
            _config = notification.Retry ?? new NotificationRetryConfig();
            _queueFilePath = Path.Combine(queueDirectory, "notification_queue.jsonl");

            // Ensure queue directory exists
            if (!Directory.Exists(queueDirectory))
            {
                try { Directory.CreateDirectory(queueDirectory); }
                catch (Exception ex) { _logger.LogWarning(ex, "Failed to create queue directory: {Dir}", queueDirectory); }
            }

            // Dedicated webhook client for retries
            _webhookClient = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };

            // Process retry queue every 30 seconds
            _retryTimer = new Timer(
                _ => _ = ProcessQueueAsync(),
                null,
                TimeSpan.FromSeconds(30),
                TimeSpan.FromSeconds(30));

            _logger.LogInformation(
                "Notification retry queue initialised: file={File}, max_attempts={Max}, backoff={Backoff}s, max_age={Age}s",
                _queueFilePath, _config.MaxAttempts, _config.BackoffSeconds, _config.MaxAgeSeconds);
        }

        /// <summary>
        /// Enqueue a failed webhook notification for retry.
        /// </summary>
        public void EnqueueWebhook(string webhookUrl, string jsonPayload)
        {
            var entry = new QueueEntry
            {
                Type = "webhook",
                WebhookUrl = webhookUrl,
                Payload = jsonPayload,
                Attempts = 0,
                NextRetryUtc = DateTimeOffset.UtcNow.AddSeconds(_config.BackoffSeconds),
                CreatedAtUtc = DateTimeOffset.UtcNow
            };
            AppendEntry(entry);
            _logger.LogDebug("Webhook notification queued for retry: {Url}", webhookUrl);
        }

        /// <summary>
        /// Enqueue a failed email notification for retry.
        /// </summary>
        public void EnqueueEmail(string subject, string body, string from, string to, string smtpHost, int smtpPort)
        {
            var entry = new QueueEntry
            {
                Type = "email",
                EmailSubject = subject,
                Payload = body,
                EmailFrom = from,
                EmailTo = to,
                SmtpHost = smtpHost,
                SmtpPort = smtpPort,
                Attempts = 0,
                NextRetryUtc = DateTimeOffset.UtcNow.AddSeconds(_config.BackoffSeconds),
                CreatedAtUtc = DateTimeOffset.UtcNow
            };
            AppendEntry(entry);
            _logger.LogDebug("Email notification queued for retry: {To}", to);
        }

        /// <summary>
        /// Process the retry queue: attempt delivery for entries whose next_retry has passed.
        /// </summary>
        private async Task ProcessQueueAsync()
        {
            List<QueueEntry> entries;
            lock (_fileLock)
            {
                entries = ReadAllEntries();
            }

            if (entries.Count == 0) return;

            var now = DateTimeOffset.UtcNow;
            var remaining = new List<QueueEntry>();

            foreach (var entry in entries)
            {
                // Discard entries older than max age
                if ((now - entry.CreatedAtUtc).TotalSeconds > _config.MaxAgeSeconds)
                {
                    _discardCount++;
                    _logger.LogWarning(
                        "Discarding {Type} notification (aged out after {Age}s): attempts={Attempts}",
                        entry.Type, (int)(now - entry.CreatedAtUtc).TotalSeconds, entry.Attempts);
                    continue;
                }

                // Not yet time to retry
                if (now < entry.NextRetryUtc)
                {
                    remaining.Add(entry);
                    continue;
                }

                // Attempt delivery
                bool success = entry.Type == "webhook"
                    ? await TryDeliverWebhookAsync(entry)
                    : await TryDeliverEmailAsync(entry);

                if (success)
                {
                    _retryCount++;
                    _logger.LogInformation(
                        "Retry succeeded for {Type} notification after {Attempts} attempts",
                        entry.Type, entry.Attempts + 1);
                    continue; // Remove from queue (don't add to remaining)
                }

                // Delivery failed — increment attempts
                entry.Attempts++;
                if (entry.Attempts >= _config.MaxAttempts)
                {
                    _discardCount++;
                    _logger.LogWarning(
                        "Discarding {Type} notification after {Max} failed attempts",
                        entry.Type, _config.MaxAttempts);
                    continue; // Remove from queue
                }

                // Exponential backoff: base * 2^attempts
                var backoff = _config.BackoffSeconds * (1 << entry.Attempts);
                entry.NextRetryUtc = now.AddSeconds(backoff);
                remaining.Add(entry);

                _logger.LogDebug(
                    "Retry {Attempt}/{Max} for {Type} scheduled in {Backoff}s",
                    entry.Attempts, _config.MaxAttempts, entry.Type, backoff);
            }

            // Rewrite queue file with remaining entries
            lock (_fileLock)
            {
                WriteAllEntries(remaining);
            }

            // Periodic metrics
            if (_retryCount > 0 || _discardCount > 0)
            {
                _logger.LogInformation(
                    "Notification retry stats: delivered={Delivered}, discarded={Discarded}, pending={Pending}",
                    _retryCount, _discardCount, remaining.Count);
            }
        }

        private async Task<bool> TryDeliverWebhookAsync(QueueEntry entry)
        {
            try
            {
                var url = entry.WebhookUrl ?? _notification.WebhookUrl ?? "";
                if (string.IsNullOrWhiteSpace(url)) return false;

                var content = new StringContent(entry.Payload ?? "{}", Encoding.UTF8, "application/json");
                var response = await _webhookClient.PostAsync(url, content).ConfigureAwait(false);
                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Webhook retry delivery failed");
                return false;
            }
        }

        private async Task<bool> TryDeliverEmailAsync(QueueEntry entry)
        {
            try
            {
                var from = entry.EmailFrom ?? _notification.Email?.From ?? "";
                var to = entry.EmailTo ?? _notification.Email?.To ?? "";
                var host = entry.SmtpHost ?? _notification.Email?.SmtpHost ?? "";
                var port = entry.SmtpPort > 0 ? entry.SmtpPort : _notification.Email?.SmtpPort ?? 587;

                if (string.IsNullOrWhiteSpace(host) || string.IsNullOrWhiteSpace(from) || string.IsNullOrWhiteSpace(to))
                    return false;

                using var message = new MailMessage(from, to, entry.EmailSubject ?? "[TinySocs] Alert", entry.Payload ?? "")
                {
                    IsBodyHtml = true
                };

                using var smtp = new SmtpClient(host, port)
                {
                    EnableSsl = port == 587 || port == 465,
                    Timeout = 10_000
                };

                await Task.Run(() => smtp.Send(message)).ConfigureAwait(false);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Email retry delivery failed");
                return false;
            }
        }

        // ── File I/O ─────────────────────────────────────────────────

        private void AppendEntry(QueueEntry entry)
        {
            lock (_fileLock)
            {
                try
                {
                    var json = JsonSerializer.Serialize(entry);
                    File.AppendAllText(_queueFilePath, json + Environment.NewLine);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to append to retry queue file");
                }
            }
        }

        private List<QueueEntry> ReadAllEntries()
        {
            var entries = new List<QueueEntry>();
            if (!File.Exists(_queueFilePath)) return entries;

            try
            {
                foreach (var line in File.ReadAllLines(_queueFilePath))
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    try
                    {
                        var entry = JsonSerializer.Deserialize<QueueEntry>(line);
                        if (entry != null) entries.Add(entry);
                    }
                    catch
                    {
                        // Skip malformed lines
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to read retry queue file");
            }

            return entries;
        }

        private void WriteAllEntries(List<QueueEntry> entries)
        {
            try
            {
                if (entries.Count == 0)
                {
                    // Delete the file if queue is empty
                    if (File.Exists(_queueFilePath))
                        File.Delete(_queueFilePath);
                    return;
                }

                var sb = new StringBuilder();
                foreach (var entry in entries)
                {
                    sb.AppendLine(JsonSerializer.Serialize(entry));
                }
                File.WriteAllText(_queueFilePath, sb.ToString());
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to write retry queue file");
            }
        }

        public void Dispose()
        {
            _retryTimer.Dispose();
            _webhookClient.Dispose();
        }

        // ── Queue entry model ────────────────────────────────────────

        private sealed class QueueEntry
        {
            public string Type { get; set; } = "webhook"; // "webhook" | "email"
            public string? WebhookUrl { get; set; }
            public string? Payload { get; set; }
            public string? EmailSubject { get; set; }
            public string? EmailFrom { get; set; }
            public string? EmailTo { get; set; }
            public string? SmtpHost { get; set; }
            public int SmtpPort { get; set; }
            public int Attempts { get; set; }
            public DateTimeOffset NextRetryUtc { get; set; }
            public DateTimeOffset CreatedAtUtc { get; set; }
        }
    }
}
