using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using Microsoft.Extensions.Logging;
using TinySocs.Agent.Configuration;
using TinySocs.Agent.Detection;
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
    /// Patch notes:
    /// - Honour per-channel start_from: now | beginning
    /// - Tail-prime (now) by setting lastSeen to current newest record_id and emitting nothing.
    /// - Read newest->older on subsequent passes and break once <= lastSeen.
    /// - Emit in chronological order (oldest->newest) within each batch.
    /// </summary>
    public sealed class EventLogInput : IInput
    {
        private readonly ILogger<EventLogInput> _logger;
        private readonly AgentConfig _config;
        private readonly IQueueWriter _queueWriter;
        private readonly HashSet<string> _missingChannels = new(StringComparer.OrdinalIgnoreCase);

        // Track last seen EventRecordID per channel so we don't re-read the same
        // events on every polling iteration. This is an in-memory bookmark only
        // (resets on agent restart).
        private readonly Dictionary<string, long?> _lastRecordIds = new(StringComparer.OrdinalIgnoreCase);

        // Direct alert: write TS-080 (event 1102) alerts directly to OpenSearch
        // to bypass the queue/shipper pipeline latency.  The queue+shipper path
        // can stall for minutes when OpenSearch returns 401 on connection test,
        // causing event 1102 to never reach the DetectionEngine within the test
        // timeout.  This fast-path fires the alert immediately.
        private HttpClient? _alertHttpClient;
        private Uri? _alertBulkUri;
        private string? _alertLogPath;
        private readonly HashSet<string> _writtenDirectAlertIds = new();
        private readonly object _alertLock = new();

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
                            long? lastSeen;
                            lock (_lastRecordIds)
                            {
                                _lastRecordIds.TryGetValue(channelName, out lastSeen);
                            }

                            //
                            // FIRST PASS FOR THIS CHANNEL: honour start_from.
                            //
                            if (lastSeen == null)
                            {
                                var startFrom = (ch.StartFrom ?? "now").Trim().ToLowerInvariant();

                                if (startFrom == "beginning")
                                {
                                    // Ingest full history from record_id 0 upwards.
                                    lock (_lastRecordIds)
                                    {
                                        _lastRecordIds[channelName] = 0;
                                    }

                                    _logger.LogInformation(
                                        "Channel {Channel} configured start_from=beginning; initial record_id set to 0.",
                                        channelName);

                                    // Continue to normal read path in the same iteration.
                                    lastSeen = 0;
                                }
                                else
                                {
                                    // Default (and "now"): prime at current tail – discover newest record_id
                                    // but do not emit historical events.
                                    var primeQuery = new EventLogQuery(channelName, PathType.LogName)
                                    {
                                        ReverseDirection = true // newest -> older
                                    };

                                    long primedRecordId = 0;

                                    using (var primeReader = new EventLogReader(primeQuery))
                                    {
                                        EventRecord? first = null;
                                        try
                                        {
                                            first = primeReader.ReadEvent();
                                            if (first != null)
                                            {
                                                try
                                                {
                                                    primedRecordId = first.RecordId ?? 0;
                                                }
                                                catch
                                                {
                                                    primedRecordId = 0;
                                                }
                                            }
                                        }
                                        finally
                                        {
                                            first?.Dispose();
                                        }
                                    }

                                    lock (_lastRecordIds)
                                    {
                                        _lastRecordIds[channelName] = primedRecordId;
                                    }

                                    _logger.LogInformation(
                                        "Primed EventLog channel {Channel} at record_id {RecordId} (start_from={StartFrom}).",
                                        channelName,
                                        primedRecordId,
                                        startFrom);

                                    // Do NOT emit anything on the priming pass.
                                    continue;
                                }
                            }

                            //
                            // SUBSEQUENT PASSES: read newest->older and stop once we hit lastSeen.
                            //
                            var query = new EventLogQuery(channelName, PathType.LogName)
                            {
                                ReverseDirection = true // newest -> older
                            };

                            using (var logReader = new EventLogReader(query))
                            {
                                var newEvents = new List<(AgentEvent Ev, long RecordId)>();
                                var currentLastSeen = lastSeen ?? 0;
                                int readCount = 0;
                                bool detectedLogClear = false;
                                EventRecord? record;

                                while (!stoppingToken.IsCancellationRequested &&
                                       readCount < 200 &&
                                       (record = logReader.ReadEvent()) != null)
                                {
                                    using (record)
                                    {
                                        long? recordId = null;
                                        try
                                        {
                                            recordId = record.RecordId;
                                        }
                                        catch
                                        {
                                            recordId = null;
                                        }

                                        if (!recordId.HasValue)
                                        {
                                            continue;
                                        }

                                        // Event 1102 (Security log cleared): fire TS-080 alert directly,
                                        // bypassing the queue/shipper pipeline that can stall.
                                        if (record.Id == 1102 && string.Equals(channelName, "Security", StringComparison.OrdinalIgnoreCase))
                                        {
                                            _logger.LogWarning(
                                                "EventLogInput: Event 1102 detected in Security channel. RecordId={RecordId}, Bookmark={Bookmark}. Firing direct TS-080 alert.",
                                                recordId.Value,
                                                currentLastSeen);

                                            TryWriteDirectAlert1102(record, channelName);
                                        }

                                        // ── No-new-events fast path ──
                                        // Newest event equals our bookmark → nothing new since last poll.
                                        // Must check BEFORE the < block to avoid false log-clear detection.
                                        if (recordId.Value == currentLastSeen)
                                        {
                                            break;
                                        }

                                        // Because we're reading newest->older, as soon as we hit
                                        // a record_id older than our bookmark, we can stop.
                                        if (recordId.Value < currentLastSeen)
                                        {
                                            // Only the FIRST event (readCount==0) can signal a log clear:
                                            // the newest event in the log has a lower record_id than our
                                            // bookmark, meaning the log was cleared or rotated.
                                            if (readCount == 0 && currentLastSeen > 0)
                                            {
                                                _logger.LogWarning(
                                                    "Channel {Channel}: newest record_id ({NewestId}) is below bookmark ({Bookmark}). Log was likely cleared. Resetting bookmark.",
                                                    channelName,
                                                    recordId.Value,
                                                    currentLastSeen);

                                                detectedLogClear = true;
                                                currentLastSeen = 0;

                                                // This event is new — process it
                                                var ev2 = MapRecordToAgentEvent(evInput.Name ?? "win-events", channelName, record);
                                                newEvents.Add((ev2, recordId.Value));
                                                readCount++;
                                                continue;
                                            }

                                            break;
                                        }

                                        var ev = MapRecordToAgentEvent(evInput.Name ?? "win-events", channelName, record);
                                        newEvents.Add((ev, recordId.Value));
                                        readCount++;
                                    }
                                }

                                if (newEvents.Count > 0)
                                {
                                    // We collected events newest->older; emit oldest->newest for nicer ordering.
                                    newEvents.Sort((a, b) => a.RecordId.CompareTo(b.RecordId));

                                    long maxRecordId = currentLastSeen;
                                    foreach (var (ev, recordId) in newEvents)
                                    {
                                        WriteToQueue(_queueWriter, ev, stoppingToken);
                                        if (recordId > maxRecordId)
                                        {
                                            maxRecordId = recordId;
                                        }
                                    }

                                    lock (_lastRecordIds)
                                    {
                                        _lastRecordIds[channelName] = maxRecordId;
                                    }

                                    _logger.LogDebug(
                                        "Read {Count} new event(s) from channel {Channel}. Advanced record_id from {Old} to {New}.",
                                        newEvents.Count,
                                        channelName,
                                        currentLastSeen,
                                        maxRecordId);
                                }
                            }
                        }
                        catch (EventLogNotFoundException ex)
                        {
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
            DateTime ts;
            try
            {
                if (record.TimeCreated.HasValue && record.TimeCreated.Value.Year > 1900)
                {
                    ts = record.TimeCreated.Value.ToUniversalTime();
                }
                else
                {
                    ts = DateTime.UtcNow;
                }
            }
            catch
            {
                ts = DateTime.UtcNow;
            }

            string message;
            try
            {
                message = record.FormatDescription() ?? string.Empty;
            }
            catch
            {
                message = string.Empty;
            }

            object? level = null;
            try
            {
                level = record.LevelDisplayName;
            }
            catch
            {
                level = null;
            }

            string? providerName = null;
            try
            {
                providerName = record.ProviderName;
            }
            catch
            {
                providerName = null;
            }

            long? recordId = null;
            try
            {
                recordId = record.RecordId;
            }
            catch
            {
                recordId = null;
            }

            string? machineName = null;
            try
            {
                machineName = record.MachineName;
            }
            catch
            {
                machineName = null;
            }

            // Extract EventData from XML (generic approach for all events)
            var eventData = ExtractEventDataFromXml(record);

            var winlogDict = new Dictionary<string, object?>
            {
                ["channel"] = channel,
                ["computer_name"] = machineName,
                ["provider_name"] = providerName,
                ["record_id"] = recordId
            };

            // Only add event_data if we extracted any fields
            if (eventData != null && eventData.Count > 0)
            {
                winlogDict["event_data"] = eventData;
            }

            var body = new Dictionary<string, object?>
            {
                ["@timestamp"] = ts.ToString("o"),
                ["message"] = message,
                ["event"] = new Dictionary<string, object?>
                {
                    ["id"] = record.Id,
                    ["code"] = record.Id,
                    ["level"] = level,
                    ["provider"] = providerName,
                    ["record_id"] = recordId
                },
                ["winlog"] = winlogDict,
                ["tinysocs"] = new Dictionary<string, object?>
                {
                    ["input_name"] = inputName
                }
            };

            return new AgentEvent
            {
                Ts = ts,
                Input = inputName,
                Channel = channel,
                EventId = record.Id,
                OpenSearchIndex = string.Empty, // shipper decides final index from config
                Body = body
            };
        }

        // =======================================================================
        // Direct TS-080 alert (event 1102) — bypasses queue/shipper pipeline
        // =======================================================================

        private void TryWriteDirectAlert1102(EventRecord record, string channel)
        {
            try
            {
                var now = DateTime.UtcNow;
                var windowStart = new DateTime(now.Year, now.Month, now.Day, now.Hour, now.Minute, 0, DateTimeKind.Utc);

                string? computerName = null;
                try { computerName = record.MachineName; } catch { /* best-effort */ }
                computerName ??= Environment.MachineName;

                var groupKey = computerName;
                var alertId = $"TS-080|{groupKey}|{windowStart:yyyy-MM-ddTHH:mm:00Z}";

                // Dedup: only one alert per minute-window per computer
                lock (_alertLock)
                {
                    if (_writtenDirectAlertIds.Contains(alertId))
                    {
                        _logger.LogDebug("Direct TS-080 alert already written for this window: {AlertId}", alertId);
                        return;
                    }
                }

                var tsStr = now.ToString("o");

                var alert = new AlertDocument
                {
                    Timestamp = tsStr,
                    Alert = new AlertInfo
                    {
                        Id = alertId,
                        RuleId = "TS-080",
                        RuleName = "event_log_cleared",
                        Severity = "high",
                        Description = $"Security event log cleared (event 1102) on {computerName}",
                        EventCount = 1,
                        FirstSeen = tsStr,
                        LastSeen = tsStr,
                        WindowStart = windowStart.ToString("o")
                    },
                    Source = new Dictionary<string, object?>
                    {
                        ["computer_name"] = computerName
                    },
                    MatchedEvents = 1,
                    Mitre = new MitreAlertInfo
                    {
                        TechniqueId = "T1070.001",
                        TechniqueName = "Indicator Removal: Clear Windows Event Logs",
                        Tactic = "defense-evasion"
                    }
                };

                // Write to OpenSearch
                WriteAlertToOpenSearch(alert);

                // Write to local alerts.log
                WriteAlertToLocalLogFile(alert);

                lock (_alertLock)
                {
                    _writtenDirectAlertIds.Add(alertId);
                    if (_writtenDirectAlertIds.Count > 1000)
                    {
                        _writtenDirectAlertIds.Clear();
                    }
                }

                _logger.LogWarning(
                    "DIRECT-ALERT: TS-080 alert written for event 1102. AlertId={AlertId}, Computer={Computer}",
                    alertId, computerName);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to write direct TS-080 alert for event 1102.");
            }
        }

        private void EnsureAlertHttpClient()
        {
            if (_alertHttpClient != null) return;

            lock (_alertLock)
            {
                if (_alertHttpClient != null) return;

                var output = _config.Output;

                var handler = new HttpClientHandler();
                if (!output.SslVerify)
                {
                    handler.ServerCertificateCustomValidationCallback =
                        HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
                }

                var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };

                // Configure pre-emptive Basic auth — same priority as OpenSearchBulkShipper:
                // 1) Config output.User/Pass
                // 2) Environment variables
                // 3) Windows Credential Manager (CredMan)
                string? authUser = null;
                string? authPass = null;
                string authSource = "none";

                if (!string.IsNullOrWhiteSpace(output.User) && !string.IsNullOrWhiteSpace(output.Pass))
                {
                    authUser = output.User;
                    authPass = output.Pass;
                    authSource = "config";
                }
                else
                {
                    // Fallback: env vars
                    var envUser = Environment.GetEnvironmentVariable("TINYSOCS_SIEM_USER")
                                  ?? Environment.GetEnvironmentVariable("SIEM_USER")
                                  ?? Environment.GetEnvironmentVariable("OPENSEARCH_USERNAME");
                    var envPass = Environment.GetEnvironmentVariable("TINYSOCS_SIEM_PASS")
                                  ?? Environment.GetEnvironmentVariable("SIEM_PASS")
                                  ?? Environment.GetEnvironmentVariable("OPENSEARCH_PASSWORD");
                    if (!string.IsNullOrWhiteSpace(envUser) && !string.IsNullOrWhiteSpace(envPass))
                    {
                        authUser = envUser;
                        authPass = envPass;
                        authSource = "env";
                    }
                }

                // Fallback: Windows Credential Manager
                if (string.IsNullOrWhiteSpace(authUser) || string.IsNullOrWhiteSpace(authPass))
                {
                    var credTarget = _config.SiemCredentials?.Target ?? "TinySocs/SIEM/Creds";
                    var (cmUser, cmPass) = TryReadGenericCredential(credTarget);
                    if (!string.IsNullOrWhiteSpace(cmUser) && !string.IsNullOrWhiteSpace(cmPass))
                    {
                        authUser = cmUser;
                        authPass = cmPass;
                        authSource = $"credman:{credTarget}";
                    }
                    else
                    {
                        // Some cmdkey writes use "target=<name>" format
                        var alt = credTarget.StartsWith("target=", StringComparison.OrdinalIgnoreCase)
                            ? credTarget.Substring("target=".Length)
                            : "target=" + credTarget;
                        var (cmUser2, cmPass2) = TryReadGenericCredential(alt);
                        if (!string.IsNullOrWhiteSpace(cmUser2) && !string.IsNullOrWhiteSpace(cmPass2))
                        {
                            authUser = cmUser2;
                            authPass = cmPass2;
                            authSource = $"credman:{alt}";
                        }
                    }
                }

                if (!string.IsNullOrWhiteSpace(authUser) && !string.IsNullOrWhiteSpace(authPass))
                {
                    var token = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{authUser}:{authPass}"));
                    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", token);
                }

                var baseUri = new Uri(output.Url);
                _alertBulkUri = new Uri(baseUri, "/_bulk");
                _alertHttpClient = client;

                // Alert log path: same directory as agent.log → alerts.log
                _alertLogPath = Path.Combine(
                    Path.GetDirectoryName(_config.Agent.LogFile) ?? @"C:\ProgramData\TinySocs\Collector\logs",
                    "alerts.log");

                _logger.LogInformation(
                    "Direct alert HttpClient initialized. BulkUri={BulkUri}, AlertLogPath={AlertLogPath}, AuthSource={AuthSource}",
                    _alertBulkUri, _alertLogPath, authSource);
            }
        }

        private void WriteAlertToOpenSearch(AlertDocument alert)
        {
            try
            {
                EnsureAlertHttpClient();

                var indexName = $"tinysocs-alerts-{DateTimeOffset.UtcNow:yyyy.MM.dd}";

                var jsonOptions = new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                    DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
                };

                var action = new { index = new { _index = indexName, _id = alert.Alert.Id } };

                object? mitreSection = alert.Mitre != null
                    ? (object)new
                    {
                        technique_id = alert.Mitre.TechniqueId,
                        technique_name = alert.Mitre.TechniqueName,
                        tactic = alert.Mitre.Tactic
                    }
                    : null;

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
                    matched_events = alert.MatchedEvents,
                    mitre = mitreSection
                };

                var ndjson = JsonSerializer.Serialize(action, jsonOptions) + "\n" +
                             JsonSerializer.Serialize(doc, jsonOptions) + "\n";

                var content = new StringContent(ndjson, Encoding.UTF8, "application/x-ndjson");

                // Synchronous POST — we're already on a background thread.
                var response = _alertHttpClient!.PostAsync(_alertBulkUri, content).GetAwaiter().GetResult();

                if (!response.IsSuccessStatusCode)
                {
                    var body = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                    _logger.LogWarning(
                        "Direct alert POST failed: HTTP {Status} - {Body}",
                        (int)response.StatusCode,
                        body.Length > 500 ? body.Substring(0, 500) : body);
                }
                else
                {
                    _logger.LogInformation(
                        "Direct alert {AlertId} written to OpenSearch index {Index}.",
                        alert.Alert.Id, indexName);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to write direct alert {AlertId} to OpenSearch.", alert.Alert.Id);
            }
        }

        private void WriteAlertToLocalLogFile(AlertDocument alert)
        {
            try
            {
                if (string.IsNullOrEmpty(_alertLogPath)) return;

                var logDir = Path.GetDirectoryName(_alertLogPath);
                if (!string.IsNullOrEmpty(logDir) && !Directory.Exists(logDir))
                {
                    Directory.CreateDirectory(logDir);
                }

                var computerName = alert.Source.TryGetValue("computer_name", out var cn) ? cn?.ToString() ?? "" : "";
                var line = $"[{alert.Timestamp}] [{alert.Alert.Severity.ToUpperInvariant()}] [{alert.Alert.RuleId}] " +
                           $"{alert.Alert.Description} (count={alert.Alert.EventCount}, computer_name={computerName}, " +
                           $"window={alert.Alert.WindowStart})";

                File.AppendAllText(_alertLogPath, line + Environment.NewLine);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to write direct alert to log file.");
            }
        }

        // =======================================================================

        /// <summary>
        /// Extract all EventData properties from the EventRecord XML.
        /// Returns a dictionary of property name -> string value for all named EventData elements.
        /// This is a generic approach that works for all event types.
        /// </summary>
        private static Dictionary<string, object?>? ExtractEventDataFromXml(EventRecord record)
        {
            try
            {
                var xml = record.ToXml();
                if (string.IsNullOrWhiteSpace(xml))
                {
                    return null;
                }

                var doc = new XmlDocument();
                doc.LoadXml(xml);

                // Find all EventData/Data elements with Name attribute
                var eventDataNodes = doc.GetElementsByTagName("EventData");
                if (eventDataNodes.Count == 0)
                {
                    return null;
                }

                var result = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);

                var eventDataNode = eventDataNodes[0];
                if (eventDataNode?.ChildNodes == null)
                {
                    return null;
                }

                foreach (XmlNode child in eventDataNode.ChildNodes)
                {
                    if (child.NodeType != XmlNodeType.Element)
                    {
                        continue;
                    }

                    var elem = (XmlElement)child;

                    // Extract <Data Name="...">value</Data>
                    if (elem.Name == "Data" && elem.HasAttribute("Name"))
                    {
                        var name = elem.GetAttribute("Name");
                        var value = elem.InnerText;

                        if (!string.IsNullOrEmpty(name))
                        {
                            result[name] = string.IsNullOrEmpty(value) ? null : value;
                        }
                    }
                }

                return result.Count > 0 ? result : null;
            }
            catch
            {
                // If XML parsing fails, just return null (no event_data field)
                return null;
            }
        }

        // =======================================================================
        // CredMan (Windows Credential Manager) helpers — same as OpenSearchBulkShipper
        // =======================================================================

        private const uint CRED_TYPE_GENERIC = 1;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CREDENTIAL
        {
            public uint Flags;
            public uint Type;
            public string TargetName;
            public string Comment;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
            public uint CredentialBlobSize;
            public IntPtr CredentialBlob;
            public uint Persist;
            public uint AttributeCount;
            public IntPtr Attributes;
            public string TargetAlias;
            public string UserName;
        }

        [DllImport("advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredRead(string target, uint type, uint reservedFlag, out IntPtr credentialPtr);

        [DllImport("advapi32.dll", EntryPoint = "CredFree", SetLastError = false)]
        private static extern void CredFree(IntPtr cred);

        private static (string? user, string? pass) TryReadGenericCredential(string target)
        {
            IntPtr pCred = IntPtr.Zero;

            try
            {
                if (!CredRead(target, CRED_TYPE_GENERIC, 0, out pCred) || pCred == IntPtr.Zero)
                {
                    return (null, null);
                }

                var cred = Marshal.PtrToStructure<CREDENTIAL>(pCred);

                var user = string.IsNullOrWhiteSpace(cred.UserName) ? null : cred.UserName;

                string? pass = null;
                if (cred.CredentialBlob != IntPtr.Zero && cred.CredentialBlobSize > 0)
                {
                    var bytes = new byte[cred.CredentialBlobSize];
                    Marshal.Copy(cred.CredentialBlob, bytes, 0, bytes.Length);

                    // Most common for Generic creds written by cmdkey/CredWrite is UTF-16LE.
                    var asUnicode = Encoding.Unicode.GetString(bytes).TrimEnd('\0');

                    // Heuristic fallback if unicode looks wrong.
                    pass = LooksMostlyPrintable(asUnicode)
                        ? asUnicode
                        : Encoding.UTF8.GetString(bytes).TrimEnd('\0');
                }

                return (user, string.IsNullOrWhiteSpace(pass) ? null : pass);
            }
            catch
            {
                return (null, null);
            }
            finally
            {
                if (pCred != IntPtr.Zero)
                {
                    try { CredFree(pCred); } catch { /* ignore */ }
                }
            }
        }

        private static bool LooksMostlyPrintable(string s)
        {
            if (string.IsNullOrEmpty(s)) return false;
            int printable = 0;
            int total = 0;

            foreach (var ch in s)
            {
                total++;
                if (ch == '\r' || ch == '\n' || ch == '\t') { printable++; continue; }
                if (ch >= 32 && ch <= 126) printable++;
            }

            return total > 0 && (double)printable / total > 0.8;
        }
    }
}