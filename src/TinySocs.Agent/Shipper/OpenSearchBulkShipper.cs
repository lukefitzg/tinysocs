using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Runtime.InteropServices;
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
    /// - POSTs to {url}/_bulk (optionally with ingest pipeline)
    /// - On success (HTTP + bulk "errors": false): acknowledges the batch
    /// - On failure: leaves the batch in the queue and backs off
    ///
    /// Key behaviour: idempotency
    /// - Uses a deterministic _id when possible (computer + channel + record_id) to prevent duplicates.
    /// </summary>
    public sealed class OpenSearchBulkShipper : IShipper
    {
        private readonly ILogger<OpenSearchBulkShipper> _logger;
        private readonly AgentConfig _config;
        private readonly IQueueReader _queueReader;
        private readonly HttpClient _httpClient;
        private readonly Uri _bulkUri;
        private readonly JsonSerializerOptions _jsonOptions;

        // Debug guard: only dump a tiny bulk sample once per process start.
        private readonly bool _debugBulk;
        private bool _bulkSampleLogged;

        // CredMan fallback (best-effort)
        private readonly string? _credManTarget;

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

            // Pull CredMan target from config if present (siem_credentials.target).
            _credManTarget = TryGetCredManTargetFromConfig(_config);

            // Ensure we always send Authorization (pre-emptive Basic) when creds are available.
            // Relying on handler.Credentials often means "only after a 401 challenge", and if the
            // handler/client gets recreated or challenge state is lost, you'll loop on 401s.
            TryConfigurePreemptiveBasicAuth(_httpClient, output);

            var baseUri = new Uri(output.Url);
            _bulkUri = BuildBulkUri(baseUri, output.Pipeline);

            _jsonOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
            };

            _debugBulk = IsTruthyEnv("TINYSOCS_DEBUG_BULK");
            _bulkSampleLogged = false;
        }

        public async Task RunAsync(CancellationToken stoppingToken)
        {
            var output = _config.Output;

            _logger.LogInformation(
                "OpenSearchBulkShipper initialised with url={Url}, bulkUri={BulkUri}, indexPattern={IndexPattern}, sslVerify={SslVerify}, batchSizeEvents={BatchSizeEvents}, batchSizeBytes={BatchSizeBytes}, flushIntervalMs={FlushIntervalMs}",
                output.Url,
                _bulkUri,
                output.IndexPattern,
                output.SslVerify,
                output.Bulk.BatchSizeEvents,
                output.Bulk.BatchSizeBytes,
                output.Bulk.FlushIntervalMs);

            if (_debugBulk)
            {
                _logger.LogWarning("TINYSOCS_DEBUG_BULK is enabled. Will log one bulk payload sample (first 2 lines) once per process start.");
            }

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

                    // DEBUG: dump only the first 2 NDJSON lines (action + doc) once per process start.
                    if (_debugBulk && !_bulkSampleLogged)
                    {
                        _bulkSampleLogged = true;
                        var sample = GetFirstNdjsonLines(payload, 2, 8192);
                        _logger.LogWarning("BULK PAYLOAD SAMPLE (first 2 lines):\n{Sample}", sample);
                    }

                    var content = new StringContent(payload, Encoding.UTF8, "application/x-ndjson");

                    _logger.LogInformation(
                        "Shipping {Count} event(s) to OpenSearch index {Index} at {Url}.",
                        batch.Count,
                        indexName,
                        output.Url);

                    using var response = await _httpClient.PostAsync(_bulkUri, content, stoppingToken)
                        .ConfigureAwait(false);

                    var responseBody = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                    if (!response.IsSuccessStatusCode)
                    {
                        _logger.LogError(
                            "OpenSearch _bulk request failed with status {StatusCode}. Body: {Body}",
                            (int)response.StatusCode,
                            Truncate(responseBody, 4096));

                        failureCount++;
                        await BackoffAsync(failureCount, _config.Output.Retry, stoppingToken).ConfigureAwait(false);
                        // Do NOT acknowledge; events will be retried.
                        continue;
                    }

                    // Parse _bulk response and ensure errors:false before acknowledging.
                    if (!IsBulkResponseSuccessful(responseBody, out var errorSummary))
                    {
                        _logger.LogError(
                            "OpenSearch _bulk response reported errors. {Summary}",
                            errorSummary);

                        failureCount++;
                        await BackoffAsync(failureCount, _config.Output.Retry, stoppingToken).ConfigureAwait(false);
                        // Do NOT acknowledge; events will be retried.
                        continue;
                    }

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
            var sb = new StringBuilder(capacity: batch.Count * 512);

            foreach (var evt in batch)
            {
                var docId = TryBuildDeterministicId(evt);

                object action;
                if (!string.IsNullOrWhiteSpace(docId))
                {
                    action = new
                    {
                        index = new
                        {
                            _index = indexName,
                            _id = docId
                        }
                    };
                }
                else
                {
                    // Fallback: no deterministic _id available; OpenSearch will generate one.
                    action = new
                    {
                        index = new
                        {
                            _index = indexName
                        }
                    };
                }

                sb.AppendLine(JsonSerializer.Serialize(action, _jsonOptions));
                sb.AppendLine(JsonSerializer.Serialize(evt, _jsonOptions));
            }

            return sb.ToString();
        }

        private static Uri BuildBulkUri(Uri baseUri, string? pipeline)
        {
            // /_bulk or /_bulk?pipeline=...
            var path = "/_bulk";
            if (string.IsNullOrWhiteSpace(pipeline))
            {
                return new Uri(baseUri, path);
            }

            var encoded = Uri.EscapeDataString(pipeline);
            return new Uri(baseUri, $"{path}?pipeline={encoded}");
        }

        private static string ResolveIndexName(string pattern, DateTimeOffset now)
        {
            // Minimal implementation: replace {yyyy.MM.dd} with today's UTC date.
            var date = now.UtcDateTime.ToString("yyyy.MM.dd");
            return pattern.Replace("{yyyy.MM.dd}", date);
        }

        /// <summary>
        /// Build an idempotent document id when possible.
        /// For Windows Event Logs, (computer, channel, record_id) is a strong key.
        /// We look for these in evt.Body:
        /// - winlog.computer_name
        /// - winlog.channel
        /// - event.record_id or winlog.record_id
        ///
        /// Returns null if insufficient data.
        /// </summary>
        private static string? TryBuildDeterministicId(AgentEvent evt)
        {
            try
            {
                if (evt.Body == null)
                {
                    return null;
                }

                var computer = GetNestedString(evt.Body, "winlog", "computer_name")
                               ?? GetNestedString(evt.Body, "winlog", "computerName"); // just in case

                var channel = GetNestedString(evt.Body, "winlog", "channel")
                              ?? evt.Channel;

                var recordId =
                    GetNestedLongish(evt.Body, "event", "record_id")
                    ?? GetNestedLongish(evt.Body, "winlog", "record_id");

                if (string.IsNullOrWhiteSpace(computer) ||
                    string.IsNullOrWhiteSpace(channel) ||
                    !recordId.HasValue ||
                    recordId.Value <= 0)
                {
                    return null;
                }

                // Keep it simple and stable.
                // Example: WINHOST01|Security|51660
                return $"{computer}|{channel}|{recordId.Value}";
            }
            catch
            {
                return null;
            }
        }

        private static string? GetNestedString(Dictionary<string, object?> root, string key1, string key2)
        {
            if (!root.TryGetValue(key1, out var lvl1) || lvl1 == null)
                return null;

            if (lvl1 is JsonElement je1)
            {
                if (je1.ValueKind == JsonValueKind.Object &&
                    je1.TryGetProperty(key2, out var je2) &&
                    je2.ValueKind == JsonValueKind.String)
                {
                    return je2.GetString();
                }
                return null;
            }

            if (lvl1 is Dictionary<string, object?> dict1)
            {
                if (dict1.TryGetValue(key2, out var v) && v != null)
                {
                    if (v is string s) return s;
                    if (v is JsonElement je2 && je2.ValueKind == JsonValueKind.String) return je2.GetString();
                }
                return null;
            }

            return null;
        }

        private static long? GetNestedLongish(Dictionary<string, object?> root, string key1, string key2)
        {
            if (!root.TryGetValue(key1, out var lvl1) || lvl1 == null)
                return null;

            if (lvl1 is JsonElement je1)
            {
                if (je1.ValueKind == JsonValueKind.Object &&
                    je1.TryGetProperty(key2, out var je2))
                {
                    if (je2.ValueKind == JsonValueKind.Number && je2.TryGetInt64(out var n))
                        return n;

                    if (je2.ValueKind == JsonValueKind.String && long.TryParse(je2.GetString(), out var ns))
                        return ns;
                }
                return null;
            }

            if (lvl1 is Dictionary<string, object?> dict1)
            {
                if (!dict1.TryGetValue(key2, out var v) || v == null)
                    return null;

                if (v is long l) return l;
                if (v is int i) return i;
                if (v is JsonElement je2)
                {
                    if (je2.ValueKind == JsonValueKind.Number && je2.TryGetInt64(out var n))
                        return n;

                    if (je2.ValueKind == JsonValueKind.String && long.TryParse(je2.GetString(), out var ns))
                        return ns;
                }
                if (v is string s && long.TryParse(s, out var ls))
                    return ls;

                return null;
            }

            return null;
        }

        private static bool IsBulkResponseSuccessful(string responseBody, out string summary)
        {
            summary = "Unknown bulk response.";

            if (string.IsNullOrWhiteSpace(responseBody))
            {
                summary = "Empty bulk response body.";
                return false;
            }

            try
            {
                using var doc = JsonDocument.Parse(responseBody);
                var root = doc.RootElement;

                if (root.TryGetProperty("errors", out var errorsProp) &&
                    errorsProp.ValueKind == JsonValueKind.True)
                {
                    // Pull a small sample of the first few item errors for logging.
                    var sb = new StringBuilder();
                    sb.Append("Bulk response errors=true. Sample item errors: ");

                    if (root.TryGetProperty("items", out var itemsProp) &&
                        itemsProp.ValueKind == JsonValueKind.Array)
                    {
                        int shown = 0;
                        foreach (var item in itemsProp.EnumerateArray())
                        {
                            if (shown >= 5) break;

                            // items are like: { "index": { "status": 201, ... , "error": {...}}}
                            if (item.ValueKind != JsonValueKind.Object) continue;

                            foreach (var op in item.EnumerateObject())
                            {
                                if (op.Value.ValueKind != JsonValueKind.Object) continue;

                                var opObj = op.Value;

                                int status = 0;
                                if (opObj.TryGetProperty("status", out var st) && st.ValueKind == JsonValueKind.Number)
                                {
                                    status = st.GetInt32();
                                }

                                if (opObj.TryGetProperty("error", out var err) && err.ValueKind == JsonValueKind.Object)
                                {
                                    var type = err.TryGetProperty("type", out var t) && t.ValueKind == JsonValueKind.String
                                        ? t.GetString()
                                        : "unknown";

                                    var reason = err.TryGetProperty("reason", out var r) && r.ValueKind == JsonValueKind.String
                                        ? r.GetString()
                                        : null;

                                    sb.Append($"[{op.Name} status={status} type={type} reason={Truncate(reason ?? "", 256)}] ");
                                    shown++;
                                }
                                else if (status >= 400)
                                {
                                    sb.Append($"[{op.Name} status={status}] ");
                                    shown++;
                                }

                                if (shown >= 5) break;
                            }
                        }
                    }

                    summary = sb.ToString();
                    return false;
                }

                // If "errors" is missing, be conservative.
                if (!root.TryGetProperty("errors", out _))
                {
                    summary = "Bulk response missing 'errors' field; treating as failure.";
                    return false;
                }

                summary = "Bulk response errors=false.";
                return true;
            }
            catch (Exception ex)
            {
                summary = $"Failed to parse bulk response JSON: {ex.Message}. Body: {Truncate(responseBody, 2048)}";
                return false;
            }
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

        private static bool IsTruthyEnv(string name)
        {
            try
            {
                var v = Environment.GetEnvironmentVariable(name);
                if (string.IsNullOrWhiteSpace(v)) return false;
                v = v.Trim();
                return v.Equals("1", StringComparison.OrdinalIgnoreCase) ||
                       v.Equals("true", StringComparison.OrdinalIgnoreCase) ||
                       v.Equals("yes", StringComparison.OrdinalIgnoreCase) ||
                       v.Equals("on", StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }

        private static string GetFirstNdjsonLines(string ndjson, int lines, int maxChars)
        {
            if (string.IsNullOrEmpty(ndjson)) return string.Empty;

            var sb = new StringBuilder();
            int start = 0;
            int found = 0;

            while (found < lines && start < ndjson.Length && sb.Length < maxChars)
            {
                int idx = ndjson.IndexOf('\n', start);
                string line;
                if (idx < 0)
                {
                    line = ndjson.Substring(start);
                    start = ndjson.Length;
                }
                else
                {
                    line = ndjson.Substring(start, idx - start);
                    start = idx + 1;
                }

                if (line.EndsWith("\r", StringComparison.Ordinal))
                {
                    line = line.Substring(0, line.Length - 1);
                }

                if (line.Length > 0)
                {
                    sb.AppendLine(line);
                    found++;
                }
            }

            var s = sb.ToString();
            return s.Length <= maxChars ? s : s.Substring(0, maxChars) + "...(truncated)";
        }

        /// <summary>
        /// Best-effort: configure pre-emptive Basic auth header if we can find creds.
        /// Uses reflection so we don't hard-couple to a specific OutputConfig schema.
        ///
        /// Supported sources:
        /// - env vars:
        ///   TINYSOCS_SIEM_USER / TINYSOCS_SIEM_PASS
        ///   SIEM_USER / SIEM_PASS
        ///   OPENSEARCH_USERNAME / OPENSEARCH_PASSWORD
        /// - output.Username / output.Password (common)
        /// - output.User / output.Pass (common)
        /// - output.BasicAuthUser / output.BasicAuthPassword (common)
        /// - output.Auth.Username / output.Auth.Password (common)
        /// - Windows Credential Manager (Generic):
        ///   target = siem_credentials.target (if present), else TinySocs/SIEM/Creds
        ///   ALSO tries "target=<name>" because cmdkey output indicates you currently stored that exact string.
        /// </summary>
        private void TryConfigurePreemptiveBasicAuth(HttpClient httpClient, object output)
        {
            try
            {
                // If someone already set it upstream, respect that.
                if (httpClient.DefaultRequestHeaders.Authorization != null)
                {
                    return;
                }

                var (user, pass, source) = TryGetUserPass(output);

                if (string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(pass))
                {
                    _logger.LogWarning("OpenSearch auth not configured (no username/password found). Requests may be sent without Authorization header.");
                    return;
                }

                var token = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{user}:{pass}"));
                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", token);

                _logger.LogInformation(
                    "OpenSearch auth configured (pre-emptive Basic). source={Source}, user={User}, pass_len={PassLen}",
                    source,
                    user,
                    pass.Length);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to configure OpenSearch pre-emptive Basic auth header. Requests may be sent without Authorization header.");
            }
        }

        private (string? user, string? pass, string source) TryGetUserPass(object output)
        {
            // 1) Env vars (explicit override)
            var envUser = GetEnvFirst("TINYSOCS_SIEM_USER", "SIEM_USER", "OPENSEARCH_USERNAME");
            var envPass = GetEnvFirst("TINYSOCS_SIEM_PASS", "SIEM_PASS", "OPENSEARCH_PASSWORD");
            if (!string.IsNullOrWhiteSpace(envUser) && !string.IsNullOrWhiteSpace(envPass))
            {
                return (envUser, envPass, "env");
            }

            // 2) Flat properties on output (common)
            var user =
                GetStringProp(output, "Username") ??
                GetStringProp(output, "User") ??
                GetStringProp(output, "BasicAuthUser") ??
                GetStringProp(output, "BasicUser") ??
                GetStringProp(output, "OpenSearchUser");

            var pass =
                GetStringProp(output, "Password") ??
                GetStringProp(output, "Pass") ??
                GetStringProp(output, "BasicAuthPassword") ??
                GetStringProp(output, "BasicPass") ??
                GetStringProp(output, "OpenSearchPassword");

            if (!string.IsNullOrWhiteSpace(user) && !string.IsNullOrWhiteSpace(pass))
            {
                return (user, pass, "output");
            }

            // 3) Nested Auth object (common)
            var authObj = GetObjProp(output, "Auth") ?? GetObjProp(output, "Authentication");
            if (authObj != null)
            {
                var authUser =
                    GetStringProp(authObj, "Username") ??
                    GetStringProp(authObj, "User");

                var authPass =
                    GetStringProp(authObj, "Password") ??
                    GetStringProp(authObj, "Pass");

                if (!string.IsNullOrWhiteSpace(authUser) && !string.IsNullOrWhiteSpace(authPass))
                {
                    return (authUser, authPass, "output.auth");
                }
            }

            // 4) CredMan fallback (Generic credential)
            var target = string.IsNullOrWhiteSpace(_credManTarget) ? "TinySocs/SIEM/Creds" : _credManTarget!;
            var (cmUser, cmPass) = TryReadGenericCredential(target);

            if (!string.IsNullOrWhiteSpace(cmUser) && !string.IsNullOrWhiteSpace(cmPass))
            {
                return (cmUser, cmPass, $"credman:{target}");
            }

            // Some cmdkey writes end up with the literal target "target=<name>"
            var alt = target.StartsWith("target=", StringComparison.OrdinalIgnoreCase)
                ? target.Substring("target=".Length)
                : "target=" + target;

            var (cmUser2, cmPass2) = TryReadGenericCredential(alt);
            if (!string.IsNullOrWhiteSpace(cmUser2) && !string.IsNullOrWhiteSpace(cmPass2))
            {
                return (cmUser2, cmPass2, $"credman:{alt}");
            }

            return (null, null, "none");
        }

        private static string? GetEnvFirst(params string[] names)
        {
            foreach (var n in names)
            {
                try
                {
                    var v = Environment.GetEnvironmentVariable(n);
                    if (!string.IsNullOrWhiteSpace(v))
                    {
                        return v.Trim();
                    }
                }
                catch
                {
                    // ignore
                }
            }
            return null;
        }

        private static string? GetStringProp(object obj, string propName)
        {
            try
            {
                var pi = obj.GetType().GetProperty(propName, BindingFlags.Instance | BindingFlags.Public | BindingFlags.IgnoreCase);
                if (pi == null) return null;
                if (pi.PropertyType != typeof(string)) return null;
                return (string?)pi.GetValue(obj);
            }
            catch
            {
                return null;
            }
        }

        private static object? GetObjProp(object obj, string propName)
        {
            try
            {
                var pi = obj.GetType().GetProperty(propName, BindingFlags.Instance | BindingFlags.Public | BindingFlags.IgnoreCase);
                return pi?.GetValue(obj);
            }
            catch
            {
                return null;
            }
        }

        private static string? TryGetCredManTargetFromConfig(object config)
        {
            try
            {
                // config.SiemCredentials.Target
                var sc = GetObjProp(config, "SiemCredentials") ?? GetObjProp(config, "SiemCredential") ?? GetObjProp(config, "SiemCreds");
                if (sc == null) return null;

                var source = GetStringProp(sc, "Source");
                var target = GetStringProp(sc, "Target");

                if (!string.IsNullOrWhiteSpace(source) &&
                    source.Equals("credman", StringComparison.OrdinalIgnoreCase) &&
                    !string.IsNullOrWhiteSpace(target))
                {
                    return target.Trim();
                }

                // Even if source isn't "credman", a target is still a useful hint.
                if (!string.IsNullOrWhiteSpace(target))
                {
                    return target.Trim();
                }
            }
            catch
            {
                // ignore
            }
            return null;
        }

        // -----------------------
        // CredMan (Credential Manager) helpers
        // -----------------------

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

            // Accept if >= 80% printable ASCII-ish.
            return total > 0 && (printable * 100 / total) >= 80;
        }
    }
}