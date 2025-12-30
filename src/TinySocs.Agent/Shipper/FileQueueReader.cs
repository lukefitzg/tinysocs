using System;
using System.Collections.Generic;
using System.IO;
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
    /// Queue reader (v2):
    /// - Reads segment files incrementally using per-segment byte offsets (in-memory cursors).
    /// - Always prefers the oldest segment with unread data.
    /// - Returns a batch (max events / max bytes).
    /// - AcknowledgeAsync commits the last returned batch for the segment and may delete fully-acked old segments.
    ///
    /// Notes:
    /// - Cursors are in-memory only (reset on agent restart).
    /// - Designed to avoid replaying the same lines forever in a tight shipper loop.
    /// </summary>
    public sealed class FileQueueReader : IQueueReader
    {
        private readonly ILogger<FileQueueReader> _logger;
        private readonly AgentConfig _config;

        private static readonly JsonSerializerOptions _jsonOptions = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        };

        // In-memory per-segment byte offsets (committed/acked).
        private readonly Dictionary<string, long> _segmentOffsets = new(StringComparer.OrdinalIgnoreCase);

        // Quarantine poison segments that repeatedly fail to parse.
        // In-memory counters are fine for Phase 8; reset on restart.
        private const int QuarantineThreshold = 20;
        private readonly Dictionary<string, int> _segmentParseFailures = new(StringComparer.OrdinalIgnoreCase);

        // Tracks the last batch we returned, so AcknowledgeAsync(count) can commit it.
        private readonly object _stateLock = new object();
        private LastBatchState? _lastBatch;

        private sealed class LastBatchState
        {
            public string SegmentPath { get; init; } = string.Empty;
            public int Count { get; init; }
            public long NewOffset { get; init; }
            public bool ReachedEofAtReadTime { get; init; }
        }

        public FileQueueReader(
            ILogger<FileQueueReader> logger,
            AgentConfig config)
        {
            _logger = logger;
            _config = config;
        }

        public Task<IReadOnlyList<AgentEvent>> ReadBatchAsync(
            int maxEvents,
            int maxBytes,
            CancellationToken cancellationToken)
        {
            var results = new List<AgentEvent>();

            // Clear lastBatch if we're about to produce a new one.
            lock (_stateLock)
            {
                _lastBatch = null;
            }

            var dir = _config.Queue.Path;
            if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir))
            {
                return Task.FromResult((IReadOnlyList<AgentEvent>)results);
            }

            var segments = Directory.GetFiles(dir, "segment-*.jsonl");
            Array.Sort(segments, StringComparer.Ordinal); // oldest first

            if (segments.Length == 0)
            {
                return Task.FromResult((IReadOnlyList<AgentEvent>)results);
            }

            // Choose the oldest segment that has unread data (or the oldest segment overall if unknown).
            string? chosen = null;
            long startOffset = 0;

            foreach (var seg in segments)
            {
                cancellationToken.ThrowIfCancellationRequested();

                long offset;
                lock (_stateLock)
                {
                    if (!_segmentOffsets.TryGetValue(seg, out offset))
                    {
                        offset = 0;
                        _segmentOffsets[seg] = 0;
                    }
                }

                long length = 0;
                try
                {
                    var fi = new FileInfo(seg);
                    length = fi.Exists ? fi.Length : 0;
                }
                catch
                {
                    length = 0;
                }

                if (length > offset)
                {
                    chosen = seg;
                    startOffset = offset;
                    break;
                }
            }

            // If none had unread data, nothing to do.
            if (chosen == null)
            {
                return Task.FromResult((IReadOnlyList<AgentEvent>)results);
            }

            bool quarantinedThisBatch = false;

            try
            {
                var (lines, newOffset, reachedEof) = ReadLinesFromOffset(
                    chosen,
                    startOffset,
                    maxEvents,
                    maxBytes,
                    cancellationToken);

                int approxBytes = 0;

                foreach (var line in lines)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    if (string.IsNullOrWhiteSpace(line))
                        continue;

                    try
                    {
                        var evt = ParseAgentEvent(line);
                        if (evt != null)
                        {
                            results.Add(evt);
                            approxBytes += line.Length;

                            // Success: reset failure streak for this segment.
                            lock (_stateLock)
                            {
                                _segmentParseFailures.Remove(chosen);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        int failures;
                        lock (_stateLock)
                        {
                            _segmentParseFailures.TryGetValue(chosen, out failures);
                            failures++;
                            _segmentParseFailures[chosen] = failures;
                        }

                        _logger.LogWarning(
                            ex,
                            "Failed to parse event from line in {Path} (failures={Failures})",
                            chosen,
                            failures);

                        if (failures >= QuarantineThreshold)
                        {
                            QuarantineSegment(chosen, $"Exceeded parse-failure threshold ({failures} >= {QuarantineThreshold})");
                            quarantinedThisBatch = true;
                            break; // stop processing this segment for this batch
                        }
                    }
                }

                // Record last batch state for AcknowledgeAsync only if we didn't quarantine the segment.
                if (!quarantinedThisBatch)
                {
                    lock (_stateLock)
                    {
                        _lastBatch = new LastBatchState
                        {
                            SegmentPath = chosen,
                            Count = results.Count,
                            NewOffset = newOffset,
                            ReachedEofAtReadTime = reachedEof
                        };
                    }
                }
                else
                {
                    // If we quarantined, we intentionally avoid committing offsets for this segment.
                    // Returning results is fine: the segment is no longer in the hot path.
                    lock (_stateLock)
                    {
                        _lastBatch = null;
                    }
                }

                _logger.LogDebug(
                    "ReadBatch: segment={Segment} startOffset={StartOffset} newOffset={NewOffset} events={Events} approxBytes={Bytes} eofAtRead={Eof} quarantined={Quarantined}",
                    Path.GetFileName(chosen),
                    startOffset,
                    newOffset,
                    results.Count,
                    approxBytes,
                    reachedEof,
                    quarantinedThisBatch);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error reading queue segment {Path}", chosen);
            }

            return Task.FromResult((IReadOnlyList<AgentEvent>)results);
        }

        /// <summary>
        /// Commits the last returned batch:
        /// - Advances the segment offset to the newOffset captured during ReadBatchAsync.
        /// - Optionally deletes fully-acked old segments (never deletes the newest segment to avoid racing the writer).
        /// </summary>
        public Task AcknowledgeAsync(int count, CancellationToken cancellationToken)
        {
            LastBatchState? batch;

            lock (_stateLock)
            {
                batch = _lastBatch;
            }

            if (batch == null)
            {
                return Task.CompletedTask;
            }

            if (count <= 0 || count != batch.Count)
            {
                _logger.LogWarning(
                    "AcknowledgeAsync called with count={Count}, but last batch count was {LastCount}. Not committing offsets.",
                    count,
                    batch.Count);

                return Task.CompletedTask;
            }

            lock (_stateLock)
            {
                _segmentOffsets[batch.SegmentPath] = batch.NewOffset;
                _lastBatch = null;
            }

            TryDeleteFullyAckedOldSegments(cancellationToken);

            return Task.CompletedTask;
        }

        private void TryDeleteFullyAckedOldSegments(CancellationToken cancellationToken)
        {
            var dir = _config.Queue.Path;
            if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir))
                return;

            string[] segments;
            try
            {
                segments = Directory.GetFiles(dir, "segment-*.jsonl");
                Array.Sort(segments, StringComparer.Ordinal); // oldest first
            }
            catch
            {
                return;
            }

            if (segments.Length == 0)
                return;

            // Never delete the newest segment (writer is most likely appending to it).
            var newest = segments[segments.Length - 1];

            for (int i = 0; i < segments.Length - 1; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var seg = segments[i];
                if (string.Equals(seg, newest, StringComparison.OrdinalIgnoreCase))
                    continue;

                long offset;
                lock (_stateLock)
                {
                    if (!_segmentOffsets.TryGetValue(seg, out offset))
                        offset = 0;
                }

                long length;
                try
                {
                    var fi = new FileInfo(seg);
                    if (!fi.Exists)
                    {
                        lock (_stateLock)
                        {
                            _segmentOffsets.Remove(seg);
                            _segmentParseFailures.Remove(seg);
                        }
                        continue;
                    }
                    length = fi.Length;
                }
                catch
                {
                    continue;
                }

                if (offset >= length && length > 0)
                {
                    try
                    {
                        File.Delete(seg);
                        lock (_stateLock)
                        {
                            _segmentOffsets.Remove(seg);
                            _segmentParseFailures.Remove(seg);
                        }

                        _logger.LogInformation("Deleted fully-acked queue segment {Segment}", Path.GetFileName(seg));
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to delete fully-acked queue segment {Segment}", seg);
                    }
                }
            }
        }

        private void QuarantineSegment(string segmentPath, string reason)
        {
            try
            {
                var badPath = segmentPath + ".bad";

                // Best-effort unique name if it already exists
                if (File.Exists(badPath))
                {
                    badPath = segmentPath + $".{DateTimeOffset.UtcNow:yyyyMMddHHmmss}.bad";
                }

                File.Move(segmentPath, badPath);

                lock (_stateLock)
                {
                    _segmentOffsets.Remove(segmentPath);
                    _segmentParseFailures.Remove(segmentPath);

                    // If the last batch pointed at this segment, drop it so we don't ack nonsense.
                    if (_lastBatch != null && string.Equals(_lastBatch.SegmentPath, segmentPath, StringComparison.OrdinalIgnoreCase))
                    {
                        _lastBatch = null;
                    }
                }

                _logger.LogWarning(
                    "Quarantined queue segment {Segment} -> {BadSegment}. Reason: {Reason}",
                    Path.GetFileName(segmentPath),
                    Path.GetFileName(badPath),
                    reason);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to quarantine poison segment {Segment}", segmentPath);
            }
        }

        /// <summary>
        /// Reads JSONL lines from a file starting at a byte offset.
        ///
        /// Key guarantees:
        /// - We only return COMPLETE lines that end with '\n'.
        /// - We NEVER advance the offset into the middle of a line.
        /// - We only accept a line if its first non-whitespace character is '{' or '['.
        ///   (No substring-hunting for '{' inside arbitrary garbage/partial content.)
        /// </summary>
        private static (List<string> Lines, long NewOffset, bool ReachedEofAtReadTime) ReadLinesFromOffset(
            string path,
            long startOffset,
            int maxEvents,
            int maxBytes,
            CancellationToken cancellationToken)
        {
            var lines = new List<string>();
            if (maxEvents <= 0 || maxBytes <= 0)
                return (lines, startOffset, false);

            using var fs = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite);

            if (startOffset < 0) startOffset = 0;
            if (startOffset > fs.Length) startOffset = fs.Length;

            fs.Seek(startOffset, SeekOrigin.Begin);

            var buffer = new byte[64 * 1024];

            int totalBytes = 0;
            long currentOffset = startOffset;

            // Collect raw bytes for the current line.
            var lineBytes = new List<byte>(4096);

            while (!cancellationToken.IsCancellationRequested)
            {
                if (lines.Count >= maxEvents || totalBytes >= maxBytes)
                    break;

                int read = fs.Read(buffer, 0, buffer.Length);
                if (read <= 0)
                {
                    // EOF. If we have a partial line buffered, rewind to its start and DO NOT claim EOF reached,
                    // because the writer may append and complete it later.
                    if (lineBytes.Count > 0)
                    {
                        currentOffset -= lineBytes.Count;
                        lineBytes.Clear();
                        return (lines, currentOffset, false);
                    }

                    return (lines, currentOffset, true);
                }

                int bufIndex = 0;
                while (bufIndex < read)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    // If limits hit mid-buffer, rewind to the start of any partial line.
                    if (lines.Count >= maxEvents || totalBytes >= maxBytes)
                    {
                        if (lineBytes.Count > 0)
                        {
                            currentOffset -= lineBytes.Count;
                            lineBytes.Clear();
                        }
                        return (lines, currentOffset, false);
                    }

                    byte b = buffer[bufIndex++];
                    currentOffset++;
                    totalBytes++;

                    if (b == (byte)'\n')
                    {
                        // Trim CR if present.
                        if (lineBytes.Count > 0 && lineBytes[^1] == (byte)'\r')
                        {
                            lineBytes.RemoveAt(lineBytes.Count - 1);
                        }

                        if (TryDecodeJsonLine(lineBytes, out var line))
                        {
                            lines.Add(line);
                        }

                        lineBytes.Clear();

                        if (lines.Count >= maxEvents || totalBytes >= maxBytes)
                            break;
                    }
                    else
                    {
                        lineBytes.Add(b);
                    }
                }
            }

            // If we stopped with a partial line buffered, rewind so we start clean next time.
            if (lineBytes.Count > 0)
            {
                currentOffset -= lineBytes.Count;
                lineBytes.Clear();
                return (lines, currentOffset, false);
            }

            return (lines, currentOffset, false);
        }

        /// <summary>
        /// Byte-level validation + decode:
        /// - Strips UTF-8 BOM (EF BB BF) at the beginning of a line
        /// - Skips leading ASCII whitespace
        /// - Accepts ONLY if first non-whitespace byte is '{' or '['
        /// - Decodes as UTF-8 (replacement fallback). If decode fails, returns false.
        /// </summary>
        private static bool TryDecodeJsonLine(List<byte> raw, out string line)
        {
            line = string.Empty;

            if (raw == null || raw.Count == 0)
                return false;

            int i = 0;

            // Strip UTF-8 BOM if present at start of line
            if (raw.Count >= 3 && raw[0] == 0xEF && raw[1] == 0xBB && raw[2] == 0xBF)
            {
                i = 3;
            }

            // Skip ASCII whitespace
            while (i < raw.Count)
            {
                byte b = raw[i];
                if (b == (byte)' ' || b == (byte)'\t')
                {
                    i++;
                    continue;
                }
                break;
            }

            if (i >= raw.Count)
                return false;

            // Strict: only accept JSON object/array at the start (after whitespace/BOM)
            byte first = raw[i];
            if (first != (byte)'{' && first != (byte)'[')
            {
                return false;
            }

            try
            {
                // Decode entire line bytes as UTF-8.
                // If there are malformed sequences, .NET will replace rather than throw;
                // but since we validated the first token, JSON parsing is much less likely to choke on random prefixes.
                line = Encoding.UTF8.GetString(raw.ToArray());

                // Also strip a BOM if it became a char (paranoia).
                line = line.TrimStart('\uFEFF');

                // Trim only leading whitespace (JSON parser allows it; but keep it clean)
                line = line.TrimStart();

                // Final sanity: must start with { or [
                if (!(line.StartsWith("{", StringComparison.Ordinal) || line.StartsWith("[", StringComparison.Ordinal)))
                    return false;

                return true;
            }
            catch
            {
                return false;
            }
        }

        private static AgentEvent? ParseAgentEvent(string line)
        {
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;

            // ts: stored as ISO8601 string in the queue; fall back to now on parse failure.
            DateTimeOffset ts;
            if (root.TryGetProperty("ts", out var tsProp) && tsProp.ValueKind == JsonValueKind.String)
            {
                var tsString = tsProp.GetString();
                if (!DateTimeOffset.TryParse(tsString, out ts))
                {
                    ts = DateTimeOffset.UtcNow;
                }
            }
            else
            {
                ts = DateTimeOffset.UtcNow;
            }

            string input = root.TryGetProperty("input", out var inputProp) && inputProp.ValueKind == JsonValueKind.String
                ? (inputProp.GetString() ?? string.Empty)
                : string.Empty;

            string channel = root.TryGetProperty("channel", out var chProp) && chProp.ValueKind == JsonValueKind.String
                ? (chProp.GetString() ?? string.Empty)
                : string.Empty;

            int? eventId = null;
            if (root.TryGetProperty("eventId", out var evtIdProp) &&
                evtIdProp.ValueKind == JsonValueKind.Number &&
                evtIdProp.TryGetInt32(out var tmpId))
            {
                eventId = tmpId;
            }

            string openSearchIndex = root.TryGetProperty("openSearchIndex", out var idxProp) && idxProp.ValueKind == JsonValueKind.String
                ? (idxProp.GetString() ?? string.Empty)
                : string.Empty;

            Dictionary<string, object?> body = new Dictionary<string, object?>();
            if (root.TryGetProperty("body", out var bodyProp) &&
                bodyProp.ValueKind != JsonValueKind.Null &&
                bodyProp.ValueKind != JsonValueKind.Undefined)
            {
                var raw = bodyProp.GetRawText();
                var parsed = JsonSerializer.Deserialize<Dictionary<string, object?>>(raw, _jsonOptions);
                if (parsed != null)
                {
                    body = parsed;
                }
            }

            return new AgentEvent
            {
                Ts = ts,
                Input = input,
                Channel = channel,
                EventId = eventId,
                OpenSearchIndex = openSearchIndex,
                Body = body
            };
        }
    }
}