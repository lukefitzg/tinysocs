using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TinySocs.Agent.Configuration;
using TinySocs.Agent.Models;

namespace TinySocs.Agent.Queueing
{
    /// <summary>
    /// Disk-backed queue implementation (JSONL segment files).
    /// Very simple v1:
    /// - One active segment file at a time
    /// - Append JSON lines
    /// - Rotate when SegmentMaxBytes is exceeded
    /// </summary>
    public sealed class FileQueueWriter : IQueueWriter
    {
        private readonly ILogger<FileQueueWriter> _logger;
        private readonly QueueConfig _config;

        // Synchronize access to segment state + file writes
        private readonly SemaphoreSlim _lock = new(1, 1);

        private string? _currentSegmentPath;
        private long _currentSegmentBytes;

        private readonly JsonSerializerOptions _jsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = false
        };

        private static readonly byte[] Newline = new byte[] { (byte)'\n' };

        public FileQueueWriter(ILogger<FileQueueWriter> logger, AgentConfig agentConfig)
        {
            _logger = logger;
            _config = agentConfig.Queue;

            // Ensure queue directory exists
            try
            {
                Directory.CreateDirectory(_config.Path);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create queue directory at {Path}", _config.Path);
                throw;
            }
        }

        public async Task EnqueueAsync(AgentEvent evt, CancellationToken cancellationToken)
        {
            // Serialize to a single JSON line as UTF-8 bytes.
            // We write bytes directly to avoid BOM/encoding surprises from StreamWriter.
            var jsonBytes = JsonSerializer.SerializeToUtf8Bytes(evt, _jsonOptions);
            var bytes = jsonBytes.Length + Newline.Length;

            await _lock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                cancellationToken.ThrowIfCancellationRequested();

                await EnsureCurrentSegmentAsync(cancellationToken).ConfigureAwait(false);

                // Rotate if this write would exceed segment max size
                if (_currentSegmentBytes + bytes > _config.SegmentMaxBytes)
                {
                    _logger.LogInformation(
                        "Rotating queue segment because size {Size} + {Write} > max {Max}",
                        _currentSegmentBytes,
                        bytes,
                        _config.SegmentMaxBytes);

                    await RotateSegmentAsync(cancellationToken).ConfigureAwait(false);
                }

                if (_currentSegmentPath == null)
                {
                    throw new InvalidOperationException("Current segment path should not be null after EnsureCurrentSegmentAsync.");
                }

                // Append bytes using a FileStream that allows concurrent readers.
                // NOTE: We intentionally avoid StreamWriter(Encoding.UTF8) because it may emit a BOM
                // when the file is empty and the encoding has a preamble.
                try
                {
                    await using var fs = new FileStream(
                        _currentSegmentPath,
                        FileMode.OpenOrCreate,
                        FileAccess.Write,
                        FileShare.ReadWrite, // allow reader while we append
                        4096,
                        FileOptions.Asynchronous | FileOptions.WriteThrough);

                    // Ensure we're appending.
                    fs.Seek(0, SeekOrigin.End);

#if NET8_0_OR_GREATER
                    await fs.WriteAsync(jsonBytes, cancellationToken).ConfigureAwait(false);
                    await fs.WriteAsync(Newline, cancellationToken).ConfigureAwait(false);
                    await fs.FlushAsync(cancellationToken).ConfigureAwait(false);
#else
                    await fs.WriteAsync(jsonBytes, 0, jsonBytes.Length, cancellationToken).ConfigureAwait(false);
                    await fs.WriteAsync(Newline, 0, Newline.Length, cancellationToken).ConfigureAwait(false);
                    await fs.FlushAsync(cancellationToken).ConfigureAwait(false);
#endif
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to append event to queue segment {Path}", _currentSegmentPath);
                    throw;
                }

                _currentSegmentBytes += bytes;
            }
            finally
            {
                _lock.Release();
            }
        }

        private async Task EnsureCurrentSegmentAsync(CancellationToken cancellationToken)
        {
            if (!string.IsNullOrEmpty(_currentSegmentPath))
            {
                return;
            }

            // Create a new segment file with a timestamp-based name
            var timestamp = DateTimeOffset.UtcNow.ToString("yyyyMMddHHmmssfff");
            var fileName = $"segment-{timestamp}.jsonl";
            var fullPath = Path.Combine(_config.Path, fileName);

            try
            {
                // Create empty file, but allow future readers/writers to open it concurrently
                await using (var fs = new FileStream(
                    fullPath,
                    FileMode.CreateNew,
                    FileAccess.Write,
                    FileShare.ReadWrite,
                    4096,
                    FileOptions.Asynchronous | FileOptions.WriteThrough))
                {
                    // no-op; just ensure it exists
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create new queue segment at {Path}", fullPath);
                throw;
            }

            _currentSegmentPath = fullPath;
            try
            {
                _currentSegmentBytes = new FileInfo(fullPath).Length;
            }
            catch
            {
                _currentSegmentBytes = 0;
            }

            _logger.LogInformation("Created new queue segment: {Path}", _currentSegmentPath);
        }

        private async Task RotateSegmentAsync(CancellationToken cancellationToken)
        {
            // In v1 we simply drop the reference and create a new file.
            // Deletion/retention is handled later by the shipper/cleaner.

            _currentSegmentPath = null;
            _currentSegmentBytes = 0;

            await EnsureCurrentSegmentAsync(cancellationToken).ConfigureAwait(false);
        }
    }
}