using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using TinySocs.Agent.Configuration;
using TinySocs.Agent.Models;
using TinySocs.Agent.Queueing;

namespace TinySocs.Agent.Inputs
{
    /// <summary>
    /// File Integrity Monitoring input.
    /// Monitors configured paths for file creation, modification, deletion,
    /// and permission changes. Uses FileSystemWatcher for real-time detection
    /// and periodic full scans as a safety net.
    ///
    /// FIM Event IDs:
    ///   1001 = File created
    ///   1002 = File modified (content hash changed)
    ///   1003 = File deleted
    ///   1004 = File renamed
    /// </summary>
    public sealed class FileIntegrityInput : IInput
    {
        private readonly ILogger<FileIntegrityInput> _logger;
        private readonly AgentConfig _config;
        private readonly IQueueWriter _queueWriter;
        private readonly FimConfig _fimConfig;

        // Baseline: filePath -> SHA256 hash
        private ConcurrentDictionary<string, string> _baseline = new(StringComparer.OrdinalIgnoreCase);
        private readonly List<FileSystemWatcher> _watchers = new();
        private bool _baselineInitialized;

        // Debounce rapid changes (FileSystemWatcher can fire multiple events for one save)
        private readonly ConcurrentDictionary<string, DateTime> _recentEvents = new(StringComparer.OrdinalIgnoreCase);
        private static readonly TimeSpan DebounceWindow = TimeSpan.FromSeconds(2);

        private const string Channel = "TinySocs-FIM";
        private const string IndexPattern = "tinysocs-winlog-{0:yyyy.MM.dd}";

        public FileIntegrityInput(
            ILogger<FileIntegrityInput> logger,
            AgentConfig config,
            IQueueWriter queueWriter,
            FimConfig fimConfig)
        {
            _logger = logger;
            _config = config;
            _queueWriter = queueWriter;
            _fimConfig = fimConfig;
        }

        public async Task RunAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("FileIntegrityInput starting. Monitored paths: {Count}", _fimConfig.Paths.Count);

            // Load or create baseline
            await InitializeBaseline();

            // Start FileSystemWatchers for real-time monitoring
            StartWatchers();

            // Periodic full scan loop
            var scanInterval = TimeSpan.FromMinutes(Math.Max(1, _fimConfig.ScanIntervalMinutes));
            _logger.LogInformation("FIM periodic scan interval: {Interval}", scanInterval);

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(scanInterval, stoppingToken);
                    await PeriodicScan();
                    CleanupRecentEvents();
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "FIM periodic scan error");
                }
            }

            // Cleanup watchers
            foreach (var w in _watchers)
            {
                w.EnableRaisingEvents = false;
                w.Dispose();
            }
            _watchers.Clear();
        }

        // ------------------------------------------------------------------
        // Baseline management
        // ------------------------------------------------------------------

        private async Task InitializeBaseline()
        {
            var baselinePath = _fimConfig.BaselinePath;
            if (File.Exists(baselinePath))
            {
                try
                {
                    var json = await File.ReadAllTextAsync(baselinePath);
                    var loaded = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
                    if (loaded != null)
                    {
                        _baseline = new ConcurrentDictionary<string, string>(loaded, StringComparer.OrdinalIgnoreCase);
                        _logger.LogInformation("FIM baseline loaded: {Count} files", _baseline.Count);
                        _baselineInitialized = true;
                        return;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to load FIM baseline, will re-scan");
                }
            }

            // First run: scan all monitored paths and create baseline (no alerts)
            _logger.LogInformation("FIM first run: creating baseline...");
            var files = EnumerateMonitoredFiles();
            foreach (var file in files)
            {
                var hash = ComputeHash(file);
                if (hash != null)
                    _baseline[file] = hash;
            }
            await SaveBaseline();
            _baselineInitialized = true;
            _logger.LogInformation("FIM baseline created: {Count} files", _baseline.Count);
        }

        public async Task ReBaseline()
        {
            _logger.LogInformation("FIM re-baseline requested");
            _baseline.Clear();
            var files = EnumerateMonitoredFiles();
            foreach (var file in files)
            {
                var hash = ComputeHash(file);
                if (hash != null)
                    _baseline[file] = hash;
            }
            await SaveBaseline();
            _logger.LogInformation("FIM re-baseline complete: {Count} files", _baseline.Count);
        }

        private async Task SaveBaseline()
        {
            try
            {
                var dir = Path.GetDirectoryName(_fimConfig.BaselinePath);
                if (!string.IsNullOrEmpty(dir))
                    Directory.CreateDirectory(dir);

                var json = JsonSerializer.Serialize(
                    _baseline.ToDictionary(kv => kv.Key, kv => kv.Value),
                    new JsonSerializerOptions { WriteIndented = true });
                await File.WriteAllTextAsync(_fimConfig.BaselinePath, json);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to save FIM baseline to {Path}", _fimConfig.BaselinePath);
            }
        }

        // ------------------------------------------------------------------
        // File enumeration and hashing
        // ------------------------------------------------------------------

        private List<string> EnumerateMonitoredFiles()
        {
            var result = new List<string>();
            var maxSize = (long)_fimConfig.MaxFileSizeMb * 1024 * 1024;

            foreach (var pathPattern in _fimConfig.Paths)
            {
                try
                {
                    if (pathPattern.Contains("**") || pathPattern.Contains("*"))
                    {
                        // Glob pattern: extract base dir and pattern
                        var parts = pathPattern.Replace("\\", "/").Split(new[] { "**" }, 2, StringSplitOptions.None);
                        var baseDir = parts[0].TrimEnd('/').Replace("/", "\\");
                        if (string.IsNullOrEmpty(baseDir)) continue;
                        if (!Directory.Exists(baseDir)) continue;

                        var searchPattern = parts.Length > 1 ? parts[1].TrimStart('/').Replace("/", "\\") : "*";
                        if (string.IsNullOrEmpty(searchPattern)) searchPattern = "*";

                        // Only use the filename part for the search
                        var filePattern = Path.GetFileName(searchPattern);
                        if (string.IsNullOrEmpty(filePattern)) filePattern = "*";

                        var option = pathPattern.Contains("**")
                            ? SearchOption.AllDirectories
                            : SearchOption.TopDirectoryOnly;

                        foreach (var file in Directory.EnumerateFiles(baseDir, filePattern, option))
                        {
                            if (ShouldExclude(file)) continue;
                            try
                            {
                                var fi = new FileInfo(file);
                                if (fi.Length <= maxSize)
                                    result.Add(file);
                            }
                            catch { /* skip inaccessible files */ }
                        }
                    }
                    else
                    {
                        // Direct file path
                        if (File.Exists(pathPattern))
                        {
                            if (!ShouldExclude(pathPattern))
                            {
                                try
                                {
                                    var fi = new FileInfo(pathPattern);
                                    if (fi.Length <= (long)_fimConfig.MaxFileSizeMb * 1024 * 1024)
                                        result.Add(pathPattern);
                                }
                                catch { }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "FIM enumeration error for pattern: {Pattern}", pathPattern);
                }
            }

            return result;
        }

        private bool ShouldExclude(string filePath)
        {
            var fileName = Path.GetFileName(filePath);
            foreach (var pattern in _fimConfig.Exclude)
            {
                var clean = pattern.Replace("**\\", "").Replace("**", "").TrimStart('\\');
                if (clean.StartsWith("*."))
                {
                    var ext = clean.Substring(1); // e.g. ".log"
                    if (filePath.EndsWith(ext, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }
            return false;
        }

        private string? ComputeHash(string filePath)
        {
            try
            {
                using var stream = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sha = SHA256.Create();
                var hashBytes = sha.ComputeHash(stream);
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
            }
            catch (Exception ex)
            {
                _logger.LogDebug("FIM hash failed for {Path}: {Error}", filePath, ex.Message);
                return null;
            }
        }

        // ------------------------------------------------------------------
        // FileSystemWatcher (real-time detection)
        // ------------------------------------------------------------------

        private void StartWatchers()
        {
            var watchedDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var pathPattern in _fimConfig.Paths)
            {
                string? dir;
                if (pathPattern.Contains("**") || pathPattern.Contains("*"))
                {
                    dir = pathPattern.Replace("\\", "/").Split(new[] { "**", "*" }, StringSplitOptions.None)[0]
                        .TrimEnd('/').Replace("/", "\\");
                }
                else
                {
                    dir = Path.GetDirectoryName(pathPattern);
                }

                if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir) || watchedDirs.Contains(dir))
                    continue;

                try
                {
                    var watcher = new FileSystemWatcher(dir)
                    {
                        IncludeSubdirectories = pathPattern.Contains("**"),
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite |
                                       NotifyFilters.Size | NotifyFilters.CreationTime,
                        EnableRaisingEvents = true,
                    };

                    watcher.Created += OnFileCreated;
                    watcher.Changed += OnFileChanged;
                    watcher.Deleted += OnFileDeleted;
                    watcher.Renamed += OnFileRenamed;
                    watcher.Error += OnWatcherError;

                    _watchers.Add(watcher);
                    watchedDirs.Add(dir);
                    _logger.LogDebug("FIM watcher started for: {Dir}", dir);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to start FIM watcher for: {Dir}", dir);
                }
            }

            _logger.LogInformation("FIM started {Count} FileSystemWatchers", _watchers.Count);
        }

        private void OnFileCreated(object sender, FileSystemEventArgs e)
        {
            if (!_baselineInitialized || ShouldExclude(e.FullPath) || !ShouldDebounce(e.FullPath)) return;
            var hash = ComputeHash(e.FullPath);
            if (hash != null)
            {
                _baseline[e.FullPath] = hash;
                EmitEvent(1001, "created", e.FullPath, null, hash);
                _ = SaveBaseline();
            }
        }

        private void OnFileChanged(object sender, FileSystemEventArgs e)
        {
            if (!_baselineInitialized || ShouldExclude(e.FullPath) || !ShouldDebounce(e.FullPath)) return;
            var oldHash = _baseline.GetValueOrDefault(e.FullPath);
            var newHash = ComputeHash(e.FullPath);
            if (newHash != null && newHash != oldHash)
            {
                _baseline[e.FullPath] = newHash;
                EmitEvent(1002, "modified", e.FullPath, oldHash, newHash);
                _ = SaveBaseline();
            }
        }

        private void OnFileDeleted(object sender, FileSystemEventArgs e)
        {
            if (!_baselineInitialized || ShouldExclude(e.FullPath) || !ShouldDebounce(e.FullPath)) return;
            var oldHash = _baseline.GetValueOrDefault(e.FullPath);
            _baseline.TryRemove(e.FullPath, out _);
            EmitEvent(1003, "deleted", e.FullPath, oldHash, null);
            _ = SaveBaseline();
        }

        private void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            if (!_baselineInitialized || !ShouldDebounce(e.FullPath)) return;
            // Remove old entry, add new
            _baseline.TryRemove(e.OldFullPath, out var oldHash);
            var newHash = ComputeHash(e.FullPath);
            if (newHash != null)
                _baseline[e.FullPath] = newHash;
            EmitEvent(1004, "renamed", e.FullPath, oldHash, newHash,
                new Dictionary<string, object?> { ["OldPath"] = e.OldFullPath });
            _ = SaveBaseline();
        }

        private void OnWatcherError(object sender, ErrorEventArgs e)
        {
            _logger.LogWarning(e.GetException(), "FIM FileSystemWatcher error");
        }

        private bool ShouldDebounce(string path)
        {
            var now = DateTime.UtcNow;
            if (_recentEvents.TryGetValue(path, out var lastTime))
            {
                if (now - lastTime < DebounceWindow)
                    return false;
            }
            _recentEvents[path] = now;
            return true;
        }

        private void CleanupRecentEvents()
        {
            var cutoff = DateTime.UtcNow - TimeSpan.FromMinutes(5);
            foreach (var kv in _recentEvents)
            {
                if (kv.Value < cutoff)
                    _recentEvents.TryRemove(kv.Key, out _);
            }
        }

        // ------------------------------------------------------------------
        // Periodic scan (safety net)
        // ------------------------------------------------------------------

        private async Task PeriodicScan()
        {
            var files = EnumerateMonitoredFiles();
            var currentFiles = new HashSet<string>(files, StringComparer.OrdinalIgnoreCase);
            int changes = 0;

            // Check for modified or new files
            foreach (var file in files)
            {
                var hash = ComputeHash(file);
                if (hash == null) continue;

                if (_baseline.TryGetValue(file, out var oldHash))
                {
                    if (hash != oldHash)
                    {
                        _baseline[file] = hash;
                        EmitEvent(1002, "modified", file, oldHash, hash);
                        changes++;
                    }
                }
                else
                {
                    _baseline[file] = hash;
                    EmitEvent(1001, "created", file, null, hash);
                    changes++;
                }
            }

            // Check for deleted files
            foreach (var baselineFile in _baseline.Keys.ToList())
            {
                if (!currentFiles.Contains(baselineFile) && !File.Exists(baselineFile))
                {
                    _baseline.TryRemove(baselineFile, out var oldHash);
                    EmitEvent(1003, "deleted", baselineFile, oldHash, null);
                    changes++;
                }
            }

            if (changes > 0)
            {
                await SaveBaseline();
                _logger.LogInformation("FIM periodic scan: {Changes} changes detected across {Total} files",
                    changes, files.Count);
            }
            else
            {
                _logger.LogDebug("FIM periodic scan: {Total} files, no changes", files.Count);
            }
        }

        // ------------------------------------------------------------------
        // Event emission
        // ------------------------------------------------------------------

        private void EmitEvent(int eventId, string changeType, string filePath,
            string? hashBefore, string? hashAfter,
            Dictionary<string, object?>? extra = null)
        {
            var body = new Dictionary<string, object?>
            {
                ["FilePath"] = filePath,
                ["ChangeType"] = changeType,
                ["HashBefore"] = hashBefore,
                ["HashAfter"] = hashAfter,
                ["FileName"] = Path.GetFileName(filePath),
                ["Directory"] = Path.GetDirectoryName(filePath),
            };

            if (extra != null)
            {
                foreach (var kv in extra)
                    body[kv.Key] = kv.Value;
            }

            try
            {
                var fi = File.Exists(filePath) ? new FileInfo(filePath) : null;
                if (fi != null)
                {
                    body["FileSize"] = fi.Length;
                    body["LastWriteTime"] = fi.LastWriteTimeUtc.ToString("o");
                }
            }
            catch { /* file may be locked or deleted */ }

            var agentEvent = new AgentEvent
            {
                Ts = DateTimeOffset.UtcNow,
                Input = "fim",
                Channel = Channel,
                EventId = eventId,
                OpenSearchIndex = string.Format(IndexPattern, DateTime.UtcNow),
                Body = body,
            };

            _queueWriter.Enqueue(agentEvent);
            _logger.LogInformation("FIM event: {ChangeType} {FilePath} (event_id={EventId})",
                changeType, filePath, eventId);
        }
    }
}
