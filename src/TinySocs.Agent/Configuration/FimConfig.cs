using System.Collections.Generic;

namespace TinySocs.Agent.Configuration;

/// <summary>
/// FIM-specific configuration, nested under an input of type "fim".
/// </summary>
public sealed class FimConfig
{
    /// <summary>Paths and glob patterns to monitor.</summary>
    public List<string> Paths { get; set; } = new()
    {
        @"C:\Windows\System32\drivers\etc\hosts",
        @"C:\Windows\System32\config\SAM",
        @"C:\Windows\System32\config\SECURITY",
        @"C:\Windows\System32\config\SYSTEM",
        @"C:\Windows\System32\GroupPolicy\**",
        // NB: do NOT watch C:\ProgramData\TinySocs\** — that tree contains the
        // agent's own event queue, the FIM baseline, and the bundled OpenSearch
        // data/logs. Watching it floods FIM with self-generated churn and creates
        // a save->detect->save feedback loop on the baseline. TinySocs-config
        // tamper detection (TS-112, currently disabled) can add a narrow, filtered
        // path when it's re-enabled.
        // Ransomware canary directory (seeded with decoy files at startup).
        // Nothing legitimate touches these, so a mass modification is a
        // high-signal early-warning of ransomware (TS-113).
        @"C:\ProgramData\TinySocs\Canary\**",
    };

    /// <summary>
    /// Ransomware-canary directory. Seeded with decoy files (invoice.docx,
    /// payroll.xlsx, …) on startup; nothing legitimate modifies them, so a burst
    /// of changes here is a high-signal ransomware indicator (TS-113 fires at
    /// <see cref="Paths"/>-wide threshold). Empty string disables seeding.
    /// </summary>
    public string CanaryPath { get; set; } = @"C:\ProgramData\TinySocs\Canary";

    /// <summary>Number of decoy files to seed in <see cref="CanaryPath"/>.</summary>
    public int CanaryFileCount { get; set; } = 60;

    /// <summary>Glob patterns to exclude from monitoring.</summary>
    public List<string> Exclude { get; set; } = new()
    {
        @"**\*.log",
        @"**\*.tmp",
        @"**\*.etl",
    };

    /// <summary>Minutes between full periodic scans (safety net for FileSystemWatcher misses).</summary>
    public int ScanIntervalMinutes { get; set; } = 15;

    /// <summary>Maximum file size in MB to hash (skip very large files).</summary>
    public int MaxFileSizeMb { get; set; } = 50;

    /// <summary>Path to the baseline JSON file.</summary>
    public string BaselinePath { get; set; } =
        @"C:\ProgramData\TinySocs\Agent\fim-baseline.json";
}
