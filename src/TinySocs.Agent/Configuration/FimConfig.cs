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
        @"C:\ProgramData\TinySocs\**\*.yml",
        @"C:\ProgramData\TinySocs\**\*.yaml",
    };

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
