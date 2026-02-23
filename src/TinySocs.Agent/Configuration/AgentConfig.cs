using System.Collections.Generic;

namespace TinySocs.Agent.Configuration;

public sealed class AgentConfig
{
    public AgentSection Agent { get; set; } = new();
    public List<InputConfig> Inputs { get; set; } = new();
    public QueueConfig Queue { get; set; } = new();
    public OutputConfig Output { get; set; } = new();
    public PrivacyConfig Privacy { get; set; } = new();
    public SiemCredentialsConfig SiemCredentials { get; set; } = new();
    public DetectionConfig Detection { get; set; } = new();
}

public sealed class AgentSection
{
    public string Name { get; set; } = "TinySocsAgent";
    public string NodeId { get; set; } = "default-node";
    public string LogLevel { get; set; } = "info";

    public string LogFile { get; set; } =
        @"C:\ProgramData\TinySocs\Collector\logs\agent.log";

    // Dev-only switch to guard FakeInput so it never runs in production
    // unless explicitly enabled in config (agent.debug_fake_input: true).
    public bool DebugFakeInput { get; set; } = false;
}

/// <summary>
/// One logical input (eventlog, fake, etc.).
/// </summary>
public sealed class InputConfig
{
    public string Type { get; set; } = "eventlog";   // "eventlog", "fake", "fim"
    public string Name { get; set; } = "win-events";

    // eventlog-specific; these will be null/unused for inputs like "fake"
    public List<EventLogChannelConfig>? Channels { get; set; }
    public BookmarksConfig? Bookmarks { get; set; }

    // fim-specific; populated when type = "fim"
    public FimConfig? Fim { get; set; }
}

public sealed class EventLogChannelConfig
{
    public string Name { get; set; } = string.Empty;
    public string Level { get; set; } = "information";   // critical/error/warning/information/verbose
    public string StartFrom { get; set; } = "now";       // now | bookmark | beginning
}

public sealed class BookmarksConfig
{
    public string Path { get; set; } =
        @"C:\ProgramData\TinySocs\Collector\agent\bookmarks";

    public int PersistIntervalSeconds { get; set; } = 10;
}

public sealed class QueueConfig
{
    public string Path { get; set; } =
        @"C:\ProgramData\TinySocs\Collector\agent\queue";

    public long SegmentMaxBytes { get; set; } = 10 * 1024 * 1024;   // 10 MB
    public int MaxSegments { get; set; } = 100;                     // ~1 GB
    public int FlushIntervalMs { get; set; } = 200;
    public bool SyncOnFlush { get; set; } = true;
    public RetentionPolicyConfig RetentionPolicy { get; set; } = new();
}

public sealed class RetentionPolicyConfig
{
    public int MinSuccessfulShipCount { get; set; } = 1;
}

public sealed class OutputConfig
{
    public string Type { get; set; } = "opensearch";
    public string Url { get; set; } = "https://localhost:9201";
    public bool SslVerify { get; set; } = false;
    public string IndexPattern { get; set; } = "tinysocs-winlog-{yyyy.MM.dd}";
    public string Pipeline { get; set; } = string.Empty;

    public string User { get; set; } = string.Empty;
    public string Pass { get; set; } = string.Empty;

    public BulkConfig Bulk { get; set; } = new();
    public RetryConfig Retry { get; set; } = new();
}

public sealed class BulkConfig
{
    public int BatchSizeEvents { get; set; } = 500;
    public long BatchSizeBytes { get; set; } = 5 * 1024 * 1024;  // 5 MB
    public int FlushIntervalMs { get; set; } = 1000;
}

public sealed class RetryConfig
{
    public int MaxRetries { get; set; } = 5;
    public int InitialBackoffMs { get; set; } = 1000;
    public int MaxBackoffMs { get; set; } = 60_000;
}

public sealed class PrivacyConfig
{
    public List<string> DropFields { get; set; } = new();
    public List<string> HashFields { get; set; } = new();
    public List<TruncateFieldConfig> TruncateFields { get; set; } = new();
}

public sealed class TruncateFieldConfig
{
    public string Field { get; set; } = string.Empty;
    public int MaxLength { get; set; } = 4096;
}

public sealed class SiemCredentialsConfig
{
    public string Source { get; set; } = "credman";            // future: env/file
    public string Target { get; set; } = "TinySocs/OpenSearch/tinysocs";
}

public sealed class DetectionConfig
{
    public bool Enabled { get; set; } = true;
    public string RulesFile { get; set; } = @"C:\ProgramData\TinySocs\Collector\rules\rules.yml";
    public int ReloadIntervalSeconds { get; set; } = 60;
    public NotificationConfig Notification { get; set; } = new();
}

public sealed class NotificationConfig
{
    public string? WebhookUrl { get; set; }
    public EmailConfig? Email { get; set; }
    public NotificationRetryConfig Retry { get; set; } = new();
}

public sealed class NotificationRetryConfig
{
    public int MaxAttempts { get; set; } = 3;
    public int BackoffSeconds { get; set; } = 30;
    public int MaxAgeSeconds { get; set; } = 3600;
}

public sealed class EmailConfig
{
    public string? SmtpHost { get; set; }
    public int SmtpPort { get; set; } = 587;
    public string? From { get; set; }
    public string? To { get; set; }
}