using System;
using System.IO;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace TinySocs.Agent.Configuration;

public sealed class ConfigLoader
{
    private const string DefaultRelativePath = "config/agent-config.yml";
    private readonly string? _explicitPath;

    public ConfigLoader()
    {
        // Allow override via env var for dev/test and Windows installs
        _explicitPath = Environment.GetEnvironmentVariable("TINYSOCS_AGENT_CONFIG");
    }

    public AgentConfig Load()
    {
        var path = ResolveConfigPath();

        if (!File.Exists(path))
        {
            // No config yet → return defaults (agent will effectively be idle).
            return new AgentConfig();
        }

        var yaml = File.ReadAllText(path);

        var deserializer = new DeserializerBuilder()
            .WithNamingConvention(UnderscoredNamingConvention.Instance)
            .IgnoreUnmatchedProperties()
            .Build();

        var config = deserializer.Deserialize<AgentConfig>(yaml);
        return config ?? new AgentConfig();
    }

    private string ResolveConfigPath()
    {
        if (!string.IsNullOrWhiteSpace(_explicitPath))
        {
            return _explicitPath!;
        }

        // Default: ./config/agent-config.yml relative to current working directory
        var cwd = Environment.CurrentDirectory;
        var candidate = Path.Combine(cwd, DefaultRelativePath);
        return candidate;
    }
}