using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Extensions.Logging;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace TinySocs.Agent.Detection
{
    /// <summary>
    /// Loads detection rules from rules.yml.
    /// </summary>
    public sealed class RuleLoader
    {
        private readonly ILogger<RuleLoader> _logger;
        private readonly IDeserializer _deserializer;

        public RuleLoader(ILogger<RuleLoader> logger)
        {
            _logger = logger;

            _deserializer = new DeserializerBuilder()
                .WithNamingConvention(UnderscoredNamingConvention.Instance)
                .IgnoreUnmatchedProperties()
                .Build();
        }

        public List<DetectionRule> LoadRules(string rulesFilePath)
        {
            try
            {
                if (!File.Exists(rulesFilePath))
                {
                    _logger.LogWarning("Rules file not found: {RulesFile}. Detection disabled.", rulesFilePath);
                    return new List<DetectionRule>();
                }

                var yaml = File.ReadAllText(rulesFilePath);
                var rulesFile = _deserializer.Deserialize<RulesFile>(yaml);

                if (rulesFile?.Rules == null || rulesFile.Rules.Count == 0)
                {
                    _logger.LogWarning("No rules found in {RulesFile}. Detection disabled.", rulesFilePath);
                    return new List<DetectionRule>();
                }

                var enabledRules = rulesFile.Rules.Where(r => r.Enabled).ToList();
                _logger.LogInformation(
                    "Loaded {EnabledCount} enabled rule(s) from {RulesFile} ({TotalCount} total).",
                    enabledRules.Count,
                    rulesFilePath,
                    rulesFile.Rules.Count);

                return enabledRules;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to load rules from {RulesFile}. Detection disabled.", rulesFilePath);
                return new List<DetectionRule>();
            }
        }
    }
}
