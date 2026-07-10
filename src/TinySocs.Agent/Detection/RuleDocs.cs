using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Extensions.Logging;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace TinySocs.Agent.Detection
{
    /// <summary>
    /// Plain-English companion content for a detection rule (TinyDocs).
    /// Shown to non-security readers alongside alerts: what happened,
    /// what to do first, and the common benign explanation.
    /// </summary>
    public sealed class RuleDoc
    {
        public string Title { get; set; } = string.Empty;
        public string WhatHappened { get; set; } = string.Empty;
        public List<string> DoFirst { get; set; } = new();
        public string FalseAlarmIf { get; set; } = string.Empty;
    }

    public sealed class RuleDocsFile
    {
        public Dictionary<string, RuleDoc> Docs { get; set; } = new();
    }

    /// <summary>
    /// Loads rule_docs.yml (vendor-authored, ships alongside rules.yml).
    /// Missing file or entries are non-fatal — alerts fall back to the
    /// technical rule name and description.
    /// </summary>
    public sealed class RuleDocsLoader
    {
        private readonly ILogger _logger;
        private readonly IDeserializer _deserializer;

        public RuleDocsLoader(ILogger logger)
        {
            _logger = logger;

            _deserializer = new DeserializerBuilder()
                .WithNamingConvention(UnderscoredNamingConvention.Instance)
                .IgnoreUnmatchedProperties()
                .Build();
        }

        public IReadOnlyDictionary<string, RuleDoc> Load(string ruleDocsFilePath)
        {
            try
            {
                if (!File.Exists(ruleDocsFilePath))
                {
                    _logger.LogInformation(
                        "Rule docs file not found: {RuleDocsFile}. Alerts will use technical rule names.",
                        ruleDocsFilePath);
                    return new Dictionary<string, RuleDoc>();
                }

                var yaml = File.ReadAllText(ruleDocsFilePath);
                var docsFile = _deserializer.Deserialize<RuleDocsFile>(yaml);

                if (docsFile?.Docs == null || docsFile.Docs.Count == 0)
                {
                    _logger.LogWarning("No entries found in {RuleDocsFile}.", ruleDocsFilePath);
                    return new Dictionary<string, RuleDoc>();
                }

                _logger.LogInformation(
                    "Loaded rule docs for {Count} rule(s) from {RuleDocsFile}.",
                    docsFile.Docs.Count,
                    ruleDocsFilePath);

                return docsFile.Docs;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Failed to load rule docs from {RuleDocsFile}. Alerts will use technical rule names.",
                    ruleDocsFilePath);
                return new Dictionary<string, RuleDoc>();
            }
        }
    }
}
