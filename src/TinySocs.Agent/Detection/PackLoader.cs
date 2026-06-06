using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using TinySocs.Agent.Configuration;

namespace TinySocs.Agent.Detection
{
    /// <summary>Outcome of attempting to load a signed pack.</summary>
    public sealed class PackLoadResult
    {
        public bool Ok { get; init; }
        public string Reason { get; init; } = "";
        public List<DetectionRule> Rules { get; init; } = new();
        public string Tier { get; init; } = "free";
        public string TierNote { get; init; } = "";
        public string PackId { get; init; } = "";
        public string PackVersion { get; init; } = "";

        public static PackLoadResult Refused(string reason) =>
            new PackLoadResult { Ok = false, Reason = reason };
    }

    /// <summary>
    /// Loads a signed v2 detection pack: verify the ed25519 signature over the
    /// canonical bytes, confirm the signing key_id is trusted, gate by licence
    /// entitlement, then map the pack's rules onto the engine's DetectionRule
    /// model. Refuses (loads nothing) on any failure — a pack that does not
    /// verify must never reach the engine.
    /// </summary>
    public sealed class PackLoader
    {
        private readonly ILogger<PackLoader> _logger;
        private readonly ContentPackConfig _config;

        public PackLoader(ILogger<PackLoader> logger, ContentPackConfig config)
        {
            _logger = logger;
            _config = config;
        }

        public PackLoadResult Load()
        {
            // ---- read artifacts ----
            if (!File.Exists(_config.PackFile))
            {
                return PackLoadResult.Refused($"pack file not found: {_config.PackFile}");
            }
            var sigPath = ResolveSignaturePath();
            if (!File.Exists(sigPath))
            {
                return PackLoadResult.Refused($"signature file not found: {sigPath}");
            }

            byte[] canonical;
            byte[] signature;
            byte[] trustedKey;
            try
            {
                canonical = File.ReadAllBytes(_config.PackFile);
                signature = Convert.FromBase64String(File.ReadAllText(sigPath).Trim());
                trustedKey = Convert.FromBase64String(_config.PublicKey.Trim());
            }
            catch (Exception ex)
            {
                return PackLoadResult.Refused($"could not read pack artifacts: {ex.Message}");
            }

            // ---- verify signature over the exact signed bytes ----
            if (!Ed25519Verifier.Verify(trustedKey, canonical, signature))
            {
                return PackLoadResult.Refused("signature does not verify (tampered or wrong key)");
            }

            // ---- parse the now-trusted bytes ----
            JsonElement root;
            JsonDocument doc;
            try
            {
                doc = JsonDocument.Parse(canonical);
                root = doc.RootElement;
            }
            catch (Exception ex)
            {
                return PackLoadResult.Refused($"pack is not valid JSON: {ex.Message}");
            }

            using (doc)
            {
                if (!root.TryGetProperty("metadata", out var meta))
                {
                    return PackLoadResult.Refused("pack has no metadata");
                }

                // key_id pinning: even a valid signature must come from the trusted key_id.
                if (meta.TryGetProperty("signature", out var sigBlock) &&
                    sigBlock.TryGetProperty("key_id", out var keyIdEl))
                {
                    var keyId = keyIdEl.GetString();
                    if (!string.Equals(keyId, _config.SigningKeyId, StringComparison.Ordinal))
                    {
                        return PackLoadResult.Refused(
                            $"pack signed by untrusted key_id '{keyId}' (expected '{_config.SigningKeyId}')");
                    }
                }

                var packId = GetString(meta, "pack_id", "unknown");
                var packVersion = GetString(meta, "pack_version", "unknown");

                // ---- licence entitlement gate ----
                byte[]? licenceKey = null;
                if (!string.IsNullOrWhiteSpace(_config.LicencePublicKey))
                {
                    try { licenceKey = Convert.FromBase64String(_config.LicencePublicKey.Trim()); }
                    catch { /* leave null -> decode-only */ }
                }
                var licence = LicenceReader.Resolve(_config.LicenceKey, licenceKey, DateTimeOffset.UtcNow);

                var packChannel = GetString(meta, "channel", licence.Entitlement.Channel);
                if (!LicenceReader.CanAccess(licence.Tier, packId, packChannel))
                {
                    return PackLoadResult.Refused(
                        $"tier '{licence.Tier}' not entitled to pack '{packId}' on channel '{packChannel}'");
                }

                // ---- map rules ----
                var rules = new List<DetectionRule>();
                if (root.TryGetProperty("rules", out var rulesEl) && rulesEl.ValueKind == JsonValueKind.Array)
                {
                    foreach (var r in rulesEl.EnumerateArray())
                    {
                        var rule = MapRule(r);
                        if (rule != null && rule.Enabled)
                        {
                            rules.Add(rule);
                        }
                    }
                }

                return new PackLoadResult
                {
                    Ok = true,
                    Reason = "valid",
                    Rules = rules,
                    Tier = licence.Tier,
                    TierNote = licence.Note,
                    PackId = packId,
                    PackVersion = packVersion,
                };
            }
        }

        private string ResolveSignaturePath()
        {
            if (!string.IsNullOrWhiteSpace(_config.SignatureFile))
            {
                return _config.SignatureFile;
            }
            // pack.yml.canonical -> pack.yml.sig
            if (_config.PackFile.EndsWith(".canonical", StringComparison.Ordinal))
            {
                return _config.PackFile.Substring(0, _config.PackFile.Length - ".canonical".Length) + ".sig";
            }
            return _config.PackFile + ".sig";
        }

        private DetectionRule? MapRule(JsonElement r)
        {
            try
            {
                var rule = new DetectionRule
                {
                    Id = GetString(r, "id", ""),
                    Name = GetString(r, "name", ""),
                    Description = GetString(r, "description", ""),
                    Severity = GetString(r, "severity", "medium"),
                    Enabled = !r.TryGetProperty("enabled", out var en) || en.ValueKind != JsonValueKind.False,
                };

                if (r.TryGetProperty("detection", out var d))
                {
                    var cond = new RuleCondition();
                    rule.Type = GetString(d, "type", "");
                    if (d.TryGetProperty("event_id", out var ev) && ev.ValueKind == JsonValueKind.Number)
                    {
                        cond.EventId = ev.GetInt32();
                    }
                    cond.Channel = GetStringOrNull(d, "channel");
                    cond.GroupBy = GetStringOrNull(d, "group_by");
                    if (d.TryGetProperty("threshold", out var th) && th.ValueKind == JsonValueKind.Number)
                    {
                        cond.Threshold = th.GetInt32();
                    }
                    if (d.TryGetProperty("window_minutes", out var wm) && wm.ValueKind == JsonValueKind.Number)
                    {
                        cond.WindowMinutes = wm.GetInt32();
                    }
                    if (d.TryGetProperty("cooldown_minutes", out var cm) && cm.ValueKind == JsonValueKind.Number)
                    {
                        cond.CooldownMinutes = cm.GetInt32();
                    }
                    if (d.TryGetProperty("field_match", out var fm) && fm.ValueKind == JsonValueKind.Object)
                    {
                        var filter = new FieldMatchFilter
                        {
                            Field = GetString(fm, "field", ""),
                            Match = GetString(fm, "match", "contains"),
                        };
                        if (fm.TryGetProperty("values", out var vals) && vals.ValueKind == JsonValueKind.Array)
                        {
                            foreach (var v in vals.EnumerateArray())
                            {
                                var s = v.GetString();
                                if (!string.IsNullOrEmpty(s))
                                {
                                    filter.Values.Add(s);
                                }
                            }
                        }
                        cond.FieldMatch = filter;
                    }
                    rule.Condition = cond;
                }

                if (r.TryGetProperty("mitre", out var m) && m.ValueKind == JsonValueKind.Object)
                {
                    rule.Mitre = new MitreInfo
                    {
                        TechniqueId = GetString(m, "technique_id", ""),
                        TechniqueName = GetString(m, "technique_name", ""),
                        Tactic = GetString(m, "tactic", ""),
                    };
                }

                if (string.IsNullOrWhiteSpace(rule.Id) || string.IsNullOrWhiteSpace(rule.Type))
                {
                    _logger.LogWarning("Skipping pack rule with missing id/type.");
                    return null;
                }
                return rule;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Skipping malformed pack rule.");
                return null;
            }
        }

        private static string GetString(JsonElement parent, string name, string fallback) =>
            parent.TryGetProperty(name, out var el) && el.ValueKind == JsonValueKind.String
                ? (el.GetString() ?? fallback)
                : fallback;

        private static string? GetStringOrNull(JsonElement parent, string name) =>
            parent.TryGetProperty(name, out var el) && el.ValueKind == JsonValueKind.String
                ? el.GetString()
                : null;
    }
}
