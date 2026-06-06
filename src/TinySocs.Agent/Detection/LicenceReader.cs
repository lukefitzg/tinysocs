using System;
using System.Text.Json;

namespace TinySocs.Agent.Detection
{
    /// <summary>tier -> what content the tier may pull. Mirrors scripts/licence.py.</summary>
    public sealed class Entitlement
    {
        public string[] Packs { get; init; } = Array.Empty<string>();
        public string Channel { get; init; } = "snapshot";
        public bool Premium { get; init; }
    }

    /// <summary>Resolved licence state for the running agent.</summary>
    public sealed class LicenceResult
    {
        public string Tier { get; init; } = "free";
        public string Note { get; init; } = "no key";
        public long Exp { get; init; }
        public Entitlement Entitlement { get; init; } = LicenceReader.EntitlementFor("free");
    }

    /// <summary>
    /// Reads a signed licence token (base64url(payload).base64url(sig)) and resolves
    /// the tier the agent should use. Billing state degrades freshness/breadth, never
    /// agent function: anything invalid/expired-past-grace collapses to 'free'.
    ///
    /// The agent reading its own tier is not the security boundary — the feed server
    /// re-verifies for access control. But when a licence public key is supplied we
    /// verify the signature anyway, so a tampered key is ignored rather than trusted.
    /// Logic mirrors effective_tier() in scripts/licence.py (14-day grace).
    /// </summary>
    public static class LicenceReader
    {
        private const int GraceDays = 14;

        public static Entitlement EntitlementFor(string tier) => tier switch
        {
            "pro" => new Entitlement
            {
                Packs = new[] { "base", "m365-pack", "persistence-premium" },
                Channel = "live",
                Premium = true,
            },
            "msp" => new Entitlement
            {
                Packs = new[] { "base", "m365-pack", "persistence-premium", "federation" },
                Channel = "live",
                Premium = true,
            },
            _ => new Entitlement
            {
                Packs = new[] { "base" },
                Channel = "snapshot",
                Premium = false,
            },
        };

        public static bool CanAccess(string tier, string packId, string channel)
        {
            var ent = EntitlementFor(tier);
            if (Array.IndexOf(ent.Packs, packId) < 0)
            {
                return false;
            }
            if (channel == "live" && ent.Channel != "live")
            {
                return false;
            }
            return true;
        }

        /// <param name="licencePublicKey">32-byte raw Ed25519 key, or null to decode without verifying.</param>
        public static LicenceResult Resolve(string? token, byte[]? licencePublicKey, DateTimeOffset now)
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                return Free("no key");
            }

            var parts = token.Trim().Split('.', 2);
            if (parts.Length != 2)
            {
                return Free("malformed token");
            }

            byte[] payloadBytes;
            byte[] sigBytes;
            try
            {
                payloadBytes = B64UrlDecode(parts[0]);
                sigBytes = B64UrlDecode(parts[1]);
            }
            catch
            {
                return Free("undecodable token");
            }

            string tier;
            long exp;
            try
            {
                using var doc = JsonDocument.Parse(payloadBytes);
                var root = doc.RootElement;
                tier = root.TryGetProperty("tier", out var t) ? (t.GetString() ?? "free") : "free";
                exp = root.TryGetProperty("exp", out var e) ? e.GetInt64() : 0;
            }
            catch
            {
                return Free("undecodable payload");
            }

            // Signature check (only load-bearing when a key is configured).
            if (licencePublicKey != null &&
                !Ed25519Verifier.Verify(licencePublicKey, payloadBytes, sigBytes))
            {
                return Free("signature does not verify");
            }

            var nowUnix = now.ToUnixTimeSeconds();
            if (exp >= nowUnix)
            {
                return new LicenceResult { Tier = tier, Note = "valid", Exp = exp, Entitlement = EntitlementFor(tier) };
            }

            // Expired but authentic: apply grace, then collapse to free.
            if (exp + (long)GraceDays * 86400 >= nowUnix)
            {
                return new LicenceResult { Tier = tier, Note = "grace", Exp = exp, Entitlement = EntitlementFor(tier) };
            }
            return Free("expired past grace");
        }

        private static LicenceResult Free(string note) =>
            new LicenceResult { Tier = "free", Note = note, Entitlement = EntitlementFor("free") };

        private static byte[] B64UrlDecode(string s)
        {
            s = s.Replace('-', '+').Replace('_', '/');
            switch (s.Length % 4)
            {
                case 2: s += "=="; break;
                case 3: s += "="; break;
            }
            return Convert.FromBase64String(s);
        }
    }
}
