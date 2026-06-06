using Microsoft.Extensions.Logging.Abstractions;
using System.Text;
using TinySocs.Agent.Configuration;
using TinySocs.Agent.Detection;
using Xunit;

namespace TinySocs.Agent.Tests
{
    public class PackLoaderTests
    {
        private const string KeyId = "tinysocs-2026";

        // A minimal but representative signed pack: one threshold rule with a
        // field_match + tuning override, one plain rule.
        private static string PackJson(string packId = "base", string channel = "snapshot",
            string keyId = KeyId, string thresholdEnvVar = "")
        {
            var tuning = string.IsNullOrEmpty(thresholdEnvVar)
                ? "null"
                : $"{{\"envvar\":\"{thresholdEnvVar}\",\"min\":3,\"max\":75,\"default\":15}}";

            return
                "{\"schema_version\":2,\"metadata\":{" +
                $"\"pack_id\":\"{packId}\",\"pack_version\":\"2026.23\",\"channel\":\"{channel}\"," +
                $"\"signature\":{{\"algorithm\":\"ed25519\",\"key_id\":\"{keyId}\",\"value\":\"\"}}}}," +
                "\"rules\":[" +
                "{\"id\":\"TS-001\",\"name\":\"brute_force_logon\",\"severity\":\"high\",\"enabled\":true," +
                "\"detection\":{\"type\":\"threshold_by_key\",\"event_id\":4625,\"channel\":\"Security\"," +
                "\"group_by\":\"winlog.event_data.TargetUserName\",\"threshold\":15,\"window_minutes\":5}," +
                $"\"tuning\":{{\"threshold\":{tuning}}}}}," +
                "{\"id\":\"TS-061\",\"name\":\"credential_dumping_tools\",\"severity\":\"critical\",\"enabled\":true," +
                "\"detection\":{\"type\":\"threshold_by_key\",\"event_id\":4688,\"channel\":\"Security\"," +
                "\"group_by\":\"winlog.computer_name\",\"threshold\":1," +
                "\"field_match\":{\"field\":\"winlog.event_data.NewProcessName\"," +
                "\"values\":[\"mimikatz.exe\",\"procdump.exe\"],\"match\":\"contains\"}}}" +
                "]}";
        }

        private static (ContentPackConfig cfg, byte[] priv) WriteSignedPack(
            string json, byte[]? signWithPriv = null, byte[]? trustPub = null)
        {
            var (pub, priv) = Ed25519TestKit.GenerateKeyPair();
            var actualSigner = signWithPriv ?? priv;
            var anchor = trustPub ?? pub;

            var dir = Path.Combine(Path.GetTempPath(), "tsockpack_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            var packFile = Path.Combine(dir, "pack.yml.canonical");
            var sigFile = Path.Combine(dir, "pack.yml.sig");

            var bytes = Encoding.UTF8.GetBytes(json);
            File.WriteAllBytes(packFile, bytes);
            File.WriteAllText(sigFile, Ed25519TestKit.B64(Ed25519TestKit.Sign(actualSigner, bytes)));

            var cfg = new ContentPackConfig
            {
                Enabled = true,
                PackFile = packFile,
                SignatureFile = sigFile,
                PublicKey = Ed25519TestKit.B64(anchor),
                SigningKeyId = KeyId,
            };
            return (cfg, priv);
        }

        private static PackLoadResult Load(ContentPackConfig cfg) =>
            new PackLoader(NullLogger<PackLoader>.Instance, cfg).Load();

        [Fact]
        public void ValidPack_LoadsRules()
        {
            var (cfg, _) = WriteSignedPack(PackJson());
            var r = Load(cfg);

            Assert.True(r.Ok, r.Reason);
            Assert.Equal(2, r.Rules.Count);
            Assert.Equal("base", r.PackId);
            Assert.Equal("free", r.Tier); // no licence
        }

        [Fact]
        public void FieldMatch_IsMapped()
        {
            var (cfg, _) = WriteSignedPack(PackJson());
            var r = Load(cfg);

            var ts061 = r.Rules.Single(x => x.Id == "TS-061");
            Assert.NotNull(ts061.Condition.FieldMatch);
            Assert.Equal("contains", ts061.Condition.FieldMatch!.Match);
            Assert.Contains("mimikatz.exe", ts061.Condition.FieldMatch.Values);
        }

        [Fact]
        public void TamperedBytes_Refused()
        {
            var (cfg, _) = WriteSignedPack(PackJson());
            var bytes = File.ReadAllBytes(cfg.PackFile);
            bytes[20] ^= 0xFF; // flip a byte after signing
            File.WriteAllBytes(cfg.PackFile, bytes);

            var r = Load(cfg);

            Assert.False(r.Ok);
            Assert.Contains("signature does not verify", r.Reason);
            Assert.Empty(r.Rules);
        }

        [Fact]
        public void UntrustedKeyId_Refused()
        {
            var (cfg, _) = WriteSignedPack(PackJson(keyId: "attacker-2026"));
            var r = Load(cfg);

            Assert.False(r.Ok);
            Assert.Contains("untrusted key_id", r.Reason);
        }

        [Fact]
        public void WrongTrustAnchor_Refused()
        {
            // Sign with one key but trust a different public key.
            var (_, signerPriv) = Ed25519TestKit.GenerateKeyPair();
            var (trustPub, _) = Ed25519TestKit.GenerateKeyPair();
            var (cfg, _) = WriteSignedPack(PackJson(), signWithPriv: signerPriv, trustPub: trustPub);

            var r = Load(cfg);

            Assert.False(r.Ok);
            Assert.Contains("signature does not verify", r.Reason);
        }

        [Fact]
        public void FreeTier_CannotLoadPremiumPack()
        {
            var (cfg, _) = WriteSignedPack(PackJson(packId: "persistence-premium", channel: "live"));
            var r = Load(cfg);

            Assert.False(r.Ok);
            Assert.Contains("not entitled", r.Reason);
        }

        [Fact]
        public void ProLicence_UnlocksPremiumPack()
        {
            var (licPub, licPriv) = Ed25519TestKit.GenerateKeyPair();
            var exp = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 86400;
            var token = Ed25519TestKit.MintLicence(licPriv,
                $"{{\"tier\":\"pro\",\"exp\":{exp},\"k\":\"licensing-2026\"}}");

            var (cfg, _) = WriteSignedPack(PackJson(packId: "persistence-premium", channel: "live"));
            cfg.LicenceKey = token;
            cfg.LicencePublicKey = Ed25519TestKit.B64(licPub);

            var r = Load(cfg);

            Assert.True(r.Ok, r.Reason);
            Assert.Equal("pro", r.Tier);
        }

        [Fact]
        public void TuningEnvVar_OverridesThreshold_Clamped()
        {
            var env = "TINYSOCS_TEST_TS001_" + Guid.NewGuid().ToString("N");
            var (cfg, _) = WriteSignedPack(PackJson(thresholdEnvVar: env));

            try
            {
                Environment.SetEnvironmentVariable(env, "9999"); // above max=75 -> clamps
                var r = Load(cfg);
                var ts001 = r.Rules.Single(x => x.Id == "TS-001");
                Assert.Equal(75, ts001.Condition.Threshold);
            }
            finally
            {
                Environment.SetEnvironmentVariable(env, null);
            }
        }

        [Fact]
        public void TuningEnvVar_Unset_UsesPackDefault()
        {
            var (cfg, _) = WriteSignedPack(PackJson(thresholdEnvVar: "TINYSOCS_DEFINITELY_UNSET_VAR_XYZ"));
            var r = Load(cfg);

            var ts001 = r.Rules.Single(x => x.Id == "TS-001");
            Assert.Equal(15, ts001.Condition.Threshold); // pack value, no override
        }

        [Fact]
        public void MissingPackFile_Refused()
        {
            var cfg = new ContentPackConfig
            {
                Enabled = true,
                PackFile = Path.Combine(Path.GetTempPath(), "does_not_exist_" + Guid.NewGuid().ToString("N")),
                PublicKey = Ed25519TestKit.B64(Ed25519TestKit.GenerateKeyPair().Pub),
            };

            var r = Load(cfg);

            Assert.False(r.Ok);
            Assert.Contains("not found", r.Reason);
        }
    }
}
