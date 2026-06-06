using TinySocs.Agent.Detection;
using Xunit;

namespace TinySocs.Agent.Tests
{
    public class LicenceReaderTests
    {
        private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1_780_000_000);

        private static string Payload(string tier, long exp) =>
            $"{{\"tier\":\"{tier}\",\"exp\":{exp},\"k\":\"licensing-2026\"}}";

        [Fact]
        public void NoToken_IsFree()
        {
            var r = LicenceReader.Resolve(null, null, Now);
            Assert.Equal("free", r.Tier);
            Assert.Equal("no key", r.Note);
        }

        [Fact]
        public void ValidProToken_VerifiesToPro()
        {
            var (pub, priv) = Ed25519TestKit.GenerateKeyPair();
            var token = Ed25519TestKit.MintLicence(priv, Payload("pro", Now.ToUnixTimeSeconds() + 86400));

            var r = LicenceReader.Resolve(token, pub, Now);

            Assert.Equal("pro", r.Tier);
            Assert.Equal("valid", r.Note);
        }

        [Fact]
        public void ExpiredWithinGrace_KeepsTier()
        {
            var (pub, priv) = Ed25519TestKit.GenerateKeyPair();
            // Expired 5 days ago; grace is 14 days.
            var exp = Now.ToUnixTimeSeconds() - 5 * 86400;
            var token = Ed25519TestKit.MintLicence(priv, Payload("msp", exp));

            var r = LicenceReader.Resolve(token, pub, Now);

            Assert.Equal("msp", r.Tier);
            Assert.Equal("grace", r.Note);
        }

        [Fact]
        public void ExpiredPastGrace_FallsBackToFree()
        {
            var (pub, priv) = Ed25519TestKit.GenerateKeyPair();
            var exp = Now.ToUnixTimeSeconds() - 30 * 86400; // well past 14-day grace
            var token = Ed25519TestKit.MintLicence(priv, Payload("pro", exp));

            var r = LicenceReader.Resolve(token, pub, Now);

            Assert.Equal("free", r.Tier);
            Assert.Equal("expired past grace", r.Note);
        }

        [Fact]
        public void TamperedToken_FallsBackToFree()
        {
            var (pub, priv) = Ed25519TestKit.GenerateKeyPair();
            var token = Ed25519TestKit.MintLicence(priv, Payload("pro", Now.ToUnixTimeSeconds() + 86400));
            // Corrupt one char of the payload segment.
            var chars = token.ToCharArray();
            chars[3] = chars[3] == 'A' ? 'B' : 'A';
            var tampered = new string(chars);

            var r = LicenceReader.Resolve(tampered, pub, Now);

            Assert.Equal("free", r.Tier);
        }

        [Fact]
        public void WrongVerifyKey_RejectsToFree()
        {
            var (_, priv) = Ed25519TestKit.GenerateKeyPair();
            var (otherPub, _) = Ed25519TestKit.GenerateKeyPair();
            var token = Ed25519TestKit.MintLicence(priv, Payload("pro", Now.ToUnixTimeSeconds() + 86400));

            var r = LicenceReader.Resolve(token, otherPub, Now);

            Assert.Equal("free", r.Tier);
            Assert.Equal("signature does not verify", r.Note);
        }

        [Fact]
        public void DecodeOnly_NoKey_ReadsTierWithoutVerifying()
        {
            var (_, priv) = Ed25519TestKit.GenerateKeyPair();
            var token = Ed25519TestKit.MintLicence(priv, Payload("pro", Now.ToUnixTimeSeconds() + 86400));

            // No verify key supplied -> trust the payload for tier (UI/channel only).
            var r = LicenceReader.Resolve(token, null, Now);

            Assert.Equal("pro", r.Tier);
        }

        [Theory]
        [InlineData("free", "base", "snapshot", false)]
        [InlineData("pro", "live", "live", true)]
        [InlineData("msp", "live", "live", true)]
        public void EntitlementTable_MatchesLicencePy(string tier, string packMustContain, string channel, bool premium)
        {
            var ent = LicenceReader.EntitlementFor(tier);
            Assert.Equal(channel, ent.Channel);
            Assert.Equal(premium, ent.Premium);
            Assert.Contains(packMustContain == "live" ? "base" : packMustContain, ent.Packs);
        }

        [Fact]
        public void CanAccess_FreeTierCannotPullPremiumPack()
        {
            Assert.True(LicenceReader.CanAccess("free", "base", "snapshot"));
            Assert.False(LicenceReader.CanAccess("free", "persistence-premium", "snapshot"));
            Assert.True(LicenceReader.CanAccess("pro", "persistence-premium", "live"));
            Assert.True(LicenceReader.CanAccess("msp", "federation", "live"));
            Assert.False(LicenceReader.CanAccess("pro", "federation", "live"));
        }

        [Fact]
        public void CanAccess_FreeTierCannotPullLiveChannel()
        {
            // free is entitled to base, but only on the snapshot channel.
            Assert.False(LicenceReader.CanAccess("free", "base", "live"));
        }
    }
}
