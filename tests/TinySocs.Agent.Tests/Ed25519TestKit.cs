using System.Text;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace TinySocs.Agent.Tests
{
    /// <summary>
    /// Hermetic ed25519 signing helpers for tests. Mirrors what the Python signer
    /// (scripts/pack_sign.py, scripts/licence.py) produces, but stays C#-only so the
    /// test suite needs no Python, no committed keys, and no external fixtures.
    /// The verify side under test is the production Ed25519Verifier (BouncyCastle).
    /// </summary>
    public static class Ed25519TestKit
    {
        public static (byte[] Pub, byte[] Priv) GenerateKeyPair()
        {
            var gen = new Ed25519KeyPairGenerator();
            gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
            var kp = gen.GenerateKeyPair();
            var pub = ((Ed25519PublicKeyParameters)kp.Public).GetEncoded();
            var priv = ((Ed25519PrivateKeyParameters)kp.Private).GetEncoded();
            return (pub, priv);
        }

        public static byte[] Sign(byte[] privRaw, byte[] message)
        {
            var priv = new Ed25519PrivateKeyParameters(privRaw, 0);
            var signer = new Ed25519Signer();
            signer.Init(forSigning: true, priv);
            signer.BlockUpdate(message, 0, message.Length);
            return signer.GenerateSignature();
        }

        public static string B64(byte[] b) => Convert.ToBase64String(b);

        public static string B64Url(byte[] b) =>
            Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        /// <summary>Mint a licence token: base64url(payload).base64url(sig), like scripts/licence.py.</summary>
        public static string MintLicence(byte[] privRaw, string payloadJson)
        {
            var payloadBytes = Encoding.UTF8.GetBytes(payloadJson);
            var sig = Sign(privRaw, payloadBytes);
            return B64Url(payloadBytes) + "." + B64Url(sig);
        }
    }
}
