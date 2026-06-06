using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace TinySocs.Agent.Detection
{
    /// <summary>
    /// Ed25519 signature verification. .NET 8's BCL has no Ed25519, so this wraps
    /// BouncyCastle. Interoperates with signatures produced by the Python signer
    /// (scripts/pack_sign.py, scripts/licence.py) — both implement RFC 8032.
    /// </summary>
    public static class Ed25519Verifier
    {
        /// <summary>Verify a detached signature over <paramref name="message"/>.</summary>
        /// <param name="publicKeyRaw">32-byte raw Ed25519 public key.</param>
        public static bool Verify(byte[] publicKeyRaw, byte[] message, byte[] signature)
        {
            if (publicKeyRaw == null || publicKeyRaw.Length != 32)
            {
                return false;
            }

            try
            {
                var pub = new Ed25519PublicKeyParameters(publicKeyRaw, 0);
                var signer = new Ed25519Signer();
                signer.Init(forSigning: false, pub);
                signer.BlockUpdate(message, 0, message.Length);
                return signer.VerifySignature(signature);
            }
            catch
            {
                return false;
            }
        }
    }
}
