using System.Security.Cryptography;

namespace Tallowbrook.Billing.Payouts;

/// <summary>
/// Key handling for payout instructions sent from Billing.Web to the agent on the finance host. The
/// instruction key combines an elliptic-curve agreement with the agent's KEM secret. Shared with
/// Billing.Agent, so both ends derive the key with exactly this code.
/// </summary>
public static class PayoutEnvelope
{
    public static readonly ECCurve Curve = ECCurve.NamedCurves.nistP256;

    private static readonly HashAlgorithmName KdfHash = HashAlgorithmName.SHA256;
    private const int KeyBytes = 32;
    private static readonly byte[] Info = "tallowbrook-payout-instruction-v1"u8.ToArray();

    public static ECDiffieHellman CreateKey() => ECDiffieHellman.Create(Curve);

    public static ECDiffieHellman ImportPublicKey(byte[] spki)
    {
        var key = ECDiffieHellman.Create(Curve);
        key.ImportSubjectPublicKeyInfo(spki, out _);
        return key;
    }

    public static byte[] DeriveKey(ECDiffieHellman own, ECDiffieHellman peer, byte[] kemSecret, byte[] salt)
    {
        byte[] agreed = own.DeriveRawSecretAgreement(peer.PublicKey);
        try
        {
            return HKDF.DeriveKey(KdfHash, [.. agreed, .. kemSecret], KeyBytes, salt, Info);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(agreed);
        }
    }
}
