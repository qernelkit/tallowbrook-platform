using System.Security.Cryptography;

namespace Tallowbrook.Billing.Agent.Banking;

/// <summary>Fixed by the bank's payment-file and statement specifications (version 3.1).</summary>
internal static class BankProfile
{
    public const string FileFormatVersion = "TBK-PAY 3.1";
    public const int BlockSize = 512;

    // Trailer checksum over the plain blocks.
    public static readonly HashAlgorithmName ControlHash = HashAlgorithmName.SHA512;

    // Curve of the key the bank signs account statements with.
    public static readonly ECCurve StatementCurve = ECCurve.NamedCurves.brainpoolP256r1;
}
