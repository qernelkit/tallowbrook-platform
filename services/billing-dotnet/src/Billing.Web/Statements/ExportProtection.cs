using System.Security.Cryptography;

namespace Tallowbrook.Billing.Web.Statements;

/// <summary>Parameters of the passphrase-protected statement export format (.tbx).</summary>
internal static class ExportProtection
{
    public const int Iterations = 600_000;
    public static readonly HashAlgorithmName KdfHash = HashAlgorithmName.SHA256;

    public const int SaltBytes = 16;
    public const int NonceBytes = 12;
    public const int TagBytes = 16;

    public static ReadOnlySpan<byte> Magic => "TBX1"u8;
}
