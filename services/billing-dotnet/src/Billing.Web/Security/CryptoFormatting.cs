using System.Buffers.Text;

namespace Tallowbrook.Billing.Web.Security;

/// <summary>Text helpers for values that end up in URLs, headers and file names.</summary>
internal static class CryptoFormatting
{
    private const string PemCertificateHeader = "-----BEGIN CERTIFICATE-----";

    public static string ToLowerHex(ReadOnlySpan<byte> bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    public static string ToBase64Url(ReadOnlySpan<byte> bytes) => Base64Url.EncodeToString(bytes);

    public static byte[] FromBase64Url(string text) => Base64Url.DecodeFromChars(text);

    /// <summary>
    /// Cheap check on partner uploads before they are stored for review: the operations team only
    /// accepts text exports, and a binary file here is almost always the wrong attachment.
    /// </summary>
    public static bool LooksLikePem(string text) => text.TrimStart().StartsWith(PemCertificateHeader, StringComparison.Ordinal);
}
