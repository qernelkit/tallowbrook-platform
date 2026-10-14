using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace Tallowbrook.Billing.Web.Partners;

/// <summary>How partner API client secrets are stored.</summary>
internal static class ClientSecretPolicy
{
    public const KeyDerivationPrf Prf = KeyDerivationPrf.HMACSHA512;
    public const int Iterations = 210_000;
    public const int SaltBytes = 16;
    public const int HashBytes = 32;
    public const int SecretBytes = 32;
}
