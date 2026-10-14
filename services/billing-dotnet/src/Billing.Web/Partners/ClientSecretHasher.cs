using System.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace Tallowbrook.Billing.Web.Partners;

public sealed record ClientSecretVerifier(byte[] Salt, byte[] Hash, DateTimeOffset CreatedAt);

/// <summary>
/// Partner API clients authenticate with a client id and a generated secret. We keep only a verifier;
/// a lost secret is rotated, never looked up.
/// </summary>
public sealed class ClientSecretHasher(TimeProvider clock)
{
    public (string Secret, ClientSecretVerifier Verifier) NewSecret()
    {
        string secret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(ClientSecretPolicy.SecretBytes)).TrimEnd('=');
        byte[] salt = RandomNumberGenerator.GetBytes(ClientSecretPolicy.SaltBytes);
        return (secret, new ClientSecretVerifier(salt, Derive(secret, salt), clock.GetUtcNow()));
    }

    public bool Matches(string presented, ClientSecretVerifier stored) =>
        CryptographicOperations.FixedTimeEquals(Derive(presented, stored.Salt), stored.Hash);

    private static byte[] Derive(string secret, byte[] salt)
    {
        byte[] hash = KeyDerivation.Pbkdf2(secret, salt, ClientSecretPolicy.Prf, ClientSecretPolicy.Iterations, ClientSecretPolicy.HashBytes);
        return hash;
    }
}
