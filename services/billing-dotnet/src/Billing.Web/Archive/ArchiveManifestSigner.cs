using System.Security.Cryptography;
using Azure.Security.KeyVault.Keys.Cryptography;
using Microsoft.Extensions.Options;

namespace Tallowbrook.Billing.Web.Archive;

public sealed record ManifestSignatures(byte[] KeyVault, string KeyVaultKeyId, byte[] Lattice);

/// <summary>
/// The nightly manifest carries two signatures: one by the Key Vault key, and one by a key whose seed
/// the operators keep in the vault. The retention auditors check both.
/// </summary>
public sealed class ArchiveManifestSigner(CryptographyClient manifestKey, IOptions<ArchiveOptions> options)
{
    public async Task<ManifestSignatures> SignAsync(byte[] manifestBytes, CancellationToken ct)
    {
        SignResult classical = await manifestKey.SignDataAsync(SignatureAlgorithm.ES384, manifestBytes, ct);
        using MLDsa seedKey = MLDsa.ImportMLDsaPrivateSeed(MLDsaAlgorithm.MLDsa65, options.Value.ManifestSeed);
        byte[] lattice = seedKey.SignData(manifestBytes);
        return new ManifestSignatures(classical.Signature, classical.KeyId, lattice);
    }
}
