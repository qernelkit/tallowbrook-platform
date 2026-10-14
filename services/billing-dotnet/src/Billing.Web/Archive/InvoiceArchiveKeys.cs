using System.Security.Cryptography;
using Azure.Security.KeyVault.Keys.Cryptography;
using KvEncryptionAlgorithm = Azure.Security.KeyVault.Keys.Cryptography.EncryptionAlgorithm;

namespace Tallowbrook.Billing.Web.Archive;

public sealed record ArchiveKey(byte[] Key, byte[] WrappedKey, string KekId);

/// <summary>
/// Each night's archive is sealed under a fresh 256-bit key. Only the wrapped copy is stored; unwrapping
/// needs the billing-archive-kek in Key Vault, which never leaves the HSM.
/// </summary>
public sealed class InvoiceArchiveKeys(CryptographyClient archiveKek)
{
    private static readonly KvEncryptionAlgorithm KeyWrap = KvEncryptionAlgorithm.RsaOaep256;

    public async Task<ArchiveKey> CreateAsync(CancellationToken ct)
    {
        byte[] dek = RandomNumberGenerator.GetBytes(32);
        EncryptResult wrapped = await archiveKek.EncryptAsync(KeyWrap, dek, ct);
        return new ArchiveKey(dek, wrapped.Ciphertext, wrapped.KeyId);
    }

    public async Task<byte[]> UnwrapAsync(byte[] wrappedKey, CancellationToken ct)
    {
        DecryptResult unwrapped = await archiveKek.DecryptAsync(KeyWrap, wrappedKey, ct);
        return unwrapped.Plaintext;
    }
}
