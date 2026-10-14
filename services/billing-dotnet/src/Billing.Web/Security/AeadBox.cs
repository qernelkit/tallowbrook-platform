using System.Security.Cryptography;

namespace Tallowbrook.Billing.Security;

/// <summary>
/// Seals small payloads under a 256-bit key: processor card tokens, nightly archive objects and payout
/// instructions. Output layout: nonce (12) || tag (16) || ciphertext. Shared with Billing.Agent.
/// </summary>
public static class AeadBox
{
    private const int KeySizeInBytes = 32;
    private const int TagSizeInBytes = 16;
    private const int NonceSizeInBytes = 12;

    public static byte[] Seal(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData = default)
    {
        CheckKey(key);
        byte[] output = new byte[NonceSizeInBytes + TagSizeInBytes + plaintext.Length];
        Span<byte> nonce = output.AsSpan(0, NonceSizeInBytes);
        Span<byte> tag = output.AsSpan(NonceSizeInBytes, TagSizeInBytes);
        Span<byte> body = output.AsSpan(NonceSizeInBytes + TagSizeInBytes);
        RandomNumberGenerator.Fill(nonce);

        using var gcm = Create(key);
        gcm.Encrypt(nonce, plaintext, body, tag, associatedData);
        return output;
    }

    public static byte[] Open(ReadOnlySpan<byte> key, ReadOnlySpan<byte> sealedData, ReadOnlySpan<byte> associatedData = default)
    {
        CheckKey(key);
        if (sealedData.Length < NonceSizeInBytes + TagSizeInBytes)
        {
            throw new ArgumentException("Sealed data is shorter than its header.", nameof(sealedData));
        }

        ReadOnlySpan<byte> nonce = sealedData[..NonceSizeInBytes];
        ReadOnlySpan<byte> tag = sealedData.Slice(NonceSizeInBytes, TagSizeInBytes);
        ReadOnlySpan<byte> body = sealedData[(NonceSizeInBytes + TagSizeInBytes)..];
        byte[] plaintext = new byte[body.Length];

        using var gcm = Create(key);
        gcm.Decrypt(nonce, body, tag, plaintext, associatedData);
        return plaintext;
    }

    private static void CheckKey(ReadOnlySpan<byte> key)
    {
        if (key.Length != KeySizeInBytes)
        {
            throw new ArgumentException($"Expected a {KeySizeInBytes}-byte key.", nameof(key));
        }
    }

    private static AesGcm Create(ReadOnlySpan<byte> key) => new AesGcm(key, TagSizeInBytes);
}
