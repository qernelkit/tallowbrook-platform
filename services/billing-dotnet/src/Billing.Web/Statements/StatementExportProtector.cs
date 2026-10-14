using System.Security.Cryptography;

namespace Tallowbrook.Billing.Web.Statements;

/// <summary>
/// Customers can download their statements protected with a passphrase they choose, e.g. to send them
/// on to their tax adviser. Layout: magic || salt || nonce || tag || ciphertext. The open-source
/// tbx-open tool on the portal's help page reads the same format.
/// </summary>
public sealed class StatementExportProtector
{
    public byte[] Protect(byte[] statement, string passphrase)
    {
        int header = ExportProtection.Magic.Length + ExportProtection.SaltBytes + ExportProtection.NonceBytes + ExportProtection.TagBytes;
        byte[] output = new byte[header + statement.Length];
        ExportProtection.Magic.CopyTo(output);

        Span<byte> salt = output.AsSpan(ExportProtection.Magic.Length, ExportProtection.SaltBytes);
        Span<byte> nonce = output.AsSpan(ExportProtection.Magic.Length + ExportProtection.SaltBytes, ExportProtection.NonceBytes);
        Span<byte> tag = output.AsSpan(header - ExportProtection.TagBytes, ExportProtection.TagBytes);
        RandomNumberGenerator.Fill(salt);
        RandomNumberGenerator.Fill(nonce);

        using var aead = CreateAead(passphrase, salt.ToArray());
        aead.Encrypt(nonce, statement, output.AsSpan(header), tag, ExportProtection.Magic);
        return output;
    }

    public byte[] Unprotect(byte[] export, string passphrase)
    {
        int header = ExportProtection.Magic.Length + ExportProtection.SaltBytes + ExportProtection.NonceBytes + ExportProtection.TagBytes;
        if (export.Length < header || !export.AsSpan(0, ExportProtection.Magic.Length).SequenceEqual(ExportProtection.Magic))
        {
            throw new InvalidDataException("Not a protected statement export.");
        }

        byte[] salt = export.AsSpan(ExportProtection.Magic.Length, ExportProtection.SaltBytes).ToArray();
        ReadOnlySpan<byte> nonce = export.AsSpan(ExportProtection.Magic.Length + ExportProtection.SaltBytes, ExportProtection.NonceBytes);
        ReadOnlySpan<byte> tag = export.AsSpan(header - ExportProtection.TagBytes, ExportProtection.TagBytes);
        byte[] statement = new byte[export.Length - header];

        using var aead = CreateAead(passphrase, salt);
        aead.Decrypt(nonce, export.AsSpan(header), tag, statement, ExportProtection.Magic);
        return statement;
    }

    private static ChaCha20Poly1305 CreateAead(string passphrase, byte[] salt)
    {
        byte[] key = Rfc2898DeriveBytes.Pbkdf2(passphrase, salt, ExportProtection.Iterations, ExportProtection.KdfHash, 32);
        try
        {
            return new ChaCha20Poly1305(key);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }
}
