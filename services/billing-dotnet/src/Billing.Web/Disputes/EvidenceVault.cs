using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;

namespace Tallowbrook.Billing.Web.Disputes;

public sealed class DisputeOptions
{
    public string EvidencePath { get; set; } = "/var/lib/tallowbrook/billing/disputes";

    /// <summary>The disputes team's certificate; they open evidence offline with the matching key.</summary>
    public string RecipientCertificatePath { get; set; } = "";

    public long MaxUploadBytes { get; set; } = 25 * 1024 * 1024;
}

public sealed record StoredEvidence(Guid Id, string DisputeId, string FileName, long Bytes, string Path);

/// <summary>
/// Files customers upload as dispute evidence (delivery photos, signed delivery notes). Each file gets its
/// own random key, which is wrapped for the disputes team and stored next to the file.
/// </summary>
public sealed class EvidenceVault(IOptions<DisputeOptions> options, ILogger<EvidenceVault> logger)
{
    private readonly Lazy<X509Certificate2> _recipient = new(() => X509CertificateLoader.LoadCertificateFromFile(options.Value.RecipientCertificatePath));

    public async Task<StoredEvidence> StoreAsync(string disputeId, string fileName, Stream upload, CancellationToken ct)
    {
        var id = Guid.NewGuid();
        string directory = Path.Combine(options.Value.EvidencePath, disputeId);
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, $"{id:N}.bin");

        using Aes aes = Aes.Create();
        using RSA recipient = _recipient.Value.GetRSAPublicKey() ?? throw new InvalidOperationException("The disputes certificate has no RSA key.");
        byte[] wrappedKey = recipient.Encrypt(aes.Key, RSAEncryptionPadding.OaepSHA256);

        long bytes;
        await using (FileStream file = File.Create(path))
        {
            await file.WriteAsync(BitConverter.GetBytes(wrappedKey.Length), ct);
            await file.WriteAsync(wrappedKey, ct);
            await file.WriteAsync(aes.IV, ct);
            using ICryptoTransform encryptor = aes.CreateEncryptor();
            await using var stream = new CryptoStream(file, encryptor, CryptoStreamMode.Write);
            await upload.CopyToAsync(stream, ct);
            await stream.FlushFinalBlockAsync(ct);
            bytes = file.Length;
        }

        logger.LogInformation("Stored evidence {EvidenceId} for dispute {DisputeId} ({Bytes} bytes)", id, disputeId, bytes);
        return new StoredEvidence(id, disputeId, Path.GetFileName(fileName), bytes, path);
    }
}
