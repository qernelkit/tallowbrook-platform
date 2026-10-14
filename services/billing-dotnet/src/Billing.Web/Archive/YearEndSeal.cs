using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace Tallowbrook.Billing.Web.Archive;

/// <summary>
/// On 2 January the index of last year's nightly manifests is sealed with a hash-based signature and
/// filed with the tax records. That seal is what the ten-year retention check starts from.
/// </summary>
public sealed class YearEndSeal(IOptions<ArchiveOptions> options, ILogger<YearEndSeal> logger)
{
    public async Task SealYearAsync(int year, CancellationToken ct)
    {
        string root = Path.Combine(options.Value.Directory, year.ToString("D4"));
        string[] manifests = Directory.GetFiles(root, "*.manifest.json", SearchOption.AllDirectories);
        Array.Sort(manifests, StringComparer.Ordinal);

        var index = new StringBuilder();
        foreach (string manifest in manifests)
        {
            byte[] content = await File.ReadAllBytesAsync(manifest, ct);
            index.AppendLine($"{Path.GetRelativePath(root, manifest)} {content.Length}");
        }

        byte[] indexBytes = Encoding.UTF8.GetBytes(index.ToString());
        await File.WriteAllBytesAsync(Path.Combine(root, "year-index.txt"), indexBytes, ct);

        // SlhDsa is marked experimental in .NET 10.
#pragma warning disable SYSLIB5006
        using SlhDsa seal = SlhDsa.ImportSlhDsaPrivateKey(SlhDsaAlgorithm.SlhDsaSha2_128s, options.Value.SealKey);
        byte[] signature = seal.SignData(indexBytes);
#pragma warning restore SYSLIB5006

        await File.WriteAllBytesAsync(Path.Combine(root, "year-index.sig"), signature, ct);
        logger.LogInformation("Sealed {Count} manifests of {Year}", manifests.Length, year);
    }
}
