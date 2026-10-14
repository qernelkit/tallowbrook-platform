using System.Security.Cryptography;
using Microsoft.Extensions.Options;

namespace Tallowbrook.Billing.Web.Invoices;

public sealed class DocumentStoreOptions
{
    public string RootPath { get; set; } = "/var/lib/tallowbrook/billing/documents";
}

/// <summary>
/// Rendered invoice PDFs on the shared volume. Files are named by content, so a re-render that produces
/// the same bytes (a reminder, a duplicate request from the portal) is stored once.
/// </summary>
public sealed class InvoiceDocumentStore(IOptions<DocumentStoreOptions> options, ILogger<InvoiceDocumentStore> logger)
{
    public async Task<string> SaveAsync(Invoice invoice, byte[] pdf, CancellationToken ct)
    {
        string address = Convert.ToHexString(SHA256.HashData(pdf)).ToLowerInvariant();
        string path = PathFor(address);
        if (!File.Exists(path))
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            string partial = path + ".partial";
            await File.WriteAllBytesAsync(partial, pdf, ct);
            File.Move(partial, path, overwrite: true);
        }

        logger.LogInformation("Stored PDF of invoice {InvoiceNumber} as {Address} ({Bytes} bytes)", invoice.Number, address, pdf.Length);
        return address;
    }

    public async Task<byte[]?> ReadAsync(string address, CancellationToken ct)
    {
        string path = PathFor(address);
        return File.Exists(path) ? await File.ReadAllBytesAsync(path, ct) : null;
    }

    private string PathFor(string address)
    {
        if (address.Length != 64 || !address.All(char.IsAsciiHexDigitLower))
        {
            throw new ArgumentException("Not a document address.", nameof(address));
        }

        // Two levels of fan-out keep directories small on the shared volume.
        return Path.Combine(options.Value.RootPath, address[..2], address[2..4], address + ".pdf");
    }
}
