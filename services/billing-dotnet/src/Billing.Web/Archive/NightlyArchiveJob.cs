using System.IO.Compression;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Tallowbrook.Billing.Security;
using Tallowbrook.Billing.Web.Invoices;

namespace Tallowbrook.Billing.Web.Archive;

public sealed record ArchiveManifest(DateOnly Day, int Invoices, string ArchiveFile, long ArchiveBytes, string WrappedKey, string KekId);

/// <summary>
/// Every night: the previous day's issued invoices and their PDFs go into one sealed archive for the
/// ten-year retention period, with a signed manifest next to it. On 2 January the year is sealed too.
/// </summary>
internal sealed class NightlyArchiveJob(
    IInvoiceStore invoices,
    InvoiceDocumentStore documents,
    InvoiceArchiveKeys keys,
    ArchiveManifestSigner signer,
    YearEndSeal yearEnd,
    IOptions<ArchiveOptions> options,
    TimeProvider clock,
    ILogger<NightlyArchiveJob> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(UntilNextRun(clock.GetUtcNow(), options.Value.RunAtUtc), clock, stoppingToken);
            DateOnly today = DateOnly.FromDateTime(clock.GetUtcNow().UtcDateTime);
            try
            {
                await ArchiveDayAsync(today.AddDays(-1), stoppingToken);
                if (today.Month == 1 && today.Day == 2)
                {
                    await yearEnd.SealYearAsync(today.Year - 1, stoppingToken);
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Archive run for {Day} failed; it will be retried tomorrow with both days", today.AddDays(-1));
            }
        }
    }

    internal async Task ArchiveDayAsync(DateOnly day, CancellationToken ct)
    {
        IReadOnlyList<Invoice> issued = invoices.IssuedOn(day);
        if (issued.Count == 0)
        {
            logger.LogInformation("Nothing to archive for {Day}", day);
            return;
        }

        using var zip = new MemoryStream();
        using (var archive = new ZipArchive(zip, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (Invoice invoice in issued)
            {
                ZipArchiveEntry json = archive.CreateEntry($"{invoice.Number}.json", CompressionLevel.Optimal);
                await using (Stream entry = json.Open())
                {
                    await JsonSerializer.SerializeAsync(entry, invoice, cancellationToken: ct);
                }

                if (invoice.PdfAddress is not null && await documents.ReadAsync(invoice.PdfAddress, ct) is { } pdf)
                {
                    ZipArchiveEntry pdfEntry = archive.CreateEntry($"{invoice.Number}.pdf", CompressionLevel.NoCompression);
                    await using Stream entry = pdfEntry.Open();
                    await entry.WriteAsync(pdf, ct);
                }
            }
        }

        ArchiveKey key = await keys.CreateAsync(ct);
        byte[] boxed = AeadBox.Seal(key.Key, zip.ToArray(), System.Text.Encoding.ASCII.GetBytes(day.ToString("yyyy-MM-dd")));

        string directory = Path.Combine(options.Value.Directory, day.Year.ToString("D4"), day.Month.ToString("D2"));
        Directory.CreateDirectory(directory);
        string archiveFile = $"{day:yyyy-MM-dd}.archive";
        await File.WriteAllBytesAsync(Path.Combine(directory, archiveFile), boxed, ct);

        var manifest = new ArchiveManifest(day, issued.Count, archiveFile, boxed.Length, Convert.ToBase64String(key.WrappedKey), key.KekId);
        byte[] manifestBytes = JsonSerializer.SerializeToUtf8Bytes(manifest);
        ManifestSignatures signatures = await signer.SignAsync(manifestBytes, ct);

        await File.WriteAllBytesAsync(Path.Combine(directory, $"{day:yyyy-MM-dd}.manifest.json"), manifestBytes, ct);
        await File.WriteAllBytesAsync(Path.Combine(directory, $"{day:yyyy-MM-dd}.manifest.kv.sig"), signatures.KeyVault, ct);
        await File.WriteAllBytesAsync(Path.Combine(directory, $"{day:yyyy-MM-dd}.manifest.ml.sig"), signatures.Lattice, ct);
        logger.LogInformation("Archived {Count} invoices of {Day}", issued.Count, day);
    }

    private static TimeSpan UntilNextRun(DateTimeOffset now, TimeOnly at)
    {
        DateTimeOffset next = new DateTimeOffset(now.UtcDateTime.Date, TimeSpan.Zero) + at.ToTimeSpan();
        if (next <= now)
        {
            next = next.AddDays(1);
        }

        return next - now;
    }
}
