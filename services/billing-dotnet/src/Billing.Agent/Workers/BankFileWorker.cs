using System.Runtime.Versioning;
using Microsoft.Extensions.Options;
using Tallowbrook.Billing.Agent.Banking;
using Tallowbrook.Billing.Agent.Payouts;
using Tallowbrook.Billing.Payouts;

namespace Tallowbrook.Billing.Agent.Workers;

/// <summary>At each cut-off on a working day: one payment file with everything due, signed and uploaded.</summary>
[SupportedOSPlatform("windows")]
internal sealed class BankFileWorker(
    PaymentQueue queue,
    BankFileWriter writer,
    PaymentFileSigner signer,
    BankGatewayClient bank,
    IOptions<BankFileOptions> options,
    TimeProvider clock,
    ILogger<BankFileWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(UntilNextCutOff(clock.GetLocalNow(), options.Value.CutOffs), clock, stoppingToken);
            DateOnly today = DateOnly.FromDateTime(clock.GetLocalNow().DateTime);
            IReadOnlyList<PayoutInstruction> due = queue.TakeDue(today);
            if (due.Count == 0)
            {
                continue;
            }

            string batchId = $"TB{clock.GetLocalNow():yyyyMMddHHmm}";
            try
            {
                byte[] file = writer.Write(batchId, today, due);
                byte[] signature = signer.Sign(file);
                Directory.CreateDirectory(options.Value.OutboxPath);
                await File.WriteAllBytesAsync(Path.Combine(options.Value.OutboxPath, $"{batchId}.pay"), file, stoppingToken);
                await bank.UploadPaymentFileAsync(batchId, file, signature, stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                queue.Return(due);
                logger.LogError(ex, "Payment file {BatchId} was not delivered; its {Count} payment(s) go into the next file", batchId, due.Count);
            }
        }
    }

    internal static TimeSpan UntilNextCutOff(DateTimeOffset now, IReadOnlyList<TimeOnly> cutOffs)
    {
        for (int day = 0; day < 8; day++)
        {
            DateTimeOffset date = now.Date.AddDays(day);
            if (date.DayOfWeek is DayOfWeek.Saturday or DayOfWeek.Sunday)
            {
                continue;
            }

            foreach (TimeOnly cutOff in cutOffs.Order())
            {
                DateTimeOffset at = new DateTimeOffset(date.Date, now.Offset) + cutOff.ToTimeSpan();
                if (at > now)
                {
                    return at - now;
                }
            }
        }

        return TimeSpan.FromHours(1);
    }
}
