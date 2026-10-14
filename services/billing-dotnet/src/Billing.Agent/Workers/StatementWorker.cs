using System.Runtime.Versioning;
using Microsoft.Extensions.Options;
using Tallowbrook.Billing.Agent.Banking;
using Tallowbrook.Billing.Agent.Statements;

namespace Tallowbrook.Billing.Agent.Workers;

/// <summary>Downloads new account statements, checks the bank's signature and spools them for bookkeeping.</summary>
[SupportedOSPlatform("windows")]
internal sealed class StatementWorker(
    BankGatewayClient bank,
    StatementVerifier verifier,
    StatementSpool spool,
    IOptions<StatementOptions> options,
    TimeProvider clock,
    ILogger<StatementWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        DateOnly since = DateOnly.FromDateTime(clock.GetLocalNow().DateTime).AddDays(-7);
        var seen = new HashSet<string>(spool.Pending(), StringComparer.Ordinal);

        using var timer = new PeriodicTimer(options.Value.PollInterval, clock);
        do
        {
            try
            {
                foreach (BankStatement statement in await bank.DownloadStatementsAsync(since, stoppingToken))
                {
                    if (seen.Contains(statement.Id) || !verifier.Verify(statement.Id, statement.Document, statement.Signature))
                    {
                        continue;
                    }

                    await spool.SpoolAsync(statement.Id, statement.Document, stoppingToken);
                    seen.Add(statement.Id);
                    logger.LogInformation("Spooled statement {StatementId} booked {BookingDate}", statement.Id, statement.BookingDate);
                }
            }
            catch (HttpRequestException ex)
            {
                logger.LogWarning(ex, "Bank portal unavailable; will retry");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
