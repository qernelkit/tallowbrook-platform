using Microsoft.Extensions.Options;
using Tallowbrook.Billing.Agent.Payouts;
using Tallowbrook.Billing.Payouts;

namespace Tallowbrook.Billing.Agent.Workers;

/// <summary>Publishes this run's payout keys, then collects and opens instructions every minute.</summary>
internal sealed class PayoutWorker(
    BillingApiClient billing,
    PayoutKeyPair keys,
    PayoutInstructionReceiver receiver,
    PaymentQueue queue,
    IOptions<PayoutOptions> options,
    TimeProvider clock,
    ILogger<PayoutWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        string agentId = options.Value.AgentId;
        await billing.PublishKeysAsync(keys.Describe(agentId, clock.GetUtcNow()), stoppingToken);
        logger.LogInformation("Agent {AgentId} published its payout keys", agentId);

        using var timer = new PeriodicTimer(options.Value.PollInterval, clock);
        do
        {
            try
            {
                foreach (SealedPayoutInstruction message in await billing.CollectAsync(agentId, stoppingToken))
                {
                    if (receiver.Open(message) is { } instruction && queue.Add(instruction))
                    {
                        logger.LogInformation("Queued payout {InstructionId}: {Amount} {Currency} to {Beneficiary}", instruction.Id, instruction.Amount, instruction.Currency, instruction.BeneficiaryName);
                    }
                }
            }
            catch (HttpRequestException ex)
            {
                logger.LogWarning(ex, "Billing API unavailable; will retry");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
