using Tallowbrook.Billing.Web.Customers;
using Tallowbrook.Billing.Web.Invoices;

namespace Tallowbrook.Billing.Web.Notifications;

/// <summary>Monday 06:00 UTC: one summary email per customer with open invoices.</summary>
internal sealed class WeeklySummaryJob(
    ICustomerStore customers,
    IInvoiceStore invoices,
    InvoiceDigestEmail composer,
    EmailOutbox outbox,
    TimeProvider clock,
    ILogger<WeeklySummaryJob> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            DateTimeOffset now = clock.GetUtcNow();
            await Task.Delay(UntilNextRun(now), clock, stoppingToken);

            DateOnly today = DateOnly.FromDateTime(clock.GetUtcNow().UtcDateTime);
            ILookup<string, Invoice> open = invoices.Open().ToLookup(i => i.CustomerId);
            int sent = 0;
            foreach (Customer customer in customers.All().Where(c => c.WantsWeeklySummary))
            {
                if (composer.Compose(customer, [.. open[customer.Id]], today) is { } email)
                {
                    await outbox.EnqueueAsync(email, stoppingToken);
                    sent++;
                }
            }

            logger.LogInformation("Weekly invoice summaries queued for {Count} customer(s)", sent);
        }
    }

    internal static TimeSpan UntilNextRun(DateTimeOffset now)
    {
        DateTimeOffset next = new DateTimeOffset(now.UtcDateTime.Date, TimeSpan.Zero).AddHours(6);
        while (next <= now || next.DayOfWeek != DayOfWeek.Monday)
        {
            next = next.AddDays(1);
        }

        return next - now;
    }
}
