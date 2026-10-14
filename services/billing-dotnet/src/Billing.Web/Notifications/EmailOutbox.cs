using System.Threading.Channels;

namespace Tallowbrook.Billing.Web.Notifications;

/// <summary>Emails are handed to the company mail relay by the outbox relay service, not sent from here.</summary>
public sealed class EmailOutbox(ILogger<EmailOutbox> logger)
{
    private readonly Channel<OutgoingEmail> _queue = Channel.CreateBounded<OutgoingEmail>(10_000);

    public ChannelReader<OutgoingEmail> Reader => _queue.Reader;

    public async ValueTask EnqueueAsync(OutgoingEmail email, CancellationToken ct)
    {
        await _queue.Writer.WriteAsync(email, ct);
        logger.LogDebug("Queued email to {Recipient}: {Subject}", email.To, email.Subject);
    }
}
