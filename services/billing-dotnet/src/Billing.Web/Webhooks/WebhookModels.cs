namespace Tallowbrook.Billing.Web.Webhooks;

/// <summary>An accounting integration that wants invoice.created / invoice.paid events.</summary>
public sealed class WebhookSubscription
{
    public required Guid Id { get; init; }

    public required string CustomerId { get; init; }

    public required Uri Url { get; init; }

    public required IReadOnlySet<string> Events { get; init; }

    /// <summary>Shared with the subscriber when the subscription is created; loaded from the secrets store.</summary>
    public required byte[] Secret { get; init; }

    public bool Paused { get; set; }

    public int ConsecutiveFailures { get; set; }
}

public sealed class WebhookDelivery
{
    public required Guid Id { get; init; }

    public required Guid SubscriptionId { get; init; }

    public required string Event { get; init; }

    public required byte[] Payload { get; init; }

    /// <summary>Extra headers the subscriber configured (e.g. their tenant key in the accounting tool).</summary>
    public IReadOnlyDictionary<string, string> Headers { get; init; } = new Dictionary<string, string>();

    public int Attempt { get; set; }
}
