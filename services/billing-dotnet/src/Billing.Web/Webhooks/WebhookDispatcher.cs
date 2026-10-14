using System.Collections.Concurrent;
using System.Text.Json;
using System.Threading.Channels;

namespace Tallowbrook.Billing.Web.Webhooks;

/// <summary>Delivers queued webhook events with retries; a subscription is paused after 20 failures in a row.</summary>
public sealed class WebhookDispatcher(
    IHttpClientFactory httpClients,
    OutboundWebhookSigner signer,
    ILogger<WebhookDispatcher> logger) : BackgroundService
{
    private const int PauseAfterFailures = 20;
    private static readonly TimeSpan[] Backoff = [TimeSpan.FromSeconds(10), TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(10), TimeSpan.FromHours(1)];

    private readonly Channel<WebhookDelivery> _queue = Channel.CreateUnbounded<WebhookDelivery>();
    private readonly ConcurrentDictionary<Guid, WebhookSubscription> _subscriptions = new();

    public void Subscribe(WebhookSubscription subscription) => _subscriptions[subscription.Id] = subscription;

    public void Publish(string customerId, string eventName, object body)
    {
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(new { type = eventName, data = body });
        foreach (WebhookSubscription subscription in _subscriptions.Values.Where(s => s.CustomerId == customerId && s.Events.Contains(eventName) && !s.Paused))
        {
            _queue.Writer.TryWrite(new WebhookDelivery
            {
                Id = Guid.NewGuid(),
                SubscriptionId = subscription.Id,
                Event = eventName,
                Payload = payload,
            });
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        HttpClient http = httpClients.CreateClient("webhooks");
        await foreach (WebhookDelivery delivery in _queue.Reader.ReadAllAsync(stoppingToken))
        {
            if (!_subscriptions.TryGetValue(delivery.SubscriptionId, out WebhookSubscription? subscription) || subscription.Paused)
            {
                continue;
            }

            delivery.Attempt++;
            try
            {
                using HttpRequestMessage request = signer.CreateRequest(delivery, subscription);
                using HttpResponseMessage response = await http.SendAsync(request, stoppingToken);
                response.EnsureSuccessStatusCode();
                subscription.ConsecutiveFailures = 0;
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException && !stoppingToken.IsCancellationRequested)
            {
                subscription.ConsecutiveFailures++;
                logger.LogWarning(ex, "Webhook {DeliveryId} to {Url} failed (attempt {Attempt})", delivery.Id, subscription.Url, delivery.Attempt);
                if (subscription.ConsecutiveFailures >= PauseAfterFailures)
                {
                    subscription.Paused = true;
                    logger.LogError("Paused webhook subscription {SubscriptionId} after {Failures} failures", subscription.Id, subscription.ConsecutiveFailures);
                }
                else if (delivery.Attempt <= Backoff.Length)
                {
                    _ = RequeueAsync(delivery, Backoff[delivery.Attempt - 1], stoppingToken);
                }
            }
        }
    }

    private async Task RequeueAsync(WebhookDelivery delivery, TimeSpan delay, CancellationToken ct)
    {
        await Task.Delay(delay, ct);
        await _queue.Writer.WriteAsync(delivery, ct);
    }
}
