using System.Net.Http.Headers;
using System.Security.Cryptography;

namespace Tallowbrook.Billing.Web.Webhooks;

/// <summary>
/// Builds the HTTP request for one webhook delivery. Subscribers check X-Tallowbrook-Signature against
/// the raw body with the secret they were given when they subscribed.
/// </summary>
public sealed class OutboundWebhookSigner(TimeProvider clock)
{
    public HttpRequestMessage CreateRequest(WebhookDelivery delivery, WebhookSubscription subscription)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, subscription.Url)
        {
            Content = new ByteArrayContent(delivery.Payload),
        };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        request.Headers.Add("X-Tallowbrook-Event", delivery.Event);
        request.Headers.Add("X-Tallowbrook-Delivery", delivery.Id.ToString());
        request.Headers.Add("X-Tallowbrook-Timestamp", clock.GetUtcNow().ToUnixTimeSeconds().ToString());

        foreach (KeyValuePair<string, string> header in delivery.Headers)
            request.Headers.TryAddWithoutValidation(header.Key, header.Value);
        byte[] signature = HMACSHA256.HashData(subscription.Secret, delivery.Payload);
        request.Headers.Add("X-Tallowbrook-Signature", Convert.ToHexStringLower(signature));
        return request;
    }
}
