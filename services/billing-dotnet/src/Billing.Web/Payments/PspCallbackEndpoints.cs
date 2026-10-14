using System.Text.Json;
using Tallowbrook.Billing.Web.Audit;
using Tallowbrook.Billing.Web.Invoices;
using Tallowbrook.Billing.Web.Webhooks;

namespace Tallowbrook.Billing.Web.Payments;

public sealed record PspCallback(string EventType, string MerchantReference, decimal Amount, string Currency, string PspReference);

internal static class PspCallbackEndpoints
{
    public static IEndpointRouteBuilder MapPspCallbacks(this IEndpointRouteBuilder app)
    {
        app.MapPost("/payments/psp/callback", HandleAsync).AllowAnonymous();
        return app;
    }

    private static async Task<IResult> HandleAsync(
        HttpRequest request,
        PspCallbackVerifier verifier,
        IInvoiceStore invoices,
        WebhookDispatcher webhooks,
        AuditTrail audit,
        TimeProvider clock,
        ILogger<PspCallback> logger)
    {
        using var buffer = new MemoryStream();
        await request.Body.CopyToAsync(buffer, request.HttpContext.RequestAborted);
        byte[] body = buffer.ToArray();
        if (!verifier.IsAuthentic(request, body))
        {
            logger.LogWarning("Dropped a payment callback from {RemoteIp}", request.HttpContext.Connection.RemoteIpAddress);
            return Results.Unauthorized();
        }

        PspCallback? callback = JsonSerializer.Deserialize<PspCallback>(body, JsonSerializerOptions.Web);
        if (callback is null || callback.EventType != "payment.captured" || !Guid.TryParse(callback.MerchantReference, out Guid invoiceId))
        {
            return Results.Ok();
        }

        Invoice? invoice = invoices.Find(invoiceId);
        if (invoice is null || invoice.Currency != callback.Currency)
        {
            logger.LogError("Payment {PspReference} does not match an open invoice", callback.PspReference);
            return Results.Ok();
        }

        invoice.RecordPayment(callback.Amount);
        invoices.Save(invoice);
        audit.Append(new AuditEvent(clock.GetUtcNow(), "psp", "payment", invoice.Number,
            new Dictionary<string, string> { ["pspReference"] = callback.PspReference }));
        if (invoice.Status == InvoiceStatus.Paid)
        {
            webhooks.Publish(invoice.CustomerId, "invoice.paid", new { invoice.Number, invoice.Total, invoice.Currency });
        }

        return Results.Ok();
    }
}
