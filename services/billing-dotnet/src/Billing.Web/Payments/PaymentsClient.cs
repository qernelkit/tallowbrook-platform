using System.Net.Http.Json;

namespace Tallowbrook.Billing.Web.Payments;

public sealed record CheckoutRequest(Guid InvoiceId, string Reference, decimal Amount, string Currency, Uri ReturnUrl);

public sealed record CheckoutResponse(Uri CheckoutUrl);

public sealed record MandateRegistration(Guid MandateId, string CustomerId, string AccountHolder, string IbanLastFour, string BankIdentifier, byte[] EncryptedIban);

/// <summary>Calls into payments-java: card and bank checkouts, and direct-debit mandate registration.</summary>
public sealed class PaymentsClient(HttpClient http, ILogger<PaymentsClient> logger)
{
    private static readonly Uri ReturnUrl = new("https://portal.tallowbrook.example/pay/done");

    public async Task<Uri> CreateCheckoutAsync(Guid invoiceId, string reference, decimal amount, string currency, CancellationToken ct)
    {
        using HttpResponseMessage response = await http.PostAsJsonAsync("v1/checkouts", new CheckoutRequest(invoiceId, reference, amount, currency, ReturnUrl), ct);
        response.EnsureSuccessStatusCode();
        CheckoutResponse body = await response.Content.ReadFromJsonAsync<CheckoutResponse>(ct)
            ?? throw new InvalidOperationException("payments-java returned an empty checkout.");
        logger.LogInformation("Checkout for invoice {Reference} created", reference);
        return body.CheckoutUrl;
    }

    public async Task RegisterMandateAsync(MandateRegistration mandate, CancellationToken ct)
    {
        using HttpResponseMessage response = await http.PostAsJsonAsync("v1/mandates", mandate, ct);
        response.EnsureSuccessStatusCode();
    }
}
