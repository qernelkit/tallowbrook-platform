using System.Security.Claims;
using Tallowbrook.Billing.Web.Invoices;
using Tallowbrook.Billing.Web.Payments;

namespace Tallowbrook.Billing.Web.Portal;

public sealed record InvoiceSummary(string Token, DateOnly IssuedOn, DateOnly DueOn, string Status, decimal Total, decimal Outstanding, string Currency, bool Overdue);

public sealed record PayPage(string InvoiceNumber, decimal Amount, string Currency, Uri CheckoutUrl);

internal static class InvoicePortalEndpoints
{
    public static RouteGroupBuilder MapInvoicePortal(this RouteGroupBuilder portal)
    {
        portal.MapGet("/invoices", ListInvoices);
        portal.MapGet("/invoices/{token}", GetInvoice);
        portal.MapGet("/invoices/{token}/download-link", CreateDownloadLink);
        return portal;
    }

    public static IEndpointRouteBuilder MapPayLinkPages(this IEndpointRouteBuilder app)
    {
        app.MapGet("/pay/{payLink}", OpenPayLinkAsync).AllowAnonymous();
        return app;
    }

    private static IResult ListInvoices(ClaimsPrincipal user, IInvoiceStore invoices, InvoiceNumberTokenizer tokenizer, TimeProvider clock)
    {
        string customerId = user.FindFirstValue("customer_id")!;
        string tenantId = user.FindFirstValue("tenant_id")!;
        DateOnly today = DateOnly.FromDateTime(clock.GetUtcNow().UtcDateTime);

        IEnumerable<InvoiceSummary> rows = invoices.ForCustomer(customerId)
            .Where(i => i.Status != InvoiceStatus.Draft)
            .Select(i => new InvoiceSummary(
                tokenizer.Tokenize(tenantId, i.Number),
                i.IssuedOn,
                i.DueOn,
                i.Status.ToString(),
                i.Total,
                i.Outstanding,
                i.Currency,
                i.IsOverdue(today)));
        return Results.Ok(rows);
    }

    private static IResult GetInvoice(string token, ClaimsPrincipal user, IInvoiceStore invoices, InvoiceNumberTokenizer tokenizer)
    {
        string tenantId = user.FindFirstValue("tenant_id")!;
        Invoice? invoice = invoices.FindByNumber(tenantId, tokenizer.Detokenize(tenantId, token));
        if (invoice is null || invoice.CustomerId != user.FindFirstValue("customer_id"))
        {
            return Results.NotFound();
        }

        return Results.Ok(new
        {
            invoice.Number,
            invoice.IssuedOn,
            invoice.DueOn,
            Status = invoice.Status.ToString(),
            invoice.Currency,
            Lines = invoice.Lines.Select(l => new { l.Description, l.Quantity, l.Unit, l.UnitPrice, l.Net }),
            invoice.Net,
            invoice.Tax,
            invoice.Total,
            invoice.Outstanding,
        });
    }

    private static IResult CreateDownloadLink(string token, ClaimsPrincipal user, IInvoiceStore invoices, InvoiceNumberTokenizer tokenizer, InvoiceDownloadLinks links)
    {
        string tenantId = user.FindFirstValue("tenant_id")!;
        Invoice? invoice = invoices.FindByNumber(tenantId, tokenizer.Detokenize(tenantId, token));
        return invoice is null || invoice.CustomerId != user.FindFirstValue("customer_id")
            ? Results.NotFound()
            : Results.Ok(new { Url = links.Create(invoice.Id) });
    }

    private static async Task<IResult> OpenPayLinkAsync(string payLink, PayLinkTokens tokens, IInvoiceStore invoices, PaymentsClient payments, CancellationToken ct)
    {
        PayLinkClaims? claims = await tokens.ValidateAsync(payLink);
        if (claims is null)
        {
            return Results.Problem("This payment link has expired. Ask for a new one from your account manager.", statusCode: StatusCodes.Status410Gone);
        }

        Invoice? invoice = invoices.Find(claims.InvoiceId);
        if (invoice is null || invoice.Status is InvoiceStatus.Paid or InvoiceStatus.Cancelled)
        {
            return Results.Problem("This invoice no longer needs to be paid.", statusCode: StatusCodes.Status410Gone);
        }

        Uri checkout = await payments.CreateCheckoutAsync(invoice.Id, invoice.Number, invoice.Outstanding, invoice.Currency, ct);
        return Results.Ok(new PayPage(invoice.Number, invoice.Outstanding, invoice.Currency, checkout));
    }
}
