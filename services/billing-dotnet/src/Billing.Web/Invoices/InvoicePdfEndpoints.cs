using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.Net.Http.Headers;
using Tallowbrook.Billing.Web.Customers;
using Tallowbrook.Billing.Web.Invoices.Pdf;

namespace Tallowbrook.Billing.Web.Invoices;

internal static class InvoicePdfEndpoints
{
    public static RouteGroupBuilder MapInvoicePdfEndpoints(this RouteGroupBuilder portal)
    {
        portal.MapGet("/invoices/{token}.pdf", GetPdfAsync).WithName("InvoicePdf");
        return portal;
    }

    /// <summary>Links from invoice emails, for billing contacts without a portal account.</summary>
    public static IEndpointRouteBuilder MapInvoiceDownloadLinks(this IEndpointRouteBuilder app)
    {
        app.MapGet("/d/{invoiceId:guid}/{expires:long}/{tag}", async (Guid invoiceId, long expires, string tag, InvoiceDownloadLinks links, IInvoiceStore invoices, InvoiceDocumentStore documents, CancellationToken ct) =>
        {
            if (!links.TryValidate(invoiceId, expires, tag))
            {
                return Results.NotFound();
            }

            Invoice? invoice = invoices.Find(invoiceId);
            byte[]? pdf = invoice?.PdfAddress is { } address ? await documents.ReadAsync(address, ct) : null;
            return pdf is null ? Results.NotFound() : Results.File(pdf, "application/pdf", $"invoice-{invoice!.Number}.pdf");
        }).AllowAnonymous();
        return app;
    }

    private static async Task<IResult> GetPdfAsync(
        string token,
        HttpContext http,
        ClaimsPrincipal user,
        InvoiceNumberTokenizer tokenizer,
        IInvoiceStore invoices,
        ICustomerStore customers,
        InvoiceDocumentStore documents,
        CancellationToken ct)
    {
        string? customerId = user.FindFirstValue("customer_id");
        string? tenantId = user.FindFirstValue("tenant_id");
        if (customerId is null || tenantId is null)
        {
            return Results.Forbid();
        }

        Invoice? invoice = invoices.FindByNumber(tenantId, tokenizer.Detokenize(tenantId, token));
        if (invoice is null || invoice.CustomerId != customerId)
        {
            return Results.NotFound();
        }

        byte[]? pdf = invoice.PdfAddress is null ? null : await documents.ReadAsync(invoice.PdfAddress, ct);
        if (pdf is null)
        {
            Customer customer = customers.Find(invoice.CustomerId) ?? throw new InvalidOperationException($"Customer {invoice.CustomerId} is missing.");
            pdf = new InvoicePdfLayout().Render(invoice, customer);
            invoice.PdfAddress = await documents.SaveAsync(invoice, pdf, ct);
            invoices.Save(invoice);
        }

        // Customers reopen the same PDF from the invoice list many times a day.
        byte[] hash = MD5.HashData(pdf);
        string etag = $"\"{Convert.ToBase64String(hash)}\"";
        if (http.Request.Headers.IfNoneMatch.Contains(etag))
        {
            return Results.StatusCode(StatusCodes.Status304NotModified);
        }

        http.Response.Headers.ETag = etag;
        http.Response.Headers.CacheControl = "private, max-age=300";
        return Results.File(pdf, "application/pdf", $"invoice-{invoice.Number}.pdf");
    }
}
