using System.Security.Claims;
using Microsoft.Extensions.Options;
using Tallowbrook.Billing.Web.Invoices;

namespace Tallowbrook.Billing.Web.Disputes;

internal static class DisputeEndpoints
{
    private static readonly HashSet<string> AllowedTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "application/pdf", "image/jpeg", "image/png", "image/heic",
    };

    public static RouteGroupBuilder MapDisputes(this RouteGroupBuilder portal)
    {
        portal.MapPost("/invoices/{token}/dispute", OpenDispute);
        portal.MapPost("/disputes/{disputeId}/evidence", UploadEvidenceAsync).DisableAntiforgery();
        return portal;
    }

    private static IResult OpenDispute(string token, ClaimsPrincipal user, IInvoiceStore invoices, InvoiceNumberTokenizer tokenizer)
    {
        string tenantId = user.FindFirstValue("tenant_id")!;
        Invoice? invoice = invoices.FindByNumber(tenantId, tokenizer.Detokenize(tenantId, token));
        if (invoice is null || invoice.CustomerId != user.FindFirstValue("customer_id"))
        {
            return Results.NotFound();
        }

        invoice.Status = InvoiceStatus.Disputed;
        invoices.Save(invoice);
        string disputeId = $"D-{invoice.Number}";
        return Results.Created($"/portal/disputes/{disputeId}", new { disputeId });
    }

    private static async Task<IResult> UploadEvidenceAsync(string disputeId, IFormFile file, EvidenceVault vault, IOptions<DisputeOptions> options, CancellationToken ct)
    {
        if (file.Length == 0 || file.Length > options.Value.MaxUploadBytes)
        {
            return Results.BadRequest("Files must be between 1 byte and 25 MB.");
        }

        if (!AllowedTypes.Contains(file.ContentType))
        {
            return Results.BadRequest("Upload a PDF or a photo.");
        }

        await using Stream upload = file.OpenReadStream();
        StoredEvidence stored = await vault.StoreAsync(disputeId, file.FileName, upload, ct);
        return Results.Ok(new { stored.Id, stored.FileName, stored.Bytes });
    }
}
