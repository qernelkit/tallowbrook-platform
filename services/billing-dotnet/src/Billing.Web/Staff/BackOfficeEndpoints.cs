using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Tallowbrook.Billing.Web.Audit;
using Tallowbrook.Billing.Web.Auth;
using Tallowbrook.Billing.Web.Customers;
using Tallowbrook.Billing.Web.EInvoicing;
using Tallowbrook.Billing.Web.Invoices;
using Tallowbrook.Billing.Web.Invoices.Pdf;
using Tallowbrook.Billing.Web.Portal;
using Tallowbrook.Billing.Web.Statements;
using Tallowbrook.Billing.Web.Webhooks;

namespace Tallowbrook.Billing.Web.Staff;

public sealed record StaffSignIn(string Account, string Password);

public sealed record WriteOffRequest(decimal Amount, string Reason);

public sealed record ManualPaymentMatch(decimal Amount, string BankReference);

internal static class BackOfficeEndpoints
{
    public static RouteGroupBuilder MapBackOffice(this RouteGroupBuilder office)
    {
        office.MapPost("/sign-in", SignInAsync).AllowAnonymous();
        office.MapPost("/invoices/{id:guid}/issue", IssueAsync).RequireAuthorization(PortalCookie.StaffPolicy);
        office.MapPost("/statements/partners/{year:int}/{month:int}", (int year, int month, PartnerStatementExporter exporter, CancellationToken ct) =>
            exporter.ExportMonthAsync(year, month, ct)).RequireAuthorization(PortalCookie.StaffPolicy);
        office.MapPost("/invoices/{id:guid}/write-off", WriteOff).RequireAuthorization(PortalCookie.StaffPolicy);
        office.MapPost("/invoices/{id:guid}/payments", MatchPayment).RequireAuthorization(PortalCookie.StaffPolicy);
        office.MapGet("/invoices/{id:guid}/pay-link", CreatePayLink).RequireAuthorization(PortalCookie.StaffPolicy);
        office.MapGet("/audit", (long? since, AuditTrail audit) => Results.Ok(audit.Since(since ?? 0)))
            .RequireAuthorization(PortalCookie.StaffPolicy);
        return office;
    }

    private static async Task<IResult> SignInAsync(
        StaffSignIn request,
        HttpContext http,
        IStaffUserStore staff,
        IPasswordHasher<StaffUser> hasher,
        FinanceDirectory directory,
        TimeProvider clock)
    {
        StaffUser? user = staff.FindByAccount(request.Account);
        if (user is null || user.Disabled || user.PasswordHash is null
            || hasher.VerifyHashedPassword(user, user.PasswordHash, request.Password) == PasswordVerificationResult.Failed)
        {
            return Results.Problem("Unknown account or wrong password.", statusCode: StatusCodes.Status401Unauthorized);
        }

        IReadOnlyList<string> roles = directory.RolesFor(user.Account);
        if (roles.Count == 0)
        {
            return Results.Problem("Your account is not in a finance group.", statusCode: StatusCodes.Status403Forbidden);
        }

        user.LastSignIn = clock.GetUtcNow();
        staff.Save(user);
        var identity = new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, user.Account),
                new Claim(ClaimTypes.Name, user.DisplayName),
                new Claim("staff", "true"),
                .. roles.Select(role => new Claim(ClaimTypes.Role, role)),
            ],
            PortalCookie.Scheme);
        await http.SignInAsync(PortalCookie.Scheme, new ClaimsPrincipal(identity));
        return Results.NoContent();
    }

    private static async Task<IResult> IssueAsync(
        Guid id,
        ClaimsPrincipal user,
        IInvoiceStore invoices,
        ICustomerStore customers,
        InvoiceDocumentStore documents,
        EInvoiceDispatcher eInvoices,
        IOptions<EInvoicingOptions> eInvoicing,
        WebhookDispatcher webhooks,
        AuditTrail audit,
        TimeProvider clock,
        CancellationToken ct)
    {
        Invoice? invoice = invoices.Find(id);
        Customer? customer = invoice is null ? null : customers.Find(invoice.CustomerId);
        if (invoice is null || customer is null)
        {
            return Results.NotFound();
        }

        if (invoice.Status != InvoiceStatus.Draft || invoice.Lines.Count == 0)
        {
            return Results.Conflict("Only a draft with at least one line can be issued.");
        }

        invoice.Status = InvoiceStatus.Issued;
        invoice.PdfAddress = await documents.SaveAsync(invoice, new InvoicePdfLayout().Render(invoice, customer), ct);
        invoices.Save(invoice);

        if (eInvoices.Build(invoice, customer) is { } document)
        {
            Directory.CreateDirectory(eInvoicing.Value.OutboxPath);
            await File.WriteAllBytesAsync(Path.Combine(eInvoicing.Value.OutboxPath, document.FileName), document.Content, ct);
            await File.WriteAllTextAsync(Path.Combine(eInvoicing.Value.OutboxPath, document.FileName + ".headers.json"), JsonSerializer.Serialize(document.Headers), ct);
        }

        webhooks.Publish(invoice.CustomerId, "invoice.created", new { invoice.Number, invoice.Total, invoice.Currency, invoice.DueOn });
        audit.Append(new AuditEvent(clock.GetUtcNow(), user.Identity!.Name!, "issue", invoice.Number));
        return Results.NoContent();
    }

    private static IResult WriteOff(Guid id, WriteOffRequest request, ClaimsPrincipal user, IInvoiceStore invoices, AuditTrail audit, TimeProvider clock)
    {
        if (!user.IsInRole("ar-lead") && !user.IsInRole("controller"))
        {
            return Results.Forbid();
        }

        Invoice? invoice = invoices.Find(id);
        if (invoice is null || request.Amount <= 0 || request.Amount > invoice.Outstanding)
        {
            return Results.BadRequest("The write-off must be positive and at most the outstanding amount.");
        }

        invoice.RecordPayment(request.Amount);
        invoices.Save(invoice);
        audit.Append(new AuditEvent(clock.GetUtcNow(), user.Identity!.Name!, "write-off", invoice.Number,
            new Dictionary<string, string> { ["amount"] = request.Amount.ToString("0.00"), ["reason"] = request.Reason }));
        return Results.NoContent();
    }

    private static IResult MatchPayment(Guid id, ManualPaymentMatch request, ClaimsPrincipal user, IInvoiceStore invoices, AuditTrail audit, TimeProvider clock)
    {
        Invoice? invoice = invoices.Find(id);
        if (invoice is null)
        {
            return Results.NotFound();
        }

        invoice.RecordPayment(request.Amount);
        invoices.Save(invoice);
        audit.Append(new AuditEvent(clock.GetUtcNow(), user.Identity!.Name!, "match-payment", invoice.Number,
            new Dictionary<string, string> { ["amount"] = request.Amount.ToString("0.00"), ["bankReference"] = request.BankReference }));
        return Results.Ok(new { invoice.Status, invoice.Outstanding });
    }

    private static IResult CreatePayLink(Guid id, IInvoiceStore invoices, PayLinkTokens tokens)
    {
        Invoice? invoice = invoices.Find(id);
        return invoice is null ? Results.NotFound() : Results.Ok(new { Token = tokens.Create(invoice) });
    }
}
