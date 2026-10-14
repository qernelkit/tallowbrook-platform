using System.Security.Claims;
using Tallowbrook.Billing.Web.Customers;
using Tallowbrook.Billing.Web.Invoices;

namespace Tallowbrook.Billing.Web.Statements;

public sealed record StatementExportRequest(int Year, int Month, string Passphrase);

internal static class StatementEndpoints
{
    private const int MinimumPassphraseLength = 12;

    public static RouteGroupBuilder MapStatementExports(this RouteGroupBuilder portal)
    {
        portal.MapPost("/statements/export", Export);
        return portal;
    }

    private static IResult Export(
        StatementExportRequest request,
        ClaimsPrincipal user,
        ICustomerStore customers,
        IInvoiceStore invoices,
        StatementBuilder builder,
        StatementExportProtector protector)
    {
        if (request.Month is < 1 or > 12 || request.Year is < 2016 or > 2100)
        {
            return Results.BadRequest("Pick a month between January 2016 and today.");
        }

        if (request.Passphrase.Length < MinimumPassphraseLength)
        {
            return Results.BadRequest($"Use at least {MinimumPassphraseLength} characters.");
        }

        Customer? customer = customers.Find(user.FindFirstValue("customer_id")!);
        if (customer is null)
        {
            return Results.Forbid();
        }

        var from = new DateOnly(request.Year, request.Month, 1);
        byte[] statement = builder.Build(customer, invoices.ForCustomer(customer.Id), from, from.AddMonths(1).AddDays(-1));
        byte[] export = protector.Protect(statement, request.Passphrase);
        return Results.File(export, "application/octet-stream", $"statement-{request.Year:D4}-{request.Month:D2}.tbx");
    }
}
