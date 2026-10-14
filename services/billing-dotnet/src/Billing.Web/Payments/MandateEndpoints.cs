using System.Security.Claims;

namespace Tallowbrook.Billing.Web.Payments;

public sealed record MandateForm(string AccountHolder, string Iban, string Bic, bool Accepted);

internal static class MandateEndpoints
{
    public static RouteGroupBuilder MapMandates(this RouteGroupBuilder portal)
    {
        portal.MapPost("/mandates", CreateAsync);
        return portal;
    }

    private static async Task<IResult> CreateAsync(MandateForm form, ClaimsPrincipal user, DirectDebitMandateVault vault, TimeProvider clock, CancellationToken ct)
    {
        if (!form.Accepted)
        {
            return Results.BadRequest("Please accept the mandate text.");
        }

        if (string.IsNullOrWhiteSpace(form.AccountHolder) || form.Bic.Length is not (8 or 11))
        {
            return Results.BadRequest("Account holder and an 8 or 11 character BIC are required.");
        }

        var mandate = new DirectDebitMandate(
            Guid.NewGuid(),
            user.FindFirstValue("customer_id")!,
            form.AccountHolder.Trim(),
            form.Iban,
            form.Bic.ToUpperInvariant(),
            DateOnly.FromDateTime(clock.GetUtcNow().UtcDateTime));
        await vault.RegisterAsync(mandate, ct);
        return Results.Created($"/portal/mandates/{mandate.Id}", new { mandate.Id, Iban = Iban.Format(mandate.Iban)[..4] + " **** " + Iban.LastFour(mandate.Iban) });
    }
}
