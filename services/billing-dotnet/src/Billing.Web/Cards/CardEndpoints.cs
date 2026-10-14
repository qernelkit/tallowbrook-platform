using System.Security.Claims;
using Tallowbrook.Billing.Web.Logging;

namespace Tallowbrook.Billing.Web.Cards;

public sealed record SavedCard(string ProcessorToken, string Brand, string LastFour, int ExpiryMonth, int ExpiryYear);

internal static class CardEndpoints
{
    public static RouteGroupBuilder MapCards(this RouteGroupBuilder portal)
    {
        portal.MapPut("/cards/default", Save);
        portal.MapGet("/cards/default", (ClaimsPrincipal user, CardTokenVault vault) =>
            vault.Describe(user.FindFirstValue("tenant_id")!, user.FindFirstValue("customer_id")!) is { } card
                ? Results.Ok(new { card.Brand, card.LastFour, card.ExpiryMonth, card.ExpiryYear })
                : Results.NotFound());
        return portal;
    }

    private static IResult Save(SavedCard saved, ClaimsPrincipal user, CardTokenVault vault, TimeProvider clock, ILogger<CardTokenVault> logger)
    {
        DateTimeOffset now = clock.GetUtcNow();
        if (saved.ExpiryYear < now.Year || (saved.ExpiryYear == now.Year && saved.ExpiryMonth < now.Month))
        {
            return Results.BadRequest("This card has expired.");
        }

        string tenantId = user.FindFirstValue("tenant_id")!;
        string customerId = user.FindFirstValue("customer_id")!;
        vault.Store(new CardOnFile(tenantId, customerId, saved.Brand, saved.LastFour, saved.ExpiryMonth, saved.ExpiryYear), saved.ProcessorToken);
        logger.LogInformation("Customer {CustomerId} saved a {Brand} card ending {CardRef}", customerId, saved.Brand, CardNumberLogFormatter.Mask(tenantId, saved.LastFour));
        return Results.NoContent();
    }
}
