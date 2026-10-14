namespace Tallowbrook.Billing.Web.Invoices.Currency;

public sealed class CurrencyConverter(IExchangeRateProvider rates)
{
    public async Task<decimal> ConvertAsync(decimal amount, string from, string to, DateOnly day, CancellationToken ct)
    {
        if (string.Equals(from, to, StringComparison.Ordinal))
        {
            return amount;
        }

        decimal fromPerEuro = await rates.PerEuroAsync(from, day, ct);
        decimal toPerEuro = await rates.PerEuroAsync(to, day, ct);
        return decimal.Round(amount / fromPerEuro * toPerEuro, 2, MidpointRounding.ToEven);
    }
}
