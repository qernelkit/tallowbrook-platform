namespace Tallowbrook.Billing.Web.Invoices.Currency;

public interface IExchangeRateProvider
{
    /// <summary>Units of <paramref name="currency"/> per euro on <paramref name="day"/> (or the last published day before it).</summary>
    Task<decimal> PerEuroAsync(string currency, DateOnly day, CancellationToken ct);
}
