using System.Globalization;
using System.Xml.Linq;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace Tallowbrook.Billing.Web.Invoices.Currency;

public sealed class ExchangeRateOptions
{
    /// <summary>Internal mirror of the European Central Bank's daily reference-rate XML.</summary>
    public string FeedUrl { get; set; } = "";

    public TimeSpan CacheFor { get; set; } = TimeSpan.FromHours(6);
}

/// <summary>Euro foreign exchange reference rates, used to convert invoices raised in other currencies.</summary>
public sealed class EcbExchangeRateProvider(HttpClient http, IMemoryCache cache, IOptions<ExchangeRateOptions> options, ILogger<EcbExchangeRateProvider> logger) : IExchangeRateProvider
{
    private static readonly XNamespace Ref = "http://www.ecb.int/vocabulary/2002-08-01/eurofxref";

    public async Task<decimal> PerEuroAsync(string currency, DateOnly day, CancellationToken ct)
    {
        if (currency == "EUR")
        {
            return 1m;
        }

        IReadOnlyDictionary<DateOnly, Dictionary<string, decimal>> rates = await LoadAsync(ct);
        foreach (DateOnly published in rates.Keys.Where(d => d <= day).OrderByDescending(d => d))
        {
            if (rates[published].TryGetValue(currency, out decimal rate))
            {
                return rate;
            }
        }

        throw new KeyNotFoundException($"No euro reference rate for {currency} on or before {day:yyyy-MM-dd}.");
    }

    private async Task<IReadOnlyDictionary<DateOnly, Dictionary<string, decimal>>> LoadAsync(CancellationToken ct)
    {
        if (cache.TryGetValue("reference-rates", out IReadOnlyDictionary<DateOnly, Dictionary<string, decimal>>? cached) && cached is not null)
        {
            return cached;
        }

        await using Stream body = await http.GetStreamAsync(options.Value.FeedUrl, ct);
        XDocument feed = await XDocument.LoadAsync(body, LoadOptions.None, ct);
        var rates = new Dictionary<DateOnly, Dictionary<string, decimal>>();
        foreach (XElement dayCube in feed.Descendants(Ref + "Cube").Where(c => c.Attribute("time") is not null))
        {
            var date = DateOnly.ParseExact((string)dayCube.Attribute("time")!, "yyyy-MM-dd", CultureInfo.InvariantCulture);
            rates[date] = dayCube.Elements(Ref + "Cube").ToDictionary(
                c => (string)c.Attribute("currency")!,
                c => decimal.Parse((string)c.Attribute("rate")!, CultureInfo.InvariantCulture));
        }

        logger.LogInformation("Loaded euro reference rates for {Days} day(s)", rates.Count);
        cache.Set("reference-rates", (IReadOnlyDictionary<DateOnly, Dictionary<string, decimal>>)rates, options.Value.CacheFor);
        return rates;
    }
}
