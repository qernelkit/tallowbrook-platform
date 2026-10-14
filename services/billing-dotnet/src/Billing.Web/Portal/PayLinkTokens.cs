using System.Globalization;
using System.Security.Claims;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Tallowbrook.Billing.Web.Auth;
using Tallowbrook.Billing.Web.Invoices;

namespace Tallowbrook.Billing.Web.Portal;

public sealed class PayLinkOptions
{
    public const string Issuer = "https://billing.tallowbrook.example/pay";
    public const string Audience = "pay-link";

    /// <summary>Base64, from the PayLinks__SigningKey secret.</summary>
    public string SigningKey { get; set; } = "";

    public TimeSpan Lifetime { get; set; } = TimeSpan.FromDays(14);
}

public sealed record PayLinkClaims(Guid InvoiceId, string InvoiceNumber, decimal Amount, string Currency);

/// <summary>Pay-by-link: the reminder email carries a token that opens the payment page for one invoice.</summary>
public sealed class PayLinkTokens(IOptions<PayLinkOptions> options, TimeProvider clock)
{
    private readonly byte[] _payLinkKey = Convert.FromBase64String(options.Value.SigningKey);
    private readonly JsonWebTokenHandler _handler = new();

    public string Create(Invoice invoice)
    {
        DateTime now = clock.GetUtcNow().UtcDateTime;
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = PayLinkOptions.Issuer,
            Audience = PayLinkOptions.Audience,
            Subject = new ClaimsIdentity([new Claim("sub", invoice.Id.ToString())]),
            Claims = new Dictionary<string, object>
            {
                ["inv"] = invoice.Number,
                ["amt"] = invoice.Outstanding.ToString(CultureInfo.InvariantCulture),
                ["cur"] = invoice.Currency,
            },
            NotBefore = now,
            Expires = now.Add(options.Value.Lifetime),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(_payLinkKey), TokenAlgorithms.PayLink),
        };
        return _handler.CreateToken(descriptor);
    }

    public async Task<PayLinkClaims?> ValidateAsync(string token)
    {
        var parameters = new TokenValidationParameters
        {
            ValidIssuer = PayLinkOptions.Issuer,
            ValidAudience = PayLinkOptions.Audience,
            IssuerSigningKey = new SymmetricSecurityKey(_payLinkKey),
            ValidAlgorithms = [TokenAlgorithms.PayLink],
            ClockSkew = TimeSpan.FromSeconds(30),
        };

        TokenValidationResult result = await _handler.ValidateTokenAsync(token, parameters);
        if (!result.IsValid)
        {
            return null;
        }

        return new PayLinkClaims(
            Guid.Parse((string)result.Claims["sub"]),
            (string)result.Claims["inv"],
            decimal.Parse((string)result.Claims["amt"], CultureInfo.InvariantCulture),
            (string)result.Claims["cur"]);
    }
}
