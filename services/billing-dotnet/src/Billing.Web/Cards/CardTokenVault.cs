using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Tallowbrook.Billing.Security;

namespace Tallowbrook.Billing.Web.Cards;

public sealed class CardVaultOptions
{
    /// <summary>Base64, from the CardVault__RootKey secret.</summary>
    public string RootKey { get; set; } = "";
}

public sealed record CardOnFile(string TenantId, string CustomerId, string Brand, string LastFour, int ExpiryMonth, int ExpiryYear);

/// <summary>
/// The card processor returns a reusable token for cards customers keep on file. We hold that token
/// sealed under a key per tenant, so a copy of one tenant's rows is useless with another tenant's key.
/// </summary>
public sealed class CardTokenVault(IOptions<CardVaultOptions> options)
{
    private static readonly byte[] Label = "tallowbrook-card-vault"u8.ToArray();

    private readonly byte[] _rootKey = Convert.FromBase64String(options.Value.RootKey);
    private readonly ConcurrentDictionary<(string TenantId, string CustomerId), (CardOnFile Card, byte[] Token)> _cards = new();

    public void Store(CardOnFile card, string processorToken)
    {
        byte[] tenantKey = TenantKey(card.TenantId);
        byte[] boxed = AeadBox.Seal(tenantKey, Encoding.UTF8.GetBytes(processorToken), Encoding.UTF8.GetBytes(card.CustomerId));
        _cards[(card.TenantId, card.CustomerId)] = (card, boxed);
    }

    public string? ProcessorToken(string tenantId, string customerId)
    {
        if (!_cards.TryGetValue((tenantId, customerId), out var entry))
        {
            return null;
        }

        byte[] tenantKey = TenantKey(tenantId);
        return Encoding.UTF8.GetString(AeadBox.Open(tenantKey, entry.Token, Encoding.UTF8.GetBytes(customerId)));
    }

    public CardOnFile? Describe(string tenantId, string customerId) =>
        _cards.TryGetValue((tenantId, customerId), out var entry) ? entry.Card : null;

    private byte[] TenantKey(string tenantId)
    {
        byte[] tenantKey = SP800108HmacCounterKdf.DeriveBytes(_rootKey, HashAlgorithmName.SHA256, Label, Encoding.UTF8.GetBytes(tenantId), 32);
        return tenantKey;
    }
}
