using System.Buffers.Binary;
using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Tallowbrook.Billing.Web.Security;

namespace Tallowbrook.Billing.Web.Invoices;

public sealed class InvoiceLinkOptions
{
    /// <summary>Base64, from the InvoiceLinks__Key secret.</summary>
    public string Key { get; set; } = "";

    public TimeSpan Lifetime { get; set; } = TimeSpan.FromDays(7);

    public Uri PublicBase { get; set; } = new("https://portal.tallowbrook.example/");
}

/// <summary>
/// Expiring links to an invoice PDF for customers without a portal account (the link goes out in the
/// invoice email). The link carries the invoice id, the expiry and a tag over both.
/// </summary>
public sealed class InvoiceDownloadLinks
{
    private const int TagBytes = 32;
    private static readonly byte[] Customization = "tallowbrook-invoice-link"u8.ToArray();

    private readonly byte[] _linkKey;
    private readonly InvoiceLinkOptions _options;
    private readonly TimeProvider _clock;

    public InvoiceDownloadLinks(IOptions<InvoiceLinkOptions> options, TimeProvider clock)
    {
        if (!Kmac256.IsSupported) throw new PlatformNotSupportedException("Invoice links cannot be issued on this platform.");
        _options = options.Value;
        _linkKey = Convert.FromBase64String(_options.Key);
        _clock = clock;
    }

    public Uri Create(Guid invoiceId)
    {
        long expires = _clock.GetUtcNow().Add(_options.Lifetime).ToUnixTimeSeconds();
        string tag = CryptoFormatting.ToBase64Url(Tag(invoiceId, expires));
        return new Uri(_options.PublicBase, $"d/{invoiceId:N}/{expires}/{tag}");
    }

    public bool TryValidate(Guid invoiceId, long expires, string tag)
    {
        if (DateTimeOffset.FromUnixTimeSeconds(expires) < _clock.GetUtcNow())
        {
            return false;
        }

        byte[] presented;
        try
        {
            presented = CryptoFormatting.FromBase64Url(tag);
        }
        catch (FormatException)
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(presented, Tag(invoiceId, expires));
    }

    private byte[] Tag(Guid invoiceId, long expires)
    {
        byte[] payload = new byte[24];
        invoiceId.TryWriteBytes(payload);
        BinaryPrimitives.WriteInt64BigEndian(payload.AsSpan(16), expires);
        byte[] tag = Kmac256.HashData(_linkKey, payload, TagBytes, Customization);
        return tag;
    }
}
