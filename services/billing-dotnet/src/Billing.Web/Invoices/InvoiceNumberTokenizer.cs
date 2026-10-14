using System.Text;
using Microsoft.Extensions.Options;
using Org.BouncyCastle.Crypto.Fpe;
using Org.BouncyCastle.Crypto.Parameters;

namespace Tallowbrook.Billing.Web.Invoices;

public sealed class InvoiceTokenOptions
{
    /// <summary>Base64, from the InvoiceTokens__Key secret (32 bytes).</summary>
    public string Key { get; set; } = "";
}

/// <summary>
/// Public portal URLs carry a token instead of the sequential invoice number, so customers cannot walk
/// through each other's invoice numbers. The token has the same number of digits as the number it
/// replaces, which keeps the old bookmarked URL format and the PDF file names unchanged.
/// </summary>
public sealed class InvoiceNumberTokenizer
{
    private const int Radix = 10;
    private const int Stripes = 32;

    private readonly byte[] _key;
    private readonly object[] _locks = Enumerable.Range(0, Stripes).Select(_ => new object()).ToArray();

    public InvoiceNumberTokenizer(IOptions<InvoiceTokenOptions> options)
    {
        _key = Convert.FromBase64String(options.Value.Key);
    }

    public string Tokenize(string tenantId, string invoiceNumber) => Transform(tenantId, invoiceNumber, forward: true);

    public string Detokenize(string tenantId, string token) => Transform(tenantId, token, forward: false);

    private string Transform(string tenantId, string value, bool forward)
    {
        if (value.Length < 6 || !value.All(char.IsAsciiDigit))
        {
            throw new ArgumentException("Invoice numbers and tokens are at least six digits.", nameof(value));
        }

        byte[] input = value.Select(c => (byte)(c - '0')).ToArray();
        byte[] output = new byte[input.Length];

        // Statement runs tokenize thousands of numbers for one tenant in parallel; the stripe keeps that
        // burst to one core so portal requests for other tenants are not queued behind it.
        object gate = _locks[(tenantId.GetHashCode() & int.MaxValue) % _locks.Length];
        lock (gate)
        {
            var engine = new FpeFf1Engine();
            engine.Init(forward, new FpeParameters(new KeyParameter(_key), Radix, Encoding.UTF8.GetBytes(tenantId)));
            engine.ProcessBlock(input, 0, input.Length, output, 0);
        }

        return string.Concat(output.Select(d => (char)('0' + d)));
    }
}
