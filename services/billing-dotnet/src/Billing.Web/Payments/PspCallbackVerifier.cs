using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace Tallowbrook.Billing.Web.Payments;

public sealed class PspOptions
{
    /// <summary>Base64, from the Psp__CallbackKey secret issued by the payment provider.</summary>
    public string CallbackKey { get; set; } = "";
}

/// <summary>The payment provider signs each callback body; anything else on that URL is dropped.</summary>
public sealed class PspCallbackVerifier(IOptions<PspOptions> options)
{
    private readonly byte[] _callbackKey = Convert.FromBase64String(options.Value.CallbackKey);

    public bool IsAuthentic(HttpRequest request, byte[] body)
    {
        if (!request.Headers.TryGetValue("X-Psp-Signature", out StringValues signatureHeader))
            return false;
        using var mac = new HMACSHA512(_callbackKey);
        byte[] expected = mac.ComputeHash(body);

        string presented = signatureHeader.ToString();
        if (presented.Length != expected.Length * 2 || !presented.All(char.IsAsciiHexDigit))
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(expected, Convert.FromHexString(presented));
    }
}
