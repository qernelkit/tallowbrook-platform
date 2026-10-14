using System.Text;
using System.Xml;
using Org.BouncyCastle.Crypto.Digests;

namespace Tallowbrook.Billing.Web.EInvoicing;

/// <summary>
/// The Eurasian customs broker's EDI operator wants a GOST R 34.11-2012 (256-bit) checksum of each
/// invoice XML in the accompanying message, as hex.
/// </summary>
internal static class EaeuInvoiceDigest
{
    public static string Compute(XmlDocument invoiceXml)
    {
        byte[] canonical = Encoding.UTF8.GetBytes(invoiceXml.OuterXml);
        var digest = new Gost3411_2012_256Digest();
        digest.BlockUpdate(canonical, 0, canonical.Length);
        byte[] result = new byte[digest.GetDigestSize()];
        digest.DoFinal(result, 0);
        return Convert.ToHexString(result);
    }
}
