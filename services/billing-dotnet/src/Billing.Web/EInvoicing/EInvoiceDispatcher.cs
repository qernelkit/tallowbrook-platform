using System.Text;
using System.Xml;
using Tallowbrook.Billing.Web.Customers;
using Tallowbrook.Billing.Web.Invoices;

namespace Tallowbrook.Billing.Web.EInvoicing;

public sealed record EInvoiceDocument(string FileName, byte[] Content, IReadOnlyDictionary<string, string> Headers);

/// <summary>Builds the e-invoice for customers that need one, in the form their channel expects.</summary>
public sealed class EInvoiceDispatcher(
    EInvoiceXmlWriter writer,
    PublicSectorInvoiceSigner publicSector,
    ChinaPartnerSigner chinaPartner,
    ILogger<EInvoiceDispatcher> logger)
{
    public EInvoiceDocument? Build(Invoice invoice, Customer customer)
    {
        XmlDocument xml = writer.Write(invoice, customer);
        var headers = new Dictionary<string, string>();

        if (customer.IsPublicSector)
        {
            xml = publicSector.Sign(xml);
        }
        else if (customer.Country == "CN")
        {
            headers["X-Partner-Signature"] = chinaPartner.Sign(Encoding.UTF8.GetBytes(xml.OuterXml));
        }
        else if (customer.Country is "KZ" or "KG" or "AM" or "BY")
        {
            headers["X-EDI-Checksum"] = EaeuInvoiceDigest.Compute(xml);
        }
        else if (customer.EInvoiceAddress is null)
        {
            return null;
        }

        logger.LogInformation("Built e-invoice for {InvoiceNumber} ({Country})", invoice.Number, customer.Country);
        return new EInvoiceDocument($"{invoice.Number}.xml", Encoding.UTF8.GetBytes(xml.OuterXml), headers);
    }
}
