using System.Globalization;
using System.Xml;
using Microsoft.Extensions.Options;
using Tallowbrook.Billing.Web.Customers;
using Tallowbrook.Billing.Web.Invoices;

namespace Tallowbrook.Billing.Web.EInvoicing;

/// <summary>UBL 2.1 invoice document (the subset the public-sector portals and the customs brokers accept).</summary>
public sealed class EInvoiceXmlWriter(IOptions<EInvoicingOptions> options)
{
    private const string Ubl = "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2";
    private const string Cac = "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2";
    private const string Cbc = "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2";

    public XmlDocument Write(Invoice invoice, Customer customer)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        XmlElement root = doc.CreateElement("Invoice", Ubl);
        doc.AppendChild(root);

        Basic(root, "CustomizationID", "urn:cen.eu:en16931:2017#compliant#urn:xeinkauf.de:kosit:xrechnung_3.0");
        Basic(root, "ID", invoice.Number);
        Basic(root, "IssueDate", invoice.IssuedOn.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture));
        Basic(root, "DueDate", invoice.DueOn.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture));
        Basic(root, "InvoiceTypeCode", "380");
        Basic(root, "DocumentCurrencyCode", invoice.Currency);
        Basic(root, "BuyerReference", invoice.BuyerReference ?? customer.EInvoiceAddress ?? customer.Id);

        XmlElement seller = Aggregate(Aggregate(root, "AccountingSupplierParty"), "Party");
        Basic(Aggregate(seller, "PartyName"), "Name", options.Value.SellerName);
        Basic(Aggregate(seller, "PartyTaxScheme"), "CompanyID", options.Value.SellerVatId);

        XmlElement buyer = Aggregate(Aggregate(root, "AccountingCustomerParty"), "Party");
        Basic(Aggregate(buyer, "PartyName"), "Name", customer.Name);
        Basic(Aggregate(buyer, "PostalAddress"), "Country", customer.Country);

        XmlElement totals = Aggregate(root, "LegalMonetaryTotal");
        Amount(totals, "LineExtensionAmount", invoice.Net, invoice.Currency);
        Amount(totals, "TaxExclusiveAmount", invoice.Net, invoice.Currency);
        Amount(totals, "TaxInclusiveAmount", invoice.Total, invoice.Currency);
        Amount(totals, "PayableAmount", invoice.Outstanding, invoice.Currency);

        int lineNumber = 0;
        foreach (InvoiceLine line in invoice.Lines)
        {
            XmlElement xmlLine = Aggregate(root, "InvoiceLine");
            Basic(xmlLine, "ID", (++lineNumber).ToString(CultureInfo.InvariantCulture));
            XmlElement quantity = Basic(xmlLine, "InvoicedQuantity", line.Quantity.ToString(CultureInfo.InvariantCulture));
            quantity.SetAttribute("unitCode", line.Unit == "kg" ? "KGM" : "C62");
            Amount(xmlLine, "LineExtensionAmount", line.Net, invoice.Currency);
            Basic(Aggregate(xmlLine, "Item"), "Name", line.Description);
            Amount(Aggregate(xmlLine, "Price"), "PriceAmount", line.UnitPrice, invoice.Currency);
        }

        return doc;
    }

    private static XmlElement Aggregate(XmlElement parent, string name)
    {
        XmlElement element = parent.OwnerDocument.CreateElement("cac", name, Cac);
        parent.AppendChild(element);
        return element;
    }

    private static XmlElement Basic(XmlElement parent, string name, string value)
    {
        XmlElement element = parent.OwnerDocument.CreateElement("cbc", name, Cbc);
        element.InnerText = value;
        parent.AppendChild(element);
        return element;
    }

    private static void Amount(XmlElement parent, string name, decimal value, string currency) =>
        Basic(parent, name, value.ToString("0.00", CultureInfo.InvariantCulture)).SetAttribute("currencyID", currency);
}
