namespace Tallowbrook.Billing.Web.EInvoicing;

public sealed class EInvoicingOptions
{
    /// <summary>PFX of the e-invoice signing certificate, mounted as a secret.</summary>
    public string SigningCertificatePath { get; set; } = "";

    /// <summary>From the EInvoicing__SigningCertificatePassword environment variable only.</summary>
    public string? SigningCertificatePassword { get; set; }

    /// <summary>Hex scalar of the key registered with the Shenzhen forwarder; from the EInvoicing__ChinaPartnerKeyHex secret.</summary>
    public string ChinaPartnerKeyHex { get; set; } = "";

    public string SellerVatId { get; set; } = "DE811907980";

    public string SellerName { get; set; } = "Tallowbrook Logistics GmbH";

    /// <summary>Picked up by the e-invoicing gateway, which delivers to each buyer's channel.</summary>
    public string OutboxPath { get; set; } = "/var/lib/tallowbrook/billing/einvoice-outbox";
}
