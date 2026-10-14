namespace Tallowbrook.Billing.Web.Invoices;

public sealed class Invoice
{
    public required Guid Id { get; init; }

    /// <summary>Sequential per tenant, e.g. 2026004812. Never shown in public URLs.</summary>
    public required string Number { get; init; }

    public required string TenantId { get; init; }

    public required string CustomerId { get; init; }

    public required string Currency { get; init; }

    public DateOnly IssuedOn { get; init; }

    public DateOnly DueOn { get; init; }

    public InvoiceStatus Status { get; set; } = InvoiceStatus.Draft;

    public List<InvoiceLine> Lines { get; init; } = [];

    public string? BuyerReference { get; init; }

    public bool IsPublicSector { get; init; }

    public CertificateOfOrigin? OriginDocument { get; init; }

    /// <summary>Content address of the rendered PDF in the document store.</summary>
    public string? PdfAddress { get; set; }

    public decimal AmountPaid { get; set; }

    public decimal Net => Lines.Sum(line => line.Net);

    public decimal Tax => Lines.Sum(line => line.Tax);

    public decimal Total => Net + Tax;

    public decimal Outstanding => Total - AmountPaid;

    public bool IsOverdue(DateOnly today) =>
        Status is InvoiceStatus.Issued or InvoiceStatus.PartiallyPaid && today > DueOn;

    public void RecordPayment(decimal amount)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(amount);
        AmountPaid += amount;
        Status = AmountPaid >= Total ? InvoiceStatus.Paid : InvoiceStatus.PartiallyPaid;
    }
}
