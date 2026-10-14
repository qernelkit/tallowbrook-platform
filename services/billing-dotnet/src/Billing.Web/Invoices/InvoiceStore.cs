using System.Collections.Concurrent;

namespace Tallowbrook.Billing.Web.Invoices;

public interface IInvoiceStore
{
    Invoice? Find(Guid id);

    Invoice? FindByNumber(string tenantId, string number);

    IReadOnlyList<Invoice> ForCustomer(string customerId);

    IReadOnlyList<Invoice> IssuedOn(DateOnly day);

    IReadOnlyList<Invoice> Open();

    void Save(Invoice invoice);
}

/// <summary>
/// Process-local store used by the portal until the invoice tables move out of the 2016 back-office
/// database. Writes are mirrored to that database by the sync job.
/// </summary>
internal sealed class InvoiceStore : IInvoiceStore
{
    private readonly ConcurrentDictionary<Guid, Invoice> _invoices = new();

    public Invoice? Find(Guid id) => _invoices.GetValueOrDefault(id);

    public Invoice? FindByNumber(string tenantId, string number) =>
        _invoices.Values.FirstOrDefault(i => i.TenantId == tenantId && i.Number == number);

    public IReadOnlyList<Invoice> ForCustomer(string customerId) =>
        [.. _invoices.Values.Where(i => i.CustomerId == customerId).OrderByDescending(i => i.IssuedOn)];

    public IReadOnlyList<Invoice> IssuedOn(DateOnly day) =>
        [.. _invoices.Values.Where(i => i.IssuedOn == day && i.Status != InvoiceStatus.Draft)];

    public IReadOnlyList<Invoice> Open() =>
        [.. _invoices.Values.Where(i => i.Status is InvoiceStatus.Issued or InvoiceStatus.PartiallyPaid)];

    public void Save(Invoice invoice) => _invoices[invoice.Id] = invoice;
}
