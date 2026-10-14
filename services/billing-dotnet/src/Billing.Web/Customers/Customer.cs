namespace Tallowbrook.Billing.Web.Customers;

public sealed class Customer
{
    public required string Id { get; init; }

    public required string TenantId { get; init; }

    public required string Name { get; init; }

    public required string BillingEmail { get; init; }

    /// <summary>ISO 3166-1 alpha-2.</summary>
    public required string Country { get; init; }

    public string PreferredCurrency { get; init; } = "EUR";

    public int PaymentTermsDays { get; init; } = 30;

    public bool IsPublicSector { get; init; }

    /// <summary>Leitweg-ID or PEPPOL participant id for public-sector e-invoices.</summary>
    public string? EInvoiceAddress { get; init; }

    /// <summary>Set for customers whose accounting partner imports our monthly statement file.</summary>
    public string? AccountingPartnerId { get; init; }

    public bool WantsWeeklySummary { get; init; } = true;
}

public interface ICustomerStore
{
    Customer? Find(string id);

    IReadOnlyList<Customer> All();
}

internal sealed class CustomerStore : ICustomerStore
{
    private readonly Dictionary<string, Customer> _customers = new(StringComparer.Ordinal);

    public Customer? Find(string id) => _customers.GetValueOrDefault(id);

    public IReadOnlyList<Customer> All() => [.. _customers.Values.OrderBy(c => c.Name, StringComparer.CurrentCulture)];

    public void Add(Customer customer) => _customers[customer.Id] = customer;
}
