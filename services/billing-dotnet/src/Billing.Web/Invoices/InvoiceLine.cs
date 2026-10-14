namespace Tallowbrook.Billing.Web.Invoices;

public sealed record InvoiceLine(
    string Description,
    decimal Quantity,
    string Unit,
    decimal UnitPrice,
    decimal TaxRate,
    string? ShipmentReference = null)
{
    public decimal Net => decimal.Round(Quantity * UnitPrice, 2, MidpointRounding.AwayFromZero);

    public decimal Tax => decimal.Round(Net * TaxRate, 2, MidpointRounding.AwayFromZero);

    public decimal Gross => Net + Tax;
}
