using System.Globalization;
using System.Text;
using Tallowbrook.Billing.Web.Customers;
using Tallowbrook.Billing.Web.Invoices;

namespace Tallowbrook.Billing.Web.Statements;

/// <summary>Monthly account statement as semicolon-separated text (the format accountants import into DATEV-style tools).</summary>
public sealed class StatementBuilder
{
    public byte[] Build(Customer customer, IReadOnlyList<Invoice> invoices, DateOnly from, DateOnly to)
    {
        var csv = new StringBuilder();
        csv.AppendLine("customer;invoice;issued;due;currency;net;tax;total;paid;outstanding;status");
        foreach (Invoice invoice in invoices.Where(i => i.IssuedOn >= from && i.IssuedOn <= to).OrderBy(i => i.IssuedOn))
        {
            csv.AppendLine(string.Join(';',
                customer.Id,
                invoice.Number,
                invoice.IssuedOn.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
                invoice.DueOn.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
                invoice.Currency,
                invoice.Net.ToString("0.00", CultureInfo.InvariantCulture),
                invoice.Tax.ToString("0.00", CultureInfo.InvariantCulture),
                invoice.Total.ToString("0.00", CultureInfo.InvariantCulture),
                invoice.AmountPaid.ToString("0.00", CultureInfo.InvariantCulture),
                invoice.Outstanding.ToString("0.00", CultureInfo.InvariantCulture),
                invoice.Status));
        }

        return Encoding.UTF8.GetBytes(csv.ToString());
    }
}
