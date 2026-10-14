using System.Globalization;
using System.Text;
using Tallowbrook.Billing.Web.Customers;
using Tallowbrook.Billing.Web.Invoices;

namespace Tallowbrook.Billing.Web.Notifications;

public sealed record OutgoingEmail(string To, string Subject, string TextBody);

/// <summary>The weekly summary email of open invoices sent to each customer's billing contact.</summary>
public sealed class InvoiceDigestEmail
{
    public OutgoingEmail? Compose(Customer customer, IReadOnlyList<Invoice> open, DateOnly today)
    {
        if (open.Count == 0)
        {
            return null;
        }

        var body = new StringBuilder();
        body.AppendLine(CultureInfo.InvariantCulture, $"Hello {customer.Name},");
        body.AppendLine();
        body.AppendLine(CultureInfo.InvariantCulture, $"You have {open.Count} open invoice(s) with Tallowbrook Logistics:");
        body.AppendLine();
        foreach (Invoice invoice in open.OrderBy(i => i.DueOn))
        {
            string flag = invoice.IsOverdue(today) ? "  OVERDUE" : "";
            body.AppendLine(CultureInfo.InvariantCulture, $"  {invoice.Number}  due {invoice.DueOn:yyyy-MM-dd}  {invoice.Outstanding,12:N2} {invoice.Currency}{flag}");
        }

        foreach (IGrouping<string, Invoice> currency in open.GroupBy(i => i.Currency))
        {
            body.AppendLine(CultureInfo.InvariantCulture, $"  Total outstanding in {currency.Key}: {currency.Sum(i => i.Outstanding):N2}");
        }

        body.AppendLine();
        body.AppendLine("You can see and pay your invoices at https://portal.tallowbrook.example/.");
        body.AppendLine("Questions about an invoice? Reply to this email and accounts receivable will get back to you.");

        return new OutgoingEmail(customer.BillingEmail, $"Your open invoices on {today:d MMMM yyyy}", body.ToString());
    }
}
