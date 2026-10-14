namespace Tallowbrook.Billing.Web.Invoices;

public enum InvoiceStatus
{
    Draft,
    Issued,
    PartiallyPaid,
    Paid,
    Disputed,
    Cancelled,
}
