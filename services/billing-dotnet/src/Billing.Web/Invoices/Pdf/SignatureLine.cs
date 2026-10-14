namespace Tallowbrook.Billing.Web.Invoices.Pdf;

/// <summary>The ruled line and caption for the authorised signatory at the foot of an invoice.</summary>
public sealed record SignatureLine(string SignatoryName, string Title, float Y);
