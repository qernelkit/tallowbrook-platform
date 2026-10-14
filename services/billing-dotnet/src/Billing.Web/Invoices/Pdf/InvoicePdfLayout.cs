using System.Globalization;
using System.Text;
using Tallowbrook.Billing.Web.Customers;

namespace Tallowbrook.Billing.Web.Invoices.Pdf;

/// <summary>
/// Lays out an invoice on A4 and writes a single-page PDF with the standard Helvetica fonts. The
/// invoice layout has not changed since 2019, so a small drawing model is enough and keeps a PDF
/// library out of the container.
/// </summary>
public sealed class InvoicePdfLayout
{
    private const float PageWidth = 595.28f;
    private const float PageHeight = 841.89f;
    private const float Margin = 56f;
    private const float LineHeight = 14f;

    private static readonly CultureInfo Invariant = CultureInfo.InvariantCulture;

    private readonly List<string> _ops = [];

    public SignatureLine Signatory { get; init; } = new("Accounts Receivable", "Tallowbrook Logistics", 96f);

    public byte[] Render(Invoice invoice, Customer customer)
    {
        _ops.Clear();
        float y = PageHeight - Margin;

        Text("Helvetica-Bold", 18, Margin, y, "Tallowbrook Logistics");
        Text("Helvetica", 9, Margin, y - 14, "Harbour Road 12 · 20457 Hamburg · billing@tallowbrook.example");
        Text("Helvetica-Bold", 14, PageWidth - Margin - 160, y, $"Invoice {invoice.Number}");

        y -= 60;
        Text("Helvetica", 10, Margin, y, customer.Name);
        Text("Helvetica", 10, Margin, y - LineHeight, customer.BillingEmail);
        Text("Helvetica", 10, PageWidth - Margin - 160, y, $"Issued: {invoice.IssuedOn:yyyy-MM-dd}");
        Text("Helvetica", 10, PageWidth - Margin - 160, y - LineHeight, $"Due: {invoice.DueOn:yyyy-MM-dd}");
        if (invoice.BuyerReference is { } reference)
        {
            Text("Helvetica", 10, PageWidth - Margin - 160, y - 2 * LineHeight, $"Your ref.: {reference}");
        }

        y -= 70;
        Rule(Margin, y + 4, PageWidth - Margin);
        Text("Helvetica-Bold", 9, Margin, y - 8, "Description");
        Text("Helvetica-Bold", 9, 330, y - 8, "Qty");
        Text("Helvetica-Bold", 9, 380, y - 8, "Unit price");
        Text("Helvetica-Bold", 9, 470, y - 8, "Net");
        y -= 26;

        foreach (InvoiceLine line in invoice.Lines)
        {
            Text("Helvetica", 9, Margin, y, Truncate(line.Description, 52));
            Text("Helvetica", 9, 330, y, $"{line.Quantity.ToString("0.##", Invariant)} {line.Unit}");
            Text("Helvetica", 9, 380, y, Money(line.UnitPrice, invoice.Currency));
            Text("Helvetica", 9, 470, y, Money(line.Net, invoice.Currency));
            y -= LineHeight;
        }

        Rule(380, y, PageWidth - Margin);
        y -= LineHeight;
        Text("Helvetica", 9, 380, y, "Net");
        Text("Helvetica", 9, 470, y, Money(invoice.Net, invoice.Currency));
        Text("Helvetica", 9, 380, y - LineHeight, "VAT");
        Text("Helvetica", 9, 470, y - LineHeight, Money(invoice.Tax, invoice.Currency));
        Text("Helvetica-Bold", 10, 380, y - 2 * LineHeight, "Total");
        Text("Helvetica-Bold", 10, 470, y - 2 * LineHeight, Money(invoice.Total, invoice.Currency));

        if (invoice.OriginDocument is { } origin)
        {
            Text("Helvetica", 8, Margin, y - 4 * LineHeight, $"Goods of {origin.OriginCountry} origin, document {origin.Number} ({origin.IssuingChamber}).");
        }

        Rule(Margin, Signatory.Y, Margin + 180);
        Text("Helvetica", 8, Margin, Signatory.Y - 10, Signatory.SignatoryName);
        Text("Helvetica", 8, Margin, Signatory.Y - 20, Signatory.Title);
        Text("Helvetica", 7, Margin, 40, $"Payable within {(invoice.DueOn.DayNumber - invoice.IssuedOn.DayNumber).ToString(Invariant)} days. Please quote {invoice.Number} with your payment.");

        return Write();
    }

    private void Text(string font, float size, float x, float y, string text)
    {
        string fontName = font == "Helvetica-Bold" ? "/F2" : "/F1";
        _ops.Add(FormattableString.Invariant($"BT {fontName} {size} Tf {x:0.##} {y:0.##} Td ({Escape(text)}) Tj ET"));
    }

    private void Rule(float x1, float y, float x2) =>
        _ops.Add(FormattableString.Invariant($"0.5 w {x1:0.##} {y:0.##} m {x2:0.##} {y:0.##} l S"));

    private byte[] Write()
    {
        byte[] content = Encoding.Latin1.GetBytes(string.Join('\n', _ops));
        string[] objects =
        [
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            FormattableString.Invariant($"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PageWidth} {PageHeight}] /Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> /Contents 6 0 R >>"),
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
        ];

        using var pdf = new MemoryStream();
        var offsets = new List<long>();
        WriteAscii(pdf, "%PDF-1.4\n");
        for (int i = 0; i < objects.Length; i++)
        {
            offsets.Add(pdf.Position);
            WriteAscii(pdf, $"{i + 1} 0 obj\n{objects[i]}\nendobj\n");
        }

        offsets.Add(pdf.Position);
        WriteAscii(pdf, $"6 0 obj\n<< /Length {content.Length} >>\nstream\n");
        pdf.Write(content);
        WriteAscii(pdf, "\nendstream\nendobj\n");

        long xref = pdf.Position;
        var table = new StringBuilder();
        table.Append(CultureInfo.InvariantCulture, $"xref\n0 {offsets.Count + 1}\n0000000000 65535 f \n");
        foreach (long offset in offsets)
        {
            table.Append(CultureInfo.InvariantCulture, $"{offset:D10} 00000 n \n");
        }

        table.Append(CultureInfo.InvariantCulture, $"trailer\n<< /Size {offsets.Count + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n");
        WriteAscii(pdf, table.ToString());
        return pdf.ToArray();
    }

    private static void WriteAscii(Stream stream, string text) => stream.Write(Encoding.ASCII.GetBytes(text));

    private static string Money(decimal amount, string currency) =>
        string.Create(Invariant, $"{amount:N2} {currency}");

    private static string Truncate(string text, int max) => text.Length <= max ? text : text[..(max - 3)] + "...";

    private static string Escape(string text) =>
        text.Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("(", "\\(", StringComparison.Ordinal)
            .Replace(")", "\\)", StringComparison.Ordinal);
}
