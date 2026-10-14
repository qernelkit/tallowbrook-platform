namespace Tallowbrook.Billing.Web.Invoices;

/// <summary>
/// Customs document attached to export invoices. Issued by a chamber of commerce; we only record the
/// reference so the PDF and the e-invoice can quote it.
/// </summary>
public sealed class CertificateOfOrigin
{
    public required string Number { get; init; }

    /// <summary>ISO 3166-1 alpha-2 country of origin of the goods.</summary>
    public required string OriginCountry { get; init; }

    /// <summary>Harmonized System tariff codes covered by the document.</summary>
    public IReadOnlyList<string> HsCodes { get; init; } = [];

    public required string IssuingChamber { get; init; }

    public DateOnly IssuedOn { get; init; }

    public bool Covers(string hsCode) =>
        HsCodes.Any(code => hsCode.StartsWith(code, StringComparison.Ordinal));
}
