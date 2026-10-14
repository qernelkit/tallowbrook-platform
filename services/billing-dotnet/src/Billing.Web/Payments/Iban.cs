using System.Numerics;

namespace Tallowbrook.Billing.Web.Payments;

/// <summary>ISO 13616 IBAN helpers.</summary>
public static class Iban
{
    private static readonly Dictionary<string, int> LengthByCountry = new(StringComparer.Ordinal)
    {
        ["AT"] = 20,
        ["BE"] = 16,
        ["CH"] = 21,
        ["DE"] = 22,
        ["DK"] = 18,
        ["ES"] = 24,
        ["FI"] = 18,
        ["FR"] = 27,
        ["GB"] = 22,
        ["IE"] = 22,
        ["IT"] = 27,
        ["LU"] = 20,
        ["NL"] = 18,
        ["NO"] = 15,
        ["PL"] = 28,
        ["PT"] = 25,
        ["SE"] = 24,
    };

    public static string Normalize(string iban) => string.Concat(iban.Where(c => !char.IsWhiteSpace(c))).ToUpperInvariant();

    /// <summary>Mod-97 check: move the first four characters to the end, letters to numbers, remainder must be 1.</summary>
    public static bool HasValidCheckDigits(string iban)
    {
        string value = Normalize(iban);
        if (value.Length < 15 || !LengthByCountry.TryGetValue(value[..2], out int length) || value.Length != length)
        {
            return false;
        }

        string rearranged = value[4..] + value[..4];
        var digits = new System.Text.StringBuilder(rearranged.Length * 2);
        foreach (char c in rearranged)
        {
            if (char.IsAsciiDigit(c))
            {
                digits.Append(c);
            }
            else if (char.IsAsciiLetterUpper(c))
            {
                digits.Append(c - 'A' + 10);
            }
            else
            {
                return false;
            }
        }

        return BigInteger.Parse(digits.ToString()) % 97 == 1;
    }

    /// <summary>For display: DE89 3704 0044 0532 0130 00.</summary>
    public static string Format(string iban) =>
        string.Join(' ', Normalize(iban).Chunk(4).Select(chunk => new string(chunk)));

    public static string LastFour(string iban) => Normalize(iban)[^4..];
}
