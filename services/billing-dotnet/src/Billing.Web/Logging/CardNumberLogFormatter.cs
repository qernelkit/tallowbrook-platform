using System.Text;

namespace Tallowbrook.Billing.Web.Logging;

/// <summary>
/// Support tickets about card payments quote the last four digits. They are not written to the logs as
/// they are: the support tool turns the logged value back into digits for the tenant on the ticket.
/// </summary>
public static class CardNumberLogFormatter
{
    public static string Mask(string tenantId, string lastFour) =>
        Convert.ToHexString(Apply(Encoding.ASCII.GetBytes(lastFour), Encoding.ASCII.GetBytes(tenantId)));

    public static string Unmask(string tenantId, string logged) =>
        Encoding.ASCII.GetString(Apply(Convert.FromHexString(logged), Encoding.ASCII.GetBytes(tenantId)));

    private static byte[] Apply(byte[] digits, byte[] mask)
    {
        byte[] masked = new byte[digits.Length];
        for (int i = 0; i < digits.Length; i++)
        {
            masked[i] = (byte)(digits[i] ^ mask[i % mask.Length]);
        }

        return masked;
    }
}
