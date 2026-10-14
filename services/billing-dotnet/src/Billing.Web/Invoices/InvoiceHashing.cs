using System.IO.Hashing;

namespace Tallowbrook.Billing.Web.Invoices;

/// <summary>Bucketing and de-duplication keys for invoice reports and CSV imports.</summary>
internal static class InvoiceHashing
{
    public const int ReportBuckets = 64;

    /// <summary>Spreads monthly report jobs over the worker pool.</summary>
    public static int ReportBucket(string tenantId, int year, int month) => HashCode.Combine(tenantId, year, month) & 0x3F;

    /// <summary>Recognises a row that a customer imported twice in the same CSV batch.</summary>
    public static ulong ImportRowKey(ReadOnlySpan<byte> row) => XxHash64.HashToUInt64(row);
}
