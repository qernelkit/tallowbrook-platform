using System.Security.Cryptography;
using Tallowbrook.Billing.Web.Customers;
using Tallowbrook.Billing.Web.Invoices;

namespace Tallowbrook.Billing.Web.Statements;

/// <summary>An accounting partner that imports our customers' monthly statements over SFTP.</summary>
public sealed record AccountingPartner(string Id, string Name, string DropFolder, byte[] StatementKey);

public interface IAccountingPartnerStore
{
    AccountingPartner? Find(string id);
}

/// <summary>
/// Writes the monthly statement file for customers whose bookkeeping is done by an accounting partner.
/// The partner's import tool fixes the file encryption: a 16-byte key exchanged at onboarding, a random
/// IV written in front of the ciphertext.
/// </summary>
public sealed class PartnerStatementExporter(
    IAccountingPartnerStore partners,
    ICustomerStore customers,
    IInvoiceStore invoices,
    StatementBuilder builder,
    ILogger<PartnerStatementExporter> logger)
{
    public async Task ExportMonthAsync(int year, int month, CancellationToken ct)
    {
        var from = new DateOnly(year, month, 1);
        DateOnly to = from.AddMonths(1).AddDays(-1);

        foreach (Customer customer in customers.All().Where(c => c.AccountingPartnerId is not null))
        {
            AccountingPartner? partner = partners.Find(customer.AccountingPartnerId!);
            if (partner is null)
            {
                logger.LogWarning("Customer {CustomerId} names unknown accounting partner {PartnerId}", customer.Id, customer.AccountingPartnerId);
                continue;
            }

            byte[] statement = builder.Build(customer, invoices.ForCustomer(customer.Id), from, to);
            string path = Path.Combine(partner.DropFolder, $"{customer.Id}-{year:D4}{month:D2}.stm");
            await File.WriteAllBytesAsync(path, Seal(partner, statement), ct);
            logger.LogInformation("Statement {Year}-{Month} for {CustomerId} written for partner {PartnerId}", year, month, customer.Id, partner.Id);
        }
    }

    private static byte[] Seal(AccountingPartner partner, byte[] statement)
    {
        using Aes aes = Aes.Create();
        aes.KeySize = 128;
        aes.Mode = CipherMode.CBC;
        aes.Key = partner.StatementKey;
        aes.GenerateIV();

        using var output = new MemoryStream();
        output.Write(aes.IV);
        using (ICryptoTransform encryptor = aes.CreateEncryptor())
        using (var stream = new CryptoStream(output, encryptor, CryptoStreamMode.Write, leaveOpen: true))
        {
            stream.Write(statement);
        }

        return output.ToArray();
    }
}

internal sealed class AccountingPartnerStore : IAccountingPartnerStore
{
    private readonly Dictionary<string, AccountingPartner> _partners = new(StringComparer.Ordinal);

    public AccountingPartner? Find(string id) => _partners.GetValueOrDefault(id);

    public void Add(AccountingPartner partner) => _partners[partner.Id] = partner;
}
