using System.ComponentModel.DataAnnotations;
using System.Text;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Microsoft.Extensions.Options;

namespace Tallowbrook.Billing.Web.Payments;

public sealed record DirectDebitMandate(Guid Id, string CustomerId, string AccountHolder, string Iban, string Bic, DateOnly SignedOn);

/// <summary>
/// Customers set up SEPA direct-debit mandates in the portal. The IBAN is encrypted to the payments
/// vault's KMS key before it leaves this service; only payments-java can read it back.
/// </summary>
public sealed class DirectDebitMandateVault(IAmazonKeyManagementService vaultKeys, PaymentsClient payments, IOptions<PaymentsOptions> options, ILogger<DirectDebitMandateVault> logger)
{
    public async Task RegisterAsync(DirectDebitMandate mandate, CancellationToken ct)
    {
        if (!Iban.HasValidCheckDigits(mandate.Iban)) throw new ValidationException($"Mandate {mandate.Id} has an invalid IBAN.");
        var request = new EncryptRequest
        {
            EncryptionAlgorithm = EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256,
            KeyId = options.Value.MandateKeyId,
            Plaintext = new MemoryStream(Encoding.UTF8.GetBytes(Iban.Normalize(mandate.Iban))),
        };
        EncryptResponse response = await vaultKeys.EncryptAsync(request, ct);

        await payments.RegisterMandateAsync(
            new MandateRegistration(mandate.Id, mandate.CustomerId, mandate.AccountHolder, Iban.LastFour(mandate.Iban), mandate.Bic, response.CiphertextBlob.ToArray()),
            ct);
        logger.LogInformation("Registered direct-debit mandate {MandateId} for customer {CustomerId}", mandate.Id, mandate.CustomerId);
    }
}
