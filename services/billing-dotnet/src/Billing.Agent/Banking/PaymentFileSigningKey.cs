using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace Tallowbrook.Billing.Agent.Banking;

/// <summary>
/// The payment-file key lives in the finance host's TPM. Its public half was registered with the bank
/// at onboarding; if the key is ever recreated, the bank has to be sent the new public key first.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class PaymentFileSigningKey
{
    private const string KeyName = "Tallowbrook-BillingAgent-PaymentFiles";
    private static readonly CngProvider Provider = CngProvider.MicrosoftPlatformCryptoProvider;

    public static CngKey OpenOrCreate() =>
        CngKey.Exists(KeyName, Provider, CngKeyOpenOptions.MachineKey)
            ? CngKey.Open(KeyName, Provider, CngKeyOpenOptions.MachineKey)
            : CngKey.Create(CngAlgorithm.ECDsaP256, KeyName, new CngKeyCreationParameters
            {
                Provider = Provider,
                KeyCreationOptions = CngKeyCreationOptions.MachineKey,
                ExportPolicy = CngExportPolicies.None,
            });
}
