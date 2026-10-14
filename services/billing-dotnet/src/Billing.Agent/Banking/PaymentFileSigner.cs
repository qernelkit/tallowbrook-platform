using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace Tallowbrook.Billing.Agent.Banking;

/// <summary>Detached signature the bank checks before it accepts a payment file.</summary>
[SupportedOSPlatform("windows")]
internal sealed class PaymentFileSigner : IDisposable
{
    private readonly Lazy<CngKey> _tpmKey = new(PaymentFileSigningKey.OpenOrCreate);

    public byte[] Sign(byte[] paymentFile)
    {
        using var signer = new ECDsaCng(_tpmKey.Value);
        byte[] signature = signer.SignData(paymentFile, HashAlgorithmName.SHA256);
        return signature;
    }

    public void Dispose()
    {
        if (_tpmKey.IsValueCreated)
        {
            _tpmKey.Value.Dispose();
        }
    }
}
