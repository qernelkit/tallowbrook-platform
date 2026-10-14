using System.Security.Cryptography;
using Tallowbrook.Billing.Payouts;

namespace Tallowbrook.Billing.Agent.Payouts;

/// <summary>
/// The agent's payout keys exist only in memory and are replaced at every start. Instructions sealed to
/// an earlier set cannot be opened; finance re-sends them from the back office.
/// </summary>
internal sealed class PayoutKeyPair : IDisposable
{
    private readonly MLKem _kem;
    private readonly ECDiffieHellman _exchange;

    public PayoutKeyPair()
    {
        if (!MLKem.IsSupported) throw new PlatformNotSupportedException("Payout instructions cannot be opened on this host.");
        _kem = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
        _exchange = PayoutEnvelope.CreateKey();
    }

    public ECDiffieHellman Exchange => _exchange;

    public AgentKeys Describe(string agentId, DateTimeOffset now) =>
        new(agentId, _kem.ExportEncapsulationKey(), _exchange.ExportSubjectPublicKeyInfo(), now);

    public byte[] Decapsulate(byte[] kemMessage) => _kem.Decapsulate(kemMessage);

    public void Dispose()
    {
        _kem.Dispose();
        _exchange.Dispose();
    }
}
