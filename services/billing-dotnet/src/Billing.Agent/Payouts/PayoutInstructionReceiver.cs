using System.Security.Cryptography;
using System.Text.Json;
using Tallowbrook.Billing.Payouts;
using Tallowbrook.Billing.Security;

namespace Tallowbrook.Billing.Agent.Payouts;

/// <summary>Opens payout instructions collected from Billing.Web.</summary>
internal sealed class PayoutInstructionReceiver(PayoutKeyPair keys, ILogger<PayoutInstructionReceiver> logger)
{
    public PayoutInstruction? Open(SealedPayoutInstruction message)
    {
        try
        {
            byte[] kemSecret = keys.Decapsulate(message.KemMessage);
            using ECDiffieHellman sender = PayoutEnvelope.ImportPublicKey(message.SenderExchangeKey);
            byte[] key = PayoutEnvelope.DeriveKey(keys.Exchange, sender, kemSecret, message.Salt);
            byte[] json = AeadBox.Open(key, message.Body, message.InstructionId.ToByteArray());
            CryptographicOperations.ZeroMemory(key);
            return JsonSerializer.Deserialize<PayoutInstruction>(json);
        }
        catch (CryptographicException ex)
        {
            // Sealed to the keys of an earlier agent run, or damaged in transit.
            logger.LogWarning(ex, "Payout instruction {InstructionId} could not be opened; ask finance to re-send it", message.InstructionId);
            return null;
        }
    }
}
