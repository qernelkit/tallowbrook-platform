using System.Security.Cryptography;
using System.Text.Json;
using Tallowbrook.Billing.Payouts;
using Tallowbrook.Billing.Security;

namespace Tallowbrook.Billing.Web.Payouts;

/// <summary>
/// Approved payouts are sealed to the agent's current keys and queued until the agent collects them.
/// Instructions older than the agent's last restart cannot be opened and are re-sent by finance.
/// </summary>
public sealed class PayoutInstructionSender(AgentRegistry agents, ILogger<PayoutInstructionSender> logger)
{
    public SealedPayoutInstruction Send(string agentId, PayoutInstruction instruction)
    {
        AgentKeys agent = agents.Find(agentId) ?? throw new InvalidOperationException($"Agent {agentId} has not published its keys.");
        byte[] salt = RandomNumberGenerator.GetBytes(16);

        logger.LogInformation("Encrypting payout instruction {InstructionId} for agent {AgentId}", instruction.Id, agent.AgentId);
        using MLKem agentKem = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, agent.KemEncapsulationKey);
        agentKem.Encapsulate(out byte[] kemMessage, out byte[] kemSecret);

        using ECDiffieHellman ephemeral = PayoutEnvelope.CreateKey();
        using ECDiffieHellman agentExchange = PayoutEnvelope.ImportPublicKey(agent.ExchangeKey);
        byte[] key = PayoutEnvelope.DeriveKey(ephemeral, agentExchange, kemSecret, salt);

        byte[] body = AeadBox.Seal(key, JsonSerializer.SerializeToUtf8Bytes(instruction), instruction.Id.ToByteArray());
        CryptographicOperations.ZeroMemory(key);

        var sealedInstruction = new SealedPayoutInstruction(instruction.Id, agentId, kemMessage, ephemeral.ExportSubjectPublicKeyInfo(), salt, body);
        agents.Enqueue(sealedInstruction);
        return sealedInstruction;
    }
}
