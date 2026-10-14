namespace Tallowbrook.Billing.Payouts;

/// <summary>An instruction to pay a carrier or refund a customer, executed by the agent through the bank file.</summary>
public sealed record PayoutInstruction(
    Guid Id,
    string BeneficiaryName,
    string BeneficiaryIban,
    string BeneficiaryBic,
    decimal Amount,
    string Currency,
    string RemittanceText,
    DateOnly ExecutionDate,
    string ApprovedBy);

/// <summary>What the agent publishes at start-up so Billing.Web can address instructions to it.</summary>
public sealed record AgentKeys(string AgentId, byte[] KemEncapsulationKey, byte[] ExchangeKey, DateTimeOffset PublishedAt);

/// <summary>A payout instruction as it travels from Billing.Web to the agent.</summary>
public sealed record SealedPayoutInstruction(
    Guid InstructionId,
    string AgentId,
    byte[] KemMessage,
    byte[] SenderExchangeKey,
    byte[] Salt,
    byte[] Body);
