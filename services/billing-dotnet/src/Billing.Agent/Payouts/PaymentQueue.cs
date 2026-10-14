using System.Collections.Concurrent;
using Tallowbrook.Billing.Payouts;

namespace Tallowbrook.Billing.Agent.Payouts;

/// <summary>Opened instructions waiting for the next payment-file cut-off.</summary>
internal sealed class PaymentQueue
{
    private readonly ConcurrentDictionary<Guid, PayoutInstruction> _pending = new();

    public bool Add(PayoutInstruction instruction) => _pending.TryAdd(instruction.Id, instruction);

    public IReadOnlyList<PayoutInstruction> TakeDue(DateOnly executionDate)
    {
        var due = new List<PayoutInstruction>();
        foreach (PayoutInstruction instruction in _pending.Values.Where(i => i.ExecutionDate <= executionDate))
        {
            if (_pending.TryRemove(instruction.Id, out PayoutInstruction? taken))
            {
                due.Add(taken);
            }
        }

        return due;
    }

    public void Return(IEnumerable<PayoutInstruction> instructions)
    {
        foreach (PayoutInstruction instruction in instructions)
        {
            _pending.TryAdd(instruction.Id, instruction);
        }
    }

    public int Count => _pending.Count;
}
