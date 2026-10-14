using System.Collections.Concurrent;
using Tallowbrook.Billing.Payouts;

namespace Tallowbrook.Billing.Web.Payouts;

/// <summary>Current keys of each finance-host agent, and the instructions waiting for it to collect.</summary>
public sealed class AgentRegistry
{
    private readonly ConcurrentDictionary<string, AgentKeys> _agents = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, ConcurrentQueue<SealedPayoutInstruction>> _outbox = new(StringComparer.Ordinal);

    public void Publish(AgentKeys keys) => _agents[keys.AgentId] = keys;

    public AgentKeys? Find(string agentId) => _agents.GetValueOrDefault(agentId);

    public void Enqueue(SealedPayoutInstruction instruction) =>
        _outbox.GetOrAdd(instruction.AgentId, _ => new ConcurrentQueue<SealedPayoutInstruction>()).Enqueue(instruction);

    public IReadOnlyList<SealedPayoutInstruction> Collect(string agentId, int max)
    {
        var batch = new List<SealedPayoutInstruction>();
        if (_outbox.TryGetValue(agentId, out ConcurrentQueue<SealedPayoutInstruction>? queue))
        {
            while (batch.Count < max && queue.TryDequeue(out SealedPayoutInstruction? next))
            {
                batch.Add(next);
            }
        }

        return batch;
    }
}
