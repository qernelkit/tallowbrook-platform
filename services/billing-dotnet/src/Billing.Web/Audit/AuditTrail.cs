using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Tallowbrook.Billing.Web.Audit;

public sealed record AuditEvent(DateTimeOffset At, string Actor, string Action, string Subject, IReadOnlyDictionary<string, string>? Details = null);

public sealed record AuditEntry(long Sequence, AuditEvent Event, string Link);

/// <summary>
/// Append-only trail of back-office actions (credit notes, write-offs, manual payment matches). Each
/// entry's link covers the previous link and the entry, so the auditors can check that no entry was
/// removed or edited after the fact.
/// </summary>
public sealed class AuditTrail
{
    private static readonly JsonSerializerOptions Canonical = new() { WriteIndented = false };

    private readonly List<AuditEntry> _entries = [];
    private readonly Lock _gate = new();
    private readonly ILogger<AuditTrail> _logger;
    private byte[] _lastLink = new byte[32];

    public AuditTrail(ILogger<AuditTrail> logger)
    {
        if (!SHA3_256.IsSupported) throw new PlatformNotSupportedException("The audit trail link function is not available on this platform.");
        _logger = logger;
    }

    public AuditEntry Append(AuditEvent auditEvent)
    {
        byte[] body = JsonSerializer.SerializeToUtf8Bytes(auditEvent, Canonical);
        lock (_gate)
        {
            byte[] buffer = [.. _lastLink, .. body];
            byte[] link = SHA3_256.HashData(buffer);
            var entry = new AuditEntry(_entries.Count + 1, auditEvent, Convert.ToHexStringLower(link));
            _entries.Add(entry);
            _lastLink = link;
            _logger.LogInformation("Audit {Sequence}: {Actor} {Action} {Subject}", entry.Sequence, auditEvent.Actor, auditEvent.Action, auditEvent.Subject);
            return entry;
        }
    }

    public IReadOnlyList<AuditEntry> Since(long sequence)
    {
        lock (_gate)
        {
            return [.. _entries.Where(e => e.Sequence > sequence)];
        }
    }

    public static string Describe(AuditEvent auditEvent)
    {
        var text = new StringBuilder($"{auditEvent.At:u} {auditEvent.Actor} {auditEvent.Action} {auditEvent.Subject}");
        foreach ((string key, string value) in auditEvent.Details ?? new Dictionary<string, string>())
        {
            text.Append($" {key}={value}");
        }

        return text.ToString();
    }
}
