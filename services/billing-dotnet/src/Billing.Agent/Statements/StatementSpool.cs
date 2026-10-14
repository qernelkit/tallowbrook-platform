using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;

namespace Tallowbrook.Billing.Agent.Statements;

/// <summary>
/// Verified statements wait on the finance host until the bookkeeping import picks them up. They hold
/// account numbers and counterparties, so they are kept protected on disk.
/// </summary>
internal sealed class StatementSpool(IDataProtectionProvider protection, IOptions<StatementOptions> options)
{
    private readonly IDataProtector _protector = protection.CreateProtector("Tallowbrook.Billing.Agent.StatementSpool.v1");

    public async Task SpoolAsync(string statementId, byte[] statement, CancellationToken ct)
    {
        Directory.CreateDirectory(options.Value.SpoolPath);
        string path = Path.Combine(options.Value.SpoolPath, $"{statementId}.camt053");
        await File.WriteAllBytesAsync(path, _protector.Protect(statement), ct);
    }

    public async Task<byte[]> ReadAsync(string statementId, CancellationToken ct)
    {
        byte[] stored = await File.ReadAllBytesAsync(Path.Combine(options.Value.SpoolPath, $"{statementId}.camt053"), ct);
        return _protector.Unprotect(stored);
    }

    public IEnumerable<string> Pending() =>
        Directory.Exists(options.Value.SpoolPath)
            ? Directory.EnumerateFiles(options.Value.SpoolPath, "*.camt053").Select(Path.GetFileNameWithoutExtension).OfType<string>()
            : [];
}
