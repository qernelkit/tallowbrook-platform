using System.Security.Cryptography;
using Microsoft.Extensions.Options;

namespace Tallowbrook.Billing.Agent.Banking;

/// <summary>The bank signs each camt.053 account statement; unsigned or altered statements are not booked.</summary>
internal sealed class StatementVerifier(IOptions<StatementOptions> options, ILogger<StatementVerifier> logger)
{
    public bool Verify(string statementId, byte[] statement, byte[] signature)
    {
        using ECDsa bankKey = ECDsa.Create(BankProfile.StatementCurve);
        bankKey.ImportFromPem(File.ReadAllText(options.Value.BankKeyPath));
        if (!bankKey.VerifyData(statement, signature, HashAlgorithmName.SHA256))
        {
            logger.LogError("Statement {StatementId} failed the bank's signature check and was not booked", statementId);
            return false;
        }

        return true;
    }
}
