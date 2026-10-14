using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace Tallowbrook.Billing.Agent.Banking;

/// <summary>
/// The bank's upload portal password, readable only by the agent's service account. Ops set it with
/// Set-AgentBankPortalCredential.ps1; the agent replaces it when the bank forces a rotation. Both write
/// the same format: hex text of a DPAPI blob over the UTF-16 password.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class BankPortalCredentialStore(IOptions<BankPortalOptions> options)
{
    public string ReadPassword()
    {
        string text = File.ReadAllText(options.Value.PasswordFile).Trim();
        byte[] clear = ProtectedData.Unprotect(Convert.FromHexString(text), null, DataProtectionScope.CurrentUser);
        try
        {
            return Encoding.Unicode.GetString(clear);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(clear);
        }
    }

    public void SavePassword(string password)
    {
        byte[] blob = ProtectedData.Protect(Encoding.Unicode.GetBytes(password), null, DataProtectionScope.CurrentUser);
        string temporary = options.Value.PasswordFile + ".new";
        File.WriteAllText(temporary, Convert.ToHexStringLower(blob));
        File.Move(temporary, options.Value.PasswordFile, overwrite: true);
    }
}
