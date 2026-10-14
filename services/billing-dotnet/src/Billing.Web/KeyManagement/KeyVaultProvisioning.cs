using Azure.Security.KeyVault.Keys;

namespace Tallowbrook.Billing.Web.KeyManagement;

/// <summary>
/// Admin command <c>provision-keys</c>: creates the archive keys in the environment's Key Vault. Run
/// once per environment by an operator with the Key Vault Crypto Officer role.
/// </summary>
internal sealed class KeyVaultProvisioning(KeyClient keys, TextWriter output)
{
    public async Task<int> RunAsync(string kekName, string manifestKeyName, CancellationToken ct)
    {
        var rsaOptions = new CreateRsaKeyOptions(kekName, hardwareProtected: true)
        {
            KeySize = 3072,
            KeyOperations = { KeyOperation.Encrypt, KeyOperation.Decrypt },
        };
        KeyVaultKey kek = await keys.CreateRsaKeyAsync(rsaOptions, ct);
        output.WriteLine($"Created {kek.Name} ({kek.KeyType}), version {kek.Properties.Version}");

        var ecOptions = new CreateEcKeyOptions(manifestKeyName, hardwareProtected: true)
        {
            CurveName = KeyCurveName.P384,
            KeyOperations = { KeyOperation.Sign, KeyOperation.Verify },
        };
        KeyVaultKey manifest = await keys.CreateEcKeyAsync(ecOptions, ct);
        output.WriteLine($"Created {manifest.Name} ({manifest.KeyType}), version {manifest.Properties.Version}");

        output.WriteLine("Grant the billing managed identity 'Key Vault Crypto User' on both keys.");
        return 0;
    }
}
