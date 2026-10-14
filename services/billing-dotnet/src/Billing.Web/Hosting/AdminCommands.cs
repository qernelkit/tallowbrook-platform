using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Tallowbrook.Billing.Web.Archive;
using Tallowbrook.Billing.Web.EInvoicing;
using Tallowbrook.Billing.Web.KeyManagement;

namespace Tallowbrook.Billing.Web.Hosting;

/// <summary>
/// One-off operator commands, run as <c>dotnet Billing.Web.dll &lt;command&gt;</c> in a shell of the
/// billing container. They exit without starting the web host.
/// </summary>
internal static class AdminCommands
{
    public static bool TryRun(string[] args, IConfiguration configuration, out int exitCode)
    {
        exitCode = 0;
        switch (args)
        {
            case ["provision-keys", ..]:
                var archive = configuration.GetSection("Archive").Get<ArchiveOptions>() ?? new ArchiveOptions();
                if (archive.VaultUri is null)
                {
                    Console.Error.WriteLine("Set Archive__VaultUri first.");
                    exitCode = 2;
                    return true;
                }

                var keys = new KeyClient(archive.VaultUri, new DefaultAzureCredential());
                exitCode = new KeyVaultProvisioning(keys, Console.Out)
                    .RunAsync(archive.KekName, archive.ManifestKeyName, CancellationToken.None)
                    .GetAwaiter().GetResult();
                return true;
            case ["generate-archive-keys", ..]:
                exitCode = ArchiveSigningKeys.Run(Console.Out);
                return true;
            case ["enroll-einvoice-cert", string directory]:
                exitCode = SigningCertificateEnrollment.Run(directory, Console.Out);
                return true;
            case ["enroll-einvoice-cert", ..]:
                Console.Error.WriteLine("usage: enroll-einvoice-cert <output-directory>");
                exitCode = 64;
                return true;
            default:
                return false;
        }
    }
}
