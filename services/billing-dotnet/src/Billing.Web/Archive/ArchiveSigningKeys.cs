using System.Security.Cryptography;

namespace Tallowbrook.Billing.Web.Archive;

/// <summary>
/// Admin command <c>generate-archive-keys</c>: prints new manifest and year-end seal keys for the
/// operator to store as Key Vault secrets. Run once per environment, then remove the terminal history.
/// </summary>
internal static class ArchiveSigningKeys
{
    public static int Run(TextWriter output)
    {
        if (!MLDsa.IsSupported)
        {
            output.WriteLine("This host's crypto library cannot generate archive keys. Run the command in the billing container.");
            return 2;
        }

        using MLDsa manifestKey = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        output.WriteLine($"Archive__ManifestSeed={Convert.ToBase64String(manifestKey.ExportMLDsaPrivateSeed())}");

        // SlhDsa is marked experimental in .NET 10.
#pragma warning disable SYSLIB5006
        using SlhDsa sealKey = SlhDsa.GenerateKey(SlhDsaAlgorithm.SlhDsaSha2_128s);
        output.WriteLine($"Archive__SealKey={Convert.ToBase64String(sealKey.ExportSlhDsaPrivateKey())}");
#pragma warning restore SYSLIB5006

        output.WriteLine("Store both values in Key Vault (billing-archive-manifest-seed, billing-archive-seal-key).");
        return 0;
    }
}
