using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Tallowbrook.Billing.Web.EInvoicing;

/// <summary>
/// Admin command <c>enroll-einvoice-cert &lt;directory&gt;</c>: creates the e-invoicing key and a
/// certificate request for the CA. The operator sends the request to the CA, then combines the issued
/// certificate and the key into the PFX mounted at EInvoicing:SigningCertificatePath.
/// </summary>
internal static class SigningCertificateEnrollment
{
    public static int Run(string directory, TextWriter output)
    {
        Directory.CreateDirectory(directory);
        var subject = new X500DistinguishedName("CN=Tallowbrook Logistics e-Invoicing, O=Tallowbrook Logistics GmbH, C=DE");

        using RSA key = RSA.Create(3072);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        string requestPath = Path.Combine(directory, "einvoice-signing.csr");
        string keyPath = Path.Combine(directory, "einvoice-signing.key");
        File.WriteAllText(requestPath, request.CreateSigningRequestPem());
        File.WriteAllText(keyPath, key.ExportPkcs8PrivateKeyPem());
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        output.WriteLine($"Wrote {requestPath} and {keyPath}. Send the request to the CA; keep the key offline.");
        return 0;
    }
}
