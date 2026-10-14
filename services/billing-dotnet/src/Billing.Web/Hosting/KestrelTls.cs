using System.Net.Security;
using System.Security.Authentication;
using Microsoft.AspNetCore.Server.Kestrel.Core;

namespace Tallowbrook.Billing.Web.Hosting;

/// <summary>
/// HTTPS settings for the portal listener. The certificate comes from Kestrel:Certificates:Default in
/// appsettings.json; the container runs on Linux, where Kestrel can restrict the suites.
/// </summary>
internal static class KestrelTls
{
    public static void ConfigureBillingTls(this KestrelServerOptions kestrel)
    {
        kestrel.ConfigureHttpsDefaults(httpsOptions =>
        {
            httpsOptions.SslProtocols = SslProtocols.Tls13;
            httpsOptions.OnAuthenticate = (connection, ssl) =>
            {
                ssl.CipherSuitesPolicy = new CipherSuitesPolicy(
                [
                    TlsCipherSuite.TLS_AES_256_GCM_SHA384,
                    TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256,
                ]);
            };
        });
    }
}
