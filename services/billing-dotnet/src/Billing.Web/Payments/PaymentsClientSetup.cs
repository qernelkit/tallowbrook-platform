using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;

namespace Tallowbrook.Billing.Web.Payments;

/// <summary>
/// The typed client for payments-java. Both sides authenticate with certificates: ours from the payments
/// keystore, and the server must present exactly the certificate we were given for it.
/// </summary>
internal static class PaymentsClientSetup
{
    public static IHttpClientBuilder AddPaymentsClient(this IServiceCollection services)
    {
        return services
            .AddHttpClient<PaymentsClient>((sp, client) =>
            {
                client.BaseAddress = sp.GetRequiredService<IOptions<PaymentsOptions>>().Value.BaseAddress;
                client.Timeout = TimeSpan.FromSeconds(20);
            })
            .ConfigurePrimaryHttpMessageHandler(sp =>
            {
                PaymentsOptions options = sp.GetRequiredService<IOptions<PaymentsOptions>>().Value;
                X509Certificate2 clientCertificate = X509CertificateLoader.LoadPkcs12FromFile(options.ClientCertificatePath, options.ClientCertificatePassword);
                X509Certificate2 serverCertificate = X509CertificateLoader.LoadCertificateFromFile(options.ServerCertificatePath);

                var handler = new SocketsHttpHandler { PooledConnectionLifetime = TimeSpan.FromMinutes(5) };
                handler.SslOptions.ClientCertificates = [clientCertificate];
                handler.SslOptions.RemoteCertificateValidationCallback = (_, presented, _, _) =>
                    presented is not null && presented.GetRawCertData().AsSpan().SequenceEqual(serverCertificate.RawData);
                return handler;
            });
    }
}
