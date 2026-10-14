namespace Tallowbrook.Billing.Web.Payments;

public sealed class PaymentsOptions
{
    public Uri BaseAddress { get; set; } = new("https://payments.tallowbrook.example/");

    public string ClientCertificatePath { get; set; } = "";

    /// <summary>From the Payments__ClientCertificatePassword environment variable only.</summary>
    public string? ClientCertificatePassword { get; set; }

    public string ServerCertificatePath { get; set; } = "";

    /// <summary>AWS KMS key (alias or ARN) of the payments vault that stores mandate IBANs.</summary>
    public string MandateKeyId { get; set; } = "";

    public string AwsRegion { get; set; } = "eu-central-1";
}
