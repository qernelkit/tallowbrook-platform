using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using Tallowbrook.Billing.Agent;
using Tallowbrook.Billing.Agent.Banking;
using Tallowbrook.Billing.Agent.Payouts;
using Tallowbrook.Billing.Agent.Statements;
using Tallowbrook.Billing.Agent.Workers;

// Billing.Agent runs as a Windows service on the on-premises finance host, under the svc-billagent gMSA.
if (!OperatingSystem.IsWindows())
{
    Console.Error.WriteLine("Billing.Agent needs Windows (TPM key, DPAPI).");
    return 1;
}

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "Tallowbrook Billing Agent");

builder.Services.Configure<BankFileOptions>(builder.Configuration.GetSection("BankFile"));
builder.Services.Configure<StatementOptions>(builder.Configuration.GetSection("Statements"));
builder.Services.Configure<BankPortalOptions>(builder.Configuration.GetSection("BankPortal"));
builder.Services.Configure<PayoutOptions>(builder.Configuration.GetSection("Payouts"));

// Protects the statement spool; the key ring stays on the finance host.
string spoolKeysPath = builder.Configuration["Spool:KeysPath"] ?? "C:/ProgramData/Tallowbrook/BillingAgent/keys";
builder.Services.AddDataProtection()
    .SetApplicationName("tallowbrook-billing-agent")
    .PersistKeysToFileSystem(new DirectoryInfo(spoolKeysPath))
    .UseCryptographicAlgorithms(new AuthenticatedEncryptorConfiguration
    {
        EncryptionAlgorithm = EncryptionAlgorithm.AES_256_CBC,
        ValidationAlgorithm = ValidationAlgorithm.HMACSHA256,
    });

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<BankFileWriter>();
builder.Services.AddSingleton<PaymentFileSigner>();
builder.Services.AddSingleton<StatementVerifier>();
builder.Services.AddSingleton<StatementSpool>();
builder.Services.AddSingleton<BankPortalCredentialStore>();
builder.Services.AddSingleton<PayoutKeyPair>();
builder.Services.AddSingleton<PayoutInstructionReceiver>();
builder.Services.AddSingleton<PaymentQueue>();

builder.Services.AddHttpClient<BankGatewayClient>((sp, client) =>
    client.BaseAddress = builder.Configuration.GetSection("BankPortal").Get<BankPortalOptions>()?.BaseAddress);
builder.Services.AddHttpClient<BillingApiClient>();

builder.Services.AddHostedService<PayoutWorker>();
builder.Services.AddHostedService<BankFileWorker>();
builder.Services.AddHostedService<StatementWorker>();

await builder.Build().RunAsync();
return 0;
