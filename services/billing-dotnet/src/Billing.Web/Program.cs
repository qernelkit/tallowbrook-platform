using Amazon;
using Amazon.KeyManagementService;
using Azure.Identity;
using Azure.Security.KeyVault.Keys.Cryptography;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Tallowbrook.Billing.Web.Archive;
using Tallowbrook.Billing.Web.Audit;
using Tallowbrook.Billing.Web.Auth;
using Tallowbrook.Billing.Web.Cards;
using Tallowbrook.Billing.Web.Customers;
using Tallowbrook.Billing.Web.Disputes;
using Tallowbrook.Billing.Web.EInvoicing;
using Tallowbrook.Billing.Web.Hosting;
using Tallowbrook.Billing.Web.Invoices;
using Tallowbrook.Billing.Web.Invoices.Currency;
using Tallowbrook.Billing.Web.Invoices.Pricing;
using Tallowbrook.Billing.Web.Notifications;
using Tallowbrook.Billing.Web.Partners;
using Tallowbrook.Billing.Web.Payments;
using Tallowbrook.Billing.Web.Payouts;
using Tallowbrook.Billing.Web.Portal;
using Tallowbrook.Billing.Web.SeedData;
using Tallowbrook.Billing.Web.Staff;
using Tallowbrook.Billing.Web.Statements;
using Tallowbrook.Billing.Web.Webhooks;

var builder = WebApplication.CreateBuilder(args);

if (AdminCommands.TryRun(args, builder.Configuration, out int exitCode))
{
    return exitCode;
}

builder.WebHost.ConfigureKestrel(kestrel => kestrel.ConfigureBillingTls());

// ---- options (secrets come from environment variables, never from appsettings)
IConfiguration config = builder.Configuration;
builder.Services.Configure<DocumentStoreOptions>(config.GetSection("Documents"));
builder.Services.Configure<InvoiceLinkOptions>(config.GetSection("InvoiceLinks"));
builder.Services.Configure<InvoiceTokenOptions>(config.GetSection("InvoiceTokens"));
builder.Services.Configure<PayLinkOptions>(config.GetSection("PayLinks"));
builder.Services.Configure<PspOptions>(config.GetSection("Psp"));
builder.Services.Configure<PaymentsOptions>(config.GetSection("Payments"));
builder.Services.Configure<CardVaultOptions>(config.GetSection("CardVault"));
builder.Services.Configure<DisputeOptions>(config.GetSection("Disputes"));
builder.Services.Configure<ArchiveOptions>(config.GetSection("Archive"));
builder.Services.Configure<EInvoicingOptions>(config.GetSection("EInvoicing"));
builder.Services.Configure<FinanceDirectoryOptions>(config.GetSection("FinanceDirectory"));
builder.Services.Configure<ExchangeRateOptions>(config.GetSection("ExchangeRates"));

// ---- authentication: portal and back office use the cookie, API callers bring an access token
builder.Services
    .AddAuthentication(PortalCookie.Scheme)
    .AddCookie(PortalCookie.Scheme, options =>
    {
        options.Cookie.Name = PortalCookie.Name;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
        options.SlidingExpiration = true;
        options.Events.OnRedirectToLogin = context =>
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        };
    })
    .AddJwtBearer(options =>
    {
        options.Authority = config["Auth:Authority"];
        options.Audience = config["Auth:Audience"];
        options.MapInboundClaims = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidAlgorithms = TokenAlgorithms.ApiAccessTokens,
            ClockSkew = TimeSpan.FromSeconds(30),
        };
    });

builder.Services.AddAuthorizationBuilder()
    .AddPolicy(PortalCookie.CustomerPolicy, policy => policy.RequireClaim("customer_id"))
    .AddPolicy(PortalCookie.StaffPolicy, policy => policy.RequireClaim("staff", "true"))
    .AddPolicy(PortalCookie.AgentPolicy, policy => policy
        .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme)
        .RequireClaim("scope", "billing.payouts"));

// Auth cookies, antiforgery tokens and TempData; the key ring lives on the shared volume.
builder.Services.AddDataProtection()
    .SetApplicationName("tallowbrook-billing")
    .PersistKeysToFileSystem(new DirectoryInfo(config["DataProtection:KeysPath"] ?? "/var/lib/tallowbrook/billing/keys"));

// Portal accounts. Back-office staff use their own hasher (see StaffPasswordHasher).
builder.Services.AddSingleton<IPasswordHasher<PortalUser>, PasswordHasher<PortalUser>>();
builder.Services.AddSingleton<IPasswordHasher<StaffUser>, StaffPasswordHasher>();

// ---- application services
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddMemoryCache();
builder.Services.AddProblemDetails();
builder.Services.AddSingleton<IInvoiceStore, InvoiceStore>();
builder.Services.AddSingleton<ICustomerStore, CustomerStore>();
builder.Services.AddSingleton<IPortalUserStore, PortalUserStore>();
builder.Services.AddSingleton<IStaffUserStore, StaffUserStore>();
builder.Services.AddSingleton<IAccountingPartnerStore, AccountingPartnerStore>();
builder.Services.AddSingleton<PartnerClientStore>();
builder.Services.AddSingleton<PartnerDocumentInbox>();
builder.Services.AddSingleton<AgentRegistry>();
builder.Services.AddSingleton<AuditTrail>();
builder.Services.AddSingleton<InvoiceDocumentStore>();
builder.Services.AddSingleton<InvoiceNumberTokenizer>();
builder.Services.AddSingleton<InvoiceDownloadLinks>();
builder.Services.AddSingleton<PayLinkTokens>();
builder.Services.AddSingleton<PortalV1PasswordVerifier>();
builder.Services.AddSingleton<FinanceDirectory>();
builder.Services.AddSingleton<FreightRateCalculator>();
builder.Services.AddSingleton<CurrencyConverter>();
builder.Services.AddSingleton<CardTokenVault>();
builder.Services.AddSingleton<PspCallbackVerifier>();
builder.Services.AddSingleton<DirectDebitMandateVault>();
builder.Services.AddSingleton<StatementBuilder>();
builder.Services.AddSingleton<StatementExportProtector>();
builder.Services.AddSingleton<PartnerStatementExporter>();
builder.Services.AddSingleton<ClientSecretHasher>();
builder.Services.AddSingleton<EvidenceVault>();
builder.Services.AddSingleton<PayoutInstructionSender>();
builder.Services.AddSingleton<EInvoiceXmlWriter>();
builder.Services.AddSingleton<PublicSectorInvoiceSigner>();
builder.Services.AddSingleton<ChinaPartnerSigner>();
builder.Services.AddSingleton<EInvoiceDispatcher>();
builder.Services.AddSingleton<InvoiceDigestEmail>();
builder.Services.AddSingleton<EmailOutbox>();
builder.Services.AddSingleton<OutboundWebhookSigner>();
builder.Services.AddSingleton<WebhookDispatcher>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<WebhookDispatcher>());
builder.Services.AddHostedService<WeeklySummaryJob>();

builder.Services.AddHttpClient("webhooks", client => client.Timeout = TimeSpan.FromSeconds(15));
builder.Services.AddHttpClient<IExchangeRateProvider, EcbExchangeRateProvider>();
builder.Services.AddPaymentsClient();
builder.Services.AddSingleton<IAmazonKeyManagementService>(sp =>
    new AmazonKeyManagementServiceClient(RegionEndpoint.GetBySystemName(sp.GetRequiredService<IOptions<PaymentsOptions>>().Value.AwsRegion)));

// ---- nightly archive (Key Vault keys created by `provision-keys`)
builder.Services.AddSingleton(_ => new DefaultAzureCredential());
builder.Services.AddSingleton(sp => new InvoiceArchiveKeys(ArchiveKeyClient(sp, archive => archive.KekName)));
builder.Services.AddSingleton(sp => new ArchiveManifestSigner(ArchiveKeyClient(sp, archive => archive.ManifestKeyName), sp.GetRequiredService<IOptions<ArchiveOptions>>()));
builder.Services.AddSingleton<YearEndSeal>();
builder.Services.AddHostedService<NightlyArchiveJob>();

var app = builder.Build();

DevelopmentSeeder.Seed(app.Services, app.Environment);

app.UseExceptionHandler();
app.UseStatusCodePages();
app.UseAuthentication();
app.UseAuthorization();

RouteGroupBuilder portal = app.MapGroup("/portal").RequireAuthorization(PortalCookie.CustomerPolicy);
portal.MapPortalSignIn();
portal.MapInvoicePortal();
portal.MapInvoicePdfEndpoints();
portal.MapMandates();
portal.MapCards();
portal.MapStatementExports();
portal.MapDisputes();

app.MapGroup("/back-office").MapBackOffice();
app.MapGroup("/partners").MapPartnerApi();
app.MapGroup("/api").MapPayouts();
app.MapPayLinkPages();
app.MapInvoiceDownloadLinks();
app.MapPspCallbacks();

app.MapPost("/quotes", (Shipment shipment, FreightRateCalculator rates) => Results.Ok(rates.Quote(shipment))).AllowAnonymous();
app.MapGet("/healthz", () => Results.Ok("ok")).AllowAnonymous();

app.Run();
return 0;

static CryptographyClient ArchiveKeyClient(IServiceProvider services, Func<ArchiveOptions, string> keyName)
{
    ArchiveOptions archive = services.GetRequiredService<IOptions<ArchiveOptions>>().Value;
    Uri vault = archive.VaultUri ?? throw new InvalidOperationException("Archive:VaultUri is not configured.");
    return new CryptographyClient(new Uri(vault, $"keys/{keyName(archive)}"), services.GetRequiredService<DefaultAzureCredential>());
}
