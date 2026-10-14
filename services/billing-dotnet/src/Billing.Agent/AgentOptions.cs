namespace Tallowbrook.Billing.Agent;

public sealed class BankFileOptions
{
    public string OutboxPath { get; set; } = "C:/ProgramData/Tallowbrook/BillingAgent/outbox";

    /// <summary>The key the bank assigned to our payment files (hex).</summary>
    public string EncryptionKeyHex { get; set; } = "";

    public string OriginatorId { get; set; } = "";

    public string OriginatorIban { get; set; } = "";

    /// <summary>Payment files go out at these local times on bank working days.</summary>
    public List<TimeOnly> CutOffs { get; set; } = [new(9, 30), new(14, 0)];
}

public sealed class StatementOptions
{
    public string BankKeyPath { get; set; } = "";

    public string SpoolPath { get; set; } = "C:/ProgramData/Tallowbrook/BillingAgent/statements";

    public TimeSpan PollInterval { get; set; } = TimeSpan.FromHours(1);
}

public sealed class BankPortalOptions
{
    public Uri BaseAddress { get; set; } = new("https://connect.bank.example/");

    public string UserName { get; set; } = "";

    /// <summary>DPAPI blob written by Set-AgentBankPortalCredential.ps1 (or by the agent after a rotation).</summary>
    public string PasswordFile { get; set; } = "C:/ProgramData/Tallowbrook/BillingAgent/bank-portal.cred";
}

public sealed class PayoutOptions
{
    public Uri BillingBaseAddress { get; set; } = new("https://billing.tallowbrook.example/");

    public Uri TokenEndpoint { get; set; } = new("https://id.tallowbrook.example/oauth2/token");

    public string AgentId { get; set; } = Environment.MachineName.ToLowerInvariant();

    public string ClientId { get; set; } = "billing-agent";

    /// <summary>From the Payouts__ClientSecret environment variable of the service only.</summary>
    public string ClientSecret { get; set; } = "";

    public TimeSpan PollInterval { get; set; } = TimeSpan.FromMinutes(1);
}
