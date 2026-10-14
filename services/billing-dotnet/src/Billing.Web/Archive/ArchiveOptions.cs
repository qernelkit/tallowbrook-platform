namespace Tallowbrook.Billing.Web.Archive;

public sealed class ArchiveOptions
{
    /// <summary>Key Vault of the billing service; set per environment.</summary>
    public Uri? VaultUri { get; set; }

    public string KekName { get; set; } = "billing-archive-kek";

    public string ManifestKeyName { get; set; } = "billing-archive-signing";

    public string Directory { get; set; } = "/var/lib/tallowbrook/billing/archive";

    /// <summary>Base64 seed printed by generate-archive-keys; from the Archive__ManifestSeed secret.</summary>
    public byte[] ManifestSeed { get; set; } = [];

    /// <summary>Base64 key printed by generate-archive-keys; from the Archive__SealKey secret.</summary>
    public byte[] SealKey { get; set; } = [];

    public TimeOnly RunAtUtc { get; set; } = new(1, 30);
}
