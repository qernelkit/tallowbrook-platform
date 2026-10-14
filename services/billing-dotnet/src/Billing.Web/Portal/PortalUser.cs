using System.Collections.Concurrent;

namespace Tallowbrook.Billing.Web.Portal;

public sealed class PortalUser
{
    public required Guid Id { get; init; }

    public required string Email { get; init; }

    public required string DisplayName { get; set; }

    public required string CustomerId { get; init; }

    public required string TenantId { get; init; }

    public List<string> Roles { get; init; } = [];

    /// <summary>Identity format. Null until a portal v1 account signs in for the first time.</summary>
    public string? PasswordHash { get; set; }

    /// <summary>Set only for accounts carried over from portal v1 that have not signed in since.</summary>
    public PortalV1Credential? PortalV1 { get; set; }

    public DateTimeOffset? LastSignIn { get; set; }

    public int FailedSignIns { get; set; }

    public bool IsLockedOut => FailedSignIns >= 10;
}

/// <summary>Stored by portal v1: a hex string and the per-user salt it was computed with.</summary>
public sealed record PortalV1Credential(string Salt, string Hash);

public interface IPortalUserStore
{
    PortalUser? FindByEmail(string email);

    void Save(PortalUser user);
}

internal sealed class PortalUserStore : IPortalUserStore
{
    private readonly ConcurrentDictionary<string, PortalUser> _byEmail = new(StringComparer.OrdinalIgnoreCase);

    public PortalUser? FindByEmail(string email) => _byEmail.GetValueOrDefault(email.Trim());

    public void Save(PortalUser user) => _byEmail[user.Email] = user;
}
