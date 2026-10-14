namespace Tallowbrook.Billing.Web.Staff;

/// <summary>A finance team member using the back office. Shares the staff table with the 2016 back-office tool.</summary>
public sealed class StaffUser
{
    public required int Id { get; init; }

    /// <summary>Active Directory sAMAccountName, e.g. j.okafor.</summary>
    public required string Account { get; init; }

    public required string DisplayName { get; init; }

    public string? PasswordHash { get; set; }

    public bool Disabled { get; set; }

    public DateTimeOffset? LastSignIn { get; set; }
}

public interface IStaffUserStore
{
    StaffUser? FindByAccount(string account);

    void Save(StaffUser user);
}

internal sealed class StaffUserStore : IStaffUserStore
{
    private readonly Dictionary<string, StaffUser> _users = new(StringComparer.OrdinalIgnoreCase);
    private readonly Lock _gate = new();

    public StaffUser? FindByAccount(string account)
    {
        lock (_gate)
        {
            return _users.GetValueOrDefault(account);
        }
    }

    public void Save(StaffUser user)
    {
        lock (_gate)
        {
            _users[user.Account] = user;
        }
    }
}
