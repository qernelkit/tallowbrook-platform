using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace Tallowbrook.Billing.Web.Staff;

/// <summary>
/// Back-office passwords live in the staff table that the 2016 back-office tool also reads, and that
/// tool only understands the older Identity hash format. Keep this until the tool is retired.
/// </summary>
internal sealed class StaffPasswordHasher : PasswordHasher<StaffUser>
{
    public StaffPasswordHasher()
        : base(Options.Create(new PasswordHasherOptions
        {
            CompatibilityMode = PasswordHasherCompatibilityMode.IdentityV2,
        }))
    {
    }
}
