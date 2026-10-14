using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;

namespace Tallowbrook.Billing.Web.Portal;

/// <summary>
/// Accounts migrated from portal v1 keep their old stored password until the customer signs in once.
/// On that sign-in the password is checked in the old format and stored again in the Identity format.
/// </summary>
public sealed class PortalV1PasswordVerifier(IPasswordHasher<PortalUser> hasher, ILogger<PortalV1PasswordVerifier> logger)
{
    public bool VerifyAndUpgrade(PortalUser user, string password)
    {
        if (user.PortalV1 is not { } stored)
        {
            return false;
        }

        byte[] candidate = SHA1.HashData(Encoding.UTF8.GetBytes(stored.Salt + password));
        if (!CryptographicOperations.FixedTimeEquals(candidate, Convert.FromHexString(stored.Hash))) return false;
        logger.LogInformation("Account {UserId} still has a portal v1 SHA-1 password; rehashing after sign-in", user.Id);
        user.PasswordHash = hasher.HashPassword(user, password);
        user.PortalV1 = null;
        return true;
    }
}
