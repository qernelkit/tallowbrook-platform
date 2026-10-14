using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Tallowbrook.Billing.Web.Auth;

namespace Tallowbrook.Billing.Web.Portal;

public sealed record SignInRequest(string Email, string Password, bool RememberMe);

internal static class PortalSignInEndpoints
{
    public static RouteGroupBuilder MapPortalSignIn(this RouteGroupBuilder portal)
    {
        portal.MapPost("/sign-in", SignInAsync).AllowAnonymous();
        portal.MapPost("/sign-out", async (HttpContext http) =>
        {
            await http.SignOutAsync(PortalCookie.Scheme);
            return Results.NoContent();
        });
        return portal;
    }

    private static async Task<IResult> SignInAsync(
        SignInRequest request,
        HttpContext http,
        IPortalUserStore users,
        IPasswordHasher<PortalUser> hasher,
        PortalV1PasswordVerifier portalV1,
        TimeProvider clock,
        ILogger<PortalUser> logger)
    {
        PortalUser? user = users.FindByEmail(request.Email);
        if (user is null || user.IsLockedOut)
        {
            return Results.Problem("The email address or password is not correct.", statusCode: StatusCodes.Status401Unauthorized);
        }

        bool ok;
        if (user.PasswordHash is null)
        {
            ok = portalV1.VerifyAndUpgrade(user, request.Password);
        }
        else
        {
            PasswordVerificationResult result = hasher.VerifyHashedPassword(user, user.PasswordHash, request.Password);
            ok = result != PasswordVerificationResult.Failed;
            if (result == PasswordVerificationResult.SuccessRehashNeeded)
            {
                user.PasswordHash = hasher.HashPassword(user, request.Password);
            }
        }

        if (!ok)
        {
            user.FailedSignIns++;
            users.Save(user);
            logger.LogWarning("Failed portal sign-in for {UserId} ({Failures} in a row)", user.Id, user.FailedSignIns);
            return Results.Problem("The email address or password is not correct.", statusCode: StatusCodes.Status401Unauthorized);
        }

        user.FailedSignIns = 0;
        user.LastSignIn = clock.GetUtcNow();
        users.Save(user);

        var identity = new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.DisplayName),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim("customer_id", user.CustomerId),
                new Claim("tenant_id", user.TenantId),
                .. user.Roles.Select(role => new Claim(ClaimTypes.Role, role)),
            ],
            PortalCookie.Scheme);

        await http.SignInAsync(PortalCookie.Scheme, new ClaimsPrincipal(identity), new AuthenticationProperties { IsPersistent = request.RememberMe });
        return Results.NoContent();
    }
}
