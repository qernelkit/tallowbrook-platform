using Microsoft.AspNetCore.Authentication.Cookies;

namespace Tallowbrook.Billing.Web.Auth;

internal static class PortalCookie
{
    public const string Scheme = CookieAuthenticationDefaults.AuthenticationScheme;
    public const string Name = "tb_portal";
    public const string CustomerPolicy = "customer";
    public const string StaffPolicy = "staff";
    public const string AgentPolicy = "payout-agent";
}
