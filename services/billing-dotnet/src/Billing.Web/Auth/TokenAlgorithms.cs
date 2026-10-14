using Microsoft.IdentityModel.Tokens;

namespace Tallowbrook.Billing.Web.Auth;

/// <summary>Signing algorithms for each kind of token the service accepts or issues.</summary>
internal static class TokenAlgorithms
{
    // identity-go issues the access tokens of our own clients; the partner gateway signs its own.
    public static readonly string[] ApiAccessTokens = [SecurityAlgorithms.EcdsaSha256, SecurityAlgorithms.RsaSha256];

    // Pay-by-link tokens are minted and checked by this service only.
    public const string PayLink = SecurityAlgorithms.HmacSha256;
}
