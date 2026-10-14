using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.Extensions.Options;
using Tallowbrook.Billing.Payouts;

namespace Tallowbrook.Billing.Agent.Payouts;

internal sealed record TokenResponse(string access_token, int expires_in);

/// <summary>Billing.Web's agent API, called with an access token from identity-go (client credentials).</summary>
internal sealed class BillingApiClient(HttpClient http, IOptions<PayoutOptions> options, TimeProvider clock)
{
    private string? _token;
    private DateTimeOffset _tokenExpires;

    public async Task PublishKeysAsync(AgentKeys keys, CancellationToken ct)
    {
        using HttpRequestMessage request = await AuthorizedAsync(HttpMethod.Put, $"api/agents/{keys.AgentId}/keys", ct);
        request.Content = JsonContent.Create(keys);
        using HttpResponseMessage response = await http.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();
    }

    public async Task<IReadOnlyList<SealedPayoutInstruction>> CollectAsync(string agentId, CancellationToken ct)
    {
        using HttpRequestMessage request = await AuthorizedAsync(HttpMethod.Get, $"api/agents/{agentId}/instructions", ct);
        using HttpResponseMessage response = await http.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<List<SealedPayoutInstruction>>(ct) ?? [];
    }

    private async Task<HttpRequestMessage> AuthorizedAsync(HttpMethod method, string path, CancellationToken ct)
    {
        if (_token is null || clock.GetUtcNow() >= _tokenExpires)
        {
            PayoutOptions settings = options.Value;
            using var form = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = settings.ClientId,
                ["client_secret"] = settings.ClientSecret,
                ["scope"] = "billing.payouts",
            });
            using HttpResponseMessage response = await http.PostAsync(settings.TokenEndpoint, form, ct);
            response.EnsureSuccessStatusCode();
            TokenResponse token = await response.Content.ReadFromJsonAsync<TokenResponse>(ct)
                ?? throw new InvalidOperationException("identity-go returned no token.");
            _token = token.access_token;
            _tokenExpires = clock.GetUtcNow().AddSeconds(token.expires_in - 60);
        }

        var request = new HttpRequestMessage(method, new Uri(options.Value.BillingBaseAddress, path));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _token);
        return request;
    }
}
