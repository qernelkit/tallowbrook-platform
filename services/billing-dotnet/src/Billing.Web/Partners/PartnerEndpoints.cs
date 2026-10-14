using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Text;
using Tallowbrook.Billing.Web.Auth;
using Tallowbrook.Billing.Web.Security;

namespace Tallowbrook.Billing.Web.Partners;

public sealed class PartnerClient
{
    public required string ClientId { get; init; }

    public required string PartnerName { get; init; }

    public ClientSecretVerifier? Verifier { get; set; }

    public List<string> CustomerIds { get; init; } = [];
}

public sealed class PartnerClientStore
{
    private readonly ConcurrentDictionary<string, PartnerClient> _clients = new(StringComparer.Ordinal);

    public PartnerClient? Find(string clientId) => _clients.GetValueOrDefault(clientId);

    public void Save(PartnerClient client) => _clients[client.ClientId] = client;
}

public sealed class PartnerDocumentInbox
{
    private readonly ConcurrentQueue<(string ClientId, string FileName, string Text)> _pending = new();

    public void Add(string clientId, string fileName, string text) => _pending.Enqueue((clientId, fileName, text));

    public int Count => _pending.Count;
}

internal static class PartnerEndpoints
{
    public static RouteGroupBuilder MapPartnerApi(this RouteGroupBuilder partners)
    {
        partners.MapPost("/clients/{clientId}/secret", RotateSecret).RequireAuthorization(PortalCookie.StaffPolicy);
        partners.MapPost("/documents", UploadDocumentAsync).AddEndpointFilter(RequireClientSecret);
        partners.MapGet("/customers", (HttpContext http) => Results.Ok(((PartnerClient)http.Items["partner"]!).CustomerIds))
            .AddEndpointFilter(RequireClientSecret);
        return partners;
    }

    private static IResult RotateSecret(string clientId, PartnerClientStore clients, ClientSecretHasher hasher)
    {
        PartnerClient? client = clients.Find(clientId);
        if (client is null)
        {
            return Results.NotFound();
        }

        (string secret, ClientSecretVerifier verifier) = hasher.NewSecret();
        client.Verifier = verifier;
        clients.Save(client);

        // Shown once to the partner manager, who passes it on through the partner's own secure channel.
        return Results.Ok(new { client.ClientId, Secret = secret });
    }

    private static async Task<IResult> UploadDocumentAsync(HttpRequest request, PartnerDocumentInbox inbox)
    {
        var client = (PartnerClient)request.HttpContext.Items["partner"]!;
        using var reader = new StreamReader(request.Body, Encoding.UTF8);
        string text = await reader.ReadToEndAsync(request.HttpContext.RequestAborted);
        if (text.Length > 64 * 1024 || !CryptoFormatting.LooksLikePem(text))
        {
            return Results.BadRequest("Upload the text export from your onboarding pack.");
        }

        string fileName = request.Headers["X-File-Name"].ToString() is { Length: > 0 } name ? Path.GetFileName(name) : "upload.txt";
        inbox.Add(client.ClientId, fileName, text);
        return Results.Accepted();
    }

    private static async ValueTask<object?> RequireClientSecret(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        HttpContext http = context.HttpContext;
        if (!AuthenticationHeaderValue.TryParse(http.Request.Headers.Authorization, out AuthenticationHeaderValue? header)
            || header.Scheme != "Basic" || header.Parameter is null)
        {
            return Results.Unauthorized();
        }

        string[] parts = Encoding.UTF8.GetString(Convert.FromBase64String(header.Parameter)).Split(':', 2);
        PartnerClientStore clients = http.RequestServices.GetRequiredService<PartnerClientStore>();
        ClientSecretHasher hasher = http.RequestServices.GetRequiredService<ClientSecretHasher>();
        PartnerClient? client = parts.Length == 2 ? clients.Find(parts[0]) : null;
        if (client?.Verifier is null || !hasher.Matches(parts[1], client.Verifier))
        {
            return Results.Unauthorized();
        }

        http.Items["partner"] = client;
        return await next(context);
    }
}
