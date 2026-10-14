using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace Tallowbrook.Billing.Agent.Banking;

public sealed record BankStatement(string Id, DateOnly BookingDate, byte[] Document, byte[] Signature);

internal sealed record StatementListing(string Id, DateOnly BookingDate, string DocumentUrl, string SignatureUrl);

/// <summary>The bank's file-transfer portal: payment file upload, statement download, password rotation.</summary>
[SupportedOSPlatform("windows")]
internal sealed class BankGatewayClient(HttpClient http, BankPortalCredentialStore credentials, IOptions<BankPortalOptions> options, ILogger<BankGatewayClient> logger)
{
    private const string PasswordAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#%+=?";

    public async Task UploadPaymentFileAsync(string batchId, byte[] paymentFile, byte[] signature, CancellationToken ct)
    {
        using var form = new MultipartFormDataContent
        {
            { new ByteArrayContent(paymentFile), "file", $"{batchId}.pay" },
            { new ByteArrayContent(signature), "signature", $"{batchId}.sig" },
        };
        using HttpResponseMessage response = await SendAsync(() => new HttpRequestMessage(HttpMethod.Post, "upload/payments") { Content = form }, ct);
        response.EnsureSuccessStatusCode();
        logger.LogInformation("Uploaded payment file {BatchId}", batchId);
    }

    public async Task<IReadOnlyList<BankStatement>> DownloadStatementsAsync(DateOnly since, CancellationToken ct)
    {
        using HttpResponseMessage listing = await SendAsync(() => new HttpRequestMessage(HttpMethod.Get, $"statements?since={since:yyyy-MM-dd}"), ct);
        listing.EnsureSuccessStatusCode();
        List<StatementListing> entries = await listing.Content.ReadFromJsonAsync<List<StatementListing>>(ct) ?? [];

        var statements = new List<BankStatement>();
        foreach (StatementListing entry in entries)
        {
            byte[] document = await GetBytesAsync(entry.DocumentUrl, ct);
            byte[] signature = await GetBytesAsync(entry.SignatureUrl, ct);
            statements.Add(new BankStatement(entry.Id, entry.BookingDate, document, signature));
        }

        return statements;
    }

    private async Task<byte[]> GetBytesAsync(string url, CancellationToken ct)
    {
        using HttpResponseMessage response = await SendAsync(() => new HttpRequestMessage(HttpMethod.Get, url), ct);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsByteArrayAsync(ct);
    }

    private async Task<HttpResponseMessage> SendAsync(Func<HttpRequestMessage> create, CancellationToken ct)
    {
        HttpResponseMessage response = await http.SendAsync(Authorize(create()), ct);
        if (response.StatusCode == HttpStatusCode.Forbidden && response.Headers.Contains("X-Password-Expired"))
        {
            response.Dispose();
            await RotatePasswordAsync(ct);
            response = await http.SendAsync(Authorize(create()), ct);
        }

        return response;
    }

    // The bank expires the portal password every 90 days and accepts a new one from the logged-in user.
    private async Task RotatePasswordAsync(CancellationToken ct)
    {
        string next = RandomNumberGenerator.GetString(PasswordAlphabet, 32);
        using HttpResponseMessage response = await http.SendAsync(
            Authorize(new HttpRequestMessage(HttpMethod.Post, "account/password") { Content = JsonContent.Create(new { newPassword = next }) }),
            ct);
        response.EnsureSuccessStatusCode();
        credentials.SavePassword(next);
        logger.LogWarning("Bank portal password was rotated at the bank's request");
    }

    private HttpRequestMessage Authorize(HttpRequestMessage request)
    {
        string basic = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{options.Value.UserName}:{credentials.ReadPassword()}"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", basic);
        return request;
    }
}
