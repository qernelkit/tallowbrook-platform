using System.DirectoryServices.Protocols;
using System.Net;
using Microsoft.Extensions.Options;

namespace Tallowbrook.Billing.Web.Staff;

public sealed class FinanceDirectoryOptions
{
    public string Server { get; set; } = "dc01.corp.tallowbrook.example";

    public string BaseDn { get; set; } = "DC=corp,DC=tallowbrook,DC=example";

    /// <summary>Only groups with this prefix map to back-office roles.</summary>
    public string GroupPrefix { get; set; } = "FIN-";

    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(10);
}

/// <summary>Back-office roles come from FIN-* group membership in Active Directory.</summary>
public sealed class FinanceDirectory(IOptions<FinanceDirectoryOptions> options, ILogger<FinanceDirectory> logger)
{
    private static readonly Dictionary<string, string> RoleByGroup = new(StringComparer.OrdinalIgnoreCase)
    {
        ["FIN-AR-CLERKS"] = "ar-clerk",
        ["FIN-AR-LEADS"] = "ar-lead",
        ["FIN-CONTROLLERS"] = "controller",
        ["FIN-AUDITORS"] = "auditor",
    };

    public IReadOnlyList<string> RolesFor(string account)
    {
        FinanceDirectoryOptions settings = options.Value;
        using var connection = new LdapConnection(new LdapDirectoryIdentifier(settings.Server, 636));
        connection.SessionOptions.SecureSocketLayer = true;
        connection.SessionOptions.ProtocolVersion = 3;
        connection.AuthType = AuthType.Kerberos;
        connection.Credential = CredentialCache.DefaultNetworkCredentials;
        connection.Timeout = settings.Timeout;
        connection.Bind();

        var request = new SearchRequest(
            settings.BaseDn,
            $"(&(objectCategory=person)(sAMAccountName={Escape(account)}))",
            SearchScope.Subtree,
            "memberOf");
        var response = (SearchResponse)connection.SendRequest(request);
        if (response.Entries.Count == 0)
        {
            logger.LogWarning("No directory entry for back-office account {Account}", account);
            return [];
        }

        var roles = new List<string>();
        foreach (string groupDn in response.Entries[0].Attributes["memberOf"]?.GetValues(typeof(string)).Cast<string>() ?? [])
        {
            string cn = groupDn.Split(',')[0].Replace("CN=", "", StringComparison.OrdinalIgnoreCase);
            if (cn.StartsWith(settings.GroupPrefix, StringComparison.OrdinalIgnoreCase) && RoleByGroup.TryGetValue(cn, out string? role))
            {
                roles.Add(role);
            }
        }

        return roles;
    }

    // RFC 4515 escaping for the account name typed into the sign-in form.
    private static string Escape(string value) =>
        value.Replace("\\", "\\5c", StringComparison.Ordinal)
            .Replace("*", "\\2a", StringComparison.Ordinal)
            .Replace("(", "\\28", StringComparison.Ordinal)
            .Replace(")", "\\29", StringComparison.Ordinal)
            .Replace("\0", "\\00", StringComparison.Ordinal);
}
