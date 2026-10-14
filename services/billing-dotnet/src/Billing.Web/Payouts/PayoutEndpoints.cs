using System.Security.Claims;
using Tallowbrook.Billing.Payouts;
using Tallowbrook.Billing.Web.Audit;
using Tallowbrook.Billing.Web.Auth;

namespace Tallowbrook.Billing.Web.Payouts;

internal static class PayoutEndpoints
{
    public static RouteGroupBuilder MapPayouts(this RouteGroupBuilder api)
    {
        // Called by Billing.Agent with its identity-go access token.
        api.MapPut("/agents/{agentId}/keys", PublishKeys).RequireAuthorization(PortalCookie.AgentPolicy);
        api.MapGet("/agents/{agentId}/instructions", (string agentId, AgentRegistry agents) => Results.Ok(agents.Collect(agentId, 50)))
            .RequireAuthorization(PortalCookie.AgentPolicy);

        // Called from the back office once a payout has its second approval.
        api.MapPost("/payouts/{agentId}", Approve).RequireAuthorization(PortalCookie.StaffPolicy);
        return api;
    }

    private static IResult PublishKeys(string agentId, AgentKeys keys, AgentRegistry agents, ILogger<AgentRegistry> logger)
    {
        if (keys.AgentId != agentId || keys.KemEncapsulationKey.Length == 0 || keys.ExchangeKey.Length == 0)
        {
            return Results.BadRequest();
        }

        agents.Publish(keys);
        logger.LogInformation("Agent {AgentId} published new payout keys", agentId);
        return Results.NoContent();
    }

    private static IResult Approve(string agentId, PayoutInstruction instruction, ClaimsPrincipal user, PayoutInstructionSender sender, AuditTrail audit, TimeProvider clock)
    {
        if (!user.IsInRole("controller") || instruction.ApprovedBy == user.Identity!.Name)
        {
            return Results.Forbid();
        }

        sender.Send(agentId, instruction);
        audit.Append(new AuditEvent(clock.GetUtcNow(), user.Identity!.Name!, "approve-payout", instruction.Id.ToString(),
            new Dictionary<string, string> { ["amount"] = instruction.Amount.ToString("0.00"), ["currency"] = instruction.Currency }));
        return Results.Accepted();
    }
}
