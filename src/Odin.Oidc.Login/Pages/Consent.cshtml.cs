using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Odin.Oidc.Login.Flow;
using Odin.Oidc.Login.Hydra;

namespace Odin.Oidc.Login.Pages;

/// <summary>
/// Hydra's consent hand-off. Today every consent is accepted for what the relying party asked: the
/// owner already consented at their identity to this app by name. A screen naming the relying party
/// is the next step, and it will honour <c>Skip</c> the way this does.
/// </summary>
public sealed class ConsentModel(HydraAdminClient hydra) : PageModel
{
    public async Task<IActionResult> OnGetAsync([FromQuery(Name = "consent_challenge")] string? consentChallenge, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(consentChallenge))
        {
            throw new SignInStoppedException("Missing consent_challenge.");
        }

        var request = await hydra.GetConsentRequestAsync(consentChallenge, ct);
        var next = await hydra.AcceptConsentAsync(consentChallenge, new HydraAcceptConsent
        {
            GrantScope = request.RequestedScope ?? [],
            GrantAccessTokenAudience = request.RequestedAccessTokenAudience,
            Session = new HydraConsentSession { IdToken = new Dictionary<string, object>() },
        }, ct);
        return Redirect(next);
    }
}
