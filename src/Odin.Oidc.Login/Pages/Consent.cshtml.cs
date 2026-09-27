using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Odin.Oidc.Login.Claims;
using Odin.Oidc.Login.Flow;
using Odin.Oidc.Login.Hydra;

namespace Odin.Oidc.Login.Pages;

/// <summary>
/// Hydra's consent hand-off. The owner consented at their identity to this app by name; here the
/// relying party is named, with what it will learn. A consent Hydra remembers, or a client Hydra
/// trusts, is accepted without asking. The claims are read fresh from the identity every time.
/// </summary>
public sealed class ConsentModel(HydraAdminClient hydra, ProfileClaims profileClaims) : PageModel
{
    public string ConsentChallenge { get; private set; } = "";
    public string RelyingPartyName { get; private set; } = "";
    public string Subject { get; private set; } = "";
    public List<string> Grants { get; } = [];

    public async Task<IActionResult> OnGetAsync([FromQuery(Name = "consent_challenge")] string? consentChallenge, CancellationToken ct)
    {
        var request = await hydra.GetConsentRequestAsync(Required(consentChallenge), ct);
        if (request.Skip || request.Client?.SkipConsent == true)
        {
            return Redirect(await AcceptAsync(consentChallenge!, request, remember: false, ct));
        }

        ConsentChallenge = consentChallenge!;
        RelyingPartyName = request.Client?.DisplayName ?? "A site";
        Subject = request.Subject ?? "";
        var scope = request.RequestedScope ?? [];
        Grants.Add($"your identity, {Subject}");
        if (scope.Contains(ProfileClaims.ProfileScope))
        {
            Grants.Add("your public name and picture");
        }
        if (scope.Contains("offline") || scope.Contains("offline_access"))
        {
            Grants.Add("to stay signed in without asking again");
        }
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(
        [FromForm(Name = "consent_challenge")] string? consentChallenge,
        [FromForm(Name = "allow")] string? allow,
        [FromForm(Name = "remember")] bool remember,
        CancellationToken ct)
    {
        Required(consentChallenge);
        if (allow != "yes")
        {
            return Redirect(await hydra.RejectConsentAsync(consentChallenge!, new HydraReject
            {
                Error = "access_denied",
                ErrorDescription = "The user did not allow this site to know who they are",
            }, ct));
        }

        var request = await hydra.GetConsentRequestAsync(consentChallenge!, ct);
        return Redirect(await AcceptAsync(consentChallenge!, request, remember, ct));
    }

    private async Task<string> AcceptAsync(string consentChallenge, HydraConsentRequest request, bool remember, CancellationToken ct)
    {
        var scope = request.RequestedScope ?? [];
        var claims = await profileClaims.ForAsync(request.Subject ?? "", scope, ct);
        return await hydra.AcceptConsentAsync(consentChallenge, new HydraAcceptConsent
        {
            GrantScope = scope,
            GrantAccessTokenAudience = request.RequestedAccessTokenAudience,
            Remember = remember,
            RememberFor = remember ? Remembered.ForSeconds : null,
            Session = new HydraConsentSession { IdToken = claims },
        }, ct);
    }

    private static string Required(string? consentChallenge) =>
        string.IsNullOrEmpty(consentChallenge) ? throw new SignInStoppedException("Missing consent_challenge.") : consentChallenge;
}
