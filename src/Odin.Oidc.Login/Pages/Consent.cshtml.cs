using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;
using Odin.Oidc.Login.Claims;
using Odin.Oidc.Login.Flow;
using Odin.Oidc.Login.Hydra;
using Odin.Oidc.Login.Registration;

namespace Odin.Oidc.Login.Pages;

/// <summary>
/// Hydra's consent hand-off. The owner consented at their identity to this app by name; here the
/// relying party is named, with what it will learn. Allow is remembered for a month. A consent
/// Hydra remembers, or a client Hydra trusts (registered with skip consent, for first parties), is
/// accepted without asking. The claims are read fresh from the identity every time.
/// </summary>
[EnableRateLimiting(FormPostLimiter.Policy)]
public sealed class ConsentModel(HydraAdminClient hydra, ProfileClaims profileClaims) : PageModel
{
    public string ConsentChallenge { get; private set; } = "";
    public HydraConsentRequest Consent { get; private set; } = new();
    public RelyingParty RelyingParty { get; private set; } = new(null, null);

    public async Task<IActionResult> OnGetAsync([FromQuery(Name = "consent_challenge")] string? consentChallenge, CancellationToken ct)
    {
        var challenge = SignInStoppedException.Required(consentChallenge, "consent_challenge");
        var request = await hydra.GetConsentRequestAsync(challenge, ct);
        if (request.Skip || request.Client.SkipConsent)
        {
            return Redirect(await AcceptAsync(challenge, request, ct));
        }

        ConsentChallenge = challenge;
        Consent = request;
        RelyingParty = RelyingParty.From(request.Client, request.RequestUrl);
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(
        [FromForm(Name = "consent_challenge")] string? consentChallenge,
        [FromForm(Name = "allow")] string? allow,
        CancellationToken ct)
    {
        var challenge = SignInStoppedException.Required(consentChallenge, "consent_challenge");
        if (allow != "yes")
        {
            return Redirect(await hydra.RejectConsentAsync(challenge, new HydraReject
            {
                Error = "access_denied",
                ErrorDescription = "The user did not allow this site to know who they are",
            }, ct));
        }

        // What is granted comes from Hydra, not the form.
        return Redirect(await AcceptAsync(challenge, await hydra.GetConsentRequestAsync(challenge, ct), ct));
    }

    private async Task<string> AcceptAsync(string challenge, HydraConsentRequest request, CancellationToken ct)
    {
        return await hydra.AcceptConsentAsync(challenge, new HydraAcceptConsent
        {
            GrantScope = request.RequestedScope,
            GrantAccessTokenAudience = request.RequestedAccessTokenAudience,
            Remember = true,
            Session = new HydraConsentSession { IdToken = await profileClaims.ForAsync(request.Subject ?? "", request.RequestedScope, ct) },
        }, ct);
    }
}
