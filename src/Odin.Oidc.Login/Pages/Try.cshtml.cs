using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;
using Odin.Oidc.Login.Flow;
using Odin.Oidc.Login.Try;

namespace Odin.Oidc.Login.Pages;

/// <summary>The try-it relying party's front door: a button that starts a sign-in through this broker's public origin.</summary>
[EnableRateLimiting(FormPostLimiter.Policy)]
public sealed class TryModel(TryRelyingParty relyingParty, TryFlowCookie cookie) : PageModel
{
    public IActionResult OnPost()
    {
        var (state, authorizeUrl) = relyingParty.Begin();
        cookie.Write(Response, state);
        return Redirect(authorizeUrl);
    }
}
