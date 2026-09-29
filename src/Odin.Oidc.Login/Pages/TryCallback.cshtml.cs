using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;
using Odin.Oidc.Login.Flow;
using Odin.Oidc.Login.Try;

namespace Odin.Oidc.Login.Pages;

/// <summary>
/// The try-it relying party's callback: the flow in the cookie or nobody's, the code for the
/// tokens, the claims on the page. A refusal from the person (or their identity) is shown, not
/// thrown: it is the sign-in's answer, and the page exists to show answers.
/// </summary>
[EnableRateLimiting(FormPostLimiter.Policy)]
public sealed class TryCallbackModel(TryRelyingParty relyingParty, TryFlowCookie cookie) : PageModel
{
    public TryResult? Result { get; private set; }
    public string? Refusal { get; private set; }

    public async Task<IActionResult> OnGetAsync(
        [FromQuery(Name = "code")] string? code,
        [FromQuery(Name = "state")] string? state,
        [FromQuery(Name = "error")] string? error,
        [FromQuery(Name = "error_description")] string? errorDescription,
        CancellationToken ct)
    {
        var flow = cookie.Read(Request);
        if (flow == null || string.IsNullOrEmpty(state) || state != flow.State)
        {
            throw new SignInStoppedException("This try was not started here or has expired. Start again from the Try page.");
        }
        cookie.Delete(Response);

        if (!string.IsNullOrEmpty(error))
        {
            Refusal = $"{error}{(string.IsNullOrEmpty(errorDescription) ? "" : ": " + errorDescription)}";
            return Page();
        }

        Result = await relyingParty.CompleteAsync(SignInStoppedException.Required(code, "code"), flow, Request.Scheme, ct);
        return Page();
    }
}
