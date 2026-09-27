using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Odin.Core.Util;
using Odin.Oidc.Login.Flow;
using Odin.Oidc.Login.Hydra;
using Odin.Oidc.Login.YouAuth;

namespace Odin.Oidc.Login.Pages;

/// <summary>
/// Hydra's login hand-off. GET: accept at once when Hydra already knows the user, else ask which
/// identity. POST: start the YouAuth flow at that identity, remembering the challenge in the flow
/// cookie so the callback can answer it.
/// </summary>
public sealed class LoginModel(HydraAdminClient hydra, YouAuthClient youAuth, LoginFlowCookie cookie, ILogger<LoginModel> logger) : PageModel
{
    /// <summary>
    /// The domain typed last time, so the owner only clicks Continue. A convenience, not a session:
    /// it grants nothing, and the relying party's login hint wins over it.
    /// </summary>
    public const string RememberedIdentityCookie = "odin_oidc_identity";

    private static readonly CookieOptions RememberedIdentityAttributes = new()
    {
        HttpOnly = true,
        Secure = true,
        SameSite = SameSiteMode.Lax,
        Path = "/login",
        MaxAge = TimeSpan.FromDays(365),
        IsEssential = true,
    };

    public string LoginChallenge { get; private set; } = "";
    public string RelyingPartyName { get; private set; } = "A site";
    public string Identity { get; private set; } = "";
    public string? Problem { get; private set; }

    public async Task<IActionResult> OnGetAsync([FromQuery(Name = "login_challenge")] string? loginChallenge, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(loginChallenge))
        {
            return BadRequest("Missing login_challenge.");
        }

        var request = await hydra.GetLoginRequestAsync(loginChallenge, ct);
        if (request.Skip && !string.IsNullOrEmpty(request.Subject))
        {
            // Hydra remembers this browser's session; the identity was proven then.
            var next = await hydra.AcceptLoginAsync(loginChallenge, new HydraAcceptLogin { Subject = request.Subject }, ct);
            return Redirect(next);
        }

        LoginChallenge = loginChallenge;
        RelyingPartyName = request.Client?.ClientName is { Length: > 0 } name ? name : request.Client?.ClientId ?? RelyingPartyName;
        Identity = request.OidcContext?.LoginHint is { Length: > 0 } hint ? hint
            : Request.Cookies.TryGetValue(RememberedIdentityCookie, out var remembered) ? remembered : "";
        return Page();
    }

    public async Task<IActionResult> OnPostAsync([FromForm(Name = "login_challenge")] string? loginChallenge, [FromForm(Name = "identity")] string? identity, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(loginChallenge))
        {
            return BadRequest("Missing login_challenge.");
        }

        var request = await hydra.GetLoginRequestAsync(loginChallenge, ct);
        LoginChallenge = loginChallenge;
        RelyingPartyName = request.Client?.ClientName is { Length: > 0 } name ? name : request.Client?.ClientId ?? RelyingPartyName;
        Identity = identity?.Trim() ?? "";

        var domain = Identity.ToLowerInvariant();
        if (!AsciiDomainNameValidator.TryValidateDomain(domain))
        {
            Problem = $"'{Identity}' is not a domain name. A Homebase identity looks like frodo.dotyou.cloud.";
            return Page();
        }

        Response.Cookies.Append(RememberedIdentityCookie, domain, RememberedIdentityAttributes);

        // YouAuth [010] and [030]
        var state = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var (authorizeUrl, keys) = youAuth.Begin(domain, state);
        cookie.Write(Response, new LoginFlowState(loginChallenge, domain, state, keys));

        logger.LogInformation("Sending the browser to {identity} for Hydra challenge {challenge}", domain, loginChallenge);
        return Redirect(authorizeUrl.ToString());
    }
}
