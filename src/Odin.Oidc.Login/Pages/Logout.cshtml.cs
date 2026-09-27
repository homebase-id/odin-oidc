using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Odin.Oidc.Login.Flow;
using Odin.Oidc.Login.Hydra;

namespace Odin.Oidc.Login.Pages;

/// <summary>
/// Hydra's logout hand-off. A logout the relying party started needs no question; one the browser
/// started (someone opened the logout URL) is confirmed, since it ends the remembered login.
/// </summary>
public sealed class LogoutModel(HydraAdminClient hydra) : PageModel
{
    public string LogoutChallenge { get; private set; } = "";
    public string Subject { get; private set; } = "";
    public bool Declined { get; private set; }

    public async Task<IActionResult> OnGetAsync([FromQuery(Name = "logout_challenge")] string? logoutChallenge, CancellationToken ct)
    {
        var request = await hydra.GetLogoutRequestAsync(Required(logoutChallenge), ct);
        if (request.RpInitiated)
        {
            return Redirect(await hydra.AcceptLogoutAsync(logoutChallenge!, ct));
        }

        LogoutChallenge = logoutChallenge!;
        Subject = request.Subject ?? "";
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(
        [FromForm(Name = "logout_challenge")] string? logoutChallenge,
        [FromForm(Name = "confirm")] string? confirm,
        CancellationToken ct)
    {
        Required(logoutChallenge);
        if (confirm == "yes")
        {
            return Redirect(await hydra.AcceptLogoutAsync(logoutChallenge!, ct));
        }

        await hydra.RejectLogoutAsync(logoutChallenge!, ct);
        Declined = true;
        return Page();
    }

    private static string Required(string? logoutChallenge) =>
        string.IsNullOrEmpty(logoutChallenge) ? throw new SignInStoppedException("Missing logout_challenge.") : logoutChallenge;
}
