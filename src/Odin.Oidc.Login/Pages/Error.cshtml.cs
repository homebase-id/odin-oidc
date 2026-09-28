using System.Diagnostics;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Odin.Oidc.Login.Flow;
using Odin.Oidc.Login.Hydra;

namespace Odin.Oidc.Login.Pages;

/// <summary>
/// The one place a failure is shown. <see cref="SignInOutcomeMiddleware"/> or the exception handler
/// re-executes here: a <see cref="SignInStoppedException"/> is a 400 with its words; a challenge
/// Hydra already answered (the browser went back to a page it had left) is a 410 that says so,
/// since Hydra's own redirect for it re-presents a used verifier; anything else is a 500 with a
/// reference to find in the log.
/// </summary>
public sealed class ErrorModel : PageModel
{
    public string Detail { get; private set; } = "Something went wrong. Go back to the site you were signing in to and try again.";
    public string? RequestId { get; private set; }

    public IActionResult OnGet()
    {
        var exception = HttpContext.Items[SignInOutcomeMiddleware.ItemKey] as Exception
                        ?? HttpContext.Features.Get<IExceptionHandlerFeature>()?.Error;
        switch (exception)
        {
            case HydraAlreadyAnsweredException:
                Response.StatusCode = StatusCodes.Status410Gone;
                Detail = "This sign-in was already completed. Return to the site you were signing in to; if it does not show you as signed in, start again from there.";
                break;
            case SignInStoppedException stopped:
                Response.StatusCode = StatusCodes.Status400BadRequest;
                Detail = stopped.Message;
                break;
            default:
                Response.StatusCode = StatusCodes.Status500InternalServerError;
                RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier;
                break;
        }
        return Page();
    }
}
