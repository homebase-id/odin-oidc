using Microsoft.AspNetCore.Http.Features;
using Odin.Oidc.Login.Hydra;

namespace Odin.Oidc.Login.Flow;

/// <summary>
/// A stopped sign-in and a challenge Hydra already answered are outcomes, not failures: they are
/// rendered by the Error page like an unhandled exception would be, but logged as information. The
/// framework's exception handler, which logs at Error, keeps the rest.
/// </summary>
public sealed class SignInOutcomeMiddleware(RequestDelegate next, ILogger<SignInOutcomeMiddleware> logger)
{
    public const string ItemKey = "Odin.Oidc.Login.Outcome";
    public const string ErrorPath = "/Error";

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await next(context);
        }
        catch (Exception e) when (e is SignInStoppedException or HydraAlreadyAnsweredException && !context.Response.HasStarted)
        {
            logger.LogInformation("{path}: {outcome}", context.Request.Path, e.Message);

            // Re-execute the pipeline at the Error page, the way ExceptionHandlerMiddleware does.
            context.Response.Clear();
            context.Items[ItemKey] = e;
            context.Request.Path = ErrorPath;
            context.Request.QueryString = QueryString.Empty;
            context.SetEndpoint(null);
            context.Features.Get<IRouteValuesFeature>()?.RouteValues?.Clear();
            await next(context);
        }
    }
}
