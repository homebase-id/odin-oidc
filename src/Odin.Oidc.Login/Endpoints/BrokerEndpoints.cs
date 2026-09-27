using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Odin.Core;
using Odin.Oidc.Login.Flow;
using Odin.Oidc.Login.Hydra;
using Odin.Oidc.Login.Options;
using Odin.Oidc.Login.YouAuth;

namespace Odin.Oidc.Login.Endpoints;

/// <summary>
/// The YouAuth callback, the client document the identity reads about this app, and health.
/// Login, consent and logout are Razor pages, because they have a form.
/// A sign-in that cannot go on throws <see cref="SignInStoppedException"/>; the Error page renders it.
/// </summary>
public static class BrokerEndpoints
{
    public static void MapBrokerEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/youauth/callback", YouAuthCallback);
        app.MapGet("/.well-known/youauth-client.json", ClientDocument);
        app.MapGet("/healthz", () => Results.Text("ok"));
    }

    /// <summary>
    /// YouAuth [080] and onward: the identity sent the browser back. Match it to the flow the cookie
    /// holds, finish the exchange, release the registration, answer Hydra's challenge.
    /// </summary>
    private static async Task<IResult> YouAuthCallback(
        HttpContext context,
        [FromQuery(Name = YouAuthWire.State)] string? state,
        [FromQuery(Name = YouAuthWire.PublicKey)] string? publicKey,
        [FromQuery(Name = YouAuthWire.Salt)] string? salt,
        [FromQuery(Name = YouAuthWire.Error)] string? error,
        [FromQuery(Name = YouAuthWire.ErrorDescription)] string? errorDescription,
        LoginFlowCookie cookie,
        YouAuthClient youAuth,
        HydraAdminClient hydra,
        ILogger<YouAuthClient> logger,
        CancellationToken ct)
    {
        // The callback belongs to the flow in the cookie or it is nobody's: without the cookie, or
        // with a state that is not its, a forged or replayed callback cannot be matched to a Hydra
        // challenge.
        var flow = cookie.Read(context.Request);
        if (flow == null || string.IsNullOrEmpty(state) ||
            !CryptographicOperations.FixedTimeEquals(state.ToUtf8ByteArray(), flow.State.ToUtf8ByteArray()))
        {
            throw new SignInStoppedException("This sign-in has expired or was not started here. Start again from the site you were signing in to.");
        }

        cookie.Delete(context.Response);

        // YouAuth [060]: the identity reported a failure, or the owner declined.
        if (!string.IsNullOrEmpty(error))
        {
            logger.LogInformation("YouAuth: {identity} answered with error={error} ({description})", flow.Identity, error, errorDescription);
            var redirect = await hydra.RejectLoginAsync(flow.LoginChallenge, new HydraReject
            {
                Error = "access_denied",
                ErrorDescription = $"{flow.Identity} did not authorize the sign-in ({error}{(string.IsNullOrEmpty(errorDescription) ? "" : ": " + errorDescription)})",
            }, ct);
            return Results.Redirect(redirect);
        }

        if (string.IsNullOrEmpty(publicKey) || string.IsNullOrEmpty(salt))
        {
            throw new SignInStoppedException("The identity's answer is incomplete.");
        }

        byte[] clientAuthToken;
        try
        {
            clientAuthToken = await youAuth.CompleteAsync(flow.Identity, flow.PrivateKeyJwk, publicKey, salt, ct);
        }
        catch (YouAuthException e)
        {
            logger.LogWarning(e, "YouAuth: the exchange with {identity} failed", flow.Identity);
            var redirect = await hydra.RejectLoginAsync(flow.LoginChallenge, new HydraReject
            {
                Error = "server_error",
                ErrorDescription = $"Could not complete the sign-in with {flow.Identity}",
            }, ct);
            return Results.Redirect(redirect);
        }

        // The token proved the identity; that is all it is for here.
        await youAuth.ReleaseAsync(flow.Identity, clientAuthToken, ct);
        CryptographicOperations.ZeroMemory(clientAuthToken);

        logger.LogInformation("Signed in {identity} for Hydra challenge {challenge}", flow.Identity, flow.LoginChallenge);
        var next = await hydra.AcceptLoginAsync(flow.LoginChallenge, new HydraAcceptLogin
        {
            Subject = flow.Identity,
            Remember = flow.Remember,
            RememberFor = flow.Remember ? Remembered.ForSeconds : null,
        }, ct);
        return Results.Redirect(next);
    }

    /// <summary>
    /// What an identity reads about this app before asking its owner to sign in here
    /// (odin-core docs/youauth-client-metadata-plan.md): the name shown small under the domain on
    /// the consent page, and the only callback the identity will redirect to.
    /// </summary>
    private static IResult ClientDocument(IOptions<BrokerOptions> options, HttpContext context)
    {
        var broker = options.Value;
        context.Response.Headers.CacheControl = "public, max-age=3600";
        return Results.Json(new { name = broker.ClientName, redirect_uris = new[] { broker.CallbackUri } });
    }
}
