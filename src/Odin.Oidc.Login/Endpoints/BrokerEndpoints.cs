using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Odin.Oidc.Login.Flow;
using Odin.Oidc.Login.Hydra;
using Odin.Oidc.Login.Options;
using Odin.Oidc.Login.Try;
using Odin.Oidc.Login.YouAuth;

namespace Odin.Oidc.Login.Endpoints;

/// <summary>
/// The YouAuth callback, Hydra's logout hand-off, the client document the identity reads about
/// this app, and health. Login and consent are Razor pages, because they have a form.
/// A sign-in that cannot go on throws <see cref="SignInStoppedException"/>; the Error page renders it.
/// </summary>
public static class BrokerEndpoints
{
    public static void MapBrokerEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/youauth/callback", YouAuthCallback).RequireRateLimiting(FormPostLimiter.Policy);
        app.MapGet("/logout", Logout);
        app.MapGet("/.well-known/youauth-client.json", ClientDocument);
        app.MapGet(TryRelyingParty.DocumentPath, TryClientDocument);
        app.MapGet("/healthz", Health);
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
        var flow = cookie.Claim(context.Request, context.Response, state, f => f.State,
            "This sign-in has expired or was not started here. Start again from the site you were signing in to.");

        // YouAuth [060]: the identity reported a failure, or the owner declined.
        if (!string.IsNullOrEmpty(error))
        {
            logger.LogInformation("YouAuth: the identity answered with error={error}", error);
            logger.LogDebug("YouAuth: {identity} answered with error={error} ({description})", flow.Identity, error, errorDescription);
            var redirect = await hydra.RejectLoginAsync(flow.LoginChallenge, new HydraReject
            {
                Error = "access_denied",
                ErrorDescription = $"{flow.Identity} did not authorize the sign-in ({OAuthError.Describe(error, errorDescription)})",
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
            logger.LogWarning("YouAuth: the token exchange with the identity failed: {reason}", e.Message);
            logger.LogDebug(e, "YouAuth: the exchange with {identity} failed", flow.Identity);
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

        logger.LogInformation("Signed in a subject for a Hydra challenge");
        logger.LogDebug("Signed in {identity} for Hydra challenge {challenge}", flow.Identity, flow.LoginChallenge);
        var next = await hydra.AcceptLoginAsync(flow.LoginChallenge, new HydraAcceptLogin { Subject = flow.Identity, Remember = flow.Remember }, ct);
        return Results.Redirect(next);
    }

    /// <summary>Hydra's logout hand-off, accepted at once: nothing links here but relying parties, whose logout is their own decision.</summary>
    private static async Task<IResult> Logout([FromQuery(Name = "logout_challenge")] string? challenge, HydraAdminClient hydra, CancellationToken ct)
    {
        return Results.Redirect(await hydra.AcceptLogoutAsync(SignInStoppedException.Required(challenge, "logout_challenge"), ct));
    }

    /// <summary>
    /// Health means this process answers and Hydra is ready, so a deploy's smoke test and an uptime
    /// probe see the whole broker.
    /// </summary>
    private static async Task<IResult> Health(HydraAdminClient hydra, CancellationToken ct)
    {
        var hydraReady = await hydra.IsReadyAsync(ct);
        return hydraReady ? Results.Text("ok") : Results.Text("hydra is not ready", statusCode: StatusCodes.Status503ServiceUnavailable);
    }

    /// <summary>The try-it relying party's client document: this app's own registration as a URL client (Try/TryRelyingParty.cs).</summary>
    private static IResult TryClientDocument(TryRelyingParty relyingParty, HttpContext context) =>
        CachedJson(context, relyingParty.Document);

    /// <summary>A document about this app that may be cached for the same hour a client document is believed for.</summary>
    private static IResult CachedJson(HttpContext context, object document)
    {
        context.Response.Headers.CacheControl = $"public, max-age={(int)Registration.ClientDocument.DefaultCache.TotalSeconds}";
        return Results.Json(document);
    }

    /// <summary>
    /// What an identity reads about this app before asking its owner to sign in here
    /// (odin-core docs/youauth-client-metadata-plan.md): the name shown small under the domain on
    /// the consent page, and the only callback the identity will redirect to.
    /// </summary>
    private static IResult ClientDocument(IOptions<BrokerOptions> options, HttpContext context) =>
        CachedJson(context, new { name = options.Value.ClientName, redirect_uris = new[] { options.Value.CallbackUri } });
}
