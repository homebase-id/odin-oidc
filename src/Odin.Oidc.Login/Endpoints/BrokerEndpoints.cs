using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Odin.Oidc.Login.Flow;
using Odin.Oidc.Login.Hydra;
using Odin.Oidc.Login.Options;
using Odin.Oidc.Login.YouAuth;

namespace Odin.Oidc.Login.Endpoints;

/// <summary>
/// Everything but the login page: the YouAuth callback, Hydra's consent and logout hand-offs, the
/// client document the identity reads about this app, and health. The login page itself is
/// <c>Pages/Login.cshtml</c>, because it has a form.
/// </summary>
public static class BrokerEndpoints
{
    public static void MapBrokerEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/youauth/callback", YouAuthCallback);
        app.MapGet("/consent", Consent);
        app.MapGet("/logout", Logout);
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
        var flow = cookie.Read(context.Request);
        if (flow == null)
        {
            return Problem(StatusCodes.Status400BadRequest, "This sign-in has expired or was not started here. Start again from the site you were signing in to.");
        }

        // The callback belongs to the flow in the cookie or it is nobody's: a forged or replayed
        // callback cannot be matched to a Hydra challenge.
        if (string.IsNullOrEmpty(state) || !CryptographicOperations.FixedTimeEquals(
                System.Text.Encoding.UTF8.GetBytes(state), System.Text.Encoding.UTF8.GetBytes(flow.State)))
        {
            return Problem(StatusCodes.Status400BadRequest, "This sign-in does not match the one in progress. Start again from the site you were signing in to.");
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
            return Problem(StatusCodes.Status400BadRequest, "The identity's answer is incomplete.");
        }

        byte[] clientAuthToken;
        try
        {
            clientAuthToken = await youAuth.CompleteAsync(flow.Identity, flow.Keys, publicKey, salt, ct);
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
            Remember = false,
        }, ct);
        return Results.Redirect(next);
    }

    /// <summary>
    /// Hydra's consent hand-off. The owner already consented at their identity to this app by name,
    /// so M1 grants what the relying party asked for; a page naming the relying party is M2.
    /// </summary>
    private static async Task<IResult> Consent(
        [FromQuery(Name = "consent_challenge")] string? challenge,
        HydraAdminClient hydra,
        CancellationToken ct)
    {
        if (string.IsNullOrEmpty(challenge))
        {
            return Problem(StatusCodes.Status400BadRequest, "Missing consent_challenge.");
        }
        var request = await hydra.GetConsentRequestAsync(challenge, ct);
        var next = await hydra.AcceptConsentAsync(challenge, new HydraAcceptConsent
        {
            GrantScope = request.RequestedScope ?? [],
            GrantAccessTokenAudience = request.RequestedAccessTokenAudience,
            Remember = false,
            Session = new HydraConsentSession { IdToken = new Dictionary<string, object>() },
        }, ct);
        return Results.Redirect(next);
    }

    /// <summary>Hydra's logout hand-off. There is no session here to end, so it is accepted at once.</summary>
    private static async Task<IResult> Logout(
        [FromQuery(Name = "logout_challenge")] string? challenge,
        HydraAdminClient hydra,
        CancellationToken ct)
    {
        if (string.IsNullOrEmpty(challenge))
        {
            return Problem(StatusCodes.Status400BadRequest, "Missing logout_challenge.");
        }
        return Results.Redirect(await hydra.AcceptLogoutAsync(challenge, ct));
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
        return Results.Json(new ClientDocumentBody(broker.ClientName, [broker.CallbackUri]));
    }

    private sealed record ClientDocumentBody(
        [property: System.Text.Json.Serialization.JsonPropertyName("name")] string Name,
        [property: System.Text.Json.Serialization.JsonPropertyName("redirect_uris")] string[] RedirectUris);

    private static IResult Problem(int status, string detail) =>
        Results.Problem(detail: detail, statusCode: status, title: "Sign-in could not continue");
}
