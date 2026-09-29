using System.Text.Json;
using System.Text.Json.Nodes;
using Odin.Oidc.Login.Flow;

namespace Odin.Oidc.Login.Registration;

/// <summary>
/// Hydra's public API through this app. The authorize endpoint is the gateway: a URL client is
/// registered from its document before the request goes on; anything else passes through
/// untouched. Discovery is Hydra's with the draft's member added (the issuer is this app's origin,
/// so Hydra's authorize endpoint already names it). The rest (token, userinfo, JWKS, revocation, logout) is relayed as is, so a deployment
/// may route all of Hydra's public paths through this app, or only these two (docs/production.md).
/// The relay is a plain HttpClient: same method, path, query, headers and body; Hydra's status,
/// headers (its CSRF cookies among them) and body back.
/// </summary>
public static class HydraRelay
{
    public const string HttpClientName = "hydra-public";

    public static void MapHydraRelay(this IEndpointRouteBuilder app)
    {
        app.MapMethods("/oauth2/auth", ["GET", "POST"], Authorize).RequireRateLimiting(FormPostLimiter.Policy);
        app.MapGet("/.well-known/openid-configuration", Discovery);
        app.Map("/oauth2/{**rest}", Relay);
        app.Map("/.well-known/jwks.json", Relay);
        app.Map("/userinfo", Relay);
    }

    private static async Task Authorize(HttpContext context, UrlClientRegistry registry, IHttpClientFactory http, CancellationToken ct)
    {
        string? clientId, redirectUri;
        if (HttpMethods.IsPost(context.Request.Method))
        {
            context.Request.EnableBuffering();
            var form = context.Request.HasFormContentType ? await context.Request.ReadFormAsync(ct) : FormCollection.Empty;
            context.Request.Body.Position = 0;
            (clientId, redirectUri) = (form["client_id"], form["redirect_uri"]);
        }
        else
        {
            (clientId, redirectUri) = (context.Request.Query["client_id"], context.Request.Query["redirect_uri"]);
        }

        if (UrlClient.TryParse(clientId, out var client))
        {
            await registry.EnsureRegisteredAsync(client!, string.IsNullOrEmpty(redirectUri) ? null : redirectUri, ct);
        }
        await RelayAsync(context, http, rewrite: null, ct);
    }

    private static Task Discovery(HttpContext context, IHttpClientFactory http, CancellationToken ct) =>
        RelayAsync(context, http, static (upstream, response, ct) => WriteDiscoveryAsync(upstream, response, ct), ct);

    /// <summary>Hydra's discovery document with the one member it cannot add.</summary>
    private static async Task WriteDiscoveryAsync(HttpContent upstream, HttpResponse response, CancellationToken ct)
    {
        var discovery = await JsonNode.ParseAsync(await upstream.ReadAsStreamAsync(ct), cancellationToken: ct);
        if (discovery is JsonObject document)
        {
            document["client_id_metadata_document_supported"] = true;
        }
        await using var writer = new Utf8JsonWriter(response.BodyWriter);
        (discovery ?? new JsonObject()).WriteTo(writer);
    }

    private static Task Relay(HttpContext context, IHttpClientFactory http, CancellationToken ct) =>
        RelayAsync(context, http, rewrite: null, ct);

    private static readonly HashSet<string> NotForwarded = new(StringComparer.OrdinalIgnoreCase)
    {
        "Host", "Connection", "Keep-Alive", "Transfer-Encoding", "Upgrade", "Proxy-Connection", "Proxy-Authorization", "TE", "Trailer",
        "X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host", "Forwarded",
    };

    private static async Task RelayAsync(HttpContext context, IHttpClientFactory httpClientFactory, Func<HttpContent, HttpResponse, CancellationToken, Task>? rewrite, CancellationToken ct)
    {
        var request = context.Request;
        using var upstream = new HttpRequestMessage(HttpMethod.Parse(request.Method), request.Path + request.QueryString);
        if (request.ContentLength > 0 || request.Headers.ContainsKey("Transfer-Encoding"))
        {
            upstream.Content = new StreamContent(request.Body);
        }
        foreach (var header in request.Headers)
        {
            if (NotForwarded.Contains(header.Key)) continue;
            IEnumerable<string> values = header.Value!;
            if (!upstream.Headers.TryAddWithoutValidation(header.Key, values))
            {
                upstream.Content?.Headers.TryAddWithoutValidation(header.Key, values);
            }
        }
        // What Hydra is told about the outside of this request: the scheme and address this app
        // saw, after its own forwarded-header trust. Hydra believes these from the oidc network.
        upstream.Headers.TryAddWithoutValidation("X-Forwarded-Proto", request.Scheme);
        upstream.Headers.TryAddWithoutValidation("X-Forwarded-Host", request.Host.Value);
        if (context.Connection.RemoteIpAddress != null)
        {
            upstream.Headers.TryAddWithoutValidation("X-Forwarded-For", context.Connection.RemoteIpAddress.ToString());
        }

        using var http = httpClientFactory.CreateClient(HttpClientName);
        using var response = await http.SendAsync(upstream, HttpCompletionOption.ResponseHeadersRead, ct);

        context.Response.StatusCode = (int)response.StatusCode;
        // Raw values, unparsed: a relay has no business validating Hydra's headers.
        foreach (var header in response.Headers.NonValidated.Concat(response.Content.Headers.NonValidated))
        {
            if (NotForwarded.Contains(header.Key) || (rewrite != null && header.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))) continue;
            context.Response.Headers[header.Key] = header.Value.Count == 1 ? header.Value.ToString() : header.Value.ToArray();
        }
        if (rewrite != null)
        {
            await rewrite(response.Content, context.Response, ct);
        }
        else
        {
            await response.Content.CopyToAsync(context.Response.Body, ct);
        }
    }
}
