using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;
using Odin.Oidc.Login.Flow;
using Odin.Oidc.Login.Options;

namespace Odin.Oidc.Login.Registration;

/// <summary>
/// Hydra's public API through this app. The authorize endpoint is the gateway: a URL client is
/// registered from its document before the request goes on; anything else passes through
/// untouched. Discovery is Hydra's with the authorize endpoint pointed here and the draft's member
/// added. The rest (token, userinfo, JWKS, revocation, logout) is relayed as is, so a deployment
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

    private static async Task Authorize(HttpContext context, UrlClientRegistry registry, IHttpClientFactory http, IOptions<BrokerOptions> options, CancellationToken ct)
    {
        IEnumerable<KeyValuePair<string, Microsoft.Extensions.Primitives.StringValues>> parameters;
        if (HttpMethods.IsPost(context.Request.Method))
        {
            context.Request.EnableBuffering();
            parameters = context.Request.HasFormContentType ? await context.Request.ReadFormAsync(ct) : [];
            context.Request.Body.Position = 0;
        }
        else
        {
            parameters = context.Request.Query;
        }
        var clientId = parameters.FirstOrDefault(p => p.Key == "client_id").Value.ToString();
        var redirectUri = parameters.FirstOrDefault(p => p.Key == "redirect_uri").Value.ToString();

        if (UrlClient.TryParse(clientId, out var client))
        {
            await registry.EnsureRegisteredAsync(client!, string.IsNullOrEmpty(redirectUri) ? null : redirectUri, ct);
        }
        else if (UrlClient.TryParseLocalhost(clientId, out client))
        {
            if (!options.Value.AllowLocalhostClients)
            {
                throw new SignInStoppedException("The client id http://localhost is for development brokers only.");
            }
            await registry.EnsureRegisteredAsync(client!, string.IsNullOrEmpty(redirectUri) ? null : redirectUri, ct);
        }

        await RelayAsync(context, http, rewrite: null, ct);
    }

    private static Task Discovery(HttpContext context, IHttpClientFactory http, IOptions<BrokerOptions> options, CancellationToken ct) =>
        RelayAsync(context, http, body =>
        {
            if (JsonNode.Parse(body) is not JsonObject discovery)
            {
                return body;
            }
            discovery["authorization_endpoint"] = $"{options.Value.PublicOrigin.TrimEnd('/')}/oauth2/auth";
            discovery["client_id_metadata_document_supported"] = true;
            return discovery.ToJsonString();
        }, ct);

    private static Task Relay(HttpContext context, IHttpClientFactory http, CancellationToken ct) =>
        RelayAsync(context, http, rewrite: null, ct);

    private static readonly HashSet<string> NotForwarded = new(StringComparer.OrdinalIgnoreCase)
    {
        "Host", "Connection", "Keep-Alive", "Transfer-Encoding", "Upgrade", "Proxy-Connection", "Proxy-Authorization", "TE", "Trailer",
        "X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host", "Forwarded",
    };

    private static async Task RelayAsync(HttpContext context, IHttpClientFactory httpClientFactory, Func<string, string>? rewrite, CancellationToken ct)
    {
        var request = context.Request;
        using var upstream = new HttpRequestMessage(new HttpMethod(request.Method), request.Path + request.QueryString);
        if (request.ContentLength > 0 || request.Headers.ContainsKey("Transfer-Encoding"))
        {
            upstream.Content = new StreamContent(request.Body);
        }
        foreach (var header in request.Headers)
        {
            if (NotForwarded.Contains(header.Key)) continue;
            if (!upstream.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray()))
            {
                upstream.Content?.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
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
        foreach (var header in response.Headers.Concat(response.Content.Headers))
        {
            if (NotForwarded.Contains(header.Key) || (rewrite != null && header.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))) continue;
            context.Response.Headers[header.Key] = header.Value.ToArray();
        }
        if (rewrite != null)
        {
            await context.Response.WriteAsync(rewrite(await response.Content.ReadAsStringAsync(ct)), ct);
        }
        else
        {
            await response.Content.CopyToAsync(context.Response.Body, ct);
        }
    }
}
