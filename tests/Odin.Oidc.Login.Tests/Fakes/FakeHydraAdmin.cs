using System.Net;
using System.Text.Json;

namespace Odin.Oidc.Login.Tests.Fakes;

/// <summary>
/// Hydra's admin API as the login app sees it: GET a request by challenge, PUT accept or reject,
/// answer with redirect_to. Records what was accepted or rejected so a test can assert on it.
/// </summary>
public sealed class FakeHydraAdmin
{
    public const string RedirectTo = "http://127.0.0.1:14444/oauth2/auth?after=challenge";

    public bool LoginSkip { get; set; }
    public string? LoginHint { get; set; }
    public string Subject { get; set; } = BrokerApp.Frodo;
    public List<string> RequestedScope { get; set; } = ["openid", "offline"];
    public bool ConsentSkip { get; set; }
    public bool ClientSkipConsent { get; set; }
    /// <summary>Answer every login call with this status instead: 410 (already answered) or 404 (no such challenge).</summary>
    public HttpStatusCode? LoginAnswer { get; set; }
    /// <summary>What /health/ready on the admin API says.</summary>
    public bool Ready { get; set; } = true;
    /// <summary>The client the login and consent requests name, as Hydra returns it.</summary>
    public string ClientId { get; set; } = "rp";
    public string? ClientName { get; set; } = "Demo relying party";
    public List<string> ClientRedirectUris { get; set; } = ["https://app.example/cb"];
    /// <summary>The authorize request that started the flow, as Hydra reports it.</summary>
    public string RequestUrl { get; set; } = RequestUrlFor("rp", "https://app.example/cb");

    public static string RequestUrlFor(string clientId, string redirectUri) =>
        $"http://hydra:4444/oauth2/auth?client_id={Uri.EscapeDataString(clientId)}&redirect_uri={Uri.EscapeDataString(redirectUri)}&response_type=code";

    /// <summary>Clients as the admin API stores them (JSON bodies), by id.</summary>
    public Dictionary<string, string> Clients { get; } = new();
    public List<string> ClientCreates { get; } = [];
    public List<string> ClientUpdates { get; } = [];
    /// <summary>Authorize requests the public API received (path and query).</summary>
    public List<string> PublicAuthorizes { get; } = [];
    /// <summary>Token requests the public API received (form bodies); each is answered with an unsigned id_token for <see cref="Subject"/> carrying the last authorize's nonce.</summary>
    public List<string> TokenRequests { get; } = [];
    public List<string?> UserinfoBearers { get; } = [];
    public const string PublicCookie = "ory_hydra_login_csrf_dev=abc123; Path=/; HttpOnly; SameSite=Lax";

    public List<(string challenge, string body)> LoginAccepts { get; } = [];
    public List<(string challenge, string body)> LoginRejects { get; } = [];
    public List<(string challenge, string body)> ConsentAccepts { get; } = [];
    public List<(string challenge, string body)> ConsentRejects { get; } = [];
    public List<(string challenge, string body)> LogoutAccepts { get; } = [];

    public RecordingHandler Handler { get; }

    public FakeHydraAdmin()
    {
        Handler = new RecordingHandler(Respond);
    }

    private Task<HttpResponseMessage> Respond(HttpRequestMessage request, string? body)
    {
        var path = request.RequestUri!.AbsolutePath;
        var query = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(request.RequestUri.Query);
        var challenge = query.TryGetValue("login_challenge", out var lc) ? lc.ToString()
            : query.TryGetValue("consent_challenge", out var cc) ? cc.ToString()
            : query.TryGetValue("logout_challenge", out var xc) ? xc.ToString() : "";

        HttpResponseMessage Redirect() => RecordingHandler.Json(HttpStatusCode.OK, JsonSerializer.Serialize(new { redirect_to = RedirectTo }));
        var client = new { client_id = ClientId, client_name = ClientName, skip_consent = ClientSkipConsent, redirect_uris = ClientRedirectUris };

        // The admin API's clients, and the public API's authorize and discovery.
        if (path == "/admin/clients" && request.Method == HttpMethod.Post)
        {
            var id = JsonDocument.Parse(body!).RootElement.GetProperty("client_id").GetString()!;
            Clients[id] = body!;
            ClientCreates.Add(body!);
            return Task.FromResult(RecordingHandler.Json(HttpStatusCode.Created, body!));
        }
        if (path.StartsWith("/admin/clients/"))
        {
            var id = Uri.UnescapeDataString(path["/admin/clients/".Length..]);
            if (request.Method == HttpMethod.Get)
            {
                return Task.FromResult(Clients.TryGetValue(id, out var stored)
                    ? RecordingHandler.Json(HttpStatusCode.OK, stored)
                    : RecordingHandler.Json(HttpStatusCode.NotFound, """{"error":"Not Found"}"""));
            }
            if (request.Method == HttpMethod.Put)
            {
                Clients[id] = body!;
                ClientUpdates.Add(body!);
                return Task.FromResult(RecordingHandler.Json(HttpStatusCode.OK, body!));
            }
        }
        if (path == "/oauth2/auth")
        {
            PublicAuthorizes.Add(request.RequestUri.PathAndQuery);
            var response = new HttpResponseMessage(HttpStatusCode.Found);
            response.Headers.Location = new Uri(RedirectTo);
            response.Headers.TryAddWithoutValidation("Set-Cookie", PublicCookie);
            return Task.FromResult(response);
        }
        if (path == "/oauth2/token" && request.Method == HttpMethod.Post)
        {
            TokenRequests.Add(body!);
            var lastAuthorize = PublicAuthorizes.LastOrDefault() ?? "";
            var nonce = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(new Uri("http://x" + lastAuthorize).Query).TryGetValue("nonce", out var n) ? n.ToString() : "";
            var payload = Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(System.Text.Encoding.UTF8.GetBytes(
                JsonSerializer.Serialize(new { iss = "http://hydra:4444/", sub = Subject, nonce, did = $"did:web:{Subject}", name = "Frodo Baggins" })));
            return Task.FromResult(RecordingHandler.Json(HttpStatusCode.OK, JsonSerializer.Serialize(new
            {
                access_token = "at-1", token_type = "bearer", expires_in = 3600, id_token = $"e30.{payload}.sig",
            })));
        }
        if (path == "/userinfo")
        {
            UserinfoBearers.Add(request.Headers.Authorization?.Parameter);
            return Task.FromResult(RecordingHandler.Json(HttpStatusCode.OK, JsonSerializer.Serialize(new { sub = Subject, name = "Frodo Baggins" })));
        }
        if (path == "/.well-known/openid-configuration")
        {
            return Task.FromResult(RecordingHandler.Json(HttpStatusCode.OK, JsonSerializer.Serialize(new
            {
                issuer = "http://hydra:4444/",
                authorization_endpoint = "http://hydra:4444/oauth2/auth",
                token_endpoint = "http://hydra:4444/oauth2/token",
                jwks_uri = "http://hydra:4444/.well-known/jwks.json",
            })));
        }

        if (LoginAnswer is { } status && path.StartsWith("/admin/oauth2/auth/requests/login"))
        {
            return Task.FromResult(RecordingHandler.Json(status, JsonSerializer.Serialize(new { error = status.ToString(), redirect_to = RedirectTo })));
        }

        switch (request.Method.Method, path)
        {
            case ("GET", "/health/ready"):
                return Task.FromResult(RecordingHandler.Json(Ready ? HttpStatusCode.OK : HttpStatusCode.ServiceUnavailable, Ready ? """{"status":"ok"}""" : """{"errors":{"database":"down"}}"""));
            case ("GET", "/admin/oauth2/auth/requests/login"):
                return Task.FromResult(RecordingHandler.Json(HttpStatusCode.OK, JsonSerializer.Serialize(new
                {
                    challenge, skip = LoginSkip, subject = LoginSkip ? Subject : "", client,
                    requested_scope = RequestedScope,
                    oidc_context = new { login_hint = LoginHint },
                    request_url = RequestUrl,
                })));
            case ("PUT", "/admin/oauth2/auth/requests/login/accept"):
                LoginAccepts.Add((challenge, body!));
                return Task.FromResult(Redirect());
            case ("PUT", "/admin/oauth2/auth/requests/login/reject"):
                LoginRejects.Add((challenge, body!));
                return Task.FromResult(Redirect());
            case ("GET", "/admin/oauth2/auth/requests/consent"):
                return Task.FromResult(RecordingHandler.Json(HttpStatusCode.OK, JsonSerializer.Serialize(new
                {
                    challenge, skip = ConsentSkip, subject = Subject, client,
                    requested_scope = RequestedScope,
                    requested_access_token_audience = Array.Empty<string>(),
                    request_url = RequestUrl,
                })));
            case ("PUT", "/admin/oauth2/auth/requests/consent/accept"):
                ConsentAccepts.Add((challenge, body!));
                return Task.FromResult(Redirect());
            case ("PUT", "/admin/oauth2/auth/requests/consent/reject"):
                ConsentRejects.Add((challenge, body!));
                return Task.FromResult(Redirect());
            case ("PUT", "/admin/oauth2/auth/requests/logout/accept"):
                LogoutAccepts.Add((challenge, body ?? ""));
                return Task.FromResult(Redirect());
            default:
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new StringContent($"fake hydra: {request.Method} {path}") });
        }
    }

    public static string? Field(string json, string name) =>
        JsonDocument.Parse(json).RootElement.TryGetProperty(name, out var value) ? value.GetString() : null;
}
