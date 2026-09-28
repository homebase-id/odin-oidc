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
        var client = new { client_id = "rp", client_name = "Demo relying party", skip_consent = ClientSkipConsent };

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
