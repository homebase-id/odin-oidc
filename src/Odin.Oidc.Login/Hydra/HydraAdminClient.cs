using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Odin.Oidc.Login.Hydra;

/// <summary>
/// The admin calls of Hydra's login, consent and logout flows this app makes, over a typed
/// HttpClient whose base address is the admin API (port 4445; never exposed). Contract: GET the
/// request by its challenge, PUT accept or reject, send the browser to the <c>redirect_to</c> that
/// comes back. Any call about a challenge already answered is HTTP 410. Also the client
/// registrations this app makes for URL clients (Registration/UrlClientRegistry.cs).
/// </summary>
public sealed class HydraAdminClient(HttpClient http)
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public Task<HydraLoginRequest> GetLoginRequestAsync(string challenge, CancellationToken ct) =>
        GetAsync<HydraLoginRequest>(Url("login", "", challenge), ct);

    public Task<string> AcceptLoginAsync(string challenge, HydraAcceptLogin accept, CancellationToken ct) =>
        PutAsync(Url("login", "/accept", challenge), accept, ct);

    public Task<string> RejectLoginAsync(string challenge, HydraReject reject, CancellationToken ct) =>
        PutAsync(Url("login", "/reject", challenge), reject, ct);

    public Task<HydraConsentRequest> GetConsentRequestAsync(string challenge, CancellationToken ct) =>
        GetAsync<HydraConsentRequest>(Url("consent", "", challenge), ct);

    public Task<string> AcceptConsentAsync(string challenge, HydraAcceptConsent accept, CancellationToken ct) =>
        PutAsync(Url("consent", "/accept", challenge), accept, ct);

    public Task<string> RejectConsentAsync(string challenge, HydraReject reject, CancellationToken ct) =>
        PutAsync(Url("consent", "/reject", challenge), reject, ct);

    public Task<string> AcceptLogoutAsync(string challenge, CancellationToken ct) =>
        PutAsync(Url("logout", "/accept", challenge), new { }, ct);

    /// <summary>The client by its id, or null when Hydra has none.</summary>
    public async Task<HydraClient?> GetClientAsync(string clientId, CancellationToken ct)
    {
        using var response = await http.GetAsync(ClientUrl(clientId), ct);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }
        return Parse<HydraClient>(await AnsweredAsync(response, ClientUrl(clientId), ct), ClientUrl(clientId));
    }

    /// <summary>Creates the client; one created meanwhile by another instance (409) is as good.</summary>
    public async Task CreateClientAsync(HydraClient client, CancellationToken ct)
    {
        using var response = await http.PostAsJsonAsync("admin/clients", client, Json, ct);
        if (response.StatusCode != HttpStatusCode.Conflict)
        {
            await AnsweredAsync(response, "admin/clients", ct);
        }
    }

    public async Task UpdateClientAsync(HydraClient client, CancellationToken ct)
    {
        using var response = await http.PutAsJsonAsync(ClientUrl(client.ClientId!), client, Json, ct);
        await AnsweredAsync(response, ClientUrl(client.ClientId!), ct);
    }

    /// <summary>Hydra's own readiness (database reachable, migrations applied), for this app's health answer.</summary>
    public async Task<bool> IsReadyAsync(CancellationToken ct)
    {
        try
        {
            using var response = await http.GetAsync("health/ready", ct);
            return response.IsSuccessStatusCode;
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException)
        {
            return false;
        }
    }

    //

    private static string ClientUrl(string clientId) => $"admin/clients/{Uri.EscapeDataString(clientId)}";

    private static string Url(string flow, string action, string challenge) =>
        $"admin/oauth2/auth/requests/{flow}{action}?{flow}_challenge={Uri.EscapeDataString(challenge)}";

    private async Task<T> GetAsync<T>(string url, CancellationToken ct)
    {
        using var response = await http.GetAsync(url, ct);
        return Parse<T>(await AnsweredAsync(response, url, ct), url);
    }

    /// <summary>Accept or reject; returns where to send the browser.</summary>
    private async Task<string> PutAsync<T>(string url, T payload, CancellationToken ct)
    {
        using var response = await http.PutAsJsonAsync(url, payload, Json, ct);
        return Parse<HydraRedirect>(await AnsweredAsync(response, url, ct), url).RedirectTo;
    }

    /// <summary>The body of a successful answer; 410 and failures become exceptions.</summary>
    private static async Task<string> AnsweredAsync(HttpResponseMessage response, string url, CancellationToken ct)
    {
        var body = await response.Content.ReadAsStringAsync(ct);
        if (response.StatusCode == HttpStatusCode.Gone)
        {
            throw new HydraAlreadyAnsweredException();
        }
        if (!response.IsSuccessStatusCode)
        {
            var error = TryParse<HydraError>(body);
            var detail = error?.Error != null ? $"{error.Error}: {error.ErrorDescription}" : body;
            throw new HydraException($"Hydra answered {response.RequestMessage?.Method} {url} with {(int)response.StatusCode}: {detail}");
        }
        return body;
    }

    private static T Parse<T>(string body, string url) =>
        TryParse<T>(body) ?? throw new HydraException($"Hydra answered {url} with an empty body");

    private static T? TryParse<T>(string body)
    {
        try
        {
            return JsonSerializer.Deserialize<T>(body, Json);
        }
        catch (JsonException)
        {
            return default;
        }
    }

    private sealed class HydraError
    {
        public string? Error { get; set; }
        public string? ErrorDescription { get; set; }
    }
}
