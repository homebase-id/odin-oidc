using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Odin.Oidc.Login.Hydra;

/// <summary>
/// The admin calls of Hydra's login, consent and logout flows this app makes, over a typed
/// HttpClient whose base address is the admin API (port 4445; never exposed). Contract: GET the
/// request by its challenge, PUT accept or reject, send the browser to the <c>redirect_to</c> that
/// comes back. Any call about a challenge already answered is HTTP 410 with a <c>redirect_to</c>.
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

    public Task<HydraLogoutRequest> GetLogoutRequestAsync(string challenge, CancellationToken ct) =>
        GetAsync<HydraLogoutRequest>(Url("logout", "", challenge), ct);

    public Task<string> AcceptLogoutAsync(string challenge, CancellationToken ct) =>
        PutAsync(Url("logout", "/accept", challenge), new { }, ct);

    /// <summary>The one answer with nowhere to send the browser: the session stays, and the page says so.</summary>
    public async Task RejectLogoutAsync(string challenge, CancellationToken ct)
    {
        var url = Url("logout", "/reject", challenge);
        using var response = await http.PutAsJsonAsync(url, new { }, Json, ct);
        await ReadAsync<object>(response, url, ct, allowEmpty: true);
    }

    //

    private static string Url(string flow, string action, string challenge) =>
        $"admin/oauth2/auth/requests/{flow}{action}?{flow}_challenge={Uri.EscapeDataString(challenge)}";

    private async Task<T> GetAsync<T>(string url, CancellationToken ct)
    {
        using var response = await http.GetAsync(url, ct);
        return (await ReadAsync<T>(response, url, ct))!;
    }

    /// <summary>Accept or reject; returns where to send the browser.</summary>
    private async Task<string> PutAsync<T>(string url, T payload, CancellationToken ct)
    {
        using var response = await http.PutAsJsonAsync(url, payload, Json, ct);
        return (await ReadAsync<HydraRedirect>(response, url, ct))!.RedirectTo;
    }

    private static async Task<T?> ReadAsync<T>(HttpResponseMessage response, string url, CancellationToken ct, bool allowEmpty = false)
    {
        var body = await response.Content.ReadAsStringAsync(ct);
        if (response.StatusCode == HttpStatusCode.Gone)
        {
            var redirect = Deserialize<HydraRedirect>(body)?.RedirectTo;
            if (!string.IsNullOrEmpty(redirect))
            {
                throw new HydraAlreadyAnsweredException(redirect);
            }
        }
        if (!response.IsSuccessStatusCode)
        {
            var error = Deserialize<HydraError>(body);
            var detail = error?.Error != null ? $"{error.Error}: {error.ErrorDescription}" : body;
            throw new HydraException($"Hydra answered {response.RequestMessage?.Method} {url} with {(int)response.StatusCode}: {detail}");
        }
        if (allowEmpty && string.IsNullOrWhiteSpace(body))
        {
            return default;
        }
        return Deserialize<T>(body) ?? throw new HydraException($"Hydra answered {response.RequestMessage?.Method} {url} with an empty body");
    }

    private static T? Deserialize<T>(string body)
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
