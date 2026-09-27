using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Odin.Oidc.Login.Hydra;

/// <summary>
/// The eight admin calls of Hydra's login, consent and logout flows, over a typed HttpClient whose
/// base address is the admin API (port 4445; never exposed). Contract: GET the request by its
/// challenge, PUT accept or reject, send the browser to the <c>redirect_to</c> that comes back.
/// A challenge that was already answered is HTTP 410 with the same <c>redirect_to</c>.
/// </summary>
public sealed class HydraAdminClient(HttpClient http)
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private const string Requests = "admin/oauth2/auth/requests";

    public Task<HydraLoginRequest> GetLoginRequestAsync(string challenge, CancellationToken ct) =>
        GetAsync<HydraLoginRequest>($"{Requests}/login?login_challenge={Uri.EscapeDataString(challenge)}", ct);

    public Task<string> AcceptLoginAsync(string challenge, HydraAcceptLogin accept, CancellationToken ct) =>
        PutAsync($"{Requests}/login/accept?login_challenge={Uri.EscapeDataString(challenge)}", accept, ct);

    public Task<string> RejectLoginAsync(string challenge, HydraReject reject, CancellationToken ct) =>
        PutAsync($"{Requests}/login/reject?login_challenge={Uri.EscapeDataString(challenge)}", reject, ct);

    public Task<HydraConsentRequest> GetConsentRequestAsync(string challenge, CancellationToken ct) =>
        GetAsync<HydraConsentRequest>($"{Requests}/consent?consent_challenge={Uri.EscapeDataString(challenge)}", ct);

    public Task<string> AcceptConsentAsync(string challenge, HydraAcceptConsent accept, CancellationToken ct) =>
        PutAsync($"{Requests}/consent/accept?consent_challenge={Uri.EscapeDataString(challenge)}", accept, ct);

    public Task<string> RejectConsentAsync(string challenge, HydraReject reject, CancellationToken ct) =>
        PutAsync($"{Requests}/consent/reject?consent_challenge={Uri.EscapeDataString(challenge)}", reject, ct);

    public Task<HydraLogoutRequest> GetLogoutRequestAsync(string challenge, CancellationToken ct) =>
        GetAsync<HydraLogoutRequest>($"{Requests}/logout?logout_challenge={Uri.EscapeDataString(challenge)}", ct);

    public Task<string> AcceptLogoutAsync(string challenge, CancellationToken ct) =>
        PutAsync($"{Requests}/logout/accept?logout_challenge={Uri.EscapeDataString(challenge)}", new { }, ct);

    public Task<string> RejectLogoutAsync(string challenge, HydraReject reject, CancellationToken ct) =>
        PutAsync($"{Requests}/logout/reject?logout_challenge={Uri.EscapeDataString(challenge)}", reject, ct);

    //

    private async Task<T> GetAsync<T>(string pathAndQuery, CancellationToken ct)
    {
        using var response = await http.GetAsync(pathAndQuery, ct);
        var body = await response.Content.ReadAsStringAsync(ct);
        if (!response.IsSuccessStatusCode)
        {
            throw Failure(response, pathAndQuery, body);
        }
        return JsonSerializer.Deserialize<T>(body, Json) ?? throw new HydraException($"Hydra answered GET {pathAndQuery} with an empty body");
    }

    /// <summary>Accept or reject. Returns where to send the browser, also when the challenge was already answered (410).</summary>
    private async Task<string> PutAsync<T>(string pathAndQuery, T payload, CancellationToken ct)
    {
        using var response = await http.PutAsJsonAsync(pathAndQuery, payload, Json, ct);
        var body = await response.Content.ReadAsStringAsync(ct);
        if (response.IsSuccessStatusCode || response.StatusCode == HttpStatusCode.Gone)
        {
            var redirect = JsonSerializer.Deserialize<HydraRedirect>(body, Json)?.RedirectTo;
            if (!string.IsNullOrEmpty(redirect))
            {
                return redirect;
            }
        }
        throw Failure(response, pathAndQuery, body);
    }

    private static HydraException Failure(HttpResponseMessage response, string pathAndQuery, string body)
    {
        var detail = body;
        try
        {
            var error = JsonSerializer.Deserialize<HydraError>(body, Json);
            if (error?.Error != null)
            {
                detail = $"{error.Error}: {error.ErrorDescription}";
            }
        }
        catch (JsonException)
        {
            // not JSON; the raw body is the detail
        }
        return new HydraException($"Hydra answered {response.RequestMessage?.Method} {pathAndQuery} with {(int)response.StatusCode}: {detail}");
    }

    private sealed class HydraError
    {
        public string? Error { get; set; }
        public string? ErrorDescription { get; set; }
    }
}
