using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Odin.Oidc.Login.Flow;
using Odin.Oidc.Login.Options;
using Odin.Oidc.Login.Registration;

namespace Odin.Oidc.Login.Try;

/// <summary>
/// This app as a relying party of itself, so anyone can see a sign-in work end to end without
/// registering anything: a URL client whose document is at /try/client.json, PKCE, no secret. It
/// goes through the public origin like any other site would, so the first sign-in fetches the
/// document over the internet and registers the client. The tokens come straight from Hydra on
/// the private network in exchange for the code, so the id_token's claims are shown without a
/// signature check; a real relying party verifies them against the JWKS.
/// </summary>
public sealed class TryRelyingParty(IHttpClientFactory httpClientFactory, IOptions<BrokerOptions> options)
{
    public const string Name = "Try it";
    public const string Scope = "openid profile";

    public static string ClientId(BrokerOptions broker) => $"{broker.PublicOrigin.TrimEnd('/')}/try/client.json";
    public static string CallbackUri(BrokerOptions broker) => $"{broker.PublicOrigin.TrimEnd('/')}/try/callback";

    /// <summary>The client document, as any site would publish it.</summary>
    public static object Document(BrokerOptions broker) => new
    {
        client_id = ClientId(broker),
        client_name = Name,
        redirect_uris = new[] { CallbackUri(broker) },
        token_endpoint_auth_method = "none",
        grant_types = new[] { "authorization_code" },
        response_types = new[] { "code" },
        scope = Scope,
    };

    /// <summary>A fresh flow and the authorize URL that starts it.</summary>
    public (TryFlowState state, string authorizeUrl) Begin()
    {
        var broker = options.Value;
        var verifier = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        var state = new TryFlowState(
            WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(16)),
            verifier,
            WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(16)));
        var url = QueryHelpers.AddQueryString($"{broker.PublicOrigin.TrimEnd('/')}/oauth2/auth", new Dictionary<string, string?>
        {
            ["client_id"] = ClientId(broker),
            ["redirect_uri"] = CallbackUri(broker),
            ["response_type"] = "code",
            ["scope"] = Scope,
            ["state"] = state.State,
            ["nonce"] = state.Nonce,
            ["code_challenge"] = WebEncoders.Base64UrlEncode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))),
            ["code_challenge_method"] = "S256",
        });
        return (state, url);
    }

    /// <summary>The code for the tokens, then userinfo: the id_token's claims and userinfo's answer.</summary>
    public async Task<TryResult> CompleteAsync(string code, TryFlowState flow, string scheme, CancellationToken ct)
    {
        var broker = options.Value;
        using var http = httpClientFactory.CreateClient(HydraRelay.HttpClientName);
        // Hydra behind TLS termination believes it is spoken to over https only when told so from the oidc network.
        http.DefaultRequestHeaders.TryAddWithoutValidation("X-Forwarded-Proto", scheme);

        using var tokenResponse = await http.PostAsync("oauth2/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = CallbackUri(broker),
            ["client_id"] = ClientId(broker),
            ["code_verifier"] = flow.Verifier,
        }), ct);
        var tokenBody = await tokenResponse.Content.ReadAsStringAsync(ct);
        if (!tokenResponse.IsSuccessStatusCode)
        {
            throw new SignInStoppedException($"The token endpoint answered {(int)tokenResponse.StatusCode}: {Detail(tokenBody)}");
        }
        using var tokens = JsonDocument.Parse(tokenBody);
        var idToken = tokens.RootElement.TryGetProperty("id_token", out var t) ? t.GetString() : null;
        var accessToken = tokens.RootElement.TryGetProperty("access_token", out var a) ? a.GetString() : null;
        if (idToken == null || accessToken == null)
        {
            throw new SignInStoppedException("The token endpoint answered without an id_token.");
        }

        var claims = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(WebEncoders.Base64UrlDecode(idToken.Split('.')[1])) ?? [];
        if (!claims.TryGetValue("nonce", out var nonce) || nonce.GetString() != flow.Nonce)
        {
            throw new SignInStoppedException("The id_token's nonce is not this flow's.");
        }

        using var userinfoRequest = new HttpRequestMessage(HttpMethod.Get, "userinfo") { Headers = { Authorization = new AuthenticationHeaderValue("Bearer", accessToken) } };
        using var userinfoResponse = await http.SendAsync(userinfoRequest, ct);
        var userinfo = await userinfoResponse.Content.ReadAsStringAsync(ct);

        return new TryResult(claims, userinfoResponse.IsSuccessStatusCode ? userinfo : $"userinfo answered {(int)userinfoResponse.StatusCode}");
    }

    private static string Detail(string body)
    {
        try
        {
            using var json = JsonDocument.Parse(body);
            return json.RootElement.TryGetProperty("error_description", out var d) ? d.GetString() ?? body : body;
        }
        catch (JsonException)
        {
            return body;
        }
    }
}

public sealed record TryResult(Dictionary<string, JsonElement> IdTokenClaims, string Userinfo)
{
    public string Subject => IdTokenClaims.TryGetValue("sub", out var sub) ? sub.GetString() ?? "" : "";
}
