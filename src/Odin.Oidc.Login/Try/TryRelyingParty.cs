using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Odin.Oidc.Login.Flow;
using Odin.Oidc.Login.Options;

namespace Odin.Oidc.Login.Try;

/// <summary>
/// This app as a relying party of itself, so anyone can see a sign-in work end to end without
/// registering anything: a URL client whose document is at /try/client.json, PKCE, no secret.
/// Every request goes to the public origin like any other site's would, so one sign-in proves
/// the gateway, the document fetch, the proxy's routes for the token endpoint and userinfo, and
/// the exchange itself. The id_token's claims are shown without a signature check: they came in
/// the token endpoint's direct answer over this app's own TLS origin, and the nonce is checked,
/// which OpenID Connect allows in place of the signature; a site with a library verifies against
/// the JWKS as well.
/// </summary>
public sealed class TryRelyingParty(IHttpClientFactory httpClientFactory, IOptions<BrokerOptions> options)
{
    public const string HttpClientName = "try-relying-party";
    public const string Name = "Try it";
    public const string Scope = "openid profile";
    public const string DocumentPath = "/try/client.json";
    public const string CallbackPath = "/try/callback";

    public string ClientId => options.Value.Url(DocumentPath);
    public string CallbackUri => options.Value.Url(CallbackPath);

    /// <summary>The client document, as any site would publish it.</summary>
    public object Document => new
    {
        client_id = ClientId,
        client_name = Name,
        redirect_uris = new[] { CallbackUri },
        token_endpoint_auth_method = "none",
        grant_types = new[] { "authorization_code" },
        response_types = new[] { "code" },
        scope = Scope,
    };

    /// <summary>A fresh flow and the authorize URL that starts it.</summary>
    public (TryFlowState state, string authorizeUrl) Begin()
    {
        var verifier = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        var state = new TryFlowState(
            WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(16)),
            verifier,
            WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(16)));
        var url = QueryHelpers.AddQueryString(options.Value.Url("/oauth2/auth"), new Dictionary<string, string?>
        {
            ["client_id"] = ClientId,
            ["redirect_uri"] = CallbackUri,
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
    public async Task<TryResult> CompleteAsync(string code, TryFlowState flow, CancellationToken ct)
    {
        using var http = httpClientFactory.CreateClient(HttpClientName);

        using var tokenResponse = await http.PostAsync(options.Value.Url("/oauth2/token"), new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = CallbackUri,
            ["client_id"] = ClientId,
            ["code_verifier"] = flow.Verifier,
        }), ct);
        var tokenBody = await tokenResponse.Content.ReadAsStringAsync(ct);
        if (!tokenResponse.IsSuccessStatusCode)
        {
            throw new SignInStoppedException($"The token endpoint answered {(int)tokenResponse.StatusCode}: {OAuthError.Describe(tokenBody)}");
        }
        var tokens = JsonSerializer.Deserialize<TokenResponse>(tokenBody);
        if (tokens is not { IdToken: { Length: > 0 } idToken, AccessToken: { Length: > 0 } accessToken })
        {
            throw new SignInStoppedException("The token endpoint answered without an id_token and an access_token.");
        }

        var claims = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(WebEncoders.Base64UrlDecode(idToken.Split('.')[1])) ?? [];
        if (!claims.TryGetValue("nonce", out var nonce) || nonce.GetString() != flow.Nonce)
        {
            throw new SignInStoppedException("The id_token's nonce is not this flow's.");
        }

        using var userinfoRequest = new HttpRequestMessage(HttpMethod.Get, options.Value.Url("/userinfo")) { Headers = { Authorization = new AuthenticationHeaderValue("Bearer", accessToken) } };
        using var userinfoResponse = await http.SendAsync(userinfoRequest, ct);
        var userinfo = await userinfoResponse.Content.ReadAsStringAsync(ct);

        return new TryResult(claims, userinfoResponse.IsSuccessStatusCode ? userinfo : $"userinfo answered {(int)userinfoResponse.StatusCode}");
    }

    private sealed record TokenResponse(
        [property: JsonPropertyName("id_token")] string? IdToken,
        [property: JsonPropertyName("access_token")] string? AccessToken);
}

public sealed record TryResult(Dictionary<string, JsonElement> IdTokenClaims, string Userinfo)
{
    public string Subject => IdTokenClaims.TryGetValue("sub", out var sub) ? sub.GetString() ?? "" : "";
}
