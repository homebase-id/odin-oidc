using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Odin.Core;
using Odin.Core.Cryptography.Data;
using Odin.Oidc.Login.Options;

namespace Odin.Oidc.Login.YouAuth;

/// <summary>The relying party's half of one login: what must survive from [030] to [090]. Lives in the flow cookie.</summary>
public sealed record YouAuthFlowKeys(string PasswordBase64, string KeyPairJson);

/// <summary>
/// This app as a YouAuth domain client: starts the flow at the identity, exchanges the callback for
/// the token, and releases the registration the token stands for, because the token's only use here
/// is having proven the identity.
/// </summary>
public sealed class YouAuthClient(IHttpClientFactory httpClientFactory, IOptions<BrokerOptions> options, ILogger<YouAuthClient> logger)
{
    public const string HttpClientName = "youauth";

    /// <summary>The client access token on the wire: 16-byte id, 16-byte half key, 1-byte type.</summary>
    private const int ClientAuthTokenLength = 33;

    /// <summary>YouAuth [010] and [030]: an ephemeral key pair, and the authorize URL to send the browser to.</summary>
    public (Uri authorizeUrl, YouAuthFlowKeys keys) Begin(string identity, string state)
    {
        var broker = options.Value;
        var password = RandomNumberGenerator.GetBytes(16);
        var keyPair = new EccFullKeyData(new SensitiveByteArray(password), EccKeySize.P384, hours: 1);

        var request = new YouAuthAuthorizeRequest
        {
            ClientId = broker.PublicHost,
            ClientType = YouAuthWire.ClientTypeDomain,
            RedirectUri = broker.CallbackUri,
            PublicKey = keyPair.PublicKeyJwkBase64Url(),
            State = state,
            Cipher = YouAuthWire.CipherAesGcm,
        };

        var url = new Uri($"https://{identity}{YouAuthWire.AuthorizePath}{request.ToQueryString()}");
        var keys = new YouAuthFlowKeys(Convert.ToBase64String(password), JsonSerializer.Serialize(keyPair));
        return (url, keys);
    }

    /// <summary>YouAuth [090] to [150]: the exchange secret, the token endpoint, and the opened client access token (33 bytes).</summary>
    public async Task<byte[]> CompleteAsync(string identity, YouAuthFlowKeys keys, string identityPublicKeyJwk, string saltBase64, CancellationToken ct)
    {
        // [090] The same secret the identity derived at [070]: ECDH over P-384, HKDF with the salt.
        var password = new SensitiveByteArray(Convert.FromBase64String(keys.PasswordBase64));
        var keyPair = JsonSerializer.Deserialize<EccFullKeyData>(keys.KeyPairJson)
                      ?? throw new YouAuthException("The flow's key pair did not survive the round trip");
        var identityPublicKey = EccPublicKeyData.FromJwkBase64UrlPublicKey(identityPublicKeyJwk);
        var exchangeSecret = keyPair.GetEcdhSharedSecret(password, identityPublicKey, Convert.FromBase64String(saltBase64));
        var digest = Convert.ToBase64String(SHA256.HashData(exchangeSecret.GetKey()));

        // [100] to [140]
        using var http = httpClientFactory.CreateClient(HttpClientName);
        using var response = await http.PostAsJsonAsync($"https://{identity}{YouAuthWire.TokenPath}", new YouAuthTokenRequest { SecretDigest = digest }, ct);
        if (!response.IsSuccessStatusCode)
        {
            throw new YouAuthException($"{identity} answered the token exchange with {(int)response.StatusCode}");
        }
        var token = await response.Content.ReadFromJsonAsync<YouAuthTokenResponse>(ct)
                    ?? throw new YouAuthException($"{identity} answered the token exchange with an empty body");

        // [150] The proof. The shared secret is not opened: this app makes no calls with the token.
        if (token.Cipher != YouAuthWire.CipherAesGcm)
        {
            var sealedWith = string.IsNullOrEmpty(token.Cipher) ? "absent, which is aes-cbc" : token.Cipher;
            if (options.Value.RequireAesGcm)
            {
                throw new YouAuthException($"{identity} sealed the token with {sealedWith}; this app requires aes-gcm");
            }
            logger.LogWarning("YouAuth: {identity} sealed the token with cipher={cipher}; aes-gcm was asked for", identity, sealedWith);
        }

        byte[] clientAuthToken;
        try
        {
            clientAuthToken = YouAuthCipher.Open(token.Cipher,
                Convert.FromBase64String(token.Base64ClientAuthTokenCipher ?? ""),
                exchangeSecret,
                Convert.FromBase64String(token.Base64ClientAuthTokenIv ?? ""));
        }
        catch (Exception e) when (e is CryptographicException or ArgumentException or FormatException)
        {
            throw new YouAuthException($"Could not open the token {identity} sent", e);
        }

        if (clientAuthToken.Length != ClientAuthTokenLength)
        {
            throw new YouAuthException($"The token {identity} sent is {clientAuthToken.Length} bytes, not {ClientAuthTokenLength}");
        }
        return clientAuthToken;
    }

    /// <summary>Deletes the registration at the identity. Best effort: the identity is already proven.</summary>
    public async Task ReleaseAsync(string identity, byte[] clientAuthToken, CancellationToken ct)
    {
        try
        {
            using var http = httpClientFactory.CreateClient(HttpClientName);
            using var request = new HttpRequestMessage(HttpMethod.Post, $"https://{identity}{YouAuthWire.LogoutPath}");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Convert.ToBase64String(clientAuthToken));
            using var response = await http.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode)
            {
                logger.LogWarning("YouAuth: {identity} answered the release of this login's registration with {status}; it expires on its own", identity, (int)response.StatusCode);
            }
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException)
        {
            logger.LogWarning(e, "YouAuth: could not release this login's registration at {identity}; it expires on its own", identity);
        }
    }
}
