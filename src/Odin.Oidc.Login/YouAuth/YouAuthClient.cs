using System.Net.Http.Headers;
using System.Security.Cryptography;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Odin.Core;
using Odin.Core.Cryptography.Data;
using Odin.Oidc.Login.Options;

namespace Odin.Oidc.Login.YouAuth;

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

    /// <summary>
    /// The library holds a private key under a password; here the key travels only inside the
    /// encrypted flow cookie, so the password protects nothing and is a constant.
    /// </summary>
    private static readonly SensitiveByteArray KeyWrap = new(new byte[16]);

    /// <summary>
    /// YouAuth [010] and [030]: an ephemeral key pair and a random state, and the authorize URL to
    /// send the browser to. What comes back must survive to [090] in the flow cookie: the state to
    /// match, and the key as a private JWK, the library's small portable form of it.
    /// </summary>
    public (Uri authorizeUrl, string state, string privateKeyJwk) Begin(string identity)
    {
        var broker = options.Value;
        var keyPair = new EccFullKeyData(KeyWrap, EccKeySize.P384, hours: 1);
        var state = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));

        // The reference client's YouAuthAuthorizeRequest, for a domain client; the two empty members
        // are on the wire as it sends them.
        var query = new Dictionary<string, string?>
        {
            ["client_id"] = broker.PublicHost,
            ["client_type"] = "domain",
            ["client_info"] = "",
            ["redirect_uri"] = broker.CallbackUri,
            ["permission_request"] = "",
            ["public_key"] = keyPair.PublicKeyJwkBase64Url(),
            ["state"] = state,
            ["cipher"] = YouAuthWire.CipherAesGcm,
        };
        var url = new Uri(QueryHelpers.AddQueryString($"https://{identity}{YouAuthWire.AuthorizePath}", query));
        return (url, state, keyPair.PrivateKeyJwk(KeyWrap));
    }

    /// <summary>YouAuth [090] to [150]: the exchange secret, the token endpoint, and the opened client access token.</summary>
    public async Task<byte[]> CompleteAsync(string identity, string privateKeyJwk, string identityPublicKeyJwk, string saltBase64, CancellationToken ct)
    {
        // [090] The same secret the identity derived at [070]: ECDH over P-384, HKDF with the salt.
        var keyPair = EccFullKeyData.FromJwkPrivateKey(KeyWrap, privateKeyJwk);
        var identityPublicKey = EccPublicKeyData.FromJwkBase64UrlPublicKey(identityPublicKeyJwk);
        var exchangeSecret = keyPair.GetEcdhSharedSecret(KeyWrap, identityPublicKey, Convert.FromBase64String(saltBase64));
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

        // [150] The proof, sealed with what was asked for at [030]. An identity that seals with
        // anything else, or says nothing, predates the choice; there are none this app should meet.
        if (token.Cipher != YouAuthWire.CipherAesGcm)
        {
            throw new YouAuthException($"{identity} sealed the token with '{token.Cipher}'; this app asked for {YouAuthWire.CipherAesGcm}");
        }

        byte[] clientAuthToken;
        try
        {
            // 16-byte IV whose first 12 bytes are the nonce, the tag appended to the ciphertext.
            clientAuthToken = AesGcm.Decrypt(
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
                logger.LogWarning("YouAuth: the identity answered the release of this login's registration with {status}; it expires on its own", (int)response.StatusCode);
                logger.LogDebug("YouAuth: the identity was {identity}", identity);
            }
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException)
        {
            logger.LogWarning("YouAuth: could not release this login's registration at the identity ({reason}); it expires on its own", e.GetType().Name);
            logger.LogDebug(e, "YouAuth: the identity was {identity}", identity);
        }
    }
}
