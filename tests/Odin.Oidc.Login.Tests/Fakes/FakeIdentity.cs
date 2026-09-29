using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Odin.Core;
using Odin.Core.Cryptography.Data;

namespace Odin.Oidc.Login.Tests.Fakes;

/// <summary>
/// An identity server's side of the token exchange, steps [070] to [140]: given the broker's public
/// key from the authorize URL it derives the same exchange secret, seals a 33-byte token with the
/// cipher it was asked for, and answers the token endpoint when the digest matches. Also records
/// the release call at /api/v2/auth/logout.
/// </summary>
public sealed class FakeIdentity
{
    public string Domain { get; }
    public byte[] ClientAuthToken { get; } = RandomNumberGenerator.GetBytes(33);
    public string SealWith { get; set; } = "aes-gcm";
    public string? EchoCipher { get; set; } = "aes-gcm";
    public List<(string path, string? authorization)> Releases { get; } = [];
    /// <summary>The public profile card at /pub/profile; null answers 404, as an identity with no card does.</summary>
    public string? PublicProfileJson { get; set; } = """{"name":"Frodo Baggins","givenName":"Frodo","familyName":"Baggins","bio":"...","image":"...","email":[{"type":"main","email":"frodo@dotyou.cloud"}]}""";
    public RecordingHandler Handler { get; }

    /// <summary>An IHttpClientFactory whose every client talks to this identity.</summary>
    public IHttpClientFactory ClientFactory => new SingleClientFactory(Handler);

    private readonly SensitiveByteArray _pwd = new(RandomNumberGenerator.GetBytes(16));
    private readonly EccFullKeyData _keyPair;
    private SensitiveByteArray? _exchangeSecret;

    public FakeIdentity(string domain)
    {
        Domain = domain;
        _keyPair = new EccFullKeyData(_pwd, EccKeySize.P384, 1);
        Handler = new RecordingHandler(Respond);
    }

    /// <summary>
    /// YouAuth [070] and [080]: takes the broker's authorize URL, derives the exchange secret, and
    /// returns the callback query the identity would redirect the browser with.
    /// </summary>
    public Dictionary<string, string> Authorize(Uri authorizeUrl, string? identityParam = null)
    {
        var query = QueryHelpers.ParseQuery(authorizeUrl.Query);
        var brokerPublicKey = EccPublicKeyData.FromJwkBase64UrlPublicKey(query["public_key"].ToString());
        var salt = RandomNumberGenerator.GetBytes(16);
        _exchangeSecret = _keyPair.GetEcdhSharedSecret(_pwd, brokerPublicKey, salt);
        return new Dictionary<string, string>
        {
            ["identity"] = identityParam ?? Domain,
            ["public_key"] = _keyPair.PublicKeyJwkBase64Url(),
            ["salt"] = Convert.ToBase64String(salt),
            ["state"] = query["state"].ToString(),
        };
    }

    public string ExpectedDigest => Convert.ToBase64String(SHA256.HashData(_exchangeSecret!.GetKey()));

    private Task<HttpResponseMessage> Respond(HttpRequestMessage request, string? body)
    {
        if (request.RequestUri!.Host != Domain)
        {
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new StringContent($"fake identity {Domain} asked as {request.RequestUri.Host}") });
        }

        switch (request.Method.Method, request.RequestUri.AbsolutePath)
        {
            case ("POST", "/api/owner/v1/youauth/token"):
            {
                var digest = JsonDocument.Parse(body!).RootElement.GetProperty("secret_digest").GetString();
                if (digest != ExpectedDigest)
                {
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
                }
                var (secretIv, secretCipher) = Seal(RandomNumberGenerator.GetBytes(16));
                var (tokenIv, tokenCipher) = Seal(ClientAuthToken);
                var response = new Dictionary<string, string?>
                {
                    ["base64SharedSecretCipher"] = Convert.ToBase64String(secretCipher),
                    ["base64SharedSecretIv"] = Convert.ToBase64String(secretIv),
                    ["base64ClientAuthTokenCipher"] = Convert.ToBase64String(tokenCipher),
                    ["base64ClientAuthTokenIv"] = Convert.ToBase64String(tokenIv),
                };
                if (EchoCipher != null)
                {
                    response["cipher"] = EchoCipher;
                }
                return Task.FromResult(RecordingHandler.Json(HttpStatusCode.OK, JsonSerializer.Serialize(response)));
            }
            case ("POST", "/api/v2/auth/logout"):
                Releases.Add((request.RequestUri.AbsolutePath, request.Headers.Authorization?.ToString()));
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
            case ("GET", "/pub/profile"):
                return Task.FromResult(PublicProfileJson == null
                    ? new HttpResponseMessage(HttpStatusCode.NotFound)
                    : RecordingHandler.Json(HttpStatusCode.OK, PublicProfileJson));
            default:
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new StringContent($"fake identity: {request.Method} {request.RequestUri.AbsolutePath}") });
        }
    }

    private (byte[] iv, byte[] cipherText) Seal(byte[] plain) => SealWith == "aes-gcm"
        ? AesGcm.Encrypt(plain, _exchangeSecret!)
        : Odin.Core.Cryptography.Crypto.AesCbc.Encrypt(plain, _exchangeSecret!);
}
