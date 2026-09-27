using System.Text.Json.Serialization;

namespace Odin.Oidc.Login.YouAuth;

/// <summary>
/// The YouAuth wire vocabulary this app speaks, copied from odin-core rather than referencing
/// Odin.Services: <c>YouAuthDefaults</c>, <c>OwnerApiPathConstants</c>, <c>UnifiedApiRouteConstants</c>,
/// and the reference client's <c>Models/</c>. The flow is documented in odin-core's
/// docs/youauth-unified-authorization.md; step numbers here are its.
/// </summary>
public static class YouAuthWire
{
    public const string AuthorizePath = "/api/owner/v1/youauth/authorize";
    public const string TokenPath = "/api/owner/v1/youauth/token";
    /// <summary>Deletes the caller's own client registration at the identity (V2AuthController).</summary>
    public const string LogoutPath = "/api/v2/auth/logout";

    public const string CipherAesGcm = "aes-gcm";

    // Query names of the [080] callback and the [060] error redirect. The callback's `identity`
    // is deliberately absent: the subject is what the owner typed, never what the callback claims.
    public const string PublicKey = "public_key";
    public const string Salt = "salt";
    public const string State = "state";
    public const string Error = "error";
    public const string ErrorDescription = "error_description";
}

/// <summary>The [100] token request body.</summary>
public sealed class YouAuthTokenRequest
{
    [JsonPropertyName("secret_digest")]
    public string SecretDigest { get; set; } = "";
}

/// <summary>
/// The [140] token response: the members this app opens. The shared secret it also carries is for
/// calling the identity, which this app never does.
/// </summary>
public sealed class YouAuthTokenResponse
{
    [JsonPropertyName("base64ClientAuthTokenCipher")]
    public string? Base64ClientAuthTokenCipher { get; set; }

    [JsonPropertyName("base64ClientAuthTokenIv")]
    public string? Base64ClientAuthTokenIv { get; set; }

    /// <summary>What sealed it. This app asks for aes-gcm and accepts nothing else.</summary>
    [JsonPropertyName("cipher")]
    public string? Cipher { get; set; }
}
