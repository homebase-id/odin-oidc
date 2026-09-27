using System.Text.Json.Serialization;
using Microsoft.AspNetCore.WebUtilities;

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

    public const string ClientTypeDomain = "domain";

    public const string CipherAesCbc = "aes-cbc";
    public const string CipherAesGcm = "aes-gcm";

    // Query names of the [080] callback and the [060] error redirect.
    public const string Identity = "identity";
    public const string PublicKey = "public_key";
    public const string Salt = "salt";
    public const string State = "state";
    public const string Error = "error";
    public const string ErrorDescription = "error_description";
}

/// <summary>The [030] authorize request. Copy of odin-core's YouAuthAuthorizeRequest, the query half only.</summary>
public sealed class YouAuthAuthorizeRequest
{
    public string ClientId { get; init; } = "";
    public string ClientType { get; init; } = YouAuthWire.ClientTypeDomain;
    public string ClientInfo { get; init; } = "";
    public string RedirectUri { get; init; } = "";
    public string PermissionRequest { get; init; } = "";
    public string PublicKey { get; init; } = "";
    public string State { get; init; } = "";
    public string Cipher { get; init; } = "";

    public string ToQueryString()
    {
        var query = new Dictionary<string, string?>
        {
            ["client_id"] = ClientId,
            ["client_type"] = ClientType,
            ["client_info"] = ClientInfo,
            ["redirect_uri"] = RedirectUri,
            ["permission_request"] = PermissionRequest,
            ["public_key"] = PublicKey,
            ["state"] = State,
        };
        if (!string.IsNullOrEmpty(Cipher))
        {
            query["cipher"] = Cipher;
        }
        return QueryHelpers.AddQueryString("", query);
    }
}

/// <summary>The [100] token request body.</summary>
public sealed class YouAuthTokenRequest
{
    [JsonPropertyName("secret_digest")]
    public string SecretDigest { get; set; } = "";
}

/// <summary>The [140] token response.</summary>
public sealed class YouAuthTokenResponse
{
    [JsonPropertyName("base64SharedSecretCipher")]
    public string? Base64SharedSecretCipher { get; set; }

    [JsonPropertyName("base64SharedSecretIv")]
    public string? Base64SharedSecretIv { get; set; }

    [JsonPropertyName("base64ClientAuthTokenCipher")]
    public string? Base64ClientAuthTokenCipher { get; set; }

    [JsonPropertyName("base64ClientAuthTokenIv")]
    public string? Base64ClientAuthTokenIv { get; set; }

    /// <summary>What sealed the two ciphers; an identity that predates the field sends none, which is CBC.</summary>
    [JsonPropertyName("cipher")]
    public string? Cipher { get; set; }
}
