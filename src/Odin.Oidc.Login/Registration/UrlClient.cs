#pragma warning disable CS9113
namespace Odin.Oidc.Login.Registration;

/// <summary>
/// A relying party whose client id is its own https URL (draft-ietf-oauth-client-id-metadata-document).
/// </summary>
public sealed class UrlClient
{
    public string Id { get; } = "";
    public string Host { get; } = "";
    public string Origin { get; } = "";
    public bool IsLocalhostDevelopment { get; }
    public IReadOnlyList<string> DeclaredCallbacks { get; } = [];
    public IReadOnlyList<string> DeclaredScope { get; } = [];

    public static bool TryParse(string? clientId, out UrlClient? client) => throw new NotImplementedException();
    public static bool TryParseLocalhost(string? clientId, out UrlClient? client) => throw new NotImplementedException();
    public IReadOnlyList<string> OwnCallbacks(IEnumerable<string> redirectUris) => throw new NotImplementedException();
    public bool Allows(string redirectUri, IReadOnlyList<string> callbacks) => throw new NotImplementedException();
}
