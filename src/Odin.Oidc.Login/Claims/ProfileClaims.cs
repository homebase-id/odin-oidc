using System.Text.Json;
using Odin.Oidc.Login.YouAuth;

namespace Odin.Oidc.Login.Claims;

/// <summary>
/// What a relying party learns beyond the subject, under the <c>profile</c> scope: the name the
/// owner published on their public profile card, the identity's public image, and what follows
/// from the domain. Read at consent time; nothing is stored here.
/// </summary>
public sealed class ProfileClaims(IHttpClientFactory httpClientFactory, ILogger<ProfileClaims> logger)
{
    public const string ProfileScope = "profile";

    /// <summary>The identity's public profile card, anonymous JSON (odin-core StaticFileController).</summary>
    private const string ProfileCardPath = "/pub/profile";

    /// <summary>The identity's public image; the identity answers with a default when none is published.</summary>
    private const string ImagePath = "/pub/image";

    public async Task<Dictionary<string, object>> ForAsync(string identity, IReadOnlyCollection<string> grantedScope, CancellationToken ct)
    {
        var claims = new Dictionary<string, object>();
        if (!grantedScope.Contains(ProfileScope))
        {
            return claims;
        }

        var name = await PublishedNameAsync(identity, ct);
        if (name != null)
        {
            claims["name"] = name;
        }
        claims["picture"] = $"https://{identity}{ImagePath}";
        claims["preferred_username"] = identity;
        claims["website"] = $"https://{identity}";
        return claims;
    }

    private async Task<string?> PublishedNameAsync(string identity, CancellationToken ct)
    {
        try
        {
            using var http = httpClientFactory.CreateClient(YouAuthClient.HttpClientName);
            using var response = await http.GetAsync($"https://{identity}{ProfileCardPath}", ct);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }
            using var card = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
            var name = card.RootElement.TryGetProperty("name", out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
            return string.IsNullOrWhiteSpace(name) ? null : name.Trim();
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or JsonException)
        {
            logger.LogWarning(e, "Could not read {identity}'s public profile; the relying party gets no name", identity);
            return null;
        }
    }
}
