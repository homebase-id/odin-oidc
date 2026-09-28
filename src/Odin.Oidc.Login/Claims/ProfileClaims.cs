using System.Text.Json;
using Odin.Oidc.Login.YouAuth;

namespace Odin.Oidc.Login.Claims;

/// <summary>
/// What a relying party learns beyond the subject. Always <c>did</c>, the subject as a
/// <c>did:web</c>, which resolves to the identity's own DID document at /.well-known/did.json.
/// Under the <c>profile</c> scope the names the owner published on their public profile card, the
/// identity's public image, and OIDC's <c>profile</c> claim: the home page, which carries the
/// identity's schema.org JSON-LD. Read at consent time; nothing is stored here.
/// </summary>
/// <remarks>
/// The card is odin-core's <c>FrontEndProfile</c> (Odin.Services.PublicPage.PersonMetadata),
/// written by <c>ProfilePublishService</c> and served anonymously by <c>StaticFileController</c>
/// at <c>/pub/profile</c>; the image at <c>/pub/image</c>, with a default when none is published.
/// Member names are copied here rather than referencing Odin.Services.
/// </remarks>
public sealed class ProfileClaims(IHttpClientFactory httpClientFactory, ILogger<ProfileClaims> logger)
{
    public const string ProfileScope = "profile";
    private const string ProfileCardPath = "/pub/profile";
    private const string ImagePath = "/pub/image";

    /// <summary>OIDC claim name, card member.</summary>
    private static readonly (string claim, string member)[] NameMembers =
    [
        ("name", "name"),
        ("given_name", "givenName"),
        ("family_name", "familyName"),
    ];

    public async Task<Dictionary<string, object>> ForAsync(string identity, IReadOnlyCollection<string> grantedScope, CancellationToken ct)
    {
        var claims = new Dictionary<string, object> { ["did"] = $"did:web:{identity}" };
        if (!grantedScope.Contains(ProfileScope))
        {
            return claims;
        }

        var origin = $"https://{identity}";
        await AddPublishedNamesAsync(identity, claims, ct);
        claims["picture"] = origin + ImagePath;
        claims["preferred_username"] = identity;
        claims["profile"] = origin + "/";
        return claims;
    }

    private async Task AddPublishedNamesAsync(string identity, Dictionary<string, object> claims, CancellationToken ct)
    {
        try
        {
            using var http = httpClientFactory.CreateClient(YouAuthClient.HttpClientName);
            using var response = await http.GetAsync($"https://{identity}{ProfileCardPath}", ct);
            if (!response.IsSuccessStatusCode)
            {
                return;
            }
            using var card = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
            foreach (var (claim, member) in NameMembers)
            {
                if (card.RootElement.TryGetProperty(member, out var value) && value.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(value.GetString()))
                {
                    claims[claim] = value.GetString()!.Trim();
                }
            }
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or JsonException)
        {
            logger.LogWarning(e, "Could not read {identity}'s public profile; the relying party gets no name", identity);
        }
    }
}
