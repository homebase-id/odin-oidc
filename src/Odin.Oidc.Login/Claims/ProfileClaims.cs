using System.Text.Json;
using Odin.Oidc.Login.YouAuth;

namespace Odin.Oidc.Login.Claims;

/// <summary>
/// What a relying party learns beyond the subject. Always <c>did</c>, the subject as a
/// <c>did:web</c>, which resolves to the identity's own DID document at /.well-known/did.json.
/// Under the <c>profile</c> scope the names the owner published on their public profile card, the
/// identity's public image, and what follows from the domain, including OIDC's <c>profile</c>
/// claim: the home page, which carries the identity's schema.org JSON-LD. Read at consent time;
/// nothing is stored here.
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
        var claims = new Dictionary<string, object> { ["did"] = $"did:web:{identity}" };
        if (!grantedScope.Contains(ProfileScope))
        {
            return claims;
        }

        // OIDC standard claim names, from the card's schema.org-style members.
        foreach (var (claim, member) in await PublishedNamesAsync(identity, ct))
        {
            claims[claim] = member;
        }
        claims["picture"] = $"https://{identity}{ImagePath}";
        claims["preferred_username"] = identity;
        claims["website"] = $"https://{identity}";
        claims["profile"] = $"https://{identity}/";
        return claims;
    }

    private static readonly (string claim, string member)[] NameMembers =
    [
        ("name", "name"),
        ("given_name", "givenName"),
        ("family_name", "familyName"),
    ];

    private async Task<List<(string claim, string value)>> PublishedNamesAsync(string identity, CancellationToken ct)
    {
        var names = new List<(string, string)>();
        try
        {
            using var http = httpClientFactory.CreateClient(YouAuthClient.HttpClientName);
            using var response = await http.GetAsync($"https://{identity}{ProfileCardPath}", ct);
            if (!response.IsSuccessStatusCode)
            {
                return names;
            }
            using var card = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
            foreach (var (claim, member) in NameMembers)
            {
                if (card.RootElement.TryGetProperty(member, out var value) && value.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(value.GetString()))
                {
                    names.Add((claim, value.GetString()!.Trim()));
                }
            }
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or JsonException)
        {
            logger.LogWarning(e, "Could not read {identity}'s public profile; the relying party gets no name", identity);
        }
        return names;
    }
}
