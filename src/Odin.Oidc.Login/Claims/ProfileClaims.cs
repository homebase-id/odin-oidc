#pragma warning disable CS9113 // stub: replaced by the implementation commit
namespace Odin.Oidc.Login.Claims;

/// <summary>
/// What a relying party learns beyond the subject, under the <c>profile</c> scope: the name the
/// owner published on their public profile card, the identity's public image, and what follows
/// from the domain. Read at consent time; nothing is stored here.
/// </summary>
public sealed class ProfileClaims(IHttpClientFactory httpClientFactory, ILogger<ProfileClaims> logger)
{
    public Task<Dictionary<string, object>> ForAsync(string identity, IReadOnlyCollection<string> grantedScope, CancellationToken ct)
    {
        throw new NotImplementedException();
    }
}
