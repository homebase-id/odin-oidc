using Microsoft.Extensions.Logging.Abstractions;
using Odin.Oidc.Login.Claims;
using Odin.Oidc.Login.Tests.Fakes;

namespace Odin.Oidc.Login.Tests;

/// <summary>
/// What a relying party learns beyond the subject, read from the identity's public profile at
/// consent time and put in the id_token and userinfo: only under the <c>profile</c> scope, and
/// only what the owner published.
/// </summary>
[TestFixture]
public class ProfileClaimsTests
{
    private const string Frodo = "frodo.dotyou.cloud";

    private static ProfileClaims Claims(FakeIdentity identity) =>
        new(new SingleClientFactory(identity.Handler), NullLogger<ProfileClaims>.Instance);

    [Test]
    public async Task WithoutTheProfileScopeNothingIsAsked()
    {
        var identity = new FakeIdentity(Frodo);

        var claims = await Claims(identity).ForAsync(Frodo, ["openid", "offline"], CancellationToken.None);

        Assert.That(claims, Is.Empty);
        Assert.That(identity.Handler.Requests, Is.Empty, "the identity is not even asked");
    }

    [Test]
    public async Task TheProfileScopeReadsThePublishedCard()
    {
        var identity = new FakeIdentity(Frodo);

        var claims = await Claims(identity).ForAsync(Frodo, ["openid", "profile"], CancellationToken.None);

        Assert.That(claims["name"], Is.EqualTo("Frodo Baggins"));
        Assert.That(claims["picture"], Is.EqualTo($"https://{Frodo}/pub/image"), "the identity serves its image there, with a default when none is published");
        Assert.That(claims["preferred_username"], Is.EqualTo(Frodo));
        Assert.That(claims["website"], Is.EqualTo($"https://{Frodo}"));
        Assert.That(claims.Keys, Is.EquivalentTo(new[] { "name", "picture", "preferred_username", "website" }), "email is not the profile scope's");
    }

    [Test]
    public async Task AnIdentityWithNoCardStillHasTheClaimsThatFollowFromItsDomain()
    {
        var identity = new FakeIdentity(Frodo) { PublicProfileJson = null };

        var claims = await Claims(identity).ForAsync(Frodo, ["profile"], CancellationToken.None);

        Assert.That(claims.Keys, Is.EquivalentTo(new[] { "picture", "preferred_username", "website" }), "no name to give; the rest is the domain's");
    }

    [Test]
    public async Task ACardWithABlankNameGivesNoName()
    {
        var identity = new FakeIdentity(Frodo) { PublicProfileJson = """{"name":"  "}""" };

        var claims = await Claims(identity).ForAsync(Frodo, ["profile"], CancellationToken.None);

        Assert.That(claims.ContainsKey("name"), Is.False);
    }

    private sealed class SingleClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }
}
