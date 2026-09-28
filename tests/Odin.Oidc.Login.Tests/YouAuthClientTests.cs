using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging.Abstractions;
using Odin.Oidc.Login.Options;
using Odin.Oidc.Login.Tests.Fakes;
using Odin.Oidc.Login.YouAuth;

namespace Odin.Oidc.Login.Tests;

/// <summary>
/// This app as a YouAuth domain client against a fake identity that runs the identity's half of
/// the exchange with odin-core's own primitives. Step numbers are the flow diagram's.
/// </summary>
[TestFixture]
public class YouAuthClientTests
{
    private const string Frodo = BrokerApp.Frodo;

    private static YouAuthClient Client(FakeIdentity identity, string publicOrigin = "https://oidc.example.org")
    {
        var options = new BrokerOptions { PublicOrigin = publicOrigin };
        return new YouAuthClient(identity.ClientFactory, Microsoft.Extensions.Options.Options.Create(options), NullLogger<YouAuthClient>.Instance);
    }

    [Test]
    public void YouAuth030_TheAuthorizeUrlNamesThisAppAndAsksForAesGcm()
    {
        var (url, state, privateKey) = Client(new FakeIdentity(Frodo)).Begin(Frodo);

        Assert.That(url.ToString(), Does.StartWith($"https://{Frodo}/api/owner/v1/youauth/authorize?"));
        var query = QueryHelpers.ParseQuery(url.Query);
        Assert.That(query["client_type"].ToString(), Is.EqualTo("domain"));
        Assert.That(query["client_id"].ToString(), Is.EqualTo("oidc.example.org"), "the client id is the broker's host, which is what the identity trusts");
        Assert.That(query["redirect_uri"].ToString(), Is.EqualTo("https://oidc.example.org/youauth/callback"));
        Assert.That(query["state"].ToString(), Is.EqualTo(state).And.Length.GreaterThanOrEqualTo(43), "32 random bytes, base64url");
        Assert.That(query["cipher"].ToString(), Is.EqualTo("aes-gcm"));
        Assert.That(query["public_key"].ToString(), Is.Not.Empty);
        Assert.That(privateKey, Is.Not.Empty, "the private half must survive to [090]");
    }

    [Test]
    public void YouAuth030_ADevPortGoesOnTheRedirectUriButNotTheClientId()
    {
        var (url, _, _) = Client(new FakeIdentity(Frodo), "https://oidc.example.org:8443").Begin(Frodo);

        var query = QueryHelpers.ParseQuery(url.Query);
        Assert.That(query["client_id"].ToString(), Is.EqualTo("oidc.example.org"));
        Assert.That(query["redirect_uri"].ToString(), Is.EqualTo("https://oidc.example.org:8443/youauth/callback"));
    }

    [Test]
    public async Task YouAuth150_TheTokenComesBackAsThe33BytesTheIdentitySealed()
    {
        var identity = new FakeIdentity(Frodo);
        var client = Client(identity);
        var (url, _, privateKey) = client.Begin(Frodo);
        var callback = identity.Authorize(url);

        var token = await client.CompleteAsync(Frodo, privateKey, callback["public_key"], callback["salt"], CancellationToken.None);

        Assert.That(token, Is.EqualTo(identity.ClientAuthToken), "both sides derived the same exchange secret and GCM opened cleanly");
        var (_, body) = identity.Handler.Requests.Single(r => r.request.RequestUri!.AbsolutePath == "/api/owner/v1/youauth/token");
        var digest = System.Text.Json.JsonDocument.Parse(body!).RootElement.GetProperty("secret_digest").GetString();
        Assert.That(digest, Is.EqualTo(identity.ExpectedDigest), "YouAuth [100]: the digest of the exchange secret, base64");
    }

    [TestCase("aes-cbc")]
    [TestCase(null)]
    public void YouAuth150_ATokenNotSealedWithWhatWasAskedForIsRefused(string? echo)
    {
        var identity = new FakeIdentity(Frodo) { SealWith = "aes-cbc", EchoCipher = echo };
        var client = Client(identity);
        var (url, _, privateKey) = client.Begin(Frodo);
        var callback = identity.Authorize(url);

        Assert.That(() => client.CompleteAsync(Frodo, privateKey, callback["public_key"], callback["salt"], CancellationToken.None),
            Throws.InstanceOf<YouAuthException>().With.Message.Contains("aes-gcm"),
            "an identity that seals with anything else predates the choice; there are none this app should meet");
    }

    [Test]
    public async Task TheRegistrationIsReleasedWithTheTokenAsBearer()
    {
        var identity = new FakeIdentity(Frodo);
        var token = identity.ClientAuthToken;

        await Client(identity).ReleaseAsync(Frodo, token, CancellationToken.None);

        var (path, authorization) = identity.Releases.Single();
        Assert.That(path, Is.EqualTo("/api/v2/auth/logout"));
        Assert.That(authorization, Is.EqualTo($"Bearer {Convert.ToBase64String(token)}"));
    }

    [Test]
    public void AReleaseThatFailsDoesNotFailTheLogin()
    {
        var identity = new FakeIdentity("nobody.example.org");
        Assert.That(() => Client(identity).ReleaseAsync(Frodo, new byte[33], CancellationToken.None), Throws.Nothing,
            "the identity is already proven; a failed cleanup is logged, not surfaced");
    }
}
