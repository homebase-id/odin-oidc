using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
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
    private const string Frodo = "frodo.dotyou.cloud";

    private static BrokerOptions Options(bool requireGcm = false) => new()
    {
        PublicHost = "oidc.example.org",
        RequireAesGcm = requireGcm,
    };

    private static YouAuthClient Client(FakeIdentity identity, BrokerOptions? options = null)
    {
        var factory = new SingleClientFactory(identity.Handler);
        return new YouAuthClient(factory, Microsoft.Extensions.Options.Options.Create(options ?? Options()), NullLogger<YouAuthClient>.Instance);
    }

    [Test]
    public void YouAuth030_TheAuthorizeUrlNamesThisAppAndAsksForAesGcm()
    {
        var (url, keys) = Client(new FakeIdentity(Frodo)).Begin(Frodo, "state-1");

        Assert.That(url.ToString(), Does.StartWith($"https://{Frodo}/api/owner/v1/youauth/authorize?"));
        var query = QueryHelpers.ParseQuery(url.Query);
        Assert.That(query["client_type"].ToString(), Is.EqualTo("domain"));
        Assert.That(query["client_id"].ToString(), Is.EqualTo("oidc.example.org"), "the client id is the broker's host, which is what the identity trusts");
        Assert.That(query["redirect_uri"].ToString(), Is.EqualTo("https://oidc.example.org/youauth/callback"));
        Assert.That(query["state"].ToString(), Is.EqualTo("state-1"));
        Assert.That(query["cipher"].ToString(), Is.EqualTo("aes-gcm"));
        Assert.That(query["public_key"].ToString(), Is.Not.Empty);
        Assert.That(keys.PrivateKeyDerBase64, Is.Not.Empty, "the private half must survive to [090]");
    }

    [Test]
    public void YouAuth010_TheKeysAreSmallEnoughToTravelInACookie()
    {
        var (_, keys) = Client(new FakeIdentity(Frodo)).Begin(Frodo, "s");

        // The DER form is ~1200 base64 chars because BouncyCastle writes the curve parameters out in
        // full rather than naming P-384; a private JWK would be ~240. Either fits; the whole
        // EccFullKeyData serialized (~2000) did not, once encrypted and joined by the rest of the state.
        var size = keys.PasswordBase64.Length + keys.PrivateKeyDerBase64.Length;
        Assert.That(size, Is.LessThan(1500), $"the flow cookie must stay well under a browser's 4096-byte limit after encryption; keys alone are {size} bytes");
    }

    [Test]
    public void YouAuth030_ADevPortGoesOnTheRedirectUriButNotTheClientId()
    {
        var options = Options();
        options.PublicPort = 8443;
        var (url, _) = Client(new FakeIdentity(Frodo), options).Begin(Frodo, "s");

        var query = QueryHelpers.ParseQuery(url.Query);
        Assert.That(query["client_id"].ToString(), Is.EqualTo("oidc.example.org"));
        Assert.That(query["redirect_uri"].ToString(), Is.EqualTo("https://oidc.example.org:8443/youauth/callback"));
    }

    [Test]
    public async Task YouAuth150_TheTokenComesBackAsThe33BytesTheIdentitySealed()
    {
        var identity = new FakeIdentity(Frodo);
        var client = Client(identity);
        var (url, keys) = client.Begin(Frodo, "s");
        var callback = identity.Authorize(url);

        var token = await client.CompleteAsync(Frodo, keys, callback["public_key"], callback["salt"], CancellationToken.None);

        Assert.That(token, Is.EqualTo(identity.ClientAuthToken), "both sides derived the same exchange secret and GCM opened cleanly");
        var (_, body) = identity.Handler.Requests.Single(r => r.request.RequestUri!.AbsolutePath == "/api/owner/v1/youauth/token");
        var digest = System.Text.Json.JsonDocument.Parse(body!).RootElement.GetProperty("secret_digest").GetString();
        Assert.That(digest, Is.EqualTo(identity.ExpectedDigest), "YouAuth [100]: the digest of the exchange secret, base64");
    }

    [Test]
    public async Task YouAuth150_AnIdentityThatPredatesTheCipherFieldIsOpenedAsCbc()
    {
        var identity = new FakeIdentity(Frodo) { SealWith = "aes-cbc", EchoCipher = null };
        var client = Client(identity);
        var (url, keys) = client.Begin(Frodo, "s");
        var callback = identity.Authorize(url);

        var token = await client.CompleteAsync(Frodo, keys, callback["public_key"], callback["salt"], CancellationToken.None);

        Assert.That(token, Is.EqualTo(identity.ClientAuthToken));
    }

    [Test]
    public void YouAuth150_WithRequireAesGcmACbcTokenIsRefused()
    {
        var identity = new FakeIdentity(Frodo) { SealWith = "aes-cbc", EchoCipher = "aes-cbc" };
        var client = Client(identity, Options(requireGcm: true));
        var (url, keys) = client.Begin(Frodo, "s");
        var callback = identity.Authorize(url);

        Assert.That(() => client.CompleteAsync(Frodo, keys, callback["public_key"], callback["salt"], CancellationToken.None),
            Throws.InstanceOf<YouAuthException>().With.Message.Contains("aes-cbc"));
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

    private sealed class SingleClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }
}
