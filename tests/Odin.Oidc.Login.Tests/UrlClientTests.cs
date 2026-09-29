using Odin.Oidc.Login.Registration;

namespace Odin.Oidc.Login.Tests;

/// <summary>
/// A relying party whose client id is its own https URL (draft-ietf-oauth-client-id-metadata-document):
/// which strings are one, which callbacks it may use, and which redirect a request may name. Our
/// rule beyond the draft: every callback sits on the client id's own host, YouAuth's rule.
/// </summary>
[TestFixture]
public class UrlClientTests
{
    [TestCase("https://jean.example/wiki")]
    [TestCase("https://jean.example/")]
    [TestCase("https://jean.example:8443/oauth-client.json")]
    [TestCase("https://sub.jean.example/apps/wiki/client")]
    public void AnHttpsUrlWithAPathIsAUrlClient(string clientId)
    {
        Assert.That(UrlClient.TryParse(clientId, out var client), Is.True);
        Assert.That(client!.Id, Is.EqualTo(clientId), "compared as a plain string, never normalised");
    }

    [TestCase("https://jean.example", "no path")]
    [TestCase("http://jean.example/wiki", "not https")]
    [TestCase("https://user:pw@jean.example/wiki", "userinfo")]
    [TestCase("https://jean.example/wiki#frag", "fragment")]
    [TestCase("https://jean.example/a/../wiki", "dot segments")]
    [TestCase("https://jean.example/wiki?x=1", "a query")]
    [TestCase("https://203.0.113.7/wiki", "an IP address")]
    [TestCase("2d78140138044b57b4aad8e4e2ef39f4", "an operator client id")]
    [TestCase("", "nothing")]
    public void OtherStringsAreNot(string clientId, string why)
    {
        Assert.That(UrlClient.TryParse(clientId, out _), Is.False, why);
    }

    [Test]
    public void TheHostIsTheIdentityShownToPeople()
    {
        UrlClient.TryParse("https://jean.example:8443/wiki", out var client);
        Assert.That(client!.Host, Is.EqualTo("jean.example"));
        Assert.That(client.Origin, Is.EqualTo("https://jean.example:8443"));
    }

    [Test]
    public void AnInternationalisedHostIsShownAsPunycode()
    {
        UrlClient.TryParse("https://bücher.example/app", out var client);
        Assert.That(client!.Host, Does.StartWith("xn--"), "a lookalike cannot paint itself");
    }

    [Test]
    public void OnlyCallbacksOnTheClientsOwnOriginCount()
    {
        UrlClient.TryParse("https://jean.example/wiki", out var client);

        var kept = client!.OwnCallbacks(["https://jean.example/cb", "https://jean.example/other", "https://evil.example/cb", "http://jean.example/cb", "https://jean.example:444/cb"]);

        Assert.That(kept, Is.EqualTo(new[] { "https://jean.example/cb", "https://jean.example/other" }), "another host, http, or another port are dropped");
    }

    [Test]
    public void ARequestsRedirectMustMatchAListedCallbackExactly()
    {
        var document = new ClientDocument(["https://jean.example/cb"], null, ["openid"], TimeSpan.FromHours(1));

        Assert.That(document.ResolveRedirect("https://jean.example/cb"), Is.EqualTo("https://jean.example/cb"));
        Assert.That(document.ResolveRedirect("https://jean.example/cb?x=1"), Is.Null, "exact string match, RFC 9700");
        Assert.That(document.ResolveRedirect("https://jean.example/CB"), Is.Null);
        Assert.That(document.ResolveRedirect(null), Is.EqualTo("https://jean.example/cb"), "the draft: the one listed callback when the request names none");
        Assert.That(new ClientDocument(["https://jean.example/a", "https://jean.example/b"], null, ["openid"], TimeSpan.Zero).ResolveRedirect(null), Is.Null, "but not when there are several");
    }

    [Test]
    public void TheLocalhostDevelopmentClientIsItsOwnDocument()
    {
        Assert.That(UrlClient.TryParse("http://localhost?redirect_uri=http%3A%2F%2F127.0.0.1%2Fcb&scope=openid%20profile", out var client), Is.True);
        Assert.That(client!.Id, Is.EqualTo("http://localhost?redirect_uri=http%3A%2F%2F127.0.0.1%2Fcb&scope=openid%20profile"));
        Assert.That(client.Host, Is.EqualTo("localhost"));
        Assert.That(client.Declared, Is.Not.Null, "nothing is fetched");
        Assert.That(client.Declared!.RedirectUris, Is.EqualTo(new[] { "http://127.0.0.1/cb" }));
        Assert.That(client.Declared.ResolveRedirect("http://127.0.0.1:5556/cb"), Is.EqualTo("http://127.0.0.1:5556/cb"), "loopback: the port is not matched, the path is");
        Assert.That(client.Declared.ResolveRedirect("http://127.0.0.1:5556/other"), Is.Null);
        Assert.That(client.Declared.Scope, Is.EqualTo(new[] { "openid", "profile" }));
    }

    [TestCase("http://localhost:3000")]
    [TestCase("http://localhost/app")]
    [TestCase("https://localhost")]
    public void OtherLocalhostFormsAreNotTheDevelopmentClient(string clientId)
    {
        Assert.That(UrlClient.TryParse(clientId, out _), Is.False);
    }
}
