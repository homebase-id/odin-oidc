using System.Net;

namespace Odin.Oidc.Login.Tests;

/// <summary>
/// What the login and consent pages say about the relying party: its callback's domain large, the
/// name it gave itself small, never the other way round. The lesson of odin-core #1818.
/// </summary>
[TestFixture]
public class RelyingPartyPagesTests
{
    private static BrokerApp AppWithBank()
    {
        var app = new BrokerApp();
        app.Hydra.ClientId = "https://evil.example/app";
        app.Hydra.ClientName = "Homebase Bank";
        app.Hydra.ClientRedirectUris = ["https://evil.example/cb"];
        app.Hydra.RequestUrl = "http://hydra:4444/oauth2/auth?client_id=https%3A%2F%2Fevil.example%2Fapp&redirect_uri=https%3A%2F%2Fevil.example%2Fcb&response_type=code";
        return app;
    }

    [TestCase("/login?login_challenge=ch1")]
    [TestCase("/consent?consent_challenge=co1")]
    public async Task TheDomainIsLargeAndTheNameIsAClaim(string path)
    {
        using var app = AppWithBank();
        using var browser = app.CreateClient();

        var html = await (await browser.GetAsync(path)).Content.ReadAsStringAsync();

        Assert.That(html, Does.Contain("<strong class=\"domain\">evil.example</strong>"), "the callback's host, from the request Hydra validated");
        Assert.That(html, Does.Contain("Calling itself").And.Contain("Homebase Bank"), "the self-declared name, small, in those words");
        Assert.That(html.IndexOf("evil.example", StringComparison.Ordinal), Is.LessThan(html.IndexOf("Homebase Bank", StringComparison.Ordinal)), "domain first");
    }

    [Test]
    public async Task WithoutANameOnlyTheDomainIsShown()
    {
        using var app = AppWithBank();
        app.Hydra.ClientName = null;
        using var browser = app.CreateClient();

        var html = await (await browser.GetAsync("/consent?consent_challenge=co1")).Content.ReadAsStringAsync();

        Assert.That(html, Does.Contain("evil.example").And.Not.Contain("Calling itself"));
    }

    [Test]
    public async Task AnInternationalisedCallbackHostIsShownAsPunycode()
    {
        using var app = AppWithBank();
        app.Hydra.RequestUrl = "http://hydra:4444/oauth2/auth?client_id=x&redirect_uri=" + Uri.EscapeDataString("https://bücher.example/cb");
        using var browser = app.CreateClient();

        var html = await (await browser.GetAsync("/login?login_challenge=ch1")).Content.ReadAsStringAsync();

        Assert.That(html, Does.Contain("xn--"));
    }

    [Test]
    public async Task WithNoRedirectAtAllThePageStillRenders()
    {
        using var app = AppWithBank();
        app.Hydra.RequestUrl = "";
        app.Hydra.ClientRedirectUris = [];
        using var browser = app.CreateClient();

        var response = await browser.GetAsync("/consent?consent_challenge=co1");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(await response.Content.ReadAsStringAsync(), Does.Contain("A site"));
    }
}
