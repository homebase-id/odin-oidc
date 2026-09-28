using System.Net;
using Odin.Oidc.Login.Tests.Fakes;

namespace Odin.Oidc.Login.Tests;

/// <summary>
/// The broker's own consent: the owner consented at their identity to this app by name, so the
/// relying party is named here, with what it will learn, and Allow is remembered. And Hydra's
/// logout hand-off, accepted at once.
/// </summary>
[TestFixture]
public class ConsentAndLogoutTests
{
    private const string Frodo = BrokerApp.Frodo;

    [Test]
    public async Task TheConsentPageNamesTheRelyingPartyAndWhatItLearns()
    {
        using var app = new BrokerApp();
        app.Hydra.RequestedScope = ["openid", "offline", "profile"];
        using var browser = app.CreateClient();

        var response = await browser.GetAsync("/consent?consent_challenge=co1");
        var html = await response.Content.ReadAsStringAsync();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), html);
        Assert.That(html, Does.Contain("Demo relying party").And.Contain(Frodo), "who asks, and as whom the owner signs in");
        Assert.That(html, Does.Contain("name, picture").And.Contain("stay signed in"), "the profile and offline scopes are spelled out");
        Assert.That(app.Hydra.ConsentAccepts, Is.Empty);
    }

    [Test]
    public async Task AllowingGrantsTheScopeWithTheClaimsAndIsRemembered()
    {
        using var app = new BrokerApp();
        app.Hydra.RequestedScope = ["openid", "profile"];
        using var browser = app.CreateClient();

        var response = await PostConsentAsync(browser, "co1", allow: true);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        Assert.That(response.Headers.Location!.ToString(), Is.EqualTo(FakeHydraAdmin.RedirectTo));
        var (challenge, body) = app.Hydra.ConsentAccepts.Single();
        Assert.That(challenge, Is.EqualTo("co1"));
        Assert.That(body, Does.Contain("\"grant_scope\":[\"openid\",\"profile\"]")
            .And.Contain("\"remember\":true").And.Contain("\"remember_for\":2592000")
            .And.Contain("\"name\":\"Frodo Baggins\"").And.Contain($"\"picture\":\"https://{Frodo}/pub/image\""),
            "the scope as requested, remembered for a month, with the claims read from the identity's public profile: " + body);
    }

    [Test]
    public async Task DenyingRejectsTheConsent()
    {
        using var app = new BrokerApp();
        using var browser = app.CreateClient();

        var response = await PostConsentAsync(browser, "co1", allow: false);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        var (challenge, body) = app.Hydra.ConsentRejects.Single();
        Assert.That(challenge, Is.EqualTo("co1"));
        Assert.That(FakeHydraAdmin.Field(body, "error"), Is.EqualTo("access_denied"));
        Assert.That(app.Hydra.ConsentAccepts, Is.Empty);
    }

    [TestCase(true, false)]
    [TestCase(false, true)]
    public async Task ARememberedOrTrustedConsentIsAcceptedWithoutAsking(bool skip, bool clientSkipsConsent)
    {
        using var app = new BrokerApp();
        app.Hydra.ConsentSkip = skip;
        app.Hydra.ClientSkipConsent = clientSkipsConsent;
        app.Hydra.RequestedScope = ["openid", "profile"];
        using var browser = app.CreateClient();

        var response = await browser.GetAsync("/consent?consent_challenge=co1");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        var (_, body) = app.Hydra.ConsentAccepts.Single();
        Assert.That(body, Does.Contain("\"name\":\"Frodo Baggins\""), "the claims are read fresh each time, even when the question is skipped");
    }

    [Test]
    public async Task LogoutIsAcceptedAtOnce()
    {
        using var app = new BrokerApp();
        using var browser = app.CreateClient();

        var response = await browser.GetAsync("/logout?logout_challenge=lo1");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        Assert.That(app.Hydra.LogoutAccepts.Single().challenge, Is.EqualTo("lo1"));
    }

    private static async Task<HttpResponseMessage> PostConsentAsync(HttpClient browser, string challenge, bool allow)
    {
        var page = await browser.GetAsync($"/consent?consent_challenge={challenge}");
        var html = await page.Content.ReadAsStringAsync();
        Assert.That(page.StatusCode, Is.EqualTo(HttpStatusCode.OK), html);
        return await BrokerApp.PostFormAsync(browser, "/consent", html, new() { ["consent_challenge"] = challenge, ["allow"] = allow ? "yes" : "no" });
    }
}
