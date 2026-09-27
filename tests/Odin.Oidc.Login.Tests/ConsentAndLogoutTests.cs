using System.Net;
using System.Text.RegularExpressions;
using Odin.Oidc.Login.Tests.Fakes;

namespace Odin.Oidc.Login.Tests;

/// <summary>
/// The broker's own consent: the owner consented at their identity to this app by name, so the
/// relying party is named here, with what it will learn, and the answer is remembered on request.
/// And Hydra's logout hand-off, which is a question only when the browser asked for it itself.
/// </summary>
[TestFixture]
public class ConsentAndLogoutTests
{
    private const string Frodo = "frodo.dotyou.cloud";

    [Test]
    public async Task TheConsentPageNamesTheRelyingPartyAndWhatItLearns()
    {
        using var app = new BrokerApp();
        app.Hydra.RequestedScope = ["openid", "offline", "profile"];
        using var browser = app.CreateClient();

        var response = await browser.GetAsync("/consent?consent_challenge=co1");
        var html = await response.Content.ReadAsStringAsync();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), html);
        Assert.That(html, Does.Contain("Demo relying party").And.Contain(Frodo), "who asks, and as whom the owner is signed in");
        Assert.That(html, Does.Contain("name").And.Contain("picture"), "the profile scope is spelled out");
        Assert.That(html, Does.Contain("name=\"remember\""));
        Assert.That(app.Hydra.ConsentAccepts, Is.Empty);
    }

    [Test]
    public async Task AllowingGrantsTheScopeWithTheClaimsAndRemembers()
    {
        using var app = new BrokerApp();
        app.Hydra.RequestedScope = ["openid", "profile"];
        using var browser = app.CreateClient();

        var response = await PostConsentAsync(browser, "co1", allow: true, remember: true);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        Assert.That(response.Headers.Location!.ToString(), Is.EqualTo(FakeHydraAdmin.RedirectTo));
        var (challenge, body) = app.Hydra.ConsentAccepts.Single();
        Assert.That(challenge, Is.EqualTo("co1"));
        Assert.That(body, Does.Contain("\"grant_scope\":[\"openid\",\"profile\"]").And.Contain("\"remember\":true").And.Contain("\"remember_for\":2592000"), body);
        Assert.That(body, Does.Contain("\"name\":\"Frodo Baggins\"").And.Contain($"\"picture\":\"https://{Frodo}/pub/image\""), "read from the identity's public profile: " + body);
    }

    [Test]
    public async Task AllowingWithoutRememberIsForThisTimeOnly()
    {
        using var app = new BrokerApp();
        using var browser = app.CreateClient();

        await PostConsentAsync(browser, "co1", allow: true, remember: false);

        var (_, body) = app.Hydra.ConsentAccepts.Single();
        Assert.That(body, Does.Contain("\"remember\":false").And.Not.Contain("remember_for"));
    }

    [Test]
    public async Task DenyingRejectsTheConsent()
    {
        using var app = new BrokerApp();
        using var browser = app.CreateClient();

        var response = await PostConsentAsync(browser, "co1", allow: false, remember: false);

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
    public async Task ALogoutTheRelyingPartyStartedIsAcceptedAtOnce()
    {
        using var app = new BrokerApp();
        app.Hydra.LogoutRpInitiated = true;
        using var browser = app.CreateClient();

        var response = await browser.GetAsync("/logout?logout_challenge=lo1");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        Assert.That(app.Hydra.LogoutAccepts.Single().challenge, Is.EqualTo("lo1"));
    }

    [Test]
    public async Task ALogoutTheBrowserStartedIsAQuestion()
    {
        using var app = new BrokerApp();
        using var browser = app.CreateClient();

        var page = await browser.GetAsync("/logout?logout_challenge=lo1");
        var html = await page.Content.ReadAsStringAsync();
        Assert.That(page.StatusCode, Is.EqualTo(HttpStatusCode.OK), html);
        Assert.That(html, Does.Contain(Frodo).And.Contain("name=\"confirm\""));
        Assert.That(app.Hydra.LogoutAccepts, Is.Empty);

        var yes = await PostAsync(browser, "/logout", html, new() { ["logout_challenge"] = "lo1", ["confirm"] = "yes" });
        Assert.That(yes.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        Assert.That(app.Hydra.LogoutAccepts.Single().challenge, Is.EqualTo("lo1"));
    }

    [Test]
    public async Task DecliningALogoutKeepsTheSession()
    {
        using var app = new BrokerApp();
        using var browser = app.CreateClient();
        var html = await (await browser.GetAsync("/logout?logout_challenge=lo1")).Content.ReadAsStringAsync();

        var no = await PostAsync(browser, "/logout", html, new() { ["logout_challenge"] = "lo1", ["confirm"] = "no" });

        Assert.That(no.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(await no.Content.ReadAsStringAsync(), Does.Contain("still signed in"));
        Assert.That(app.Hydra.LogoutRejects.Single().challenge, Is.EqualTo("lo1"));
        Assert.That(app.Hydra.LogoutAccepts, Is.Empty);
    }

    // ---------------------------------------------------------------------------------------

    private static async Task<HttpResponseMessage> PostConsentAsync(HttpClient browser, string challenge, bool allow, bool remember)
    {
        var page = await browser.GetAsync($"/consent?consent_challenge={challenge}");
        var html = await page.Content.ReadAsStringAsync();
        Assert.That(page.StatusCode, Is.EqualTo(HttpStatusCode.OK), html);
        var form = new Dictionary<string, string> { ["consent_challenge"] = challenge, ["allow"] = allow ? "yes" : "no" };
        if (remember)
        {
            form["remember"] = "true";
        }
        return await PostAsync(browser, "/consent", html, form);
    }

    /// <summary>POST a page's form with the antiforgery token the page rendered.</summary>
    internal static async Task<HttpResponseMessage> PostAsync(HttpClient browser, string path, string pageHtml, Dictionary<string, string> form)
    {
        var token = Regex.Match(pageHtml, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value;
        Assert.That(token, Is.Not.Empty, "the form carries an antiforgery token");
        form["__RequestVerificationToken"] = token;
        return await browser.PostAsync(path, new FormUrlEncodedContent(form));
    }
}
