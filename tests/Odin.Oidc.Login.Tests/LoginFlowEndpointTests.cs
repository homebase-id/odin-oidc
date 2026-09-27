using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.WebUtilities;
using Odin.Oidc.Login.Flow;
using Odin.Oidc.Login.Pages;
using Odin.Oidc.Login.Tests.Fakes;

namespace Odin.Oidc.Login.Tests;

/// <summary>
/// One login end to end through the app's endpoints, with Hydra and the identity faked behind the
/// HttpClients: Hydra's challenge in, the owner's identity typed, the YouAuth detour, the callback
/// opened, the registration released, the challenge accepted for the subject the owner typed.
/// </summary>
[TestFixture]
public class LoginFlowEndpointTests
{
    private const string Frodo = "frodo.dotyou.cloud";

    [Test]
    public async Task ALoginHydraAlreadyKnowsIsAcceptedWithoutAsking()
    {
        using var app = new BrokerApp();
        app.Hydra.LoginSkip = true;
        app.Hydra.LoginSubject = Frodo;
        using var browser = app.CreateClient();

        var response = await browser.GetAsync("/login?login_challenge=ch1");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        Assert.That(response.Headers.Location!.ToString(), Is.EqualTo(FakeHydraAdmin.RedirectTo));
        var (challenge, body) = app.Hydra.LoginAccepts.Single();
        Assert.That(challenge, Is.EqualTo("ch1"));
        Assert.That(FakeHydraAdmin.Field(body, "subject"), Is.EqualTo(Frodo));
    }

    [Test]
    public async Task TheLoginPageAsksWhichIdentityAndPrefillsTheHint()
    {
        using var app = new BrokerApp();
        app.Hydra.LoginHint = "sam.dotyou.cloud";
        using var browser = app.CreateClient();

        var response = await browser.GetAsync("/login?login_challenge=ch1");
        var html = await response.Content.ReadAsStringAsync();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), html);
        Assert.That(html, Does.Contain("name=\"identity\"").And.Contain("value=\"sam.dotyou.cloud\"").And.Contain("Demo relying party"));
        Assert.That(app.Hydra.LoginAccepts, Is.Empty);
    }

    [Test]
    public async Task YouAuth030_TypingAnIdentitySendsTheBrowserThereWithTheFlowCookieSet()
    {
        using var app = new BrokerApp();
        using var browser = app.CreateClient();

        var response = await PostIdentityAsync(browser, "ch1", "Frodo.DotYou.Cloud");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        var location = response.Headers.Location!;
        Assert.That(location.ToString(), Does.StartWith($"https://{Frodo}/api/owner/v1/youauth/authorize?"), "lower-cased, and the identity's authorize endpoint");
        var query = QueryHelpers.ParseQuery(location.Query);
        Assert.That(query["client_id"].ToString(), Is.EqualTo(app.PublicHost));
        Assert.That(query["cipher"].ToString(), Is.EqualTo("aes-gcm"));
        Assert.That(query["redirect_uri"].ToString(), Is.EqualTo($"https://{app.PublicHost}/youauth/callback"));
        var setCookie = response.Headers.GetValues("Set-Cookie").Single(c => c.StartsWith($"{LoginFlowCookie.Name}="));
        Assert.That(setCookie.Length, Is.LessThan(4096), "a browser drops a cookie over 4096 bytes without a word, and the callback then finds no flow");
    }

    [Test]
    public async Task TheIdentityTypedLastTimeIsRememberedAndPrefilled()
    {
        using var app = new BrokerApp();
        using var browser = app.CreateClient();
        var response = await PostIdentityAsync(browser, "ch1", "Frodo.DotYou.Cloud");

        var remembered = response.Headers.GetValues("Set-Cookie").Single(c => c.StartsWith($"{LoginModel.RememberedIdentityCookie}="));
        Assert.That(remembered, Does.Contain("frodo.dotyou.cloud").And.Contain("max-age=").IgnoreCase.And.Contain("secure").IgnoreCase.And.Contain("samesite=lax").IgnoreCase,
            "a year-long, non-sensitive cookie with the domain alone; it is a convenience, not a session");

        var page = await browser.GetAsync("/login?login_challenge=ch2");
        Assert.That(await page.Content.ReadAsStringAsync(), Does.Contain("value=\"frodo.dotyou.cloud\""), "next time the owner only clicks Continue");
    }

    [Test]
    public async Task TheRelyingPartysHintBeatsTheRememberedIdentity()
    {
        using var app = new BrokerApp();
        using var browser = app.CreateClient();
        await PostIdentityAsync(browser, "ch1", Frodo);
        app.Hydra.LoginHint = "sam.dotyou.cloud";

        var page = await browser.GetAsync("/login?login_challenge=ch2");

        Assert.That(await page.Content.ReadAsStringAsync(), Does.Contain("value=\"sam.dotyou.cloud\"").And.Not.Contain($"value=\"{Frodo}\""),
            "the relying party knows who it expects; the cookie is only a default");
    }

    [Test]
    public async Task AnIdentityThatIsNotADomainIsRefusedOnThePage()
    {
        using var app = new BrokerApp();
        using var browser = app.CreateClient();

        var response = await PostIdentityAsync(browser, "ch1", "not a domain");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), "the page again, with the problem named");
        Assert.That(await response.Content.ReadAsStringAsync(), Does.Contain("not a domain").And.Contain("name=\"identity\""));
        Assert.That(app.Hydra.LoginAccepts, Is.Empty);
    }

    [Test]
    public async Task YouAuth150_TheCallbackProvesTheIdentityReleasesTheTokenAndAcceptsTheLogin()
    {
        using var app = new BrokerApp();
        using var browser = app.CreateClient();
        var authorize = (await PostIdentityAsync(browser, "ch1", Frodo)).Headers.Location!;
        var callback = app.Identity.Authorize(authorize, identityParam: "mallory.example.org");

        var response = await browser.GetAsync(QueryHelpers.AddQueryString("/youauth/callback", callback!));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect), await response.Content.ReadAsStringAsync());
        Assert.That(response.Headers.Location!.ToString(), Is.EqualTo(FakeHydraAdmin.RedirectTo));
        var (challenge, body) = app.Hydra.LoginAccepts.Single();
        Assert.That(challenge, Is.EqualTo("ch1"), "the challenge from the cookie, bound at [030]");
        Assert.That(FakeHydraAdmin.Field(body, "subject"), Is.EqualTo(Frodo), "the identity the owner typed, never what the callback claims");
        Assert.That(app.Identity.Releases.Single().authorization, Is.EqualTo($"Bearer {Convert.ToBase64String(app.Identity.ClientAuthToken)}"), "the registration is released right after proving the identity");
        Assert.That(response.Headers.GetValues("Set-Cookie").Single(), Does.StartWith($"{LoginFlowCookie.Name}=").And.Contain("expires=").IgnoreCase, "the flow cookie is gone");
    }

    [Test]
    public async Task YouAuth080_ACallbackWhoseStateDoesNotMatchTheCookieIsRefused()
    {
        using var app = new BrokerApp();
        using var browser = app.CreateClient();
        var authorize = (await PostIdentityAsync(browser, "ch1", Frodo)).Headers.Location!;
        var callback = app.Identity.Authorize(authorize);
        callback["state"] = "forged";

        var response = await browser.GetAsync(QueryHelpers.AddQueryString("/youauth/callback", callback!));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        Assert.That(app.Hydra.LoginAccepts, Is.Empty, "nothing was accepted");
        Assert.That(app.Identity.Handler.Requests, Is.Empty, "the identity was not even asked");
    }

    [Test]
    public async Task ACallbackWithoutAFlowCookieIsRefused()
    {
        using var app = new BrokerApp();
        using var browser = app.CreateClient();

        var response = await browser.GetAsync("/youauth/callback?identity=x&public_key=y&salt=z&state=w");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        Assert.That(await response.Content.ReadAsStringAsync(), Does.Contain("expired").IgnoreCase);
    }

    [Test]
    public async Task YouAuth060_TheOwnerDecliningRejectsTheHydraLogin()
    {
        using var app = new BrokerApp();
        using var browser = app.CreateClient();
        var authorize = (await PostIdentityAsync(browser, "ch1", Frodo)).Headers.Location!;
        var state = QueryHelpers.ParseQuery(authorize.Query)["state"].ToString();

        var response = await browser.GetAsync($"/youauth/callback?error=cancelled-by-user&error_description=Sam+declined&state={state}");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        var (challenge, body) = app.Hydra.LoginRejects.Single();
        Assert.That(challenge, Is.EqualTo("ch1"));
        Assert.That(FakeHydraAdmin.Field(body, "error"), Is.EqualTo("access_denied"), "OAuth's word for it, so the relying party understands");
        Assert.That(FakeHydraAdmin.Field(body, "error_description"), Does.Contain("cancelled-by-user"));
        Assert.That(app.Hydra.LoginAccepts, Is.Empty);
    }

    [Test]
    public async Task ConsentGrantsWhatWasRequested()
    {
        using var app = new BrokerApp();
        app.Hydra.RequestedScope = ["openid", "offline"];
        using var browser = app.CreateClient();

        var response = await browser.GetAsync("/consent?consent_challenge=co1");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        Assert.That(response.Headers.Location!.ToString(), Is.EqualTo(FakeHydraAdmin.RedirectTo));
        var (challenge, body) = app.Hydra.ConsentAccepts.Single();
        Assert.That(challenge, Is.EqualTo("co1"));
        Assert.That(body, Does.Contain("\"grant_scope\":[\"openid\",\"offline\"]"), body);
    }

    [Test]
    public async Task LogoutIsAccepted()
    {
        using var app = new BrokerApp();
        using var browser = app.CreateClient();

        var response = await browser.GetAsync("/logout?logout_challenge=lo1");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        Assert.That(app.Hydra.LogoutAccepts.Single().challenge, Is.EqualTo("lo1"));
    }

    [Test]
    public async Task ThisAppPublishesItsOwnYouAuthClientDocument()
    {
        using var app = new BrokerApp();
        using var browser = app.CreateClient();

        var response = await browser.GetAsync("/.well-known/youauth-client.json");
        var json = await response.Content.ReadAsStringAsync();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(response.Content.Headers.ContentType?.MediaType, Is.EqualTo("application/json"));
        Assert.That(json, Is.EqualTo($$"""{"name":"Homebase Sign-in","redirect_uris":["https://{{app.PublicHost}}/youauth/callback"]}"""),
            "what the identity reads to pin the callback and name this app on the consent page");
    }

    [Test]
    public async Task HealthAnswers()
    {
        using var app = new BrokerApp();
        using var browser = app.CreateClient();
        Assert.That((await browser.GetAsync("/healthz")).StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    // ---------------------------------------------------------------------------------------

    /// <summary>GET the page for its antiforgery token, then POST the identity as the form does.</summary>
    private static async Task<HttpResponseMessage> PostIdentityAsync(HttpClient browser, string challenge, string identity)
    {
        var page = await browser.GetAsync($"/login?login_challenge={challenge}");
        var html = await page.Content.ReadAsStringAsync();
        Assert.That(page.StatusCode, Is.EqualTo(HttpStatusCode.OK), html);
        var token = Regex.Match(html, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value;
        Assert.That(token, Is.Not.Empty, "the login form carries an antiforgery token");

        return await browser.PostAsync("/login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = token,
            ["login_challenge"] = challenge,
            ["identity"] = identity,
        }));
    }
}
