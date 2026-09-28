using System.Net;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;

namespace Odin.Oidc.Login.Tests;

/// <summary>
/// The app behind a TLS proxy on the open internet: whom it believes about the scheme and the
/// client's address, what it tells browsers, how much it takes from one address, what health means,
/// and what it writes to the log.
/// </summary>
[TestFixture]
public class HardeningTests
{
    private const string Frodo = BrokerApp.Frodo;

    /// <summary>A browser at one address; the app sees it as the connection's remote address.</summary>
    private static HttpClient BrowserAt(BrokerApp app, string address, string? forwardedProto = null)
    {
        var browser = app.CreateClient();
        browser.DefaultRequestHeaders.Add(BrokerApp.RemoteAddressHeader, address);
        if (forwardedProto != null)
        {
            browser.DefaultRequestHeaders.Add("X-Forwarded-Proto", forwardedProto);
        }
        return browser;
    }

    // ---------------------------------------------------------------------------------------
    // The proxy
    // ---------------------------------------------------------------------------------------

    [Test]
    public async Task AForwardedProtoIsBelievedFromTheTrustedProxyNetworkOnly()
    {
        using var app = new BrokerApp();
        app.Settings["Broker:TrustedProxyNetworks:0"] = "10.0.0.0/8";
        app.ClientOptions.BaseAddress = new Uri("http://localhost"); // plain http, as behind a proxy
        using var viaProxy = BrowserAt(app, "10.1.2.3", forwardedProto: "https");
        using var direct = BrowserAt(app, "192.168.1.9", forwardedProto: "https");

        Assert.That((await viaProxy.GetAsync("/healthz")).Headers.Contains("Strict-Transport-Security"), Is.True, "the proxy said https, and it is believed");
        Assert.That((await direct.GetAsync("/healthz")).Headers.Contains("Strict-Transport-Security"), Is.False, "anyone else saying https is not; the request stays http");
    }

    [Test]
    public async Task WithNoTrustedProxyNothingForwardedIsBelieved()
    {
        using var app = new BrokerApp();
        app.ClientOptions.BaseAddress = new Uri("http://localhost");
        using var browser = BrowserAt(app, "10.1.2.3", forwardedProto: "https");

        Assert.That((await browser.GetAsync("/healthz")).Headers.Contains("Strict-Transport-Security"), Is.False, "the safe default for a public repo: trust nobody until configured");
        Assert.That(app.Logs.Select(l => l.message), Has.Some.Contains("Believing no X-Forwarded-*"), "and the mode is said at startup, so a first deploy sees it");
    }

    // ---------------------------------------------------------------------------------------
    // What browsers are told
    // ---------------------------------------------------------------------------------------

    [Test]
    public async Task ThePagesCarrySecurityHeadersAndAreNotCached()
    {
        using var app = new BrokerApp();
        using var browser = app.CreateClient();

        var response = await browser.GetAsync("/login?login_challenge=ch1");
        var html = await response.Content.ReadAsStringAsync();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), html);
        Assert.That(response.Headers.GetValues("Content-Security-Policy").Single(),
            Does.Contain("default-src 'self'").And.Contain("frame-ancestors 'none'").And.Contain("form-action 'self'").And.Not.Contain("unsafe-inline"));
        Assert.That(response.Headers.GetValues("X-Content-Type-Options").Single(), Is.EqualTo("nosniff"));
        Assert.That(response.Headers.GetValues("Referrer-Policy").Single(), Is.EqualTo("no-referrer"));
        Assert.That(response.Headers.CacheControl?.NoStore, Is.True, "a sign-in page is never served from a cache");
        Assert.That(response.Headers.GetValues("Strict-Transport-Security").Single(), Does.Contain("max-age=31536000"), "the test client speaks https");
        Assert.That(html, Does.Not.Contain("<style"), "no inline style, so the policy needs no unsafe-inline");
        Assert.That(html, Does.Contain("site.css?v="), "the one stylesheet, with a content version");

        var css = await browser.GetAsync("/site.css");
        Assert.That(css.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(css.Headers.CacheControl?.Public, Is.True, "and it may be cached; the version in its link busts it");
    }

    [TestCase("/youauth/callback?state=x", HttpStatusCode.BadRequest)]
    [TestCase("/login?login_challenge=unknown", HttpStatusCode.InternalServerError)]
    public async Task TheErrorPageCarriesTheSameHeaders(string path, HttpStatusCode expected)
    {
        using var app = new BrokerApp();
        app.Hydra.LoginAnswer = HttpStatusCode.NotFound;
        using var browser = app.CreateClient();

        var response = await browser.GetAsync(path);

        Assert.That(response.StatusCode, Is.EqualTo(expected));
        Assert.That(response.Headers.GetValues("Content-Security-Policy").Single(), Does.Contain("frame-ancestors 'none'"),
            "the exception handler rebuilds the response; the headers must be set on the rebuilt one too");
        Assert.That(response.Headers.GetValues("Strict-Transport-Security").Single(), Does.Contain("max-age"));
    }

    // ---------------------------------------------------------------------------------------
    // How much one address may do
    // ---------------------------------------------------------------------------------------

    [Test]
    public async Task OneAddressIsSlowedDownAfterItsShareOfRequests()
    {
        using var app = new BrokerApp();
        app.Settings["Broker:FormPostsPerMinute"] = "3";
        using var browser = BrowserAt(app, "203.0.113.7");
        var html = await (await browser.GetAsync("/login?login_challenge=ch1")).Content.ReadAsStringAsync(); // one of the three

        var second = await BrokerApp.PostFormAsync(browser, "/login", html, new() { ["login_challenge"] = "ch1", ["identity"] = "not a domain" });
        var third = await BrokerApp.PostFormAsync(browser, "/login", html, new() { ["login_challenge"] = "ch1", ["identity"] = "not a domain" });
        var fourth = await BrokerApp.PostFormAsync(browser, "/login", html, new() { ["login_challenge"] = "ch1", ["identity"] = "not a domain" });

        Assert.That(second.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(third.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(fourth.StatusCode, Is.EqualTo(HttpStatusCode.TooManyRequests), "the fourth request from one address in a minute");
        Assert.That(await fourth.Content.ReadAsStringAsync(), Does.Contain("slow down").IgnoreCase);

        using var other = BrowserAt(app, "203.0.113.8");
        Assert.That((await other.GetAsync("/login?login_challenge=ch1")).StatusCode, Is.EqualTo(HttpStatusCode.OK), "another address is not affected");
    }

    // ---------------------------------------------------------------------------------------
    // What health means
    // ---------------------------------------------------------------------------------------

    [Test]
    public async Task HealthMeansHydraIsReadyToo()
    {
        using var app = new BrokerApp();
        using var browser = app.CreateClient();

        Assert.That((await browser.GetAsync("/healthz")).StatusCode, Is.EqualTo(HttpStatusCode.OK));

        app.Hydra.Ready = false;
        var down = await browser.GetAsync("/healthz");
        Assert.That(down.StatusCode, Is.EqualTo(HttpStatusCode.ServiceUnavailable), "a smoke test or an uptime probe must see Hydra's state, not only this process's");
        Assert.That(await down.Content.ReadAsStringAsync(), Does.Contain("hydra").IgnoreCase);
    }

    // ---------------------------------------------------------------------------------------
    // What goes to the log
    // ---------------------------------------------------------------------------------------

    [Test]
    public async Task AtInformationNoLogLineNamesAnIdentity()
    {
        using var app = new BrokerApp();
        using var browser = app.CreateClient();
        var html = await (await browser.GetAsync("/login?login_challenge=ch1")).Content.ReadAsStringAsync();
        var authorize = (await BrokerApp.PostFormAsync(browser, "/login", html, new() { ["login_challenge"] = "ch1", ["identity"] = Frodo })).Headers.Location!;
        var callback = app.Identity.Authorize(authorize);
        await browser.GetAsync(QueryHelpers.AddQueryString("/youauth/callback", callback!));
        await browser.GetAsync("/consent?consent_challenge=co1");

        var atInformationOrAbove = app.Logs.Where(l => l.level >= LogLevel.Information && l.category.StartsWith("Odin.")).ToList();
        Assert.That(atInformationOrAbove, Is.Not.Empty, "the login is still recorded");
        Assert.That(atInformationOrAbove.Select(l => l.message), Has.None.Contains(Frodo),
            "identity domains are the sensitive datum; they are Debug, which is off in production");
        Assert.That(app.Logs.Where(l => l.level == LogLevel.Debug).Select(l => l.message), Has.Some.Contains(Frodo), "and Debug has them for an incident");
    }
}
