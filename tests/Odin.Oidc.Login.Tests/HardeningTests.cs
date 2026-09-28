using System.Net;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Odin.Oidc.Login.Tests.Fakes;

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

    private static HttpRequestMessage From(string address, string path, string? forwardedProto = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Add(BrokerApp.RemoteAddressHeader, address);
        if (forwardedProto != null)
        {
            request.Headers.Add("X-Forwarded-Proto", forwardedProto);
        }
        return request;
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
        using var browser = app.CreateClient();

        var viaProxy = await browser.SendAsync(From("10.1.2.3", "/healthz", forwardedProto: "https"));
        var direct = await browser.SendAsync(From("192.168.1.9", "/healthz", forwardedProto: "https"));

        Assert.That(viaProxy.Headers.Contains("Strict-Transport-Security"), Is.True, "the proxy said https, and it is believed");
        Assert.That(direct.Headers.Contains("Strict-Transport-Security"), Is.False, "anyone else saying https is not; the request stays http");
    }

    [Test]
    public async Task WithNoTrustedProxyNothingForwardedIsBelieved()
    {
        using var app = new BrokerApp();
        app.ClientOptions.BaseAddress = new Uri("http://localhost");
        using var browser = app.CreateClient();

        var response = await browser.SendAsync(From("10.1.2.3", "/healthz", forwardedProto: "https"));

        Assert.That(response.Headers.Contains("Strict-Transport-Security"), Is.False, "the safe default for a public repo: trust nobody until configured");
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
        Assert.That(html, Does.Contain("site.css"));
    }

    // ---------------------------------------------------------------------------------------
    // How much one address may do
    // ---------------------------------------------------------------------------------------

    [Test]
    public async Task OneAddressIsSlowedDownAfterItsShareOfFormPosts()
    {
        using var app = new BrokerApp();
        app.Settings["Broker:FormPostsPerMinute"] = "3";
        using var browser = app.CreateClient();

        var page = await browser.SendAsync(From("203.0.113.7", "/login?login_challenge=ch1"));
        var html = await page.Content.ReadAsStringAsync();
        HttpResponseMessage? last = null;
        for (var i = 0; i < 4; i++)
        {
            last = await PostLoginAsync(browser, html, "203.0.113.7", "not a domain");
        }

        Assert.That(last!.StatusCode, Is.EqualTo(HttpStatusCode.TooManyRequests), "the fourth post from one address in a minute");
        Assert.That(await last.Content.ReadAsStringAsync(), Does.Contain("slow down").IgnoreCase);

        var other = await PostLoginAsync(browser, html, "203.0.113.8", "not a domain");
        Assert.That(other.StatusCode, Is.EqualTo(HttpStatusCode.OK), "another address is not affected");
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
        var page = await browser.GetAsync("/login?login_challenge=ch1");
        var authorize = (await PostLoginAsync(browser, await page.Content.ReadAsStringAsync(), "203.0.113.7", Frodo)).Headers.Location!;
        var callback = app.Identity.Authorize(authorize);
        await browser.GetAsync(QueryHelpers.AddQueryString("/youauth/callback", callback!));
        await browser.GetAsync("/consent?consent_challenge=co1");

        var atInformationOrAbove = app.Logs.Where(l => l.level >= LogLevel.Information && l.category.StartsWith("Odin.")).ToList();
        Assert.That(atInformationOrAbove, Is.Not.Empty, "the login is still recorded");
        Assert.That(atInformationOrAbove.Select(l => l.message), Has.None.Contains(Frodo),
            "identity domains are the sensitive datum; they are Debug, which is off in production");
        Assert.That(app.Logs.Where(l => l.level == LogLevel.Debug).Select(l => l.message), Has.Some.Contains(Frodo), "and Debug has them for an incident");
    }

    // ---------------------------------------------------------------------------------------

    private static async Task<HttpResponseMessage> PostLoginAsync(HttpClient browser, string pageHtml, string address, string identity)
    {
        var token = System.Text.RegularExpressions.Regex.Match(pageHtml, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value;
        var request = new HttpRequestMessage(HttpMethod.Post, "/login")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["__RequestVerificationToken"] = token,
                ["login_challenge"] = "ch1",
                ["identity"] = identity,
            }),
        };
        request.Headers.Add(BrokerApp.RemoteAddressHeader, address);
        return await browser.SendAsync(request);
    }
}
