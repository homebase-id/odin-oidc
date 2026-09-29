using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Odin.Oidc.Login.Registration;
using Odin.Oidc.Login.Try;

namespace Odin.Oidc.Login.Tests;

/// <summary>
/// The try-it relying party: this app signing in through itself as a URL client, so a deployment
/// can be verified end to end from a browser with nothing registered by hand.
/// </summary>
[TestFixture]
public class TryPageTests
{
    private const string Origin = "https://oidc.example.org";
    private const string ClientId = Origin + "/try/client.json";
    private const string Callback = Origin + "/try/callback";

    [Test]
    public async Task ItsClientDocumentPassesTheBrokersOwnRules()
    {
        using var app = new BrokerApp();
        using var browser = app.CreateClient();

        var response = await browser.GetAsync("/try/client.json");
        var json = await response.Content.ReadAsStringAsync();

        Assert.That(response.Content.Headers.ContentType?.MediaType, Is.EqualTo("application/json"));
        Assert.That(response.Headers.CacheControl?.MaxAge, Is.EqualTo(TimeSpan.FromHours(1)));
        Assert.That(UrlClient.TryParse(ClientId, out var client), Is.True);
        var document = ClientDocumentFetcher.Parse(client!, json, TimeSpan.Zero);
        Assert.That(document.RedirectUris, Is.EqualTo(new[] { Callback }));
        Assert.That(document.Name, Is.EqualTo("Try it"));
        Assert.That(document.Scope, Is.EqualTo(new[] { "openid", "profile" }));
    }

    [Test]
    public async Task TheGatewayRegistersItFromThatDocumentLikeAnyOtherSite()
    {
        using var app = new BrokerApp();
        using var browser = app.CreateClient();
        app.Web.Document(ClientId, await (await browser.GetAsync("/try/client.json")).Content.ReadAsStringAsync());

        var start = await Start(browser);
        var authorize = await browser.GetAsync(start.Headers.Location!);

        Assert.That(authorize.StatusCode, Is.EqualTo(HttpStatusCode.Found), await authorize.Content.ReadAsStringAsync());
        Assert.That(app.Web.Requests, Is.EqualTo(new[] { ClientId }), "fetched over the public origin, as for any site");
        var created = JsonDocument.Parse(app.Hydra.ClientCreates.Single()).RootElement;
        Assert.That(created.GetProperty("client_id").GetString(), Is.EqualTo(ClientId));
        Assert.That(created.GetProperty("redirect_uris")[0].GetString(), Is.EqualTo(Callback));
    }

    [Test]
    public async Task StartingSendsTheBrowserToTheAuthorizeEndpointWithPkceAndAFlowCookie()
    {
        using var app = new BrokerApp();
        using var browser = app.CreateClient();

        var response = await Start(browser);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        var location = response.Headers.Location!;
        Assert.That(location.GetLeftPart(UriPartial.Path), Is.EqualTo(Origin + "/oauth2/auth"), "through the public origin, so the gateway and the document fetch are exercised");
        var query = QueryHelpers.ParseQuery(location.Query);
        Assert.That(query["client_id"].ToString(), Is.EqualTo(ClientId));
        Assert.That(query["redirect_uri"].ToString(), Is.EqualTo(Callback));
        Assert.That(query["scope"].ToString(), Is.EqualTo("openid profile"));
        Assert.That(query["code_challenge_method"].ToString(), Is.EqualTo("S256"));
        Assert.That(query["code_challenge"].ToString(), Has.Length.EqualTo(43));
        Assert.That(query["state"].ToString(), Is.Not.Empty);
        Assert.That(query["nonce"].ToString(), Is.Not.Empty);
        Assert.That(response.Headers.GetValues("Set-Cookie").Single(), Does.StartWith($"{TryFlowCookie.Name}=").And.Contain("httponly").IgnoreCase.And.Contain("secure").IgnoreCase);
    }

    [Test]
    public async Task TheCallbackExchangesTheCodeAndShowsTheClaims()
    {
        using var app = new BrokerApp();
        using var browser = app.CreateClient();
        var start = await Start(browser);
        var query = QueryHelpers.ParseQuery(start.Headers.Location!.Query);
        app.Hydra.PublicAuthorizes.Add(start.Headers.Location.PathAndQuery); // Hydra saw the authorize (the fake's token answer takes the nonce from it)

        var response = await browser.GetAsync($"/try/callback?code=code-1&state={query["state"]}");
        var html = await response.Content.ReadAsStringAsync();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK), html);
        var token = QueryHelpers.ParseQuery("?" + app.Hydra.TokenRequests.Single());
        Assert.That(token["grant_type"].ToString(), Is.EqualTo("authorization_code"));
        Assert.That(token["code"].ToString(), Is.EqualTo("code-1"));
        Assert.That(token["client_id"].ToString(), Is.EqualTo(ClientId));
        Assert.That(token["redirect_uri"].ToString(), Is.EqualTo(Callback));
        Assert.That(WebEncoders.Base64UrlEncode(SHA256.HashData(Encoding.ASCII.GetBytes(token["code_verifier"].ToString()))), Is.EqualTo(query["code_challenge"].ToString()), "the verifier the cookie kept is the one the challenge was made from");
        Assert.That(app.Hydra.UserinfoBearers, Is.EqualTo(new[] { "at-1" }));
        Assert.That(html, Does.Contain($"Signed in as <strong>{BrokerApp.Frodo}</strong>").And.Contain("<th>did</th>").And.Contain($"did:web:{BrokerApp.Frodo}").And.Contain("Frodo Baggins"));
        Assert.That(response.Headers.GetValues("Set-Cookie").Single(), Does.StartWith($"{TryFlowCookie.Name}=").And.Contain("expires=").IgnoreCase, "the flow is over");
    }

    [Test]
    public async Task ACallbackForAFlowNotStartedHereIsStopped()
    {
        using var app = new BrokerApp();
        using var browser = app.CreateClient();
        await Start(browser);

        var noCookie = await app.CreateClient().GetAsync("/try/callback?code=c&state=s");
        var wrongState = await browser.GetAsync("/try/callback?code=c&state=not-mine");

        Assert.That(noCookie.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        Assert.That(wrongState.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        Assert.That(app.Hydra.TokenRequests, Is.Empty);
    }

    [Test]
    public async Task ARefusalIsShownNotThrown()
    {
        using var app = new BrokerApp();
        using var browser = app.CreateClient();
        var start = await Start(browser);
        var state = QueryHelpers.ParseQuery(start.Headers.Location!.Query)["state"];

        var response = await browser.GetAsync($"/try/callback?error=access_denied&error_description=The+user+said+no&state={state}");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(await response.Content.ReadAsStringAsync(), Does.Contain("refused").And.Contain("access_denied: The user said no"));
        Assert.That(app.Hydra.TokenRequests, Is.Empty);
    }

    [Test]
    public async Task AnIdTokenWithAnotherNonceIsStopped()
    {
        using var app = new BrokerApp();
        using var browser = app.CreateClient();
        var start = await Start(browser);
        var state = QueryHelpers.ParseQuery(start.Headers.Location!.Query)["state"];
        app.Hydra.PublicAuthorizes.Add("/oauth2/auth?nonce=somebody-elses");

        var response = await browser.GetAsync($"/try/callback?code=c&state={state}");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        Assert.That(await response.Content.ReadAsStringAsync(), Does.Contain("nonce"));
    }

    private static async Task<HttpResponseMessage> Start(HttpClient browser)
    {
        var page = await (await browser.GetAsync("/try")).Content.ReadAsStringAsync();
        Assert.That(page, Does.Contain("Sign in with Homebase"));
        return await BrokerApp.PostFormAsync(browser, "/try", page, []);
    }
}
