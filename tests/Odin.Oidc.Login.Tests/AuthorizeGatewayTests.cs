using System.Net;
using System.Text.Json;
using Odin.Oidc.Login.Tests.Fakes;

namespace Odin.Oidc.Login.Tests;

/// <summary>
/// The gateway in front of Hydra's authorize endpoint: an operator-registered client passes
/// through; a URL client is registered in Hydra from its document on first sight, then passes
/// through; and the discovery document is Hydra's with two changes.
/// </summary>
[TestFixture]
public class AuthorizeGatewayTests
{
    private const string Jean = "https://jean.example/wiki";
    private const string JeanCallback = "https://jean.example/cb";

    private static string Authorize(string clientId, string redirectUri) =>
        $"/oauth2/auth?client_id={Uri.EscapeDataString(clientId)}&redirect_uri={Uri.EscapeDataString(redirectUri)}&response_type=code&scope=openid&state=s&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256";

    [Test]
    public async Task AnOperatorClientPassesThroughUntouched()
    {
        using var app = new BrokerApp();
        using var browser = app.CreateClient();

        var response = await browser.GetAsync(Authorize("2d78140138044b57b4aad8e4e2ef39f4", "https://app.example/cb"));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Found));
        Assert.That(response.Headers.Location!.ToString(), Is.EqualTo(FakeHydraAdmin.RedirectTo), "Hydra's answer, relayed");
        Assert.That(response.Headers.GetValues("Set-Cookie").Single(), Is.EqualTo(FakeHydraAdmin.PublicCookie), "Hydra's CSRF cookie reaches the browser");
        Assert.That(app.Hydra.PublicAuthorizes.Single(), Does.Contain("client_id=2d78140138044b57b4aad8e4e2ef39f4").And.Contain("code_challenge="));
        Assert.That(app.Web.Requests, Is.Empty);
        Assert.That(app.Hydra.ClientCreates, Is.Empty);
    }

    [Test]
    public async Task AUrlClientIsRegisteredFromItsDocumentOnFirstSightThenPassedThrough()
    {
        using var app = new BrokerApp();
        app.Web.Document(Jean, "Jean's wiki", JeanCallback, "https://jean.example/cb2");
        using var browser = app.CreateClient();

        var response = await browser.GetAsync(Authorize(Jean, JeanCallback));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Found), await response.Content.ReadAsStringAsync());
        var created = JsonDocument.Parse(app.Hydra.ClientCreates.Single()).RootElement;
        Assert.That(created.GetProperty("client_id").GetString(), Is.EqualTo(Jean), "the URL is the id, in Hydra too");
        Assert.That(created.GetProperty("client_name").GetString(), Is.EqualTo("Jean's wiki"));
        Assert.That(created.GetProperty("redirect_uris").EnumerateArray().Select(e => e.GetString()), Is.EqualTo(new[] { JeanCallback, "https://jean.example/cb2" }));
        Assert.That(created.GetProperty("token_endpoint_auth_method").GetString(), Is.EqualTo("none"), "public, PKCE");
        Assert.That(created.GetProperty("grant_types").EnumerateArray().Select(e => e.GetString()), Is.EqualTo(new[] { "authorization_code", "refresh_token" }));
        Assert.That(created.GetProperty("response_types").EnumerateArray().Select(e => e.GetString()), Is.EqualTo(new[] { "code" }));
        Assert.That(created.GetProperty("scope").GetString(), Is.EqualTo("openid"));
        Assert.That(created.GetProperty("metadata").GetProperty("registered").GetString(), Is.EqualTo("by-url"), "told apart from operator-registered clients");
        Assert.That(app.Hydra.PublicAuthorizes.Single(), Does.Contain("client_id=https%3A%2F%2Fjean.example%2Fwiki"));
    }

    [Test]
    public async Task ASecondSightWithinTheCacheLifetimeNeitherFetchesNorCreates()
    {
        using var app = new BrokerApp();
        app.Web.Document(Jean, "Jean's wiki", JeanCallback);
        using var browser = app.CreateClient();

        await browser.GetAsync(Authorize(Jean, JeanCallback));
        await browser.GetAsync(Authorize(Jean, JeanCallback));

        Assert.That(app.Web.Requests, Has.Count.EqualTo(1));
        Assert.That(app.Hydra.ClientCreates, Has.Count.EqualTo(1));
        Assert.That(app.Hydra.PublicAuthorizes, Has.Count.EqualTo(2));
    }

    [Test]
    public async Task AKnownClientWhoseDocumentChangedIsUpdated()
    {
        using var app = new BrokerApp();
        app.Web.Document(Jean, "Jean's wiki", JeanCallback);
        app.Hydra.Clients[Jean] = JsonSerializer.Serialize(new { client_id = Jean, client_name = "Old name", redirect_uris = new[] { "https://jean.example/old" }, metadata = new { registered = "by-url" } });
        using var browser = app.CreateClient();

        var response = await browser.GetAsync(Authorize(Jean, JeanCallback));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Found));
        Assert.That(app.Hydra.ClientCreates, Is.Empty);
        var updated = JsonDocument.Parse(app.Hydra.ClientUpdates.Single()).RootElement;
        Assert.That(updated.GetProperty("redirect_uris").EnumerateArray().Select(e => e.GetString()), Is.EqualTo(new[] { JeanCallback }), "a site adds or moves a callback by editing its document");
        Assert.That(updated.GetProperty("client_name").GetString(), Is.EqualTo("Jean's wiki"));
    }

    [Test]
    public async Task ACallbackTheDocumentDoesNotListIsRefusedAtTheBroker()
    {
        using var app = new BrokerApp();
        app.Web.Document(Jean, "Jean's wiki", JeanCallback);
        using var browser = app.CreateClient();

        var response = await browser.GetAsync(Authorize(Jean, "https://jean.example/elsewhere"));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest), "the redirect is not trusted, so nobody is sent there, not even with an error");
        Assert.That(await response.Content.ReadAsStringAsync(), Does.Contain("jean.example/elsewhere"));
        Assert.That(app.Hydra.PublicAuthorizes, Is.Empty);
    }

    [Test]
    public async Task NoDocumentIsARefusalThatSaysWhatWasExpected()
    {
        using var app = new BrokerApp();
        using var browser = app.CreateClient();

        var response = await browser.GetAsync(Authorize(Jean, JeanCallback));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        Assert.That(await response.Content.ReadAsStringAsync(), Does.Contain(Jean).And.Contain("404"));
        Assert.That(app.Hydra.ClientCreates, Is.Empty);
        Assert.That(app.Hydra.PublicAuthorizes, Is.Empty);
    }

    [Test]
    public async Task TheLocalhostDevelopmentClientIsRefusedUnlessAllowed()
    {
        var localhost = "http://localhost?redirect_uri=http%3A%2F%2F127.0.0.1%2Fcb";

        using (var app = new BrokerApp())
        using (var browser = app.CreateClient())
        {
            var response = await browser.GetAsync(Authorize(localhost, "http://127.0.0.1:5556/cb"));
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest), "production: a loopback client id is never a relying party");
            Assert.That(app.Hydra.ClientCreates, Is.Empty);
        }

        using (var app = new BrokerApp())
        {
            app.Settings["Broker:AllowLocalhostClients"] = "true";
            using var browser = app.CreateClient();
            var response = await browser.GetAsync(Authorize(localhost, "http://127.0.0.1:5556/cb"));
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Found));
            Assert.That(app.Web.Requests, Is.Empty, "never fetched");
            var created = JsonDocument.Parse(app.Hydra.ClientCreates.Single()).RootElement;
            Assert.That(created.GetProperty("redirect_uris").EnumerateArray().Select(e => e.GetString()), Is.EqualTo(new[] { "http://127.0.0.1:5556/cb" }), "the callback as used, port included, since Hydra matches exactly");
        }
    }

    [Test]
    public async Task DiscoveryIsHydrasWithTheGatewayAsAuthorizeEndpointAndTheDraftsMember()
    {
        using var app = new BrokerApp();
        using var browser = app.CreateClient();

        var response = await browser.GetAsync("/.well-known/openid-configuration");
        var discovery = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(response.Content.Headers.ContentType?.MediaType, Is.EqualTo("application/json"));
        Assert.That(discovery.GetProperty("issuer").GetString(), Is.EqualTo("http://hydra:4444/"), "Hydra's, untouched");
        Assert.That(discovery.GetProperty("authorization_endpoint").GetString(), Is.EqualTo($"https://{app.PublicHost}/oauth2/auth"), "through this app");
        Assert.That(discovery.GetProperty("token_endpoint").GetString(), Is.EqualTo("http://hydra:4444/oauth2/token"), "Hydra's");
        Assert.That(discovery.GetProperty("client_id_metadata_document_supported").GetBoolean(), Is.True);
    }
}
