using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Odin.Oidc.Login.Registration;
using Odin.Oidc.Login.Tests.Fakes;

namespace Odin.Oidc.Login.Tests;

/// <summary>
/// The client document at a URL client's id: what it must say, what is taken from it, and the
/// limits on fetching it, the same as odin-core's for the YouAuth client document but with the
/// draft's 5 KB and its rule that a missing or invalid document stops the request.
/// </summary>
[TestFixture]
public class ClientDocumentTests
{
    private const string Id = "https://jean.example/wiki";

    private static ClientDocumentFetcher Fetcher(FakeWeb web) =>
        new(new SingleClientFactory(web.Handler), NullLogger<ClientDocumentFetcher>.Instance);

    private static UrlClient Client(string id = Id)
    {
        UrlClient.TryParse(id, out var client);
        return client!;
    }

    [Test]
    public async Task AValidDocumentIsTheRegistration()
    {
        var web = new FakeWeb();
        web.Document(Id, """{"client_id":"https://jean.example/wiki","client_name":"  Jean's\u0007 wiki  ","redirect_uris":["https://jean.example/cb","https://evil.example/cb"],"scope":"openid profile email","token_endpoint_auth_method":"none"}""");

        var doc = await Fetcher(web).FetchAsync(Client(), CancellationToken.None);

        Assert.That(doc.RedirectUris, Is.EqualTo(new[] { "https://jean.example/cb" }), "only callbacks on the client's own origin");
        Assert.That(doc.Name, Is.EqualTo("Jean's wiki"), "trimmed, control characters removed");
        Assert.That(doc.Scope, Is.EqualTo(new[] { "openid", "profile" }), "intersected with what this broker offers; email is not");
    }

    [Test]
    public async Task OnlyTheClientIdAndCallbacksAreRequired()
    {
        var web = new FakeWeb();
        web.Document(Id, """{"client_id":"https://jean.example/wiki","redirect_uris":["https://jean.example/cb"]}""");

        var doc = await Fetcher(web).FetchAsync(Client(), CancellationToken.None);

        Assert.That(doc.Name, Is.Null);
        Assert.That(doc.Scope, Is.EqualTo(new[] { "openid" }), "the default when the document names none");
    }

    [Test]
    public async Task ALongNameIsCapped()
    {
        var web = new FakeWeb();
        web.Document(Id, "x".PadLeft(200, 'n'), "https://jean.example/cb");

        var doc = await Fetcher(web).FetchAsync(Client(), CancellationToken.None);

        Assert.That(doc.Name, Has.Length.EqualTo(64));
    }

    [Test]
    public async Task TheCacheLifetimeFollowsTheDocumentsHeaderWithinBounds()
    {
        var web = new FakeWeb();
        web.Document(Id, "Wiki", "https://jean.example/cb");
        web.Answers[Id].Headers.TryAddWithoutValidation("Cache-Control", "max-age=7200");
        Assert.That((await Fetcher(web).FetchAsync(Client(), CancellationToken.None)).CacheFor, Is.EqualTo(TimeSpan.FromHours(2)));

        web.Answers[Id].Headers.Remove("Cache-Control");
        web.Answers[Id].Headers.TryAddWithoutValidation("Cache-Control", "max-age=10");
        Assert.That((await Fetcher(web).FetchAsync(Client(), CancellationToken.None)).CacheFor, Is.EqualTo(TimeSpan.FromMinutes(5)), "never below five minutes");

        web.Answers[Id].Headers.Remove("Cache-Control");
        web.Answers[Id].Headers.TryAddWithoutValidation("Cache-Control", "max-age=999999");
        Assert.That((await Fetcher(web).FetchAsync(Client(), CancellationToken.None)).CacheFor, Is.EqualTo(TimeSpan.FromDays(1)), "never above a day");

        web.Answers[Id].Headers.Remove("Cache-Control");
        Assert.That((await Fetcher(web).FetchAsync(Client(), CancellationToken.None)).CacheFor, Is.EqualTo(TimeSpan.FromHours(1)), "an hour when it says nothing");
    }

    [TestCase("""{"client_id":"https://jean.example/other","redirect_uris":["https://jean.example/cb"]}""", "client_id")]
    [TestCase("""{"client_id":"https://jean.example/wiki"}""", "redirect_uris")]
    [TestCase("""{"client_id":"https://jean.example/wiki","redirect_uris":["https://evil.example/cb"]}""", "redirect_uris")]
    [TestCase("""{"client_id":"https://jean.example/wiki","redirect_uris":["https://jean.example/cb"],"token_endpoint_auth_method":"client_secret_basic"}""", "token_endpoint_auth_method")]
    [TestCase("not json", "JSON")]
    public void AnInvalidDocumentIsRefusedNamingWhy(string json, string names)
    {
        var web = new FakeWeb();
        web.Document(Id, json);

        Assert.That(() => Fetcher(web).FetchAsync(Client(), CancellationToken.None),
            Throws.InstanceOf<ClientDocumentException>().With.Message.Contains(names));
    }

    [Test]
    public void NoDocumentIsARefusalNotAFallback()
    {
        var web = new FakeWeb();

        Assert.That(() => Fetcher(web).FetchAsync(Client(), CancellationToken.None),
            Throws.InstanceOf<ClientDocumentException>().With.Message.Contains("404"),
            "the draft: the document is the registration; without it there is nothing to trust");
    }

    [Test]
    public void ARedirectAnswerIsNotFollowed()
    {
        var web = new FakeWeb();
        var moved = new HttpResponseMessage(HttpStatusCode.MovedPermanently);
        moved.Headers.Location = new Uri("https://jean.example/elsewhere");
        web.Answers[Id] = moved;

        Assert.That(() => Fetcher(web).FetchAsync(Client(), CancellationToken.None),
            Throws.InstanceOf<ClientDocumentException>().With.Message.Contains("301"));
    }

    [Test]
    public void ADocumentOverFiveKilobytesIsRefused()
    {
        var web = new FakeWeb();
        web.Document(Id, "{\"client_id\":\"https://jean.example/wiki\",\"redirect_uris\":[\"https://jean.example/cb\"],\"padding\":\"" + new string('p', 6000) + "\"}");

        Assert.That(() => Fetcher(web).FetchAsync(Client(), CancellationToken.None),
            Throws.InstanceOf<ClientDocumentException>());
    }

    private sealed class SingleClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false) { MaxResponseContentBufferSize = ClientDocumentFetcher.MaxBytes };
    }
}
