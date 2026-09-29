using System.Net;

namespace Odin.Oidc.Login.Tests.Fakes;

/// <summary>The web as the client-document fetcher sees it: a few URLs with canned answers, everything else 404.</summary>
public sealed class FakeWeb
{
    /// <summary>A fresh message per request, since the fetcher disposes what it gets.</summary>
    public Dictionary<string, Func<HttpResponseMessage>> Answers { get; } = new();
    public List<string> Requests { get; } = [];
    public RecordingHandler Handler { get; }

    /// <summary>An IHttpClientFactory with the fetcher's buffer limit, for testing it on its own.</summary>
    public IHttpClientFactory ClientFactory =>
        new SingleClientFactory(Handler, http => http.MaxResponseContentBufferSize = Login.Registration.ClientDocumentFetcher.MaxBytes);

    public FakeWeb()
    {
        Handler = new RecordingHandler((request, _) =>
        {
            var url = request.RequestUri!.ToString();
            Requests.Add(url);
            return Task.FromResult(Answers.TryGetValue(url, out var answer)
                ? answer()
                : new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new StringContent("no such document") });
        });
    }

    public void Document(string url, string json, string? cacheControl = null) => Answers[url] = () =>
    {
        var response = RecordingHandler.Json(HttpStatusCode.OK, json);
        if (cacheControl != null)
        {
            response.Headers.TryAddWithoutValidation("Cache-Control", cacheControl);
        }
        return response;
    };

    /// <summary>A minimal valid client document for <paramref name="clientId"/> with these callbacks.</summary>
    public void ValidDocument(string clientId, string name, params string[] redirectUris) =>
        Document(clientId, System.Text.Json.JsonSerializer.Serialize(new { client_id = clientId, client_name = name, redirect_uris = redirectUris }));
}
