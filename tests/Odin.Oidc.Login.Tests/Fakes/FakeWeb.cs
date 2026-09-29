using System.Net;

namespace Odin.Oidc.Login.Tests.Fakes;

/// <summary>The web as the client-document fetcher sees it: a few URLs with canned answers, everything else 404.</summary>
public sealed class FakeWeb
{
    public Dictionary<string, HttpResponseMessage> Answers { get; } = new();
    public List<string> Requests { get; } = [];
    public RecordingHandler Handler { get; }

    public FakeWeb()
    {
        Handler = new RecordingHandler((request, _) =>
        {
            var url = request.RequestUri!.ToString();
            Requests.Add(url);
            return Task.FromResult(Answers.TryGetValue(url, out var answer)
                ? Clone(answer)
                : new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new StringContent("no such document") });
        });
    }

    public void Document(string url, string json) => Answers[url] = RecordingHandler.Json(HttpStatusCode.OK, json);

    /// <summary>A minimal valid client document for <paramref name="clientId"/> with these callbacks.</summary>
    public void Document(string clientId, string name, params string[] redirectUris) =>
        Document(clientId, System.Text.Json.JsonSerializer.Serialize(new { client_id = clientId, client_name = name, redirect_uris = redirectUris }));

    private static HttpResponseMessage Clone(HttpResponseMessage answer)
    {
        var copy = new HttpResponseMessage(answer.StatusCode);
        if (answer.Content is StringContent)
        {
            var text = answer.Content.ReadAsStringAsync().Result;
            copy.Content = new StringContent(text, System.Text.Encoding.UTF8, answer.Content.Headers.ContentType?.MediaType ?? "text/plain");
        }
        foreach (var header in answer.Headers)
        {
            copy.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }
        return copy;
    }
}
