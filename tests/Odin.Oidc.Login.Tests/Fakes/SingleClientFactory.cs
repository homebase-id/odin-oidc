namespace Odin.Oidc.Login.Tests.Fakes;

/// <summary>An IHttpClientFactory whose every client talks to one handler, for a service tested on its own.</summary>
public sealed class SingleClientFactory(HttpMessageHandler handler, Action<HttpClient>? configure = null) : IHttpClientFactory
{
    public HttpClient CreateClient(string name)
    {
        var client = new HttpClient(handler, disposeHandler: false);
        configure?.Invoke(client);
        return client;
    }
}
