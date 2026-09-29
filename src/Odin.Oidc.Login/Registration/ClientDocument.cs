#pragma warning disable CS9113
namespace Odin.Oidc.Login.Registration;

public sealed record ClientDocument(string ClientId, IReadOnlyList<string> RedirectUris, string? Name, IReadOnlyList<string> Scope, TimeSpan CacheFor);

public sealed class ClientDocumentException(string message) : Exception(message);

public sealed class ClientDocumentFetcher(IHttpClientFactory httpClientFactory, ILogger<ClientDocumentFetcher> logger)
{
    public const string HttpClientName = "client-documents";
    public const int MaxBytes = 5 * 1024;

    public Task<ClientDocument> FetchAsync(UrlClient client, CancellationToken ct) => throw new NotImplementedException();
}
