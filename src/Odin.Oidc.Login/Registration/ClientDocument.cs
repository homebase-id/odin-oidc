using System.Net;
using System.Text.Json;

namespace Odin.Oidc.Login.Registration;

/// <summary>
/// A URL client's registration, read from the document at its id: the callbacks it may use (only
/// those on its own origin), the name it gives itself, the scope it may ask for, and for how long
/// this may be believed before the document is read again.
/// </summary>
public sealed record ClientDocument(IReadOnlyList<string> RedirectUris, string? Name, IReadOnlyList<string> Scope, TimeSpan CacheFor)
{
    /// <summary>What a document is believed for when it says nothing about caching.</summary>
    public static readonly TimeSpan DefaultCache = TimeSpan.FromHours(1);

    /// <summary>
    /// The callback a request may be sent to: the redirect it named when that is one of the
    /// listed callbacks, the one listed callback when it named none (the draft), else null. The
    /// match is the same string (RFC 9700); an http loopback callback matches on any port, since
    /// a native app picks its port at run time (RFC 8252), and only the development client can
    /// have listed one.
    /// </summary>
    public string? ResolveRedirect(string? requested)
    {
        if (requested == null)
        {
            return RedirectUris.Count == 1 ? RedirectUris[0] : null;
        }
        if (RedirectUris.Contains(requested, StringComparer.Ordinal))
        {
            return requested;
        }
        return Uri.TryCreate(requested, UriKind.Absolute, out var uri) && IsLoopback(requested)
               && RedirectUris.Any(c => Uri.TryCreate(c, UriKind.Absolute, out var allowed)
                                        && allowed.Scheme == uri.Scheme && allowed.Host == uri.Host && allowed.AbsolutePath == uri.AbsolutePath)
            ? requested
            : null;
    }

    public static bool IsLoopback(string redirectUri) =>
        Uri.TryCreate(redirectUri, UriKind.Absolute, out var uri)
        && uri.Scheme == Uri.UriSchemeHttp
        && IPAddress.TryParse(uri.Host.Trim('[', ']'), out var address)
        && IPAddress.IsLoopback(address);
}

/// <summary>The document could not be fetched or says something a URL client may not; the message says what, for the 400 page.</summary>
public sealed class ClientDocumentException(string message) : Exception(message);

/// <summary>
/// One GET of the client id, as the draft prescribes: 200 and JSON only, no redirect followed, a
/// few kilobytes, a few seconds, never from a special-use address (the handler's connect callback,
/// see Program.cs). A missing or invalid document is a refusal, not a fallback: it is the only
/// registration a URL client has.
/// </summary>
public sealed class ClientDocumentFetcher(IHttpClientFactory httpClientFactory, ILogger<ClientDocumentFetcher> logger)
{
    public const string HttpClientName = "client-documents";

    /// <summary>The draft's recommended maximum; a document is a few hundred bytes. Enforced by the HttpClient's buffer size.</summary>
    public const int MaxBytes = 5 * 1024;

    /// <summary>A name is a label, not a page; the same cap as odin-core's client document.</summary>
    public const int MaxNameLength = 64;

    /// <summary>The scopes this broker issues; a document asking for others gets these.</summary>
    public static readonly string[] OfferedScope = ["openid", "offline", "offline_access", "profile"];

    private static readonly TimeSpan MinCache = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan MaxCache = TimeSpan.FromDays(1);

    public async Task<ClientDocument> FetchAsync(UrlClient client, CancellationToken ct)
    {
        HttpResponseMessage response;
        string body;
        try
        {
            using var http = httpClientFactory.CreateClient(HttpClientName);
            response = await http.GetAsync(client.Id, ct);
            body = await response.Content.ReadAsStringAsync(ct);
        }
        catch (Exception e) when (e is HttpRequestException or OperationCanceledException && !ct.IsCancellationRequested)
        {
            // Includes a body over MaxBytes, a refused address, and the timeout.
            logger.LogDebug(e, "No client document from {clientId}: {reason}", client.Id, e.Message);
            throw Refuse(client, $"could not be read: {e.Message}");
        }

        using (response)
        {
            if (response.StatusCode != HttpStatusCode.OK)
            {
                throw new ClientDocumentException($"{client.Id} answered {(int)response.StatusCode} instead of 200 with its client document. A site that signs people in here publishes one at its client id.");
            }
            if (!string.Equals(response.Content.Headers.ContentType?.MediaType, "application/json", StringComparison.OrdinalIgnoreCase))
            {
                throw Refuse(client, "is not served as application/json.");
            }
            return Parse(client, body, CacheLifetime(response));
        }
    }

    /// <summary>The document's members as the draft names them; anything else is ignored, and anything a URL client may not have is refused.</summary>
    public static ClientDocument Parse(UrlClient client, string json, TimeSpan cacheFor)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json);
        }
        catch (JsonException)
        {
            throw Refuse(client, "is not JSON.");
        }

        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                throw Refuse(client, "is not a JSON object.");
            }

            var clientId = StringMember(root, "client_id");
            if (clientId != client.Id)
            {
                throw Refuse(client, $"says client_id is '{clientId}'; it must be the URL it is served at.");
            }

            var authMethod = StringMember(root, "token_endpoint_auth_method");
            if (authMethod != null && authMethod != "none")
            {
                throw Refuse(client, $"asks for token_endpoint_auth_method '{authMethod}'. A URL client is public: 'none', with PKCE.");
            }

            var redirectUris = client.OwnCallbacks(StringArrayMember(root, "redirect_uris"));
            if (redirectUris.Count == 0)
            {
                throw Refuse(client, $"lists no https redirect_uris on {client.Origin}. Only callbacks on the site's own origin count.");
            }

            var declared = StringMember(root, "scope")?.Split(' ', StringSplitOptions.RemoveEmptyEntries) ?? [];
            var scope = OfferedScope.Where(s => s == "openid" || declared.Contains(s)).ToList();

            return new ClientDocument(redirectUris, CleanName(StringMember(root, "client_name")), scope, cacheFor);
        }
    }

    private static ClientDocumentException Refuse(UrlClient client, string what) =>
        new($"The client document at {client.Id} {what}");

    private static string? StringMember(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static IEnumerable<string> StringArrayMember(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Array
            ? value.EnumerateArray().Where(e => e.ValueKind == JsonValueKind.String).Select(e => e.GetString()!)
            : [];

    /// <summary>Control characters go, whitespace collapses, the ends are trimmed, the length is capped; nothing left is no name.</summary>
    private static string? CleanName(string? name)
    {
        if (name == null)
        {
            return null;
        }
        var visible = new string(name.Where(c => !char.IsControl(c)).ToArray());
        var collapsed = string.Join(' ', visible.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        return collapsed.Length == 0 ? null : collapsed.Length > MaxNameLength ? collapsed[..MaxNameLength] : collapsed;
    }

    /// <summary>The document's own max-age, held to between five minutes and a day; an hour when it says nothing.</summary>
    private static TimeSpan CacheLifetime(HttpResponseMessage response)
    {
        var maxAge = response.Headers.CacheControl?.MaxAge;
        if (maxAge == null)
        {
            return ClientDocument.DefaultCache;
        }
        return maxAge.Value < MinCache ? MinCache : maxAge.Value > MaxCache ? MaxCache : maxAge.Value;
    }
}
