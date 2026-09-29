using System.Net;

namespace Odin.Oidc.Login.Registration;

/// <summary>
/// A relying party whose client id is its own https URL, the way draft-ietf-oauth-client-id-metadata-document
/// (and ATProto's OAuth) defines one: no registration, since the document at that URL is the
/// registration, and the host in it is what the person sees. What is checked here is the draft's
/// shape of the id, and our own rule that its callbacks are on its own origin, which is YouAuth's.
/// </summary>
public sealed class UrlClient
{
    /// <summary>The id as the relying party sent it: compared everywhere as a plain string, never normalised.</summary>
    public string Id { get; }

    /// <summary>The host of the id, in punycode when internationalised, so a lookalike cannot paint itself.</summary>
    public string Host { get; }

    /// <summary>Scheme, host and port: every callback must sit here.</summary>
    public string Origin { get; }

    /// <summary>
    /// ATProto's <c>http://localhost</c> development client is its own document: callbacks and
    /// scope come from the id's query and nothing is fetched. Null for every other client.
    /// </summary>
    public ClientDocument? Declared { get; }

    private readonly int _port;

    private UrlClient(string id, Uri uri, ClientDocument? declared)
    {
        Id = id;
        Host = uri.IdnHost;
        Origin = $"{uri.Scheme}://{uri.IdnHost}{(uri.IsDefaultPort ? "" : ":" + uri.Port)}";
        Declared = declared;
        _port = uri.Port;
    }

    /// <summary>
    /// The draft's client id: https, a host name (not an address), a path, no userinfo, no fragment,
    /// no single- or double-dot segment. Our policy beyond it: no query, since nothing in a document
    /// URL needs one and the id is shown to people. Also the development client, exactly
    /// <c>http://localhost</c> with an optional query of <c>redirect_uri</c> (repeatable, loopback
    /// only) and <c>scope</c>. Anything else is an operator-registered id.
    /// </summary>
    public static bool TryParse(string? clientId, out UrlClient? client)
    {
        client = null;
        if (clientId == null)
        {
            return false;
        }
        if (clientId == "http://localhost" || clientId.StartsWith("http://localhost?", StringComparison.Ordinal))
        {
            var localhost = new Uri(clientId, UriKind.Absolute);
            var query = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(localhost.Query);
            var callbacks = query.TryGetValue("redirect_uri", out var redirects)
                ? redirects.Where(r => r != null && ClientDocument.IsLoopback(r)).Select(r => r!).ToList()
                : ["http://127.0.0.1/", "http://[::1]/"];
            var scope = query.TryGetValue("scope", out var scopes)
                ? scopes.ToString().Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList()
                : ["openid"];
            client = new UrlClient(clientId, localhost, new ClientDocument(callbacks, null, scope, ClientDocument.DefaultCache));
            return true;
        }

        const string prefix = "https://";
        if (!clientId.StartsWith(prefix, StringComparison.Ordinal)
            || clientId.IndexOfAny(['#', '?', '@']) >= 0
            || !Uri.TryCreate(clientId, UriKind.Absolute, out var uri)
            || uri.HostNameType != UriHostNameType.Dns)
        {
            return false;
        }
        var pathStart = clientId.IndexOf('/', prefix.Length);
        if (pathStart < 0 || clientId[pathStart..].Split('/').Any(segment => segment is "." or ".."))
        {
            return false; // no path component, or a dot segment
        }

        client = new UrlClient(clientId, uri, null);
        return true;
    }

    /// <summary>The redirect URIs a document lists that are this client's to claim: https on its own origin.</summary>
    public IReadOnlyList<string> OwnCallbacks(IEnumerable<string> redirectUris) =>
        redirectUris.Where(r => Uri.TryCreate(r, UriKind.Absolute, out var uri)
                                && uri.Scheme == Uri.UriSchemeHttps
                                && string.Equals(uri.IdnHost, Host, StringComparison.OrdinalIgnoreCase)
                                && uri.Port == _port)
            .ToList();
}
