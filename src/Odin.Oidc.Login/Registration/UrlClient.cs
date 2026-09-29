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

    /// <summary>ATProto's <c>http://localhost</c> client for development: never fetched, its callbacks and scope are in the id's query.</summary>
    public bool IsLocalhostDevelopment { get; }

    public IReadOnlyList<string> DeclaredCallbacks { get; }
    public IReadOnlyList<string> DeclaredScope { get; }

    private UrlClient(string id, Uri uri, bool localhost, IReadOnlyList<string> callbacks, IReadOnlyList<string> scope)
    {
        Id = id;
        Host = uri.IdnHost;
        Origin = $"{uri.Scheme}://{uri.IdnHost}{(uri.IsDefaultPort ? "" : ":" + uri.Port)}";
        IsLocalhostDevelopment = localhost;
        DeclaredCallbacks = callbacks;
        DeclaredScope = scope;
    }

    /// <summary>
    /// The draft's client id: https, a host name (not an address), a path, no userinfo, no fragment,
    /// no single- or double-dot segment. Our policy beyond it: no query, since nothing in a document
    /// URL needs one and the id is shown to people. Anything else is an operator-registered id.
    /// </summary>
    public static bool TryParse(string? clientId, out UrlClient? client)
    {
        client = null;
        const string prefix = "https://";
        if (clientId == null || !clientId.StartsWith(prefix, StringComparison.Ordinal)
            || clientId.IndexOfAny(['#', '?', '@']) >= 0
            || !Uri.TryCreate(clientId, UriKind.Absolute, out var uri)
            || uri.HostNameType != UriHostNameType.Dns)
        {
            return false;
        }

        var pathStart = clientId.IndexOf('/', prefix.Length);
        if (pathStart < 0)
        {
            return false; // no path component
        }
        if (clientId[pathStart..].Split('/').Any(segment => segment is "." or ".."))
        {
            return false;
        }

        client = new UrlClient(clientId, uri, localhost: false, [], []);
        return true;
    }

    /// <summary>
    /// ATProto's development client, exactly <c>http://localhost</c> with an optional query of
    /// <c>redirect_uri</c> (repeatable) and <c>scope</c>. Its callbacks are loopback addresses
    /// (RFC 8252: the port is chosen at run time and not matched).
    /// </summary>
    public static bool TryParseLocalhost(string? clientId, out UrlClient? client)
    {
        client = null;
        if (clientId == null || !(clientId == "http://localhost" || clientId.StartsWith("http://localhost?", StringComparison.Ordinal)))
        {
            return false;
        }

        var uri = new Uri(clientId, UriKind.Absolute);
        var query = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(uri.Query);
        var callbacks = query.TryGetValue("redirect_uri", out var redirects)
            ? redirects.Where(r => r != null && IsLoopback(r)).Select(r => r!).ToList()
            : ["http://127.0.0.1/", "http://[::1]/"];
        var scope = query.TryGetValue("scope", out var scopes)
            ? scopes.ToString().Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList()
            : ["openid"];
        client = new UrlClient(clientId, uri, localhost: true, callbacks, scope);
        return true;
    }

    /// <summary>The redirect URIs a document lists that are this client's to claim: https on its own origin.</summary>
    public IReadOnlyList<string> OwnCallbacks(IEnumerable<string> redirectUris) =>
        redirectUris.Where(r => Uri.TryCreate(r, UriKind.Absolute, out var uri)
                                && uri.Scheme == Uri.UriSchemeHttps
                                && string.Equals(uri.IdnHost, Host, StringComparison.OrdinalIgnoreCase)
                                && uri.IsDefaultPort == new Uri(Origin).IsDefaultPort
                                && uri.Port == new Uri(Origin).Port)
            .ToList();

    /// <summary>
    /// Whether the request's redirect is one of the callbacks: the same string (RFC 9700), or for
    /// the development client the same loopback scheme, host and path whatever the port.
    /// </summary>
    public bool Allows(string redirectUri, IReadOnlyList<string> callbacks)
    {
        if (!IsLocalhostDevelopment)
        {
            return callbacks.Contains(redirectUri, StringComparer.Ordinal);
        }
        return Uri.TryCreate(redirectUri, UriKind.Absolute, out var requested)
               && callbacks.Any(c => Uri.TryCreate(c, UriKind.Absolute, out var allowed)
                                     && allowed.Scheme == requested.Scheme
                                     && allowed.Host == requested.Host
                                     && allowed.AbsolutePath == requested.AbsolutePath);
    }

    private static bool IsLoopback(string redirectUri) =>
        Uri.TryCreate(redirectUri, UriKind.Absolute, out var uri)
        && uri.Scheme == Uri.UriSchemeHttp
        && IPAddress.TryParse(uri.Host.Trim('[', ']'), out var address)
        && IPAddress.IsLoopback(address);
}
