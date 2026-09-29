using Odin.Oidc.Login.Hydra;

namespace Odin.Oidc.Login.Registration;

/// <summary>
/// What the login and consent pages say about the relying party: the domain of the callback the
/// browser will be sent to, which Hydra has already matched against the client's registration, and
/// the name the client gave itself, which is only its own claim. The domain is shown large and the
/// name small, never the other way round: for a URL client the domain is the client id's own host,
/// and for an operator-registered one the callback's. An internationalised host is punycode, so a
/// lookalike cannot paint itself.
/// </summary>
public sealed record RelyingParty(string? Domain, string? Name)
{
    /// <summary>The domain, or a generic word for a request that names no callback at all.</summary>
    public string Shown => Domain ?? "A site";

    public static RelyingParty From(HydraClient client, string? requestUrl)
    {
        var redirect = RedirectUriOf(requestUrl) ?? client.RedirectUris?.FirstOrDefault();
        var domain = Uri.TryCreate(redirect, UriKind.Absolute, out var uri) ? uri.IdnHost : null;
        return new RelyingParty(domain, client.ClientName is { Length: > 0 } ? client.ClientName : null);
    }

    private static string? RedirectUriOf(string? requestUrl) =>
        Uri.TryCreate(requestUrl, UriKind.Absolute, out var uri)
        && Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(uri.Query).TryGetValue("redirect_uri", out var value)
            ? value.ToString()
            : null;
}
