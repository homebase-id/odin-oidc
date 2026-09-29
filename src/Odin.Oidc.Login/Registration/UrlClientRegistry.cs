using Microsoft.Extensions.Caching.Memory;
using Odin.Oidc.Login.Flow;
using Odin.Oidc.Login.Hydra;

namespace Odin.Oidc.Login.Registration;

/// <summary>
/// Makes a URL client known to Hydra before its authorize request is relayed: reads its document
/// (or, for the development client, its id), checks the request's redirect against it, and
/// creates or updates the client in Hydra under the same id, so the token endpoint, userinfo and
/// everything else stay Hydra's untouched. A known client costs nothing until its document's cache
/// lifetime passes; failures are never cached.
/// </summary>
public sealed class UrlClientRegistry(ClientDocumentFetcher fetcher, HydraAdminClient hydra, IMemoryCache cache, ILogger<UrlClientRegistry> logger)
{
    public const string RegisteredByUrl = "by-url";

    public async Task EnsureRegisteredAsync(UrlClient client, string? redirectUri, CancellationToken ct)
    {
        var document = cache.Get<ClientDocument>(CacheKey(client.Id)) ?? await RegisterAsync(client, ct);

        // The draft: a redirect may be left out when the document lists exactly one.
        redirectUri ??= document.RedirectUris.Count == 1 ? document.RedirectUris[0] : null;
        if (redirectUri == null || !client.Allows(redirectUri, document.RedirectUris))
        {
            // The one refusal that must be a page here: an untrusted redirect is never sent anything.
            throw new SignInStoppedException(
                $"The site {client.Id} asked to send you to {redirectUri ?? "no address"}, which its client document does not list. Nothing was sent there.");
        }
    }

    private async Task<ClientDocument> RegisterAsync(UrlClient client, CancellationToken ct)
    {
        ClientDocument document;
        try
        {
            document = client.IsLocalhostDevelopment
                ? new ClientDocument(client.Id, client.DeclaredCallbacks, null, client.DeclaredScope, TimeSpan.FromHours(1))
                : await fetcher.FetchAsync(client, ct);
        }
        catch (ClientDocumentException e)
        {
            logger.LogWarning("A URL client was refused: {reason}", e.Message);
            throw new SignInStoppedException(e.Message);
        }

        var wanted = new HydraClient
        {
            ClientId = client.Id,
            ClientName = document.Name,
            RedirectUris = document.RedirectUris.ToList(),
            TokenEndpointAuthMethod = "none",
            GrantTypes = ["authorization_code", "refresh_token"],
            ResponseTypes = ["code"],
            Scope = string.Join(' ', document.Scope),
            Metadata = new HydraClientMetadata { Registered = RegisteredByUrl, FetchedAt = DateTimeOffset.UtcNow },
        };

        var existing = await hydra.GetClientAsync(client.Id, ct);
        if (existing == null)
        {
            await hydra.CreateClientAsync(wanted, ct);
            logger.LogInformation("Registered a URL client from its document: {clientId}", client.Id);
        }
        else if (existing.Metadata?.Registered != RegisteredByUrl)
        {
            // An operator put a client at this id on purpose; its registration is theirs to change.
            logger.LogDebug("The client {clientId} is operator-managed; its document is checked but not written to Hydra", client.Id);
        }
        else if (!SameRegistration(existing, wanted))
        {
            await hydra.UpdateClientAsync(wanted, ct);
            logger.LogInformation("Updated a URL client from its changed document: {clientId}", client.Id);
        }

        cache.Set(CacheKey(client.Id), document, document.CacheFor);
        return document;
    }

    private static bool SameRegistration(HydraClient existing, HydraClient wanted) =>
        existing.ClientName == wanted.ClientName
        && existing.Scope == wanted.Scope
        && (existing.RedirectUris ?? []).SequenceEqual(wanted.RedirectUris ?? []);

    private static string CacheKey(string clientId) => $"url-client:{clientId}";
}
