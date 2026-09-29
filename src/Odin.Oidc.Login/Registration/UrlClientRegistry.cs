using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Odin.Oidc.Login.Flow;
using Odin.Oidc.Login.Hydra;
using Odin.Oidc.Login.Options;

namespace Odin.Oidc.Login.Registration;

/// <summary>
/// Makes a URL client known to Hydra before its authorize request is relayed: reads its document
/// (or, for the development client, its id), checks the request's redirect against it, and
/// creates or updates the client in Hydra under the same id, so the token endpoint, userinfo and
/// everything else stay Hydra's untouched. A known client costs nothing until its document's cache
/// lifetime passes; failures are never cached. Every refusal is a <see cref="SignInStoppedException"/>,
/// a page: an untrusted redirect is never sent anything, not even an error.
/// </summary>
public sealed class UrlClientRegistry(ClientDocumentFetcher fetcher, HydraAdminClient hydra, IMemoryCache cache, IOptions<BrokerOptions> options, ILogger<UrlClientRegistry> logger)
{
    public const string RegisteredByUrl = "by-url";

    public async Task EnsureRegisteredAsync(UrlClient client, string? redirectUri, CancellationToken ct)
    {
        if (client.Declared != null && !options.Value.AllowLocalhostClients)
        {
            throw new SignInStoppedException("The client id http://localhost is for development brokers only.");
        }

        var document = cache.Get<ClientDocument>(CacheKey(client.Id)) ?? await RegisterAsync(client, ct);
        if (document.ResolveRedirect(redirectUri) == null)
        {
            throw new SignInStoppedException(
                $"The site {client.Id} asked to send you to {redirectUri ?? "no address"}, which its client document does not list. Nothing was sent there.");
        }
    }

    private async Task<ClientDocument> RegisterAsync(UrlClient client, CancellationToken ct)
    {
        ClientDocument document;
        try
        {
            document = client.Declared ?? await fetcher.FetchAsync(client, ct);
        }
        catch (ClientDocumentException e)
        {
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
            Metadata = new HydraClientMetadata { Registered = RegisteredByUrl },
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
            logger.LogDebug("The client {clientId} is operator-made; its document is checked but not written to Hydra", client.Id);
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
