#pragma warning disable CS9113 // stub: replaced by the implementation commit
using Microsoft.Extensions.Options;
using Odin.Oidc.Login.Options;

namespace Odin.Oidc.Login.YouAuth;

/// <summary>The relying party's half of one login: what must survive from [030] to [090]. Lives in the flow cookie.</summary>
public sealed record YouAuthFlowKeys(string PasswordBase64, string KeyPairJson);

/// <summary>
/// This app as a YouAuth domain client: starts the flow at the identity, exchanges the callback for
/// the token, and releases the registration the token stands for, because the token's only use here
/// is having proven the identity.
/// </summary>
public sealed class YouAuthClient(IHttpClientFactory httpClientFactory, IOptions<BrokerOptions> options, ILogger<YouAuthClient> logger)
{
    public const string HttpClientName = "youauth";

    /// <summary>YouAuth [010] and [030]: an ephemeral key pair, and the authorize URL to send the browser to.</summary>
    public (Uri authorizeUrl, YouAuthFlowKeys keys) Begin(string identity, string state)
    {
        throw new NotImplementedException();
    }

    /// <summary>YouAuth [090] to [150]: the exchange secret, the token endpoint, and the opened client access token (33 bytes).</summary>
    public Task<byte[]> CompleteAsync(string identity, YouAuthFlowKeys keys, string identityPublicKeyJwk, string saltBase64, CancellationToken ct)
    {
        throw new NotImplementedException();
    }

    /// <summary>Deletes the registration at the identity. Best effort: the identity is already proven.</summary>
    public Task ReleaseAsync(string identity, byte[] clientAuthToken, CancellationToken ct)
    {
        throw new NotImplementedException();
    }
}
