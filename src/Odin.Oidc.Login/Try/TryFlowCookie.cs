using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using Odin.Oidc.Login.Flow;
using Odin.Oidc.Login.Options;

namespace Odin.Oidc.Login.Try;

/// <summary>What the try-it relying party must remember between sending the browser off and its return: PKCE verifier, state, nonce.</summary>
public sealed record TryFlowState(string State, string Verifier, string Nonce);

public sealed class TryFlowCookie(IDataProtectionProvider dataProtection, IOptions<BrokerOptions> options)
    : ProtectedCookie<TryFlowState>(dataProtection, options, Name, "Odin.Oidc.Login.Try.v1")
{
    public const string Name = "__Host-odin_oidc_try";
}
