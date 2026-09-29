using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using Odin.Oidc.Login.Options;

namespace Odin.Oidc.Login.Flow;

/// <summary>One login's state between sending the browser to the identity and its return.</summary>
public sealed class LoginFlowCookie(IDataProtectionProvider dataProtection, IOptions<BrokerOptions> options)
    : ProtectedCookie<LoginFlowState>(dataProtection, options, Name, "Odin.Oidc.Login.Flow.v1")
{
    public const string Name = "__Host-odin_oidc_flow";
}
