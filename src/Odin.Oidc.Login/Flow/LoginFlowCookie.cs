#pragma warning disable CS9113 // stub: replaced by the implementation commit
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using Odin.Oidc.Login.Options;

namespace Odin.Oidc.Login.Flow;

/// <summary>
/// The flow state, encrypted and signed by Data Protection with a lifetime, in a host-only cookie.
/// No server-side state: any instance with the same key ring can finish a login another started.
/// </summary>
public sealed class LoginFlowCookie(IDataProtectionProvider dataProtection, IOptions<BrokerOptions> options)
{
    public const string Name = "__Host-odin_oidc_flow";

    public void Write(HttpResponse response, LoginFlowState state) => throw new NotImplementedException();

    /// <summary>The state, or null when there is no cookie or it is expired or tampered with.</summary>
    public LoginFlowState? Read(HttpRequest request) => throw new NotImplementedException();

    public void Delete(HttpResponse response) => throw new NotImplementedException();
}
