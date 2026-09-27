using System.Security.Cryptography;
using System.Text.Json;
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

    private readonly ITimeLimitedDataProtector _protector =
        dataProtection.CreateProtector("Odin.Oidc.Login.Flow.v1").ToTimeLimitedDataProtector();

    private static readonly CookieOptions Attributes = new()
    {
        HttpOnly = true,
        Secure = true,
        SameSite = SameSiteMode.Lax,
        Path = "/",
        IsEssential = true,
    };

    public void Write(HttpResponse response, LoginFlowState state)
    {
        var value = _protector.Protect(JsonSerializer.Serialize(state), options.Value.FlowLifetime);
        response.Cookies.Append(Name, value, Attributes);
    }

    /// <summary>The state, or null when there is no cookie or it is expired or tampered with.</summary>
    public LoginFlowState? Read(HttpRequest request)
    {
        if (!request.Cookies.TryGetValue(Name, out var value) || string.IsNullOrEmpty(value))
        {
            return null;
        }
        try
        {
            return JsonSerializer.Deserialize<LoginFlowState>(_protector.Unprotect(value));
        }
        catch (Exception e) when (e is CryptographicException or JsonException)
        {
            return null;
        }
    }

    public void Delete(HttpResponse response) => response.Cookies.Delete(Name, Attributes);
}
