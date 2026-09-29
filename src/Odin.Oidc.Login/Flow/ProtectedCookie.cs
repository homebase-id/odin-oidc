using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;

namespace Odin.Oidc.Login.Flow;

/// <summary>
/// A flow's state, encrypted and signed by Data Protection with a lifetime, in a host-only cookie.
/// No server-side state: any instance with the same key ring can finish a flow another started.
/// </summary>
public abstract class ProtectedCookie<T>(IDataProtectionProvider dataProtection, string name, string purpose, TimeSpan lifetime)
{
    private readonly ITimeLimitedDataProtector _protector = dataProtection.CreateProtector(purpose).ToTimeLimitedDataProtector();

    private static readonly CookieOptions Attributes = new()
    {
        HttpOnly = true,
        Secure = true,
        SameSite = SameSiteMode.Lax,
        Path = "/",
    };

    public void Write(HttpResponse response, T state) =>
        response.Cookies.Append(name, _protector.Protect(JsonSerializer.Serialize(state), lifetime), Attributes);

    /// <summary>The state, or null when there is no cookie or it is expired or tampered with.</summary>
    public T? Read(HttpRequest request)
    {
        if (!request.Cookies.TryGetValue(name, out var value) || string.IsNullOrEmpty(value))
        {
            return default;
        }
        try
        {
            return JsonSerializer.Deserialize<T>(_protector.Unprotect(value));
        }
        catch (Exception e) when (e is CryptographicException or JsonException)
        {
            return default;
        }
    }

    public void Delete(HttpResponse response) => response.Cookies.Delete(name, Attributes);
}
