using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using Odin.Oidc.Login.Options;

namespace Odin.Oidc.Login.Flow;

/// <summary>
/// A flow's state, encrypted and signed by Data Protection with the flow lifetime, in a host-only
/// cookie. No server-side state: any instance with the same key ring can finish a flow another started.
/// </summary>
public abstract class ProtectedCookie<T>(IDataProtectionProvider dataProtection, IOptions<BrokerOptions> options, string name, string purpose)
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
        response.Cookies.Append(name, _protector.Protect(JsonSerializer.Serialize(state), options.Value.FlowLifetime), Attributes);

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

    /// <summary>
    /// The flow a callback belongs to, taken from the cookie and ended: a callback belongs to the
    /// flow in the cookie or it is nobody's. Without the cookie, or with a state that is not its, a
    /// forged or replayed callback cannot be matched to anything, and the sign-in stops with
    /// <paramref name="stopMessage"/>.
    /// </summary>
    public T Claim(HttpRequest request, HttpResponse response, string? state, Func<T, string> stateOf, string stopMessage)
    {
        var flow = Read(request);
        if (flow == null || string.IsNullOrEmpty(state)
            || !CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(state), Encoding.UTF8.GetBytes(stateOf(flow))))
        {
            throw new SignInStoppedException(stopMessage);
        }
        Delete(response);
        return flow;
    }
}
