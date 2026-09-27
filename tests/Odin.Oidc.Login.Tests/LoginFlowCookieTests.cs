using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Odin.Oidc.Login.Flow;
using Odin.Oidc.Login.Options;
using Odin.Oidc.Login.YouAuth;

namespace Odin.Oidc.Login.Tests;

/// <summary>The flow state survives the round trip through the browser and nothing else does.</summary>
[TestFixture]
public class LoginFlowCookieTests
{
    private static readonly LoginFlowState State = new("challenge-1", "frodo.dotyou.cloud", "state-xyz", new YouAuthFlowKeys("cHdk", "ZGVy"));

    private static LoginFlowCookie Cookie(TimeSpan? lifetime = null)
    {
        var keys = Directory.CreateTempSubdirectory("odin-oidc-keys");
        var provider = DataProtectionProvider.Create(keys);
        var options = new BrokerOptions { FlowLifetime = lifetime ?? TimeSpan.FromMinutes(10) };
        return new LoginFlowCookie(provider, Microsoft.Extensions.Options.Options.Create(options));
    }

    private static (string name, string value, string setCookie) Written(LoginFlowCookie cookie, LoginFlowState state)
    {
        var context = new DefaultHttpContext();
        cookie.Write(context.Response, state);
        var setCookie = context.Response.Headers.SetCookie.ToString();
        var pair = setCookie.Split(';')[0].Split('=', 2);
        return (pair[0], pair[1], setCookie);
    }

    private static LoginFlowState? ReadBack(LoginFlowCookie cookie, string name, string value)
    {
        var context = new DefaultHttpContext();
        context.Request.Headers.Cookie = $"{name}={value}";
        return cookie.Read(context.Request);
    }

    [Test]
    public void RoundTrips()
    {
        var cookie = Cookie();
        var (name, value, setCookie) = Written(cookie, State);

        Assert.That(name, Is.EqualTo(LoginFlowCookie.Name));
        Assert.That(setCookie, Does.Contain("httponly").IgnoreCase.And.Contain("secure").IgnoreCase.And.Contain("samesite=lax").IgnoreCase.And.Contain("path=/").IgnoreCase);
        Assert.That(value, Does.Not.Contain("frodo"), "the state is encrypted, not merely signed");
        Assert.That(ReadBack(cookie, name, value), Is.EqualTo(State));
    }

    [Test]
    public void NoCookieIsNull()
    {
        Assert.That(Cookie().Read(new DefaultHttpContext().Request), Is.Null);
    }

    [Test]
    public void ATamperedCookieIsNull()
    {
        var cookie = Cookie();
        var (name, value, _) = Written(cookie, State);
        var tampered = value[..^4] + (value.EndsWith("AAAA") ? "BBBB" : "AAAA");

        Assert.That(ReadBack(cookie, name, tampered), Is.Null);
    }

    [Test]
    public async Task AnExpiredCookieIsNull()
    {
        var cookie = Cookie(TimeSpan.FromMilliseconds(1));
        var (name, value, _) = Written(cookie, State);
        await Task.Delay(50);

        Assert.That(ReadBack(cookie, name, value), Is.Null, "the owner took longer than the flow allows; they start over");
    }

    [Test]
    public void DeleteExpiresTheCookie()
    {
        var context = new DefaultHttpContext();
        Cookie().Delete(context.Response);
        Assert.That(context.Response.Headers.SetCookie.ToString(), Does.StartWith($"{LoginFlowCookie.Name}=").And.Contain("expires=").IgnoreCase);
    }
}
