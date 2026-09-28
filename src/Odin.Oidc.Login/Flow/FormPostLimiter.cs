using System.Net;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;

namespace Odin.Oidc.Login.Flow;

/// <summary>
/// One address gets so many requests a minute to the login and consent pages and the callback;
/// the rest are told to slow down. The address is the connection's, which is the client's only
/// once forwarded headers from a trusted proxy have been applied.
/// </summary>
public static class FormPostLimiter
{
    public const string Policy = "form-posts";

    public static IServiceCollection AddFormPostLimiter(this IServiceCollection services, int perMinute) => services.AddRateLimiter(limiter =>
    {
        limiter.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
        limiter.OnRejected = async (context, ct) =>
        {
            context.HttpContext.Response.ContentType = "text/plain";
            await context.HttpContext.Response.WriteAsync("Too many sign-in attempts from your address. Slow down and try again in a minute.", ct);
        };
        limiter.AddPolicy(Policy, context => RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress ?? IPAddress.None,
            _ => new FixedWindowRateLimiterOptions { PermitLimit = perMinute, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
    });
}
