namespace Odin.Oidc.Login.Flow;

/// <summary>
/// What every answer tells the browser, set here rather than at the proxy so it holds behind any
/// proxy: no framing, no scripts or styles but this origin's own file, no referrer, no sniffing,
/// nothing cached, and HSTS once the request is known to be https.
/// </summary>
public static class SecurityHeaders
{
    public const string ContentSecurityPolicy = "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'";

    public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder app) => app.Use(async (context, next) =>
    {
        var headers = context.Response.Headers;
        headers["Content-Security-Policy"] = ContentSecurityPolicy;
        headers["X-Content-Type-Options"] = "nosniff";
        headers["Referrer-Policy"] = "no-referrer";
        headers["X-Frame-Options"] = "DENY";
        headers.CacheControl = "no-store";
        if (context.Request.IsHttps)
        {
            headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";
        }
        await next(context);
    });
}

/// <summary>Named rate-limit policies; the numbers are BrokerOptions'.</summary>
public static class RateLimits
{
    public const string FormPosts = "form-posts";
}
