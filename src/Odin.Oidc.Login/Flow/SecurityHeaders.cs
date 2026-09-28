namespace Odin.Oidc.Login.Flow;

/// <summary>
/// What every answer tells the browser about content, set here rather than at the proxy so it
/// holds behind any proxy: no framing, no scripts or styles but this origin's own file, no
/// referrer, no sniffing, nothing cached unless the endpoint says so (the client document and the
/// stylesheet do). HSTS is the framework's <c>UseHsts</c>, next to this in Program.cs.
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
        await next(context);
    });
}
