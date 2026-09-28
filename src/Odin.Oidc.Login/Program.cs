using System.Net;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using IPNetwork = Microsoft.AspNetCore.HttpOverrides.IPNetwork;
using Microsoft.AspNetCore.RateLimiting;
using Odin.Oidc.Login.Claims;
using Odin.Oidc.Login.Endpoints;
using Odin.Oidc.Login.Flow;
using Odin.Oidc.Login.Hydra;
using Odin.Oidc.Login.Options;
using Odin.Oidc.Login.YouAuth;

var builder = WebApplication.CreateBuilder(args);
var options = builder.Configuration.GetSection(BrokerOptions.Section).Get<BrokerOptions>() ?? new BrokerOptions();

builder.Services.AddOptions<BrokerOptions>().BindConfiguration(BrokerOptions.Section);
builder.Services.AddRazorPages();
builder.Services.AddSingleton<LoginFlowCookie>();
builder.Services.AddSingleton<YouAuthClient>();
builder.Services.AddSingleton<ProfileClaims>();
builder.Services.AddHttpClient<HydraAdminClient>(http => http.BaseAddress = new Uri(options.HydraAdminUrl));

// Talks to identities; never follows a redirect, since an identity's answer is always a body.
builder.Services.AddHttpClient(YouAuthClient.HttpClientName, http =>
    {
        http.Timeout = TimeSpan.FromSeconds(10);
        http.MaxResponseContentBufferSize = 64 * 1024; // an identity's answers are small; it is a third party
    })
    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { AllowAutoRedirect = false });

builder.Services.AddDataProtection()
    .SetApplicationName("odin-oidc")
    .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(builder.Environment.ContentRootPath, options.KeyRingPath)));

// The TLS proxy in front, if any, is the only source believed about scheme and client address.
builder.Services.Configure<ForwardedHeadersOptions>(forwarded =>
{
    forwarded.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost;
    forwarded.ForwardLimit = 1;
    forwarded.KnownProxies.Clear();
    forwarded.KnownNetworks.Clear();
    foreach (var cidr in options.TrustedProxyNetworks)
    {
        forwarded.KnownNetworks.Add(IPNetwork.Parse(cidr));
    }
});

// Forms and callbacks are small; a body larger than this is not a sign-in.
builder.WebHost.ConfigureKestrel(kestrel =>
{
    kestrel.Limits.MaxRequestBodySize = 16 * 1024;
    kestrel.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(10);
});

// One address gets so many form posts and callbacks a minute; the rest are told to slow down.
builder.Services.AddRateLimiter(limiter =>
{
    limiter.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    limiter.OnRejected = async (context, ct) =>
    {
        context.HttpContext.Response.ContentType = "text/plain";
        await context.HttpContext.Response.WriteAsync("Too many sign-in attempts from your address. Slow down and try again in a minute.", ct);
    };
    limiter.AddPolicy(RateLimits.FormPosts, context => RateLimitPartition.GetFixedWindowLimiter(
        context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = options.FormPostsPerMinute, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
});

var app = builder.Build();
if (options.TrustedProxyNetworks.Count > 0)
{
    // With no known network the framework's middleware believes every X-Forwarded-* header; only
    // enabling it once a proxy is named is what makes "trust nobody" the default.
    app.UseForwardedHeaders();
}
app.UseSecurityHeaders();
app.UseExceptionHandler(SignInOutcomeMiddleware.ErrorPath);
app.UseMiddleware<SignInOutcomeMiddleware>();
app.UseStaticFiles();
// Routing after the outcome middleware, so a re-executed request is routed to the Error page.
app.UseRouting();
app.UseRateLimiter();
app.MapRazorPages();
app.MapBrokerEndpoints();
app.Run();

public partial class Program;
