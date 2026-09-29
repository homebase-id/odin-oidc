using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Odin.Oidc.Login.Claims;
using Odin.Oidc.Login.Endpoints;
using Odin.Oidc.Login.Flow;
using Odin.Oidc.Login.Hydra;
using Odin.Oidc.Login.Options;
using Odin.Oidc.Login.Registration;
using Odin.Oidc.Login.YouAuth;
using IPNetwork = Microsoft.AspNetCore.HttpOverrides.IPNetwork;

var builder = WebApplication.CreateBuilder(args);
var options = builder.Configuration.GetSection(BrokerOptions.Section).Get<BrokerOptions>() ?? new BrokerOptions();

builder.Services.AddOptions<BrokerOptions>().BindConfiguration(BrokerOptions.Section);
builder.Services.AddRazorPages();
builder.Services.AddSingleton<LoginFlowCookie>();
builder.Services.AddSingleton<YouAuthClient>();
builder.Services.AddSingleton<ProfileClaims>();
builder.Services.AddMemoryCache();
builder.Services.AddSingleton<ClientDocumentFetcher>();
builder.Services.AddScoped<UrlClientRegistry>();
builder.Services.AddHttpClient<HydraAdminClient>(http =>
{
    http.BaseAddress = new Uri(options.HydraAdminUrl);
    http.Timeout = TimeSpan.FromSeconds(5); // same network; a stalled Hydra must not pin every probe for the default 100 s
});

// Talks to identities; never follows a redirect, since an identity's answer is always a body.
builder.Services.AddHttpClient(YouAuthClient.HttpClientName, http =>
    {
        http.Timeout = TimeSpan.FromSeconds(10);
        http.MaxResponseContentBufferSize = 64 * 1024; // an identity's answers are small; it is a third party
    })
    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { AllowAutoRedirect = false });

// Hydra's public API, relayed: no redirect followed (they are the browser's), no cookie kept (they are the browser's).
builder.Services.AddHttpClient(HydraRelay.HttpClientName, http =>
    {
        http.BaseAddress = new Uri(options.HydraPublicUrl);
        http.Timeout = TimeSpan.FromSeconds(15);
    })
    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false });

// Reads a URL client's document: a third party's small JSON, from a public address only.
builder.Services.AddHttpClient(ClientDocumentFetcher.HttpClientName, http =>
    {
        http.Timeout = TimeSpan.FromSeconds(3);
        http.MaxResponseContentBufferSize = ClientDocumentFetcher.MaxBytes;
        http.DefaultRequestHeaders.Accept.ParseAdd("application/json");
    })
    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        UseCookies = false,
        ConnectCallback = SafeAddress.Connect(allowLocal: options.AllowLocalhostClients),
    });

builder.Services.AddDataProtection()
    .SetApplicationName("odin-oidc")
    .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(builder.Environment.ContentRootPath, options.KeyRingPath)));

builder.Services.AddFormPostLimiter(options.FormPostsPerMinute);
builder.Services.AddHsts(hsts =>
{
    hsts.MaxAge = TimeSpan.FromDays(365);
    hsts.IncludeSubDomains = true;
    hsts.ExcludedHosts.Clear(); // the framework skips localhost by default; the tests speak https to it
});

// Forms and callbacks are small; a body larger than this is not a sign-in.
builder.WebHost.ConfigureKestrel(kestrel =>
{
    kestrel.Limits.MaxRequestBodySize = 16 * 1024;
    kestrel.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(10);
});

var app = builder.Build();

// The TLS proxy in front, if any, is the only source believed about scheme and client address.
// With no known network the framework's middleware believes every X-Forwarded-* header; enabling it
// only once a proxy is named is what makes "trust nobody" the default.
if (options.TrustedProxyNetworks.Count > 0)
{
    var forwarded = new ForwardedHeadersOptions
    {
        ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost,
        ForwardLimit = 1,
    };
    forwarded.KnownProxies.Clear();
    forwarded.KnownNetworks.Clear();
    foreach (var cidr in options.TrustedProxyNetworks)
    {
        forwarded.KnownNetworks.Add(IPNetwork.Parse(cidr));
    }
    app.UseForwardedHeaders(forwarded);
    app.Logger.LogInformation("Believing X-Forwarded-* headers from {networks}", string.Join(", ", options.TrustedProxyNetworks));
}
else
{
    app.Logger.LogInformation("Believing no X-Forwarded-* headers: every request is seen as it arrives (set Broker:TrustedProxyNetworks behind a proxy)");
}

app.UseExceptionHandler(SignInOutcomeMiddleware.ErrorPath);
app.UseMiddleware<SignInOutcomeMiddleware>();
// After the two handlers, so a response they rebuild for the Error page gets the headers again.
app.UseSecurityHeaders();
app.UseHsts();
app.UseStaticFiles(new StaticFileOptions
{
    // The one stylesheet may be cached; its link carries a content version.
    OnPrepareResponse = context => context.Context.Response.Headers.CacheControl = "public, max-age=86400",
});
// Routing after the outcome middleware, so a re-executed request is routed to the Error page.
app.UseRouting();
app.UseRateLimiter();
app.MapRazorPages();
app.MapBrokerEndpoints();
app.MapHydraRelay();
app.Run();

public partial class Program;
