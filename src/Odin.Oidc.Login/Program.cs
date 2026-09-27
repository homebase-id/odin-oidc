using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Diagnostics;
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
builder.Services.AddHttpClient<HydraAdminClient>(http => http.BaseAddress = new Uri(options.HydraAdminUrl));

// Talks to identities; never follows a redirect, since an identity's answer is always a body.
builder.Services.AddHttpClient(YouAuthClient.HttpClientName, http => http.Timeout = TimeSpan.FromSeconds(10))
    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { AllowAutoRedirect = false });

builder.Services.AddDataProtection()
    .SetApplicationName("odin-oidc")
    .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(builder.Environment.ContentRootPath, options.KeyRingPath)));

// Where the app listens, and its certificate in development, are Kestrel's own configuration
// (appsettings.Development.json, ASPNETCORE_URLS in the image).
var app = builder.Build();
app.UseExceptionHandler(new ExceptionHandlerOptions
{
    ExceptionHandlingPath = "/Error",
    // A stopped sign-in and an already-answered challenge are outcomes the Error page renders, not
    // failures for the log.
    SuppressDiagnosticsCallback = context => context.Exception is SignInStoppedException or HydraAlreadyAnsweredException,
});
app.MapRazorPages();
app.MapBrokerEndpoints();
app.Run();

public partial class Program;
