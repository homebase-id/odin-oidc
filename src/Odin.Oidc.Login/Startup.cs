using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using Odin.Oidc.Login.Endpoints;
using Odin.Oidc.Login.Flow;
using Odin.Oidc.Login.Hydra;
using Odin.Oidc.Login.Options;
using Odin.Oidc.Login.YouAuth;

namespace Odin.Oidc.Login;

public static class Startup
{
    public static void AddOdinOidcLogin(this WebApplicationBuilder builder)
    {
        var services = builder.Services;
        var options = builder.Configuration.GetSection(BrokerOptions.Section).Get<BrokerOptions>() ?? new BrokerOptions();

        services.AddOptions<BrokerOptions>().BindConfiguration(BrokerOptions.Section);
        services.AddRazorPages();
        services.AddSingleton<LoginFlowCookie>();
        services.AddSingleton<YouAuthClient>();

        services.AddHttpClient<HydraAdminClient>((sp, http) =>
        {
            http.BaseAddress = new Uri(sp.GetRequiredService<IOptions<BrokerOptions>>().Value.HydraAdminUrl);
        });

        // Talks to identities; never follows a redirect, since an identity's answer is always a body.
        services.AddHttpClient(YouAuthClient.HttpClientName, http => http.Timeout = TimeSpan.FromSeconds(10))
            .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { AllowAutoRedirect = false });

        services.AddDataProtection()
            .SetApplicationName("odin-oidc")
            .PersistKeysToFileSystem(new DirectoryInfo(options.KeyRingPath));

        // TLS is terminated here when a certificate is configured (development); behind a proxy it is not.
        if (!string.IsNullOrEmpty(options.CertificatePath) && !string.IsNullOrEmpty(options.KeyPath))
        {
            var certificate = X509Certificate2.CreateFromPemFile(options.CertificatePath, options.KeyPath);
            builder.WebHost.ConfigureKestrel(kestrel => kestrel.ListenAnyIP(options.ListenPort, listen => listen.UseHttps(certificate)));
        }
    }

    public static void MapOdinOidcLogin(this WebApplication app)
    {
        if (!app.Environment.IsDevelopment())
        {
            app.UseExceptionHandler("/Error");
        }
        app.MapRazorPages();
        app.MapBrokerEndpoints();
    }
}
