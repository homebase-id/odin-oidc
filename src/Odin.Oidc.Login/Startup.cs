using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
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
        services.AddOptions<BrokerOptions>().BindConfiguration(BrokerOptions.Section);
        services.AddRazorPages();
        services.AddSingleton<LoginFlowCookie>();
        services.AddSingleton<YouAuthClient>();
        services.AddHttpClient<HydraAdminClient>((sp, http) =>
        {
            http.BaseAddress = new Uri(sp.GetRequiredService<IOptions<BrokerOptions>>().Value.HydraAdminUrl);
        });
        services.AddHttpClient(YouAuthClient.HttpClientName, http => http.Timeout = TimeSpan.FromSeconds(10))
            .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { AllowAutoRedirect = false });

        var options = builder.Configuration.GetSection(BrokerOptions.Section).Get<BrokerOptions>() ?? new BrokerOptions();
        services.AddDataProtection()
            .SetApplicationName("odin-oidc")
            .PersistKeysToFileSystem(new DirectoryInfo(options.KeyRingPath));
    }

    public static void MapOdinOidcLogin(this WebApplication app)
    {
        app.MapRazorPages();
    }
}
