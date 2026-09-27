using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Odin.Oidc.Login.Hydra;
using Odin.Oidc.Login.Tests.Fakes;
using Odin.Oidc.Login.YouAuth;

namespace Odin.Oidc.Login.Tests;

/// <summary>
/// The login app in-process with a fake Hydra admin API and one fake identity behind its two
/// HttpClients. The test client speaks https so the Secure flow cookie travels.
/// </summary>
public sealed class BrokerApp : WebApplicationFactory<Program>
{
    public FakeHydraAdmin Hydra { get; } = new();
    public FakeIdentity Identity { get; }
    public string PublicHost { get; }

    public BrokerApp(string identityDomain = "frodo.dotyou.cloud", string publicHost = "oidc.example.org")
    {
        Identity = new FakeIdentity(identityDomain);
        PublicHost = publicHost;
        ClientOptions.BaseAddress = new Uri("https://localhost");
        ClientOptions.AllowAutoRedirect = false;
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        var keys = Directory.CreateTempSubdirectory("odin-oidc-keys").FullName;
        builder.UseSetting("Broker:PublicHost", PublicHost);
        builder.UseSetting("Broker:PublicPort", "");
        builder.UseSetting("Broker:ClientName", "Homebase Sign-in");
        builder.UseSetting("Broker:HydraAdminUrl", "http://hydra-admin:4445/");
        builder.UseSetting("Broker:KeyRingPath", keys);
        builder.UseSetting("Broker:CertificatePath", "");
        builder.UseSetting("Broker:KeyPath", "");

        builder.ConfigureTestServices(services =>
        {
            services.AddHttpClient<HydraAdminClient>().ConfigurePrimaryHttpMessageHandler(() => Hydra.Handler);
            services.AddHttpClient(YouAuthClient.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => Identity.Handler);
        });
    }
}
