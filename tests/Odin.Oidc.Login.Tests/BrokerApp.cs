using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
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
    public const string Frodo = "frodo.dotyou.cloud";

    public FakeHydraAdmin Hydra { get; } = new();
    public FakeIdentity Identity { get; }
    public string PublicHost { get; }

    /// <summary>Extra Broker:* settings for one test, e.g. TrustedProxyNetworks:0.</summary>
    public Dictionary<string, string?> Settings { get; } = new();

    /// <summary>Every log line the app wrote, with its level and rendered message.</summary>
    public List<(LogLevel level, string category, string message)> Logs { get; } = [];

    /// <summary>The test client says where it is calling from with this header; the app sees it as the connection's remote address.</summary>
    public const string RemoteAddressHeader = "X-Test-Remote-Address";

    public BrokerApp(string identityDomain = Frodo, string publicHost = "oidc.example.org")
    {
        Identity = new FakeIdentity(identityDomain);
        PublicHost = publicHost;
        ClientOptions.BaseAddress = new Uri("https://localhost");
        ClientOptions.AllowAutoRedirect = false;
    }

    /// <summary>POST a page's form with the antiforgery token the page rendered.</summary>
    public static async Task<HttpResponseMessage> PostFormAsync(HttpClient browser, string path, string pageHtml, Dictionary<string, string> form)
    {
        var token = System.Text.RegularExpressions.Regex.Match(pageHtml, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value;
        NUnit.Framework.Assert.That(token, Is.Not.Empty, "the form carries an antiforgery token");
        form["__RequestVerificationToken"] = token;
        return await browser.PostAsync(path, new FormUrlEncodedContent(form));
    }

    private sealed class RemoteAddressFromHeader : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use(async (context, nextMiddleware) =>
            {
                if (context.Request.Headers.TryGetValue(RemoteAddressHeader, out var address))
                {
                    context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse(address.ToString());
                }
                await nextMiddleware(context);
            });
            next(app);
        };
    }

    private sealed class ListLoggerProvider(List<(LogLevel, string, string)> sink) : ILoggerProvider
    {
        public ILogger CreateLogger(string categoryName) => new ListLogger(categoryName, sink);
        public void Dispose() { }

        private sealed class ListLogger(string category, List<(LogLevel, string, string)> sink) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel logLevel) => true;
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            {
                lock (sink)
                {
                    sink.Add((logLevel, category, formatter(state, exception)));
                }
            }
        }
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        var keys = Directory.CreateTempSubdirectory("odin-oidc-keys").FullName;
        builder.UseSetting("Broker:PublicOrigin", $"https://{PublicHost}");
        builder.UseSetting("Broker:ClientName", "Homebase Sign-in");
        builder.UseSetting("Broker:HydraAdminUrl", "http://hydra-admin:4445/");
        builder.UseSetting("Broker:KeyRingPath", keys);

        foreach (var (key, value) in Settings)
        {
            builder.UseSetting(key, value);
        }

        builder.ConfigureTestServices(services =>
        {
            services.AddHttpClient<HydraAdminClient>().ConfigurePrimaryHttpMessageHandler(() => Hydra.Handler);
            services.AddHttpClient(YouAuthClient.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => Identity.Handler);
            services.AddSingleton<IStartupFilter>(new RemoteAddressFromHeader());
            services.AddSingleton<ILoggerProvider>(new ListLoggerProvider(Logs));
        });
    }
}
