namespace Odin.Oidc.Login.Options;

/// <summary>Bound from the <c>Broker</c> configuration section.</summary>
public sealed class BrokerOptions
{
    public const string Section = "Broker";

    /// <summary>The host relying parties and identities see this app at, e.g. oidc.homebase.id. It is the YouAuth client id.</summary>
    public string PublicHost { get; set; } = "";

    /// <summary>The port on that host, when not 443 (dev: 8443). The identity fetches the client document on 443 regardless.</summary>
    public int? PublicPort { get; set; }

    /// <summary>What the client document calls this app; shown small under the domain on the owner's consent page.</summary>
    public string ClientName { get; set; } = "Homebase Sign-in";

    public string HydraAdminUrl { get; set; } = "http://127.0.0.1:14445/";

    /// <summary>Where Data Protection keeps its key ring; shared between instances.</summary>
    public string KeyRingPath { get; set; } = "keys";

    /// <summary>PEM certificate and key for Kestrel; when unset the app listens on plain http (behind a proxy, or in tests).</summary>
    public string? CertificatePath { get; set; }
    public string? KeyPath { get; set; }
    public int ListenPort { get; set; } = 8443;

    /// <summary>Refuse a token the identity sealed with anything but aes-gcm, instead of logging a warning.</summary>
    public bool RequireAesGcm { get; set; }

    /// <summary>How long the owner has to sign in and consent at their identity before the flow cookie expires.</summary>
    public TimeSpan FlowLifetime { get; set; } = TimeSpan.FromMinutes(10);

    public string PublicOrigin => PublicPort is null or 443 ? $"https://{PublicHost}" : $"https://{PublicHost}:{PublicPort}";
    public string CallbackUri => $"{PublicOrigin}/youauth/callback";
}
