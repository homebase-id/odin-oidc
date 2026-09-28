namespace Odin.Oidc.Login.Options;

/// <summary>Bound from the <c>Broker</c> configuration section.</summary>
public sealed class BrokerOptions
{
    public const string Section = "Broker";

    /// <summary>
    /// Where relying parties and identities reach this app, e.g. https://oidc.homebase.id. Its host is
    /// the YouAuth client id; the identity compares the callback's host to it and fetches the client
    /// document from it on 443, whatever port is here (development uses 8443).
    /// </summary>
    public string PublicOrigin { get; set; } = "";

    /// <summary>What the client document calls this app; shown small under the domain on the owner's consent page.</summary>
    public string ClientName { get; set; } = "Homebase Sign-in";

    public string HydraAdminUrl { get; set; } = "http://127.0.0.1:14445/";

    /// <summary>Where Data Protection keeps its key ring, relative to the content root; shared between instances.</summary>
    public string KeyRingPath { get; set; } = "keys";

    /// <summary>How long the owner has to sign in and consent at their identity before the flow cookie expires.</summary>
    public TimeSpan FlowLifetime { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Networks (CIDR) whose X-Forwarded-For/Proto/Host headers are believed: the TLS proxy in front
    /// of this app. Empty, the default, believes nobody, and the app then sees every request as http.
    /// </summary>
    public List<string> TrustedProxyNetworks { get; set; } = [];

    /// <summary>Form posts and callbacks one client address may make per minute before it is told to slow down.</summary>
    public int FormPostsPerMinute { get; set; } = 20;

    public string PublicHost => new Uri(PublicOrigin).Host;
    public string CallbackUri => $"{PublicOrigin.TrimEnd('/')}/youauth/callback";
}
