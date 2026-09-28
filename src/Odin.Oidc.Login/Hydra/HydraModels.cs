namespace Odin.Oidc.Login.Hydra;

// Hydra's admin API, snake_case on the wire (HydraAdminClient sets the naming policy). Only the
// members this app reads or writes; Hydra ignores what it does not know and so do we.

public sealed class HydraClient
{
    public string? ClientId { get; set; }
    public string? ClientName { get; set; }
    public bool SkipConsent { get; set; }

    /// <summary>What the pages call the relying party: its name, else its id, else a generic word.</summary>
    public string DisplayName => ClientName is { Length: > 0 } ? ClientName : ClientId is { Length: > 0 } ? ClientId : "A site";
}

public sealed class HydraOidcContext
{
    public string? LoginHint { get; set; }
}

public sealed class HydraLoginRequest
{
    /// <summary>Hydra already knows the user (a remembered session): accept at once with <see cref="Subject"/>, no UI.</summary>
    public bool Skip { get; set; }
    public string? Subject { get; set; }
    public HydraClient Client { get; set; } = new();
    public HydraOidcContext? OidcContext { get; set; }
}

public sealed class HydraConsentRequest
{
    /// <summary>The user already consented to this client and scope (remembered): accept at once, no UI.</summary>
    public bool Skip { get; set; }
    public string? Subject { get; set; }
    public HydraClient Client { get; set; } = new();
    public List<string> RequestedScope { get; set; } = [];
    public List<string>? RequestedAccessTokenAudience { get; set; }
}

/// <summary>How long Hydra remembers a login or a consent for a browser when asked to: a month.</summary>
public static class Remembered
{
    public const long ForSeconds = 30L * 24 * 3600;
}

public sealed class HydraAcceptLogin
{
    public string Subject { get; set; } = "";
    public bool Remember { get; set; }
    public long? RememberFor => Remember ? Remembered.ForSeconds : null;
}

public sealed class HydraConsentSession
{
    public Dictionary<string, object>? IdToken { get; set; }
}

public sealed class HydraAcceptConsent
{
    public List<string> GrantScope { get; set; } = [];
    public List<string>? GrantAccessTokenAudience { get; set; }
    public bool Remember { get; set; }
    public long? RememberFor => Remember ? Remembered.ForSeconds : null;
    public HydraConsentSession? Session { get; set; }
}

public sealed class HydraReject
{
    public string Error { get; set; } = "";
    public string? ErrorDescription { get; set; }
}

/// <summary>Every accept and reject answers with where to send the browser.</summary>
public sealed class HydraRedirect
{
    public string RedirectTo { get; set; } = "";
}
