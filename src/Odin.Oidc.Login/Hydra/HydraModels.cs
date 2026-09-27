namespace Odin.Oidc.Login.Hydra;

// Hydra's admin API, snake_case on the wire (HydraAdminClient sets the naming policy). Only the
// members this app reads or writes; Hydra ignores what it does not know and so do we.

public sealed class HydraClient
{
    public string? ClientId { get; set; }
    public string? ClientName { get; set; }
    public bool SkipConsent { get; set; }
}

public sealed class HydraOidcContext
{
    public string? LoginHint { get; set; }
}

public sealed class HydraLoginRequest
{
    public string Challenge { get; set; } = "";
    /// <summary>Hydra already knows the user (a remembered session): accept at once with <see cref="Subject"/>, no UI.</summary>
    public bool Skip { get; set; }
    public string? Subject { get; set; }
    public HydraClient? Client { get; set; }
    public List<string>? RequestedScope { get; set; }
    public List<string>? RequestedAccessTokenAudience { get; set; }
    public HydraOidcContext? OidcContext { get; set; }
    public string? RequestUrl { get; set; }
}

public sealed class HydraConsentRequest
{
    public string Challenge { get; set; } = "";
    public bool Skip { get; set; }
    public string? Subject { get; set; }
    public HydraClient? Client { get; set; }
    public List<string>? RequestedScope { get; set; }
    public List<string>? RequestedAccessTokenAudience { get; set; }
}

public sealed class HydraLogoutRequest
{
    public string Challenge { get; set; } = "";
    public string? Subject { get; set; }
    public string? Sid { get; set; }
    public bool RpInitiated { get; set; }
}

public sealed class HydraAcceptLogin
{
    public string Subject { get; set; } = "";
    public bool Remember { get; set; }
    public long? RememberFor { get; set; }
    public Dictionary<string, object>? Context { get; set; }
}

public sealed class HydraConsentSession
{
    public Dictionary<string, object>? IdToken { get; set; }
    public Dictionary<string, object>? AccessToken { get; set; }
}

public sealed class HydraAcceptConsent
{
    public List<string> GrantScope { get; set; } = [];
    public List<string>? GrantAccessTokenAudience { get; set; }
    public bool Remember { get; set; }
    public long? RememberFor { get; set; }
    public HydraConsentSession? Session { get; set; }
}

public sealed class HydraReject
{
    public string Error { get; set; } = "";
    public string? ErrorDescription { get; set; }
    public int? StatusCode { get; set; }
}

/// <summary>Every accept and reject answers with where to send the browser.</summary>
public sealed class HydraRedirect
{
    public string RedirectTo { get; set; } = "";
}
