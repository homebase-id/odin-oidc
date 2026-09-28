namespace Odin.Oidc.Login.Hydra;

/// <summary>Hydra's admin API answered with something other than success or an already-answered challenge.</summary>
public sealed class HydraException(string message) : Exception(message);

/// <summary>
/// The challenge was already answered (HTTP 410), typically the browser going back to a page it had
/// left. Hydra names a redirect, but it re-presents a verifier that is spent, so the Error page
/// tells the person instead.
/// </summary>
public sealed class HydraAlreadyAnsweredException(string redirectTo) : Exception("Hydra already answered this challenge")
{
    public string RedirectTo { get; } = redirectTo;
}
