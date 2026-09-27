namespace Odin.Oidc.Login.Flow;

/// <summary>
/// The sign-in cannot go on and the person in the browser should be told why, in words, on the
/// Error page with a 400. Thrown from pages and endpoints; the exception handler renders it.
/// </summary>
public sealed class SignInStoppedException(string detail) : Exception(detail);

/// <summary>How long Hydra remembers a login or a consent for this browser when asked to: a month, like the identity's own auto-consent.</summary>
public static class Remembered
{
    public const long ForSeconds = 30L * 24 * 3600;
}
