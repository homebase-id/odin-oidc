namespace Odin.Oidc.Login.Flow;

/// <summary>
/// The sign-in cannot go on and the person in the browser should be told why, in words, on the
/// Error page with a 400. Thrown from pages and endpoints; the exception handler renders it.
/// </summary>
public sealed class SignInStoppedException(string detail) : Exception(detail)
{
    /// <summary>The value of a hand-typed URL's parameter, or the stop that says which one is missing.</summary>
    public static string Required(string? value, string parameter) =>
        string.IsNullOrEmpty(value) ? throw new SignInStoppedException($"Missing {parameter}.") : value;
}
