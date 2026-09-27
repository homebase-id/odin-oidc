namespace Odin.Oidc.Login.Flow;

/// <summary>
/// The sign-in cannot go on and the person in the browser should be told why, in words, on the
/// Error page with a 400. Thrown from pages and endpoints; the exception handler renders it.
/// </summary>
public sealed class SignInStoppedException(string detail) : Exception(detail);
