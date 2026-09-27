namespace Odin.Oidc.Login.YouAuth;

/// <summary>The identity's answer could not be turned into proof: a failed exchange, a cipher this app refuses, a bad token.</summary>
public sealed class YouAuthException(string message, Exception? inner = null) : Exception(message, inner);
