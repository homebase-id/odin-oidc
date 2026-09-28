namespace Odin.Oidc.Login.YouAuth;

/// <summary>
/// The identity's answer could not be turned into proof: a failed exchange, a cipher this app
/// refuses, a bad token. The message never names the identity, so it is safe at any log level;
/// the caller knows which identity it was.
/// </summary>
public sealed class YouAuthException(string message, Exception? inner = null) : Exception(message, inner);
