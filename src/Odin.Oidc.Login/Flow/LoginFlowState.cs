namespace Odin.Oidc.Login.Flow;

/// <summary>
/// Everything one login needs between sending the browser to the identity and its return. It lives
/// only in the flow cookie: the Hydra challenge to answer, the identity the owner typed (the subject,
/// never the callback's echo), the YouAuth state to match, and the ephemeral key as a private JWK.
/// </summary>
public sealed record LoginFlowState(string LoginChallenge, string Identity, string State, string PrivateKeyJwk);
