using Odin.Oidc.Login.YouAuth;

namespace Odin.Oidc.Login.Flow;

/// <summary>
/// Everything one login needs between sending the browser to the identity and its return. It lives
/// only in the flow cookie: the Hydra challenge to answer, the identity the owner typed (the subject,
/// never the callback's echo), the YouAuth state to match, and the ephemeral keys.
/// </summary>
public sealed record LoginFlowState(string LoginChallenge, string Identity, string State, YouAuthFlowKeys Keys);
