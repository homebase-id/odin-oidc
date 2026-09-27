namespace Odin.Oidc.Login.Hydra;

/// <summary>Hydra's admin API answered with something other than success or an already-answered challenge.</summary>
public sealed class HydraException(string message) : Exception(message);
