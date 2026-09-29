namespace Odin.Oidc.Login.Registration;

/// <summary>What the pages say about the relying party: its callback's domain, and the name it gave itself.</summary>
public sealed record RelyingParty(string? Domain, string? Name);
