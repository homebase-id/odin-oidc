#pragma warning disable CS9113 // stub: replaced by the implementation commit
namespace Odin.Oidc.Login.Hydra;

/// <summary>
/// The eight admin calls of Hydra's login, consent and logout flows, over a typed HttpClient whose
/// base address is the admin API (port 4445; never exposed). Contract: GET the request by its
/// challenge, PUT accept or reject, send the browser to the <c>redirect_to</c> that comes back.
/// A challenge that was already answered is HTTP 410 with the same <c>redirect_to</c>.
/// </summary>
public sealed class HydraAdminClient(HttpClient http)
{
    public Task<HydraLoginRequest> GetLoginRequestAsync(string challenge, CancellationToken ct) => throw new NotImplementedException();
    public Task<string> AcceptLoginAsync(string challenge, HydraAcceptLogin accept, CancellationToken ct) => throw new NotImplementedException();
    public Task<string> RejectLoginAsync(string challenge, HydraReject reject, CancellationToken ct) => throw new NotImplementedException();

    public Task<HydraConsentRequest> GetConsentRequestAsync(string challenge, CancellationToken ct) => throw new NotImplementedException();
    public Task<string> AcceptConsentAsync(string challenge, HydraAcceptConsent accept, CancellationToken ct) => throw new NotImplementedException();
    public Task<string> RejectConsentAsync(string challenge, HydraReject reject, CancellationToken ct) => throw new NotImplementedException();

    public Task<HydraLogoutRequest> GetLogoutRequestAsync(string challenge, CancellationToken ct) => throw new NotImplementedException();
    public Task<string> AcceptLogoutAsync(string challenge, CancellationToken ct) => throw new NotImplementedException();
    public Task<string> RejectLogoutAsync(string challenge, HydraReject reject, CancellationToken ct) => throw new NotImplementedException();
}
