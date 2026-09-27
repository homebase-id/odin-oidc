using System.Net;
using Odin.Oidc.Login.Hydra;
using Odin.Oidc.Login.Tests.Fakes;

namespace Odin.Oidc.Login.Tests;

/// <summary>The wire contract with Hydra's admin API: paths, the challenge query, snake_case bodies, redirect_to.</summary>
[TestFixture]
public class HydraAdminClientTests
{
    private static (HydraAdminClient client, RecordingHandler handler) Client(Func<HttpRequestMessage, string?, HttpResponseMessage> respond)
    {
        var handler = new RecordingHandler((r, b) => Task.FromResult(respond(r, b)));
        var http = new HttpClient(handler) { BaseAddress = new Uri("http://hydra-admin:4445/") };
        return (new HydraAdminClient(http), handler);
    }

    [Test]
    public async Task GetsTheLoginRequestByChallenge()
    {
        var (client, handler) = Client((_, _) => RecordingHandler.Json(HttpStatusCode.OK,
            """{"challenge":"abc","skip":true,"subject":"frodo.dotyou.cloud","requested_scope":["openid"],"client":{"client_id":"rp","skip_consent":true},"oidc_context":{"login_hint":"frodo.dotyou.cloud"}}"""));

        var request = await client.GetLoginRequestAsync("abc", CancellationToken.None);

        Assert.That(handler.Requests.Single().request.RequestUri!.PathAndQuery, Is.EqualTo("/admin/oauth2/auth/requests/login?login_challenge=abc"));
        Assert.That(request.Skip, Is.True);
        Assert.That(request.Subject, Is.EqualTo("frodo.dotyou.cloud"));
        Assert.That(request.Client!.SkipConsent, Is.True);
        Assert.That(request.OidcContext!.LoginHint, Is.EqualTo("frodo.dotyou.cloud"));
    }

    [Test]
    public async Task AcceptsALoginWithASnakeCaseBodyAndReturnsWhereToGo()
    {
        var (client, handler) = Client((_, _) => RecordingHandler.Json(HttpStatusCode.OK, """{"redirect_to":"http://hydra/oauth2/auth?x=1"}"""));

        var redirect = await client.AcceptLoginAsync("abc", new HydraAcceptLogin { Subject = "frodo.dotyou.cloud", Remember = false }, CancellationToken.None);

        var (request, body) = handler.Requests.Single();
        Assert.That(request.Method, Is.EqualTo(HttpMethod.Put));
        Assert.That(request.RequestUri!.PathAndQuery, Is.EqualTo("/admin/oauth2/auth/requests/login/accept?login_challenge=abc"));
        Assert.That(body, Does.Contain("\"subject\":\"frodo.dotyou.cloud\"").And.Contain("\"remember\":false").And.Not.Contain("remember_for"), $"body: {body}");
        Assert.That(redirect, Is.EqualTo("http://hydra/oauth2/auth?x=1"));
    }

    [Test]
    public async Task RejectsALoginWithTheErrorHydraExpects()
    {
        var (client, handler) = Client((_, _) => RecordingHandler.Json(HttpStatusCode.OK, """{"redirect_to":"http://rp/callback?error=access_denied"}"""));

        var redirect = await client.RejectLoginAsync("abc", new HydraReject { Error = "access_denied", ErrorDescription = "cancelled" }, CancellationToken.None);

        var (request, body) = handler.Requests.Single();
        Assert.That(request.RequestUri!.PathAndQuery, Is.EqualTo("/admin/oauth2/auth/requests/login/reject?login_challenge=abc"));
        Assert.That(body, Does.Contain("\"error\":\"access_denied\"").And.Contain("\"error_description\":\"cancelled\""));
        Assert.That(redirect, Does.Contain("error=access_denied"));
    }

    [Test]
    public async Task AcceptsConsentWithScopeAndIdTokenClaims()
    {
        var (client, handler) = Client((_, _) => RecordingHandler.Json(HttpStatusCode.OK, """{"redirect_to":"http://rp/callback?code=1"}"""));

        await client.AcceptConsentAsync("c1", new HydraAcceptConsent
        {
            GrantScope = ["openid", "profile"],
            Session = new HydraConsentSession { IdToken = new Dictionary<string, object> { ["name"] = "Frodo" } },
        }, CancellationToken.None);

        var (request, body) = handler.Requests.Single();
        Assert.That(request.RequestUri!.PathAndQuery, Is.EqualTo("/admin/oauth2/auth/requests/consent/accept?consent_challenge=c1"));
        Assert.That(body, Does.Contain("\"grant_scope\":[\"openid\",\"profile\"]").And.Contain("\"id_token\":{\"name\":\"Frodo\"}"), $"body: {body}");
    }

    [Test]
    public void AChallengeAlreadyAnsweredSaysWhereToGoWhateverTheCall()
    {
        var (client, _) = Client((_, _) => RecordingHandler.Json(HttpStatusCode.Gone, """{"error":"already_handled","redirect_to":"http://hydra/oauth2/auth?again=1"}"""));

        Assert.That(() => client.GetLoginRequestAsync("abc", CancellationToken.None),
            Throws.InstanceOf<HydraAlreadyAnsweredException>().With.Property("RedirectTo").EqualTo("http://hydra/oauth2/auth?again=1"),
            "HTTP 410 on a GET: the browser went back to a page it had left");
        Assert.That(() => client.AcceptLoginAsync("abc", new HydraAcceptLogin { Subject = "frodo.dotyou.cloud" }, CancellationToken.None),
            Throws.InstanceOf<HydraAlreadyAnsweredException>().With.Property("RedirectTo").EqualTo("http://hydra/oauth2/auth?again=1"),
            "and on a PUT; the Error page sends the browser on");
    }

    [Test]
    public void AnyOtherFailureIsAnException()
    {
        var (client, _) = Client((_, _) => RecordingHandler.Json(HttpStatusCode.NotFound, """{"error":"Not Found","error_description":"Unable to locate the requested resource"}"""));

        Assert.That(() => client.GetLoginRequestAsync("gone", CancellationToken.None),
            Throws.InstanceOf<HydraException>().With.Message.Contains("404").And.Message.Contains("Unable to locate"));
    }
}
