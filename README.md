# odin-oidc

An OpenID Connect broker for Homebase identities: any software that speaks OIDC can offer
"Sign in with Homebase". The issuer is [Ory Hydra](https://github.com/ory/hydra), unmodified;
the login-and-consent app in `src/Odin.Oidc.Login` is ours, and it proves who the user is with
the YouAuth flow against the user's own identity server. The OIDC subject is the identity's
domain. See `docs/flow.md` for the sequence and for what is stored where.

## Running locally

Prerequisites: Docker with compose, the .NET 9 SDK, and a sibling checkout of
[odin-core](https://github.com/homebase-id/odin-core) at `../odin-core` (the login app references
its `Odin.Core` and `Odin.Core.Cryptography` projects; `odin-core.ref` names the commit CI builds
against).

### 1. Hydra

```bash
cp docker/.env.example docker/.env      # then set HYDRA_SECRETS_SYSTEM to 32+ random characters
docker compose -f docker/compose.yml up -d
curl http://127.0.0.1:14444/.well-known/openid-configuration
```

Hydra's public port is 14444 and its admin port 14445 on the host (odin-core's dev host owns
4444). Register the demo relying party and run it:

```bash
scripts/create-test-client.sh > docker/demo-client.json     # prints client_id and client_secret
scripts/run-demo-rp.sh <client_id> <client_secret>          # http://127.0.0.1:5555
```

Opening http://127.0.0.1:5555 and clicking the authorize link makes Hydra send the browser to
`${LOGIN_APP_URL}/login?login_challenge=...`, which is where the login app takes over.

### 2. The login app

The identity must reach the app over https, and it compares the redirect host to the client id
without the port, so in development the app runs on 8443 under one of odin-core's dev certificates
(the identity host owns 443 on the same machine):

```bash
scripts/dev-cert.sh                                          # copies collab.dotyou.cloud's cert from ../odin-core
ASPNETCORE_ENVIRONMENT=Development dotnet run --project src/Odin.Oidc.Login
curl https://collab.dotyou.cloud:8443/.well-known/youauth-client.json
```

`appsettings.Development.json` sets `Broker:PublicOrigin` to `https://collab.dotyou.cloud:8443` and
Kestrel's endpoint to that port and certificate; `LOGIN_APP_URL` in `docker/.env` must match. With odin-core's dev identity host and the
odin-js owner app running as its README describes, the whole flow runs locally: open
http://127.0.0.1:5555, click the authorize link, type `frodo.dotyou.cloud`, sign in and approve at
frodo, and the demo relying party shows an id_token whose `sub` is `frodo.dotyou.cloud`.

Until `oidc.dotyou.cloud` has a certificate on the dev certbot host, the owner's consent page names
the broker as collab, and collab itself cannot sign in through it.

### 3. A public relying party with PKCE

The way a browser or native app signs in: no client secret, PKCE required. `scripts/demo-rp.mjs`
is one in eighty lines with no dependencies (Node 18+):

```bash
scripts/create-public-client.sh > docker/demo-public-client.json   # prints the client id
node scripts/demo-rp.mjs <client_id>                              # http://127.0.0.1:5556
```

It prints the id_token's claims and the userinfo answer; `docs/flow.md` lists what they carry.
The consent page names the relying party and lists that; Allow is remembered for a month on that
browser, and "Keep me signed in" on the login page does the same for the login, so the next
relying party skips both. `prompt=login` from a relying party still asks. A first-party relying
party can skip the broker's consent page altogether: register it with `--skip-consent`.

## Tests, image, CI

`dotnet build odin-oidc.sln --warnaserror` and `dotnet test odin-oidc.sln`; the fakes are described
in `tests/Odin.Oidc.Login.Tests/BrokerApp.cs`. The `Dockerfile` header says how the image is built
against the pinned odin-core commit (`scripts/bump-odin-core.sh` moves the pin); `.github/workflows/ci.yml`
does the same on every push.
