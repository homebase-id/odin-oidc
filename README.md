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

(Step 2 onward; filled in as the app lands.)
