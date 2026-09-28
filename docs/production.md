# Running the broker in production

This is the generic runbook: what the broker needs from any host and any TLS proxy. Nothing here
names a particular deployment; that lives with whoever operates one.

## Shape

`docker/compose.yml` is the production compose. It publishes no port. Three containers share a
user-defined network, `oidc`, with a fixed subnet (`OIDC_NETWORK`, default `172.30.0.0/24`):

| Container | Listens on the `oidc` network | Route it from the proxy? |
|---|---|---|
| `hydra` | `hydra:4444`, the public OAuth2/OIDC API | yes: `/.well-known/*`, `/oauth2/*`, `/userinfo` |
| `hydra` | `hydra:4445`, the admin API | **never**; reach it with `docker compose exec hydra hydra ...` |
| `login` | `login:8080`, the login app | yes: everything else (`/login`, `/consent`, `/logout`, `/youauth/callback`, `/.well-known/youauth-client.json`, `/healthz`, `/site.css`) |
| `postgres` | `postgres:5432` | no |

Put your TLS proxy on the `oidc` network and give both routes one origin, the issuer. The proxy
must send `X-Forwarded-Proto` and `X-Forwarded-For`; both Hydra (`SERVE_TLS_ALLOW_TERMINATION_FROM`)
and the login app (`Broker__TrustedProxyNetworks__0`) believe those headers only from the `oidc`
subnet, which is why the subnet is fixed. Everything else the browser needs, HSTS aside, the login
app sets itself (a strict content security policy, no framing, no caching); the proxy adds
`Strict-Transport-Security` for Hydra's paths, since Hydra does not.

One worked example, Caddy, on the `oidc` network:

```
oidc.example.org {
    header Strict-Transport-Security "max-age=31536000; includeSubDomains"
    request_body { max_size 64KB }
    handle /.well-known/openid-configuration { reverse_proxy hydra:4444 }
    handle /.well-known/jwks.json           { reverse_proxy hydra:4444 }
    handle /oauth2/*                        { reverse_proxy hydra:4444 }
    handle /userinfo                        { reverse_proxy hydra:4444 }
    handle                                  { reverse_proxy login:8080 }
}
```

Note the two `/.well-known` documents go to different containers: OpenID discovery and the JWKS
are Hydra's; `/.well-known/youauth-client.json` is the login app's, which is what an identity reads
before asking its owner to sign in here.

## Configuration

All of it is `docker/.env` (see `.env.example`); nothing in the compose or `hydra.yml` changes per
environment. The issuer, `HYDRA_ISSUER`, is baked into every token's `iss` and into every relying
party's configuration: decide it once. `LOGIN_APP_URL` is the same origin.

Secrets, and only these: `HYDRA_DB_PASSWORD`, and `HYDRA_SECRETS_SYSTEM`, which encrypts what Hydra
stores, including its signing keys. Keep them in your secret store and render `.env` from it;
never in the repo. Error messages can quote rejected values, so a config that references a secret
is safer than one that contains it.

## What is stateful, and backups

| What | Where | Lost means |
|---|---|---|
| Hydra's database | volume `hydra-pgdata` | every relying party registration, every remembered login and consent, every refresh token, and the JWKS signing keys |
| `HYDRA_SECRETS_SYSTEM` | your secret store | the database is unreadable: signing keys and client secrets are encrypted with it |
| the login app's key ring | volume `login-keys` | in-flight ten-minute flow cookies only; not an outage, but a second instance must share the volume |

Back up the database dump, the key ring and the *name* of the secret entry together, nightly:

```bash
docker compose exec -T postgres pg_dump -U hydra hydra | gzip > hydra-$(date +%F).sql.gz
docker run --rm -v odin-oidc_login-keys:/keys:ro alpine tar cz -C /keys . > login-keys-$(date +%F).tgz
```

A backup counts only once restored and read back. Monthly, on a scratch host: start a throwaway
Postgres, restore the dump, start a throwaway Hydra with the same `SECRETS_SYSTEM` against it, and
`hydra list clients --endpoint http://127.0.0.1:4445` must list the relying parties.

## Rotations

**Signing keys.** Hydra signs id_tokens with the `hydra.openid.id-token` key set. Adding a key
makes it the signing key; older keys stay in the JWKS so tokens already issued still verify:

```bash
docker compose exec hydra hydra create jwk hydra.openid.id-token --alg RS256 --endpoint http://127.0.0.1:4445
```

Quarterly is a reasonable cadence. Verify the CLI spelling against the Hydra version you run.

**The system secret.** `HYDRA_SECRETS_SYSTEM` takes a comma-separated list: the first encrypts, all
decrypt. Rotate by prepending a new value, restarting, and following Hydra's documentation for
re-encrypting stored data before removing the old value. Rehearse it on the scratch restore, never
first on production.

**Hydra upgrades.** Backup, change `HYDRA_IMAGE` to the new digest, `docker compose up -d`: the
`hydra-migrate` service applies migrations before `hydra` starts.

## Relying parties

Registration is by hand, on the host, through the admin API. Redirect URIs are the allowlist:
https only, matched exactly.

```bash
# a browser or native app: public client, PKCE
docker compose exec hydra hydra create client --endpoint http://127.0.0.1:4445 --format json \
  --name "Example app" --grant-type authorization_code,refresh_token --response-type code \
  --scope openid,offline,profile --redirect-uri https://app.example.org/callback \
  --token-endpoint-auth-method none

# a server-side application: confidential client; add --skip-consent for a first-party one
docker compose exec hydra hydra create client --endpoint http://127.0.0.1:4445 --format json \
  --name "Example forum" --grant-type authorization_code,refresh_token --response-type code \
  --scope openid,offline,profile --redirect-uri https://forum.example.org/auth/callback \
  --token-endpoint-auth-method client_secret_basic --skip-consent
```

`--skip-consent` skips the broker's consent page for that client; the owner still approves the
sign-in at their own identity. Keep a list of registered clients (name, id, redirect URIs, skip
consent) with your deployment.

## Logging

At Information the login app records events without identity domains: a domain is the sensitive
datum. Debug names them, for an incident. Hydra logs at info with `leak_sensitive_values: false`.
Container logs rotate (json-file, 10 MB x 5); a host may set another driver.

## Health

`GET /healthz` is 200 only when the login app answers and Hydra reports ready on its admin API.
Probe it, and `/.well-known/openid-configuration`, from outside. `/healthz` is served by the login
app, so it goes through the proxy like everything else.

## Go-live checklist

1. The backup ran once and the verify-restore passed, even on the empty database.
2. A demo relying party registered; `scripts/demo-rp.mjs` against the real issuer signs someone in;
   their identity's consent page names the broker by its published name, since the client document
   is fetched from the real origin for the first time.
3. A signing-key rotation rehearsed: id_tokens issued before still verify against the JWKS.
4. The system-secret rotation rehearsed on the scratch restore.
5. No new listening port on the host beyond the proxy's.
6. Rollback is `docker compose down` and removing the DNS name; nothing depends on the issuer until
   a real relying party is registered, which is why the first period has only the demo one.
