# Running the broker in production

This is the generic runbook: what the broker needs from any host and any TLS proxy. Nothing here
names a particular deployment; that lives with whoever operates one.

## Shape

`docker/compose.yml` is the production compose. It publishes no port. Three containers share a
user-defined network, `oidc`, with a fixed subnet (`OIDC_NETWORK`, default `172.30.0.0/24`):

| Container | Listens on the `oidc` network | Route it from the proxy? |
|---|---|---|
| `login` | `login:8080`, the login app | yes: **`/oauth2/auth` and `/.well-known/openid-configuration`**, and everything that is not Hydra's (`/login`, `/consent`, `/logout`, `/youauth/callback`, `/.well-known/youauth-client.json`, `/healthz`, `/site.css`) |
| `hydra` | `hydra:4444`, the public OAuth2/OIDC API | yes: the rest of `/oauth2/*`, `/.well-known/jwks.json`, `/userinfo`; or route these to the login app too, which relays them |
| `hydra` | `hydra:4445`, the admin API | **never**; reach it with `docker compose exec hydra hydra ...` |
| `postgres` | `postgres:5432` | no |

The authorize endpoint and discovery go to the login app, not to Hydra: the app is the gateway
that registers a URL client from its document before relaying the request to Hydra
(`docs/relying-parties.md`), and it serves discovery as Hydra's with the authorize endpoint
pointed at itself and `client_id_metadata_document_supported` added. It relays the rest of
Hydra's public API too, so the simplest contract is one upstream, the login app; the split
below saves the token endpoint and userinfo the extra hop.

Put your TLS proxy on the `oidc` network and give every route one origin, the issuer. The proxy
must send `X-Forwarded-Proto` and `X-Forwarded-For`; both Hydra (`SERVE_TLS_ALLOW_TERMINATION_FROM`)
and the login app (`Broker__TrustedProxyNetworks__0`) believe those headers only from the `oidc`
subnet, which is why the subnet is fixed; the app sets them again on what it relays. Everything
else the browser needs, HSTS aside, the login app sets itself (a strict content security policy,
no framing, no caching); the proxy adds `Strict-Transport-Security` for Hydra's paths, since
Hydra does not.

One worked example, Caddy, on the `oidc` network (Caddy picks the longest matching `handle`, so
`/oauth2/auth` wins over `/oauth2/*`):

```
oidc.example.org {
    header Strict-Transport-Security "max-age=31536000; includeSubDomains"
    request_body { max_size 64KB }   # a coarse first cut; the app's own limit, 16 KB, is the real one
    handle /.well-known/openid-configuration { reverse_proxy login:8080 }
    handle /oauth2/auth                     { reverse_proxy login:8080 }
    handle /.well-known/jwks.json           { reverse_proxy hydra:4444 }
    handle /oauth2/*                        { reverse_proxy hydra:4444 }
    handle /userinfo                        { reverse_proxy hydra:4444 }
    handle                                  { reverse_proxy login:8080 }
}
```

Note the `/.well-known` documents: OpenID discovery is Hydra's, served through the login app;
the JWKS is Hydra's directly; `/.well-known/youauth-client.json` is the login app's own, which is
what an identity reads before asking its owner to sign in here.

The login app reaches the site named in a URL client's id, so it needs outbound https to the
internet; it refuses to connect to any special-use address (loopback, private, link-local, and
the rest of RFC 6890), so a client id cannot point it into your network.

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

## What a login leaves behind, and for how long

Every sign-in is a row in Hydra's flow table plus its codes and tokens. They are referenced for as
long as anything points at them: the challenge for 30 minutes, the access and id tokens for an
hour, a refresh token (`offline` scope) for 30 days and renewed on use, a remembered login or
consent for 30 days. Expiry does not delete: the `hydra-janitor` service in the compose runs
Hydra's janitor once a day and removes what is past its lifetime plus a 30-hour grace period, in
batches, so the tables stay bounded at roughly a month of logins. Shorten the month with
`Remembered.ForSeconds` in the app and `ttl.refresh_token` in `hydra.yml` if that is too long a
record of who signed in where.

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

Two kinds, told apart in Hydra by the client's `metadata`:

**URL clients** need nothing from the operator: their client id is their own https URL, and the
document there is their registration (`docs/relying-parties.md`). The login app creates them in
Hydra on first sight with `metadata.registered = "by-url"`, and updates them when the document
changes. They are public clients with PKCE, callbacks only on their own origin; the consent page
shows their host large and their self-declared name small. Rows for sites nobody signs in
through any more can be removed now and then: `delete from hydra_client where metadata->>'registered'
= 'by-url' and created_at < now() - interval '30 days' and id not in (select client_id from
hydra_oauth2_flow)` (a flow row lives about a month, see above), and the app recreates any that
returns.

**Operator-registered clients** are made by hand, on the host, through the admin API:
`scripts/create-public-client.sh` (a browser or native app, PKCE) and
`scripts/create-test-client.sh` (a server-side application with a secret) are the two shapes; for
production change the name and the redirect URI, which is the allowlist (https only, matched
exactly), and add `--skip-consent` for a first-party relying party so the broker's consent page is
skipped; the owner still approves the sign-in at their own identity. Give them
`--metadata '{"managed":"operator"}'` so the app never writes to them, and keep a list (name, id,
redirect URIs, skip consent) with your deployment. This is the path for software that insists on
a client secret.

## Logging

At Information the login app names no identity domain; Debug does, for an incident. Relying
parties are named at Information (a URL client's id, when it is registered, updated or refused):
they are sites, not people. Container
logs rotate (json-file, 10 MB x 5); a host may set another driver.

## Health

`GET /healthz` is 200 only when the login app answers and Hydra reports ready on its admin API: a
readiness answer for a smoke test or an uptime probe from outside, not a liveness probe to
restart the container on. Probe `/.well-known/openid-configuration` too.

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
