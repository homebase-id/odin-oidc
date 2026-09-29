# Adding "Sign in with Homebase" to a site

The broker is a standard OpenID Connect provider. Any OIDC library works; the issuer is the
broker's origin (for the public one, `https://oidc.homebase.id/`), and discovery is at
`/.well-known/openid-configuration`. The subject a login returns is the person's identity
domain; `docs/flow.md` lists every claim.

There are two ways to be a relying party.

## 1. No registration: your client id is your own URL

Pick an https URL on your site with a path, for example `https://jean.example/oauth-client.json`,
and serve this JSON document there (`Content-Type: application/json`):

```json
{
  "client_id": "https://jean.example/oauth-client.json",
  "client_name": "Jean's wiki",
  "redirect_uris": ["https://jean.example/auth/callback"],
  "token_endpoint_auth_method": "none",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "openid profile offline"
}
```

Then configure your OIDC library with that URL as the client id, no client secret, and PKCE
(S256). That is all: the first time a browser arrives at the broker's authorize endpoint with
your client id, the broker reads the document, registers you from it, and continues. This is the
IETF draft "OAuth Client ID Metadata Document" (`draft-ietf-oauth-client-id-metadata-document`),
which ATProto's OAuth also uses; discovery announces it with
`client_id_metadata_document_supported: true`.

Rules, from the draft and from this broker:

- `client_id` in the document must be exactly the URL it is served at. The id is compared as a
  plain string, so use one spelling everywhere. It must be https with a path; no query, no
  fragment, no user info, no `.` or `..` segments, no IP address.
- Every entry in `redirect_uris` must be https on the same host and port as the client id, and
  the `redirect_uri` in a request must match one of them exactly. Callbacks elsewhere are
  ignored; a request for one that is not listed is refused at the broker with a page saying so,
  and nothing is sent to it.
- Only public clients: `token_endpoint_auth_method` must be `none` (or absent), and PKCE is
  required. A URL client cannot hold a secret, since nobody hands one out. Software that insists
  on a client secret takes the second path below.
- `scope` may name any of `openid`, `profile`, `offline`, `offline_access`; `openid` is always
  included. `client_name` is trimmed and capped at 64 characters. Nothing else in the document is
  used.
- The document is fetched with a 3-second timeout, up to 5 KB, only when it answers 200 with
  `application/json`; a redirect is not followed. It is cached for the time its `Cache-Control:
  max-age` says, held to between five minutes and a day (an hour when it says nothing), so a new
  callback or a new name takes effect within that time. A document that cannot be read stops the
  sign-in with a 400 page; failures are never cached, so fixing the document is enough.
- The site must be reachable from the broker at a public address. A site on a private or loopback
  address cannot be a URL client of a production broker.

What the person sees: the broker's login and consent pages show your **host** large, from the
callback the request named, and your `client_name` small beneath it as "Calling itself '…'". The
domain is the trust anchor; the name is your claim. There is no logo.

For development against a broker run with `Broker:AllowLocalhostClients` (the development
settings in this repo), the client id `http://localhost` with `redirect_uri` and `scope` in its
query is accepted without any document, as ATProto defines it; the callbacks must be loopback
addresses, and their port is not matched. `scripts/demo-rp.mjs --url-client` is one such client.

## 2. Registered by the operator

The operator creates a client with `hydra create client` on the host (`docs/production.md`),
which can also be a confidential client with a secret, and can skip the broker's consent page
for a first-party site. Ask the operator for the client id.
