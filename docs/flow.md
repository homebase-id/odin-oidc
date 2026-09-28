# Sign in with Homebase: the broker flow

```mermaid
sequenceDiagram
    participant rp as Relying party<br/>(Discourse, Grafana, ...)
    participant hydra as Hydra<br/>oidc.homebase.id
    participant app as Odin.Oidc.Login<br/>(this repo)
    participant idn as Sam's identity<br/>sam.dotyou.cloud

    rp->>hydra: GET /oauth2/auth (client_id, PKCE, scope, state)
    hydra->>app: 302 /login?login_challenge
    app->>app: skip? accept at once. Else ask "which identity?" (login_hint prefilled)
    app->>idn: 302 YouAuth [030] /api/owner/v1/youauth/authorize<br/>client_type=domain, client_id=broker host,<br/>redirect_uri=https://broker/youauth/callback, public_key, state, cipher=aes-gcm
    idn->>app: YouAuth [030] fetches https://broker/.well-known/youauth-client.json<br/>{name: "Homebase Sign-in", redirect_uris: [callback]}
    idn->>idn: Sam signs in and consents (owner console)
    idn->>app: 302 YouAuth [080] /youauth/callback?identity&public_key&salt&state
    app->>app: state matches the flow cookie; derive exchange secret (ECDH P-384 + HKDF)
    app->>idn: YouAuth [100] POST /api/owner/v1/youauth/token {secret_digest}
    idn->>app: YouAuth [140] sealed client access token, cipher=aes-gcm
    app->>app: YouAuth [150] open it: 33 bytes = proof of identity
    app->>idn: POST /api/v2/auth/logout (Bearer token): release the registration
    app->>hydra: PUT /admin/oauth2/auth/requests/login/accept {subject: sam.dotyou.cloud}
    hydra->>app: 302 /consent?consent_challenge
    app->>idn: GET /pub/profile (profile scope): the published name
    app->>app: remembered or trusted? accept. Else the page: "Let <relying party> know who you are?"
    app->>hydra: PUT .../consent/accept {grant_scope, remember, session.id_token: name, picture, preferred_username, website}
    hydra->>rp: 302 redirect_uri?code&state
    rp->>hydra: POST /oauth2/token (code, PKCE verifier)
    hydra->>rp: id_token (sub = sam.dotyou.cloud), access token
```

## What is stored where

| Where | What | Why |
|---|---|---|
| Hydra's Postgres | OAuth client registrations, signing keys, login/consent sessions (subject, remembered consents), authorization codes, access and refresh tokens | Hydra's own state; an OIDC issuer cannot be stateless |
| Odin.Oidc.Login | A Data Protection key ring, nothing else at rest | Each login's state lives in a 10-minute encrypted cookie and dies with it |
| The identity | A domain registration for the broker, between authorize and the broker's logout call | The broker releases it as soon as the identity is proven |

## What a relying party learns

Always `sub`, the identity's domain, and `did`, the same as a `did:web`, which resolves to the
identity's own DID document at `/.well-known/did.json` (a custom claim; OIDC allows any, and a
relying party that does not know it ignores it). Under the `profile` scope also `name`,
`given_name` and `family_name` from the identity's public profile card (absent when not
published), `picture` (the identity's public image URL), `preferred_username` (the domain),
`website` (`https://` + domain) and `profile`, OIDC's profile-page claim, which is the identity's
home page and carries its schema.org JSON-LD. Read from the identity at consent time, never stored
by the broker; Hydra keeps them in the consent session for the id_token and userinfo. No email: an
identity's mail address is not public information.
